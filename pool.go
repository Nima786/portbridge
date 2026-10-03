package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errNoSpare = errors.New("no tunnel connection available from the other server")

const (
	refillParallel   = 8
	refillIdle       = 300 * time.Millisecond
	refillBackoff0   = 1 * time.Second
	refillBackoffM   = 30 * time.Second
	parkPingInterval = 15 * time.Second
	parkPingTimeout  = 3 * time.Second

	// How often the liveness loop looks for spares that are due a check. The
	// interval above is per spare; this is only how finely it is scheduled.
	livenessTick = time.Second

	// How long a check of every spare waits for the replies. Short, because it
	// runs while a user is waiting and the usual answer is tens of milliseconds.
	verifyTimeout = 1500 * time.Millisecond
)

type parked struct {
	conn     net.Conn
	at       time.Time
	lastPing time.Time
}

// pool holds authenticated tunnel connections that are ready to carry a user,
// and always lives on the edge.
//
// In direct mode the edge fills it by dialling the origin, so dial is set and an
// empty pool simply means a slightly slower connection for one user.
//
// In reverse mode the edge cannot dial anywhere: the origin opens the
// connections and the edge accepts them, so dial is nil and an empty pool means
// waiting briefly for the origin to supply one.
type pool struct {
	mu      sync.Mutex
	items   []parked
	waiters []chan net.Conn

	maxSize int
	maxAge  time.Duration

	// dial is nil in reverse mode.
	dial func() (net.Conn, error)

	// waitForOffer is how long a user waits in reverse mode for the origin to
	// supply a connection before giving up.
	waitForOffer time.Duration

	log *throttled

	// lastErr remembers why the most recent attempt to build a spare failed.
	lastErr atomic.Value

	// Counters, read by the status writer.
	statParked    int64
	statOffered   int64
	statDiscarded int64

	// fastDeaths counts spares that died very soon after being built, since the
	// refill loop last looked.
	fastDeaths int32

	// verifying is set while a check of every spare is under way, so a burst of
	// failing users starts one check between them rather than one each.
	verifying int32
}

func newPool(maxSize int, maxAge, waitForOffer time.Duration, dial func() (net.Conn, error)) *pool {
	return &pool{
		maxSize:      maxSize,
		maxAge:       maxAge,
		dial:         dial,
		waitForOffer: waitForOffer,
		log:          newThrottled(),
	}
}

func (p *pool) parkedCount() int {
	return int(atomic.LoadInt64(&p.statParked))
}

// offer hands the edge a freshly authenticated connection that the origin just
// opened. Used in reverse mode only. Returns false if the pool is full, in which
// case the caller should close the connection.
func (p *pool) offer(c net.Conn) bool {
	p.mu.Lock()
	// A user already waiting takes priority over parking it.
	for len(p.waiters) > 0 {
		ch := p.waiters[0]
		p.waiters = p.waiters[1:]
		select {
		case ch <- c:
			p.mu.Unlock()
			return true
		default:
			// That waiter gave up already; try the next one.
		}
	}
	if len(p.items) >= p.maxSize {
		p.mu.Unlock()
		return false
	}
	p.items = append(p.items, parked{conn: c, at: time.Now(), lastPing: time.Now()})
	atomic.StoreInt64(&p.statParked, int64(len(p.items)))
	atomic.AddInt64(&p.statOffered, 1)
	p.mu.Unlock()
	return true
}

// takeParked pops the freshest usable spare, discarding any that have aged out
// or are already dead. Returns nil when the pool holds nothing usable.
func (p *pool) takeParked() net.Conn {
	for {
		p.mu.Lock()
		if len(p.items) == 0 {
			p.mu.Unlock()
			return nil
		}
		last := len(p.items) - 1
		it := p.items[last]
		p.items[last] = parked{}
		p.items = p.items[:last]
		atomic.StoreInt64(&p.statParked, int64(len(p.items)))
		p.mu.Unlock()

		if time.Since(it.at) >= p.maxAge || !socketAlive(it.conn) {
			p.discard(it)
			continue
		}
		return it.conn
	}
}

// take returns a connection ready to be activated.
func (p *pool) take(ctx context.Context) (net.Conn, error) {
	if c := p.takeParked(); c != nil {
		return c, nil
	}
	if p.dial != nil {
		return p.dial()
	}
	return p.waitForConn(ctx)
}

// waitForConn is the reverse-mode path: park a request and let the next
// connection the origin opens satisfy it.
func (p *pool) waitForConn(ctx context.Context) (net.Conn, error) {
	ch := make(chan net.Conn, 1)
	p.mu.Lock()
	p.waiters = append(p.waiters, ch)
	p.mu.Unlock()

	timer := time.NewTimer(p.waitForOffer)
	defer timer.Stop()

	select {
	case c := <-ch:
		// A nil value means the pool shut down while we waited.
		if c == nil {
			return nil, errNoSpare
		}
		return c, nil
	case <-timer.C:
		p.dropWaiter(ch)
		// A connection may have arrived in the instant we gave up.
		select {
		case c := <-ch:
			if c != nil {
				return c, nil
			}
		default:
		}
		p.log.printf("no spare tunnel connection from the other server within %s; is the origin running?", p.waitForOffer)
		return nil, errNoSpare
	case <-ctx.Done():
		p.dropWaiter(ch)
		select {
		case c := <-ch:
			if c != nil {
				_ = c.Close()
			}
		default:
		}
		return nil, ctx.Err()
	}
}

func (p *pool) dropWaiter(ch chan net.Conn) {
	p.mu.Lock()
	for i, w := range p.waiters {
		if w == ch {
			p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

// maintain evicts spares that have aged out or died and, in direct mode, keeps
// the pool topped up.
//
// Refills happen in parallel: building them one at a time cannot keep pace with
// expiry on a slow link, which turns the pool into a treadmill that never fills.
// Repeated failures back off instead of hammering a route that is clearly down.
func (p *pool) maintain(ctx context.Context) {
	backoff := time.Duration(0)

	// Liveness checks run on their own clock. They used to share this loop with
	// refilling, so a handful of dead connections, each taking seconds to give up
	// on, held the loop up and starved the refills behind them.
	go p.liveness(ctx)

	for {
		if ctx.Err() != nil {
			return
		}
		p.evict()

		var failures int32
		if p.dial != nil {
			p.mu.Lock()
			needed := p.maxSize - len(p.items)
			p.mu.Unlock()

			if needed > 0 {
				var wg sync.WaitGroup
				slots := make(chan struct{}, refillParallel)
				for i := 0; i < needed; i++ {
					if ctx.Err() != nil {
						break
					}
					wg.Add(1)
					slots <- struct{}{}
					go func() {
						defer wg.Done()
						defer func() { <-slots }()

						c, err := p.dial()
						if err != nil {
							atomic.AddInt32(&failures, 1)
							// Keep the reason. Counting failures without saying
							// why turns a clear problem, such as a refused
							// disguise, into a silent one.
							p.lastErr.Store(err.Error())
							return
						}
						if !p.offerLocal(c) {
							_ = c.Close()
						}
					}()
				}
				wg.Wait()
			}
		}

		// A connection that was accepted, authenticated and then dropped within
		// seconds is a failure even though dialling it went fine. Without
		// counting these, a wrong password or a version the other end refuses
		// looked like success to the refill loop, which then rebuilt the whole
		// pool several times a second for as long as it ran.
		if p.dial != nil {
			if fast := atomic.SwapInt32(&p.fastDeaths, 0); fast > 0 {
				failures += fast
				if _, ok := p.lastErr.Load().(string); !ok {
					p.lastErr.Store("the other server accepts connections and then drops them at once " +
						"(wrong secret, clocks apart, shared connections set differently, or an older version)")
				}
			}
		}

		wait := refillIdle
		if failures > 0 {
			if backoff == 0 {
				backoff = refillBackoff0
			} else if backoff < refillBackoffM {
				backoff *= 2
				if backoff > refillBackoffM {
					backoff = refillBackoffM
				}
			}
			reason, _ := p.lastErr.Load().(string)
			if reason == "" {
				reason = "no reason reported"
			}
			p.log.printf("could not build %d spare tunnel connections: %s; retrying in %s",
				failures, reason, backoff)
			wait = backoff
		} else {
			backoff = 0
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// offerLocal parks a connection this side dialled. Unlike offer it does not hand
// off to waiters, because in direct mode a waiting user would have dialled its
// own connection rather than waiting.
func (p *pool) offerLocal(c net.Conn) bool {
	p.mu.Lock()
	if len(p.items) >= p.maxSize {
		p.mu.Unlock()
		return false
	}
	p.items = append(p.items, parked{conn: c, at: time.Now(), lastPing: time.Now()})
	atomic.StoreInt64(&p.statParked, int64(len(p.items)))
	p.mu.Unlock()
	return true
}

// fastDeathAge is how young a spare has to be when it dies to count as having
// been refused rather than having simply worn out or lost its path.
const fastDeathAge = 20 * time.Second

func (p *pool) evict() {
	p.mu.Lock()
	original := p.items
	kept := original[:0]
	var dead []parked
	for _, it := range original {
		if time.Since(it.at) < p.maxAge && socketAlive(it.conn) {
			kept = append(kept, it)
		} else {
			dead = append(dead, it)
		}
	}
	for i := len(kept); i < len(original); i++ {
		original[i] = parked{}
	}
	p.items = kept
	atomic.StoreInt64(&p.statParked, int64(len(p.items)))
	p.mu.Unlock()

	for _, it := range dead {
		p.discard(it)
	}
}

// discard closes a spare that is no good, and if it died young works out why.
func (p *pool) discard(it parked) {
	atomic.AddInt64(&p.statDiscarded, 1)
	if time.Since(it.at) < fastDeathAge {
		atomic.AddInt32(&p.fastDeaths, 1)
		// The far side may have said why just before it hung up.
		if b, ok := pendingByte(it.conn); ok && isRejection(b) {
			reason := describeRejection(b)
			p.lastErr.Store(reason.Error())
			p.log.printf("the other server refused a connection: %v", reason)
		}
	}
	_ = it.conn.Close()
}

// flush closes every parked spare. Used when the route changes: spares built
// over the old route are worth nothing on the new one.
func (p *pool) flush() {
	p.mu.Lock()
	items := p.items
	p.items = nil
	atomic.StoreInt64(&p.statParked, 0)
	p.mu.Unlock()
	for _, it := range items {
		_ = it.conn.Close()
	}
}

// liveness proves, on a schedule, that parked connections still work.
//
// Every transport is checked, plain TCP included. That was the gap: a plain
// connection was assumed healthy until something tried to use it, so a route
// that had quietly stopped carrying data left the pool full of connections that
// looked ready and were not, and the first users to arrive paid for finding out.
// The check is one byte each way, every fifteen seconds per connection, which
// also keeps anything tracking idle connections along the route from forgetting
// them.
func (p *pool) liveness(ctx context.Context) {
	t := time.NewTicker(livenessTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.checkSpares(ctx, parkPingInterval, parkPingTimeout, false)
		}
	}
}

// checkSpares pings the spares that have not been proven alive for at least
// older, in parallel, and keeps the ones that answer. With all set it ignores
// the pacing and checks everything at once.
//
// A spare being checked is out of the pool, so no user can pick it up halfway
// through; the number out at once is capped so a quiet pool is never emptied by
// its own checking.
func (p *pool) checkSpares(ctx context.Context, older, timeout time.Duration, all bool) {
	now := time.Now()

	p.mu.Lock()
	limit := len(p.items)/4 + 1
	if all {
		limit = len(p.items)
	}
	var due []parked
	kept := p.items[:0]
	for _, it := range p.items {
		if len(due) < limit && now.Sub(it.lastPing) >= older {
			due = append(due, it)
		} else {
			kept = append(kept, it)
		}
	}
	for i := len(kept); i < len(p.items); i++ {
		p.items[i] = parked{}
	}
	p.items = kept
	atomic.StoreInt64(&p.statParked, int64(len(p.items)))
	p.mu.Unlock()

	if len(due) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, it := range due {
		wg.Add(1)
		go func(it parked) {
			defer wg.Done()
			if ctx.Err() != nil {
				_ = it.conn.Close()
				return
			}
			if err := probeParkedWithin(it.conn, timeout); err != nil {
				p.discard(it)
				return
			}
			it.lastPing = time.Now()
			p.putBack(it)
		}(it)
	}
	wg.Wait()
}

// putBack returns a checked spare to the pool, or straight to a user who is
// waiting for one.
func (p *pool) putBack(it parked) {
	p.mu.Lock()
	for len(p.waiters) > 0 {
		ch := p.waiters[0]
		p.waiters = p.waiters[1:]
		select {
		case ch <- it.conn:
			p.mu.Unlock()
			return
		default:
		}
	}
	if len(p.items) < p.maxSize && time.Since(it.at) < p.maxAge && socketAlive(it.conn) {
		p.items = append(p.items, it)
		atomic.StoreInt64(&p.statParked, int64(len(p.items)))
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	atomic.AddInt64(&p.statDiscarded, 1)
	_ = it.conn.Close()
}

// verifyAll checks every spare right now. Called when a user's activation timed
// out: one dead spare is usually not alone, and finding the rest in a second
// beats letting each following attempt discover them one at a time, four seconds
// apiece.
func (p *pool) verifyAll(ctx context.Context) {
	if !atomic.CompareAndSwapInt32(&p.verifying, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&p.verifying, 0)
	p.checkSpares(ctx, 0, verifyTimeout, true)
}

func probeParked(c net.Conn) error {
	return probeParkedWithin(c, parkPingTimeout)
}

// probeParkedWithin sends one byte and expects one back.
func probeParkedWithin(c net.Conn, timeout time.Duration) error {
	if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := c.Write([]byte{msgParkPing}); err != nil {
		return err
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	var pong [1]byte
	if _, err := io.ReadFull(c, pong[:]); err != nil {
		return err
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	if pong[0] != msgParkPong {
		if isRejection(pong[0]) {
			return describeRejection(pong[0])
		}
		return errBadAck
	}
	return nil
}

func (p *pool) closeAll() {
	p.mu.Lock()
	items := p.items
	p.items = nil
	waiters := p.waiters
	p.waiters = nil
	atomic.StoreInt64(&p.statParked, 0)
	p.mu.Unlock()

	for _, it := range items {
		_ = it.conn.Close()
	}
	for _, ch := range waiters {
		close(ch)
	}
}
