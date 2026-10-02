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

	// waitForOffer is how long a user waits for the origin to supply a
	// connection in reverse mode before giving up.
	waitForOffer time.Duration

	log *throttled

	// lastErr remembers why the most recent attempt to build a spare failed.
	lastErr atomic.Value

	// Counters, read by the status writer.
	statParked    int64
	statOffered   int64
	statDiscarded int64
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
			atomic.AddInt64(&p.statDiscarded, 1)
			_ = it.conn.Close()
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

	for {
		if ctx.Err() != nil {
			return
		}
		p.evict()
		p.probeKeepalives(ctx)

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

func (p *pool) evict() {
	p.mu.Lock()
	original := p.items
	kept := original[:0]
	var dead []net.Conn
	for _, it := range original {
		if time.Since(it.at) < p.maxAge && socketAlive(it.conn) {
			kept = append(kept, it)
		} else {
			dead = append(dead, it.conn)
		}
	}
	for i := len(kept); i < len(original); i++ {
		original[i] = parked{}
	}
	p.items = kept
	atomic.StoreInt64(&p.statParked, int64(len(p.items)))
	p.mu.Unlock()

	for _, c := range dead {
		atomic.AddInt64(&p.statDiscarded, 1)
		_ = c.Close()
	}
}

func (p *pool) probeKeepalives(ctx context.Context) {
	// Pick at most 2 items that need keepalive per cycle to avoid blocking users
	const maxProbesPerCycle = 2
	var candidates []parked

	p.mu.Lock()
	now := time.Now()
	for i := 0; i < len(p.items); i++ {
		it := p.items[i]
		if needsKeepalive(it.conn) && now.Sub(it.lastPing) >= parkPingInterval {
			candidates = append(candidates, it)
			p.items = append(p.items[:i], p.items[i+1:]...)
			i--
			if len(candidates) >= maxProbesPerCycle {
				break
			}
		}
	}
	atomic.StoreInt64(&p.statParked, int64(len(p.items)))
	p.mu.Unlock()

	if len(candidates) == 0 {
		return
	}

	for _, it := range candidates {
		if ctx.Err() != nil {
			_ = it.conn.Close()
			continue
		}

		err := probeParked(it.conn)
		if err != nil {
			atomic.AddInt64(&p.statDiscarded, 1)
			_ = it.conn.Close()
			continue
		}

		it.lastPing = time.Now()

		p.mu.Lock()
		handed := false
		for len(p.waiters) > 0 {
			ch := p.waiters[0]
			p.waiters = p.waiters[1:]
			select {
			case ch <- it.conn:
				handed = true
				break
			default:
			}
			if handed {
				break
			}
		}
		if !handed {
			if len(p.items) < p.maxSize && time.Since(it.at) < p.maxAge && socketAlive(it.conn) {
				p.items = append(p.items, it)
				atomic.StoreInt64(&p.statParked, int64(len(p.items)))
			} else {
				_ = it.conn.Close()
				atomic.AddInt64(&p.statDiscarded, 1)
			}
		}
		p.mu.Unlock()
	}
}

func probeParked(c net.Conn) error {
	if err := c.SetWriteDeadline(time.Now().Add(parkPingTimeout)); err != nil {
		return err
	}
	if _, err := c.Write([]byte{msgParkPing}); err != nil {
		return err
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	if err := c.SetReadDeadline(time.Now().Add(parkPingTimeout)); err != nil {
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
