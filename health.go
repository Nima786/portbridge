package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Whether the route to the other server is really carrying data.
//
// Why this exists
//
// A tunnel used to decide it was healthy by counting its parked connections. That
// count measures the wrong thing. Parking a connection takes a handful of
// packets, and a route that lets a handful of packets through and then cuts the
// connection off, which is what filtering of a whole address tends to look like,
// leaves every parked connection looking perfectly fine. The status read "ready",
// the log said nothing, and every real user waited for a reply that never came.
//
// Two things are measured instead:
//
//   - what happens to real users: an activation that gets its confirmation is
//     proof, and one that times out is evidence against the route;
//   - a periodic transfer, larger than the few packets a filter allows, over the
//     same route a real user would take. It needs no user to be present, so a
//     quiet tunnel finds out too, and it works out which route to use when there
//     is more than one.

// pathState is the summary the menu shows.
type pathState int32

const (
	pathUnknown  pathState = iota // nothing measured yet
	pathOK                        // data flows
	pathDegraded                  // something is wrong but it is not clearly the route
	pathBlocked                   // connections open, data does not flow
)

func (s pathState) String() string {
	switch s {
	case pathOK:
		return "ok"
	case pathDegraded:
		return "degraded"
	case pathBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

const (
	// Activation timeouts in a row before the route is called degraded, and
	// before it is called blocked. Users' activations can time out for reasons
	// of their own now and then, so one is never enough.
	healthDegradedAfter = 3
	healthBlockedAfter  = 5

	// How often a standing problem is repeated in the log. State changes are
	// always logged at once.
	healthRemindEvery = 2 * time.Minute
)

// pathHealth is what the tunnel believes about the route to the other server.
type pathHealth struct {
	mu sync.Mutex

	state pathState
	note  string

	timeouts int // activations in a row that timed out
	closed   int // activations in a row that were refused outright

	lastOK     time.Time
	lastLogged time.Time

	hasBackup bool

	// nudge asks the path check to run now rather than wait for its turn.
	nudge chan struct{}
}

func newPathHealth(hasBackup bool) *pathHealth {
	return &pathHealth{hasBackup: hasBackup, nudge: make(chan struct{}, 1)}
}

// hint is what to do about a blocked route, which depends on what is configured.
func (h *pathHealth) hint() string {
	if h.hasBackup {
		return "A backup route is configured, so the tunnel will move to it."
	}
	return "This is the route being filtered, not a fault in PortBridge. Options: " +
		"a different foreign server or address, or a tunnel routed through a CDN."
}

// change records a new state and says so in the log, immediately when it is a
// change and at most every healthRemindEvery when it is not. Call with mu held.
func (h *pathHealth) change(s pathState, note string) {
	prev := h.state
	h.state = s
	h.note = note
	now := time.Now()

	switch {
	case s == prev:
		if (s == pathBlocked || s == pathDegraded) && now.Sub(h.lastLogged) >= healthRemindEvery {
			h.lastLogged = now
			log.Printf("still %s: %s", s, note)
		}
	case s == pathOK && (prev == pathBlocked || prev == pathDegraded):
		h.lastLogged = now
		log.Printf("the route to the other server is carrying data again")
	case s == pathBlocked:
		h.lastLogged = now
		log.Printf("connections to the other server open normally but data does not flow: %s %s", note, h.hint())
	case s == pathDegraded:
		h.lastLogged = now
		log.Printf("the route to the other server looks unhealthy: %s", note)
	}
}

// activationOK records that a real user got through.
func (h *pathHealth) activationOK() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.timeouts, h.closed = 0, 0
	h.lastOK = time.Now()
	if h.state != pathOK {
		h.change(pathOK, "")
	}
}

// activationFailed records that a real user could not be put on the tunnel.
//
// A timeout and an outright refusal mean different things and are counted
// apart. A timeout, with the connection apparently fine, is the signature of a
// route that has stopped carrying data. A refusal, where the other server closes
// at once, is far more often that server being unable to reach the service it
// publishes, which is not the route's doing.
func (h *pathHealth) activationFailed(err error) {
	// A refusal to do with settings or clocks says nothing about the route, and
	// has its own message. Counting it here would mislead.
	if errors.Is(err, errMuxMismatch) || errors.Is(err, errAuthSkew) || errors.Is(err, errAuthReplay) {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if isTimeout(err) {
		h.timeouts++
		h.closed = 0
	} else {
		h.closed++
		h.timeouts = 0
	}

	switch {
	case h.timeouts >= healthBlockedAfter:
		h.change(pathBlocked, fmt.Sprintf("%d users in a row waited for the other server and got no answer.", h.timeouts))
	case h.timeouts >= healthDegradedAfter:
		h.change(pathDegraded, fmt.Sprintf("%d users in a row waited for the other server and got no answer.", h.timeouts))
	case h.closed >= healthDegradedAfter:
		h.change(pathDegraded, fmt.Sprintf("the other server closed %d connections in a row as soon as a user arrived; "+
			"check that the service it publishes is running: %v", h.closed, err))
	}
	if h.timeouts >= healthDegradedAfter {
		h.poke()
	}
}

// probeResult records what a transfer check found.
func (h *pathHealth) probeResult(out probeOutcome) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch out.kind {
	case probePassed:
		h.timeouts = 0
		h.lastOK = time.Now()
		h.change(pathOK, "")
	case probeStalled:
		h.change(pathBlocked, "a test transfer over this route started and then stopped moving.")
	case probeUnsupported:
		// The other end hung up on the test. Most likely it is a version that
		// predates it, so nothing is concluded from it.
	default:
		h.change(pathDegraded, fmt.Sprintf("a test transfer over this route failed: %v", out.err))
	}
}

// poke asks the path check to run soon. Non-blocking; a request already pending
// is enough.
func (h *pathHealth) poke() {
	select {
	case h.nudge <- struct{}{}:
	default:
	}
}

// provenRecently reports whether data was seen flowing within the last d, by a
// user getting through or a check passing.
func (h *pathHealth) provenRecently(d time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state == pathOK && !h.lastOK.IsZero() && time.Since(h.lastOK) < d
}

// isBlocked reports whether users should stop waiting on this route.
func (h *pathHealth) isBlocked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state == pathBlocked
}

// snapshot is what the status file publishes.
func (h *pathHealth) snapshot() (state, note string, lastOKSeconds int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	lastOKSeconds = -1
	if !h.lastOK.IsZero() {
		lastOKSeconds = int64(time.Since(h.lastOK).Seconds())
	}
	return h.state.String(), h.note, lastOKSeconds
}

// ---------------------------------------------------------------------------
// The transfer check
// ---------------------------------------------------------------------------

// probeKind is how a transfer check ended.
type probeKind int

const (
	probePassed      probeKind = iota
	probeStalled               // started, then stopped moving
	probeUnsupported           // the other end hung up at once
	probeFailed                // anything else
)

type probeOutcome struct {
	kind probeKind
	err  error
}

// pathCheckSize is how much is moved each way. It has to be more than the few
// packets a per-connection filter allows: measured on a real route that cut
// every connection after six packets, downloads stopped above about 14 KB and
// uploads above about 8 KB, so 32 KB each way cannot slip through.
const pathCheckSize = 32 * 1024

// pathCheckIdle is how long a check may go without any progress before it is
// called stalled. Progress rather than total time, so a slow but working link
// is never mistaken for a blocked one, while a route that stops moving is caught
// after this long however large the transfer. A variable so tests can shorten it.
var pathCheckIdle = newTunable(8 * time.Second)

// tunable is a duration that tests may shorten while background goroutines of an
// earlier test are still winding down, so it is read and written atomically.
type tunable struct{ ns atomic.Int64 }

func newTunable(d time.Duration) *tunable {
	t := &tunable{}
	t.ns.Store(int64(d))
	return t
}

func (t *tunable) get() time.Duration  { return time.Duration(t.ns.Load()) }
func (t *tunable) set(d time.Duration) { t.ns.Store(int64(d)) }

// pathCheckBudget is the longest a whole check may take, however slowly it
// progresses.
const pathCheckBudget = 60 * time.Second

// runPathCheck moves pathCheckSize bytes down and the same up over an
// authenticated speed-test connection. It speaks the existing speed-test
// protocol, so any peer that can run a speed test can answer it.
func runPathCheck(c net.Conn) error {
	started := time.Now()
	// Each step gets a fresh idle allowance, up to the overall budget.
	step := func() {
		d := time.Now().Add(pathCheckIdle.get())
		if limit := started.Add(pathCheckBudget); d.After(limit) {
			d = limit
		}
		_ = c.SetDeadline(d)
	}

	// Download: ask for the bytes, wait for the go-ahead, read them all.
	var hdr [5]byte
	hdr[0] = 0x02
	binary.BigEndian.PutUint32(hdr[1:], pathCheckSize)
	step()
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	var ready [1]byte
	if _, err := io.ReadFull(c, ready[:]); err != nil {
		return err
	}
	buf := make([]byte, 8*1024)
	for left := pathCheckSize; left > 0; {
		step()
		want := len(buf)
		if want > left {
			want = left
		}
		n, err := c.Read(buf[:want])
		left -= n
		if err != nil && left > 0 {
			return err
		}
	}

	// Upload: announce it, wait for the go-ahead, send the bytes, wait for the
	// receipt.
	hdr[0] = 0x03
	step()
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, ready[:]); err != nil {
		return err
	}
	chunk := make([]byte, pathCheckSize)
	for i := range chunk {
		chunk[i] = byte(i*7 + 3)
	}
	for sent := 0; sent < len(chunk); {
		step()
		end := sent + 8*1024
		if end > len(chunk) {
			end = len(chunk)
		}
		n, err := c.Write(chunk[sent:end])
		sent += n
		if err != nil {
			return err
		}
	}
	step()
	if _, err := io.ReadFull(c, ready[:]); err != nil {
		return err
	}

	_, _ = c.Write([]byte{0x04})
	return nil
}

// classifyProbe turns the error from a check into an outcome. Only a stall is
// evidence against the route: the other end hanging up at once says it does not
// understand the test, which is what an older version does.
func classifyProbe(err error, sinceStart time.Duration) probeOutcome {
	switch {
	case err == nil:
		return probeOutcome{kind: probePassed}
	case isTimeout(err):
		return probeOutcome{kind: probeStalled, err: err}
	case (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && sinceStart < 3*time.Second:
		return probeOutcome{kind: probeUnsupported, err: err}
	default:
		return probeOutcome{kind: probeFailed, err: err}
	}
}

// ---------------------------------------------------------------------------
// The prober
// ---------------------------------------------------------------------------

const (
	// How often an idle route that seems healthy is checked, and how often one
	// in trouble is. A check moves 64 KB, so the slow rate costs about 20 MB a
	// day and nothing at all while real users are getting through (see run).
	probeEveryHealthy = 5 * time.Minute

	// Stalled checks in a row on the route in use before it is set aside.
	// Two, so a single unlucky check never moves traffic.
	probeStallsToSwitch = 2
)

// probeEveryTrouble is how often a route in trouble is checked, and
// probeFirstWait how long after start the first check waits. Variables so tests
// can shorten them.
var (
	probeEveryTrouble = newTunable(15 * time.Second)
	probeFirstWait    = newTunable(4 * time.Second)
)

// prober checks the routes of a tunnel that dials, and moves traffic between
// them. Only the dialling side has routes to choose between, so only it has one.
type prober struct {
	cfg    *Config
	routes *router
	health *pathHealth

	// onSwitch is called when the route in use changed, so connections already
	// made over the old one can be dropped and rebuilt over the new one.
	onSwitch func()

	stalls []int32 // per route: consecutive stalled checks
	rng    *rand.Rand
	logs   *throttled
}

func newProber(cfg *Config, routes *router, health *pathHealth, onSwitch func()) *prober {
	return &prober{
		cfg:      cfg,
		routes:   routes,
		health:   health,
		onSwitch: onSwitch,
		stalls:   make([]int32, routes.count()),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		logs:     newThrottled(),
	}
}

// checkRoute runs one transfer check over route i.
func (p *prober) checkRoute(i int) probeOutcome {
	started := time.Now()
	raw, err := p.routes.dialRoute(i, 6*time.Second)
	if err != nil {
		// Could not even connect: that is the easy kind of block, and the
		// ordinary dial path already handles it.
		return probeOutcome{kind: probeFailed, err: err}
	}
	tuneSocket(raw)
	rc := p.routes.routeConfig(i)
	c, err := wrapDialPurpose(raw, rc, authPurposeSpeedtest)
	if err != nil {
		_ = raw.Close()
		return classifyHandshake(err)
	}
	defer c.Close()

	if err := sendAuthPurpose(c, p.cfg.secret, authPurposeSpeedtest); err != nil {
		return classifyHandshake(err)
	}
	return classifyProbe(runPathCheck(c), time.Since(started))
}

// classifyHandshake handles a failure before the check proper began. A handshake
// that times out is the same symptom as a transfer that stalls: it got through
// the first few packets and no further.
func classifyHandshake(err error) probeOutcome {
	if isTimeout(err) {
		return probeOutcome{kind: probeStalled, err: err}
	}
	return probeOutcome{kind: probeFailed, err: err}
}

// cycle checks the route in use, and any route being held back that is due for
// another chance. Returns whether traffic was moved.
func (p *prober) cycle() (moved bool) {
	cur := p.routes.currentIndex()

	// Real users getting through is better proof than any test, and free. While
	// that is happening recently, the test over the route in use is skipped;
	// routes held back are still tried on their own schedule below.
	if !p.health.provenRecently(probeEveryHealthy) {
		out := p.checkRoute(cur)
		p.health.probeResult(out)
		moved = p.judge(cur, out)
	}

	// Routes held back for stalling are only brought back after a transfer over
	// them succeeds, never on a timer alone.
	for _, j := range p.routes.dueForTrial() {
		trial := p.checkRoute(j)
		if trial.kind == probePassed {
			if p.routes.restore(j) {
				moved = true
			}
			continue
		}
		if trial.kind == probeStalled || trial.kind == probeFailed {
			p.routes.extendHold(j, routeStallHold)
		}
	}

	if moved && p.onSwitch != nil {
		p.onSwitch()
	}
	return moved
}

// judge acts on the result of a check over the route in use. Returns true if
// traffic was moved to another route.
func (p *prober) judge(cur int, out probeOutcome) (moved bool) {
	switch out.kind {
	case probePassed:
		atomic.StoreInt32(&p.stalls[cur], 0)
		p.routes.handshakeOK(cur)
	case probeStalled:
		n := atomic.AddInt32(&p.stalls[cur], 1)
		if n >= probeStallsToSwitch && p.routes.count() > 1 {
			atomic.StoreInt32(&p.stalls[cur], 0)
			p.routes.setAside(cur, routeStallHold, "a test transfer stalled")
			moved = true
		}
	case probeFailed:
		p.routes.handshakeFailed(cur, out.err)
	}
	return moved
}

// run checks the routes until the context ends.
func (p *prober) run(ctx context.Context) {
	// A moment to let the first connections come up, so the first check does
	// not race the start of the tunnel.
	wait := probeFirstWait.get()
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.health.nudge:
			timer.Stop()
		case <-timer.C:
		}

		p.cycle()

		state, _, _ := p.health.snapshot()
		if state == pathOK.String() || state == pathUnknown.String() {
			// Spread the checks of many tunnels on one machine apart.
			wait = probeEveryHealthy + time.Duration(p.rng.Int63n(int64(60*time.Second)))
		} else {
			wait = probeEveryTrouble.get()
		}
		// While traffic is on a backup route, the preferred one keeps being
		// tried, so the way back is found promptly when the block lifts.
		if p.routes.currentIndex() != 0 && wait > routeTrialEvery {
			wait = routeTrialEvery
		}
	}
}
