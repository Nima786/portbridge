package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Multiplexing: many user sessions sharing a few long-lived connections across
// the border, instead of one connection per session.
//
// Why it is worth having
//
//	A busy tunnel without it holds hundreds of simultaneous connections between
//	the same two addresses on the same port. That pattern is itself a signal, no
//	matter how well each individual connection is disguised, and on a restricted
//	route the sheer number of connection setups is often what gets noticed first.
//	With multiplexing the two servers hold a handful of connections that stay up
//	for hours, which is what an ordinary long-lived web application looks like.
//
// Why it is a choice
//
//	Everything shares one TCP connection, so a lost packet stalls every session
//	riding on it until it is resent, not just the one that lost data. On a lossy
//	intercontinental route that is a real cost, and it is the reason this is
//	offered as a choice. The engine itself defaults to off; the menu suggests it
//	for the disguises where opening a fresh connection per user is the expensive
//	part (websocket, gRPC, KCP). Several links rather than one limit the damage,
//	but they do not remove it.
//
// What this layer does not change
//
//	It hands back things that behave like ordinary connections, so the rest of
//	the program is unaware of it. The session handshake, the confirmation that
//	the far side really reached the service, the retry when it does not, and the
//	byte shifting all work exactly as they do on a real connection.
//
// Shape of the protocol
//
//	frame: [1B type][4B stream id BE][2B payload length BE][payload]
//
//	Only the edge ever opens a stream, because only the edge knows when a user
//	has arrived. That removes any question of the two ends picking the same
//	stream number, whichever of them dialled.
//
// Frame types deliberately start well clear of the one-byte session signals in
// auth.go, and share no value with them.
//
// That is not tidiness. If one end shares connections and the other does not,
// they will talk past each other, and what happens next depends entirely on these
// numbers. Overlapping values were read as a valid signal by the other side,
// which then went on to open a real connection to the service and reply, and the
// muddle only surfaced later as an unexplained end-of-file. Distinct values mean
// the first frame either end sees is plainly not what it expected, so it refuses
// the connection and says so.
//
// The pairing code already carries the choice, so the two ends cannot disagree by
// accident. This is for the case where someone edits a settings file by hand.
const (
	muxOpen        byte = 0x21 // edge -> origin: a new session is starting
	muxData        byte = 0x22 // payload for one stream
	muxCredit      byte = 0x23 // 4B: this many more bytes may be sent to me
	muxFin         byte = 0x24 // I have finished sending on this stream
	muxReset       byte = 0x25 // this stream is over
	muxPing        byte = 0x26 // is this link still alive?
	muxPong        byte = 0x27 // yes
	muxTeardown    byte = 0x28 // edge -> origin: delete this tunnel
	muxTeardownAck byte = 0x29 // origin -> edge: confirm teardown
)

const (
	muxHeaderLen = 7

	// One frame's worth of payload. Kept at the size of the copy buffer used for
	// shifting bytes, so a full read becomes exactly one frame.
	muxMaxPayload = 32 * 1024

	// How much a sender may have outstanding on one stream before waiting for the
	// reader to catch up. Without a limit, one fast download would let the far
	// side pile up unbounded data in memory on behalf of a slow user.
	//
	// The limit cannot be a single fixed number, and getting that wrong was
	// costly. A sender may have at most one window in flight per round trip, so
	// the window divided by the round trip IS the speed ceiling: 512 KB across a
	// 90 ms route caps one session near 45 Mbit/s no matter how fast the link is.
	// Measured against another tunnel on a real route, that made a large download
	// five times slower than it should have been while the link sat idle.
	//
	// So a session starts small and doubles, but only while its reader is keeping
	// up, and only while the link it rides on has memory to spare. A session that
	// wants speed gets it; the many short ones stay cheap; and the total a link
	// can tie up stays bounded.
	muxWindowStart = 256 * 1024
	muxWindowMax   = 4 * 1024 * 1024

	// How much extra buffering all the sessions on one link may take between
	// them. This is the real memory limit, and it is why growing is safe.
	muxGrowBudget = 16 * 1024 * 1024

	// A link with nothing on it is indistinguishable from a link that has
	// silently died, which on these routes happens often. Pinging proves it
	// works and keeps anything tracking connections along the way from
	// forgetting it.
	//
	// Kept short on purpose: a link that has silently died is otherwise still
	// counted as "up" while users land on it and wait.
	muxPingEvery = 15 * time.Second
	muxPingGrace = 50 * time.Second

	// How long a link is avoided after a session on it failed to start, and how
	// long it is given to answer a check before being dropped.
	muxSuspectFor = 30 * time.Second
	muxCheckWait  = 6 * time.Second

	// How long the origin waits, after the edge opens a stream, for the session
	// handshake that should follow immediately.
	muxActivateWait = 15 * time.Second

	// How long a user waits for a link to appear when none is up yet.
	muxWaitForLink = 5 * time.Second

	// Queue depths for the one goroutine that owns the wire. Control frames get
	// their own queue, and priority, for a reason worth stating: they are tiny,
	// they include the credit that lets a stalled sender continue, and if they
	// had to queue behind a backlog of somebody's download then a busy link
	// would strangle itself.
	muxCtrlQueue = 256
	muxDataQueue = 8

	// How long to wait to queue an end-of-session marker before concluding the
	// link is stuck.
	muxOrderedWait = 30 * time.Second
)

var (
	// errNoCarrier deliberately wraps errNoSpare, so the edge treats "no link is
	// up" the same way it treats "no spare connection is available": as
	// something retrying cannot fix.
	errNoCarrier = fmt.Errorf("%w: no multiplexed link to the other server is up", errNoSpare)

	errMuxClosed   = errors.New("the multiplexed link closed")
	errMuxOverflow = errors.New("the other end sent more than the agreed amount of data")
	errMuxBacklog  = errors.New("the multiplexed link stopped accepting anything")
	errStreamGone  = errors.New("the session was ended by the other end")

	// errRouteChanged is why links are closed when the path to the other server
	// is switched to a different route.
	errRouteChanged = errors.New("the route to the other server changed")
)

// ---------------------------------------------------------------------------
// Deadlines
// ---------------------------------------------------------------------------

// deadline makes SetReadDeadline and SetWriteDeadline work on a stream, which
// matters more than it sounds: the existing code interrupts a blocked read by
// moving its deadline to now, and that has to keep working when the connection
// is virtual.
//
// The channel is what a blocked reader waits on. It is closed when the time
// passes, and replaced when a fresh deadline is set after an expired one.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	expire chan struct{}
	gen    uint64 // bumped whenever a timer is replaced or cancelled
}

func newDeadline() *deadline {
	return &deadline{expire: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	// Any timer already running but not yet through the lock is now stale.
	d.gen++

	expired := false
	select {
	case <-d.expire:
		expired = true
	default:
	}

	if t.IsZero() {
		// No deadline. Anything waiting on an already-fired channel needs a
		// fresh one, or every later read would return immediately.
		if expired {
			d.expire = make(chan struct{})
		}
		return
	}

	if wait := time.Until(t); wait > 0 {
		if expired {
			d.expire = make(chan struct{})
		}
		ch := d.expire
		d.gen++
		gen := d.gen
		d.timer = time.AfterFunc(wait, func() { d.fire(ch, gen) })
		return
	}

	// Already in the past: wake anything waiting straight away.
	if !expired {
		close(d.expire)
	}
}

// fire closes ch, unless it has been closed already. The timer runs on its own
// goroutine, so it can race with set: both may decide the same channel needs
// closing, and closing twice panics. Checking under the lock settles it.
func (d *deadline) fire(ch chan struct{}, gen uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ch != d.expire || gen != d.gen {
		// A newer deadline has taken over; this timer's moment has passed.
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expire
}

// timeoutError is what a stream returns when a deadline passes. It reports
// itself as a timeout, which the rest of the program checks for to tell a slow
// path apart from a broken one.
type timeoutError struct{}

func (timeoutError) Error() string   { return os.ErrDeadlineExceeded.Error() }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
func (timeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }

// ---------------------------------------------------------------------------
// One stream
// ---------------------------------------------------------------------------

// muxStream is one session riding on a carrier, presented as an ordinary
// connection.
type muxStream struct {
	id uint32
	c  *carrier

	// Receiving. Unread bytes are rbuf[rstart:rend], and rbuf is always kept at
	// its full length so the space after rend can be written into directly.
	//
	// An explicit pair of offsets rather than appending to a slice and reslicing
	// it. Appending looked harmless and was the single most expensive thing on
	// this path: growing the slice and shifting its contents accounted for
	// nearly a third of the processor time on a large transfer. With offsets, a
	// reader that keeps up leaves the buffer empty each time, so it is reset to
	// the start instead of growing, and one frame's worth of space serves the
	// whole session.
	rmu        sync.Mutex
	rbuf       []byte
	rstart     int
	rend       int
	uncredited int  // consumed by the reader, not yet credited back
	finished   bool // the far side has finished sending
	rwin       int  // how much the far side may have in flight to us
	rtaken     int  // how much of the link's grow budget this session holds
	rreleased  bool // the session is over and its budget has been handed back
	rready     chan struct{}

	// Sending.
	wmu      sync.Mutex
	window   int32 // bytes we may still send; read and written atomically
	windowUp chan struct{}
	needOpen bool // the open frame has not been sent yet
	wClosed  bool

	targetPort uint16

	dead     chan struct{} // the stream or its carrier has finished
	deadOnce sync.Once
	err      atomic.Value // error: why it finished

	rdl *deadline
	wdl *deadline
}

func (s *muxStream) TargetPort() uint16 { return s.targetPort }

func newMuxStream(c *carrier, id uint32, opener bool) *muxStream {
	return &muxStream{
		id:       id,
		c:        c,
		rready:   make(chan struct{}, 1),
		rwin:     muxWindowStart,
		window:   muxWindowStart,
		windowUp: make(chan struct{}, 1),
		needOpen: opener,
		dead:     make(chan struct{}),
		rdl:      newDeadline(),
		wdl:      newDeadline(),
	}
}

func poke(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *muxStream) kill(err error) {
	s.deadOnce.Do(func() {
		if err != nil {
			s.err.Store(err)
		}
		close(s.dead)
		s.releaseGrow()
	})
	poke(s.rready)
	poke(s.windowUp)
}

// releaseGrow hands this session's share of the link's buffering back, once, so
// a long-lived link does not run out of room for later sessions.
func (s *muxStream) releaseGrow() {
	s.rmu.Lock()
	taken := s.rtaken
	s.rtaken = 0
	// From here on nothing may take more: a reader draining the last buffered
	// bytes of a finished session used to take budget that was never returned,
	// and a long-lived link slowly ran out of room to grow.
	s.rreleased = true
	s.rmu.Unlock()
	s.c.returnGrow(taken)
}

func (s *muxStream) reason() error {
	if e, ok := s.err.Load().(error); ok && e != nil {
		return e
	}
	return errMuxClosed
}

// deliver hands the stream data that arrived for it. Called only from the
// carrier's reader, so it must never block.
//
// It copies, and has to: the reader hands over a buffer it reuses for the next
// frame, so anything kept must be kept somewhere of our own.
func (s *muxStream) deliver(p []byte) error {
	s.rmu.Lock()
	if s.rend-s.rstart+len(p) > s.rwin {
		s.rmu.Unlock()
		return errMuxOverflow
	}
	s.stash(p)
	s.rmu.Unlock()
	poke(s.rready)
	return nil
}

// stash puts p at the end of the receive buffer, making room first. Called with
// rmu held.
//
// Room is found in the cheapest way that works: usually there is space already;
// otherwise sliding the unread bytes back to the front is enough, which is the
// normal case for a reader that is keeping up; only a reader falling behind
// makes the buffer bigger.
func (s *muxStream) stash(p []byte) {
	held := s.rend - s.rstart

	if len(s.rbuf)-s.rend < len(p) {
		switch {
		case len(s.rbuf)-held >= len(p):
			copy(s.rbuf, s.rbuf[s.rstart:s.rend])
		default:
			// Doubling, so a steady stream stops reallocating after a couple of
			// rounds while a short session keeps a buffer its own size. A fixed
			// floor of one frame's worth was tried and was worse: the many short
			// sessions each churned thirty-two kilobytes to hold a few hundred
			// bytes.
			size := held + len(p)
			if grow := 2 * len(s.rbuf); size < grow {
				size = grow
			}
			grown := make([]byte, size)
			copy(grown, s.rbuf[s.rstart:s.rend])
			s.rbuf = grown
		}
		s.rstart, s.rend = 0, held
	}

	copy(s.rbuf[s.rend:], p)
	s.rend += len(p)
}

// buffered reports how much has arrived and not yet been read. Called with rmu
// held.
func (s *muxStream) buffered() int { return s.rend - s.rstart }

// finish records that the far side has stopped sending. Anything already
// buffered is still readable first, which is what makes a clean half-close work.
func (s *muxStream) finish() {
	s.rmu.Lock()
	s.finished = true
	s.rmu.Unlock()
	poke(s.rready)
}

func (s *muxStream) Read(p []byte) (int, error) {
	for {
		s.rmu.Lock()
		if s.buffered() > 0 {
			n := copy(p, s.rbuf[s.rstart:s.rend])
			s.rstart += n
			drained := s.rstart == s.rend
			if drained {
				s.rstart, s.rend = 0, 0
				// Let go of a buffer that only grew to absorb a backlog, so a
				// long session does not hold its peak size for ever. Anything up
				// to one frame's worth is kept, because that is the buffer being
				// reused from one frame to the next.
				if len(s.rbuf) > muxMaxPayload {
					s.rbuf = nil
				}
			}
			s.uncredited += n
			give := 0
			if s.uncredited >= s.rwin/2 {
				give = s.uncredited
				s.uncredited = 0
			}
			// The reader has taken everything there was, so the far side is
			// being held back by the window rather than by us. Widen it, if the
			// link can spare the memory, and pass the extra on as credit.
			if drained && !s.rreleased && s.rwin < muxWindowMax {
				want := s.rwin
				if want > muxWindowMax-s.rwin {
					want = muxWindowMax - s.rwin
				}
				if got := s.c.takeGrow(want); got > 0 {
					s.rwin += got
					s.rtaken += got
					give += got
				}
			}
			s.rmu.Unlock()

			if give > 0 {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], uint32(give))
				// Sent without waiting: a reader must never be held up by the
				// state of the wire, or a full link could never drain.
				s.c.sendControl(muxFrame{typ: muxCredit, id: s.id, payload: b[:]})
			}
			return n, nil
		}
		done := s.finished
		s.rmu.Unlock()

		if done {
			return 0, io.EOF
		}

		select {
		case <-s.rready:
		case <-s.dead:
			// Buffered data still counts: loop once more so the last of it is
			// handed over before reporting the end.
			s.rmu.Lock()
			pending := s.buffered() > 0
			s.rmu.Unlock()
			if pending {
				continue
			}
			if errors.Is(s.reason(), errStreamGone) {
				return 0, io.EOF
			}
			return 0, s.reason()
		case <-s.rdl.wait():
			return 0, timeoutError{}
		}
	}
}

func (s *muxStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()

	if s.wClosed {
		return 0, io.ErrClosedPipe
	}

	sent := 0
	for sent < len(p) {
		select {
		case <-s.dead:
			return sent, s.reason()
		default:
		}

		room := int(atomic.LoadInt32(&s.window))
		if room <= 0 {
			select {
			case <-s.windowUp:
			case <-s.dead:
				return sent, s.reason()
			case <-s.wdl.wait():
				return sent, timeoutError{}
			}
			continue
		}

		n := len(p) - sent
		if n > muxMaxPayload {
			n = muxMaxPayload
		}
		if n > room {
			n = room
		}

		frames := []muxFrame{{typ: muxData, id: s.id, payload: p[sent : sent+n]}}
		if s.needOpen {
			// The open frame rides with the first data, so starting a session
			// costs one write rather than two. Nothing waits on the open by
			// itself, so there is no reason to send it alone.
			s.needOpen = false
			var openPayload []byte
			if s.targetPort > 0 {
				var pb [2]byte
				binary.BigEndian.PutUint16(pb[:], s.targetPort)
				openPayload = pb[:]
			}
			frames = []muxFrame{{typ: muxOpen, id: s.id, payload: openPayload}, frames[0]}
		}
		if err := s.c.sendData(s, frames...); err != nil {
			return sent, err
		}
		atomic.AddInt32(&s.window, int32(-n))
		sent += n
	}
	return sent, nil
}

// grant records credit returned by the reader on the far side.
func (s *muxStream) grant(n uint32) {
	atomic.AddInt32(&s.window, int32(n))
	poke(s.windowUp)
}

// CloseWrite finishes sending without ending the stream, so the other direction
// can still deliver what it has left. Truncated downloads come from getting this
// wrong.
func (s *muxStream) CloseWrite() error {
	s.wmu.Lock()
	if s.wClosed {
		s.wmu.Unlock()
		return nil
	}
	s.wClosed = true
	never := s.needOpen
	s.needOpen = false
	s.wmu.Unlock()

	if never {
		// Nothing was ever sent, so the far side does not know this stream
		// exists. Announcing it only to immediately finish is pointless.
		return nil
	}
	s.c.sendOrdered(muxFrame{typ: muxFin, id: s.id})
	return nil
}

func (s *muxStream) Close() error {
	first := false
	s.deadOnce.Do(func() {
		first = true
		s.err.Store(errMuxClosed)
		close(s.dead)
		s.releaseGrow()
	})
	poke(s.rready)
	poke(s.windowUp)

	if !first {
		return nil
	}

	s.wmu.Lock()
	never := s.needOpen
	s.needOpen = false
	s.wmu.Unlock()

	s.c.forget(s.id)
	if !never {
		// Queued behind this stream's own data, so the far side reads all of it
		// before learning the session is over.
		s.c.sendOrdered(muxFrame{typ: muxReset, id: s.id})
	}
	return nil
}

func (s *muxStream) LocalAddr() net.Addr  { return s.c.conn.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr { return s.c.conn.RemoteAddr() }

func (s *muxStream) SetDeadline(t time.Time) error {
	s.rdl.set(t)
	s.wdl.set(t)
	return nil
}

func (s *muxStream) SetReadDeadline(t time.Time) error {
	s.rdl.set(t)
	return nil
}

func (s *muxStream) SetWriteDeadline(t time.Time) error {
	s.wdl.set(t)
	return nil
}

// ---------------------------------------------------------------------------
// One carrier
// ---------------------------------------------------------------------------

type muxFrame struct {
	typ     byte
	id      uint32
	payload []byte
}

// frameBufSize is the size of a pooled frame buffer: a session-opening frame
// followed by a full frame of data, which is the largest thing ever queued.
const frameBufSize = 2*muxHeaderLen + muxMaxPayload

// framePool lends out the buffers data frames are assembled in.
//
// A frame has to be copied rather than pointed at, because it is queued for the
// one goroutine that owns the wire while the caller goes back to reusing its own
// buffer. The copy is unavoidable; allocating fresh room for it every time was
// not.
//
// Only large frames come from here. Handing a credit or a keepalive a buffer
// meant for a full frame of data was measurably worse than letting it allocate
// its own dozen bytes: those small frames are the most frequent thing on a busy
// link, and each one was churning thirty-two kilobytes.
var framePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, frameBufSize)
		return &b
	},
}

// frameSmall is the size below which a frame is cheaper to allocate outright
// than to borrow room for. Every control frame is far below it.
const frameSmall = 512

func encodeFrames(frames ...muxFrame) *[]byte {
	total := 0
	for _, f := range frames {
		total += muxHeaderLen + len(f.payload)
	}

	var buf *[]byte
	switch {
	case total <= frameSmall:
		small := make([]byte, 0, total)
		buf = &small
	default:
		buf = framePool.Get().(*[]byte)
		if cap(*buf) < total {
			grown := make([]byte, 0, total)
			buf = &grown
		}
	}

	b := (*buf)[:0]
	for _, f := range frames {
		var hdr [muxHeaderLen]byte
		hdr[0] = f.typ
		binary.BigEndian.PutUint32(hdr[1:5], f.id)
		binary.BigEndian.PutUint16(hdr[5:7], uint16(len(f.payload)))
		b = append(b, hdr[:]...)
		b = append(b, f.payload...)
	}
	*buf = b
	return buf
}

// recycleFrame returns a frame buffer for reuse. Only the goroutine that has
// finished with a buffer may call it, which is the one that wrote it to the wire
// or the one that gave up on queueing it.
func recycleFrame(b *[]byte) {
	if cap(*b) == frameBufSize {
		*b = (*b)[:0]
		framePool.Put(b)
	}
}

// carrier is one real connection across the border, carrying many streams.
//
// Exactly one goroutine reads the connection and exactly one writes it. That
// split is what keeps the whole thing from seizing up: if the reader could also
// write, then two ends both blocked on a full wire would wait for each other for
// ever, and neither would ever read the other's data to clear it.
type carrier struct {
	conn net.Conn

	ctrl chan *[]byte
	data chan *[]byte

	mu      sync.Mutex
	streams map[uint32]*muxStream
	nextID  uint32
	closed  bool

	incoming chan *muxStream
	done     chan struct{}
	doneOnce sync.Once

	lastHeard int64 // unix nano, read and written atomically

	// onTeardown is called if the remote peer asks to teardown the tunnel.
	onTeardown    func()
	teardownAckCh chan struct{}

	// growLeft is the extra buffering the sessions on this link may still take
	// between them. It is what keeps widening a window safe: a session can only
	// grow while this lasts, so the memory one link can tie up has a ceiling
	// however many sessions ask for speed at once.
	growLeft int64

	// born is when the link came up. A link that dies within moments of coming
	// up says something is wrong with the route or the settings, and is treated
	// differently from one that ran for hours.
	born time.Time

	// suspectUntil (unix nano, atomic) is set when a session on this link failed
	// to start. Until it passes, other links are preferred, and a check is sent
	// to find out whether this one is still alive.
	suspectUntil int64
	checking     int32

	// onDone is told once, when the link finishes, how long it lived and why.
	onDone func(age time.Duration, err error)
}

// markSuspect notes that a session on this link failed to start, steers new
// sessions elsewhere for a while, and asks the other end to answer a ping. If no
// answer comes the link is dropped instead of left to fail users one by one.
func (c *carrier) markSuspect() {
	atomic.StoreInt64(&c.suspectUntil, time.Now().Add(muxSuspectFor).UnixNano())
	if !atomic.CompareAndSwapInt32(&c.checking, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(&c.checking, 0)
		before := atomic.LoadInt64(&c.lastHeard)
		c.sendControl(muxFrame{typ: muxPing})
		t := time.NewTimer(muxCheckWait)
		defer t.Stop()
		select {
		case <-c.done:
		case <-t.C:
			if atomic.LoadInt64(&c.lastHeard) == before {
				c.fail(fmt.Errorf("the other server did not answer a check within %s", muxCheckWait))
			}
		}
	}()
}

func (c *carrier) isSuspect() bool {
	return time.Now().UnixNano() < atomic.LoadInt64(&c.suspectUntil)
}

// suspect is called by the edge when a session on this stream failed to start.
func (s *muxStream) suspect() { s.c.markSuspect() }

// checkFirstFrame looks at the very first byte the other end sent on a shared
// link. Anything that is not a shared-link frame means the two ends disagree
// about settings, and the useful thing is to say so by name.
func checkFirstFrame(typ byte) error {
	switch {
	case typ >= muxOpen && typ <= muxTeardownAck:
		return nil
	case isRejection(typ):
		return describeRejection(typ)
	case typ == msgActivate || typ == msgActivatePort || typ == msgParkPing:
		return errMuxOnlyHere
	default:
		return fmt.Errorf("the other server sent something that is not shared-connection data (0x%02x); "+
			"check that both servers have the same settings", typ)
	}
}

// takeGrow hands out up to n bytes of this link's grow budget, returning how much
// was actually available.
func (c *carrier) takeGrow(n int) int {
	if n <= 0 {
		return 0
	}
	for {
		left := atomic.LoadInt64(&c.growLeft)
		if left <= 0 {
			return 0
		}
		take := int64(n)
		if take > left {
			take = left
		}
		if atomic.CompareAndSwapInt64(&c.growLeft, left, left-take) {
			return int(take)
		}
	}
}

// returnGrow gives budget back when a session ends, so later sessions can grow.
func (c *carrier) returnGrow(n int) {
	if n > 0 {
		atomic.AddInt64(&c.growLeft, int64(n))
	}
}

func newCarrier(conn net.Conn) *carrier {
	c := &carrier{
		conn:     conn,
		ctrl:     make(chan *[]byte, muxCtrlQueue),
		data:     make(chan *[]byte, muxDataQueue),
		streams:  make(map[uint32]*muxStream),
		nextID:   1,
		incoming: make(chan *muxStream, 64),
		done:     make(chan struct{}),
		growLeft: muxGrowBudget,
		born:     time.Now(),
	}
	atomic.StoreInt64(&c.lastHeard, time.Now().UnixNano())
	return c
}

func (c *carrier) start() {
	go c.writeLoop()
	go c.readLoop()
	go c.keepalive()
}

// sendControl queues a small frame without ever waiting. If even the control
// queue is full the link is wedged beyond use, so it is torn down rather than
// left to hang.
func (c *carrier) sendControl(frames ...muxFrame) {
	buf := encodeFrames(frames...)
	select {
	case c.ctrl <- buf:
	case <-c.done:
		recycleFrame(buf)
	default:
		recycleFrame(buf)
		c.fail(errMuxBacklog)
	}
}

// sendData queues payload, waiting while the link is busy. Waiting here is the
// point: it is how a fast sender is slowed to the speed of the link.
func (c *carrier) sendData(s *muxStream, frames ...muxFrame) error {
	buf := encodeFrames(frames...)
	select {
	case c.data <- buf:
		return nil
	case <-s.dead:
		recycleFrame(buf)
		return s.reason()
	case <-c.done:
		recycleFrame(buf)
		return errMuxClosed
	case <-s.wdl.wait():
		recycleFrame(buf)
		return timeoutError{}
	}
}

// sendOrdered queues a frame that must stay behind the data already queued for
// the same stream.
//
// This is what "I have finished sending" and "this session is over" need, and it
// is easy to get wrong: sent on the priority queue they would overtake the tail
// of somebody's download, and the far side would see the end of the session
// before the last of the data. That looks exactly like a truncated file.
//
// It gives up after a while rather than waiting for ever, because by then the
// link is stuck and is about to be torn down anyway.
func (c *carrier) sendOrdered(frames ...muxFrame) {
	buf := encodeFrames(frames...)
	timer := time.NewTimer(muxOrderedWait)
	defer timer.Stop()
	select {
	case c.data <- buf:
	case <-c.done:
		recycleFrame(buf)
	case <-timer.C:
		recycleFrame(buf)
		c.fail(errMuxBacklog)
	}
}

func (c *carrier) writeLoop() {
	for {
		// Control first, always. Credit lives in this queue, and a sender
		// waiting for credit behind a queue of data would deadlock the link.
		select {
		case b := <-c.ctrl:
			if !c.put(b) {
				return
			}
			continue
		default:
		}

		select {
		case b := <-c.ctrl:
			if !c.put(b) {
				return
			}
		case b := <-c.data:
			if !c.put(b) {
				return
			}
		case <-c.done:
			return
		}
	}
}

// put writes one queued frame buffer and hands it back for reuse. The write
// goroutine is the only one left holding it by this point, so returning it here
// is safe.
func (c *carrier) put(b *[]byte) bool {
	_, err := c.conn.Write(*b)
	recycleFrame(b)
	if err != nil {
		c.fail(err)
		return false
	}
	return true
}

func (c *carrier) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// fail tears the carrier down and every stream on it. Sessions on a dead link
// are finished whether or not anyone has noticed yet.
func (c *carrier) fail(err error) {
	c.doneOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
		if c.onDone != nil {
			c.onDone(time.Since(c.born), err)
		}
	})

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	victims := make([]*muxStream, 0, len(c.streams))
	for _, s := range c.streams {
		victims = append(victims, s)
	}
	c.streams = map[uint32]*muxStream{}
	c.mu.Unlock()

	for _, s := range victims {
		s.kill(err)
	}
}

func (c *carrier) forget(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

func (c *carrier) streamCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}

// open starts a new stream. Nothing goes on the wire until the first write.
func (c *carrier) open(targetPort ...uint16) (*muxStream, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errMuxClosed
	}
	id := c.nextID
	c.nextID++
	s := newMuxStream(c, id, true)
	if len(targetPort) > 0 {
		s.targetPort = targetPort[0]
	}
	c.streams[id] = s
	c.mu.Unlock()
	return s, nil
}

// readLoop is the only reader of the underlying connection.
func (c *carrier) readLoop() {
	hdr := make([]byte, muxHeaderLen)

	// One buffer for every frame's payload, instead of fresh room each time.
	// Reuse is safe because each frame is finished with before the next is read:
	// data is copied into the receiving session's own buffer, and a credit is
	// acted on immediately.
	body := make([]byte, muxMaxPayload)

	first := true
	for {
		got := 0
		if first {
			// The first byte is looked at on its own. A refusal from the other
			// end is a single byte followed by a close, which would never fill
			// a whole header, and its reason would be lost behind a bare
			// end-of-file.
			first = false
			if _, err := io.ReadFull(c.conn, hdr[:1]); err != nil {
				c.fail(err)
				return
			}
			if err := checkFirstFrame(hdr[0]); err != nil {
				c.fail(err)
				return
			}
			got = 1
		}
		if _, err := io.ReadFull(c.conn, hdr[got:]); err != nil {
			c.fail(err)
			return
		}
		typ := hdr[0]
		id := binary.BigEndian.Uint32(hdr[1:5])
		length := int(binary.BigEndian.Uint16(hdr[5:7]))

		var payload []byte
		if length > 0 {
			if length > len(body) {
				// Nothing this program sends is larger than one frame's worth,
				// so the other end is either broken or not speaking to us.
				c.fail(fmt.Errorf("the other end sent an oversized frame of %d bytes", length))
				return
			}
			payload = body[:length]
			if _, err := io.ReadFull(c.conn, payload); err != nil {
				c.fail(err)
				return
			}
		}
		atomic.StoreInt64(&c.lastHeard, time.Now().UnixNano())

		if err := c.handle(typ, id, payload); err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *carrier) handle(typ byte, id uint32, payload []byte) error {
	switch typ {
	case muxPing:
		c.sendControl(muxFrame{typ: muxPong})
		return nil

	case muxPong:
		return nil

	case muxOpen:
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return errMuxClosed
		}
		if _, dup := c.streams[id]; dup {
			c.mu.Unlock()
			return fmt.Errorf("the other end reused session number %d", id)
		}
		s := newMuxStream(c, id, false)
		if len(payload) >= 2 {
			s.targetPort = binary.BigEndian.Uint16(payload[:2])
		}
		c.streams[id] = s
		c.mu.Unlock()

		select {
		case c.incoming <- s:
		default:
			// More sessions arriving than are being picked up. Refuse this one
			// rather than hold up the whole link.
			c.forget(id)
			c.sendControl(muxFrame{typ: muxReset, id: id})
		}
		return nil

	case muxData:
		s := c.lookup(id)
		if s == nil {
			// Data for a session this side has already finished with. Normal
			// when both ends close at once; tell the far side and move on.
			c.sendControl(muxFrame{typ: muxReset, id: id})
			return nil
		}
		if err := s.deliver(payload); err != nil {
			s.kill(err)
			c.forget(id)
			c.sendControl(muxFrame{typ: muxReset, id: id})
		}
		return nil

	case muxCredit:
		if len(payload) != 4 {
			return errors.New("a credit frame was the wrong size")
		}
		if s := c.lookup(id); s != nil {
			s.grant(binary.BigEndian.Uint32(payload))
		}
		return nil

	case muxFin:
		if s := c.lookup(id); s != nil {
			s.finish()
		}
		return nil

	case muxReset:
		if s := c.lookup(id); s != nil {
			s.finish()
			s.kill(errStreamGone)
			c.forget(id)
		}
		return nil

	case muxTeardown:
		c.sendControl(muxFrame{typ: muxTeardownAck})
		if c.onTeardown != nil {
			c.onTeardown()
		}
		return nil

	case muxTeardownAck:
		c.mu.Lock()
		ch := c.teardownAckCh
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown frame type %d on the link", typ)
	}
}

func (c *carrier) lookup(id uint32) *muxStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

// keepalive proves the link still works, and notices when it has stopped
// working. A route that dies silently is the usual failure on these paths, and
// without this it would only be discovered by a user landing on it.
func (c *carrier) keepalive() {
	ticker := time.NewTicker(muxPingEvery)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			since := time.Since(time.Unix(0, atomic.LoadInt64(&c.lastHeard)))
			if since > muxPingGrace {
				c.fail(fmt.Errorf("nothing heard from the other server for %s",
					since.Round(time.Second)))
				return
			}
			c.sendControl(muxFrame{typ: muxPing})
		}
	}
}

// ---------------------------------------------------------------------------
// The set of links
// ---------------------------------------------------------------------------

// carrierSet is every multiplexed link this process has, and the machinery to
// keep them up.
//
// One of the two servers dials and the other accepts, exactly as before, so dial
// is set on one side and nil on the other. What rides inside is identical either
// way, which is why turning a tunnel round changes nothing here.
type carrierSet struct {
	mu     sync.Mutex
	items  []*carrier
	closed bool

	target int
	dial   func() (net.Conn, error)

	// onStream is set on the side that receives sessions rather than starting
	// them, and is called once per session with something that behaves like a
	// connection.
	onStream func(net.Conn)

	onTeardown func()

	added   chan struct{}
	log     *throttled
	lastErr atomic.Value

	// youngStreak counts links in a row that died soon after coming up.
	youngStreak int32
}

func (cs *carrierSet) SetOnTeardown(fn func()) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.onTeardown = fn
	for _, c := range cs.items {
		c.onTeardown = fn
	}
}

// Teardown sends a muxTeardown control frame to the remote peer and waits for muxTeardownAck.
func (cs *carrierSet) Teardown(ctx context.Context) error {
	cs.mu.Lock()
	var live []*carrier
	for _, c := range cs.items {
		if !c.isClosed() {
			live = append(live, c)
		}
	}
	cs.mu.Unlock()

	if len(live) == 0 {
		return errors.New("no live carrier to send teardown")
	}

	c := live[0]
	ackCh := make(chan struct{}, 1)
	c.mu.Lock()
	c.teardownAckCh = ackCh
	c.mu.Unlock()

	c.sendControl(muxFrame{typ: muxTeardown})

	select {
	case <-ackCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(8 * time.Second):
		return errors.New("teardown ack timeout")
	}
}

func newCarrierSet(target int, dial func() (net.Conn, error), onStream func(net.Conn)) *carrierSet {
	if target < 1 {
		target = 1
	}
	return &carrierSet{
		target:   target,
		dial:     dial,
		onStream: onStream,
		added:    make(chan struct{}, 1),
		log:      newThrottled(),
	}
}

// add takes a connection that has already been disguised and authenticated, and
// turns it into a working link.
func (cs *carrierSet) add(conn net.Conn) bool {
	c := newCarrier(conn)

	cs.mu.Lock()
	if cs.closed {
		cs.mu.Unlock()
		return false
	}
	c.onTeardown = cs.onTeardown
	c.onDone = cs.noteDeath
	cs.items = append(cs.items, c)
	cs.mu.Unlock()

	c.start()
	if cs.onStream != nil {
		go cs.acceptLoop(c)
	}
	poke(cs.added)
	return true
}

// acceptLoop hands every session the far side starts to the handler, and returns
// when the link dies.
func (cs *carrierSet) acceptLoop(c *carrier) {
	for {
		select {
		case s := <-c.incoming:
			go cs.onStream(s)
		case <-c.done:
			cs.remove(c)
			return
		}
	}
}

func (cs *carrierSet) remove(c *carrier) {
	cs.mu.Lock()
	for i, item := range cs.items {
		if item == c {
			cs.items = append(cs.items[:i], cs.items[i+1:]...)
			break
		}
	}
	cs.mu.Unlock()
}

// best picks the least busy live link, dropping any that have died on the way.
func (cs *carrierSet) best() *carrier {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	kept := cs.items[:0]
	for _, c := range cs.items {
		if !c.isClosed() {
			kept = append(kept, c)
		}
	}
	for i := len(kept); i < len(cs.items); i++ {
		cs.items[i] = nil
	}
	cs.items = kept

	// Links that recently failed to start a session are passed over while any
	// other link is up. If every link is suspect one is used anyway: a doubtful
	// link is still better than telling the user nothing is available.
	var pick, pickSuspect *carrier
	fewest, fewestSuspect := -1, -1
	for _, c := range cs.items {
		n := c.streamCount()
		if c.isSuspect() {
			if fewestSuspect < 0 || n < fewestSuspect {
				pickSuspect, fewestSuspect = c, n
			}
			continue
		}
		if fewest < 0 || n < fewest {
			pick, fewest = c, n
		}
	}
	if pick == nil {
		return pickSuspect
	}
	return pick
}

// dropAll closes every link, for when the route underneath them has changed.
// They are rebuilt on the new route by the normal upkeep.
func (cs *carrierSet) dropAll(reason error) {
	cs.mu.Lock()
	items := make([]*carrier, len(cs.items))
	copy(items, cs.items)
	cs.mu.Unlock()
	for _, c := range items {
		c.fail(reason)
	}
}

// youngLimit is how long a link must live to count as having worked.
const youngLimit = 20 * time.Second

// noteDeath is called when a link finishes. A run of links that die almost at
// once is reported by name when the cause is a settings mismatch, and slows the
// rebuilding so a broken pair does not hammer the route.
func (cs *carrierSet) noteDeath(age time.Duration, err error) {
	if errors.Is(err, errRouteChanged) || errors.Is(err, errMuxClosed) {
		return
	}
	if age >= youngLimit {
		atomic.StoreInt32(&cs.youngStreak, 0)
		return
	}
	atomic.AddInt32(&cs.youngStreak, 1)
	switch {
	case errors.Is(err, errMuxMismatch), errors.Is(err, errMuxOnlyHere), errors.Is(err, errMuxOnlyThere):
		cs.log.printf("shared connections do not match between the two servers: %v", err)
	default:
		cs.log.printf("a link to the other server closed after %s: %v", age.Round(time.Second), err)
	}
}

// open starts one session across the border. Unlike a spare connection this
// needs no round trip: the session is announced along with the user's opening
// bytes, so there is nothing to wait for.
func (cs *carrierSet) open(done <-chan struct{}, targetPort ...uint16) (net.Conn, error) {
	var tp uint16
	if len(targetPort) > 0 {
		tp = targetPort[0]
	}
	giveUp := time.NewTimer(muxWaitForLink)
	defer giveUp.Stop()

	for {
		if c := cs.best(); c != nil {
			s, err := c.open(tp)
			if err == nil {
				return s, nil
			}
			cs.remove(c)
			continue
		}

		select {
		case <-cs.added:
		case <-done:
			return nil, errNoCarrier
		case <-giveUp.C:
			reason, _ := cs.lastErr.Load().(string)
			if reason != "" {
				return nil, fmt.Errorf("%w (last attempt: %s)", errNoCarrier, reason)
			}
			return nil, errNoCarrier
		}
	}
}

func (cs *carrierSet) count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.items)
}

// stats reports how many links are up and how many sessions are on them.
func (cs *carrierSet) stats() (links, streams int) {
	cs.mu.Lock()
	items := make([]*carrier, len(cs.items))
	copy(items, cs.items)
	cs.mu.Unlock()

	for _, c := range items {
		if c.isClosed() {
			continue
		}
		links++
		streams += c.streamCount()
	}
	return links, streams
}

// maintain keeps the wanted number of links up on the side that dials. On the
// side that accepts there is nothing to keep up, so it only tidies away links
// that have died.
func (cs *carrierSet) maintain(done <-chan struct{}) {
	backoff := time.Duration(0)

	for {
		select {
		case <-done:
			return
		default:
		}

		cs.prune()

		wait := time.Second
		if cs.dial != nil {
			if missing := cs.target - cs.count(); missing > 0 {
				if cs.build(missing) {
					backoff = 0
					wait = 200 * time.Millisecond
					// Links that keep dying straight after coming up mean
					// rebuilding faster will not help; slow down instead.
					if streak := atomic.LoadInt32(&cs.youngStreak); streak > 0 {
						wait = refillBackoff0
						for i := int32(1); i < streak && wait < refillBackoffM; i++ {
							wait *= 2
						}
						if wait > refillBackoffM {
							wait = refillBackoffM
						}
					}
				} else {
					if backoff == 0 {
						backoff = refillBackoff0
					} else if backoff < refillBackoffM {
						backoff *= 2
						if backoff > refillBackoffM {
							backoff = refillBackoffM
						}
					}
					reason, _ := cs.lastErr.Load().(string)
					if reason == "" {
						reason = "no reason reported"
					}
					cs.log.printf("cannot open the link to the other server: %s; retrying in %s",
						reason, backoff)
					wait = backoff
				}
			}
		}

		select {
		case <-done:
			return
		case <-time.After(wait):
		}
	}
}

// build opens up to n links, in parallel, and reports whether any succeeded.
func (cs *carrierSet) build(n int) bool {
	var wg sync.WaitGroup
	var won int32

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := cs.dial()
			if err != nil {
				cs.lastErr.Store(err.Error())
				return
			}
			if !cs.add(conn) {
				_ = conn.Close()
				return
			}
			atomic.AddInt32(&won, 1)
		}()
	}
	wg.Wait()
	return atomic.LoadInt32(&won) > 0
}

func (cs *carrierSet) prune() {
	cs.mu.Lock()
	kept := cs.items[:0]
	for _, c := range cs.items {
		if !c.isClosed() {
			kept = append(kept, c)
		}
	}
	for i := len(kept); i < len(cs.items); i++ {
		cs.items[i] = nil
	}
	cs.items = kept
	cs.mu.Unlock()
}

func (cs *carrierSet) closeAll() {
	cs.mu.Lock()
	items := cs.items
	cs.items = nil
	cs.closed = true
	cs.mu.Unlock()

	for _, c := range items {
		c.fail(errMuxClosed)
	}
}
