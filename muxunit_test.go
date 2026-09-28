package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// carrierPair wires two carriers together in memory. net.Pipe has no buffering
// of its own, which is deliberate here: it means every test exercises the real
// blocking behaviour rather than a version of it smoothed out by a kernel
// socket buffer.
func carrierPair(t *testing.T) (*carrier, *carrier) {
	t.Helper()
	a, b := net.Pipe()
	ca, cb := newCarrier(a), newCarrier(b)
	ca.start()
	cb.start()
	t.Cleanup(func() {
		ca.fail(errMuxClosed)
		cb.fail(errMuxClosed)
	})
	return ca, cb
}

// acceptOne waits for the far side to notice a new session.
func acceptOne(t *testing.T, c *carrier) *muxStream {
	t.Helper()
	select {
	case s := <-c.incoming:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the other end never saw the session start")
		return nil
	}
}

// A session must carry data in both directions.
func TestMuxCarriesDataBothWays(t *testing.T) {
	ca, cb := carrierPair(t)

	up, err := ca.open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := up.Write([]byte("hello from the edge")); err != nil {
		t.Fatalf("write: %v", err)
	}

	down := acceptOne(t, cb)
	got := make([]byte, 64)
	n, err := down.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got[:n]) != "hello from the edge" {
		t.Fatalf("got %q", got[:n])
	}

	if _, err := down.Write([]byte("and back again")); err != nil {
		t.Fatalf("reply: %v", err)
	}
	n, err = up.Read(got)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(got[:n]) != "and back again" {
		t.Fatalf("got reply %q", got[:n])
	}
}

// Finishing one direction must not cut the other off, and everything already
// sent must still arrive. Getting this wrong is what truncates downloads.
func TestMuxHalfCloseDeliversEverything(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	payload := bytes.Repeat([]byte("abcdefgh"), 5000) // 40 KB, several frames
	go func() {
		_, _ = up.Write(payload)
		_ = up.CloseWrite()
	}()

	down := acceptOne(t, cb)
	got, err := io.ReadAll(down)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, wanted %d", len(got), len(payload))
	}

	// The other direction is still open.
	if _, err := down.Write([]byte("still here")); err != nil {
		t.Fatalf("reply after half close: %v", err)
	}
	buf := make([]byte, 32)
	n, err := up.Read(buf)
	if err != nil {
		t.Fatalf("read after half close: %v", err)
	}
	if string(buf[:n]) != "still here" {
		t.Fatalf("got %q", buf[:n])
	}
}

// A sender must not be able to run ahead of a reader that is not consuming.
// Without this one fast session could queue unbounded data in memory.
func TestMuxSenderWaitsForTheReader(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	// Send the first byte so the session exists on the other side, then leave
	// the reader untouched.
	if _, err := up.Write([]byte{0}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	down := acceptOne(t, cb)

	// More than the window a session starts with. The window only widens while
	// the reader is keeping up, and this reader is deliberately not, so the
	// sender has to stop.
	payload := muxWindowStart + 64<<10

	done := make(chan int, 1)
	go func() {
		n, _ := up.Write(make([]byte, payload))
		done <- n
	}()

	select {
	case n := <-done:
		t.Fatalf("the sender wrote %d bytes without the reader taking any", n)
	case <-time.After(500 * time.Millisecond):
		// Correct: it is waiting.
	}

	// Draining the reader must release it.
	read := 0
	buf := make([]byte, 32<<10)
	deadline := time.After(10 * time.Second)
	for read < payload {
		select {
		case <-deadline:
			t.Fatalf("only %d bytes arrived", read)
		default:
		}
		_ = down.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := down.Read(buf)
		read += n
		if err != nil {
			t.Fatalf("read after %d bytes: %v", read, err)
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sender never finished even once the reader caught up")
	}
}

// Everything that goes in must come out unchanged, in order, at a size well
// past one frame.
func TestMuxLargeTransferIsIntact(t *testing.T) {
	ca, cb := carrierPair(t)

	payload := make([]byte, 4<<20)
	rnd := rand.New(rand.NewSource(7))
	rnd.Read(payload)

	up, _ := ca.open()
	go func() {
		_, _ = up.Write(payload)
		_ = up.CloseWrite()
	}()

	down := acceptOne(t, cb)
	got, err := io.ReadAll(down)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("%d bytes arrived, wanted %d, and they differ", len(got), len(payload))
	}
}

// Many sessions at once on one link, each with its own data, must not mix.
func TestMuxManySessionsDoNotMix(t *testing.T) {
	ca, cb := carrierPair(t)

	const sessions = 40
	const size = 64 << 10

	payloads := make([][]byte, sessions)
	rnd := rand.New(rand.NewSource(11))
	for i := range payloads {
		payloads[i] = make([]byte, size)
		rnd.Read(payloads[i])
	}

	// The far side echoes whatever it is given, so a mix-up shows up as wrong
	// bytes coming back rather than as a silent pass.
	go func() {
		for {
			select {
			case s := <-cb.incoming:
				go func(s *muxStream) {
					b, _ := io.ReadAll(s)
					_, _ = s.Write(b)
					_ = s.CloseWrite()
				}(s)
			case <-cb.done:
				return
			}
		}
	}()

	var wg sync.WaitGroup
	fail := make(chan string, sessions)
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := ca.open()
			if err != nil {
				fail <- "open failed"
				return
			}
			go func() {
				_, _ = s.Write(payloads[i])
				_ = s.CloseWrite()
			}()
			got, err := io.ReadAll(s)
			if err != nil {
				fail <- "read failed"
				return
			}
			if !bytes.Equal(got, payloads[i]) {
				fail <- "session came back with the wrong bytes"
			}
		}(i)
	}
	wg.Wait()
	close(fail)
	for msg := range fail {
		t.Fatal(msg)
	}
}

// Moving a read deadline to now must interrupt a read that is already blocked.
// The shutdown path depends on exactly this to avoid hanging for minutes.
func TestMuxDeadlineInterruptsABlockedRead(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	_, _ = up.Write([]byte{1})
	down := acceptOne(t, cb)

	// Consume the first byte so the next read has nothing waiting.
	one := make([]byte, 1)
	if _, err := down.Read(one); err != nil {
		t.Fatalf("first read: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := down.Read(buf)
		result <- err
	}()

	time.Sleep(100 * time.Millisecond)
	_ = down.SetReadDeadline(time.Now())

	select {
	case err := <-result:
		if !isTimeout(err) {
			t.Fatalf("wanted a timeout, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the blocked read was never interrupted")
	}

	// Clearing the deadline must make the session usable again.
	_ = down.SetReadDeadline(time.Time{})
	_, _ = up.Write([]byte("again"))
	buf := make([]byte, 16)
	_ = down.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := down.Read(buf)
	if err != nil {
		t.Fatalf("read after clearing the deadline: %v", err)
	}
	if string(buf[:n]) != "again" {
		t.Fatalf("got %q", buf[:n])
	}
}

// When the link itself dies, every session on it must end rather than hang.
func TestMuxLinkFailureEndsEverySession(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	_, _ = up.Write([]byte{9})
	down := acceptOne(t, cb)

	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		one := make([]byte, 1)
		_, _ = down.Read(one)
		_, err := down.Read(buf)
		result <- err
	}()

	time.Sleep(100 * time.Millisecond)
	ca.fail(errors.New("the link went down"))

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("the session carried on after the link died")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a session on a dead link never ended")
	}
}

// A session ended by the far side must still hand over what it had already sent
// before reporting the end.
func TestMuxEndOfSessionStillDeliversBufferedData(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	if _, err := up.Write([]byte("last words")); err != nil {
		t.Fatalf("write: %v", err)
	}
	down := acceptOne(t, cb)

	// Give the bytes time to arrive, then end the session from the sending side.
	time.Sleep(200 * time.Millisecond)
	_ = up.Close()
	time.Sleep(200 * time.Millisecond)

	got, err := io.ReadAll(down)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if string(got) != "last words" {
		t.Fatalf("got %q", got)
	}
}

// A keepalive must be answered, or the far side would conclude the link is dead.
func TestMuxPingIsAnswered(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Deliberately not started: nothing drains the queue, so what would have
	// gone on the wire can be inspected.
	c := newCarrier(a)
	if err := c.handle(muxPing, 0, nil); err != nil {
		t.Fatalf("handling a ping: %v", err)
	}
	select {
	case queued := <-c.ctrl:
		frame := *queued
		if len(frame) != muxHeaderLen || frame[0] != muxPong {
			t.Fatalf("expected a pong, got %v", frame)
		}
	default:
		t.Fatal("a ping went unanswered")
	}
}

// Anything unrecognised means the two ends are out of step, which is not
// something to carry on through.
func TestMuxNonsenseFrameEndsTheLink(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := newCarrier(a)
	if err := c.handle(99, 1, nil); err == nil {
		t.Fatal("an unknown frame type was accepted")
	}
}

// The deadline helper is small but load-bearing, so its own behaviour is worth
// pinning down.
func TestMuxDeadlineHelper(t *testing.T) {
	d := newDeadline()

	// No deadline: nothing fires.
	select {
	case <-d.wait():
		t.Fatal("an unset deadline fired")
	default:
	}

	// In the past: fires at once.
	d.set(time.Now().Add(-time.Second))
	select {
	case <-d.wait():
	default:
		t.Fatal("a deadline in the past did not fire")
	}

	// Cleared again: back to not firing, or every later read would fail.
	d.set(time.Time{})
	select {
	case <-d.wait():
		t.Fatal("clearing the deadline left it fired")
	default:
	}

	// In the future: fires when it should.
	d.set(time.Now().Add(150 * time.Millisecond))
	select {
	case <-d.wait():
		t.Fatal("fired early")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-d.wait():
	case <-time.After(2 * time.Second):
		t.Fatal("never fired")
	}
}

// If one end shares connections and the other does not, they must fail plainly
// rather than half-work.
//
// The pairing code stops the two ends disagreeing by accident, so this guards
// against a settings file edited by hand. It is worth guarding: when the frame
// numbers overlapped the session signals, the side not sharing read the first
// frame as a valid instruction, went off and opened a real connection to the
// service, and replied. Nothing failed until much later, and what surfaced was an
// unexplained end-of-file rather than anything pointing at the cause.
func TestMuxFrameTypesCannotBeMistakenForSessionSignals(t *testing.T) {
	// protoVersion shares its value with the activate signal already, which is
	// harmless because they are never read in the same place. Listed once.
	sessionBytes := map[byte]string{
		msgActivate:  "activate",
		msgAck:       "acknowledgement",
		rejClockSkew: "clock skew refusal",
		rejReplay:    "replay refusal",
	}
	frames := map[byte]string{
		muxOpen:   "open",
		muxData:   "data",
		muxCredit: "credit",
		muxFin:    "finished",
		muxReset:  "reset",
		muxPing:   "ping",
		muxPong:   "pong",
	}

	for value, frame := range frames {
		if name, clash := sessionBytes[value]; clash {
			t.Fatalf("the %s frame uses %#x, which is also the %s signal", frame, value, name)
		}
	}

	// And the other way round: a session signal must not read as a known frame,
	// so the sharing end refuses it instead of acting on it.
	for value, name := range sessionBytes {
		if frame, clash := frames[value]; clash {
			t.Fatalf("the %s signal uses %#x, which is also the %s frame", name, value, frame)
		}
	}
}

// A session signal arriving where a frame was expected must end the link with
// something a log reader can act on.
func TestMuxRefusesASessionSignalAsAFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := newCarrier(a)
	err := c.handle(msgAck, 0, nil)
	if err == nil {
		t.Fatal("an acknowledgement byte was accepted as a frame")
	}
	if !strings.Contains(err.Error(), "unknown frame type") {
		t.Fatalf("the complaint was %q, which does not say what went wrong", err)
	}
}

// A session whose reader keeps up must be allowed to go faster than its starting
// window would permit.
//
// This is the fault that made shared connections five times slower than they
// should have been on a real route. A sender may only have one window in flight
// per round trip, so a fixed window is a fixed speed limit: 256 KB across a 90 ms
// route is about 22 Mbit/s however fast the link really is. The window has to
// widen for sessions that can use it.
func TestMuxWindowWidensForAFastReader(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	// A payload far larger than the starting window, read as fast as it arrives.
	payload := make([]byte, 8<<20)
	rnd := rand.New(rand.NewSource(23))
	rnd.Read(payload)

	go func() {
		_, _ = up.Write(payload)
		_ = up.CloseWrite()
	}()

	down := acceptOne(t, cb)
	got, err := io.ReadAll(down)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("%d bytes arrived of %d, and they differ", len(got), len(payload))
	}

	ms := down
	ms.rmu.Lock()
	win := ms.rwin
	ms.rmu.Unlock()
	if win <= muxWindowStart {
		t.Fatalf("the window never widened; still %d", win)
	}
	if win > muxWindowMax {
		t.Fatalf("the window grew past its ceiling: %d", win)
	}
}

// Widening must be bounded by what the link can spare, or many fast sessions at
// once would between them tie up more memory than the machine has.
func TestMuxWindowGrowthIsBoundedPerLink(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := newCarrier(a)

	// Take the whole budget in pieces and check no more is handed out.
	taken := 0
	for i := 0; i < 10000; i++ {
		got := c.takeGrow(1 << 20)
		if got == 0 {
			break
		}
		taken += got
	}
	if taken != muxGrowBudget {
		t.Fatalf("handed out %d of a %d budget", taken, muxGrowBudget)
	}
	if extra := c.takeGrow(1 << 20); extra != 0 {
		t.Fatalf("handed out %d more than the budget", extra)
	}

	// Giving it back must make it available again, so a long-lived link does not
	// starve the sessions that come later.
	c.returnGrow(taken)
	if got := c.takeGrow(1 << 20); got != 1<<20 {
		t.Fatalf("after returning the budget only %d was available", got)
	}
}

// A session that grew must hand its share back when it ends.
func TestMuxWindowGrowthIsReturnedOnClose(t *testing.T) {
	ca, cb := carrierPair(t)

	up, _ := ca.open()
	go func() {
		_, _ = up.Write(make([]byte, 4<<20))
		_ = up.CloseWrite()
	}()

	down := acceptOne(t, cb)
	if _, err := io.ReadAll(down); err != nil {
		t.Fatalf("read all: %v", err)
	}

	ms := down
	ms.rmu.Lock()
	held := ms.rtaken
	ms.rmu.Unlock()
	if held == 0 {
		t.Fatal("the session never took any of the link's budget, so it cannot have grown")
	}

	before := atomic.LoadInt64(&cb.growLeft)
	_ = down.Close()
	after := atomic.LoadInt64(&cb.growLeft)
	if after != before+int64(held) {
		t.Fatalf("closing returned %d of the %d it held", after-before, held)
	}
	if after > muxGrowBudget {
		t.Fatalf("more budget came back than ever existed: %d", after)
	}

	// Closing twice must not hand the budget back twice.
	_ = down.Close()
	if again := atomic.LoadInt64(&cb.growLeft); again != after {
		t.Fatalf("closing again changed the budget from %d to %d", after, again)
	}
}

// The receive buffer was reworked from appending to a slice into a pair of
// offsets, which is the sort of change that silently loses or duplicates bytes.
// This drives it through the awkward cases: partial reads, refills while data is
// still unread, and a reader that drains exactly to the end.
func TestMuxReceiveBufferKeepsEveryByteInOrder(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := newCarrier(a)
	s := newMuxStream(c, 1, false)

	var want []byte
	var got []byte

	// Deliver in uneven pieces and read back in uneven pieces, so the offsets
	// are rarely aligned with anything.
	piece := 0
	for round := 0; round < 200; round++ {
		for i := 0; i < 3; i++ {
			piece++
			chunk := bytes.Repeat([]byte{byte(piece)}, 1+piece%997)
			if err := s.deliver(chunk); err != nil {
				t.Fatalf("delivering piece %d: %v", piece, err)
			}
			want = append(want, chunk...)
		}
		// Read back less than was delivered, so a backlog builds and the buffer
		// has to make room around unread bytes.
		out := make([]byte, 1+round%500)
		n, err := s.Read(out)
		if err != nil {
			t.Fatalf("read in round %d: %v", round, err)
		}
		got = append(got, out[:n]...)
	}

	s.finish()
	for {
		out := make([]byte, 4096)
		n, err := s.Read(out)
		got = append(got, out[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("draining: %v", err)
		}
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("read back %d bytes, expected %d, and they do not match", len(got), len(want))
	}
}

// Once a reader has taken everything, the buffer must go back to the start
// rather than creep forward, or a long session would grow a buffer for ever.
func TestMuxReceiveBufferResetsWhenDrained(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := newCarrier(a)
	s := newMuxStream(c, 1, false)

	chunk := bytes.Repeat([]byte("x"), 8192)
	out := make([]byte, 8192)

	for i := 0; i < 50; i++ {
		if err := s.deliver(chunk); err != nil {
			t.Fatalf("deliver: %v", err)
		}
		if _, err := io.ReadFull(s, out); err != nil {
			t.Fatalf("read: %v", err)
		}
	}

	s.rmu.Lock()
	start, end, size := s.rstart, s.rend, len(s.rbuf)
	s.rmu.Unlock()

	if start != 0 || end != 0 {
		t.Fatalf("a drained buffer still points at %d:%d", start, end)
	}
	if size > muxMaxPayload {
		t.Fatalf("a drained buffer grew to %d bytes after steady traffic", size)
	}
}

// The window is the promise of how much may be in flight. Breaking it has to be
// caught, because it is the only thing bounding memory per session.
func TestMuxOverflowStillRefused(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := newCarrier(a)
	s := newMuxStream(c, 1, false)

	chunk := bytes.Repeat([]byte("y"), muxMaxPayload)
	delivered := 0
	for {
		err := s.deliver(chunk)
		if err == nil {
			delivered += len(chunk)
			if delivered > muxWindowStart*4 {
				t.Fatal("the window was never enforced")
			}
			continue
		}
		if !errors.Is(err, errMuxOverflow) {
			t.Fatalf("got %v, expected the overflow refusal", err)
		}
		break
	}
	if delivered > muxWindowStart {
		t.Fatalf("accepted %d bytes against a window of %d", delivered, muxWindowStart)
	}
}

// Frame buffers are now borrowed and returned. If one were returned while still
// queued, two frames would share memory and the link would carry nonsense, so
// check that what comes off the wire is exactly what was sent.
func TestMuxFrameBuffersAreSafeToReuse(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := newCarrier(a)
	c.start()
	defer c.fail(errMuxClosed)

	const streams = 8
	const rounds = 40

	// Read the wire and check each frame as it arrives. Checking here rather
	// than collecting first matters: nothing may hold the wire up, or the link
	// would conclude it had gone quiet and tear itself down.
	var seen int64
	bad := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		hdr := make([]byte, muxHeaderLen)
		body := make([]byte, 64*1024)
		for atomic.LoadInt64(&seen) < streams*rounds {
			if _, err := io.ReadFull(b, hdr); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[5:7]))
			if n > 0 {
				if _, err := io.ReadFull(b, body[:n]); err != nil {
					return
				}
			}
			if hdr[0] != muxData {
				continue
			}
			id := binary.BigEndian.Uint32(hdr[1:5])
			// Every byte of a data frame must be the number of the session that
			// sent it. Anything else means two frames shared a buffer.
			for _, ch := range body[:n] {
				if uint32(ch) != id {
					select {
					case bad <- fmt.Sprintf("session %d carried a byte belonging to %d", id, ch):
					default:
					}
					return
				}
			}
			atomic.AddInt64(&seen, 1)
		}
	}()

	var wg sync.WaitGroup
	for i := 1; i <= streams; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s := newMuxStream(c, uint32(id), false)
			for r := 0; r < rounds; r++ {
				body := bytes.Repeat([]byte{byte(id)}, 1000+r)
				if _, err := s.Write(body); err != nil {
					return
				}
			}
		}(i)
	}
	wg.Wait()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("only %d of %d frames arrived", atomic.LoadInt64(&seen), streams*rounds)
	}
	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
	if got := atomic.LoadInt64(&seen); got != streams*rounds {
		t.Fatalf("saw %d frames, expected %d", got, streams*rounds)
	}
}
