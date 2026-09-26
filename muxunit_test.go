package main

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
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

	done := make(chan int, 1)
	go func() {
		n, _ := up.Write(make([]byte, muxWindow+64<<10))
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
	for read < muxWindow+64<<10 {
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
	case frame := <-c.ctrl:
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
