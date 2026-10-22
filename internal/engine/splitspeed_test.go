package engine

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// splitPair sets up the two ends of a split stream over loopback. The client
// end's dialLeg is wrapped so a test can make dialing slow (like a real link,
// where every leg costs several round trips) or make some dials fail.
func splitPair(t *testing.T, delay time.Duration, failEvery int32) (client, server net.Conn, maxParallel *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &Config{Transport: TransportPlain, AntiFreeze: true, secret: []byte("0123456789abcdef0123456789abcdef")}

	serverCh := make(chan net.Conn, 1)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, err := wrapAccept(c, cfg, nil)
				if errors.Is(err, errSplitLegAttached) {
					return
				}
				if err != nil {
					_ = c.Close()
					return
				}
				select {
				case serverCh <- sc:
				default:
				}
			}(raw)
		}
	}()

	raw0, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := wrapDial(raw0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	sc, ok := cc.(*splitConn)
	if !ok {
		t.Fatalf("expected a split connection, got %T", cc)
	}

	var inFlight, peak, attempts atomic.Int32
	maxParallel = &peak
	real := sc.dialLeg
	sc.dialLeg = func(role byte, seq uint32) (*legRef, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(delay)
		if failEvery > 0 && attempts.Add(1)%failEvery == 0 {
			return nil, errors.New("injected dial failure")
		}
		return real(role, seq)
	}

	// The first bytes written start the server end.
	go func() { _, _ = cc.Write([]byte("x")) }()
	select {
	case server = <-serverCh:
	case <-time.After(3 * time.Second):
		t.Fatal("no server end")
	}
	t.Cleanup(func() { _ = server.Close() })
	b := make([]byte, 1)
	if _, err := io.ReadFull(server, b); err != nil {
		t.Fatal(err)
	}
	return cc, server, maxParallel
}

// transfer sends size bytes each way and returns how long it took.
func transfer(t *testing.T, client, server net.Conn, size int) time.Duration {
	t.Helper()
	_ = client.SetDeadline(time.Now().Add(60 * time.Second))
	_ = server.SetDeadline(time.Now().Add(60 * time.Second))
	c2s := make([]byte, size)
	s2c := make([]byte, size)
	_, _ = rand.Read(c2s)
	_, _ = rand.Read(s2c)
	gotS := make([]byte, size)
	gotC := make([]byte, size)

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				errs <- err
			}
		}()
	}
	write := func(c net.Conn, b []byte) func() error {
		return func() error {
			for off := 0; off < len(b); off += 8192 {
				if _, err := c.Write(b[off:min(off+8192, len(b))]); err != nil {
					return err
				}
			}
			return nil
		}
	}
	read := func(c net.Conn, b []byte) func() error {
		return func() error { _, err := io.ReadFull(c, b); return err }
	}
	run(write(client, c2s))
	run(write(server, s2c))
	run(read(server, gotS))
	run(read(client, gotC))
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("transfer failed: %v", err)
	}
	took := time.Since(start)
	if !bytes.Equal(gotS, c2s) || !bytes.Equal(gotC, s2c) {
		t.Fatal("the bytes that arrived are not the bytes that were sent")
	}
	return took
}

// With every leg costing 120 ms to set up, dialing them one after another
// would take 2 MB / 14 KB * 120 ms, about 17 s each way. Dialing side by side
// has to be far quicker, and the bytes must still arrive intact and in order.
func TestSplitStreamDialsLegsSideBySide(t *testing.T) {
	client, server, peak := splitPair(t, 120*time.Millisecond, 0)
	took := transfer(t, client, server, 2<<20)
	t.Logf("2 MB each way in %s, up to %d dials at once", took, peak.Load())
	if peak.Load() < 3 {
		t.Fatalf("only %d legs were ever dialed at once", peak.Load())
	}
	if took > 12*time.Second {
		t.Fatalf("took %s; legs are still being renewed too slowly", took)
	}
}

// A dial that fails must be tried again under the same number: the server waits
// for every number in turn.
func TestSplitStreamSurvivesFailedDials(t *testing.T) {
	client, server, _ := splitPair(t, 5*time.Millisecond, 6)
	transfer(t, client, server, 512<<10)
}

// A quiet connection does not keep a crowd of spare legs open.
func TestSplitStreamKeepsFewSpareLegsWhenIdle(t *testing.T) {
	client, _, _ := splitPair(t, 1*time.Millisecond, 0)
	time.Sleep(300 * time.Millisecond)
	sc := client.(*splitConn)
	for name, q := range map[string]*legQueue{"write": sc.wq, "read": sc.rq} {
		q.mu.Lock()
		n := len(q.ready)
		q.mu.Unlock()
		if n > q.base {
			t.Errorf("%s: %d spare legs held while idle, want at most %d", name, n, q.base)
		}
	}
}
