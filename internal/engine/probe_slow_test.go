package engine

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// shapedProxy forwards TCP connections to target, each direction held to
// bytesPerSec. With stopAfter > 0, a direction stops forwarding (without
// closing) once that many bytes have passed it: what a DPI freeze looks like.
func shapedProxy(t *testing.T, target string, bytesPerSec int, stopAfter int64) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 2048)
		var moved int64
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if stopAfter > 0 && moved+int64(n) > stopAfter {
					<-done // frozen: hold the connection open, move nothing
					return
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
				moved += int64(n)
				// Hold the pace with no credit saved up while idle: every
				// chunk takes the time it would at the rate.
				select {
				case <-time.After(time.Duration(float64(n) / float64(bytesPerSec) * float64(time.Second))):
				case <-done:
					return
				}
			}
			if err != nil {
				if cw, ok := dst.(*net.TCPConn); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			wg.Add(2)
			go pipe(u, c)
			go pipe(c, u)
			go func() { <-done; _ = c.Close(); _ = u.Close() }()
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

func plainSpecTo(addr string) ProbeCandidateSpec {
	_, ps, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(ps)
	return ProbeCandidateSpec{
		ID: "direct-plain", Label: "Plain", Mode: "direct", Link: "plain",
		Transport: string(TransportPlain), TargetAddr: addr, Port: port,
	}
}

// A link that is slow but keeps moving data is a working link. It used to run
// out of the planned time and be shown as frozen by DPI.
func TestProbeSlowLinkIsNotFrozen(t *testing.T) {
	ln, err := StartProbeListener("127.0.0.1", 0, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// About 1 Mbit/s each way: the old fixed budget needed about 1.6.
	addr, stop := shapedProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Port)), 125_000, 0)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := RunProbeDialer(ctx, []ProbeCandidateSpec{plainSpecTo(addr)}, ln.Secret, 0)[0]
	if res.Status != "ok" {
		t.Fatalf("slow link: status %s (%s), want ok", res.Status, res.Error)
	}
	if res.DownMbps < 0.4 || res.DownMbps > 1.6 || res.UpMbps < 0.4 || res.UpMbps > 1.6 {
		t.Fatalf("slow link speeds ↓%.2f ↑%.2f Mbps, want about 1", res.DownMbps, res.UpMbps)
	}
}

// A link whose data stops is frozen, and is called that within a few seconds
// of stopping, not when some budget runs out.
func TestProbeFrozenLinkIsThrottled(t *testing.T) {
	old := probeStallWindow
	probeStallWindow = time.Second
	defer func() { probeStallWindow = old }()

	ln, err := StartProbeListener("127.0.0.1", 0, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Fast, then nothing after 40 KB in either direction: past the handshake
	// and pings, inside the first transfer.
	addr, stop := shapedProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Port)), 50_000_000, 40*1024)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	res := RunProbeDialer(ctx, []ProbeCandidateSpec{plainSpecTo(addr)}, ln.Secret, 0)[0]
	if res.Status != "throttled" {
		t.Fatalf("frozen link: status %s (%s), want throttled", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "stopped") {
		t.Fatalf("frozen link error %q, want it to say the data stopped", res.Error)
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Fatalf("a frozen link took %s to be called frozen", took)
	}
}

func TestProbeSizeFor(t *testing.T) {
	soft := time.Now().Add(5 * time.Second)
	if got := probeSizeFor(0, 384<<10, soft); got != 384<<10 {
		t.Fatalf("unknown rate: %d, want the default", got)
	}
	if got := probeSizeFor(50e6, 384<<10, soft); got != 384<<10 {
		t.Fatalf("fast link: %d, want the default", got)
	}
	got := probeSizeFor(125_000, 384<<10, soft)
	if got >= 384<<10 || got < probeMinMeasure {
		t.Fatalf("slow link: %d, want smaller than the default and at least the floor", got)
	}
	if got := probeSizeFor(1000, 384<<10, soft); got != probeMinMeasure {
		t.Fatalf("very slow link: %d, want the floor", got)
	}
}

// The listener never takes a port it is told to avoid, even when asked for it.
func TestProbeListenerAvoidsPorts(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	want := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	ln, err := StartProbeListenerAvoiding("127.0.0.1", want, map[int]bool{want: true}, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if ln.Port == want {
		t.Fatalf("listener took avoided port %d", want)
	}
	_ = io.Discard
}
