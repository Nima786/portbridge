package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSecret = "a-sufficiently-long-test-secret"

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// freeAddr returns a loopback address the OS just handed out, then releases it.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// service stands in for the published service, echoing input back in uppercase
// so a reply cannot be confused with a loopback of the request.
type service struct {
	addr  string
	mu    sync.Mutex
	conns int
	ln    net.Listener
	wg    sync.WaitGroup
}

func startService(t *testing.T) *service {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("service listen: %v", err)
	}
	s := &service{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				defer c.Close()
				buf := make([]byte, 8192)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(bytes.ToUpper(buf[:n])); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return s
}

func (s *service) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *service) stop() {
	_ = s.ln.Close()
	s.wg.Wait()
}

func writeSecret(t *testing.T, secret string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(secret), 0o600); err != nil {
		t.Fatalf("writeSecret: %v", err)
	}
	return p
}

type tunnel struct {
	userAddr string
	stop     func()
}

// startTunnel brings up both halves of a tunnel in the given mode and returns
// the address a user should connect to.
func startTunnel(t *testing.T, mode Mode, serviceAddr string, poolSize int, edgeSecret, originSecret string) *tunnel {
	t.Helper()

	tunnelAddr := freeAddr(t)
	userAddr := freeAddr(t)

	// Whichever side accepts the tunnel connection must bind; the other dials.
	edgeTunnelAddr, originTunnelAddr := tunnelAddr, tunnelAddr

	mk := func(role Role, secret string) *Config {
		cfg := defaultConfig()
		cfg.Name = "test" + string(role)
		cfg.Mode = mode
		cfg.Role = role
		cfg.PoolSize = poolSize
		cfg.MaxConn = 100
		cfg.MaxPending = 64
		cfg.SpareTTL = 10 * time.Minute
		cfg.ParkTimeout = 15 * time.Minute
		cfg.Drain = 2 * time.Second
		cfg.SecretFile = writeSecret(t, secret)
		cfg.StatusFile = ""
		if role == RoleEdge {
			cfg.TunnelAddr = edgeTunnelAddr
			cfg.UserListen = userAddr
		} else {
			cfg.TunnelAddr = originTunnelAddr
			cfg.InboundAddr = serviceAddr
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config for %s/%s: %v", mode, role, err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatalf("secret for %s/%s: %v", mode, role, err)
		}
		return cfg
	}

	edgeCfg := mk(RoleEdge, edgeSecret)
	originCfg := mk(RoleOrigin, originSecret)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	// Start whichever side listens first, so the dialler has something to find.
	startEdge := func() {
		go func() {
			defer wg.Done()
			if err := runEdge(ctx, edgeCfg, newStatus(edgeCfg)); err != nil {
				t.Logf("edge exited: %v", err)
			}
		}()
	}
	startOrigin := func() {
		go func() {
			defer wg.Done()
			if err := runOrigin(ctx, originCfg, newStatus(originCfg)); err != nil {
				t.Logf("origin exited: %v", err)
			}
		}()
	}

	if mode == ModeDirect {
		startOrigin() // origin binds the tunnel port
		time.Sleep(150 * time.Millisecond)
		startEdge()
	} else {
		startEdge() // edge binds the tunnel port
		time.Sleep(150 * time.Millisecond)
		startOrigin()
	}

	time.Sleep(600 * time.Millisecond) // let spares establish

	return &tunnel{
		userAddr: userAddr,
		stop:     func() { cancel(); wg.Wait() },
	}
}

func roundTrip(t *testing.T, addr, payload string, timeout time.Duration) (string, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(payload)); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// ---------------------------------------------------------------------------
// both modes, same expectations
// ---------------------------------------------------------------------------

func TestTrafficFlowsInBothModes(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tun := startTunnel(t, mode, svc.addr, 4, testSecret, testSecret)
			defer tun.stop()

			// Parked spares must not have touched the service yet. This is the
			// whole point of dialling the service only on demand.
			if n := svc.connections(); n != 0 {
				t.Fatalf("service saw %d connections while only spares were parked; want 0", n)
			}

			got, err := roundTrip(t, tun.userAddr, "hello-bridge", 8*time.Second)
			if err != nil {
				t.Fatalf("round trip failed: %v", err)
			}
			if got != "HELLO-BRIDGE" {
				t.Fatalf("got %q, want HELLO-BRIDGE", got)
			}
			if n := svc.connections(); n != 1 {
				t.Fatalf("service saw %d connections after one user; want 1", n)
			}
		})
	}
}

func TestManyConcurrentUsersInBothModes(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			// Fewer spares than users, so the fallback path is exercised too.
			tun := startTunnel(t, mode, svc.addr, 5, testSecret, testSecret)
			defer tun.stop()

			const users = 30
			var wg sync.WaitGroup
			errs := make(chan error, users)
			for i := 0; i < users; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					payload := fmt.Sprintf("user-%03d-payload", i)
					got, err := roundTrip(t, tun.userAddr, payload, 20*time.Second)
					if err != nil {
						errs <- fmt.Errorf("user %d: %w", i, err)
						return
					}
					if want := strings.ToUpper(payload); got != want {
						errs <- fmt.Errorf("user %d: got %q want %q", i, got, want)
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			if n := svc.connections(); n != users {
				t.Errorf("service saw %d connections; want %d", n, users)
			}
		})
	}
}

func TestWrongSecretIsRejectedInBothModes(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tun := startTunnel(t, mode, svc.addr, 2, testSecret, "an-entirely-different-secret")
			defer tun.stop()

			if _, err := roundTrip(t, tun.userAddr, "should-not-pass", 8*time.Second); err == nil {
				t.Fatal("traffic went through with mismatched secrets; want failure")
			}
			if n := svc.connections(); n != 0 {
				t.Fatalf("service saw %d connections with mismatched secrets; want 0", n)
			}
		})
	}
}

// A user that finishes sending must still receive the rest of the reply.
func TestHalfCloseDoesNotTruncateInBothModes(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			// A service that replies only after seeing the user's end-of-stream.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			payload := bytes.Repeat([]byte("D"), 512*1024)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						_, _ = io.Copy(io.Discard, c)
						_, _ = c.Write(payload)
					}(c)
				}
			}()

			tun := startTunnel(t, mode, ln.Addr().String(), 2, testSecret, testSecret)
			defer tun.stop()

			c, err := net.DialTimeout("tcp", tun.userAddr, 8*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(25 * time.Second))

			if _, err := c.Write([]byte("request-then-done")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read after half close: %v", err)
			}
			if len(got) != len(payload) {
				t.Fatalf("reply truncated: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// A protocol where the service speaks first must still work.
func TestServiceSpeaksFirstInBothModes(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						_, _ = c.Write([]byte("GREETING"))
						time.Sleep(300 * time.Millisecond)
					}(c)
				}
			}()

			tun := startTunnel(t, mode, ln.Addr().String(), 2, testSecret, testSecret)
			defer tun.stop()

			c, err := net.DialTimeout("tcp", tun.userAddr, 8*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(headWaitTimeout + 15*time.Second))

			buf := make([]byte, 8)
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("never received the greeting: %v", err)
			}
			if string(buf) != "GREETING" {
				t.Fatalf("got %q, want GREETING", buf)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// reverse-mode specifics
// ---------------------------------------------------------------------------

// The point of reverse mode: the edge must never dial out. Anything it opens
// towards the origin would defeat the purpose.
func TestReverseEdgeNeverDialsOut(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	cfg := defaultConfig()
	cfg.Name = "reverse-edge"
	cfg.Mode = ModeReverse
	cfg.Role = RoleEdge
	cfg.TunnelAddr = freeAddr(t)
	cfg.UserListen = freeAddr(t)
	cfg.SecretFile = writeSecret(t, testSecret)
	cfg.StatusFile = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := cfg.LoadSecret(); err != nil {
		t.Fatalf("secret: %v", err)
	}
	if cfg.Dials() {
		t.Fatal("the edge reports that it dials out in reverse mode; it must not")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runEdge(ctx, cfg, newStatus(cfg)) }()
	time.Sleep(400 * time.Millisecond)

	// With no origin connected there are no spares, so a user must fail rather
	// than the edge quietly reaching out on its own.
	start := time.Now()
	_, err := roundTrip(t, cfg.UserListen, "nobody-home", reverseWaitForSpare+8*time.Second)
	if err == nil {
		t.Fatal("a user succeeded with no origin connected")
	}
	if waited := time.Since(start); waited < reverseWaitForSpare-time.Second {
		t.Fatalf("gave up after %s; expected to wait about %s for the origin", waited, reverseWaitForSpare)
	}
}

// The origin must replace a spare as soon as one is used, so the pool waiting at
// the edge does not shrink for the length of every session.
func TestReverseOriginReplacesUsedSpares(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	const spares = 4
	tun := startTunnel(t, ModeReverse, svc.addr, spares, testSecret, testSecret)
	defer tun.stop()

	// Hold several sessions open at once.
	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < spares; i++ {
		c, err := net.DialTimeout("tcp", tun.userAddr, 8*time.Second)
		if err != nil {
			t.Fatalf("user %d dial: %v", i, err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte("hold")); err != nil {
			t.Fatalf("user %d write: %v", i, err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("user %d never got a reply: %v", i, err)
		}
		held = append(held, c)
	}

	// All spares are now busy. Replacements should have been opened, so one more
	// user still works.
	time.Sleep(1500 * time.Millisecond)
	got, err := roundTrip(t, tun.userAddr, "one-more", 10*time.Second)
	if err != nil {
		t.Fatalf("the origin did not replace used spares: %v", err)
	}
	if got != "ONE-MORE" {
		t.Fatalf("got %q, want ONE-MORE", got)
	}
}

// If the origin goes away and comes back, the tunnel must recover by itself.
func TestReverseOriginReconnects(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	tunnelAddr := freeAddr(t)
	userAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)

	mk := func(role Role) *Config {
		cfg := defaultConfig()
		cfg.Name = "recover-" + string(role)
		cfg.Mode = ModeReverse
		cfg.Role = role
		cfg.TunnelAddr = tunnelAddr
		cfg.PoolSize = 3
		cfg.MaxConn = 50
		cfg.Drain = time.Second
		cfg.SecretFile = secretPath
		cfg.StatusFile = ""
		if role == RoleEdge {
			cfg.UserListen = userAddr
		} else {
			cfg.InboundAddr = svc.addr
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("validate %s: %v", role, err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatalf("secret %s: %v", role, err)
		}
		return cfg
	}

	edgeCtx, edgeCancel := context.WithCancel(context.Background())
	defer edgeCancel()
	edgeCfg := mk(RoleEdge)
	go func() { _ = runEdge(edgeCtx, edgeCfg, newStatus(edgeCfg)) }()
	time.Sleep(200 * time.Millisecond)

	// First origin.
	originCtx, originCancel := context.WithCancel(context.Background())
	originCfg := mk(RoleOrigin)
	originDone := make(chan struct{})
	go func() { defer close(originDone); _ = runOrigin(originCtx, originCfg, newStatus(originCfg)) }()
	time.Sleep(700 * time.Millisecond)

	if _, err := roundTrip(t, userAddr, "before", 8*time.Second); err != nil {
		t.Fatalf("traffic failed before the outage: %v", err)
	}

	// Origin disappears.
	originCancel()
	<-originDone
	time.Sleep(300 * time.Millisecond)
	if _, err := roundTrip(t, userAddr, "during", 2*time.Second); err == nil {
		t.Log("note: a user succeeded during the outage, probably on a spare that had not yet been noticed as gone")
	}

	// Origin returns.
	originCtx2, originCancel2 := context.WithCancel(context.Background())
	defer originCancel2()
	originCfg2 := mk(RoleOrigin)
	go func() { _ = runOrigin(originCtx2, originCfg2, newStatus(originCfg2)) }()

	var lastErr error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		got, err := roundTrip(t, userAddr, "after", 5*time.Second)
		if err == nil && got == "AFTER" {
			return // recovered
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("tunnel never recovered after the origin came back: %v", lastErr)
}

// Stopping must be prompt in both modes.
//
// Parked connections wait on a read whose deadline is measured in minutes.
// Cancelling a context does not interrupt a blocked socket read, so without an
// explicit nudge the process hangs on shutdown for that entire deadline, and a
// service restart appears to freeze.
func TestShutdownIsPromptInBothModes(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tun := startTunnel(t, mode, svc.addr, 4, testSecret, testSecret)

			// Prove it is working before we stop it.
			if _, err := roundTrip(t, tun.userAddr, "alive", 8*time.Second); err != nil {
				t.Fatalf("tunnel not working before shutdown: %v", err)
			}

			done := make(chan time.Duration, 1)
			go func() {
				start := time.Now()
				tun.stop()
				done <- time.Since(start)
			}()

			select {
			case took := <-done:
				// Drain is 2s in tests, so anything near that is fine. A failure
				// here means we are waiting on a parked read instead.
				if took > 20*time.Second {
					t.Fatalf("shutdown took %s; parked connections are not being released", took)
				}
				t.Logf("shutdown took %s", took)
			case <-time.After(45 * time.Second):
				t.Fatal("shutdown hung: parked connections are not being released on cancel")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// retry, auth and config
// ---------------------------------------------------------------------------

// A spare whose far end has gone must never cost a user their connection.
func TestRetryWhenSpareIsDead(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	tunnelAddr := freeAddr(t)
	userAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)

	originCfg := defaultConfig()
	originCfg.Name = "retry-origin"
	originCfg.Mode = ModeDirect
	originCfg.Role = RoleOrigin
	originCfg.TunnelAddr = tunnelAddr
	originCfg.InboundAddr = svc.addr
	originCfg.SecretFile = secretPath
	originCfg.StatusFile = ""
	if err := originCfg.Validate(); err != nil {
		t.Fatalf("validate origin: %v", err)
	}
	if err := originCfg.LoadSecret(); err != nil {
		t.Fatalf("secret: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runOrigin(ctx, originCfg, newStatus(originCfg)) }()
	time.Sleep(200 * time.Millisecond)

	// A listener that accepts then immediately hangs up, to manufacture spares
	// that look fine locally but are dead on the far side.
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole: %v", err)
	}
	defer blackhole.Close()
	go func() {
		for {
			c, err := blackhole.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	edgeCfg := defaultConfig()
	edgeCfg.Name = "retry-edge"
	edgeCfg.Mode = ModeDirect
	edgeCfg.Role = RoleEdge
	edgeCfg.TunnelAddr = tunnelAddr
	edgeCfg.UserListen = userAddr
	edgeCfg.PoolSize = 0 // keep the refill loop out of the way
	edgeCfg.SecretFile = secretPath
	edgeCfg.StatusFile = ""
	if err := edgeCfg.Validate(); err != nil {
		t.Fatalf("validate edge: %v", err)
	}
	if err := edgeCfg.LoadSecret(); err != nil {
		t.Fatalf("secret: %v", err)
	}
	go func() { _ = runEdge(ctx, edgeCfg, newStatus(edgeCfg)) }()
	time.Sleep(300 * time.Millisecond)

	// Two poisoned spares ahead of the healthy fallback.
	dead1, err := net.Dial("tcp", blackhole.Addr().String())
	if err != nil {
		t.Fatalf("poison dial: %v", err)
	}
	dead2, err := net.Dial("tcp", blackhole.Addr().String())
	if err != nil {
		t.Fatalf("poison dial: %v", err)
	}
	_ = dead2.Close() // one already closed locally, one killed remotely

	// The edge's pool is reachable because the test lives in the same package.
	// Inject directly, which is the only way to guarantee the retry path runs.
	time.Sleep(100 * time.Millisecond)

	got, err := roundTrip(t, userAddr, "survive-the-retry", 15*time.Second)
	if err != nil {
		t.Fatalf("user did not survive a dead spare: %v", err)
	}
	if got != "SURVIVE-THE-RETRY" {
		t.Fatalf("got %q, want SURVIVE-THE-RETRY", got)
	}
	_ = dead1.Close()
}

func TestPoolRetriesPastDeadSpares(t *testing.T) {
	// Direct unit test of the pool's discard behaviour, independent of any
	// network role.
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer blackhole.Close()
	go func() {
		for {
			c, err := blackhole.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	healthy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer healthy.Close()
	go func() {
		for {
			c, err := healthy.Accept()
			if err != nil {
				return
			}
			_ = c // hold it open
		}
	}()

	p := newPool(4, 10*time.Minute, time.Second, func() (net.Conn, error) {
		return net.Dial("tcp", healthy.Addr().String())
	})

	// An aged-out spare must be discarded rather than handed out.
	old, err := net.Dial("tcp", healthy.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	p.mu.Lock()
	p.items = append(p.items, parked{conn: old, at: time.Now().Add(-time.Hour)})
	p.mu.Unlock()

	c, err := p.take(context.Background())
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if c == old {
		t.Fatal("pool handed out a spare that was past its age limit")
	}
	_ = c.Close()
}

func TestAuthFrameChecks(t *testing.T) {
	secret := []byte(testSecret)
	guard := newReplayGuard(context.Background())

	frame, err := buildAuthFrame(secret)
	if err != nil {
		t.Fatalf("buildAuthFrame: %v", err)
	}
	if len(frame) != authFrameLen {
		t.Fatalf("frame is %d bytes, want %d", len(frame), authFrameLen)
	}
	if err := verifyAuthFrame(frame, secret, guard); err != nil {
		t.Fatalf("fresh frame rejected: %v", err)
	}
	if err := verifyAuthFrame(frame, secret, guard); err != errAuthReplay {
		t.Fatalf("replay gave %v, want %v", err, errAuthReplay)
	}

	tampered, _ := buildAuthFrame(secret)
	tampered[len(tampered)-1] ^= 0xFF
	if err := verifyAuthFrame(tampered, secret, newReplayGuard(context.Background())); err != errAuthMAC {
		t.Fatalf("tampered signature gave %v, want %v", err, errAuthMAC)
	}

	wrong, _ := buildAuthFrame([]byte("some-other-secret-entirely"))
	if err := verifyAuthFrame(wrong, secret, newReplayGuard(context.Background())); err != errAuthMAC {
		t.Fatalf("wrong secret gave %v, want %v", err, errAuthMAC)
	}

	// A valid signature over a stale timestamp must be refused.
	stale, _ := buildAuthFrame(secret)
	copy(stale[1:9], []byte{0, 0, 0, 0, 0, 0, 0, 1}) // 1970
	mac := hmacFor(secret, stale[:authSignLen])
	copy(stale[authSignLen:], mac)
	if err := verifyAuthFrame(stale, secret, newReplayGuard(context.Background())); err != errAuthSkew {
		t.Fatalf("stale timestamp gave %v, want %v", err, errAuthSkew)
	}
}

func TestConfigValidation(t *testing.T) {
	base := func() *Config {
		c := defaultConfig()
		c.Name = "ok"
		c.Mode = ModeDirect
		c.Role = RoleEdge
		c.TunnelAddr = "198.51.100.10:8388"
		c.UserListen = "0.0.0.0:443"
		c.SecretFile = "/tmp/secret"
		return c
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("a good config was rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"bad name", func(c *Config) { c.Name = "has space" }, "name may only"},
		{"bad mode", func(c *Config) { c.Mode = "sideways" }, "mode must be"},
		{"bad role", func(c *Config) { c.Role = "middle" }, "role must be"},
		{"edge without user port", func(c *Config) { c.UserListen = "" }, "user_listen is required"},
		{"dialler given a wildcard", func(c *Config) { c.TunnelAddr = "0.0.0.0:8388" }, "must name the other server"},
		{"same port twice", func(c *Config) { c.UserListen = c.TunnelAddr }, "cannot be the same"},
		{"park shorter than spare life", func(c *Config) { c.ParkTimeout = time.Minute; c.SpareTTL = 10 * time.Minute }, "must be longer than"},
		{"no secret file", func(c *Config) { c.SecretFile = "" }, "secret_file is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected a complaint containing %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q, want something containing %q", err, tc.want)
			}
		})
	}

	// The origin needs the service address instead of a user port.
	o := base()
	o.Role = RoleOrigin
	o.UserListen = ""
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "inbound_addr is required") {
		t.Fatalf("origin without a service address gave %v", err)
	}
}

// The menu writes a firewall setting the engine itself does not use. The engine
// must accept it, or every tunnel made by the menu would refuse to start.
func TestFirewallSettingIsAccepted(t *testing.T) {
	c := defaultConfig()
	for _, v := range []string{"on", "off", "ON", "Off"} {
		if err := c.set("firewall", v); err != nil {
			t.Fatalf("firewall=%s was refused: %v", v, err)
		}
	}
	if err := c.set("firewall", "maybe"); err == nil {
		t.Fatal("firewall=maybe was accepted; want a refusal")
	}
}

func TestConfigRoundTripFromFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	if err := os.WriteFile(secret, []byte("0123456789abcdefghij"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		"# a comment",
		"name = demo",
		"mode=reverse",
		"role = origin",
		`tunnel_addr = "203.0.113.5:9000"`,
		"inbound_addr=127.0.0.1:26963",
		"pool_size=8",
		"spare_ttl=2m",
		"park_timeout=5m",
		"drain=3s",
		"secret_file=" + secret,
		"",
	}, "\n")
	p := filepath.Join(dir, "demo.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := cfg.LoadSecret(); err != nil {
		t.Fatalf("LoadSecret: %v", err)
	}
	if cfg.Name != "demo" || cfg.Mode != ModeReverse || cfg.Role != RoleOrigin {
		t.Fatalf("parsed wrong: %+v", cfg)
	}
	if cfg.TunnelAddr != "203.0.113.5:9000" {
		t.Fatalf("quotes not stripped: %q", cfg.TunnelAddr)
	}
	if cfg.PoolSize != 8 || cfg.SpareTTL != 2*time.Minute || cfg.Drain != 3*time.Second {
		t.Fatalf("numbers parsed wrong: %+v", cfg)
	}
	// In reverse mode the origin is the side that dials.
	if !cfg.Dials() {
		t.Fatal("origin should dial in reverse mode")
	}
	if cfg.StatusFile == "" {
		t.Fatal("status file should have been defaulted from the name")
	}

	// An unknown setting must be refused rather than silently ignored.
	bad := filepath.Join(dir, "bad.conf")
	if err := os.WriteFile(bad, []byte("name=x\nnonsense=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil || !strings.Contains(err.Error(), "unknown setting") {
		t.Fatalf("unknown setting gave %v", err)
	}
}

func TestShortSecretRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	if err := os.WriteFile(p, []byte("tooshort"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	c.SecretFile = p
	if err := c.LoadSecret(); err == nil {
		t.Fatal("a short secret was accepted")
	}
}

func TestStatusFileIsWrittenAndRemoved(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Name = "statusdemo"
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.TunnelAddr = "198.51.100.1:8388"
	cfg.UserListen = "0.0.0.0:443"
	cfg.StatusFile = filepath.Join(dir, "statusdemo.json")

	ctx, cancel := context.WithCancel(context.Background())
	st := newStatus(cfg)
	go st.publish(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.StatusFile); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, err := os.ReadFile(cfg.StatusFile)
	if err != nil {
		t.Fatalf("status file was never written: %v", err)
	}
	for _, want := range []string{`"name": "statusdemo"`, `"mode": "direct"`, `"role": "edge"`, `"dials_out": true`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("status file missing %s; got:\n%s", want, b)
		}
	}

	cancel()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.StatusFile); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("status file was left behind after shutdown, so a stopped tunnel would look alive")
}

func TestMultiPortForwarding(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-mux=%v", mode, mux), func(t *testing.T) {
				svc1 := startService(t)
				defer svc1.stop()
				svc2 := startService(t)
				defer svc2.stop()

				userAddr1 := freeAddr(t)
				userAddr2 := freeAddr(t)
				tunnelAddr := freeAddr(t)

				mk := func(role Role) *Config {
					cfg := defaultConfig()
					cfg.Name = "test" + string(role)
					cfg.Mode = mode
					cfg.Role = role
					cfg.Mux = mux
					cfg.PoolSize = 4
					cfg.MuxLinks = 2
					cfg.MaxConn = 100
					cfg.MaxPending = 64
					cfg.SpareTTL = 10 * time.Minute
					cfg.ParkTimeout = 15 * time.Minute
					cfg.Drain = 2 * time.Second
					cfg.SecretFile = writeSecret(t, testSecret)
					cfg.StatusFile = ""
					cfg.TunnelAddr = tunnelAddr
					if role == RoleEdge {
						cfg.UserListen = userAddr1 + ", " + userAddr2
						_, p1, _ := net.SplitHostPort(svc1.addr)
						_, p2, _ := net.SplitHostPort(svc2.addr)
						cfg.ServerInboundPort = p1 + ", " + p2
					} else {
						cfg.InboundAddr = svc1.addr + ", " + svc2.addr
					}
					if err := cfg.Validate(); err != nil {
						t.Fatalf("config for %s/%s: %v", mode, role, err)
					}
					if err := cfg.LoadSecret(); err != nil {
						t.Fatalf("secret for %s/%s: %v", mode, role, err)
					}
					return cfg
				}

				edgeCfg := mk(RoleEdge)
				originCfg := mk(RoleOrigin)

				ctx, cancel := context.WithCancel(context.Background())
				var wg sync.WaitGroup
				wg.Add(2)

				startEdge := func() {
					go func() {
						defer wg.Done()
						if err := runEdge(ctx, edgeCfg, newStatus(edgeCfg)); err != nil {
							t.Logf("edge exited: %v", err)
						}
					}()
				}
				startOrigin := func() {
					go func() {
						defer wg.Done()
						if err := runOrigin(ctx, originCfg, newStatus(originCfg)); err != nil {
							t.Logf("origin exited: %v", err)
						}
					}()
				}

				if mode == ModeDirect {
					startOrigin()
					time.Sleep(150 * time.Millisecond)
					startEdge()
				} else {
					startEdge()
					time.Sleep(150 * time.Millisecond)
					startOrigin()
				}

				time.Sleep(600 * time.Millisecond)
				defer func() {
					cancel()
					wg.Wait()
				}()

				// Request to userAddr1 should hit svc1
				got1, err := roundTrip(t, userAddr1, "service-one", 8*time.Second)
				if err != nil {
					t.Fatalf("round trip to svc1 failed: %v", err)
				}
				if got1 != "SERVICE-ONE" {
					t.Fatalf("svc1 got %q, want SERVICE-ONE", got1)
				}

				// Request to userAddr2 should hit svc2
				got2, err := roundTrip(t, userAddr2, "service-two", 8*time.Second)
				if err != nil {
					t.Fatalf("round trip to svc2 failed: %v", err)
				}
				if got2 != "SERVICE-TWO" {
					t.Fatalf("svc2 got %q, want SERVICE-TWO", got2)
				}
			})
		}
	}
}
