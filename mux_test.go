package main

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// counter sits in the path of the cross-border connection and counts how many
// real connections are made through it. That is the only way to check the claim
// multiplexing actually makes: that many sessions ride on a few connections.
type counter struct {
	addr string
	ln   net.Listener
	to   string

	mu sync.Mutex
	n  int
}

func startCounter(t *testing.T, to string) *counter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("counter listen: %v", err)
	}
	c := &counter{addr: ln.Addr().String(), ln: ln, to: to}
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.n++
			c.mu.Unlock()

			out, err := net.DialTimeout("tcp", c.to, 5*time.Second)
			if err != nil {
				_ = in.Close()
				continue
			}
			go func() {
				defer in.Close()
				defer out.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(out, in); close(done) }()
				_, _ = io.Copy(in, out)
				<-done
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// startTunnelMux brings up both halves with sessions shared over a few links.
// dialVia, when set, is the address the dialling side should use instead of the
// real one, so a counter can be placed in between.
func startTunnelMux(t *testing.T, mode Mode, tr Transport, serviceAddr string, links int, dialVia func(real string) string) *tunnel {
	t.Helper()

	bindAddr := freeAddr(t)
	userAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)
	certFile, keyFile := certPaths(t)

	dialAddr := bindAddr
	if dialVia != nil {
		dialAddr = dialVia(bindAddr)
	}

	mk := func(role Role) *Config {
		cfg := defaultConfig()
		cfg.Name = "mx" + string(role)
		cfg.Mode = mode
		cfg.Role = role
		cfg.MaxConn = 200
		cfg.MaxPending = 64
		cfg.Drain = 2 * time.Second
		cfg.SecretFile = secretPath
		cfg.StatusFile = ""
		cfg.Transport = tr
		cfg.CertFile = certFile
		cfg.KeyFile = keyFile
		cfg.Mux = true
		cfg.MuxLinks = links

		// Whichever side dials must aim at the counter; the other binds for real.
		if cfg.Dials() {
			cfg.TunnelAddr = dialAddr
		} else {
			cfg.TunnelAddr = bindAddr
		}
		if role == RoleEdge {
			cfg.UserListen = userAddr
		} else {
			cfg.InboundAddr = serviceAddr
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config %s/%s/%s: %v", mode, tr, role, err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatalf("secret: %v", err)
		}
		return cfg
	}

	edgeCfg, originCfg := mk(RoleEdge), mk(RoleOrigin)

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
		time.Sleep(200 * time.Millisecond)
		startEdge()
	} else {
		startEdge()
		time.Sleep(200 * time.Millisecond)
		startOrigin()
	}
	time.Sleep(1200 * time.Millisecond)

	return &tunnel{userAddr: userAddr, stop: func() { cancel(); wg.Wait() }}
}

// Sharing links must not change what a user sees, in either direction and with
// or without a disguise.
func TestMuxTrafficFlowsInBothModes(t *testing.T) {
	for _, tr := range []Transport{TransportPlain, TransportTLS} {
		for _, mode := range []Mode{ModeDirect, ModeReverse} {
			t.Run(string(tr)+"/"+string(mode), func(t *testing.T) {
				svc := startService(t)
				defer svc.stop()

				tun := startTunnelMux(t, mode, tr, svc.addr, 2, nil)
				defer tun.stop()

				// Links sitting idle must not have touched the service. Holding
				// connections open to it that carry nothing is what makes a
				// service log rubbish and eventually hang up.
				if n := svc.connections(); n != 0 {
					t.Fatalf("service saw %d connections before any user", n)
				}

				got, err := roundTrip(t, tun.userAddr, "hello-shared", 15*time.Second)
				if err != nil {
					t.Fatalf("round trip failed: %v", err)
				}
				if got != "HELLO-SHARED" {
					t.Fatalf("got %q", got)
				}
				if n := svc.connections(); n != 1 {
					t.Fatalf("service saw %d connections after one user; want 1", n)
				}
			})
		}
	}
}

// The actual claim: a crowd of users must not turn into a crowd of connections
// across the border.
func TestMuxKeepsTheNumberOfRealConnectionsDown(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	var cnt *counter
	tun := startTunnelMux(t, ModeDirect, TransportPlain, svc.addr, 3, func(real string) string {
		cnt = startCounter(t, real)
		return cnt.addr
	})
	defer tun.stop()

	const users = 60
	var wg sync.WaitGroup
	errs := make(chan error, users)
	for i := 0; i < users; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := roundTrip(t, tun.userAddr, "crowd", 20*time.Second); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a user failed: %v", err)
	}

	if n := svc.connections(); n != users {
		t.Fatalf("service saw %d connections for %d users", n, users)
	}
	// Three links were asked for. A little slack for one being replaced, but
	// nothing like sixty.
	if got := cnt.count(); got > 6 {
		t.Fatalf("%d real connections were made across the border for %d users", got, users)
	}
}

// Finishing the upload must not cut off the reply, on a shared link as much as
// on its own connection.
func TestMuxHalfCloseDoesNotTruncate(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tun := startTunnelMux(t, mode, TransportPlain, svc.addr, 2, nil)
			defer tun.stop()

			c, err := net.DialTimeout("tcp", tun.userAddr, 10*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(25 * time.Second))

			payload := bytes.Repeat([]byte("ab"), 256<<10) // 512 KB
			go func() {
				_, _ = c.Write(payload)
				// Finish sending, then expect the whole reply anyway.
				_ = c.(*net.TCPConn).CloseWrite()
			}()

			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read all: %v", err)
			}
			if !bytes.Equal(got, bytes.ToUpper(payload)) {
				t.Fatalf("got %d bytes back, wanted %d", len(got), len(payload))
			}
		})
	}
}

// A large transfer must arrive unchanged, which is where a framing mistake or a
// flow-control mistake would show up.
func TestMuxLargeTransferIsUnchanged(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	tun := startTunnelMux(t, ModeDirect, TransportTLS, svc.addr, 2, nil)
	defer tun.stop()

	payload := make([]byte, 3<<20)
	rnd := rand.New(rand.NewSource(3))
	for i := range payload {
		payload[i] = byte('a' + rnd.Intn(26))
	}

	c, err := net.DialTimeout("tcp", tun.userAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))

	go func() {
		_, _ = c.Write(payload)
		_ = c.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, bytes.ToUpper(payload)) {
		t.Fatalf("%d bytes came back, wanted %d", len(got), len(payload))
	}
}

// Several users at once, each with their own data, must not have it mixed up.
func TestMuxConcurrentUsersKeepTheirOwnData(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	tun := startTunnelMux(t, ModeReverse, TransportPlain, svc.addr, 3, nil)
	defer tun.stop()

	const users = 30
	var wg sync.WaitGroup
	bad := make(chan string, users)
	for i := 0; i < users; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := bytes.Repeat([]byte{byte('a' + i%26)}, 4096)
			c, err := net.DialTimeout("tcp", tun.userAddr, 20*time.Second)
			if err != nil {
				bad <- "dial failed"
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := c.Write(want); err != nil {
				bad <- "write failed"
				return
			}
			got := make([]byte, len(want))
			if _, err := io.ReadFull(c, got); err != nil {
				bad <- "read failed"
				return
			}
			if !bytes.Equal(got, bytes.ToUpper(want)) {
				bad <- "a user got somebody else's bytes"
			}
		}(i)
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
}

// Stopping must be prompt. Idle shared links are blocked on a read that a
// cancelled context alone does not interrupt, which is exactly the mistake that
// once made shutdown take minutes.
func TestMuxShutdownIsPrompt(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tun := startTunnelMux(t, mode, TransportPlain, svc.addr, 3, nil)

			done := make(chan struct{})
			go func() {
				tun.stop()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("shutting down took too long")
			}
		})
	}
}

// A wrong secret must be refused before any session can be started, the same as
// on a connection of its own.
func TestMuxWrongSecretIsRefused(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	bindAddr := freeAddr(t)
	userAddr := freeAddr(t)

	mk := func(role Role, secret string) *Config {
		cfg := defaultConfig()
		cfg.Name = "mxbad" + string(role)
		cfg.Mode = ModeDirect
		cfg.Role = role
		cfg.TunnelAddr = bindAddr
		cfg.MaxConn = 50
		cfg.MaxPending = 32
		cfg.Drain = time.Second
		cfg.SecretFile = writeSecret(t, secret)
		cfg.StatusFile = ""
		cfg.Mux = true
		cfg.MuxLinks = 2
		if role == RoleEdge {
			cfg.UserListen = userAddr
		} else {
			cfg.InboundAddr = svc.addr
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config: %v", err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatalf("secret: %v", err)
		}
		return cfg
	}

	edgeCfg := mk(RoleEdge, testSecret)
	originCfg := mk(RoleOrigin, "a-completely-different-secret")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = runOrigin(ctx, originCfg, newStatus(originCfg)) }()
	time.Sleep(200 * time.Millisecond)
	go func() { defer wg.Done(); _ = runEdge(ctx, edgeCfg, newStatus(edgeCfg)) }()
	time.Sleep(1200 * time.Millisecond)
	defer func() { cancel(); wg.Wait() }()

	if _, err := roundTrip(t, userAddr, "should-not-work", 8*time.Second); err == nil {
		t.Fatal("traffic went through with the wrong secret")
	}
	if n := svc.connections(); n != 0 {
		t.Fatalf("the service was touched %d times despite the wrong secret", n)
	}
}

// Turning multiplexing on must not be possible with settings that cannot work.
func TestMuxSettingsValidation(t *testing.T) {
	base := func() *Config {
		cfg := defaultConfig()
		cfg.Name = "v"
		cfg.Mode = ModeDirect
		cfg.Role = RoleEdge
		cfg.TunnelAddr = "1.2.3.4:443"
		cfg.UserListen = "0.0.0.0:8443"
		cfg.SecretFile = "/tmp/secret"
		cfg.Mux = true
		return cfg
	}

	cfg := base()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a plain multiplexed tunnel should be valid: %v", err)
	}

	cfg = base()
	cfg.MuxLinks = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero links was accepted")
	}

	cfg = base()
	cfg.MuxLinks = 500
	if err := cfg.Validate(); err == nil {
		t.Fatal("an absurd number of links was accepted")
	}
}

// The startup line must say which arrangement is in use, because the two behave
// differently enough that a log without it is confusing.
func TestMuxSummarySaysSo(t *testing.T) {
	cfg := defaultConfig()
	cfg.Name = "s"
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.TunnelAddr = "1.2.3.4:443"
	cfg.UserListen = "0.0.0.0:8443"

	if got := cfg.Summary(); !bytes.Contains([]byte(got), []byte("Spares")) {
		t.Fatalf("without multiplexing the summary should mention spares: %s", got)
	}

	cfg.Mux = true
	cfg.MuxLinks = 5
	got := cfg.Summary()
	if !bytes.Contains([]byte(got), []byte("share 5 long-lived")) {
		t.Fatalf("with multiplexing the summary should say so: %s", got)
	}
}
