package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// listenAt gives back a listener that accepts and immediately closes, which is
// all a route test needs: whether the address can be reached at all.
func listenAt(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// With only one route there is nothing to choose, and it must still work.
func TestRouteSingleTarget(t *testing.T) {
	addr, stop := listenAt(t)
	defer stop()

	cfg := defaultConfig()
	cfg.TunnelAddr = addr
	r := newRouter(cfg)

	if len(r.targets) != 1 {
		t.Fatalf("expected one route, got %v", r.targets)
	}
	c, err := r.dial(2 * time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
	if got := r.describe(); got != addr {
		t.Fatalf("describe said %q", got)
	}
}

// The preferred route must be used when it works, and the fallback left alone.
func TestRoutePrefersTheFirst(t *testing.T) {
	first, stopFirst := listenAt(t)
	defer stopFirst()
	second, stopSecond := listenAt(t)
	defer stopSecond()

	cfg := defaultConfig()
	cfg.TunnelAddr = first
	cfg.AltTarget = second
	r := newRouter(cfg)

	c, err := r.dial(2 * time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := c.RemoteAddr().String(); got != first {
		t.Fatalf("went to %s instead of the preferred %s", got, first)
	}
	_ = c.Close()
}

// When the preferred route cannot be reached, the fallback must carry it. This is
// the whole point: the far server is fine, its address is simply unreachable.
func TestRouteFallsBackWhenTheFirstIsUnreachable(t *testing.T) {
	// A closed port stands in for a blocked address.
	dead, stopDead := listenAt(t)
	stopDead()
	alive, stopAlive := listenAt(t)
	defer stopAlive()

	cfg := defaultConfig()
	cfg.TunnelAddr = dead
	cfg.AltTarget = alive
	r := newRouter(cfg)

	c, err := r.dial(2 * time.Second)
	if err != nil {
		t.Fatalf("both routes failed: %v", err)
	}
	if got := c.RemoteAddr().String(); got != alive {
		t.Fatalf("ended up at %s, wanted the fallback %s", got, alive)
	}
	_ = c.Close()

	// Having fallen back, it should stay there rather than pay for the dead
	// route on every single attempt.
	if r.pick() != 1 {
		t.Fatal("it did not stay on the route that worked")
	}
}

// A fallback that is also unreachable must report a failure, not hang or lie.
func TestRouteBothUnreachable(t *testing.T) {
	a, stopA := listenAt(t)
	stopA()
	b, stopB := listenAt(t)
	stopB()

	cfg := defaultConfig()
	cfg.TunnelAddr = a
	cfg.AltTarget = b
	r := newRouter(cfg)

	if c, err := r.dial(time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a connection was reported when neither route works")
	}
}

// After a while it must try the preferred route again, so a block that has been
// lifted is picked up instead of being waited out for ever.
func TestRouteReturnsToThePreferredOne(t *testing.T) {
	first, stopFirst := listenAt(t)
	defer stopFirst()
	second, stopSecond := listenAt(t)
	defer stopSecond()

	cfg := defaultConfig()
	cfg.TunnelAddr = first
	cfg.AltTarget = second
	r := newRouter(cfg)

	// Pretend it fell back a long time ago.
	r.settle(1)
	r.mu.Lock()
	r.lastGood = time.Now().Add(-2 * routeRecheck)
	r.mu.Unlock()

	if r.pick() != 0 {
		t.Fatal("it never went back to trying the preferred route")
	}
}

// A fallback address only makes sense on the side that dials, and has to be a
// real address.
func TestRouteSettingValidation(t *testing.T) {
	base := func() *Config {
		cfg := defaultConfig()
		cfg.Name = "r"
		cfg.Mode = ModeDirect
		cfg.Role = RoleEdge // dials in direct mode
		cfg.TunnelAddr = "1.2.3.4:443"
		cfg.UserListen = "0.0.0.0:8443"
		cfg.SecretFile = "/tmp/secret"
		return cfg
	}

	cfg := base()
	cfg.AltTarget = "link.example.com:443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a hostname fallback should be fine: %v", err)
	}

	cfg = base()
	cfg.AltTarget = "no-port-here"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an address without a port was accepted")
	}

	cfg = base()
	cfg.AltTarget = "0.0.0.0:443"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a listen-anywhere address was accepted as somewhere to dial")
	}

	// The origin waits to be called in direct mode, so it has nothing to dial.
	cfg = base()
	cfg.Role = RoleOrigin
	cfg.UserListen = ""
	cfg.InboundAddr = "127.0.0.1:1080"
	cfg.AltTarget = "link.example.com:443"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a fallback was accepted on the side that only waits")
	}
}

// The startup line must mention the fallback, so which routes exist is visible
// without reading the settings file.
func TestRouteSummaryMentionsTheFallback(t *testing.T) {
	cfg := defaultConfig()
	cfg.Name = "s"
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.TunnelAddr = "1.2.3.4:443"
	cfg.UserListen = "0.0.0.0:8443"

	if got := cfg.Summary(); strings.Contains(got, "falling back") {
		t.Fatalf("no fallback was set, so none should be mentioned: %s", got)
	}

	cfg.AltTarget = "link.example.com:443"
	got := cfg.Summary()
	if !strings.Contains(got, "falling back to link.example.com:443") {
		t.Fatalf("the fallback is missing from the summary: %s", got)
	}
}

// A tunnel with a fallback configured must carry traffic normally when the
// preferred route works, disguise and all.
func TestRouteFallbackTunnelStillWorks(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	// The fallback points at a closed port, so if it were ever preferred the
	// tunnel would not come up at all.
	dead, stopDead := listenAt(t)
	stopDead()

	tun := startTunnelAlt(t, svc.addr, dead)
	defer tun.stop()

	got, err := roundTrip(t, tun.userAddr, "with-a-fallback", 15*time.Second)
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if got != "WITH-A-FALLBACK" {
		t.Fatalf("got %q", got)
	}
}

// And when the preferred route is dead from the start, the tunnel must come up
// on the fallback without anyone intervening.
func TestRouteTunnelComesUpOnTheFallback(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	tun := startTunnelDeadPrimary(t, svc.addr)
	defer tun.stop()

	got, err := roundTrip(t, tun.userAddr, "over-the-fallback", 20*time.Second)
	if err != nil {
		t.Fatalf("the tunnel never came up on the fallback: %v", err)
	}
	if got != "OVER-THE-FALLBACK" {
		t.Fatalf("got %q", got)
	}
}

// startTunnelRoutes brings up a direct-mode tunnel where the edge is told to
// dial primary and fall back to alt, while the origin actually listens on bind.
func startTunnelRoutes(t *testing.T, serviceAddr, bind, primary, alt string) *tunnel {
	t.Helper()

	userAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)

	mk := func(role Role) *Config {
		cfg := defaultConfig()
		cfg.Name = "rt" + string(role)
		cfg.Mode = ModeDirect
		cfg.Role = role
		cfg.PoolSize = 3
		cfg.MaxConn = 50
		cfg.MaxPending = 32
		cfg.Drain = 2 * time.Second
		cfg.SecretFile = secretPath
		cfg.StatusFile = ""
		if role == RoleEdge {
			cfg.TunnelAddr = primary
			cfg.AltTarget = alt
			cfg.UserListen = userAddr
		} else {
			cfg.TunnelAddr = bind
			cfg.InboundAddr = serviceAddr
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config %s: %v", role, err)
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
	go func() {
		defer wg.Done()
		if err := runOrigin(ctx, originCfg, newStatus(originCfg)); err != nil {
			t.Logf("origin exited: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	go func() {
		defer wg.Done()
		if err := runEdge(ctx, edgeCfg, newStatus(edgeCfg)); err != nil {
			t.Logf("edge exited: %v", err)
		}
	}()
	time.Sleep(1200 * time.Millisecond)

	return &tunnel{userAddr: userAddr, stop: func() { cancel(); wg.Wait() }}
}

// startTunnelAlt: the preferred route is the real one, the fallback is dead.
func startTunnelAlt(t *testing.T, serviceAddr, deadAlt string) *tunnel {
	t.Helper()
	bind := freeAddr(t)
	return startTunnelRoutes(t, serviceAddr, bind, bind, deadAlt)
}

// startTunnelDeadPrimary: the preferred route is dead, so only the fallback can
// bring the tunnel up.
func startTunnelDeadPrimary(t *testing.T, serviceAddr string) *tunnel {
	t.Helper()
	bind := freeAddr(t)
	dead, stop := listenAt(t)
	stop()
	return startTunnelRoutes(t, serviceAddr, bind, dead, bind)
}
