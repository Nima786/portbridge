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
	c, _, err := r.dial(2 * time.Second)
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

	c, _, err := r.dial(2 * time.Second)
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

	c, _, err := r.dial(2 * time.Second)
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

	if c, _, err := r.dial(time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a connection was reported when neither route works")
	}
}

// Each route claims its own hostname.
//
// This matters for what an onlooker can put together. The direct route must not
// name the domain that only exists for the CDN, because that domain's records
// point at the CDN rather than at the server being dialled, and a name that does
// not match the destination is more telling than either on its own.
func TestRouteEachRouteClaimsItsOwnName(t *testing.T) {
	dead, stopDead := listenAt(t)
	stopDead()
	alive, stopAlive := listenAt(t)
	defer stopAlive()

	cfg := defaultConfig()
	cfg.Transport = TransportWSS
	cfg.TunnelAddr = alive
	cfg.ServerName = "www.bing.com"
	cfg.AltTarget = "link.example.com:443"
	cfg.AltServerName = "link.example.com"

	r := newRouter(cfg)
	if len(r.targets) != 2 {
		t.Fatalf("expected two routes, got %d", len(r.targets))
	}
	if r.targets[0].name != "www.bing.com" {
		t.Fatalf("the direct route claims %q", r.targets[0].name)
	}
	if r.targets[1].name != "link.example.com" {
		t.Fatalf("the fallback route claims %q", r.targets[1].name)
	}

	// Taking the direct route hands back the innocuous name.
	c, claim, err := r.dial(2 * time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
	if claim != "www.bing.com" {
		t.Fatalf("the direct route asked to claim %q", claim)
	}

	// And the name really does change what goes on the wire.
	if got := cfg.withClaimedName("link.example.com").effectiveServerName(); got != "link.example.com" {
		t.Fatalf("claiming a different name gave %q", got)
	}
	if cfg.ServerName != "www.bing.com" {
		t.Fatal("claiming a name for one route changed the tunnel's own setting")
	}

	// With no separate name given, the fallback claims the same as the first.
	cfg2 := defaultConfig()
	cfg2.TunnelAddr = dead
	cfg2.ServerName = "www.bing.com"
	cfg2.AltTarget = alive
	r2 := newRouter(cfg2)
	if r2.targets[1].name != "www.bing.com" {
		t.Fatalf("the fallback claims %q when nothing else was given", r2.targets[1].name)
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

	// A name for the fallback only means something when there is a fallback.
	cfg = base()
	cfg.AltServerName = "link.example.com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a name for a fallback that does not exist was accepted")
	}

	// And it has to be a name, since naming is the entire point of it.
	cfg = base()
	cfg.AltTarget = "link.example.com:443"
	cfg.AltServerName = "203.0.113.9"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an address was accepted as the name to claim")
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

// routeSetup is what a route test varies: where the edge dials, where it falls
// back to, and what each of those claims to be.
type routeSetup struct {
	bind      string // where the origin really listens
	primary   string // what the edge dials first
	alt       string // and what it falls back to
	transport Transport
	name      string // claimed on the first route
	altName   string // claimed on the fallback
}

// startTunnelRoutes brings up a direct-mode tunnel with the given arrangement of
// routes.
func startTunnelRoutes(t *testing.T, serviceAddr string, s routeSetup) *tunnel {
	t.Helper()

	userAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)
	certFile, keyFile := certPaths(t)
	if s.transport == "" {
		s.transport = TransportPlain
	}

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
		cfg.Transport = s.transport
		cfg.ServerName = s.name
		cfg.CertFile, cfg.KeyFile = certFile, keyFile
		if role == RoleEdge {
			cfg.TunnelAddr = s.primary
			cfg.AltTarget = s.alt
			cfg.AltServerName = s.altName
			cfg.UserListen = userAddr
		} else {
			cfg.TunnelAddr = s.bind
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
	return startTunnelRoutes(t, serviceAddr, routeSetup{bind: bind, primary: bind, alt: deadAlt})
}

// startTunnelDeadPrimary: the preferred route is dead, so only the fallback can
// bring the tunnel up.
func startTunnelDeadPrimary(t *testing.T, serviceAddr string) *tunnel {
	t.Helper()
	bind := freeAddr(t)
	dead, stop := listenAt(t)
	stop()
	return startTunnelRoutes(t, serviceAddr, routeSetup{bind: bind, primary: dead, alt: bind})
}

// The fallback must work when it also has to claim a different hostname, which is
// the real arrangement: go straight to the server under an innocuous name, and
// through the CDN under the real domain.
func TestRouteFallbackWithItsOwnNameCarriesTraffic(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	bind := freeAddr(t)
	dead, stop := listenAt(t)
	stop()

	tun := startTunnelRoutes(t, svc.addr, routeSetup{
		bind:      bind,
		primary:   dead,
		alt:       bind,
		transport: TransportWSS,
		name:      "www.bing.com",
		altName:   "link.example.com",
	})
	defer tun.stop()

	got, err := roundTrip(t, tun.userAddr, "over-the-cdn-name", 20*time.Second)
	if err != nil {
		t.Fatalf("the fallback did not carry traffic under its own name: %v", err)
	}
	if got != "OVER-THE-CDN-NAME" {
		t.Fatalf("got %q", got)
	}
}
