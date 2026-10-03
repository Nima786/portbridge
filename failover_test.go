package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A route that opens and then goes quiet
// ---------------------------------------------------------------------------

// limitedProxy stands in for a route that lets a connection open and carry its
// first few packets, then silently stops: the connection stays up, nothing more
// arrives, and nobody is told. That is what filtering of a whole address looks
// like, and it is the case a count of ready connections cannot see.
type limitedProxy struct {
	addr string
	ln   net.Listener
	cut  int64 // bytes swallowed after the limit, across all connections
}

func startLimitedProxy(t *testing.T, upstream string, limit int) *limitedProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &limitedProxy{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c, upstream, limit)
		}
	}()
	return p
}

func (p *limitedProxy) serve(c net.Conn, upstream string, limit int) {
	defer c.Close()
	up, err := net.DialTimeout("tcp", upstream, 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	pipe := func(dst, src net.Conn) {
		// When either direction ends, both do, as a real connection would.
		defer dst.Close()
		defer src.Close()
		buf := make([]byte, 4096)
		passed := 0
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if passed < limit {
					take := n
					if passed+take > limit {
						take = limit - passed
					}
					_, _ = dst.Write(buf[:take])
					passed += take
					atomic.AddInt64(&p.cut, int64(n-take))
				} else {
					atomic.AddInt64(&p.cut, int64(n))
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(up, c)
	pipe(c, up)
}

func (p *limitedProxy) stop() { _ = p.ln.Close() }

// tunnelCfg builds and validates one half of a direct tunnel.
func tunnelCfg(t *testing.T, role Role, mutate func(*Config)) *Config {
	t.Helper()
	cfg := defaultConfig()
	cfg.Name = "ft" + string(role)
	cfg.Mode = ModeDirect
	cfg.Role = role
	cfg.PoolSize = 4
	cfg.MaxConn = 100
	cfg.MaxPending = 64
	cfg.SpareTTL = 10 * time.Minute
	cfg.ParkTimeout = 15 * time.Minute
	cfg.Drain = 2 * time.Second
	cfg.SecretFile = writeSecret(t, testSecret)
	cfg.StatusFile = ""
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config for %s: %v", role, err)
	}
	if err := cfg.LoadSecret(); err != nil {
		t.Fatalf("secret for %s: %v", role, err)
	}
	return cfg
}

// runHalf starts one half of a tunnel and returns a function that stops it.
func runHalf(t *testing.T, cfg *Config, run func(context.Context, *Config, *status) error) (*status, func()) {
	t.Helper()
	st := newStatus(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := run(ctx, cfg, st); err != nil {
			t.Logf("%s exited: %v", cfg.Role, err)
		}
	}()
	return st, func() { cancel(); wg.Wait() }
}

// setProbeTimings shortens the path check timings for a test and returns the
// function that puts them back.
func setProbeTimings(first, idle, trouble time.Duration) func() {
	of, oi, ot := probeFirstWait.get(), pathCheckIdle.get(), probeEveryTrouble.get()
	probeFirstWait.set(first)
	pathCheckIdle.set(idle)
	probeEveryTrouble.set(trouble)
	return func() {
		probeFirstWait.set(of)
		pathCheckIdle.set(oi)
		probeEveryTrouble.set(ot)
	}
}

// The headline behaviour: the preferred route opens connections fine but carries
// nothing, and users must end up on the backup route without anyone touching
// anything.
func TestFailsOverWhenConnectionsOpenButDataDies(t *testing.T) {
	defer setProbeTimings(200*time.Millisecond, 1200*time.Millisecond, 400*time.Millisecond)()

	svc := startService(t)
	defer svc.stop()

	originAddr := freeAddr(t)
	originCfg := tunnelCfg(t, RoleOrigin, func(c *Config) {
		c.TunnelAddr = originAddr
		c.InboundAddr = svc.addr
	})
	_, stopOrigin := runHalf(t, originCfg, runOrigin)
	defer stopOrigin()
	time.Sleep(150 * time.Millisecond)

	// The preferred route lets 120 bytes through each way (enough for the
	// handshake, which is at most 115) and swallows everything after.
	proxy := startLimitedProxy(t, originAddr, 120)
	defer proxy.stop()

	userAddr := freeAddr(t)
	edgeCfg := tunnelCfg(t, RoleEdge, func(c *Config) {
		c.TunnelAddr = proxy.addr
		c.AltTarget = originAddr
		c.UserListen = userAddr
	})
	_, stopEdge := runHalf(t, edgeCfg, runEdge)
	defer stopEdge()

	deadline := time.Now().Add(45 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		// Long enough that it cannot fit in what the preferred route lets by.
		payload := strings.Repeat("hello through the backup ", 60)
		got, err := roundTrip(t, userAddr, payload, 6*time.Second)
		if err == nil {
			if got != strings.ToUpper(payload) {
				t.Fatalf("got %q", got)
			}
			if atomic.LoadInt64(&proxy.cut) == 0 {
				t.Fatalf("the preferred route was never used, so nothing was proved")
			}
			return
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("users never reached the service through the backup route: %v", lastErr)
}

// Without a backup there is nowhere to go, but the state must say so honestly
// rather than reporting ready.
func TestBlockedRouteWithoutBackupIsReportedBlocked(t *testing.T) {
	defer setProbeTimings(200*time.Millisecond, 1000*time.Millisecond, 300*time.Millisecond)()
	lc := captureLog(t)

	svc := startService(t)
	defer svc.stop()

	originAddr := freeAddr(t)
	originCfg := tunnelCfg(t, RoleOrigin, func(c *Config) {
		c.TunnelAddr = originAddr
		c.InboundAddr = svc.addr
	})
	_, stopOrigin := runHalf(t, originCfg, runOrigin)
	defer stopOrigin()
	time.Sleep(150 * time.Millisecond)

	proxy := startLimitedProxy(t, originAddr, 120)
	defer proxy.stop()

	userAddr := freeAddr(t)
	edgeCfg := tunnelCfg(t, RoleEdge, func(c *Config) {
		c.TunnelAddr = proxy.addr
		c.UserListen = userAddr
	})
	_, stopEdge := runHalf(t, edgeCfg, runEdge)
	defer stopEdge()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if strings.Contains(lc.String(), "open normally but data does not flow") {
			return
		}
	}
	t.Fatalf("the tunnel never admitted that data does not flow:\n%s", lc.String())
}

// ---------------------------------------------------------------------------
// Settings mismatch is named, not silent
// ---------------------------------------------------------------------------

// logCapture collects log output for the length of a test.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	lc := &logCapture{}
	old := log.Writer()
	log.SetOutput(io.MultiWriter(lc, old))
	t.Cleanup(func() { log.SetOutput(old) })
	return lc
}

func TestMuxMismatchIsNamedInTheLog(t *testing.T) {
	cases := []struct {
		name       string
		edgeMux    bool
		originMux  bool
		wantInside string
	}{
		{"edge shares, origin does not", true, false, "shared connections"},
		{"origin shares, edge does not", false, true, "shared connections"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := captureLog(t)
			svc := startService(t)
			defer svc.stop()

			originAddr := freeAddr(t)
			userAddr := freeAddr(t)
			originCfg := tunnelCfg(t, RoleOrigin, func(c *Config) {
				c.TunnelAddr = originAddr
				c.InboundAddr = svc.addr
				c.Mux = tc.originMux
			})
			_, stopOrigin := runHalf(t, originCfg, runOrigin)
			defer stopOrigin()
			time.Sleep(150 * time.Millisecond)

			edgeCfg := tunnelCfg(t, RoleEdge, func(c *Config) {
				c.TunnelAddr = originAddr
				c.UserListen = userAddr
				c.Mux = tc.edgeMux
			})
			_, stopEdge := runHalf(t, edgeCfg, runEdge)
			defer stopEdge()

			// The user is refused, and the reason shows up in the log within
			// moments rather than after a twenty second hang.
			start := time.Now()
			_, _ = roundTrip(t, userAddr, "ping", 8*time.Second)
			if time.Since(start) > 12*time.Second {
				t.Fatalf("the mismatch took %s to show", time.Since(start))
			}

			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if strings.Contains(lc.String(), tc.wantInside) {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Fatalf("the log never named the mismatch:\n%s", lc.String())
		})
	}
}

func TestTunnelPurposeChecks(t *testing.T) {
	mux := &Config{Mux: true}
	pooled := &Config{Mux: false}

	if err := checkTunnelPurpose(mux, authPurposeTunnelMux); err != nil {
		t.Fatalf("matching mux rejected: %v", err)
	}
	if err := checkTunnelPurpose(pooled, authPurposeTunnelPooled); err != nil {
		t.Fatalf("matching pooled rejected: %v", err)
	}
	if err := checkTunnelPurpose(pooled, authPurposeTunnelMux); !errors.Is(err, errMuxOnlyThere) {
		t.Fatalf("mux dialler vs pooled acceptor: %v", err)
	}
	if err := checkTunnelPurpose(mux, authPurposeTunnelPooled); !errors.Is(err, errMuxOnlyHere) {
		t.Fatalf("pooled dialler vs mux acceptor: %v", err)
	}
	// A build that predates the check says nothing, and must keep working.
	if err := checkTunnelPurpose(mux, authPurposeTunnel); err != nil {
		t.Fatalf("legacy purpose rejected by mux acceptor: %v", err)
	}
	if err := checkTunnelPurpose(pooled, authPurposeTunnel); err != nil {
		t.Fatalf("legacy purpose rejected by pooled acceptor: %v", err)
	}
}

func TestFirstFrameNamesTheProblem(t *testing.T) {
	if err := checkFirstFrame(muxPing); err != nil {
		t.Fatalf("a shared-link frame was refused: %v", err)
	}
	if err := checkFirstFrame(rejMuxMismatch); !errors.Is(err, errMuxMismatch) {
		t.Fatalf("mismatch byte gave %v", err)
	}
	if err := checkFirstFrame(msgActivatePort); !errors.Is(err, errMuxOnlyHere) {
		t.Fatalf("a pooled-mode byte gave %v", err)
	}
	if err := checkFirstFrame(0x7f); err == nil {
		t.Fatalf("garbage was accepted")
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealthStates(t *testing.T) {
	h := newPathHealth(false)
	timeout := os.ErrDeadlineExceeded

	for i := 0; i < healthDegradedAfter; i++ {
		h.activationFailed(timeout)
	}
	if state, _, _ := h.snapshot(); state != "degraded" {
		t.Fatalf("after %d timeouts state is %s", healthDegradedAfter, state)
	}
	for i := healthDegradedAfter; i < healthBlockedAfter; i++ {
		h.activationFailed(timeout)
	}
	if state, _, _ := h.snapshot(); state != "blocked" {
		t.Fatalf("after %d timeouts state is %s", healthBlockedAfter, state)
	}
	if !h.isBlocked() {
		t.Fatalf("isBlocked disagrees with the state")
	}

	h.activationOK()
	if state, _, last := h.snapshot(); state != "ok" || last < 0 {
		t.Fatalf("after a success state is %s (last ok %d)", state, last)
	}
}

func TestHealthIgnoresSettingsErrors(t *testing.T) {
	h := newPathHealth(false)
	for i := 0; i < 10; i++ {
		h.activationFailed(errMuxMismatch)
		h.activationFailed(errAuthSkew)
	}
	if state, _, _ := h.snapshot(); state != "unknown" {
		t.Fatalf("settings errors changed the state to %s", state)
	}
}

func TestHealthCountsRefusalsApart(t *testing.T) {
	h := newPathHealth(false)
	for i := 0; i < healthBlockedAfter+2; i++ {
		h.activationFailed(io.EOF)
	}
	if state, _, _ := h.snapshot(); state == "blocked" {
		t.Fatalf("outright refusals were taken as a filtered route")
	}
}

func TestClassifyProbe(t *testing.T) {
	if k := classifyProbe(nil, time.Second).kind; k != probePassed {
		t.Fatalf("nil: %v", k)
	}
	if k := classifyProbe(os.ErrDeadlineExceeded, time.Second).kind; k != probeStalled {
		t.Fatalf("timeout: %v", k)
	}
	if k := classifyProbe(io.EOF, 100*time.Millisecond).kind; k != probeUnsupported {
		t.Fatalf("quick EOF: %v", k)
	}
	if k := classifyProbe(io.EOF, 20*time.Second).kind; k != probeFailed {
		t.Fatalf("slow EOF: %v", k)
	}
}

// A path check against a real speed-test responder must pass, and against a
// responder that goes quiet after a few bytes must be called a stall.
func TestPathCheckPassesAndStalls(t *testing.T) {
	defer setProbeTimings(probeFirstWait.get(), 700*time.Millisecond, probeEveryTrouble.get())()

	a, b := net.Pipe()
	go runSpeedtestServer(b)
	if err := runPathCheck(a); err != nil {
		t.Fatalf("a working responder failed the check: %v", err)
	}
	_ = a.Close()

	// A responder that answers the first request and then stops.
	c, d := net.Pipe()
	go func() {
		defer d.Close()
		var hdr [5]byte
		if _, err := io.ReadFull(d, hdr[:]); err != nil {
			return
		}
		_, _ = d.Write([]byte{0x00})
		_, _ = d.Write(make([]byte, 4000)) // a little, then nothing
		time.Sleep(3 * time.Second)
	}()
	err := runPathCheck(c)
	_ = c.Close()
	if err == nil || classifyProbe(err, time.Second).kind != probeStalled {
		t.Fatalf("a responder that went quiet gave %v", err)
	}
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

func twoRouteRouter(t *testing.T) *router {
	t.Helper()
	cfg := defaultConfig()
	cfg.TunnelAddr = "192.0.2.1:443"
	cfg.AltTarget = "192.0.2.2:443"
	return newRouter(cfg)
}

func TestSetAsideMovesToTheNextRoute(t *testing.T) {
	r := twoRouteRouter(t)
	r.settle(0)
	r.setAside(0, time.Minute, "test")
	if got := r.currentIndex(); got != 1 {
		t.Fatalf("expected to move to route 1, on %d", got)
	}
	if !r.isSetAside(0) {
		t.Fatalf("route 0 is not marked as set aside")
	}
	if order := r.order(); order[0] != 1 {
		t.Fatalf("order starts with %v", order)
	}
}

func TestRestoreGoesBack(t *testing.T) {
	r := twoRouteRouter(t)
	r.settle(0)
	r.setAside(0, time.Minute, "test")
	if !r.restore(0) {
		t.Fatalf("restore did not report a move")
	}
	if got := r.currentIndex(); got != 0 {
		t.Fatalf("on route %d after restore", got)
	}
	if r.isSetAside(0) {
		t.Fatalf("still set aside after restore")
	}
}

func TestOnlyRouteIsNeverSetAsideForGood(t *testing.T) {
	cfg := defaultConfig()
	cfg.TunnelAddr = "192.0.2.1:443"
	r := newRouter(cfg)
	r.setAside(0, time.Minute, "test")
	if order := r.order(); len(order) != 1 || order[0] != 0 {
		t.Fatalf("the only route must still be tried: %v", order)
	}
}

func TestHandshakeFailuresSetARouteAside(t *testing.T) {
	r := twoRouteRouter(t)
	r.settle(0)
	for i := 0; i < 2; i++ {
		r.handshakeFailed(0, errors.New("x"))
	}
	if r.isSetAside(0) {
		t.Fatalf("two failures set the route aside")
	}
	r.handshakeFailed(0, errors.New("x"))
	if !r.isSetAside(0) {
		t.Fatalf("three failures in a row did not set the route aside")
	}
	r2 := twoRouteRouter(t)
	r2.handshakeFailed(0, errors.New("x"))
	r2.handshakeOK(0)
	r2.handshakeFailed(0, errors.New("x"))
	r2.handshakeFailed(0, errors.New("x"))
	if r2.isSetAside(0) {
		t.Fatalf("a success in between did not reset the count")
	}
}

func TestRepeatedSetAsideHoldsLonger(t *testing.T) {
	r := twoRouteRouter(t)
	r.setAside(0, time.Minute, "a")
	first := r.badUntil[0]
	r.restore(0) // resets the count
	r.setAside(0, time.Minute, "a")
	r.setAside(0, time.Minute, "a")
	if !r.badUntil[0].After(first) {
		t.Fatalf("a repeat did not hold longer")
	}
}

func TestCleanIPsTakeTurnsAndSkipSetAside(t *testing.T) {
	cfg := defaultConfig()
	cfg.TunnelAddr = "192.0.2.9:443"
	cfg.CleanIPs = []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	r := newRouter(cfg)
	r.settle(0)

	seen := map[int]bool{}
	for i := 0; i < 12; i++ {
		seen[r.order()[0]] = true
	}
	if len(seen) < 3 {
		t.Fatalf("only %d of 3 clean addresses took a turn", len(seen))
	}

	r.setAside(1, time.Minute, "test")
	for i := 0; i < 12; i++ {
		if first := r.order()[0]; first == 1 {
			t.Fatalf("a clean address that was set aside was still chosen first")
		}
	}
}

func TestCleanAddrForms(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":                 "1.2.3.4:443",
		"1.2.3.4:8443":            "1.2.3.4:8443",
		"2001:db8::1":             "[2001:db8::1]:443",
		"[2001:db8::1]":           "[2001:db8::1]:443",
		"[2001:db8::1]:" + "8443": "[2001:db8::1]:8443",
		"":                        "",
	}
	for in, want := range cases {
		if got := cleanAddr(in, "443"); got != want {
			t.Errorf("cleanAddr(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"example.com", "1.2.3.4:0", "1.2.3.4:99999", "nonsense"} {
		if err := checkCleanIP(bad); err == nil {
			t.Errorf("checkCleanIP(%q) accepted it", bad)
		}
	}
	for _, good := range []string{"1.2.3.4", "1.2.3.4:443", "2001:db8::1", "[2001:db8::1]:443"} {
		if err := checkCleanIP(good); err != nil {
			t.Errorf("checkCleanIP(%q): %v", good, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func TestStealthKeysDoNotSwitchOffDefaults(t *testing.T) {
	cfg := defaultConfig()
	if err := cfg.set("tls_fragment_size", "60"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.set("tls_fragment_sleep", "5ms"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.set("utls_profile", "chrome"); err != nil {
		t.Fatal(err)
	}
	cfg.CDN = true
	if !cfg.useUTLS() || !cfg.useFragment() {
		t.Fatalf("setting a size or profile turned the CDN defaults off")
	}
}

func TestBadUTLSProfileIsRefused(t *testing.T) {
	cfg := defaultConfig()
	if err := cfg.set("utls_profile", "netscape"); err == nil {
		t.Fatalf("an unknown profile was accepted")
	}
}

func TestBackupRouteThroughCDNGetsBrowserDefaults(t *testing.T) {
	cfg := defaultConfig()
	cfg.TunnelAddr = "192.0.2.1:443"
	cfg.AltTarget = "192.0.2.2:443"
	cfg.AltServerName = "front.example.org"
	cfg.ServerName = "www.example.org"
	r := newRouter(cfg)
	if got := r.routeConfig(0); got.useUTLS() || got.useFragment() {
		t.Fatalf("the direct route picked up CDN defaults")
	}
	if got := r.routeConfig(1); !got.useUTLS() || !got.useFragment() {
		t.Fatalf("the CDN backup route did not get the browser defaults")
	}
}

func TestMultiPortSettingsMustAgree(t *testing.T) {
	cfg := defaultConfig()
	cfg.Role = RoleEdge
	cfg.Mode = ModeDirect
	cfg.TunnelAddr = "192.0.2.1:9000"
	cfg.UserListen = "0.0.0.0:443,0.0.0.0:8443"
	cfg.ServerInboundPort = "443"
	cfg.SecretFile = writeSecret(t, testSecret)
	if err := cfg.Validate(); err == nil {
		t.Fatalf("two listens with one target port were accepted")
	}

	o := defaultConfig()
	o.InboundAddrs = []string{"127.0.0.1:1", "127.0.0.1:2"}
	if got := o.InboundFor(3); got != "" {
		t.Fatalf("an unknown port was sent to %q", got)
	}
	if got := o.InboundFor(0); got != "127.0.0.1:1" {
		t.Fatalf("no port asked should mean the first service, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Spare liveness on a plain connection
// ---------------------------------------------------------------------------

// A plain spare whose far end has silently stopped answering must be found and
// dropped by the check that runs after a failed activation. Plain connections
// used to be exempt from pinging altogether, so a dead one sat in the pool
// looking ready until a user landed on it.
func TestVerifyAllDropsASilentPlainSpare(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepted int32
	silentClosed := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			first := atomic.AddInt32(&accepted, 1) == 1
			go func(c net.Conn, silent bool) {
				defer c.Close()
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						if silent {
							close(silentClosed)
						}
						return
					}
					if !silent && buf[0] == msgParkPing {
						_, _ = c.Write([]byte{msgParkPong})
					}
				}
			}(c, first)
		}
	}()

	p := newPool(3, 10*time.Minute, time.Second, func() (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.maintain(ctx)
	defer p.closeAll()

	deadline := time.Now().Add(5 * time.Second)
	for p.parkedCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if p.parkedCount() < 3 {
		t.Fatalf("the pool only filled to %d", p.parkedCount())
	}

	p.verifyAll(ctx)

	select {
	case <-silentClosed:
	case <-time.After(5 * time.Second):
		t.Fatalf("the silent spare was never dropped")
	}
}
