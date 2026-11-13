package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAndMatchRouteHostPatterns(t *testing.T) {
	got, err := ParseRouteHostPatterns("https://DE.VPN.Example.com:443/path, .app.example.com, *.cdn.example.ir.")
	if err != nil {
		t.Fatalf("ParseRouteHostPatterns failed: %v", err)
	}
	want := []string{"de.vpn.example.com", "*.app.example.com", "*.cdn.example.ir"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}

	for _, bad := range []string{"*", "1.2.3.4", "[2001:db8::1]", "localhost", "*.bad", "bad..domain.com"} {
		if _, err := ParseRouteHostPatterns(bad); err == nil {
			t.Errorf("expected %q to be rejected by ParseRouteHostPatterns", bad)
		}
	}

	okExact, scoreExact := MatchRouteHost("de.vpn.example.com", []string{"de.vpn.example.com"}, false)
	okWild, scoreWild := MatchRouteHost("de.vpn.example.com", []string{"*.vpn.example.com"}, false)
	if !okExact || !okWild || scoreExact <= scoreWild {
		t.Fatalf("expected exact match score (%d) > wildcard score (%d)", scoreExact, scoreWild)
	}
	if okRoot, _ := MatchRouteHost("vpn.example.com", []string{"*.vpn.example.com"}, false); !okRoot {
		t.Fatal("expected wildcard *.vpn.example.com to match root vpn.example.com as well")
	}
	if okWWW, _ := MatchRouteHost("www.shop.example.com", []string{"shop.example.com"}, true); !okWWW {
		t.Fatal("expected website bridge implicit www.shop.example.com to match shop.example.com")
	}
	if okWWWOff, _ := MatchRouteHost("www.shop.example.com", []string{"shop.example.com"}, false); okWWWOff {
		t.Fatal("did not expect www.shop.example.com to match exact shop.example.com when websiteAutoWWW is false")
	}

	if pat, clash := RouteHostPatternsConflict([]string{"de.example.com"}, []string{"de.example.com"}); !clash || pat != "de.example.com" {
		t.Fatalf("expected identical exact patterns to conflict, got clash=%v pat=%q", clash, pat)
	}
	if _, clash := RouteHostPatternsConflict([]string{"de.example.com"}, []string{"*.example.com"}); clash {
		t.Fatal("expected exact subdomain de.example.com alongside *.example.com to be allowed by specificity")
	}
}

type runningSharedPair struct {
	edgeCfg       *Config
	writeEdgeConf func(extra string)
	cancelEdge    context.CancelFunc
	edgeDone      chan struct{}
	cancelOrig    context.CancelFunc
	origDone      chan struct{}
}

func startSharedTunnelPair(t *testing.T, runtimeDir, secretPath, sharedUserAddr, name, proxyVerStr, baseExtra string) (*runningSharedPair, *ppService) {
	t.Helper()
	svc := startPPService(t)
	tunnelAddr := freeAddr(t)

	originCfg := DefaultConfig()
	originCfg.Name = name
	originCfg.Mode = ModeDirect
	originCfg.Role = RoleOrigin
	originCfg.TunnelAddr = tunnelAddr
	originCfg.InboundAddr = svc.addr
	originCfg.Transport = TransportPlain
	originCfg.Mux = true
	originCfg.MuxLinks = 1
	originCfg.MaxConn = 200
	_ = originCfg.Set("proxy_protocol", proxyVerStr)
	originCfg.Drain = 200 * time.Millisecond
	originCfg.SecretFile = secretPath
	originCfg.StatusFile = ""
	if err := originCfg.Validate(); err != nil {
		t.Fatalf("%s origin validate: %v", name, err)
	}
	if err := originCfg.LoadSecret(); err != nil {
		t.Fatalf("%s origin secret: %v", name, err)
	}

	statusPath := filepath.Join(runtimeDir, name+".json")
	edgeConfPath := filepath.Join(runtimeDir, name+".conf")
	writeEdgeConf := func(extra string) {
		body := fmt.Sprintf(`name = %s
mode = direct
role = edge
tunnel_addr = %s
user_listen = %s
transport = plain
mux = on
mux_links = 1
max_conn = 200
proxy_protocol = %s
drain = 200ms
secret_file = %s
status_file = %s
%s
%s
`, name, tunnelAddr, sharedUserAddr, proxyVerStr, secretPath, statusPath, baseExtra, extra)
		if err := os.WriteFile(edgeConfPath, []byte(body), 0o600); err != nil {
			t.Fatalf("%s write edge conf: %v", name, err)
		}
	}
	writeEdgeConf("")

	edgeCfg, err := LoadConfig(edgeConfPath)
	if err != nil {
		t.Fatalf("%s LoadConfig: %v", name, err)
	}
	if err := edgeCfg.Validate(); err != nil {
		t.Fatalf("%s edge validate: %v", name, err)
	}
	if err := edgeCfg.LoadSecret(); err != nil {
		t.Fatalf("%s edge secret: %v", name, err)
	}

	origCtx, cancelOrig := context.WithCancel(context.Background())
	edgeCtx, cancelEdge := context.WithCancel(context.Background())
	origDone := make(chan struct{})
	edgeDone := make(chan struct{})

	go func() {
		_ = runOrigin(origCtx, originCfg, newStatus(originCfg))
		close(origDone)
	}()
	go func() {
		_ = runEdge(edgeCtx, edgeCfg, newStatus(edgeCfg))
		close(edgeDone)
	}()

	pair := &runningSharedPair{
		edgeCfg:       edgeCfg,
		writeEdgeConf: writeEdgeConf,
		cancelEdge:    cancelEdge,
		edgeDone:      edgeDone,
		cancelOrig:    cancelOrig,
		origDone:      origDone,
	}
	t.Cleanup(func() {
		cancelEdge()
		cancelOrig()
		<-edgeDone
		<-origDone
	})
	return pair, svc
}

func TestSharedPortSNIAndHostRouterEndToEnd(t *testing.T) {
	shortDir, err := os.MkdirTemp("", "pbsni")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })

	secretPath := filepath.Join(shortDir, "secret")
	if err := os.WriteFile(secretPath, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	sharedUserAddr := freeAddr(t)
	sharedPort := mustPort(t, sharedUserAddr)

	// 1. Website Bridge for shop.example.com (PROXY v1)
	pairShop, svcShop := startSharedTunnelPair(t, shortDir, secretPath, sharedUserAddr, "wb-shop", "v1",
		"website_bridge = on\nwebsite_domains = shop.example.com")
	// 2. Exact VPN tunnel for de.vpn.example.com (PROXY v1)
	pairDE, svcDE := startSharedTunnelPair(t, shortDir, secretPath, sharedUserAddr, "vpn-de", "v1",
		"route_hosts = de.vpn.example.com")
	// 3. Wildcard VPN tunnel *.vpn.example.com + Default Fallback (PROXY v2)
	_, svcWild := startSharedTunnelPair(t, shortDir, secretPath, sharedUserAddr, "vpn-wild", "v2",
		"route_hosts = *.vpn.example.com\nroute_default = on")

	manifestOf := func(tun string) string {
		return filepath.Join(shortDir, fmt.Sprintf("sni-port-%d-%s.json", sharedPort, tun))
	}

	// Wait until all 3 manifests are registered and mux links come up.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		m1, _ := os.Stat(manifestOf("wb-shop"))
		m2, _ := os.Stat(manifestOf("vpn-de"))
		m3, _ := os.Stat(manifestOf("vpn-wild"))
		if m1 != nil && m2 != nil && m3 != nil {
			c, dialErr := net.DialTimeout("tcp", sharedUserAddr, 300*time.Millisecond)
			if dialErr == nil {
				req := "GET /warmup HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
				_, _ = c.Write([]byte(req))
				reply := make([]byte, len(req))
				_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				_, rerr := io.ReadFull(c, reply)
				_ = c.Close()
				if rerr == nil && string(reply) == strings.ToUpper(req) {
					break
				}
			}
		}
		time.Sleep(80 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // allow 250ms peer manifest cache refresh across all 3 peers

	sendAndVerify := func(payload []byte, chunkSize int, wantSvc *ppService, wantPP string) {
		t.Helper()
		c, err := net.DialTimeout("tcp", sharedUserAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("Dial(%s): %v", sharedUserAddr, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(6 * time.Second))
		localAddr := c.LocalAddr().String()

		if chunkSize > 0 {
			for off := 0; off < len(payload); off += chunkSize {
				end := off + chunkSize
				if end > len(payload) {
					end = len(payload)
				}
				if _, err := c.Write(payload[off:end]); err != nil {
					t.Fatalf("chunked Write: %v", err)
				}
				time.Sleep(4 * time.Millisecond)
			}
		} else if _, err := c.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}

		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("ReadFull echo (%d bytes): %v", len(payload), err)
		}
		if !bytes.Equal(got, bytes.ToUpper(payload)) {
			t.Fatalf("unexpected echoed payload: got %q, want %q", got, bytes.ToUpper(payload))
		}

		rec := wantSvc.last(t)
		if rec.kind != wantPP {
			t.Fatalf("expected PROXY %s header at backend, got %q", wantPP, rec.kind)
		}
		if rec.src != localAddr {
			t.Fatalf("backend saw visitor src %q, want real client TCP address %q", rec.src, localAddr)
		}
	}

	// Repeat several rounds so round-robin accept exercises both local accept AND cross-tunnel handoffs!
	for round := 0; round < 4; round++ {
		// A) HTTP Host routing (with implicit www. matching on Website Bridge)
		httpReq := []byte(fmt.Sprintf("GET /round-%d HTTP/1.1\r\nHost: www.shop.example.com\r\nUser-Agent: test\r\n\r\n", round))
		sendAndVerify(httpReq, 0, svcShop, "v1")

		// B) Fragmented TLS ClientHello for exact domain de.vpn.example.com (must beat *.vpn.example.com!)
		helloDE := append(buildTestClientHello("de.vpn.example.com"), []byte(fmt.Sprintf("vless-de-%d", round))...)
		sendAndVerify(helloDE, 11, svcDE, "v1")

		// C) TLS ClientHello for wildcard fi.vpn.example.com -> svcWild (PROXY v2)
		helloFI := append(buildTestClientHello("fi.vpn.example.com"), []byte(fmt.Sprintf("trojan-fi-%d", round))...)
		sendAndVerify(helloFI, 0, svcWild, "v2")

		// D) Raw non-TLS/HTTP TCP traffic -> routed to Default Fallback (vpn-wild, PROXY v2)
		rawPayload := []byte(fmt.Sprintf("raw-custom-binary-protocol-round-%d-payload", round))
		sendAndVerify(rawPayload, 0, svcWild, "v2")
	}

	// Verify per-tunnel Client Guard isolation via live hot-reload:
	// Blocking 127.0.0.1 on vpn-de MUST block de.vpn.example.com while shop.example.com
	// and fi.vpn.example.com on the exact same port continue succeeding!
	pairDE.writeEdgeConf("blocked_ips = 127.0.0.1")
	if err := ReloadGuardControl(pairDE.edgeCfg.ControlSocketPath()); err != nil {
		t.Fatalf("ReloadGuardControl(vpn-de): %v", err)
	}

	blockedConn, err := net.DialTimeout("tcp", sharedUserAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial for blocked SNI: %v", err)
	}
	_ = blockedConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = blockedConn.Write(append(buildTestClientHello("de.vpn.example.com"), []byte("should-drop")...))
	buf := make([]byte, 32)
	n, rerr := blockedConn.Read(buf)
	_ = blockedConn.Close()
	if rerr == nil && n > 0 {
		t.Fatalf("expected 127.0.0.1 to be dropped by vpn-de guard, but received %d bytes", n)
	}

	// Sibling tunnels on the same port must be completely unaffected by vpn-de's IP block!
	sendAndVerify(append(buildTestClientHello("shop.example.com"), []byte("still-alive-shop")...), 0, svcShop, "v1")
	sendAndVerify(append(buildTestClientHello("fi.vpn.example.com"), []byte("still-alive-fi")...), 0, svcWild, "v2")

	// Verify zero-downtime sibling survival when vpn-de AND wb-shop are stopped one by one:
	pairDE.cancelEdge()
	<-pairDE.edgeDone
	time.Sleep(300 * time.Millisecond)

	for i := 0; i < 3; i++ {
		sendAndVerify(append(buildTestClientHello("shop.example.com"), []byte("after-de-stop")...), 0, svcShop, "v1")
		sendAndVerify(append(buildTestClientHello("nl.vpn.example.com"), []byte("after-de-stop")...), 0, svcWild, "v2")
	}

	pairShop.cancelEdge()
	<-pairShop.edgeDone
	time.Sleep(300 * time.Millisecond)

	for i := 0; i < 3; i++ {
		sendAndVerify(append(buildTestClientHello("se.vpn.example.com"), []byte("after-shop-stop")...), 0, svcWild, "v2")
	}
}

func mustPort(t *testing.T, hostport string) int {
	t.Helper()
	_, pStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort(%s): %v", hostport, err)
	}
	var p int
	if _, err := fmt.Sscanf(pStr, "%d", &p); err != nil {
		t.Fatalf("parse port %q: %v", pStr, err)
	}
	return p
}
