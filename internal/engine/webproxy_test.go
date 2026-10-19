package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestShouldRouteViaIran(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutboundProxy = true
	cfg.OutboundProxyMode = "split"
	cfg.OutboundIranDomains = "custom-sms.com, .ir, shaparak.ir"
	cfg.OutboundBypassDomains = "telegram.org, api.telegram.org, sub.custom-sms.com"

	cases := []struct {
		host string
		want bool
	}{
		{"portbridge-iran-check.ir", true},
		{"myshop.ir:443", true},
		{"bpm.shaparak.ir", true},
		{"api.zarinpal.com", true},
		{"api.kavenegar.com", true},
		{"api.custom-sms.com", true},
		// Explicit bypass overrides Iran list
		{"sub.custom-sms.com", false},
		{"api.telegram.org", false},
		{"core.telegram.org:443", false},
		{"api.wordpress.org", false},
		{"example.com", false},
	}
	for _, tc := range cases {
		if got := ShouldRouteViaIran(tc.host, cfg); got != tc.want {
			t.Errorf("split mode ShouldRouteViaIran(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}

	// In "all" mode, everything goes via Iran except bypass domains and loopback/private IPs.
	cfg.OutboundProxyMode = "all"
	allCases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"myshop.ir", true},
		{"api.telegram.org", false},
		{"updates.wordpress.org", false},
		{"127.0.0.1:8080", false},
		{"localhost", false},
	}
	for _, tc := range allCases {
		if got := ShouldRouteViaIran(tc.host, cfg); got != tc.want {
			t.Errorf("all mode ShouldRouteViaIran(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestOutboundProxyEndToEnd(t *testing.T) {
	allowLoopbackProxyForTest = true
	defer func() { allowLoopbackProxyForTest = false }()

	// Target web server pretending to be an external destination.
	destSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		_, _ = fmt.Fprintf(w, "hello from %s", r.Host)
	}))
	defer destSrv.Close()
	destURL, err := url.Parse(destSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, destPort, err := net.SplitHostPort(destURL.Host)
	if err != nil {
		t.Fatal(err)
	}

	bindAddr := freeAddr(t)
	userAddr := freeAddr(t)
	proxyPort := freePortForProxy(t)
	secretPath := writeSecret(t, testSecret)

	mk := func(role Role) *Config {
		cfg := DefaultConfig()
		cfg.Name = "wb-" + string(role)
		cfg.Mode = ModeDirect
		cfg.Role = role
		cfg.Transport = TransportPlain
		cfg.Mux = true
		cfg.MuxLinks = 2
		cfg.SecretFile = secretPath
		cfg.StatusFile = ""
		cfg.TunnelAddr = bindAddr
		cfg.WebsiteBridge = true
		cfg.OutboundProxy = true
		cfg.OutboundProxyPort = proxyPort
		cfg.OutboundProxyMode = "split"
		cfg.OutboundIranDomains = ".ir, shaparak.ir"
		cfg.OutboundBypassDomains = "telegram.org"
		if role == RoleEdge {
			cfg.UserListen = userAddr
			cfg.LocalIP = "185.143.233.10"
		} else {
			cfg.InboundAddr = destURL.Host
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("validate %s: %v", role, err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatalf("load secret: %v", err)
		}
		return cfg
	}

	edgeCfg, origCfg := mk(RoleEdge), mk(RoleOrigin)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = runOrigin(ctx, origCfg, newStatus(origCfg))
	}()
	time.Sleep(150 * time.Millisecond)
	go func() {
		defer wg.Done()
		_ = runEdge(ctx, edgeCfg, newStatus(edgeCfg))
	}()
	defer func() {
		cancel()
		wg.Wait()
	}()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	time.Sleep(800 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		},
		Timeout: 5 * time.Second,
	}

	// 1. Built-in Iran exit IP verification (portbridge-iran-check.ir) via reverse mux stream to Edge.
	resp, err := client.Get("http://" + OutboundCheckHost + "/ip")
	if err != nil {
		t.Fatalf("Iran check request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-PortBridge-Route"); got != "iran" {
		t.Fatalf("X-PortBridge-Route = %q, want iran", got)
	}
	if !strings.Contains(string(body), "185.143.233.10") {
		t.Fatalf("Iran check body = %q, want edge LocalIP 185.143.233.10", string(body))
	}

	// 2. HTTP CONNECT via Iran route for portbridge-iran-check.ir:80
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n", OutboundCheckHost, OutboundCheckHost)
	br := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("CONNECT response error: %v", err)
	}
	if connectResp.StatusCode != 200 {
		_ = conn.Close()
		t.Fatalf("CONNECT status = %d, want 200", connectResp.StatusCode)
	}
	if got := connectResp.Header.Get("X-PortBridge-Route"); got != "iran" {
		_ = conn.Close()
		t.Fatalf("CONNECT X-PortBridge-Route = %q, want iran", got)
	}
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", OutboundCheckHost)
	innerResp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("inner GET response error: %v", err)
	}
	innerBody, _ := io.ReadAll(innerResp.Body)
	_ = innerResp.Body.Close()
	_ = conn.Close()
	if !strings.Contains(string(innerBody), "185.143.233.10") {
		t.Fatalf("inner body = %q, want 185.143.233.10", string(innerBody))
	}

	// 3. Direct route via HTTP proxy to local test server (127.0.0.1:<destPort>)
	resp2, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/test", destPort))
	if err != nil {
		t.Fatalf("direct proxy GET failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if !strings.Contains(string(body2), "hello from 127.0.0.1") {
		t.Fatalf("direct body = %q", string(body2))
	}
	dconn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(dconn, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n", destPort, destPort)
	dbr := bufio.NewReader(dconn)
	dConnectResp, err := http.ReadResponse(dbr, nil)
	_ = dconn.Close()
	if err != nil {
		t.Fatalf("direct CONNECT response error: %v", err)
	}
	if got := dConnectResp.Header.Get("X-PortBridge-Route"); got != "direct" {
		t.Fatalf("direct CONNECT X-PortBridge-Route = %q, want direct", got)
	}

	// 4. SOCKS5 proxy test on the same port to OutboundCheckHost:80 (via Iran)
	sconn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sconn.Close()
	if _, err := sconn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	sreply := make([]byte, 2)
	if _, err := io.ReadFull(sconn, sreply); err != nil || sreply[0] != 0x05 || sreply[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting reply = %v, err = %v", sreply, err)
	}
	hostBytes := []byte(OutboundCheckHost)
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}, hostBytes...)
	req = append(req, 0x00, 80)
	if _, err := sconn.Write(req); err != nil {
		t.Fatal(err)
	}
	connReply := make([]byte, 10)
	if _, err := io.ReadFull(sconn, connReply); err != nil || connReply[1] != 0x00 {
		t.Fatalf("SOCKS5 connect reply = %v, err = %v", connReply, err)
	}
	_, _ = fmt.Fprintf(sconn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", OutboundCheckHost)
	sbr := bufio.NewReader(sconn)
	sResp, err := http.ReadResponse(sbr, nil)
	if err != nil {
		t.Fatalf("SOCKS5 HTTP response error: %v", err)
	}
	sBody, _ := io.ReadAll(sResp.Body)
	_ = sResp.Body.Close()
	if !strings.Contains(string(sBody), "185.143.233.10") {
		t.Fatalf("SOCKS5 body = %q, want 185.143.233.10", string(sBody))
	}
}

func freePortForProxy(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
