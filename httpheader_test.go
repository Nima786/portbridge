package main

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen")
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-done
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// After the exchange the connection carries the tunnel's own bytes untouched, in
// both directions, and none of them were swallowed by the header reading.
func TestHTTPHeaderThenRawBytes(t *testing.T) {
	c, s := tcpPair(t)
	errs := make(chan error, 2)
	go func() { errs <- httpHeaderDial(c, "cdn.example.org") }()
	go func() { errs <- httpHeaderAccept(s) }()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	go func() { _, _ = c.Write([]byte("tunnel bytes from the dialler")) }()
	buf := make([]byte, len("tunnel bytes from the dialler"))
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "tunnel bytes from the dialler" {
		t.Fatalf("bytes after the header were lost or changed: %q %v", buf, err)
	}
	go func() { _, _ = s.Write([]byte("and back")) }()
	back := make([]byte, 8)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, back); err != nil || string(back) != "and back" {
		t.Fatalf("reply bytes lost: %q %v", back, err)
	}
}

// The name asked for is the name sent, and it looks like a browser's request.
func TestHTTPHeaderNamesTheChosenHost(t *testing.T) {
	req := string(httpHeaderRequest("my.chosen.example"))
	if !strings.HasPrefix(req, "GET / HTTP/1.1\r\n") || !strings.Contains(req, "\r\nHost: my.chosen.example\r\n") ||
		!strings.HasSuffix(req, "\r\n\r\n") {
		t.Fatalf("unexpected request:\n%s", req)
	}
	if !strings.Contains(string(httpHeaderRequest("")), defaultHTTPHost) {
		t.Fatalf("no default name used")
	}
	if !strings.HasPrefix(string(httpHeaderReply()), "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("unexpected reply")
	}
}

// A peer without the header turned on is refused at once, by name, not after a
// timeout, and the one with it on is told the other did not answer.
func TestHTTPHeaderMismatchIsNamedQuickly(t *testing.T) {
	// Acceptor has it on, the dialler sends its own opening bytes.
	c, s := tcpPair(t)
	go func() {
		_, _ = c.Write([]byte("\x47\x00random opening bytes of a plain link, not a web request, long enough to matter......"))
	}()
	start := time.Now()
	err := httpHeaderAccept(s)
	if !errors.Is(err, errHTTPNotHeader) || time.Since(start) > 2*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}

	// Dialler has it on, the acceptor does not and just closes.
	c2, s2 := tcpPair(t)
	go func() {
		buf := make([]byte, 64)
		_, _ = s2.Read(buf)
		_ = s2.Close()
	}()
	err = httpHeaderDial(c2, "x.example")
	if !errors.Is(err, errHTTPNoReply) {
		t.Fatalf("dialler got %v", err)
	}
}

func TestHTTPHeaderConfig(t *testing.T) {
	cfg := defaultConfig()
	if err := cfg.set("http_header", "on"); err != nil {
		t.Fatal(err)
	}
	cfg.Name = "httptest"
	cfg.Transport = TransportPlain
	cfg.Role = RoleEdge
	cfg.Mode = ModeDirect
	cfg.TunnelAddr = "192.0.2.1:443"
	cfg.UserListen = "127.0.0.1:9999"
	cfg.SecretFile = writeSecret(t, testSecret)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPHost != defaultHTTPHost {
		t.Fatalf("no default host: %q", cfg.HTTPHost)
	}

	bad := *cfg
	bad.Transport = TransportWSS
	bad.HTTPHeader = true
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "plain") {
		t.Fatalf("http_header on a website link was accepted: %v", err)
	}
	if err := cfg.set("http_host", "not a host!"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("a bad host name was accepted")
	}
	if err := cfg.set("http_header", "maybe"); err == nil {
		t.Fatalf("a bad value was accepted")
	}
}

// Through the real engine, in both directions, with a name of my own choosing.
func TestTunnelCarriesTrafficWithTheWebHeader(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		t.Run(string(mode), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tunnelAddr := freeAddr(t)
			userAddr := freeAddr(t)
			mk := func(role Role) *Config {
				return tunnelCfg(t, role, func(c *Config) {
					c.Mode = mode
					c.HTTPHeader = true
					c.HTTPHost = "files.example.org"
					c.TunnelAddr = tunnelAddr
					if role == RoleEdge {
						c.UserListen = userAddr
					} else {
						c.InboundAddr = svc.addr
					}
				})
			}
			edgeCfg, originCfg := mk(RoleEdge), mk(RoleOrigin)
			if mode == ModeDirect {
				_, stop := runHalf(t, originCfg, runOrigin)
				defer stop()
				time.Sleep(150 * time.Millisecond)
				_, stop2 := runHalf(t, edgeCfg, runEdge)
				defer stop2()
			} else {
				_, stop := runHalf(t, edgeCfg, runEdge)
				defer stop()
				time.Sleep(150 * time.Millisecond)
				_, stop2 := runHalf(t, originCfg, runOrigin)
				defer stop2()
			}
			time.Sleep(800 * time.Millisecond)

			payload := strings.Repeat("through the fake web header ", 200)
			got, err := roundTrip(t, userAddr, payload, 8*time.Second)
			if err != nil || got != strings.ToUpper(payload) {
				t.Fatalf("traffic did not flow: %v", err)
			}
		})
	}
}

// What a filter sees first on the wire really is a web request, and only then the
// tunnel's own bytes.
func TestWebHeaderIsWhatComesFirstOnTheWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen")
	}
	defer ln.Close()
	first := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 200)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := io.ReadFull(c, buf)
		first <- string(buf[:n])
	}()

	cfg := tunnelCfg(t, RoleEdge, func(c *Config) {
		c.Mode = ModeDirect
		c.HTTPHeader = true
		c.HTTPHost = "wire.example.org"
		c.TunnelAddr = ln.Addr().String()
		c.UserListen = freeAddr(t)
		c.PoolSize = 1
		c.PathProbe = false
	})
	_, stop := runHalf(t, cfg, runEdge)
	defer stop()

	select {
	case s := <-first:
		if !strings.HasPrefix(s, "GET / HTTP/1.1\r\nHost: wire.example.org\r\n") {
			t.Fatalf("the first bytes on the wire were not the web request: %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("nothing was sent")
	}
}

// A version 7 code brings the web header to the foreign half, and a plain code
// does not grow one.
func TestPairingCodeCarriesTheWebHeader(t *testing.T) {
	code := encodeCode("v=7\nname=hdr\nmode=direct\ntunnel_port=8443\nrelay_ip=1.1.1.1\nserver_ip=2.2.2.2\n" +
		"inbound_port=8080\npool=10\ntransport=plain\nhttp_header=on\nhttp_host=files.example.org\n" +
		"secret=0123456789abcdef0123456789abcdef\n")
	p, err := decodePairingCode(code)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := applyPairingData(p, dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(filepath.Join(dir, "hdr.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HTTPHeader || cfg.HTTPHost != "files.example.org" {
		t.Fatalf("the foreign half lost the web header: %v %q", cfg.HTTPHeader, cfg.HTTPHost)
	}

	plain := goodPairing("nohdr")
	plain.TunnelPort, plain.InboundPort = "9443", "9090"
	if err := applyPairingData(plain, dir); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := LoadConfig(filepath.Join(dir, "nohdr.conf"))
	if cfg2.HTTPHeader {
		t.Fatalf("a plain code grew a web header")
	}

	bad := goodPairing("badhdr")
	bad.Transport = "wss"
	bad.HTTPHeader = "on"
	if err := applyPairingData(bad, t.TempDir()); err == nil {
		t.Fatalf("a web header on a website link was accepted")
	}
}

// Ensure the fake web request is not static or identical across connections,
// and has a realistic browser size (> 500 bytes).
func TestHTTPHeaderDynamicAndRandomized(t *testing.T) {
	req1 := httpHeaderRequest("www.bing.com")
	req2 := httpHeaderRequest("www.bing.com")

	if len(req1) < 400 || len(req2) < 400 {
		t.Fatalf("request size is too small: len1=%d len2=%d", len(req1), len(req2))
	}

	// Over a few samples, requests must not be identical
	different := false
	for i := 0; i < 5; i++ {
		r := httpHeaderRequest("www.bing.com")
		if string(r) != string(req1) {
			different = true
			break
		}
	}
	if !different {
		t.Fatal("httpHeaderRequest generated identical bytes across connections")
	}
}

// Scanners sending garbage or non-HTTP data receive a realistic 400 Bad Request
// from nginx instead of being abruptly disconnected with zero bytes.
func TestHTTPHeaderAnswersBadRequestToProbes(t *testing.T) {
	c, s := tcpPair(t)
	go func() {
		// Scanner sends binary garbage
		_, _ = c.Write([]byte("\x16\x03\x01\x02\x00some non-http probe"))
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpHeaderAccept(s)
	}()

	buf := make([]byte, 1024)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("expected 400 Bad Request reply, got read error: %v", err)
	}
	reply := string(buf[:n])
	if !strings.HasPrefix(reply, "HTTP/1.1 400 Bad Request\r\n") || !strings.Contains(reply, "nginx") {
		t.Fatalf("expected authentic nginx 400 Bad Request, got:\n%s", reply)
	}

	if err := <-errCh; !errors.Is(err, errHTTPNotHeader) {
		t.Fatalf("expected errHTTPNotHeader, got %v", err)
	}
}
