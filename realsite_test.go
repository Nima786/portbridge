package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Helper: spins up a mock HTTPS "real cover website" that serves a mock cert and HTTP 200.
func startMockCoverSite(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	certFile, keyFile := certPaths(t)
	cert, err := ensureCert(certFile, keyFile, "www.example.com")
	if err != nil {
		t.Fatalf("ensureCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening mock cover site: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Hello from the Genuine Website!"))
	})

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	tlsLn := tls.NewListener(ln, server.TLSConfig)
	go func() {
		_ = server.Serve(tlsLn)
	}()

	return ln.Addr().String(), func() {
		_ = server.Close()
		_ = ln.Close()
	}
}

// 1. Strangers connecting get passed straight to the genuine site.
func TestRealSiteStrangersPassedToCoverSite(t *testing.T) {
	coverAddr, cleanupCover := startMockCoverSite(t)
	defer cleanupCover()

	secret := []byte("0123456789abcdef0123456789abcdef")

	// Server config: listening with RealSite enabled
	serverCertFile, serverKeyFile := certPaths(t)
	serverCert, err := ensureCert(serverCertFile, serverKeyFile, "tunnel.internal")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Name:       "test-rs",
		Transport:  TransportTLS,
		RealSite:   true,
		CoverSite:  coverAddr,
		ServerName: "www.example.com",
		secret:     secret,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newReplayGuard(ctx)

	// Accept loop for server
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		// wrapAccept with RealSite
		_, _ = wrapAccept(raw, cfg, &serverCert, guard)
	}()

	// Stranger connects with normal standard TLS Client (no PortBridge secret proof)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "www.example.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("stranger dial failed: %v", err)
	}
	defer conn.Close()

	// Verify stranger got the cover site's cert, not PortBridge's cert!
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no certificates presented to stranger")
	}
	if state.PeerCertificates[0].Subject.CommonName != "www.example.com" {
		t.Fatalf("stranger got cert with CN %q, expected cover site 'www.example.com'",
			state.PeerCertificates[0].Subject.CommonName)
	}

	// Stranger sends HTTP request
	req := "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("writing request: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if !strings.Contains(string(resp), "Hello from the Genuine Website!") {
		t.Fatalf("stranger did not receive cover site response; got: %q", string(resp))
	}
}

// 2. Authentic PortBridge clients carrying secret proof connect into the tunnel.
func TestRealSiteAuthenticClientConnects(t *testing.T) {
	coverAddr, cleanupCover := startMockCoverSite(t)
	defer cleanupCover()

	secret := []byte("0123456789abcdef0123456789abcdef")

	serverCertFile, serverKeyFile := certPaths(t)
	serverCert, err := ensureCert(serverCertFile, serverKeyFile, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := &Config{
		Name:       "test-rs-server",
		Transport:  TransportTLS,
		RealSite:   true,
		CoverSite:  coverAddr,
		ServerName: "www.example.com",
		secret:     secret,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newReplayGuard(ctx)

	serverAccepted := make(chan net.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		c, err := wrapAccept(raw, serverCfg, &serverCert, guard)
		if err != nil {
			t.Errorf("wrapAccept server error: %v", err)
			return
		}
		serverAccepted <- c
	}()

	// Client dials with RealSite=true
	clientCfg := &Config{
		Name:       "test-rs-client",
		Transport:  TransportTLS,
		RealSite:   true,
		ServerName: "www.example.com",
		secret:     secret,
	}
	clientCfg.prepareTLS(nil)

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer rawClient.Close()

	clientConn, err := wrapDial(rawClient, clientCfg)
	if err != nil {
		t.Fatalf("client wrapDial failed: %v", err)
	}
	defer clientConn.Close()

	select {
	case srvConn := <-serverAccepted:
		defer srvConn.Close()
		// Send data across authentic tunnel
		go func() {
			_, _ = clientConn.Write([]byte("tunnel payload"))
		}()
		buf := make([]byte, 64)
		n, err := srvConn.Read(buf)
		if err != nil {
			t.Fatalf("server read tunnel payload error: %v", err)
		}
		if string(buf[:n]) != "tunnel payload" {
			t.Fatalf("expected 'tunnel payload', got %q", string(buf[:n]))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to accept authentic tunnel client")
	}
}

// 3. Copied/replayed hellos from a real client get detected and passed to the real site.
func TestRealSiteReplayedHelloPassedToCoverSite(t *testing.T) {
	coverAddr, cleanupCover := startMockCoverSite(t)
	defer cleanupCover()

	secret := []byte("0123456789abcdef0123456789abcdef")

	serverCertFile, serverKeyFile := certPaths(t)
	serverCert, err := ensureCert(serverCertFile, serverKeyFile, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := &Config{
		Name:       "test-rs-replay",
		Transport:  TransportTLS,
		RealSite:   true,
		CoverSite:  coverAddr,
		ServerName: "www.example.com",
		secret:     secret,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newReplayGuard(ctx)

	// Step 1: Real client connects to server. We wrap raw client conn with a recorder
	// to capture the exact ClientHello bytes sent on the wire.
	clientCfg := &Config{
		Name:       "test-rs-replay-client",
		Transport:  TransportTLS,
		RealSite:   true,
		ServerName: "www.example.com",
		secret:     secret,
	}
	clientCfg.prepareTLS(nil)

	serverAccepted := make(chan net.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		c, err := wrapAccept(raw, serverCfg, &serverCert, guard)
		if err == nil {
			serverAccepted <- c
		}
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawClient.Close()

	// Capture first write (which is the ClientHello)
	var capturedHello []byte
	var recMu sync.Mutex
	recorder := &recordConn{
		Conn: rawClient,
		onWrite: func(b []byte) {
			recMu.Lock()
			if len(capturedHello) == 0 {
				capturedHello = append([]byte(nil), b...)
			}
			recMu.Unlock()
		},
	}

	clientConn, err := wrapDial(recorder, clientCfg)
	if err != nil {
		t.Fatalf("first connection wrapDial failed: %v", err)
	}
	defer clientConn.Close()

	select {
	case srvConn := <-serverAccepted:
		srvConn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("first connection was not accepted")
	}

	recMu.Lock()
	rawHello := append([]byte(nil), capturedHello...)
	recMu.Unlock()

	if len(rawHello) == 0 {
		t.Fatal("failed to capture ClientHello from first connection")
	}

	// Step 2 (Replay attack): censor replays the exact captured ClientHello on a new connection!
	// Replay guard must detect it and pass it to the cover site.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		// wrapAccept should detect replay and forward stranger to cover site
		_, _ = wrapAccept(raw, serverCfg, &serverCert, guard)
	}()

	if _, err := c2.Write(rawHello); err != nil {
		t.Fatal(err)
	}

	// Read reply from c2: cover site will answer with TLS ServerHello!
	replyBuf := make([]byte, 1024)
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c2.Read(replyBuf)
	if err != nil {
		t.Fatalf("reading response to replayed hello: %v", err)
	}
	// Reply from mock cover site starts with TLS record: 0x16 0x03
	if n < 5 || replyBuf[0] != 0x16 || replyBuf[1] != 0x03 {
		t.Fatalf("replayed hello did not receive TLS response from cover site; got %x", replyBuf[:n])
	}
}

type recordConn struct {
	net.Conn
	onWrite func([]byte)
}

func (r *recordConn) Write(b []byte) (int, error) {
	if r.onWrite != nil {
		r.onWrite(b)
	}
	return r.Conn.Write(b)
}

// 4. ClientHello split across multiple TCP segments is reassembled and verified.
func TestRealSiteSplitHello(t *testing.T) {
	coverAddr, cleanupCover := startMockCoverSite(t)
	defer cleanupCover()

	secret := []byte("0123456789abcdef0123456789abcdef")

	serverCertFile, serverKeyFile := certPaths(t)
	serverCert, err := ensureCert(serverCertFile, serverKeyFile, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := &Config{
		Name:       "test-rs-split",
		Transport:  TransportTLS,
		RealSite:   true,
		CoverSite:  coverAddr,
		ServerName: "www.example.com",
		secret:     secret,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newReplayGuard(ctx)

	serverAccepted := make(chan net.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		c, err := wrapAccept(raw, serverCfg, &serverCert, guard)
		if err != nil {
			t.Errorf("wrapAccept server error: %v", err)
			return
		}
		serverAccepted <- c
	}()

	// Client dials with RealSite and fragmentation enabled
	clientCfg := &Config{
		Name:             "test-rs-split-client",
		Transport:        TransportTLS,
		RealSite:         true,
		TLSFragment:      true,
		TLSFragmentSize:  30, // split after 30 bytes, well before Session ID offset (44)
		TLSFragmentSleep: 10 * time.Millisecond,
		ServerName:       "www.example.com",
		secret:           secret,
	}
	clientCfg.prepareTLS(nil)

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer rawClient.Close()

	clientConn, err := wrapDial(rawClient, clientCfg)
	if err != nil {
		t.Fatalf("client wrapDial with split hello failed: %v", err)
	}
	defer clientConn.Close()

	select {
	case srvConn := <-serverAccepted:
		defer srvConn.Close()
		go func() {
			_, _ = clientConn.Write([]byte("fragmented tunnel payload"))
		}()
		buf := make([]byte, 64)
		n, err := srvConn.Read(buf)
		if err != nil {
			t.Fatalf("server read payload error: %v", err)
		}
		if string(buf[:n]) != "fragmented tunnel payload" {
			t.Fatalf("expected 'fragmented tunnel payload', got %q", string(buf[:n]))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to accept fragmented ClientHello")
	}
}

// 5. Non-TLS garbage sent by strangers gets forwarded to the cover site cleanly.
func TestRealSiteNonTLSStrangersForwarded(t *testing.T) {
	coverAddr, cleanupCover := startMockCoverSite(t)
	defer cleanupCover()

	secret := []byte("0123456789abcdef0123456789abcdef")

	serverCertFile, serverKeyFile := certPaths(t)
	serverCert, err := ensureCert(serverCertFile, serverKeyFile, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := &Config{
		Name:       "test-rs-nontls",
		Transport:  TransportTLS,
		RealSite:   true,
		CoverSite:  coverAddr,
		ServerName: "www.example.com",
		secret:     secret,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newReplayGuard(ctx)

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = wrapAccept(raw, serverCfg, &serverCert, guard)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send non-TLS raw garbage
	if _, err := conn.Write([]byte("RANDOM_PORT_SCANNER_PROBE\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	// Sockets should not crash or panic; connection gets closed or handled cleanly
	time.Sleep(100 * time.Millisecond)
}
