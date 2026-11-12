package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestH3DirectBidirectionalAndMux(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := []byte("0123456789abcdef0123456789abcdef")
	cert := makeXHTTPTestCert(t, "www.google.com")
	guard := newReplayGuard(ctx)

	serverCfg := DefaultConfig()
	serverCfg.Mode = ModeDirect
	serverCfg.Role = RoleOrigin
	serverCfg.Transport = TransportH3
	serverCfg.ServerName = "www.google.com"
	serverCfg.WSPath = "/api/v3/testh3"
	serverCfg.Mux = true
	serverCfg.secret = secret
	serverCfg.prepareTLS(&cert)

	ln, err := h3Listen("127.0.0.1:0", serverCfg, &cert, guard)
	if err != nil {
		t.Fatalf("h3Listen: %v", err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 8)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, err := wrapAccept(c, serverCfg, &cert, guard)
				if err != nil {
					_ = c.Close()
					return
				}
				if _, err := recvAuthPurpose(sc, secret, guard); err != nil {
					_ = sc.Close()
					return
				}
				acceptedCh <- sc
			}(raw)
		}
	}()

	clientCfg := DefaultConfig()
	clientCfg.Mode = ModeDirect
	clientCfg.Role = RoleEdge
	clientCfg.TunnelAddr = ln.Addr().String()
	clientCfg.Transport = TransportH3
	clientCfg.ServerName = "www.google.com"
	clientCfg.WSPath = "/api/v3/testh3"
	clientCfg.Mux = true
	clientCfg.secret = secret
	clientCfg.prepareTLS(nil)

	rawPre, err := dialH3QUIC(ln.Addr().String(), clientCfg, 5*time.Second)
	if err != nil {
		t.Fatalf("dialH3QUIC: %v", err)
	}
	cc, err := wrapDialPurpose(rawPre, clientCfg, authPurposeTunnelMux)
	if err != nil {
		_ = rawPre.Close()
		t.Fatalf("wrapDialPurpose(h3): %v", err)
	}
	// Verify h3PreConn ownership handoff makes rawPre.Close() a safe no-op.
	_ = rawPre.Close()
	defer cc.Close()

	if err := sendAuthPurpose(cc, secret, authPurposeTunnelMux); err != nil {
		t.Fatalf("sendAuthPurpose: %v", err)
	}

	var sc net.Conn
	select {
	case sc = <-acceptedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to accept H3 stream")
	}
	defer sc.Close()

	// 1. Bidirectional 1.5 MB transfer over H3 stream.
	const payloadBytes = 1536 * 1024
	upData := make([]byte, payloadBytes)
	downData := make([]byte, payloadBytes)
	_, _ = rand.Read(upData)
	_, _ = rand.Read(downData)

	upWant := sha256.Sum256(upData)
	downWant := sha256.Sum256(downData)

	var wg sync.WaitGroup
	var upGot, downGot [32]byte
	var wUpErr, rUpErr, wDownErr, rDownErr error

	wg.Add(4)
	go func() {
		defer wg.Done()
		_, wUpErr = cc.Write(upData)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, len(upData))
		if _, rUpErr = io.ReadFull(sc, buf); rUpErr == nil {
			upGot = sha256.Sum256(buf)
		}
	}()
	go func() {
		defer wg.Done()
		_, wDownErr = sc.Write(downData)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, len(downData))
		if _, rDownErr = io.ReadFull(cc, buf); rDownErr == nil {
			downGot = sha256.Sum256(buf)
		}
	}()
	wg.Wait()

	for _, err := range []error{wUpErr, rUpErr, wDownErr, rDownErr} {
		if err != nil {
			t.Fatalf("bidirectional H3 transfer failed: %v", err)
		}
	}
	if upGot != upWant {
		t.Fatal("H3 uplink SHA256 mismatch")
	}
	if downGot != downWant {
		t.Fatal("H3 downlink SHA256 mismatch")
	}

	// 2. Concurrent Read + Close race safety check on a second H3 connection.
	rawPre2, err := dialH3QUIC(ln.Addr().String(), clientCfg, 5*time.Second)
	if err != nil {
		t.Fatalf("dialH3QUIC #2: %v", err)
	}
	cc2, err := wrapDialPurpose(rawPre2, clientCfg, authPurposeTunnelMux)
	if err != nil {
		t.Fatalf("wrapDialPurpose #2: %v", err)
	}
	if err := sendAuthPurpose(cc2, secret, authPurposeTunnelMux); err != nil {
		t.Fatalf("sendAuthPurpose #2: %v", err)
	}
	sc2 := <-acceptedCh
	defer sc2.Close()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		var b [64]byte
		_, _ = cc2.Read(b[:])
	}()
	time.Sleep(25 * time.Millisecond)
	_ = cc2.Close()
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked Read on h3ClientConn did not unblock after Close()")
	}
}

func TestH3CDNSplitHTTPAndCloudflareEdgeSimulation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := []byte("fedcba9876543210fedcba9876543210")
	cert := makeXHTTPTestCert(t, "cdn.example.com")
	guard := newReplayGuard(ctx)

	serverCfg := DefaultConfig()
	serverCfg.Mode = ModeDirect
	serverCfg.Role = RoleOrigin
	serverCfg.Transport = TransportH3
	serverCfg.CDN = true
	serverCfg.ServerName = "cdn.example.com"
	serverCfg.WSPath = "/api/v1/h3cdn"
	serverCfg.secret = secret
	serverCfg.prepareTLS(&cert)

	// h3Listen with CDN=true binds BOTH UDP HTTP/3 and TCP TLS on the same port.
	originLn, err := h3Listen("127.0.0.1:0", serverCfg, &cert, guard)
	if err != nil {
		t.Fatalf("h3Listen(CDN): %v", err)
	}
	defer originLn.Close()

	originAddr := originLn.Addr().String()
	_, portStr, _ := net.SplitHostPort(originAddr)
	originPort, _ := strconv.Atoi(portStr)

	acceptedCh := make(chan net.Conn, 8)
	go func() {
		for {
			raw, err := originLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, err := wrapAccept(c, serverCfg, &cert, guard)
				if err != nil {
					if !errors.Is(err, errXHTTPUplinkAttached) {
						_ = c.Close()
					}
					return
				}
				if _, err := recvAuthPurpose(sc, secret, guard); err != nil {
					_ = sc.Close()
					return
				}
				acceptedCh <- sc
			}(raw)
		}
	}()

	// Subtest A: End-to-end HTTP/3 SplitHTTP (client H3 -> origin UDP H3).
	t.Run("end-to-end-h3-split", func(t *testing.T) {
		clientCfg := DefaultConfig()
		clientCfg.Mode = ModeDirect
		clientCfg.Role = RoleEdge
		clientCfg.TunnelAddr = originAddr
		clientCfg.Transport = TransportH3
		clientCfg.CDN = true
		clientCfg.ServerName = "cdn.example.com"
		clientCfg.WSPath = "/api/v1/h3cdn"
		clientCfg.secret = secret
		clientCfg.prepareTLS(nil)

		pre, err := dialH3QUIC(originAddr, clientCfg, 5*time.Second)
		if err != nil {
			t.Fatalf("dialH3QUIC: %v", err)
		}
		cc, err := wrapDialPurpose(pre, clientCfg, authPurposeTunnelMux)
		if err != nil {
			t.Fatalf("wrapDialPurpose(h3-cdn): %v", err)
		}
		defer cc.Close()

		if err := sendAuthPurpose(cc, secret, authPurposeTunnelMux); err != nil {
			t.Fatalf("sendAuthPurpose: %v", err)
		}

		var sc net.Conn
		select {
		case sc = <-acceptedCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for H3-CDN session on origin")
		}
		defer sc.Close()

		msgUp := bytes.Repeat([]byte("H3-CDN-UPLINK-DATA-"), 8000)
		msgDown := bytes.Repeat([]byte("H3-CDN-DOWNLINK-DATA-"), 8000)

		errCh := make(chan error, 2)
		go func() {
			_, err := cc.Write(msgUp)
			errCh <- err
		}()
		go func() {
			_, err := sc.Write(msgDown)
			errCh <- err
		}()

		gotUp := make([]byte, len(msgUp))
		if _, err := io.ReadFull(sc, gotUp); err != nil {
			t.Fatalf("reading H3-CDN uplink: %v", err)
		}
		gotDown := make([]byte, len(msgDown))
		if _, err := io.ReadFull(cc, gotDown); err != nil {
			t.Fatalf("reading H3-CDN downlink: %v", err)
		}
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("write error: %v", err)
			}
		}
		if !bytes.Equal(gotUp, msgUp) || !bytes.Equal(gotDown, msgDown) {
			t.Fatal("H3-CDN payload mismatch")
		}
	})

	// Subtest B: Simulated Cloudflare Edge (Client speaks QUIC/HTTP3 UDP to CF Edge,
	// CF Edge forwards HTTP/1.1 GET+POST over TLS/TCP to Origin's TCP port).
	t.Run("cloudflare-h3-to-http1-origin", func(t *testing.T) {
		targetURL, _ := url.Parse("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)))
		rp := httputil.NewSingleHostReverseProxy(targetURL)
		rp.FlushInterval = -1
		rp.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "cdn.example.com",
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			},
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: 16,
		}

		cfUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenUDP for mock CF: %v", err)
		}
		defer cfUDP.Close()

		cfSrv := &http3.Server{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{http3.NextProtoH3},
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Host = "cdn.example.com"
				rp.ServeHTTP(w, r)
			}),
		}
		defer cfSrv.Close()
		go func() {
			_ = cfSrv.Serve(cfUDP)
		}()

		clientCfg := DefaultConfig()
		clientCfg.Mode = ModeDirect
		clientCfg.Role = RoleEdge
		clientCfg.TunnelAddr = cfUDP.LocalAddr().String()
		clientCfg.Transport = TransportH3
		clientCfg.CDN = true
		clientCfg.ServerName = "cdn.example.com"
		clientCfg.WSPath = "/api/v1/h3cdn"
		clientCfg.secret = secret
		clientCfg.prepareTLS(nil)

		pre, err := dialH3QUIC(cfUDP.LocalAddr().String(), clientCfg, 5*time.Second)
		if err != nil {
			t.Fatalf("dialH3QUIC to mock CF: %v", err)
		}
		cc, err := wrapDialPurpose(pre, clientCfg, authPurposeTunnelMux)
		if err != nil {
			t.Fatalf("wrapDialPurpose via mock CF: %v", err)
		}
		defer cc.Close()

		if err := sendAuthPurpose(cc, secret, authPurposeTunnelMux); err != nil {
			t.Fatalf("sendAuthPurpose via mock CF: %v", err)
		}

		var sc net.Conn
		select {
		case sc = <-acceptedCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for Origin TCP session via mock CF H3 proxy")
		}
		defer sc.Close()

		want := []byte("hello through Cloudflare QUIC H3 edge to HTTP/1.1 TLS origin!")
		if _, err := cc.Write(want); err != nil {
			t.Fatalf("cc.Write: %v", err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(sc, got); err != nil {
			t.Fatalf("sc.Read: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("uplink mismatch: got %q want %q", got, want)
		}

		reply := []byte("origin chunked HTTP/1.1 reply back over Cloudflare HTTP/3 stream!")
		if _, err := sc.Write(reply); err != nil {
			t.Fatalf("sc.Write: %v", err)
		}
		gotReply := make([]byte, len(reply))
		if _, err := io.ReadFull(cc, gotReply); err != nil {
			t.Fatalf("cc.Read: %v", err)
		}
		if !bytes.Equal(gotReply, reply) {
			t.Fatalf("downlink mismatch: got %q want %q", gotReply, reply)
		}
	})
}

func TestH3Decoy404ForUnauthenticatedProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := []byte("0123456789abcdef0123456789abcdef")
	cert := makeXHTTPTestCert(t, "www.google.com")
	guard := newReplayGuard(ctx)

	serverCfg := DefaultConfig()
	serverCfg.Transport = TransportH3
	serverCfg.ServerName = "www.google.com"
	serverCfg.WSPath = "/api/v3/secretpath"
	serverCfg.secret = secret
	serverCfg.prepareTLS(&cert)

	ln, err := h3Listen("127.0.0.1:0", serverCfg, &cert, guard)
	if err != nil {
		t.Fatalf("h3Listen: %v", err)
	}
	defer ln.Close()

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         "www.google.com",
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, path := range []string{"/", "/api/v3/secretpath", "/api/v1/unknown"} {
		resp, err := client.Get("https://" + ln.Addr().String() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "404 Not Found") {
			t.Fatalf("expected 404 nginx decoy for %s, got status=%d body=%q", path, resp.StatusCode, string(body))
		}
	}
}

func TestProbeListenerDemuxesH3AndPortHopKCPOnSamePort(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	pl, err := StartProbeListener("127.0.0.1", 0, secret, 30*time.Second)
	if err != nil {
		t.Fatalf("StartProbeListener: %v", err)
	}
	defer pl.Close()

	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(pl.Port))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	specs := []ProbeCandidateSpec{
		{
			ID:         "direct-h3",
			Label:      "QUIC / HTTP/3 Stream",
			Mode:       "direct",
			Transport:  "h3",
			Link:       "h3",
			ServerName: "www.google.com",
			Port:       pl.Port,
			TargetAddr: target,
		},
		{
			ID:         "direct-kcp-hop",
			Label:      "KCP Port-Hopping UDP",
			Mode:       "direct",
			Transport:  "kcp",
			Link:       "kcp-hop",
			PortHop:    true,
			Port:       pl.Port,
			TargetAddr: target,
		},
		{
			ID:         "direct-xhttp",
			Label:      "SplitHTTP / XHTTP Stream (Direct)",
			Mode:       "direct",
			Transport:  "xhttp",
			Link:       "xhttp",
			Stealth:    true,
			ServerName: "www.bing.com",
			Port:       pl.Port,
			TargetAddr: target,
		},
	}

	for _, sp := range specs {
		res := probeOneSpec(ctx, sp, secret, 64*1024)
		if res.Status != "ok" {
			t.Fatalf("probe candidate %s on shared port %d failed: status=%q error=%q summary=%q",
				sp.ID, pl.Port, res.Status, res.Error, res.Summary)
		}
	}
}
