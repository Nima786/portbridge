package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func reserveFreeTCPAndUDPPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 32; i++ {
		tln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := tln.Addr().(*net.TCPAddr).Port
		uln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		if err != nil {
			_ = tln.Close()
			continue
		}
		_ = uln.Close()
		_ = tln.Close()
		return port
	}
	t.Fatal("could not reserve a free TCP+UDP port")
	return 0
}

func reserveFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestAsymmetricEndToEndTunnelAndSpeedtest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Start a local TCP echo backend service on the Foreign (Origin) side.
	svcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend Listen: %v", err)
	}
	defer svcLn.Close()
	go func() {
		for {
			c, err := svcLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	dir := t.TempDir()
	rawSecret := make([]byte, 32)
	_, _ = rand.Read(rawSecret)
	secretB64 := base64.StdEncoding.EncodeToString(rawSecret)
	secretFile := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(secretFile, []byte(secretB64+"\n"), 0600); err != nil {
		t.Fatalf("writing secret file: %v", err)
	}

	originPort := reserveFreeTCPPort(t)
	asymDownPort := reserveFreeTCPAndUDPPort(t)
	userPort := reserveFreeTCPPort(t)
	originAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort))
	userAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(userPort))

	originConfPath := filepath.Join(dir, "asym-origin.conf")
	originConf := fmt.Sprintf(`name = asym-test-origin
mode = direct
role = origin
transport = xhttp
asymmetric = on
asym_uplink = xhttp
asym_downlink = kcp-hop
asym_down_port = %d
peer_ip = 127.0.0.1
server_name = www.bing.com
ws_path = /api/v1/asymtest
mux = on
mux_links = 2
tunnel_addr = %s
inbound_addr = %s
cert_file = %s
key_file = %s
secret_file = %s
`, asymDownPort, originAddr, svcLn.Addr().String(),
		filepath.Join(dir, "origin-cert.pem"), filepath.Join(dir, "origin-key.pem"), secretFile)
	if err := os.WriteFile(originConfPath, []byte(originConf), 0600); err != nil {
		t.Fatalf("writing origin conf: %v", err)
	}
	originCfg, err := LoadConfig(originConfPath)
	if err != nil {
		t.Fatalf("LoadConfig(origin): %v", err)
	}
	originCfg.StatusFile = ""
	if err := originCfg.Validate(); err != nil {
		t.Fatalf("originCfg.Validate: %v", err)
	}
	if err := originCfg.LoadSecret(); err != nil {
		t.Fatalf("originCfg.LoadSecret: %v", err)
	}

	edgeConfPath := filepath.Join(dir, "asym-edge.conf")
	edgeConf := fmt.Sprintf(`name = asym-test-edge
mode = direct
role = edge
transport = xhttp
asymmetric = on
asym_uplink = xhttp
asym_downlink = kcp-hop
asym_down_port = %d
peer_ip = 127.0.0.1
server_name = www.bing.com
ws_path = /api/v1/asymtest
utls = on
tls_fragment = on
mux = on
mux_links = 2
path_probe = off
tunnel_addr = %s
user_listen = %s
cert_file = %s
key_file = %s
secret_file = %s
`, asymDownPort, originAddr, userAddr,
		filepath.Join(dir, "edge-cert.pem"), filepath.Join(dir, "edge-key.pem"), secretFile)
	if err := os.WriteFile(edgeConfPath, []byte(edgeConf), 0600); err != nil {
		t.Fatalf("writing edge conf: %v", err)
	}
	edgeCfg, err := LoadConfig(edgeConfPath)
	if err != nil {
		t.Fatalf("LoadConfig(edge): %v", err)
	}
	edgeCfg.StatusFile = ""
	if err := edgeCfg.Validate(); err != nil {
		t.Fatalf("edgeCfg.Validate: %v", err)
	}
	if err := edgeCfg.LoadSecret(); err != nil {
		t.Fatalf("edgeCfg.LoadSecret: %v", err)
	}

	originDone := make(chan error, 1)
	go func() {
		originDone <- runOrigin(ctx, originCfg, newStatus(originCfg))
	}()

	// Wait briefly for Origin TCP listener to come up.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", originCfg.TunnelAddr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	edgeCtx, cancelEdge := context.WithCancel(ctx)
	defer cancelEdge()
	edgeDone := make(chan error, 1)
	go func() {
		edgeDone <- runEdge(edgeCtx, edgeCfg, newStatus(edgeCfg))
	}()

	// Wait for Edge user listener + Asymmetric Mux carrier link to come up.
	ready := false
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", userAddr, 200*time.Millisecond)
		if err != nil {
			time.Sleep(40 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		ping := []byte("asym-warmup")
		_, wErr := c.Write(ping)
		got := make([]byte, len(ping))
		_, rErr := io.ReadFull(c, got)
		_ = c.Close()
		if wErr == nil && rErr == nil && bytes.Equal(got, ping) {
			ready = true
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Asymmetric tunnel (XHTTP uplink + KCP-Hop reverse downlink) did not become ready in time")
	}

	// 2. Run 6 concurrent user streams transferring 256 KB each over the asymmetric carrier.
	const numClients = 6
	const payloadLen = 256 * 1024
	var wg sync.WaitGroup
	errCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", userAddr, 5*time.Second)
			if err != nil {
				errCh <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))

			send := make([]byte, payloadLen)
			_, _ = rand.Read(send)
			wantHash := sha256.Sum256(send)

			wDone := make(chan error, 1)
			go func() {
				_, err := c.Write(send)
				wDone <- err
			}()

			recv := make([]byte, payloadLen)
			if _, err := io.ReadFull(c, recv); err != nil {
				errCh <- fmt.Errorf("client %d read: %w", id, err)
				return
			}
			if err := <-wDone; err != nil {
				errCh <- fmt.Errorf("client %d write: %w", id, err)
				return
			}
			if sha256.Sum256(recv) != wantHash {
				errCh <- fmt.Errorf("client %d SHA256 mismatch", id)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// 3. Stop Edge daemon (freeing asymDownPort) while Origin remains up, and verify
	// RunSpeedtest(edgeConfPath, 0.25) spins up its own temporary asymmetric listener
	// and completes the full bidirectional speedtest cleanly.
	cancelEdge()
	<-edgeDone

	stOut, err := RunSpeedtest(edgeConfPath, 0.25)
	if err != nil {
		t.Fatalf("RunSpeedtest(asymmetric): %v\noutput:\n%s", err, stOut)
	}
	if !strings.Contains(stOut, "RTT:") || !strings.Contains(stOut, "Download") {
		t.Fatalf("unexpected speedtest output:\n%s", stOut)
	}

	cancel()
	<-originDone
}

func TestAsymmetricAutomaticTCPTLSFallbackWhenUDPBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret := []byte("0123456789abcdef0123456789abcdef")
	cert := makeXHTTPTestCert(t, "www.bing.com")

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin Listen: %v", err)
	}
	defer originLn.Close()

	downPort := reserveFreeTCPAndUDPPort(t)

	originCfg := DefaultConfig()
	originCfg.Mode = ModeDirect
	originCfg.Role = RoleOrigin
	originCfg.Transport = TransportXHTTP
	originCfg.Asymmetric = true
	originCfg.AsymUplink = "xhttp"
	originCfg.AsymDownlink = "kcp-hop"
	originCfg.AsymDownPort = downPort
	originCfg.PeerIP = "127.0.0.1"
	originCfg.ServerName = "www.bing.com"
	originCfg.WSPath = "/api/v1/asymfb"
	originCfg.Mux = true
	originCfg.secret = secret
	originCfg.prepareTLS(&cert)

	originGuard := newReplayGuard(ctx)
	asymOrigin := newAsymOriginRuntime(ctx, originCfg)

	acceptedCh := make(chan net.Conn, 4)
	go func() {
		for {
			raw, err := originLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				up, err := wrapAccept(c, originCfg, &cert, originGuard)
				if err != nil {
					if !errors.Is(err, errXHTTPUplinkAttached) {
						_ = c.Close()
					}
					return
				}
				paired, err := asymOrigin.PairAcceptedUplink(ctx, up)
				if err != nil {
					_ = up.Close()
					return
				}
				if _, err := recvAuthPurpose(paired, secret, originGuard); err != nil {
					_ = paired.Close()
					return
				}
				acceptedCh <- paired
			}(raw)
		}
	}()

	edgeCfg := DefaultConfig()
	edgeCfg.Mode = ModeDirect
	edgeCfg.Role = RoleEdge
	edgeCfg.Transport = TransportXHTTP
	edgeCfg.Asymmetric = true
	edgeCfg.AsymUplink = "xhttp"
	edgeCfg.AsymDownlink = "kcp-hop"
	edgeCfg.AsymDownPort = downPort
	edgeCfg.PeerIP = "127.0.0.1"
	edgeCfg.ServerName = "www.bing.com"
	edgeCfg.WSPath = "/api/v1/asymfb"
	edgeCfg.TunnelAddr = originLn.Addr().String()
	edgeCfg.Mux = true
	edgeCfg.secret = secret
	edgeCfg.prepareTLS(nil)

	asymEdge, err := newAsymEdgeRuntime(edgeCfg, cert)
	if err != nil {
		t.Fatalf("newAsymEdgeRuntime: %v", err)
	}
	defer asymEdge.Close()

	// Simulate total UDP blackhole on the Relay server by closing both UDP listeners
	// while keeping the TCP TLS fallback listener open on the exact same port!
	_ = asymEdge.kcpLn.Close()
	_ = asymEdge.h3Ln.Close()

	routes := newRouter(edgeCfg)

	// Connection #1: Origin tries UDP KCP-Hop first, hits 3s ACK timeout because UDP is
	// blackholed, and automatically falls back to Reverse TLS over TCP!
	c1, _, err := asymEdge.Dial(ctx, routes, -1, 6*time.Second, authPurposeTunnelMux)
	if err != nil {
		t.Fatalf("asymEdge.Dial #1 (UDP blackholed -> TCP TLS fallback): %v", err)
	}
	defer c1.Close()

	var s1 net.Conn
	select {
	case s1 = <-acceptedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Origin paired connection #1")
	}
	defer s1.Close()

	if asymOrigin.tcpFallbackUntil.Load() <= time.Now().UnixNano() {
		t.Fatal("expected asymOrigin.tcpFallbackUntil to be cached after UDP blackhole fallback")
	}

	// Verify full-duplex payload over the paired XHTTP-Uplink + Reverse-TLS-Downlink connection.
	upMsg := []byte("uplink over XHTTP while UDP is completely blocked!")
	downMsg := []byte("downlink over automatic Reverse TLS TCP fallback!")
	if _, err := c1.Write(upMsg); err != nil {
		t.Fatalf("c1.Write: %v", err)
	}
	gotUp := make([]byte, len(upMsg))
	if _, err := io.ReadFull(s1, gotUp); err != nil {
		t.Fatalf("s1.Read: %v", err)
	}
	if !bytes.Equal(gotUp, upMsg) {
		t.Fatal("uplink payload mismatch")
	}
	if _, err := s1.Write(downMsg); err != nil {
		t.Fatalf("s1.Write: %v", err)
	}
	gotDown := make([]byte, len(downMsg))
	if _, err := io.ReadFull(c1, gotDown); err != nil {
		t.Fatalf("c1.Read: %v", err)
	}
	if !bytes.Equal(gotDown, downMsg) {
		t.Fatal("downlink payload mismatch")
	}

	// Connection #2: Because tcpFallbackUntil is cached for 2 minutes, pairing must
	// go straight to Reverse TLS over TCP without paying the 3s UDP timeout!
	start2 := time.Now()
	c2, _, err := asymEdge.Dial(ctx, routes, -1, 6*time.Second, authPurposeTunnelMux)
	if err != nil {
		t.Fatalf("asymEdge.Dial #2 (cached TCP fallback): %v", err)
	}
	defer c2.Close()
	s2 := <-acceptedCh
	defer s2.Close()
	if elapsed := time.Since(start2); elapsed > 2*time.Second {
		t.Fatalf("expected cached TCP fallback to pair quickly (<2s), took %v", elapsed)
	}
}

func TestFinalizeProbeReportSynthesizesAsymmetricCandidates(t *testing.T) {
	// Direct candidates ran on port 2053, Reverse candidates ran on port 2083,
	// and CDN ran on port 443 (matching Auto-Heal / Smart Finder default ports).
	raw := []ProbeCandidateResult{
		{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:         "direct-xhttp",
				Label:      "Direct · SplitHTTP / XHTTP Stream",
				Mode:       "direct",
				Link:       "xhttp",
				Transport:  "xhttp",
				Stealth:    true,
				Shared:     true,
				ServerName: "www.bing.com",
				TargetAddr: "5.6.7.8:2053",
				Port:       2053,
			},
			Status:      "ok",
			Attempts:    2,
			Successes:   2,
			HandshakeMS: 45,
			RTTMS:       42,
			JitterMS:    3,
			DownMbps:    25, // Direct download throttled
			UpMbps:      95, // Direct upload fast
			AvgMbps:     60,
		},
		{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:         "direct-cdn-xhttp",
				Label:      "Direct · SplitHTTP / XHTTP via CDN",
				Mode:       "direct",
				Link:       "xhttp-cdn",
				Transport:  "xhttp",
				CDN:        true,
				Shared:     true,
				ServerName: "cdn.example.com",
				Domain:     "cdn.example.com",
				TargetAddr: "cdn.example.com:443",
				Port:       443,
			},
			Status:      "ok",
			Attempts:    2,
			Successes:   2,
			HandshakeMS: 90,
			RTTMS:       70,
			JitterMS:    6,
			DownMbps:    35,
			UpMbps:      55,
			AvgMbps:     45,
		},
		{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:         "reverse-kcp-hop",
				Label:      "Reverse · KCP Port-Hopping UDP",
				Mode:       "reverse",
				Link:       "kcp-hop",
				Transport:  "kcp",
				PortHop:    true,
				Shared:     true,
				TargetAddr: "1.2.3.4:2083",
				Port:       2083,
			},
			Status:      "ok",
			Attempts:    2,
			Successes:   2,
			HandshakeMS: 38,
			RTTMS:       40,
			JitterMS:    2,
			DownMbps:    140, // Reverse UDP download fast!
			UpMbps:      30,
			AvgMbps:     85,
		},
	}

	report := FinalizeProbeReport(raw, "cdn.example.com")
	if report == nil {
		t.Fatal("FinalizeProbeReport returned nil")
	}

	var foundDirectAsym, foundCDNAsym *ProbeCandidateResult
	for i := range report.Results {
		r := &report.Results[i]
		switch r.ID {
		case "direct-asymmetric":
			foundDirectAsym = r
		case "direct-asymmetric-cdn":
			foundCDNAsym = r
		}
	}

	if foundDirectAsym == nil {
		t.Fatal("expected FinalizeProbeReport to synthesize direct-asymmetric even when Direct port (2053) != Reverse port (2083)")
	}
	if !foundDirectAsym.Asymmetric || foundDirectAsym.AsymUplink != "xhttp" || foundDirectAsym.AsymDownlink != "kcp-hop" {
		t.Fatalf("unexpected direct-asymmetric fields: %+v", foundDirectAsym)
	}
	if foundDirectAsym.DownMbps != 140 || foundDirectAsym.UpMbps != 95 {
		t.Fatalf("expected direct-asymmetric to combine Reverse DownMbps (140) + Direct UpMbps (95), got %.1f / %.1f",
			foundDirectAsym.DownMbps, foundDirectAsym.UpMbps)
	}

	if foundCDNAsym == nil {
		t.Fatal("expected FinalizeProbeReport to synthesize direct-asymmetric-cdn")
	}
	if !foundCDNAsym.Asymmetric || !foundCDNAsym.CDN || foundCDNAsym.AsymUplink != "xhttp" || foundCDNAsym.AsymDownlink != "kcp-hop" {
		t.Fatalf("unexpected direct-asymmetric-cdn fields: %+v", foundCDNAsym)
	}
}
