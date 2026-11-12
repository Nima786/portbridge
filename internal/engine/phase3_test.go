package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTwinSeqWindowSlidingBitmap(t *testing.T) {
	var w twinSeqWindow
	if w.Accept(0) {
		t.Fatal("seq 0 must never be accepted as data")
	}
	if !w.Accept(10) {
		t.Fatal("initial seq 10 should be accepted")
	}
	if w.Accept(10) {
		t.Fatal("duplicate seq 10 must be rejected")
	}

	// Out-of-order earlier sequences within window.
	for _, s := range []uint32{9, 1, 5, 8} {
		if !w.Accept(s) {
			t.Fatalf("earlier unseen seq %d should be accepted", s)
		}
		if w.Accept(s) {
			t.Fatalf("duplicate earlier seq %d must be rejected", s)
		}
	}

	// Advance across 64-bit word boundaries (1, 63, 64, 65, 500).
	for _, step := range []uint32{11, 74, 138, 203, 703} {
		if !w.Accept(step) {
			t.Fatalf("advancing seq %d should be accepted", step)
		}
	}
	// Previously seen 203 (500 behind 703) must still be remembered!
	if w.Accept(203) {
		t.Fatal("seq 203 should still be marked seen after 500-bit shift")
	}
	// Unseen 204 (499 behind 703) must be accepted once!
	if !w.Accept(204) {
		t.Fatal("unseen seq 204 within 2048 window should be accepted")
	}
	if w.Accept(204) {
		t.Fatal("duplicate seq 204 must be rejected")
	}

	// Advance past 2048 window: seq 3000 makes seq 703 (2297 behind) stale.
	if !w.Accept(3000) {
		t.Fatal("seq 3000 should be accepted")
	}
	if w.Accept(703) {
		t.Fatal("stale seq 703 (>2048 behind 3000) must be rejected")
	}
	// Exact boundary: 3000 - 2047 = 953 is inside window; 3000 - 2048 = 952 is outside.
	if w.Accept(952) {
		t.Fatal("seq 952 (exact 2048 behind) must be rejected")
	}
	if !w.Accept(953) {
		t.Fatal("seq 953 (2047 behind) should be accepted")
	}

	// uint32 wrap-around across 0xffffffff -> 1.
	var wrapW twinSeqWindow
	for _, s := range []uint32{0xfffffffe, 0xffffffff, 1, 2} {
		if !wrapW.Accept(s) {
			t.Fatalf("wrap-around seq 0x%x should be accepted", s)
		}
		if wrapW.Accept(s) {
			t.Fatalf("duplicate wrap-around seq 0x%x must be rejected", s)
		}
	}
	if !wrapW.Accept(0xfffffffd) {
		t.Fatal("unseen pre-wrap seq 0xfffffffd within window should be accepted")
	}
}

func TestTwinPathDuplicationBlackoutAndFallback(t *testing.T) {
	psk := []byte("phase3-twinpath-secret-key-32byt")

	// 1. Two copies of the same packet have zero identical header bytes and tamper fails.
	keys := deriveTwinPathKeys(psk)
	var sid [8]byte
	_, _ = rand.Read(sid[:])
	payload := []byte("gaming-tick-payload")
	p1, err := encodeTwinPathPacket(nil, &keys, sid, 42, payload)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := encodeTwinPathPacket(nil, &keys, sid, 42, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p1[:twinHeaderSize], p2[:twinHeaderSize]) {
		t.Fatal("two Twin-Path copies shared identical wire headers")
	}
	tampered := append([]byte(nil), p1...)
	tampered[10] ^= 0x01
	if _, _, _, ok := decodeTwinPathPacket(tampered, &keys); ok {
		t.Fatal("tampered Twin-Path packet passed HMAC verification")
	}

	// 2. Dual-port TwinPath survives complete loss of primary leg and deduplicates cleanly.
	lnRaw, err := ListenTwinPath(0, 2, psk)
	if err != nil {
		t.Fatal(err)
	}
	defer lnRaw.Close()
	ln := lnRaw.(*TwinPathListenConn)
	basePort := ln.LocalAddr().(*net.UDPAddr).Port

	dialConn, err := DialTwinPath("127.0.0.1", basePort, 2, psk)
	if err != nil {
		t.Fatal(err)
	}
	defer dialConn.Close()

	// Send 50 latency-sensitive packets; verify exact 1-to-1 delivery with zero duplicates.
	rxDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		for i := 0; i < 50; i++ {
			_ = ln.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, rerr := ln.ReadFrom(buf)
			if rerr != nil {
				rxDone <- fmt.Errorf("read %d: %w", i, rerr)
				return
			}
			want := fmt.Sprintf("pkt-%03d", i)
			if string(buf[:n]) != want {
				rxDone <- fmt.Errorf("got %q, want %q", string(buf[:n]), want)
				return
			}
			if _, werr := ln.WriteTo([]byte("ack-"+want), addr); werr != nil {
				rxDone <- fmt.Errorf("write %d: %w", i, werr)
				return
			}
		}
		rxDone <- nil
	}()

	ackBuf := make([]byte, 1500)
	for i := 0; i < 50; i++ {
		if i == 25 {
			// Kill Leg 0 local socket mid-flight! Leg 1 must carry packets 25..49 seamlessly!
			dialConn.mu.RLock()
			l0 := dialConn.legs[0]
			dialConn.mu.RUnlock()
			if l0 != nil {
				_ = l0.sock.Close()
			}
		}
		msg := []byte(fmt.Sprintf("pkt-%03d", i))
		if _, err := dialConn.WriteTo(msg, dialConn.RemoteAddr()); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
		_ = dialConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := dialConn.ReadFrom(ackBuf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if string(ackBuf[:n]) != "ack-"+string(msg) {
			t.Fatalf("unexpected ack %q", string(ackBuf[:n]))
		}
	}
	if err := <-rxDone; err != nil {
		t.Fatal(err)
	}
}

func TestWebRTCSTUNAndSRTPWireCompliance(t *testing.T) {
	psk := []byte("phase3-webrtc-secret-key-32bytes")
	keys := deriveWebRTCKeys(psk)
	wrongKeys := deriveWebRTCKeys([]byte("wrong-secret-key-for-active-prob"))

	var sid [8]byte
	_, _ = rand.Read(sid[:])

	// 1. RFC 5389 STUN Binding Request wire format & CRC32 FINGERPRINT check.
	req, txID, err := buildSTUNBindingRequest(&keys, sid)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(req[0:2]) != 0x0001 || binary.BigEndian.Uint32(req[4:8]) != 0x2112A442 {
		t.Fatalf("invalid RFC 5389 STUN header: %x", req[:8])
	}
	fpOff := len(req) - 8
	if (crc32.ChecksumIEEE(req[:fpOff]) ^ 0x5354554e) != binary.BigEndian.Uint32(req[fpOff+4:fpOff+8]) {
		t.Fatal("STUN FINGERPRINT does not match RFC 5389 §15.5")
	}
	gotTx, gotSID, ok := parseAndVerifySTUNBindingRequest(req, &keys)
	if !ok || gotTx != txID || gotSID != sid {
		t.Fatalf("valid STUN request rejected: ok=%v gotSID=%x want=%x", ok, gotSID, sid)
	}
	if _, _, ok := parseAndVerifySTUNBindingRequest(req, &wrongKeys); ok {
		t.Fatal("STUN request verified under wrong PSK")
	}

	// 2. IPv4 and IPv6 STUN Binding Success Responses.
	for _, peer := range []net.Addr{
		&net.UDPAddr{IP: net.ParseIP("203.0.113.42"), Port: 54321},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::42"), Port: 54321},
	} {
		resp := buildSTUNBindingResponse(&keys, txID, peer)
		if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 {
			t.Fatalf("expected 0x0101 Binding Success Response, got 0x%04x", binary.BigEndian.Uint16(resp[0:2]))
		}
		if !parseAndVerifySTUNBindingResponse(resp, &keys) {
			t.Fatalf("STUN response failed verification for peer %v", peer)
		}
		if parseAndVerifySTUNBindingResponse(resp, &wrongKeys) {
			t.Fatal("STUN response verified under wrong PSK")
		}
	}

	// 3. SRTP v2 Opus (<=240B) and VP8 (>240B) framing & constant-time auth.
	clk := newRTPStreamClock()
	smallPayload := bytes.Repeat([]byte{0xaa}, 120)
	srtpSmall, err := encodeWebRTCSRTP(nil, &keys, clk, sid, 1, smallPayload)
	if err != nil {
		t.Fatal(err)
	}
	if srtpSmall[0] != 0x80 || (srtpSmall[1]&0x7f) != rtpPTOpus {
		t.Fatalf("expected RTP v2 Opus PT 111 for small frame, got %02x %02x", srtpSmall[0], srtpSmall[1])
	}
	largePayload := bytes.Repeat([]byte{0xbb}, 800)
	srtpLarge, err := encodeWebRTCSRTP(nil, &keys, clk, sid, 2, largePayload)
	if err != nil {
		t.Fatal(err)
	}
	if srtpLarge[0] != 0x80 || (srtpLarge[1]&0x7f) != rtpPTVP8 {
		t.Fatalf("expected RTP v2 VP8 PT 96 for video-sized frame, got %02x %02x", srtpLarge[0], srtpLarge[1])
	}
	decSID, decSeq, decPay, ok := decodeWebRTCSRTP(srtpLarge, &keys)
	if !ok || decSID != sid || decSeq != 2 || !bytes.Equal(decPay, largePayload) {
		t.Fatalf("SRTP decode mismatch: ok=%v seq=%d", ok, decSeq)
	}
	if _, _, _, ok := decodeWebRTCSRTP(srtpLarge, &wrongKeys); ok {
		t.Fatal("SRTP verified under wrong PSK")
	}
}

func TestPhase3FullTunnelEndToEndAndProbe(t *testing.T) {
	// Start local echo service representing the published origin backend.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	runCase := func(t *testing.T, name string, extraEdge, extraOrigin string) {
		t.Helper()
		dir := t.TempDir()
		secPath := filepath.Join(dir, "secret.key")
		if err := os.WriteFile(secPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
			t.Fatal(err)
		}

		// Reserve free UDP+TCP bridge port and user listen port.
		tPort := reserveFreePort(t)
		uPort := reserveFreePort(t)

		mode := "direct"
		edgeTunAddr := fmt.Sprintf("127.0.0.1:%d", tPort)
		origTunAddr := fmt.Sprintf("127.0.0.1:%d", tPort)
		if bytes.Contains([]byte(extraEdge), []byte("mode = reverse")) {
			mode = "reverse"
		}
		_ = mode

		edgeConfPath := filepath.Join(dir, "edge.conf")
		origConfPath := filepath.Join(dir, "origin.conf")

		baseEdge := fmt.Sprintf(`name = %s
role = edge
user_listen = 127.0.0.1:%d
tunnel_addr = %s
secret_file = %s
status_file = %s
mux = on
mux_links = 1
drain = 100ms
path_probe = off
%s
`, name, uPort, edgeTunAddr, secPath, filepath.Join(dir, "edge.json"), extraEdge)

		baseOrig := fmt.Sprintf(`name = %s
role = origin
inbound_addr = %s
tunnel_addr = %s
secret_file = %s
status_file = %s
mux = on
mux_links = 1
drain = 100ms
path_probe = off
%s
`, name, backendAddr, origTunAddr, secPath, filepath.Join(dir, "orig.json"), extraOrigin)

		if err := os.WriteFile(edgeConfPath, []byte(baseEdge), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(origConfPath, []byte(baseOrig), 0o600); err != nil {
			t.Fatal(err)
		}

		edgeCfg, err := LoadConfig(edgeConfPath)
		if err != nil {
			t.Fatalf("LoadConfig edge: %v", err)
		}
		if err := edgeCfg.Validate(); err != nil {
			t.Fatalf("Validate edge: %v", err)
		}
		if err := edgeCfg.LoadSecret(); err != nil {
			t.Fatal(err)
		}

		origCfg, err := LoadConfig(origConfPath)
		if err != nil {
			t.Fatalf("LoadConfig origin: %v", err)
		}
		if err := origCfg.Validate(); err != nil {
			t.Fatalf("Validate origin: %v", err)
		}
		if err := origCfg.LoadSecret(); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = runOrigin(ctx, origCfg, newStatus(origCfg))
		}()
		go func() {
			defer wg.Done()
			_ = runEdge(ctx, edgeCfg, newStatus(edgeCfg))
		}()
		defer func() {
			cancel()
			wg.Wait()
		}()

		userAddr := fmt.Sprintf("127.0.0.1:%d", uPort)
		payload := bytes.Repeat([]byte("Phase3-WebRTC-TwinPath-Verify!"), 200) // 6000 bytes
		var lastErr error
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", userAddr, time.Second)
			if err != nil {
				lastErr = err
				time.Sleep(80 * time.Millisecond)
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				_ = conn.Close()
				lastErr = err
				time.Sleep(80 * time.Millisecond)
				continue
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				_ = conn.Close()
				lastErr = err
				time.Sleep(80 * time.Millisecond)
				continue
			}
			_ = conn.Close()
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s payload mismatch", name)
			}
			lastErr = nil
			break
		}
		if lastErr != nil {
			t.Fatalf("%s failed to pass traffic: %v", name, lastErr)
		}
	}

	t.Run("direct-webrtc", func(t *testing.T) {
		runCase(t, "wrtc1", "mode = direct\ntransport = webrtc", "mode = direct\ntransport = webrtc")
	})
	t.Run("reverse-webrtc-porthop", func(t *testing.T) {
		runCase(t, "wrtc2",
			"mode = reverse\ntransport = webrtc\nport_hop = on\nport_hop_ports = 4",
			"mode = reverse\ntransport = webrtc\nport_hop = on\nport_hop_ports = 4\nport_hop_interval = 200ms")
	})
	t.Run("direct-twinpath-gaming", func(t *testing.T) {
		runCase(t, "twin1",
			"mode = direct\ntransport = kcp\ntwin_path = on",
			"mode = direct\ntransport = kcp\ntwin_path = on")
	})
	t.Run("direct-webrtc-twinpath", func(t *testing.T) {
		runCase(t, "wt1",
			"mode = direct\ntransport = webrtc\ntwin_path = on",
			"mode = direct\ntransport = webrtc\ntwin_path = on")
	})
	t.Run("asymmetric-webrtc-downlink", func(t *testing.T) {
		dp := reserveFreePort(t)
		cfgStr := fmt.Sprintf("mode = direct\nasymmetric = on\nasym_uplink = xhttp\nasym_downlink = webrtc\nasym_down_port = %d\nserver_name = www.bing.com\ncert_file = %s\nkey_file = %s",
			dp, filepath.Join(t.TempDir(), "c.pem"), filepath.Join(t.TempDir(), "k.pem"))
		runCase(t, "asymwrtc", cfgStr, cfgStr)
	})

	// Verify ProbeListener serves both direct-webrtc and direct-twin on the shared probe port!
	t.Run("probe-webrtc-and-twin", func(t *testing.T) {
		secret := []byte("probe-phase3-secret-32-bytes-key")
		pl, err := StartProbeListener("127.0.0.1", 0, secret, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer pl.Close()

		target := fmt.Sprintf("127.0.0.1:%d", pl.Port)
		specs := []ProbeCandidateSpec{
			{
				ID: "direct-webrtc", Label: "Direct WebRTC", Mode: "direct",
				Link: "webrtc", Transport: string(TransportWebRTC), Shared: true,
				TargetAddr: target, Port: pl.Port,
			},
			{
				ID: "direct-twin", Label: "Direct Twin-Path", Mode: "direct",
				Link: "twin", Transport: string(TransportKCP), TwinPath: true, Shared: true,
				Gaming: true, TargetAddr: target, Port: pl.Port,
			},
		}
		results := RunProbeDialer(context.Background(), specs, secret, 64*1024)
		if len(results) != 2 {
			t.Fatalf("expected 2 probe results, got %d", len(results))
		}
		for _, r := range results {
			if r.Status != "ok" {
				t.Fatalf("probe %s failed on shared ProbeListener: status=%s err=%s", r.ID, r.Status, r.Error)
			}
		}
	})
}

func reserveFreePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		// Also verify port and port+1..port+3 UDP are free for multi-port tests.
		ok := true
		for p := port; p < port+4 && p <= 65535; p++ {
			u, uerr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
			if uerr != nil {
				ok = false
				break
			}
			_ = u.Close()
		}
		if ok {
			return port
		}
	}
	t.Fatal("could not reserve free 4-port block")
	return 0
}
