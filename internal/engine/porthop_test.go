package engine

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

func TestPortHopPacketWireFormat(t *testing.T) {
	psk := []byte("0123456789abcdef-super-secret-psk")
	keys := derivePortHopKeys(psk)
	wrongKeys := derivePortHopKeys([]byte("different-pre-shared-key-value!!"))

	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello kcp fec payload over port hopping")

	pkt1, err := encodePortHopPacket(nil, &keys, sid, payload)
	if err != nil {
		t.Fatalf("encodePortHopPacket: %v", err)
	}
	if len(pkt1) != portHopHeaderSize+len(payload) {
		t.Fatalf("expected packet length %d, got %d", portHopHeaderSize+len(payload), len(pkt1))
	}

	pkt2, err := encodePortHopPacket(nil, &keys, sid, payload)
	if err != nil {
		t.Fatalf("encodePortHopPacket #2: %v", err)
	}
	if bytes.Equal(pkt1[:portHopHeaderSize], pkt2[:portHopHeaderSize]) {
		t.Fatal("two encoded headers for identical session+payload should differ due to random 4B salt")
	}
	if bytes.Equal(pkt1[4:12], sid[:]) {
		t.Fatal("raw sessionID must be XOR-masked on the wire")
	}

	gotSID, gotPayload, ok := decodePortHopPacket(pkt1, &keys)
	if !ok {
		t.Fatal("valid packet failed authentication")
	}
	if gotSID != sid {
		t.Fatalf("decoded sessionID %x != %x", gotSID, sid)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decoded payload mismatch")
	}

	// Wrong PSK must fail authentication.
	if _, _, ok := decodePortHopPacket(pkt1, &wrongKeys); ok {
		t.Fatal("packet decoded with wrong PSK")
	}

	// Any bit flip in salt, masked sessionID, auth tag, or payload must fail.
	for _, idx := range []int{0, 3, 5, 11, 12, 15, 16, len(pkt1) - 1} {
		corrupt := append([]byte(nil), pkt1...)
		corrupt[idx] ^= 0x01
		if _, _, ok := decodePortHopPacket(corrupt, &keys); ok {
			t.Fatalf("tampered byte at index %d was accepted", idx)
		}
	}

	// Truncated packet (< 16B) must fail cleanly.
	if _, _, ok := decodePortHopPacket(pkt1[:15], &keys); ok {
		t.Fatal("truncated packet <16B was accepted")
	}
}

func TestPortHopSilentDiscardAndSymmetricNATRouting(t *testing.T) {
	psk := []byte("symmetric-nat-test-shared-secret")
	ln, err := ListenPortHopAddr("127.0.0.1:0", 4, psk)
	if err != nil {
		t.Fatalf("ListenPortHopAddr: %v", err)
	}
	defer ln.Close()

	ports := ln.BoundPorts()
	if len(ports) < 2 {
		t.Fatalf("expected at least 2 bound UDP ports, got %v", ports)
	}

	// Send unauthenticated / malformed garbage to primary and companion ports;
	// listener must silently discard them.
	stranger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()

	for _, p := range ports {
		dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}
		_, _ = stranger.WriteToUDP([]byte("short"), dst)
		_, _ = stranger.WriteToUDP(bytes.Repeat([]byte{0xab}, 48), dst)
	}

	_ = ln.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	buf := make([]byte, 256)
	if n, _, err := ln.ReadFrom(buf); err == nil {
		t.Fatalf("expected timeout after stray packets, got %d bytes", n)
	}
	_ = ln.SetReadDeadline(time.Time{})

	// Now simulate one logical client session hopping across two different local
	// ephemeral sockets AND two different server destination ports.
	keys := derivePortHopKeys(psk)
	sid := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	clientSockA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSockA.Close()

	clientSockB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSockB.Close()

	// Hop 1: clientSockA -> server ports[0]
	pktA, _ := encodePortHopPacket(nil, &keys, sid, []byte("msg-1"))
	if _, err := clientSockA.WriteToUDP(pktA, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ports[0]}); err != nil {
		t.Fatal(err)
	}
	n1, vaddr1, err := ln.ReadFrom(buf)
	if err != nil || string(buf[:n1]) != "msg-1" {
		t.Fatalf("ReadFrom #1: n=%d err=%v", n1, err)
	}

	// Reply 1 must arrive on clientSockA from server ports[0].
	if _, err := ln.WriteTo([]byte("ack-1"), vaddr1); err != nil {
		t.Fatal(err)
	}
	_ = clientSockA.SetReadDeadline(time.Now().Add(time.Second))
	rn1, from1, err := clientSockA.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("clientSockA ReadFromUDP: %v", err)
	}
	if from1.Port != ports[0] {
		t.Fatalf("expected reply #1 from server port %d, got %d", ports[0], from1.Port)
	}
	if _, pay1, ok := decodePortHopPacket(buf[:rn1], &keys); !ok || string(pay1) != "ack-1" {
		t.Fatalf("unexpected reply #1 payload: ok=%v pay=%q", ok, pay1)
	}

	// Hop 2: clientSockB -> server ports[len(ports)-1] (both srcPort and dstPort changed!)
	lastServerPort := ports[len(ports)-1]
	pktB, _ := encodePortHopPacket(nil, &keys, sid, []byte("msg-2"))
	if _, err := clientSockB.WriteToUDP(pktB, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: lastServerPort}); err != nil {
		t.Fatal(err)
	}
	n2, vaddr2, err := ln.ReadFrom(buf)
	if err != nil || string(buf[:n2]) != "msg-2" {
		t.Fatalf("ReadFrom #2: n=%d err=%v", n2, err)
	}
	if vaddr1.String() != vaddr2.String() {
		t.Fatalf("logical session address changed across port hop: %s vs %s", vaddr1, vaddr2)
	}

	// Reply 2 must arrive on clientSockB from lastServerPort (symmetric routing!).
	if _, err := ln.WriteTo([]byte("ack-2"), vaddr2); err != nil {
		t.Fatal(err)
	}
	_ = clientSockB.SetReadDeadline(time.Now().Add(time.Second))
	rn2, from2, err := clientSockB.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("clientSockB ReadFromUDP: %v", err)
	}
	if from2.Port != lastServerPort {
		t.Fatalf("expected symmetric reply #2 from server port %d, got %d", lastServerPort, from2.Port)
	}
	if _, pay2, ok := decodePortHopPacket(buf[:rn2], &keys); !ok || string(pay2) != "ack-2" {
		t.Fatalf("unexpected reply #2 payload: ok=%v pay=%q", ok, pay2)
	}
}

func TestPortHopLiveKCPSessionRotationZeroDrop(t *testing.T) {
	psk := []byte("live-kcp-port-hop-zero-drop-test-psk")
	serverPC, err := ListenPortHopAddr("127.0.0.1:0", DefaultPortHopPorts, psk)
	if err != nil {
		t.Fatalf("ListenPortHopAddr: %v", err)
	}
	defer serverPC.Close()

	basePort := serverPC.LocalAddr().(*net.UDPAddr).Port
	key := sha256.Sum256(psk)
	serverBlock, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		t.Fatal(err)
	}
	kcpLn, err := kcp.ServeConn(serverBlock, 10, 3, serverPC)
	if err != nil {
		t.Fatal(err)
	}
	defer kcpLn.Close()

	const payloadSize = 512 * 1024
	wantClientToServer := make([]byte, payloadSize)
	wantServerToClient := make([]byte, payloadSize)
	_, _ = rand.Read(wantClientToServer)
	_, _ = rand.Read(wantServerToClient)

	serverErrCh := make(chan error, 1)
	go func() {
		sess, err := kcpLn.AcceptKCP()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer sess.Close()
		sess.SetStreamMode(true)
		sess.SetWriteDelay(false)
		sess.SetNoDelay(1, 10, 2, 1)
		sess.SetWindowSize(1024, 1024)
		sess.SetMtu(1360)

		var wg sync.WaitGroup
		var writeErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Pace writes slightly so multiple 75ms port hops occur mid-stream.
			for off := 0; off < len(wantServerToClient); off += 32 * 1024 {
				end := off + 32*1024
				if end > len(wantServerToClient) {
					end = len(wantServerToClient)
				}
				if _, err := sess.Write(wantServerToClient[off:end]); err != nil {
					writeErr = err
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
		}()

		got := make([]byte, payloadSize)
		_, readErr := io.ReadFull(sess, got)
		wg.Wait()
		if readErr != nil {
			serverErrCh <- readErr
			return
		}
		if writeErr != nil {
			serverErrCh <- writeErr
			return
		}
		if !bytes.Equal(got, wantClientToServer) {
			serverErrCh <- io.ErrUnexpectedEOF
			return
		}
		serverErrCh <- nil
	}()

	clientPC, err := DialPortHopWithConfig("127.0.0.1", basePort, DefaultPortHopPorts, psk, PortHopDialConfig{
		HopInterval: 75 * time.Millisecond,
		DrainWindow: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DialPortHopWithConfig: %v", err)
	}
	defer clientPC.Close()

	clientBlock, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		t.Fatal(err)
	}
	clientSess, err := kcp.NewConn2(clientPC.RemoteAddr(), clientBlock, 10, 3, clientPC)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()
	clientSess.SetStreamMode(true)
	clientSess.SetWriteDelay(false)
	clientSess.SetNoDelay(1, 10, 2, 1)
	clientSess.SetWindowSize(1024, 1024)
	clientSess.SetMtu(1360)
	_ = clientSess.SetDeadline(time.Now().Add(15 * time.Second))

	var cwg sync.WaitGroup
	var cWriteErr error
	cwg.Add(1)
	go func() {
		defer cwg.Done()
		for off := 0; off < len(wantClientToServer); off += 32 * 1024 {
			end := off + 32*1024
			if end > len(wantClientToServer) {
				end = len(wantClientToServer)
			}
			if _, err := clientSess.Write(wantClientToServer[off:end]); err != nil {
				cWriteErr = err
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	gotFromServer := make([]byte, payloadSize)
	if _, err := io.ReadFull(clientSess, gotFromServer); err != nil {
		t.Fatalf("client ReadFull: %v", err)
	}
	cwg.Wait()
	if cWriteErr != nil {
		t.Fatalf("client Write: %v", cWriteErr)
	}
	if !bytes.Equal(gotFromServer, wantServerToClient) {
		t.Fatal("server->client stream corrupted across port hops")
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server session failed: %v", err)
	}
	if hops := clientPC.HopCount(); hops < 4 {
		t.Fatalf("expected at least 4 live socket+port rotations during transfer, got %d", hops)
	}
	if clientPC.FallbackLocked() {
		t.Fatal("did not expect fallback lock when companion ports were bound")
	}
}

func TestPortHopFallbackToBasePortWhenHoppedPortsBlocked(t *testing.T) {
	psk := []byte("cloud-firewall-single-port-fallback-psk")
	// Bind ONLY 1 port on the server (simulating AWS/Oracle security rules that
	// only opened basePort while blocking basePort+1..basePort+7).
	serverPC, err := ListenPortHopAddr("127.0.0.1:0", 1, psk)
	if err != nil {
		t.Fatal(err)
	}
	defer serverPC.Close()

	basePort := serverPC.LocalAddr().(*net.UDPAddr).Port
	key := sha256.Sum256(psk)
	serverBlock, _ := kcp.NewAESBlockCrypt(key[:16])
	kcpLn, err := kcp.ServeConn(serverBlock, 10, 3, serverPC)
	if err != nil {
		t.Fatal(err)
	}
	defer kcpLn.Close()

	go func() {
		sess, err := kcpLn.AcceptKCP()
		if err != nil {
			return
		}
		defer sess.Close()
		sess.SetStreamMode(true)
		sess.SetWriteDelay(false)
		sess.SetNoDelay(1, 10, 2, 1)
		sess.SetMtu(1360)
		_, _ = io.Copy(sess, sess)
	}()

	clientPC, err := DialPortHopWithConfig("127.0.0.1", basePort, 8, psk, PortHopDialConfig{
		HopInterval:  90 * time.Millisecond,
		DrainWindow:  300 * time.Millisecond,
		FallbackWait: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientPC.Close()

	clientBlock, _ := kcp.NewAESBlockCrypt(key[:16])
	sess, err := kcp.NewConn2(clientPC.RemoteAddr(), clientBlock, 10, 3, clientPC)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetMtu(1360)
	_ = sess.SetDeadline(time.Now().Add(10 * time.Second))

	// Exchange data across several rotation cycles so hop #1 tries basePort+1,
	// detects unreachable companion ports, locks dstPort back to basePort, and
	// continues rotating local srcPort on subsequent hops.
	for i := 0; i < 6; i++ {
		msg := make([]byte, 8192)
		_, _ = rand.Read(msg)
		if _, err := sess.Write(msg); err != nil {
			t.Fatalf("iter %d Write: %v", i, err)
		}
		echo := make([]byte, len(msg))
		if _, err := io.ReadFull(sess, echo); err != nil {
			t.Fatalf("iter %d ReadFull: %v", i, err)
		}
		if !bytes.Equal(echo, msg) {
			t.Fatalf("iter %d echo mismatch", i)
		}
		time.Sleep(80 * time.Millisecond)
	}

	if !clientPC.FallbackLocked() {
		t.Fatal("expected FallbackLocked() == true when companion server ports are closed")
	}
	if clientPC.HopCount() < 3 {
		t.Fatalf("expected local srcPort rotation to continue in fallback mode, HopCount=%d", clientPC.HopCount())
	}
}

func TestPortHopFirewallHelpers(t *testing.T) {
	tool, rules, err := BuildPortHopIPTablesRules("185.42.214.20", 7465, 8, "sess_01")
	if err != nil {
		t.Fatalf("BuildPortHopIPTablesRules: %v", err)
	}
	if tool != "iptables" || len(rules) != 3 {
		t.Fatalf("unexpected tool=%q rules=%d", tool, len(rules))
	}
	joined := strings.Join(rules[2], " ")
	if !strings.Contains(joined, "--dport 7465:7472") || !strings.Contains(joined, "portbridge-sess_01") {
		t.Fatalf("unexpected peer allow rule: %s", joined)
	}

	applyNFT, teardownNFT, err := BuildPortHopNFTablesRules("2001:db8::1", 7465, 8, "sess-v6")
	if err != nil {
		t.Fatalf("BuildPortHopNFTablesRules: %v", err)
	}
	if !strings.Contains(applyNFT, "ip6 saddr 2001:db8::1 udp dport 7465-7472 accept") ||
		!strings.Contains(applyNFT, `"portbridge-sess-v6"`) ||
		!strings.Contains(teardownNFT, "delete chain inet portbridge") {
		t.Fatalf("unexpected nftables output:\n%s\n---\n%s", applyNFT, teardownNFT)
	}
}
