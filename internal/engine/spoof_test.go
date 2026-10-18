package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildAndParseDecoyClientHello(t *testing.T) {
	for _, domain := range WhitelistedSNIs {
		rec := BuildDecoyClientHello(domain)
		if len(rec) < 180 {
			t.Fatalf("BuildDecoyClientHello(%q) length = %d, want >= 180", domain, len(rec))
		}
		if rec[0] != 0x16 || rec[1] != 0x03 || rec[2] != 0x01 {
			t.Fatalf("BuildDecoyClientHello(%q) bad TLS record header: %x", domain, rec[:5])
		}
		recLen := int(binary.BigEndian.Uint16(rec[3:5]))
		if recLen+5 != len(rec) {
			t.Fatalf("BuildDecoyClientHello(%q) record length mismatch: header=%d total=%d", domain, recLen+5, len(rec))
		}
		gotSNI, ok := ParseClientHelloSNI(rec)
		if !ok {
			t.Fatalf("ParseClientHelloSNI(%q) returned false", domain)
		}
		if gotSNI != domain {
			t.Fatalf("ParseClientHelloSNI(%q) = %q, want %q", domain, gotSNI, domain)
		}
	}
}

func TestIPv4UDPAndTCPPacketChecksums(t *testing.T) {
	srcIP := net.ParseIP("104.18.4.130").To4()
	dstIP := net.ParseIP("198.51.100.42").To4()
	payload := []byte("hello-spoof-packet")

	udpPkt, err := buildIPv4UDPPacket(srcIP, dstIP, 443, 51820, 64, payload)
	if err != nil {
		t.Fatalf("buildIPv4UDPPacket: %v", err)
	}
	if len(udpPkt) != 20+8+len(payload) {
		t.Fatalf("unexpected UDP packet length %d", len(udpPkt))
	}
	if sum := ipv4Checksum(udpPkt[:20]); sum != 0 {
		t.Fatalf("IPv4 header checksum invalid on UDP packet: 0x%04x", sum)
	}
	if !bytes.Equal(udpPkt[12:16], srcIP) || !bytes.Equal(udpPkt[16:20], dstIP) {
		t.Fatalf("UDP packet IPs mismatch")
	}

	tcpPkt, err := buildIPv4TCPPacket(srcIP, dstIP, 51820, 443, 0x11223344, 0x55667788, 64, false, payload)
	if err != nil {
		t.Fatalf("buildIPv4TCPPacket: %v", err)
	}
	if len(tcpPkt) != 20+20+len(payload) {
		t.Fatalf("unexpected TCP packet length %d", len(tcpPkt))
	}
	if sum := ipv4Checksum(tcpPkt[:20]); sum != 0 {
		t.Fatalf("IPv4 header checksum invalid on TCP packet: 0x%04x", sum)
	}
	badTCP, err := buildIPv4TCPPacket(srcIP, dstIP, 51820, 443, 0x11223344, 0x55667788, 64, true, payload)
	if err != nil {
		t.Fatalf("buildIPv4TCPPacket(corruptChecksum): %v", err)
	}
	if bytes.Equal(tcpPkt[36:38], badTCP[36:38]) {
		t.Fatalf("badChecksum TCP packet should have inverted TCP checksum")
	}
}

func TestSpoofPacketConnHeaderAndDecoyFilter(t *testing.T) {
	u1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP 1: %v", err)
	}
	defer u1.Close()

	u2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP 2: %v", err)
	}
	defer u2.Close()

	cfg := DefaultConfig()
	cfg.IPSpoof = true
	cfg.SpoofIP = DefaultSpoofIP
	cfg.SpoofSNI = DefaultSpoofSNI
	cfg.secret = []byte("0123456789abcdef0123456789abcdef")

	c1, err := newSpoofPacketConn(u1, cfg, u2.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("newSpoofPacketConn 1: %v", err)
	}
	defer c1.Close()
	c2, err := newSpoofPacketConn(u2, cfg, u1.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("newSpoofPacketConn 2: %v", err)
	}
	defer c2.Close()

	// Force fallback to normal UDP socket so test runs without CAP_NET_RAW / root.
	atomic.StoreUint32(&c1.rawFallback, 1)
	atomic.StoreUint32(&c2.rawFallback, 1)

	// Send a decoy ClientHello directly to u2; c2.ReadFrom should ignore it and read the real frame.
	decoy := BuildDecoyClientHello(DefaultSpoofSNI)
	if _, err := u1.WriteToUDP(decoy, u2.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("WriteToUDP decoy: %v", err)
	}

	want := []byte("kcp-authenticated-frame-payload")
	if _, err := c1.WriteTo(want, u2.LocalAddr()); err != nil {
		t.Fatalf("c1.WriteTo: %v", err)
	}

	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, addr, err := c2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("c2.ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("c2.ReadFrom got %q, want %q", buf[:n], want)
	}
	if addr.String() != u1.LocalAddr().String() {
		t.Fatalf("c2.ReadFrom addr = %s, want %s", addr.String(), u1.LocalAddr().String())
	}
}

func TestProbeListenerDualModeKCPAndSpoof(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	pl, err := StartProbeListener("127.0.0.1", 0, secret, 30*time.Second)
	if err != nil {
		t.Fatalf("StartProbeListener: %v", err)
	}
	defer pl.Close()

	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(pl.Port))
	specs := []ProbeCandidateSpec{
		{
			ID:         "direct-sni-spoof",
			Label:      "Decoy Whitelisted SNI",
			Mode:       "direct",
			Link:       "website",
			Transport:  string(TransportTLS),
			Stealth:    true,
			SNISpoof:   true,
			SpoofSNI:   DefaultSpoofSNI,
			ServerName: DefaultSpoofSNI,
			TargetAddr: target,
			Port:       pl.Port,
		},
		{
			ID:         "direct-kcp",
			Label:      "KCP over UDP",
			Mode:       "direct",
			Link:       "kcp",
			Transport:  string(TransportKCP),
			TargetAddr: target,
			Port:       pl.Port,
		},
		{
			ID:         "direct-ip-spoof",
			Label:      "Source IP + SNI Spoof",
			Mode:       "direct",
			Link:       "kcp",
			Transport:  string(TransportKCP),
			SNISpoof:   true,
			SpoofSNI:   DefaultSpoofSNI,
			IPSpoof:    true,
			SpoofIP:    DefaultSpoofIP,
			TargetAddr: target,
			Port:       pl.Port,
		},
	}

	results := RunProbeDialer(context.Background(), specs, secret, 32*1024)
	if len(results) != len(specs) {
		t.Fatalf("RunProbeDialer returned %d results, want %d", len(results), len(specs))
	}
	for _, r := range results {
		if r.Status != "ok" {
			t.Fatalf("candidate %s failed: status=%s error=%s", r.ID, r.Status, r.Error)
		}
	}
}

func TestConfigSpoofSettingsValidation(t *testing.T) {
	cfg := DefaultConfig()
	_ = cfg.Set("name", "spoof-test")
	_ = cfg.Set("mode", "direct")
	_ = cfg.Set("role", "edge")
	_ = cfg.Set("tunnel_addr", "198.51.100.10:443")
	_ = cfg.Set("user_listen", "0.0.0.0:8443")
	_ = cfg.Set("secret_file", "/etc/portbridge/tunnels/spoof-test.secret")
	_ = cfg.Set("transport", "kcp")
	if err := cfg.Set("sni_spoof", "on"); err != nil {
		t.Fatalf("Set sni_spoof: %v", err)
	}
	if err := cfg.Set("spoof_sni", "www.recaptcha.net"); err != nil {
		t.Fatalf("Set spoof_sni: %v", err)
	}
	if err := cfg.Set("ip_spoof", "on"); err != nil {
		t.Fatalf("Set ip_spoof: %v", err)
	}
	if err := cfg.Set("spoof_ip", "142.250.185.206"); err != nil {
		t.Fatalf("Set spoof_ip: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate valid spoof config: %v", err)
	}
	if got := cfg.EffectiveSpoofSNI(); got != "www.recaptcha.net" {
		t.Fatalf("EffectiveSpoofSNI = %q, want www.recaptcha.net", got)
	}
	if got := cfg.EffectiveSpoofIP(); got != "142.250.185.206" {
		t.Fatalf("EffectiveSpoofIP = %q, want 142.250.185.206", got)
	}

	_ = cfg.Set("spoof_ip", "not-an-ip")
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for invalid spoof_ip")
	}
}
