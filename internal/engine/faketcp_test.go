package engine

import (
	"bytes"
	"net"
	"testing"
)

func TestFakeTCPFrameEncodeDecodeAndRSTIgnore(t *testing.T) {
	mask := deriveFakeTCPMask([]byte("faketcp-secret-xyz"))
	srcIP := net.ParseIP("198.51.100.10").To4()
	dstIP := net.ParseIP("203.0.113.20").To4()
	payload := []byte("kcp-fec-over-faketcp-segment")

	seg := encodeFakeTCPFrame(srcIP, dstIP, 54321, 8443, 1000, 2000, fakeTCPDirC2S, mask, payload)
	if len(seg) != fakeTCPHeaderLen+fakeTCPInnerHeaderLen+len(payload) {
		t.Fatalf("unexpected segment length %d", len(seg))
	}

	srcPort, seq, got, ok := decodeFakeTCPFrame(seg, fakeTCPDirC2S, 8443, mask)
	if !ok {
		t.Fatal("expected decodeFakeTCPFrame to accept valid FakeTCP segment")
	}
	if srcPort != 54321 || seq != 1000 {
		t.Fatalf("unexpected TCP fields: src=%d seq=%d", srcPort, seq)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}

	// Simulate ISP or kernel RST injection: must be ignored.
	rstSeg := append([]byte(nil), seg...)
	rstSeg[13] |= 0x04 // RST flag
	if _, _, _, ok := decodeFakeTCPFrame(rstSeg, fakeTCPDirC2S, 8443, mask); ok {
		t.Fatal("expected RST segment to be ignored by decodeFakeTCPFrame")
	}

	// Wrong secret mask must be rejected.
	wrongMask := deriveFakeTCPMask([]byte("wrong-secret"))
	if _, _, _, ok := decodeFakeTCPFrame(seg, fakeTCPDirC2S, 8443, wrongMask); ok {
		t.Fatal("expected segment with wrong secret mask to be rejected")
	}
}
