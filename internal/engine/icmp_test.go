package engine

import (
	"bytes"
	"testing"
)

func TestICMPFrameEncodeDecodeAndDirectionFilter(t *testing.T) {
	mask := deriveICMPMask([]byte("test-secret-123"))
	payload := []byte("hello-kcp-over-icmp-payload")

	// Dialer -> Listener (Echo Request, Type 8, flag C2S)
	c2sPkt := encodeICMPFrame(icmpTypeEchoRequest, 0x1234, 7, 51234, 443, icmpFlagC2S, mask, payload)
	if c2sPkt[0] != icmpTypeEchoRequest {
		t.Fatalf("expected ICMP type %d, got %d", icmpTypeEchoRequest, c2sPkt[0])
	}
	if internetChecksum(c2sPkt) != 0 {
		t.Fatalf("expected valid ICMP checksum (0 remainder), got 0x%04x", internetChecksum(c2sPkt))
	}

	// Listener expects icmpFlagC2S on localPort 443: should accept.
	id, seq, srcPort, got, ok := decodeICMPFrame(c2sPkt, icmpFlagC2S, 443, mask)
	if !ok {
		t.Fatal("expected listener to accept C2S ICMP frame")
	}
	if srcPort != 51234 || id != 0x1234 || seq != 7 {
		t.Fatalf("unexpected header fields: src=%d id=0x%x seq=%d", srcPort, id, seq)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}

	// Simulate Linux kernel's automatic Echo Reply (Type 0) echoing the exact C2S payload:
	// Dialer expects icmpFlagS2C, so it MUST ignore the kernel's automatic Echo Reply!
	kernelAutoReply := append([]byte(nil), c2sPkt...)
	kernelAutoReply[0] = icmpTypeEchoReply
	if _, _, _, _, ok := decodeICMPFrame(kernelAutoReply, icmpFlagS2C, 51234, mask); ok {
		t.Fatal("dialer must ignore kernel automatic Echo Reply that still carries icmpFlagC2S")
	}

	// Listener -> Dialer (Echo Reply, Type 0, flag S2C)
	s2cPkt := encodeICMPFrame(icmpTypeEchoReply, 0x1234, 8, 443, 51234, icmpFlagS2C, mask, payload)
	_, _, srcPort2, got2, ok := decodeICMPFrame(s2cPkt, icmpFlagS2C, 51234, mask)
	if !ok {
		t.Fatal("expected dialer to accept genuine S2C ICMP Echo Reply")
	}
	if srcPort2 != 443 || !bytes.Equal(got2, payload) {
		t.Fatalf("unexpected S2C decode: src=%d payload=%q", srcPort2, got2)
	}

	// Wrong secret mask must be rejected.
	wrongMask := deriveICMPMask([]byte("different-secret"))
	if _, _, _, _, ok := decodeICMPFrame(c2sPkt, icmpFlagC2S, 443, mask); !ok {
		t.Fatal("sanity check failed")
	}
	if _, _, _, _, ok := decodeICMPFrame(c2sPkt, icmpFlagC2S, 443, wrongMask); ok {
		t.Fatal("expected frame with wrong secret mask to be rejected")
	}
}
