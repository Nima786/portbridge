package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// WebRTC Video-Call Disguise (RFC 5389 ICE STUN + RFC 3550 / 3711 SRTP) for KCP + FEC.
//
// Wire Behavior (RFC 7983 single-port WebRTC multiplexing):
//   1. Connectivity & Consent Freshness (RFC 5389 / RFC 7675):
//      Every client UDP socket opens immediately with a genuine RFC 5389 STUN Binding
//      Request (Type 0x0001, Magic Cookie 0x2112A442) carrying standard WebRTC ICE
//      attributes (USERNAME, ICE-CONTROLLING, PRIORITY, MESSAGE-INTEGRITY, FINGERPRINT)
//      and repeats consent checks every 12s.
//      The server validates FINGERPRINT and PSK-keyed MESSAGE-INTEGRITY in constant time
//      (silently dropping unauthorized probes) and answers with an RFC 5389 STUN Binding
//      Success Response (Type 0x0101) containing the client's XOR-MAPPED-ADDRESS.
//   2. Media Framing (RFC 3550 RTP v2 + RFC 3711 SRTP):
//      Every KCP+FEC datagram is framed as a 32-byte-overhead SRTP v2 packet:
//        [0]     0x80 (RTP v2, P=0, X=0, CC=0)
//        [1]     M | PT (PT 111 Opus for <=240B packets; PT 96 VP8 video for >240B)
//        [2:4]   RTP Sequence Number (monotonic uint16 per socket)
//        [4:8]   RTP Timestamp (90 kHz media clock)
//        [8:12]  SSRC (consistent 32-bit synchronization source per socket)
//        [12:16] Random Salt (4 bytes, crypto/rand)
//        [16:28] Masked Meta (12 bytes): (SessionID [8B] || LogicalSeq [4B]) XOR KeyStream12
//        [28:N]  Encrypted KCP+FEC Payload
//        [N:N+4] 32-bit SRTP Auth Tag (truncated HMAC-SHA256 over [0:N], constant-time)
//
// Supports single-leg UDP, Dynamic Port-Hopping (port_hop = on), and Twin-Path 1+1
// packet duplication (twin_path = on) with 2048-packet sliding-window deduplication.

const (
	stunMagicCookie     uint32 = 0x2112A442
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
	stunFingerprintXOR  uint32 = 0x5354554e

	stunAttrUsername       uint16 = 0x0006
	stunAttrMessageInteg   uint16 = 0x0008
	stunAttrXorMappedAddr  uint16 = 0x0020
	stunAttrPriority       uint16 = 0x0024
	stunAttrFingerprint    uint16 = 0x8028
	stunAttrIceControlling uint16 = 0x802a

	rtpVersionByte byte = 0x80
	rtpPTOpus      byte = 111
	rtpPTVP8       byte = 96

	webrtcRTPHeaderSize = 12
	webrtcSaltSize      = 4
	webrtcMetaSize      = 12
	webrtcTagSize       = 4
	webrtcOverhead      = webrtcRTPHeaderSize + webrtcSaltSize + webrtcMetaSize + webrtcTagSize // 32 bytes

	webrtcConsentInterval = 12 * time.Second
)

type webrtcKeys struct {
	stunKey [32]byte // HMAC-SHA1 key for STUN MESSAGE-INTEGRITY
	iceMask [32]byte // KeyStream key for masking 8B sessionID in ICE-CONTROLLING
	ksKey   [32]byte // KeyStream key for SRTP 12B session+seq metadata
	macKey  [32]byte // HMAC-SHA256 key for 32-bit SRTP auth tag
	ufrag   string   // Deterministic 9-char "xxxx:yyyy" ICE USERNAME derived from PSK
}

func deriveWebRTCKeys(psk []byte) webrtcKeys {
	derive := func(label string) [32]byte {
		m := hmac.New(sha256.New, psk)
		m.Write([]byte(label))
		var out [32]byte
		m.Sum(out[:0])
		return out
	}
	ufSum := derive("portbridge-webrtc-ufrag-v1")
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var uf [9]byte
	for i := 0; i < 4; i++ {
		uf[i] = alphabet[int(ufSum[i])%len(alphabet)]
	}
	uf[4] = ':'
	for i := 0; i < 4; i++ {
		uf[5+i] = alphabet[int(ufSum[4+i])%len(alphabet)]
	}
	return webrtcKeys{
		stunKey: derive("portbridge-webrtc-stun-mi-v1"),
		iceMask: derive("portbridge-webrtc-ice-mask-v1"),
		ksKey:   derive("portbridge-webrtc-srtp-ks-v1"),
		macKey:  derive("portbridge-webrtc-srtp-mac-v1"),
		ufrag:   string(uf[:]),
	}
}

func maskICESessionID(iceMask *[32]byte, txID []byte, sid [8]byte) [8]byte {
	m := hmac.New(sha256.New, iceMask[:])
	m.Write(txID[:12])
	var sum [32]byte
	m.Sum(sum[:0])
	var out [8]byte
	for i := 0; i < 8; i++ {
		out[i] = sid[i] ^ sum[i]
	}
	return out
}

// buildSTUNBindingRequest constructs an RFC 5389 STUN Binding Request carrying
// USERNAME, ICE-CONTROLLING (masked sessionID), PRIORITY, MESSAGE-INTEGRITY, and FINGERPRINT.
func buildSTUNBindingRequest(keys *webrtcKeys, sessionID [8]byte) ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, err
	}

	// Layout:
	//   20B STUN header
	//   16B USERNAME (4B TLV + 9B "xxxx:yyyy" padded to 12B)
	//   12B ICE-CONTROLLING (4B TLV + 8B tie-breaker)
	//    8B PRIORITY (4B TLV + 4B uint32)
	//   24B MESSAGE-INTEGRITY (4B TLV + 20B HMAC-SHA1)
	//    8B FINGERPRINT (4B TLV + 4B CRC32^0x5354554e)
	// Total = 88 bytes (68 bytes of attributes).
	buf := make([]byte, 88)
	binary.BigEndian.PutUint16(buf[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], txID[:])

	off := 20
	// 1. USERNAME (9 bytes -> padded to 12 bytes)
	binary.BigEndian.PutUint16(buf[off:off+2], stunAttrUsername)
	binary.BigEndian.PutUint16(buf[off+2:off+4], 9)
	copy(buf[off+4:off+13], keys.ufrag)
	off += 16

	// 2. ICE-CONTROLLING (8 bytes)
	maskedSID := maskICESessionID(&keys.iceMask, txID[:], sessionID)
	binary.BigEndian.PutUint16(buf[off:off+2], stunAttrIceControlling)
	binary.BigEndian.PutUint16(buf[off+2:off+4], 8)
	copy(buf[off+4:off+12], maskedSID[:])
	off += 12

	// 3. PRIORITY (4 bytes: standard WebRTC host candidate priority)
	binary.BigEndian.PutUint16(buf[off:off+2], stunAttrPriority)
	binary.BigEndian.PutUint16(buf[off+2:off+4], 4)
	binary.BigEndian.PutUint32(buf[off+4:off+8], 0x6e001eff)
	off += 8

	// 4. MESSAGE-INTEGRITY (RFC 5389 §15.4: length field includes MI TLV = off - 20 + 24)
	miOff := off
	binary.BigEndian.PutUint16(buf[2:4], uint16(miOff-20+24))
	miMac := hmac.New(sha1.New, keys.stunKey[:])
	miMac.Write(buf[:miOff])
	var miSum [20]byte
	miMac.Sum(miSum[:0])
	binary.BigEndian.PutUint16(buf[miOff:miOff+2], stunAttrMessageInteg)
	binary.BigEndian.PutUint16(buf[miOff+2:miOff+4], 20)
	copy(buf[miOff+4:miOff+24], miSum[:])
	off += 24

	// 5. FINGERPRINT (RFC 5389 §15.5: length field includes FP TLV = off - 20 + 8)
	fpOff := off
	binary.BigEndian.PutUint16(buf[2:4], uint16(fpOff-20+8))
	fp := crc32.ChecksumIEEE(buf[:fpOff]) ^ stunFingerprintXOR
	binary.BigEndian.PutUint16(buf[fpOff:fpOff+2], stunAttrFingerprint)
	binary.BigEndian.PutUint16(buf[fpOff+2:fpOff+4], 4)
	binary.BigEndian.PutUint32(buf[fpOff+4:fpOff+8], fp)

	return buf, txID, nil
}

// parseAndVerifySTUNBindingRequest validates an incoming RFC 5389 STUN Binding Request
// in constant time and extracts its transaction ID and masked 8-byte sessionID.
func parseAndVerifySTUNBindingRequest(pkt []byte, keys *webrtcKeys) (txID [12]byte, sid [8]byte, ok bool) {
	if len(pkt) < 52 || (len(pkt)&3) != 0 {
		return txID, sid, false
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != stunBindingRequest {
		return txID, sid, false
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != stunMagicCookie {
		return txID, sid, false
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if 20+msgLen != len(pkt) {
		return txID, sid, false
	}
	copy(txID[:], pkt[8:20])

	// Verify trailing FINGERPRINT first.
	fpOff := len(pkt) - 8
	if binary.BigEndian.Uint16(pkt[fpOff:fpOff+2]) != stunAttrFingerprint ||
		binary.BigEndian.Uint16(pkt[fpOff+2:fpOff+4]) != 4 {
		return txID, sid, false
	}
	wantFP := crc32.ChecksumIEEE(pkt[:fpOff]) ^ stunFingerprintXOR
	if binary.BigEndian.Uint32(pkt[fpOff+4:fpOff+8]) != wantFP {
		return txID, sid, false
	}

	// Walk attributes up to FINGERPRINT to locate ICE-CONTROLLING and MESSAGE-INTEGRITY.
	var maskedSID [8]byte
	hasSID := false
	miOff := -1
	pos := 20
	for pos+4 <= fpOff {
		aType := binary.BigEndian.Uint16(pkt[pos : pos+2])
		aLen := int(binary.BigEndian.Uint16(pkt[pos+2 : pos+4]))
		padded := (aLen + 3) & ^3
		if pos+4+padded > fpOff {
			return txID, sid, false
		}
		val := pkt[pos+4 : pos+4+aLen]
		switch aType {
		case stunAttrIceControlling:
			if aLen == 8 {
				copy(maskedSID[:], val)
				hasSID = true
			}
		case stunAttrMessageInteg:
			if aLen == 20 && pos+24 == fpOff {
				miOff = pos
			}
		}
		pos += 4 + padded
	}
	if miOff < 20 || !hasSID {
		return txID, sid, false
	}

	// Compute expected MESSAGE-INTEGRITY with adjusted STUN header length.
	var hdr [20]byte
	copy(hdr[:], pkt[:20])
	binary.BigEndian.PutUint16(hdr[2:4], uint16(miOff-20+24))
	miMac := hmac.New(sha1.New, keys.stunKey[:])
	miMac.Write(hdr[:])
	miMac.Write(pkt[20:miOff])
	var wantMI [20]byte
	miMac.Sum(wantMI[:0])
	if subtle.ConstantTimeCompare(pkt[miOff+4:miOff+24], wantMI[:]) != 1 {
		return txID, sid, false
	}

	sid = maskICESessionID(&keys.iceMask, txID[:], maskedSID)
	return txID, sid, true
}

// buildSTUNBindingResponse constructs an RFC 5389 STUN Binding Success Response (0x0101)
// with XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY, and FINGERPRINT.
func buildSTUNBindingResponse(keys *webrtcKeys, txID [12]byte, peer net.Addr) []byte {
	var ip net.IP
	var port int
	if ua, ok := peer.(*net.UDPAddr); ok && ua != nil {
		ip = ua.IP
		port = ua.Port
	} else if peer != nil {
		if h, pStr, err := net.SplitHostPort(peer.String()); err == nil {
			ip = net.ParseIP(h)
			port, _ = strconv.Atoi(pStr)
		}
	}
	ip4 := ip.To4()
	xmaAttrLen := 8 // IPv4 XOR-MAPPED-ADDRESS value length
	if ip4 == nil && len(ip) == net.IPv6len {
		xmaAttrLen = 20
	}

	totalLen := 20 + (4 + xmaAttrLen) + 24 + 8
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], stunBindingResponse)
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], txID[:])

	off := 20
	binary.BigEndian.PutUint16(buf[off:off+2], stunAttrXorMappedAddr)
	binary.BigEndian.PutUint16(buf[off+2:off+4], uint16(xmaAttrLen))
	buf[off+4] = 0x00
	binary.BigEndian.PutUint16(buf[off+6:off+8], uint16(port)^uint16(stunMagicCookie>>16))
	if xmaAttrLen == 8 {
		buf[off+5] = 0x01 // IPv4
		var v4 [4]byte
		if ip4 != nil {
			copy(v4[:], ip4)
		}
		var cookieBytes [4]byte
		binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
		for i := 0; i < 4; i++ {
			buf[off+8+i] = v4[i] ^ cookieBytes[i]
		}
	} else {
		buf[off+5] = 0x02 // IPv6
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:16], txID[:])
		for i := 0; i < 16; i++ {
			buf[off+8+i] = ip[i] ^ mask[i]
		}
	}
	off += 4 + xmaAttrLen

	miOff := off
	binary.BigEndian.PutUint16(buf[2:4], uint16(miOff-20+24))
	miMac := hmac.New(sha1.New, keys.stunKey[:])
	miMac.Write(buf[:miOff])
	var miSum [20]byte
	miMac.Sum(miSum[:0])
	binary.BigEndian.PutUint16(buf[miOff:miOff+2], stunAttrMessageInteg)
	binary.BigEndian.PutUint16(buf[miOff+2:miOff+4], 20)
	copy(buf[miOff+4:miOff+24], miSum[:])
	off += 24

	fpOff := off
	binary.BigEndian.PutUint16(buf[2:4], uint16(fpOff-20+8))
	fp := crc32.ChecksumIEEE(buf[:fpOff]) ^ stunFingerprintXOR
	binary.BigEndian.PutUint16(buf[fpOff:fpOff+2], stunAttrFingerprint)
	binary.BigEndian.PutUint16(buf[fpOff+2:fpOff+4], 4)
	binary.BigEndian.PutUint32(buf[fpOff+4:fpOff+8], fp)

	return buf
}

// parseAndVerifySTUNBindingResponse verifies a server STUN Binding Success Response.
func parseAndVerifySTUNBindingResponse(pkt []byte, keys *webrtcKeys) bool {
	if len(pkt) < 56 || (len(pkt)&3) != 0 {
		return false
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != stunBindingResponse {
		return false
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != stunMagicCookie {
		return false
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if 20+msgLen != len(pkt) {
		return false
	}
	fpOff := len(pkt) - 8
	if binary.BigEndian.Uint16(pkt[fpOff:fpOff+2]) != stunAttrFingerprint ||
		binary.BigEndian.Uint16(pkt[fpOff+2:fpOff+4]) != 4 {
		return false
	}
	if (crc32.ChecksumIEEE(pkt[:fpOff]) ^ stunFingerprintXOR) != binary.BigEndian.Uint32(pkt[fpOff+4:fpOff+8]) {
		return false
	}
	miOff := fpOff - 24
	if miOff < 20 ||
		binary.BigEndian.Uint16(pkt[miOff:miOff+2]) != stunAttrMessageInteg ||
		binary.BigEndian.Uint16(pkt[miOff+2:miOff+4]) != 20 {
		return false
	}
	var hdr [20]byte
	copy(hdr[:], pkt[:20])
	binary.BigEndian.PutUint16(hdr[2:4], uint16(miOff-20+24))
	miMac := hmac.New(sha1.New, keys.stunKey[:])
	miMac.Write(hdr[:])
	miMac.Write(pkt[20:miOff])
	var wantMI [20]byte
	miMac.Sum(wantMI[:0])
	return subtle.ConstantTimeCompare(pkt[miOff+4:miOff+24], wantMI[:]) == 1
}

type rtpStreamClock struct {
	ssrc    uint32
	wireSeq atomic.Uint32
	tsBase  uint32
	startNS int64
}

func newRTPStreamClock() *rtpStreamClock {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	ssrc := binary.BigEndian.Uint32(rnd[0:4])
	if ssrc == 0 {
		ssrc = 0x4b637031
	}
	initSeq := uint32(binary.BigEndian.Uint16(rnd[4:6]))
	tsBase := binary.BigEndian.Uint32(rnd[2:6])
	c := &rtpStreamClock{
		ssrc:    ssrc,
		tsBase:  tsBase,
		startNS: time.Now().UnixNano(),
	}
	c.wireSeq.Store(initSeq)
	return c
}

func (c *rtpStreamClock) writeHeader(dst []byte, payloadLen int) {
	dst[0] = rtpVersionByte
	if payloadLen <= 240 {
		dst[1] = rtpPTOpus
	} else if payloadLen < 1100 {
		dst[1] = 0x80 | rtpPTVP8 // Marker bit on end-of-frame video packet
	} else {
		dst[1] = rtpPTVP8
	}
	seq := uint16(c.wireSeq.Add(1))
	binary.BigEndian.PutUint16(dst[2:4], seq)
	elapsedNS := time.Now().UnixNano() - c.startNS
	if elapsedNS < 0 {
		elapsedNS = 0
	}
	// 90 kHz RTP video clock: 90,000 ticks/sec = 9 ticks per 100 microseconds.
	ts := c.tsBase + uint32((elapsedNS*9)/100_000)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	binary.BigEndian.PutUint32(dst[8:12], c.ssrc)
}

func webrtcSRTPKeyStream12(ksKey *[32]byte, rtpAndSalt16 []byte) [webrtcMetaSize]byte {
	mac := hmac.New(sha256.New, ksKey[:])
	mac.Write(rtpAndSalt16[:16])
	var sum [32]byte
	mac.Sum(sum[:0])
	var out [webrtcMetaSize]byte
	copy(out[:], sum[:webrtcMetaSize])
	return out
}

func webrtcSRTPAuthTag(macKey *[32]byte, body []byte) [webrtcTagSize]byte {
	mac := hmac.New(sha256.New, macKey[:])
	mac.Write(body)
	var sum [32]byte
	mac.Sum(sum[:0])
	var tag [webrtcTagSize]byte
	copy(tag[:], sum[:webrtcTagSize])
	return tag
}

func encodeWebRTCSRTP(dst []byte, keys *webrtcKeys, clock *rtpStreamClock, sessionID [8]byte, logicalSeq uint32, payload []byte) ([]byte, error) {
	total := webrtcOverhead + len(payload)
	if cap(dst) < total {
		dst = make([]byte, total)
	} else {
		dst = dst[:total]
	}

	clock.writeHeader(dst[0:12], len(payload))
	if _, err := rand.Read(dst[12:16]); err != nil {
		return nil, err
	}

	var rawMeta [webrtcMetaSize]byte
	copy(rawMeta[0:8], sessionID[:])
	binary.BigEndian.PutUint32(rawMeta[8:12], logicalSeq)

	ks := webrtcSRTPKeyStream12(&keys.ksKey, dst[0:16])
	for i := 0; i < webrtcMetaSize; i++ {
		dst[16+i] = rawMeta[i] ^ ks[i]
	}
	copy(dst[28:28+len(payload)], payload)

	tagOff := 28 + len(payload)
	tag := webrtcSRTPAuthTag(&keys.macKey, dst[:tagOff])
	copy(dst[tagOff:tagOff+4], tag[:])
	return dst, nil
}

func decodeWebRTCSRTP(pkt []byte, keys *webrtcKeys) (sessionID [8]byte, logicalSeq uint32, payload []byte, ok bool) {
	if len(pkt) < webrtcOverhead || pkt[0] != rtpVersionByte {
		return sessionID, 0, nil, false
	}
	pt := pkt[1] & 0x7f
	if pt != rtpPTOpus && pt != rtpPTVP8 {
		return sessionID, 0, nil, false
	}

	tagOff := len(pkt) - webrtcTagSize
	wantTag := webrtcSRTPAuthTag(&keys.macKey, pkt[:tagOff])
	if subtle.ConstantTimeCompare(pkt[tagOff:], wantTag[:]) != 1 {
		return sessionID, 0, nil, false
	}

	ks := webrtcSRTPKeyStream12(&keys.ksKey, pkt[0:16])
	var rawMeta [webrtcMetaSize]byte
	for i := 0; i < webrtcMetaSize; i++ {
		rawMeta[i] = pkt[16+i] ^ ks[i]
	}
	copy(sessionID[:], rawMeta[0:8])
	logicalSeq = binary.BigEndian.Uint32(rawMeta[8:12])
	payload = pkt[28:tagOff]
	return sessionID, logicalSeq, payload, true
}

type webrtcSessionAddr struct {
	id  [8]byte
	str string
}

func newWebRTCSessionAddr(id [8]byte) webrtcSessionAddr {
	return webrtcSessionAddr{
		id:  id,
		str: "webrtc:" + hex.EncodeToString(id[:]),
	}
}

func (a webrtcSessionAddr) Network() string { return "udp" }
func (a webrtcSessionAddr) String() string  { return a.str }

type webrtcPeerSession struct {
	mu       sync.Mutex
	legs     [2]twinLegEndpoint
	clocks   [2]*rtpStreamClock
	dedup    twinSeqWindow
	txSeq    atomic.Uint32
	lastSeen atomic.Int64
	vaddr    webrtcSessionAddr
}

func newWebRTCPeerSession(sid [8]byte, now int64) *webrtcPeerSession {
	s := &webrtcPeerSession{
		clocks: [2]*rtpStreamClock{newRTPStreamClock(), newRTPStreamClock()},
		vaddr:  newWebRTCSessionAddr(sid),
	}
	s.lastSeen.Store(now)
	return s
}

func (s *webrtcPeerSession) touchLeg(sock net.PacketConn, raddr net.Addr, now int64) {
	key := makeLegKey(sock, raddr)
	s.lastSeen.Store(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.legs[0].key == key {
		s.legs[0].sock = sock
		s.legs[0].peerAddr = raddr
		s.legs[0].lastSeen = now
	} else if s.legs[1].key == key {
		s.legs[1].sock = sock
		s.legs[1].peerAddr = raddr
		s.legs[1].lastSeen = now
		if s.legs[0].sock == nil || now-s.legs[0].lastSeen > twinLegStaleNS {
			s.legs[0], s.legs[1] = s.legs[1], s.legs[0]
			s.clocks[0], s.clocks[1] = s.clocks[1], s.clocks[0]
		}
	} else if s.legs[0].sock == nil {
		s.legs[0] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
	} else if s.legs[1].sock == nil {
		s.legs[1] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
	} else if s.legs[0].lastSeen <= s.legs[1].lastSeen {
		s.legs[0] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
		s.clocks[0] = newRTPStreamClock()
	} else {
		s.legs[1] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
		s.clocks[1] = newRTPStreamClock()
	}
}

func (s *webrtcPeerSession) recordSRTPAndCheckDup(sock net.PacketConn, raddr net.Addr, seq uint32, now int64) bool {
	s.touchLeg(sock, raddr, now)
	s.mu.Lock()
	ok := s.dedup.Accept(seq)
	s.mu.Unlock()
	return ok
}

func (s *webrtcPeerSession) activeLegs(now int64) (l0 twinLegEndpoint, c0 *rtpStreamClock, l1 twinLegEndpoint, c1 *rtpStreamClock, hasPrimary bool, hasBoth bool) {
	s.mu.Lock()
	leg0, clk0 := s.legs[0], s.clocks[0]
	leg1, clk1 := s.legs[1], s.clocks[1]
	s.mu.Unlock()

	ok0 := leg0.sock != nil && leg0.peerAddr != nil && now-leg0.lastSeen < twinLegActiveNS
	ok1 := leg1.sock != nil && leg1.peerAddr != nil && now-leg1.lastSeen < twinLegActiveNS && leg1.key != leg0.key
	if ok0 && ok1 {
		if leg1.lastSeen-leg0.lastSeen > twinLegStaleNS {
			return leg1, clk1, leg0, clk0, true, true
		}
		return leg0, clk0, leg1, clk1, true, true
	}
	if ok0 {
		return leg0, clk0, twinLegEndpoint{}, nil, true, false
	}
	if ok1 {
		return leg1, clk1, twinLegEndpoint{}, nil, true, false
	}
	if leg0.sock != nil && leg0.peerAddr != nil {
		return leg0, clk0, twinLegEndpoint{}, nil, true, false
	}
	return twinLegEndpoint{}, nil, twinLegEndpoint{}, nil, false, false
}

// webrtcServerMux holds server-side WebRTC STUN + SRTP state for both dedicated
// WebRTCListenConn and shared multi-protocol UDP listeners.
type webrtcServerMux struct {
	keys        webrtcKeys
	maxDupBytes int
	sessions    sync.Map // [8]byte -> *webrtcPeerSession
}

func newWebRTCServerMux(psk []byte, maxDupBytes int) *webrtcServerMux {
	if maxDupBytes <= 0 {
		maxDupBytes = DefaultTwinPathMaxDupBytes
	}
	return &webrtcServerMux{
		keys:        deriveWebRTCKeys(psk),
		maxDupBytes: maxDupBytes,
	}
}

func (m *webrtcServerMux) getOrCreateSession(sid [8]byte, now int64) *webrtcPeerSession {
	if existing, loaded := m.sessions.Load(sid); loaded {
		return existing.(*webrtcPeerSession)
	}
	fresh := newWebRTCPeerSession(sid, now)
	actual, _ := m.sessions.LoadOrStore(sid, fresh)
	return actual.(*webrtcPeerSession)
}

func (m *webrtcServerMux) tryHandlePacket(sock net.PacketConn, raddr net.Addr, buf []byte, n int) (payloadLen int, vaddr net.Addr, matched bool, deliver bool) {
	pkt := buf[:n]

	// 1. RFC 5389 STUN Binding Request (first byte 0x00).
	if n >= 52 && pkt[0] == 0x00 && pkt[1] == 0x01 {
		txID, sid, ok := parseAndVerifySTUNBindingRequest(pkt, &m.keys)
		if !ok {
			return 0, nil, false, false
		}
		now := time.Now().UnixNano()
		sess := m.getOrCreateSession(sid, now)
		sess.touchLeg(sock, raddr, now)
		resp := buildSTUNBindingResponse(&m.keys, txID, raddr)
		_, _ = sock.WriteTo(resp, raddr)
		return 0, nil, true, false
	}

	// 2. RFC 3550 / 3711 SRTP v2 packet (first byte 0x80).
	if n >= webrtcOverhead && pkt[0] == rtpVersionByte {
		sid, seq, payload, ok := decodeWebRTCSRTP(pkt, &m.keys)
		if !ok {
			return 0, nil, false, false
		}
		if seq == 0 || len(payload) == 0 {
			return 0, nil, true, false
		}
		now := time.Now().UnixNano()
		sess := m.getOrCreateSession(sid, now)
		if !sess.recordSRTPAndCheckDup(sock, raddr, seq, now) {
			return 0, nil, true, false
		}
		pLen := len(payload)
		copy(buf[:pLen], payload)
		return pLen, sess.vaddr, true, true
	}

	return 0, nil, false, false
}

func (m *webrtcServerMux) writeSessionPacket(sid [8]byte, p []byte) (int, error) {
	val, exists := m.sessions.Load(sid)
	if !exists {
		return len(p), nil
	}
	sess := val.(*webrtcPeerSession)
	now := time.Now().UnixNano()
	l0, c0, l1, c1, hasPrimary, hasBoth := sess.activeLegs(now)
	if !hasPrimary {
		return len(p), nil
	}

	seq := sess.txSeq.Add(1)
	if seq == 0 {
		seq = sess.txSeq.Add(1)
	}

	sendCopy := func(leg twinLegEndpoint, clk *rtpStreamClock) error {
		need := webrtcOverhead + len(p)
		if need <= 2048 {
			bp := portHopBufPool.Get().(*[]byte)
			pkt, err := encodeWebRTCSRTP((*bp)[:0], &m.keys, clk, sid, seq, p)
			if err != nil {
				portHopBufPool.Put(bp)
				return err
			}
			_, err = leg.sock.WriteTo(pkt, leg.peerAddr)
			portHopBufPool.Put(bp)
			return err
		}
		pkt, err := encodeWebRTCSRTP(nil, &m.keys, clk, sid, seq, p)
		if err != nil {
			return err
		}
		_, err = leg.sock.WriteTo(pkt, leg.peerAddr)
		return err
	}

	err0 := sendCopy(l0, c0)
	if hasBoth && len(p) <= m.maxDupBytes && c1 != nil {
		err1 := sendCopy(l1, c1)
		if err0 != nil && err1 == nil {
			return len(p), nil
		}
	}
	if err0 != nil {
		return 0, err0
	}
	return len(p), nil
}

func (m *webrtcServerMux) sweepIdle(cutoff int64) {
	m.sessions.Range(func(k, v any) bool {
		s := v.(*webrtcPeerSession)
		if s.lastSeen.Load() < cutoff {
			m.sessions.Delete(k)
		}
		return true
	})
}

// WebRTCListenConn implements net.PacketConn for WebRTC STUN + SRTP tunnels.
type WebRTCListenConn struct {
	mux        *webrtcServerMux
	primary    net.PacketConn
	companions []*net.UDPConn
	rxCh       chan portHopRxItem
	rdl        *deadline
	wdl        *deadline
	closed     atomic.Bool
	closedCh   chan struct{}
	once       sync.Once
}

// ListenWebRTC binds a server UDP socket (or multi-port pool when portCount > 1)
// and serves RFC 5389 STUN Binding + RFC 3550/3711 SRTP media packets.
func ListenWebRTC(basePort int, portCount int, psk []byte) (net.PacketConn, error) {
	if basePort < 0 || basePort > 65535 {
		return nil, fmt.Errorf("invalid webrtc basePort %d", basePort)
	}
	if len(psk) == 0 {
		return nil, errors.New("webrtc PSK must not be empty")
	}
	if portCount <= 0 {
		portCount = 1
	}
	addr := net.JoinHostPort("", strconv.Itoa(basePort))
	return newWebRTCListenConnWithParams(addr, portCount, DefaultTwinPathMaxDupBytes, psk, nil)
}

func newWebRTCListenConn(addr string, cfg *Config, avoid map[int]bool) (*WebRTCListenConn, error) {
	portCount := 1
	if cfg.PortHop {
		portCount = cfg.EffectivePortHopPorts()
	} else if cfg.TwinPath {
		portCount = 2
	}
	return newWebRTCListenConnWithParams(addr, portCount, cfg.EffectiveTwinPathMaxBytes(), cfg.secret, avoid)
}

func newWebRTCListenConnWithParams(addr string, portCount int, maxDupBytes int, psk []byte, avoid map[int]bool) (*WebRTCListenConn, error) {
	if len(psk) == 0 {
		return nil, errors.New("webrtc secret must not be empty")
	}
	network := "udp"
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolving webrtc listen addr: %w", err)
	}
	if laddr.IP != nil {
		if laddr.IP.To4() != nil {
			network = "udp4"
		} else if len(laddr.IP) == net.IPv6len {
			network = "udp6"
		}
	}
	primary, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, fmt.Errorf("listening webrtc udp: %w", err)
	}
	tuneUDPSocket(primary)

	c := &WebRTCListenConn{
		mux:      newWebRTCServerMux(psk, maxDupBytes),
		primary:  primary,
		rxCh:     make(chan portHopRxItem, 4096),
		rdl:      newDeadline(),
		wdl:      newDeadline(),
		closedCh: make(chan struct{}),
	}

	if portCount > 1 {
		if ua := primary.LocalAddr().(*net.UDPAddr); ua != nil && ua.Port > 0 {
			for i := 1; i < portCount; i++ {
				port := ua.Port + i
				if port > 65535 || (avoid != nil && avoid[port]) {
					continue
				}
				uc, err := net.ListenUDP(network, &net.UDPAddr{IP: ua.IP, Port: port, Zone: ua.Zone})
				if err != nil {
					continue
				}
				tuneUDPSocket(uc)
				c.companions = append(c.companions, uc)
			}
		}
	}

	go c.readLoop(primary)
	for _, comp := range c.companions {
		go c.readLoop(comp)
	}
	go c.janitorLoop()
	return c, nil
}

func (c *WebRTCListenConn) BoundPorts() []int {
	var out []int
	if ua, ok := c.primary.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		out = append(out, ua.Port)
	}
	for _, comp := range c.companions {
		if ua, ok := comp.LocalAddr().(*net.UDPAddr); ok && ua != nil {
			out = append(out, ua.Port)
		}
	}
	return out
}

func (c *WebRTCListenConn) readLoop(sock net.PacketConn) {
	for {
		bp := portHopBufPool.Get().(*[]byte)
		buf := *bp
		n, raddr, err := sock.ReadFrom(buf)
		if err != nil {
			portHopBufPool.Put(bp)
			if c.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n <= 0 {
			portHopBufPool.Put(bp)
			continue
		}
		pLen, vaddr, _, deliver := c.mux.tryHandlePacket(sock, raddr, buf, n)
		if !deliver {
			portHopBufPool.Put(bp)
			continue
		}
		select {
		case c.rxCh <- portHopRxItem{bufPtr: bp, n: pLen, addr: vaddr}:
		case <-c.closedCh:
			portHopBufPool.Put(bp)
			return
		default:
			portHopBufPool.Put(bp)
		}
	}
}

func (c *WebRTCListenConn) janitorLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			c.mux.sweepIdle(time.Now().Add(-twinSessionIdle).UnixNano())
		}
	}
}

func (c *WebRTCListenConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	select {
	case item := <-c.rxCh:
		buf := *item.bufPtr
		n := item.n
		if n > len(p) {
			n = len(p)
		}
		copy(p[:n], buf[:n])
		portHopBufPool.Put(item.bufPtr)
		return n, item.addr, nil
	case <-c.rdl.wait():
		return 0, nil, timeoutError{}
	case <-c.closedCh:
		return 0, nil, net.ErrClosed
	}
}

func (c *WebRTCListenConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if wa, ok := addr.(webrtcSessionAddr); ok {
		return c.mux.writeSessionPacket(wa.id, p)
	}
	return 0, errors.New("unknown webrtc session address")
}

func (c *WebRTCListenConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
		_ = c.primary.Close()
		for _, comp := range c.companions {
			_ = comp.Close()
		}
	})
	return nil
}

func (c *WebRTCListenConn) LocalAddr() net.Addr                { return c.primary.LocalAddr() }
func (c *WebRTCListenConn) SetDeadline(t time.Time) error      { c.rdl.set(t); c.wdl.set(t); return nil }
func (c *WebRTCListenConn) SetReadDeadline(t time.Time) error  { c.rdl.set(t); return nil }
func (c *WebRTCListenConn) SetWriteDeadline(t time.Time) error { c.wdl.set(t); return nil }

type webrtcClientLeg struct {
	sock   *net.UDPConn
	dst    *net.UDPAddr
	dstIdx int
	clock  *rtpStreamClock
	rxPkts atomic.Uint64
	stunOK atomic.Uint64
}

// WebRTCDialConn implements client-side RFC 5389 STUN + RFC 3550/3711 SRTP framing
// with optional Dynamic Port-Hopping and Twin-Path 1+1 packet duplication.
type WebRTCDialConn struct {
	keys        webrtcKeys
	sessionID   [8]byte
	network     string
	localBind   *net.UDPAddr
	targets     []*net.UDPAddr
	twinPath    bool
	maxDupBytes int
	hopInterval time.Duration
	drainWindow time.Duration

	mu         sync.RWMutex
	legs       [2]*webrtcClientLeg
	portCursor int
	lockBase   bool

	dedupMu sync.Mutex
	dedup   twinSeqWindow
	txSeq   atomic.Uint32

	rxCh     chan portHopRxItem
	rdl      *deadline
	wdl      *deadline
	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

// DialWebRTC opens a WebRTC STUN+SRTP client net.PacketConn to serverAddr:basePort.
func DialWebRTC(serverAddr string, basePort int, hopCount int, twinPath bool, psk []byte) (*WebRTCDialConn, error) {
	if hopCount <= 0 {
		if twinPath {
			hopCount = 2
		} else {
			hopCount = 1
		}
	}
	var hopInt time.Duration
	if hopCount > 2 || (!twinPath && hopCount > 1) {
		hopInt = DefaultPortHopInterval
	}
	addr := net.JoinHostPort(serverAddr, strconv.Itoa(basePort))
	return dialWebRTCInternal(addr, nil, hopCount, hopInt, DefaultPortHopDrainWindow, twinPath, DefaultTwinPathMaxDupBytes, psk)
}

func newWebRTCDialConn(addr string, cfg *Config) (*WebRTCDialConn, error) {
	var localBind *net.UDPAddr
	if src := cfg.sourceFor(addr); src != nil {
		if ta, ok := src.(*net.TCPAddr); ok && len(ta.IP) > 0 {
			localBind = &net.UDPAddr{IP: ta.IP, Zone: ta.Zone}
		}
	}
	portCount := 1
	var hopInterval time.Duration
	if cfg.PortHop {
		portCount = cfg.EffectivePortHopPorts()
		hopInterval = cfg.EffectivePortHopInterval()
	} else if cfg.TwinPath {
		portCount = 2
	}
	return dialWebRTCInternal(addr, localBind, portCount, hopInterval, DefaultPortHopDrainWindow, cfg.TwinPath, cfg.EffectiveTwinPathMaxBytes(), cfg.secret)
}

func dialWebRTCInternal(addr string, localBind *net.UDPAddr, portCount int, hopInterval, drainWindow time.Duration, twinPath bool, maxDupBytes int, psk []byte) (*WebRTCDialConn, error) {
	if len(psk) == 0 {
		return nil, errors.New("webrtc PSK must not be empty")
	}
	if portCount <= 0 {
		portCount = 1
	}
	if maxDupBytes <= 0 {
		maxDupBytes = DefaultTwinPathMaxDupBytes
	}

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving webrtc server %q: %w", addr, err)
	}
	if raddr.Port <= 0 || raddr.Port > 65535 {
		return nil, fmt.Errorf("invalid webrtc port %d", raddr.Port)
	}

	network := "udp4"
	if raddr.IP != nil && raddr.IP.To4() == nil {
		network = "udp6"
	}

	targets := make([]*net.UDPAddr, 0, portCount)
	for i := 0; i < portCount; i++ {
		p := raddr.Port + i
		if p > 65535 {
			break
		}
		ipCopy := make(net.IP, len(raddr.IP))
		copy(ipCopy, raddr.IP)
		targets = append(targets, &net.UDPAddr{IP: ipCopy, Port: p, Zone: raddr.Zone})
	}

	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, fmt.Errorf("generating webrtc session ID: %w", err)
	}

	c := &WebRTCDialConn{
		keys:        deriveWebRTCKeys(psk),
		sessionID:   sid,
		network:     network,
		localBind:   localBind,
		targets:     targets,
		twinPath:    twinPath,
		maxDupBytes: maxDupBytes,
		hopInterval: hopInterval,
		drainWindow: drainWindow,
		rxCh:        make(chan portHopRxItem, 4096),
		rdl:         newDeadline(),
		wdl:         newDeadline(),
		closedCh:    make(chan struct{}),
	}

	leg0, err := c.openLeg(0)
	if err != nil {
		return nil, err
	}
	c.legs[0] = leg0
	go c.readLegLoop(leg0)
	c.sendSTUNCheck(leg0)

	if twinPath {
		idx1 := 0
		if len(targets) > 1 {
			idx1 = 1
		}
		leg1, err := c.openLeg(idx1)
		if err != nil {
			_ = leg0.sock.Close()
			return nil, err
		}
		c.legs[1] = leg1
		c.portCursor = idx1
		go c.readLegLoop(leg1)
		c.sendSTUNCheck(leg1)
		if idx1 > 0 {
			go c.watchHoppedLeg(leg1, 1)
		}
	}

	go c.consentLoop()
	if hopInterval > 0 {
		go c.rotationLoop()
	}

	return c, nil
}

func (c *WebRTCDialConn) openLeg(dstIdx int) (*webrtcClientLeg, error) {
	var bindAddr *net.UDPAddr
	if c.localBind != nil {
		bindAddr = &net.UDPAddr{IP: c.localBind.IP, Port: 0, Zone: c.localBind.Zone}
	}
	sock, err := net.ListenUDP(c.network, bindAddr)
	if err != nil {
		return nil, fmt.Errorf("opening webrtc local udp socket: %w", err)
	}
	tuneUDPSocket(sock)
	if dstIdx < 0 || dstIdx >= len(c.targets) {
		dstIdx = 0
	}
	return &webrtcClientLeg{
		sock:   sock,
		dst:    c.targets[dstIdx],
		dstIdx: dstIdx,
		clock:  newRTPStreamClock(),
	}, nil
}

func (c *WebRTCDialConn) sendSTUNCheck(leg *webrtcClientLeg) {
	if leg == nil {
		return
	}
	if req, _, err := buildSTUNBindingRequest(&c.keys, c.sessionID); err == nil {
		_, _ = leg.sock.WriteToUDP(req, leg.dst)
	}
}

func (c *WebRTCDialConn) consentLoop() {
	ticker := time.NewTicker(webrtcConsentInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			c.mu.RLock()
			l0, l1 := c.legs[0], c.legs[1]
			c.mu.RUnlock()
			c.sendSTUNCheck(l0)
			if l1 != nil {
				c.sendSTUNCheck(l1)
			}
		}
	}
}

func (c *WebRTCDialConn) watchHoppedLeg(leg *webrtcClientLeg, slot int) {
	timer := time.NewTimer(defaultPortHopFallbackWait)
	defer timer.Stop()
	select {
	case <-c.closedCh:
		return
	case <-timer.C:
	}
	if leg.rxPkts.Load() > 0 {
		return
	}
	c.mu.Lock()
	if c.closed.Load() || c.legs[slot] != leg || leg.rxPkts.Load() > 0 {
		c.mu.Unlock()
		return
	}
	c.lockBase = true
	rebound, err := c.openLeg(0)
	if err != nil {
		c.mu.Unlock()
		return
	}
	old := c.legs[slot]
	c.legs[slot] = rebound
	c.mu.Unlock()

	go c.readLegLoop(rebound)
	c.sendSTUNCheck(rebound)
	c.retireLeg(old)
}

func (c *WebRTCDialConn) rotationLoop() {
	ticker := time.NewTicker(c.hopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			c.rotate()
		}
	}
}

func (c *WebRTCDialConn) rotate() {
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return
	}
	idx0 := 0
	if !c.lockBase && len(c.targets) > 1 {
		c.portCursor = (c.portCursor + 1) % len(c.targets)
		idx0 = c.portCursor
	}
	new0, err := c.openLeg(idx0)
	if err != nil {
		c.mu.Unlock()
		return
	}
	var new1 *webrtcClientLeg
	idx1 := 0
	if c.twinPath {
		if !c.lockBase && len(c.targets) > 1 {
			idx1 = (idx0 + 1) % len(c.targets)
		}
		new1, err = c.openLeg(idx1)
		if err != nil {
			_ = new0.sock.Close()
			c.mu.Unlock()
			return
		}
	}
	old0, old1 := c.legs[0], c.legs[1]
	c.legs[0], c.legs[1] = new0, new1
	c.mu.Unlock()

	go c.readLegLoop(new0)
	c.sendSTUNCheck(new0)
	if idx0 > 0 {
		go c.watchHoppedLeg(new0, 0)
	}
	if new1 != nil {
		go c.readLegLoop(new1)
		c.sendSTUNCheck(new1)
		if idx1 > 0 {
			go c.watchHoppedLeg(new1, 1)
		}
	}
	c.retireLeg(old0)
	c.retireLeg(old1)
}

func (c *WebRTCDialConn) retireLeg(leg *webrtcClientLeg) {
	if leg == nil {
		return
	}
	if c.drainWindow <= 0 {
		_ = leg.sock.Close()
		return
	}
	go func() {
		t := time.NewTimer(c.drainWindow)
		defer t.Stop()
		select {
		case <-c.closedCh:
		case <-t.C:
		}
		_ = leg.sock.Close()
	}()
}

func (c *WebRTCDialConn) readLegLoop(leg *webrtcClientLeg) {
	for {
		bp := portHopBufPool.Get().(*[]byte)
		buf := *bp
		n, _, err := leg.sock.ReadFromUDP(buf)
		if err != nil {
			portHopBufPool.Put(bp)
			return
		}
		if n <= 0 {
			portHopBufPool.Put(bp)
			continue
		}
		pkt := buf[:n]

		// STUN Binding Success Response (0x0101).
		if n >= 56 && pkt[0] == 0x01 && pkt[1] == 0x01 {
			if parseAndVerifySTUNBindingResponse(pkt, &c.keys) {
				leg.rxPkts.Add(1)
				leg.stunOK.Add(1)
			}
			portHopBufPool.Put(bp)
			continue
		}

		// SRTP v2 packet (0x80).
		sid, seq, payload, ok := decodeWebRTCSRTP(pkt, &c.keys)
		if !ok || sid != c.sessionID {
			portHopBufPool.Put(bp)
			continue
		}
		leg.rxPkts.Add(1)
		if seq == 0 || len(payload) == 0 {
			portHopBufPool.Put(bp)
			continue
		}

		c.dedupMu.Lock()
		first := c.dedup.Accept(seq)
		c.dedupMu.Unlock()
		if !first {
			portHopBufPool.Put(bp)
			continue
		}

		pLen := len(payload)
		copy(buf[:pLen], payload)
		select {
		case c.rxCh <- portHopRxItem{bufPtr: bp, n: pLen, addr: c.targets[0]}:
		case <-c.closedCh:
			portHopBufPool.Put(bp)
			return
		default:
			portHopBufPool.Put(bp)
		}
	}
}

func (c *WebRTCDialConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	select {
	case item := <-c.rxCh:
		buf := *item.bufPtr
		n := item.n
		if n > len(p) {
			n = len(p)
		}
		copy(p[:n], buf[:n])
		portHopBufPool.Put(item.bufPtr)
		return n, item.addr, nil
	case <-c.rdl.wait():
		return 0, nil, timeoutError{}
	case <-c.closedCh:
		return 0, nil, net.ErrClosed
	}
}

func (c *WebRTCDialConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.RLock()
	l0, l1 := c.legs[0], c.legs[1]
	c.mu.RUnlock()
	if l0 == nil && l1 == nil {
		return 0, net.ErrClosed
	}

	seq := c.txSeq.Add(1)
	if seq == 0 {
		seq = c.txSeq.Add(1)
	}

	sendOn := func(leg *webrtcClientLeg) error {
		if leg == nil {
			return net.ErrClosed
		}
		need := webrtcOverhead + len(p)
		if need <= 2048 {
			bp := portHopBufPool.Get().(*[]byte)
			pkt, err := encodeWebRTCSRTP((*bp)[:0], &c.keys, leg.clock, c.sessionID, seq, p)
			if err != nil {
				portHopBufPool.Put(bp)
				return err
			}
			_, err = leg.sock.WriteToUDP(pkt, leg.dst)
			portHopBufPool.Put(bp)
			return err
		}
		pkt, err := encodeWebRTCSRTP(nil, &c.keys, leg.clock, c.sessionID, seq, p)
		if err != nil {
			return err
		}
		_, err = leg.sock.WriteToUDP(pkt, leg.dst)
		return err
	}

	if c.twinPath && len(p) <= c.maxDupBytes && l0 != nil && l1 != nil {
		err0 := sendOn(l0)
		err1 := sendOn(l1)
		if err0 != nil && err1 != nil {
			return 0, err0
		}
		return len(p), nil
	}

	chosen := l0
	if chosen == nil || (l1 != nil && l0.rxPkts.Load() == 0 && l1.rxPkts.Load() > 0) {
		chosen = l1
	}
	if err := sendOn(chosen); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WebRTCDialConn) STUNResponsesReceived() uint64 {
	c.mu.RLock()
	l0, l1 := c.legs[0], c.legs[1]
	c.mu.RUnlock()
	var total uint64
	if l0 != nil {
		total += l0.stunOK.Load()
	}
	if l1 != nil {
		total += l1.stunOK.Load()
	}
	return total
}

func (c *WebRTCDialConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
		c.mu.Lock()
		l0, l1 := c.legs[0], c.legs[1]
		c.legs[0], c.legs[1] = nil, nil
		c.mu.Unlock()
		if l0 != nil {
			_ = l0.sock.Close()
		}
		if l1 != nil {
			_ = l1.sock.Close()
		}
	})
	return nil
}

func (c *WebRTCDialConn) LocalAddr() net.Addr {
	c.mu.RLock()
	l0 := c.legs[0]
	c.mu.RUnlock()
	if l0 != nil {
		return l0.sock.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *WebRTCDialConn) RemoteAddr() net.Addr               { return c.targets[0] }
func (c *WebRTCDialConn) SetDeadline(t time.Time) error      { c.rdl.set(t); c.wdl.set(t); return nil }
func (c *WebRTCDialConn) SetReadDeadline(t time.Time) error  { c.rdl.set(t); return nil }
func (c *WebRTCDialConn) SetWriteDeadline(t time.Time) error { c.wdl.set(t); return nil }
