package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultSpoofSNI is the default whitelisted SNI sent in decoy ClientHello packets.
	DefaultSpoofSNI = "challenges.cloudflare.com"
	// DefaultSpoofIP is the default whitelisted IPv4 address used for source IP spoofing.
	DefaultSpoofIP = "104.18.4.130"

	spoofHeaderSize = 8
	spoofFlagRaw    = 0x01
	spoofFlagEcho   = 0x02
	spoofFlagDecoy  = 0x80
)

// WhitelistedSNIs is the curated list of commonly whitelisted SNI hostnames
// that pass strict DPI filtering (Cloudflare Turnstile/challenges, Google reCAPTCHA,
// common CDNs, and domestic payment gateways).
var WhitelistedSNIs = []string{
	"challenges.cloudflare.com",
	"www.recaptcha.net",
	"security.vercel.com",
	"cdnjs.cloudflare.com",
	"cdn.jsdelivr.net",
	"cloudflare-dns.com",
	"one.one.one.one",
	"radar.cloudflare.com",
	"www.google.com",
	"fonts.gstatic.com",
	"unpkg.com",
	"shaparak.ir",
}

// BuildDecoyClientHello constructs a realistic, standards-compliant TLS 1.3
// ClientHello record advertising the given SNI hostname.
func BuildDecoyClientHello(sni string) []byte {
	sni = strings.TrimSpace(sni)
	if sni == "" {
		sni = DefaultSpoofSNI
	}
	sniBytes := []byte(sni)

	randomBytes := make([]byte, 32)
	sessionID := make([]byte, 32)
	keySharePub := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	_, _ = rand.Read(sessionID)
	_, _ = rand.Read(keySharePub)

	// Build extensions block
	var exts []byte
	appendExt := func(extType uint16, body []byte) {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], extType)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
		exts = append(exts, hdr[:]...)
		exts = append(exts, body...)
	}

	// 1. server_name (0x0000)
	sniExt := make([]byte, 5+len(sniBytes))
	binary.BigEndian.PutUint16(sniExt[0:2], uint16(3+len(sniBytes)))
	sniExt[2] = 0x00 // host_name type
	binary.BigEndian.PutUint16(sniExt[3:5], uint16(len(sniBytes)))
	copy(sniExt[5:], sniBytes)
	appendExt(0x0000, sniExt)

	// 2. extended_master_secret (0x0017)
	appendExt(0x0017, nil)

	// 3. renegotiation_info (0xff01)
	appendExt(0xff01, []byte{0x00})

	// 4. supported_groups (0x000a): X25519 (0x001d), secp256r1 (0x0017), secp384r1 (0x0018)
	appendExt(0x000a, []byte{
		0x00, 0x06,
		0x00, 0x1d,
		0x00, 0x17,
		0x00, 0x18,
	})

	// 5. ec_point_formats (0x000b): uncompressed (0x00)
	appendExt(0x000b, []byte{0x01, 0x00})

	// 6. signature_algorithms (0x000d)
	appendExt(0x000d, []byte{
		0x00, 0x0c,
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x08, 0x05, // rsa_pss_rsae_sha384
		0x05, 0x01, // rsa_pkcs1_sha384
	})

	// 7. application_layer_protocol_negotiation (0x0010): "h2", "http/1.1"
	appendExt(0x0010, []byte{
		0x00, 0x0c,
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
	})

	// 8. status_request (0x0005): OCSP
	appendExt(0x0005, []byte{0x01, 0x00, 0x00, 0x00, 0x00})

	// 9. supported_versions (0x002b): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
	appendExt(0x002b, []byte{
		0x04,
		0x03, 0x04,
		0x03, 0x03,
	})

	// 10. psk_key_exchange_modes (0x002d): psk_dhe_ke (0x01)
	appendExt(0x002d, []byte{0x01, 0x01})

	// 11. key_share (0x0033): X25519 (0x001d) + 32-byte public key
	keyShare := make([]byte, 2+4+32)
	binary.BigEndian.PutUint16(keyShare[0:2], 36)
	binary.BigEndian.PutUint16(keyShare[2:4], 0x001d)
	binary.BigEndian.PutUint16(keyShare[4:6], 32)
	copy(keyShare[6:], keySharePub)
	appendExt(0x0033, keyShare)

	// Cipher suites: TLS 1.3 + TLS 1.2 ECDHE suites
	cipherSuites := []byte{
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
		0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
		0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	}

	// Assemble ClientHello body
	var body []byte
	body = append(body, 0x03, 0x03) // client_version: TLS 1.2 (0x0303)
	body = append(body, randomBytes...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)

	var csLen [2]byte
	binary.BigEndian.PutUint16(csLen[:], uint16(len(cipherSuites)))
	body = append(body, csLen[:]...)
	body = append(body, cipherSuites...)

	body = append(body, 0x01, 0x00) // compression_methods: 1 byte (null)

	var extsLen [2]byte
	binary.BigEndian.PutUint16(extsLen[:], uint16(len(exts)))
	body = append(body, extsLen[:]...)
	body = append(body, exts...)

	// Assemble Handshake message (type 0x01 = ClientHello)
	handshakeLen := len(body)
	handshake := make([]byte, 4+handshakeLen)
	handshake[0] = 0x01
	handshake[1] = byte(handshakeLen >> 16)
	handshake[2] = byte(handshakeLen >> 8)
	handshake[3] = byte(handshakeLen)
	copy(handshake[4:], body)

	// Assemble TLS Record (type 0x16 = Handshake, legacy version 0x0301)
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}

// ParseClientHelloSNI extracts the SNI server_name from a TLS ClientHello record.
// Used by unit tests and diagnostic verification.
func ParseClientHelloSNI(record []byte) (string, bool) {
	if len(record) < 5 || record[0] != 0x16 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+recLen || recLen < 4 {
		return "", false
	}
	hs := record[5 : 5+recLen]
	if hs[0] != 0x01 {
		return "", false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen || hsLen < 34 {
		return "", false
	}
	p := hs[4 : 4+hsLen]
	// Skip version (2) + random (32)
	p = p[34:]
	if len(p) < 1 {
		return "", false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return "", false
	}
	p = p[sidLen:]
	csLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < csLen+1 {
		return "", false
	}
	p = p[csLen:]
	compLen := int(p[0])
	p = p[1:]
	if len(p) < compLen+2 {
		return "", false
	}
	p = p[compLen:]
	extsLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < extsLen {
		return "", false
	}
	p = p[:extsLen]
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[0:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < extLen {
			return "", false
		}
		extBody := p[:extLen]
		p = p[extLen:]
		if extType == 0x0000 && len(extBody) >= 5 {
			nameType := extBody[2]
			nameLen := int(binary.BigEndian.Uint16(extBody[3:5]))
			if nameType == 0x00 && len(extBody) >= 5+nameLen {
				return string(extBody[5 : 5+nameLen]), true
			}
		}
	}
	return "", false
}

// buildIPv4UDPPacket constructs a raw IPv4 + UDP packet with valid IPv4 and UDP checksums.
func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, ttl int, payload []byte) ([]byte, error) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("IPv4 addresses required for raw UDP spoofing")
	}
	if ttl <= 0 || ttl > 255 {
		ttl = 64
	}
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	if totalLen > 65535 {
		return nil, errors.New("UDP payload too large for IPv4 packet")
	}

	pkt := make([]byte, totalLen)
	// IPv4 Header (20 bytes)
	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	var idBuf [2]byte
	_, _ = rand.Read(idBuf[:])
	pkt[4] = idBuf[0]
	pkt[5] = idBuf[1]
	pkt[6] = 0x40 // Don't Fragment
	pkt[7] = 0x00
	pkt[8] = byte(ttl)
	pkt[9] = 17 // IPPROTO_UDP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:20]))

	// UDP Header (8 bytes)
	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)
	csum := tcpUDPChecksum(src4, dst4, 17, pkt[20:])
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[26:28], csum)
	return pkt, nil
}

// buildIPv4TCPPacket constructs a raw IPv4 + TCP PSH|ACK packet for decoy ClientHello injection.
func buildIPv4TCPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, seq, ack uint32, ttl int, corruptChecksum bool, payload []byte) ([]byte, error) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("IPv4 addresses required for raw TCP decoy injection")
	}
	if ttl <= 0 || ttl > 255 {
		ttl = 64
	}
	tcpLen := 20 + len(payload)
	totalLen := 20 + tcpLen
	if totalLen > 65535 {
		return nil, errors.New("TCP payload too large for IPv4 packet")
	}

	pkt := make([]byte, totalLen)
	// IPv4 Header (20 bytes)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	var idBuf [2]byte
	_, _ = rand.Read(idBuf[:])
	pkt[4] = idBuf[0]
	pkt[5] = idBuf[1]
	pkt[6] = 0x40 // DF
	pkt[7] = 0x00
	pkt[8] = byte(ttl)
	pkt[9] = 6 // IPPROTO_TCP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:20]))

	// TCP Header (20 bytes)
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // Data offset: 5 (20 bytes)
	tcp[13] = 0x18 // Flags: PSH (0x08) | ACK (0x10)
	binary.BigEndian.PutUint16(tcp[14:16], 512)
	copy(tcp[20:], payload)

	csum := tcpUDPChecksum(src4, dst4, 6, tcp)
	if corruptChecksum {
		csum ^= 0xffff
		if csum == 0 {
			csum = 0xbeef
		}
	}
	binary.BigEndian.PutUint16(tcp[16:18], csum)
	return pkt, nil
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpUDPChecksum(src4, dst4 net.IP, proto byte, segment []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst4[2:4]))
	sum += uint32(proto)
	sum += uint32(len(segment))

	for i := 0; i+1 < len(segment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i : i+2]))
	}
	if len(segment)%2 == 1 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func deriveSpoofMask(secret string) [spoofHeaderSize]byte {
	sum := sha256.Sum256([]byte("pb-spoof-v1:" + secret))
	var mask [spoofHeaderSize]byte
	copy(mask[:], sum[:spoofHeaderSize])
	return mask
}

func isDecoyClientHello(b []byte) bool {
	return len(b) >= 44 &&
		b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x01 &&
		b[5] == 0x01 && b[9] == 0x03 && b[10] == 0x03
}

// spoofPacketConn wraps an unconnected *net.UDPConn so KCP can send and receive
// UDP packets whose IPv4 source address is forged to a whitelisted IP (e.g. 104.18.4.130).
// It automatically handles both mutual bidirectional IP spoofing and asymmetric setups
// where only one side's ISP allows outbound source IP spoofing.
type spoofPacketConn struct {
	udpConn    *net.UDPConn
	rawFD      int
	spoofIP    net.IP
	localIP    [4]byte
	localPt    int
	mask       [spoofHeaderSize]byte
	spoofSNI   string
	allowPlain bool
	plainPeers sync.Map

	mu          sync.RWMutex
	defaultPeer *net.UDPAddr
	firstRawTx  time.Time
	lastDecoyAt time.Time
	rxConfirmed uint32
	txConfirmed uint32
	peerGotRaw  uint32
	rawFallback uint32
	closed      uint32
}

func newSpoofPacketConn(udpConn *net.UDPConn, cfg *Config, defaultPeer *net.UDPAddr) (*spoofPacketConn, error) {
	spoofIPStr := cfg.EffectiveSpoofIP()
	spoofIP := net.ParseIP(spoofIPStr).To4()
	if spoofIP == nil {
		spoofIP = net.ParseIP(DefaultSpoofIP).To4()
	}

	var localPort int
	var localIP [4]byte
	if la, ok := udpConn.LocalAddr().(*net.UDPAddr); ok && la != nil {
		localPort = la.Port
		if ip4 := la.IP.To4(); ip4 != nil && !ip4.IsUnspecified() {
			copy(localIP[:], ip4)
		}
	}
	if defaultPeer != nil && localIP == [4]byte{} {
		if outboundIP := detectOutboundIPv4(defaultPeer.IP); outboundIP != nil {
			copy(localIP[:], outboundIP)
		}
	}

	rawFD, err := openRawSpoofSocket()
	if err != nil {
		rawFD = -1
	}

	c := &spoofPacketConn{
		udpConn:     udpConn,
		rawFD:       rawFD,
		spoofIP:     spoofIP,
		localIP:     localIP,
		localPt:     localPort,
		mask:        deriveSpoofMask(string(cfg.secret)),
		spoofSNI:    cfg.EffectiveSpoofSNI(),
		allowPlain:  cfg.allowPlainKCP,
		defaultPeer: defaultPeer,
	}
	if rawFD < 0 {
		atomic.StoreUint32(&c.rawFallback, 1)
	}
	return c, nil
}

func detectOutboundIPv4(dst net.IP) net.IP {
	if dst == nil {
		return nil
	}
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: 443})
	if err != nil {
		return nil
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok && la != nil {
		return la.IP.To4()
	}
	return nil
}

func (c *spoofPacketConn) encodePacket(payload []byte, flags byte) []byte {
	c.mu.RLock()
	lip := c.localIP
	c.mu.RUnlock()

	out := make([]byte, spoofHeaderSize+len(payload))
	out[0] = 'P' ^ c.mask[0]
	out[1] = 'B' ^ c.mask[1]
	out[2] = 'S' ^ c.mask[2]
	out[3] = flags ^ c.mask[3]
	out[4] = lip[0] ^ c.mask[4]
	out[5] = lip[1] ^ c.mask[5]
	out[6] = lip[2] ^ c.mask[6]
	out[7] = lip[3] ^ c.mask[7]
	copy(out[spoofHeaderSize:], payload)
	return out
}

func (c *spoofPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+spoofHeaderSize+64)
	for {
		n, addr, err := c.udpConn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if isDecoyClientHello(buf[:n]) {
			continue
		}
		if n < spoofHeaderSize || (buf[0]^c.mask[0]) != 'P' || (buf[1]^c.mask[1]) != 'B' || (buf[2]^c.mask[2]) != 'S' {
			if c.allowPlain && n > 0 {
				if addr != nil {
					c.plainPeers.Store(addr.String(), true)
				}
				if n > len(p) {
					n = len(p)
				}
				copy(p[:n], buf[:n])
				return n, addr, nil
			}
			// Ignore decoy ClientHello or stray non-PortBridge datagrams.
			continue
		}
		flags := buf[3] ^ c.mask[3]
		if flags&spoofFlagDecoy != 0 {
			continue
		}
		var senderIP [4]byte
		senderIP[0] = buf[4] ^ c.mask[4]
		senderIP[1] = buf[5] ^ c.mask[5]
		senderIP[2] = buf[6] ^ c.mask[6]
		senderIP[3] = buf[7] ^ c.mask[7]

		atomic.StoreUint32(&c.rxConfirmed, 1)
		if flags&spoofFlagRaw != 0 {
			atomic.StoreUint32(&c.peerGotRaw, 1)
		}
		if flags&spoofFlagEcho != 0 {
			atomic.StoreUint32(&c.txConfirmed, 1)
		}

		// Determine the real peer UDPAddr to present to KCP and record for replies.
		peerAddr := addr
		c.mu.RLock()
		defPeer := c.defaultPeer
		c.mu.RUnlock()

		if senderIP != ([4]byte{}) {
			peerAddr = &net.UDPAddr{
				IP:   net.IPv4(senderIP[0], senderIP[1], senderIP[2], senderIP[3]),
				Port: addr.Port,
			}
			c.mu.Lock()
			if c.defaultPeer == nil {
				c.defaultPeer = peerAddr
			}
			if c.localIP == ([4]byte{}) {
				if outIP := detectOutboundIPv4(peerAddr.IP); outIP != nil {
					copy(c.localIP[:], outIP)
				}
			}
			c.mu.Unlock()
		} else if defPeer != nil {
			peerAddr = &net.UDPAddr{IP: defPeer.IP, Port: addr.Port}
		}

		if c.allowPlain && peerAddr != nil {
			c.plainPeers.Delete(peerAddr.String())
		}

		payloadLen := n - spoofHeaderSize
		if payloadLen > len(p) {
			payloadLen = len(p)
		}
		copy(p[:payloadLen], buf[spoofHeaderSize:spoofHeaderSize+payloadLen])
		return payloadLen, peerAddr, nil
	}
}

func (c *spoofPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		resolved, err := net.ResolveUDPAddr("udp4", addr.String())
		if err != nil {
			return 0, err
		}
		udpAddr = resolved
	}
	if c.allowPlain {
		if _, isPlain := c.plainPeers.Load(udpAddr.String()); isPlain {
			return c.udpConn.WriteToUDP(p, udpAddr)
		}
	}

	c.mu.RLock()
	if c.defaultPeer != nil && udpAddr.IP.Equal(c.spoofIP) {
		udpAddr = &net.UDPAddr{IP: c.defaultPeer.IP, Port: udpAddr.Port}
	}
	needDecoy := c.spoofSNI != "" && (c.lastDecoyAt.IsZero() || time.Since(c.lastDecoyAt) > 25*time.Second)
	c.mu.RUnlock()

	if needDecoy {
		c.mu.Lock()
		if c.lastDecoyAt.IsZero() || time.Since(c.lastDecoyAt) > 25*time.Second {
			c.lastDecoyAt = time.Now()
			decoy := BuildDecoyClientHello(c.spoofSNI)
			sentRawDecoy := false
			if c.rawFD >= 0 && c.spoofIP != nil && atomic.LoadUint32(&c.rawFallback) == 0 {
				if err := sendRawSpoofedUDP(c.rawFD, c.spoofIP, udpAddr.IP, c.localPt, udpAddr.Port, 64, decoy); err == nil {
					sentRawDecoy = true
				}
			}
			if !sentRawDecoy {
				_, _ = c.udpConn.WriteToUDP(decoy, udpAddr)
			}
		}
		c.mu.Unlock()
	}

	var baseFlags byte
	if atomic.LoadUint32(&c.rxConfirmed) != 0 {
		baseFlags |= spoofFlagEcho
	}

	// If we have a raw socket, check whether raw spoofed outbound is working or if
	// the local ISP blocks outbound spoofed IPs (asymmetric BCP38).
	if c.rawFD >= 0 && atomic.LoadUint32(&c.rawFallback) == 0 {
		c.mu.Lock()
		if c.firstRawTx.IsZero() {
			c.firstRawTx = time.Now()
		}
		rawElapsed := time.Since(c.firstRawTx)
		c.mu.Unlock()

		fallbackTimeout := 800 * time.Millisecond
		if atomic.LoadUint32(&c.rxConfirmed) != 0 {
			fallbackTimeout = 400 * time.Millisecond
		}
		if atomic.LoadUint32(&c.txConfirmed) == 0 && rawElapsed > fallbackTimeout {
			// Peer has not echoed receipt of our raw-spoofed packets; enable asymmetric
			// fallback so outbound uses normal UDP while inbound still accepts raw spoofed packets.
			atomic.StoreUint32(&c.rawFallback, 1)
		} else {
			pkt := c.encodePacket(p, baseFlags|spoofFlagRaw)
			if err := sendRawSpoofedUDP(c.rawFD, c.spoofIP, udpAddr.IP, c.localPt, udpAddr.Port, 64, pkt); err == nil {
				return len(p), nil
			}
			atomic.StoreUint32(&c.rawFallback, 1)
		}
	}

	pkt := c.encodePacket(p, baseFlags)
	if _, err := c.udpConn.WriteToUDP(pkt, udpAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *spoofPacketConn) Close() error {
	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		if c.rawFD >= 0 {
			closeRawSpoofSocket(c.rawFD)
		}
	}
	return c.udpConn.Close()
}

func (c *spoofPacketConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

func (c *spoofPacketConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c *spoofPacketConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *spoofPacketConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// SNIScanResult reports whether a candidate whitelisted SNI passed DPI inspection
// and how fast the handshake completed.
type SNIScanResult struct {
	SNI       string `json:"sni"`
	Reachable bool   `json:"reachable"`
	RTTMs     int64  `json:"rtt_ms"`
	Error     string `json:"error,omitempty"`
}

// ScanWhitelistedSNIs tests a list of candidate SNI hostnames from the current server
// by performing a TLS ClientHello handshake to targetAddr (or 1.1.1.1:443 / the SNI host)
// and ranking working SNIs by handshake RTT.
func ScanWhitelistedSNIs(ctx context.Context, targetAddr string, candidates []string) []SNIScanResult {
	if len(candidates) == 0 {
		candidates = WhitelistedSNIs
	}
	results := make([]SNIScanResult, len(candidates))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	for i, rawSNI := range candidates {
		sni := strings.TrimSpace(rawSNI)
		if sni == "" {
			continue
		}
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = SNIScanResult{SNI: host, Error: ctx.Err().Error()}
				return
			}

			dialTarget := strings.TrimSpace(targetAddr)
			if dialTarget == "" {
				dialTarget = net.JoinHostPort(host, "443")
			} else if _, _, err := net.SplitHostPort(dialTarget); err != nil {
				dialTarget = net.JoinHostPort(dialTarget, "443")
			}

			probeCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
			defer cancel()

			start := time.Now()
			d := &net.Dialer{Timeout: 3500 * time.Millisecond}
			rawConn, err := d.DialContext(probeCtx, "tcp", dialTarget)
			if err != nil {
				results[idx] = SNIScanResult{SNI: host, Error: err.Error()}
				return
			}
			defer rawConn.Close()
			_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))

			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true, //nolint:gosec // probing DPI pass-through of ClientHello SNI
				MinVersion:         tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(probeCtx); err != nil {
				results[idx] = SNIScanResult{SNI: host, Error: err.Error()}
				return
			}
			rtt := time.Since(start).Milliseconds()
			if rtt <= 0 {
				rtt = 1
			}
			results[idx] = SNIScanResult{
				SNI:       host,
				Reachable: true,
				RTTMs:     rtt,
			}
		}(i, sni)
	}
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Reachable != results[j].Reachable {
			return results[i].Reachable
		}
		if results[i].Reachable && results[i].RTTMs != results[j].RTTMs {
			return results[i].RTTMs < results[j].RTTMs
		}
		return results[i].SNI < results[j].SNI
	})
	return results
}

// SpoofProbeListenResult reports what packets arrived during an IP-spoof capability test.
type SpoofProbeListenResult struct {
	ReceivedSpoofed bool   `json:"received_spoofed"`
	ReceivedNormal  bool   `json:"received_normal"`
	ObservedSpoofIP string `json:"observed_spoof_ip,omitempty"`
	ObservedRealIP  string `json:"observed_real_ip,omitempty"`
	Error           string `json:"error,omitempty"`
}

// SpoofProbeSendResult reports whether raw spoofed and normal UDP probe packets were sent.
type SpoofProbeSendResult struct {
	RawSent    bool   `json:"raw_sent"`
	NormalSent bool   `json:"normal_sent"`
	RawError   string `json:"raw_error,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RunSpoofProbeListener listens on listenAddr for raw-spoofed and normal UDP probe packets
// carrying the given token.
func RunSpoofProbeListener(ctx context.Context, listenAddr, token string, timeout time.Duration) SpoofProbeListenResult {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return SpoofProbeListenResult{Error: err.Error()}
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return SpoofProbeListenResult{Error: err.Error()}
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)

	rawTag := "PB-SPOOF-PROBE:" + token + ":RAW"
	normTag := "PB-SPOOF-PROBE:" + token + ":NORMAL"

	var res SpoofProbeListenResult
	buf := make([]byte, 512)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		msg := string(buf[:n])
		switch msg {
		case rawTag:
			res.ReceivedSpoofed = true
			if addr != nil {
				res.ObservedSpoofIP = addr.IP.String()
			}
		case normTag:
			res.ReceivedNormal = true
			if addr != nil {
				res.ObservedRealIP = addr.IP.String()
			}
		}
		if res.ReceivedSpoofed && res.ReceivedNormal {
			break
		}
	}
	return res
}

// SendSpoofProbePackets sends both raw source-IP-spoofed UDP packets (SrcIP = spoofIP)
// and normal UDP packets to targetAddr with the given token so the listener can verify
// whether outbound source IP spoofing is permitted by the VPS provider.
func SendSpoofProbePackets(targetAddr, spoofIPStr, token string) SpoofProbeSendResult {
	var res SpoofProbeSendResult
	dstAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		res.Error = fmt.Sprintf("resolve target %q: %v", targetAddr, err)
		return res
	}
	if strings.TrimSpace(spoofIPStr) == "" {
		spoofIPStr = DefaultSpoofIP
	}
	spoofIP := net.ParseIP(strings.TrimSpace(spoofIPStr)).To4()
	if spoofIP == nil {
		res.Error = fmt.Sprintf("invalid spoof IP %q", spoofIPStr)
		return res
	}

	rawPayload := []byte("PB-SPOOF-PROBE:" + token + ":RAW")
	normPayload := []byte("PB-SPOOF-PROBE:" + token + ":NORMAL")

	rawFD, err := openRawSpoofSocket()
	if err != nil {
		res.RawError = err.Error()
	} else {
		defer closeRawSpoofSocket(rawFD)
		var sendErr error
		for i := 0; i < 3; i++ {
			if err := sendRawSpoofedUDP(rawFD, spoofIP, dstAddr.IP, 44300+i, dstAddr.Port, 64, rawPayload); err != nil {
				sendErr = err
			} else {
				res.RawSent = true
			}
			time.Sleep(15 * time.Millisecond)
		}
		if !res.RawSent && sendErr != nil {
			res.RawError = sendErr.Error()
		}
	}

	uConn, err := net.DialUDP("udp4", nil, dstAddr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer uConn.Close()
	for i := 0; i < 3; i++ {
		if _, err := uConn.Write(normPayload); err == nil {
			res.NormalSent = true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return res
}
