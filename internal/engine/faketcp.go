package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	fakeTCPHeaderLen      = 20
	fakeTCPInnerHeaderLen = 8

	fakeTCPFlagSYN    byte = 0x02
	fakeTCPFlagPSHACK byte = 0x18

	fakeTCPDirC2S byte = 0x01
	fakeTCPDirS2C byte = 0x02
)

var fakeTCPMagic = [3]byte{'P', 'B', 'F'}

type fakeTCPPeerState struct {
	seq       atomic.Uint32
	peerSeq   atomic.Uint32
	outerPort atomic.Uint32
	localIP   net.IP
}

// fakeTCPPacketConn implements net.PacketConn over raw IPv4 TCP segments
// (PSH|ACK with advancing sequence and acknowledgment numbers) so KCP + FEC
// streams look like active TCP sessions on the wire while avoiding kernel TCP
// head-of-line blocking and handshake filters.
type fakeTCPPacketConn struct {
	conn       *net.IPConn
	isServer   bool
	localIP    net.IP
	localPort  uint16 // Virtual KCP port (and server listen port)
	outerPort  atomic.Uint32
	txPkts     atomic.Uint32
	remoteIP   net.IP
	remotePort uint16
	seq        atomic.Uint32
	peerSeq    atomic.Uint32
	mask       [fakeTCPInnerHeaderLen]byte
	peers      sync.Map // string(ip:virtualPort) -> *fakeTCPPeerState
	rstCleanup func()
	closeOnce  sync.Once
}

func deriveFakeTCPMask(secret []byte) [fakeTCPInnerHeaderLen]byte {
	h := sha256.Sum256(append([]byte("portbridge-faketcp-v1:"), secret...))
	var mask [fakeTCPInnerHeaderLen]byte
	copy(mask[:], h[:fakeTCPInnerHeaderLen])
	return mask
}

func randomUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v < 65536 {
		v += 65536
	}
	return v
}

func installFakeTCPRSTDrop(port uint16, matchDest bool) func() {
	if port == 0 || os.Geteuid() != 0 {
		return func() {}
	}
	outFlag := "--sport"
	inFlag := "--dport"
	if matchDest {
		outFlag = "--dport"
		inFlag = "--sport"
	}
	portStr := strconv.Itoa(int(port))
	addedRST := false
	if exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", outFlag, portStr, "--tcp-flags", "RST", "RST", "-j", "DROP").Run() != nil {
		if exec.Command("iptables", "-I", "OUTPUT", "1", "-p", "tcp", outFlag, portStr, "--tcp-flags", "RST", "RST", "-j", "DROP").Run() == nil {
			addedRST = true
		}
	}
	addedPreRaw := false
	if exec.Command("iptables", "-t", "raw", "-C", "PREROUTING", "-p", "tcp", inFlag, portStr, "-j", "CT", "--notrack").Run() != nil {
		if exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "1", "-p", "tcp", inFlag, portStr, "-j", "CT", "--notrack").Run() == nil {
			addedPreRaw = true
		}
	}
	addedOutRaw := false
	if exec.Command("iptables", "-t", "raw", "-C", "OUTPUT", "-p", "tcp", outFlag, portStr, "-j", "CT", "--notrack").Run() != nil {
		if exec.Command("iptables", "-t", "raw", "-I", "OUTPUT", "1", "-p", "tcp", outFlag, portStr, "-j", "CT", "--notrack").Run() == nil {
			addedOutRaw = true
		}
	}
	return func() {
		if addedRST {
			_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", outFlag, portStr, "--tcp-flags", "RST", "RST", "-j", "DROP").Run()
		}
		if addedPreRaw {
			_ = exec.Command("iptables", "-t", "raw", "-D", "PREROUTING", "-p", "tcp", inFlag, portStr, "-j", "CT", "--notrack").Run()
		}
		if addedOutRaw {
			_ = exec.Command("iptables", "-t", "raw", "-D", "OUTPUT", "-p", "tcp", outFlag, portStr, "-j", "CT", "--notrack").Run()
		}
	}
}

func sendLowTTLSYNDecoy(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) {
	rawFD, err := openRawSpoofSocket()
	if err != nil {
		return
	}
	defer closeRawSpoofSocket(rawFD)
	// Send a low-TTL (TTL=3) TCP SYN so local ISP stateful middleboxes see a
	// TCP handshake initiation on the 5-tuple before PSH|ACK segments flow,
	// while expiring before reaching the remote server.
	_ = sendRawTCPPacket(rawFD, srcIP, dstIP, srcPort, dstPort, seq, 0, fakeTCPFlagSYN, 3, nil, false)
}

func newFakeTCPDialConn(addr string, cfg *Config) (*fakeTCPPacketConn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving faketcp target %q: %w", addr, err)
	}
	if raddr.IP == nil || raddr.IP.To4() == nil {
		return nil, fmt.Errorf("faketcp transport requires an IPv4 target address, got %q", addr)
	}
	dstIP := raddr.IP.To4()
	srcIP := detectOutboundIPv4(dstIP)
	if srcIP == nil {
		srcIP = net.IPv4zero
	}

	rawConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("opening raw faketcp socket (requires root/CAP_NET_RAW): %w", err)
	}
	ipConn, ok := rawConn.(*net.IPConn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T for ip4:tcp", rawConn)
	}
	_ = ipConn.SetReadBuffer(4 * 1024 * 1024)
	_ = ipConn.SetWriteBuffer(4 * 1024 * 1024)

	lport := randomEphemeralPort()
	initSeq := randomUint32()
	rport := uint16(raddr.Port)
	cleanup := installFakeTCPRSTDrop(rport, true)

	if !srcIP.IsUnspecified() {
		sendLowTTLSYNDecoy(srcIP, dstIP, lport, rport, initSeq-1)
	}

	c := &fakeTCPPacketConn{
		conn:       ipConn,
		isServer:   false,
		localIP:    srcIP,
		localPort:  lport,
		remoteIP:   dstIP,
		remotePort: rport,
		mask:       deriveFakeTCPMask(cfg.secret),
		rstCleanup: cleanup,
	}
	c.outerPort.Store(uint32(lport))
	c.seq.Store(initSeq)
	c.peerSeq.Store(randomUint32())
	return c, nil
}

func newFakeTCPListenConn(addr string, cfg *Config) (*fakeTCPPacketConn, error) {
	laddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving faketcp listen addr %q: %w", addr, err)
	}
	bindIP := "0.0.0.0"
	localIP := net.IPv4zero
	if laddr.IP != nil && laddr.IP.To4() != nil && !laddr.IP.IsUnspecified() {
		localIP = laddr.IP.To4()
		bindIP = localIP.String()
	}

	rawConn, err := net.ListenPacket("ip4:tcp", bindIP)
	if err != nil {
		return nil, fmt.Errorf("listening raw faketcp socket (requires root/CAP_NET_RAW): %w", err)
	}
	ipConn, ok := rawConn.(*net.IPConn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T for ip4:tcp", rawConn)
	}
	_ = ipConn.SetReadBuffer(4 * 1024 * 1024)
	_ = ipConn.SetWriteBuffer(4 * 1024 * 1024)

	lport := uint16(laddr.Port)
	cleanup := installFakeTCPRSTDrop(lport, false)

	return &fakeTCPPacketConn{
		conn:       ipConn,
		isServer:   true,
		localIP:    localIP,
		localPort:  lport,
		mask:       deriveFakeTCPMask(cfg.secret),
		rstCleanup: cleanup,
	}, nil
}

func encodeFakeTCPFrame(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, dirFlag byte, mask [fakeTCPInnerHeaderLen]byte, payload []byte) []byte {
	return encodeFakeTCPFrameWithOuter(srcIP, dstIP, srcPort, dstPort, srcPort, dstPort, seq, ack, dirFlag, mask, payload)
}

func encodeFakeTCPFrameWithOuter(srcIP, dstIP net.IP, outerSrcPort, outerDstPort, innerSrcPort, innerDstPort uint16, seq, ack uint32, dirFlag byte, mask [fakeTCPInnerHeaderLen]byte, payload []byte) []byte {
	tcpLen := fakeTCPHeaderLen + fakeTCPInnerHeaderLen + len(payload)
	seg := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(seg[0:2], outerSrcPort)
	binary.BigEndian.PutUint16(seg[2:4], outerDstPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = (fakeTCPHeaderLen / 4) << 4
	seg[13] = fakeTCPFlagPSHACK
	binary.BigEndian.PutUint16(seg[14:16], 65535) // Window size

	inner := seg[fakeTCPHeaderLen : fakeTCPHeaderLen+fakeTCPInnerHeaderLen]
	inner[0] = fakeTCPMagic[0]
	inner[1] = fakeTCPMagic[1]
	inner[2] = fakeTCPMagic[2]
	inner[3] = dirFlag
	binary.BigEndian.PutUint16(inner[4:6], innerSrcPort)
	binary.BigEndian.PutUint16(inner[6:8], innerDstPort)
	for i := 0; i < fakeTCPInnerHeaderLen; i++ {
		inner[i] ^= mask[i]
	}

	copy(seg[fakeTCPHeaderLen+fakeTCPInnerHeaderLen:], payload)

	if s4, d4 := srcIP.To4(), dstIP.To4(); s4 != nil && d4 != nil {
		binary.BigEndian.PutUint16(seg[16:18], tcpPseudoChecksum(s4, d4, seg))
	}
	return seg
}

func tcpPseudoChecksum(srcIP, dstIP net.IP, tcpSeg []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += 6 // IPPROTO_TCP
	sum += uint32(len(tcpSeg))

	b := tcpSeg
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func decodeFakeTCPAtOffset(seg []byte, expectedFlag byte, expectedDstPort uint16, mask [fakeTCPInnerHeaderLen]byte) (innerSrcPort, outerSrcPort uint16, seq uint32, payload []byte, ok bool) {
	if len(seg) < fakeTCPHeaderLen+fakeTCPInnerHeaderLen {
		return 0, 0, 0, nil, false
	}
	dataOff := int(seg[12]>>4) * 4
	if dataOff < fakeTCPHeaderLen || len(seg) < dataOff+fakeTCPInnerHeaderLen {
		return 0, 0, 0, nil, false
	}
	flags := seg[13]
	// Ignore RST (0x04) or FIN (0x01) segments
	if (flags&0x04) != 0 || (flags&0x01) != 0 {
		return 0, 0, 0, nil, false
	}

	var hdr [fakeTCPInnerHeaderLen]byte
	for i := 0; i < fakeTCPInnerHeaderLen; i++ {
		hdr[i] = seg[dataOff+i] ^ mask[i]
	}
	if hdr[0] != fakeTCPMagic[0] || hdr[1] != fakeTCPMagic[1] || hdr[2] != fakeTCPMagic[2] {
		return 0, 0, 0, nil, false
	}
	if hdr[3] != expectedFlag {
		return 0, 0, 0, nil, false
	}
	innerDstPort := binary.BigEndian.Uint16(hdr[6:8])
	if expectedDstPort != 0 && innerDstPort != expectedDstPort {
		return 0, 0, 0, nil, false
	}
	outerSrcPort = binary.BigEndian.Uint16(seg[0:2])
	innerSrcPort = binary.BigEndian.Uint16(hdr[4:6])
	seq = binary.BigEndian.Uint32(seg[4:8])
	return innerSrcPort, outerSrcPort, seq, seg[dataOff+fakeTCPInnerHeaderLen:], true
}

func decodeFakeTCPFrame(raw []byte, expectedFlag byte, expectedDstPort uint16, mask [fakeTCPInnerHeaderLen]byte) (srcPort uint16, seq uint32, payload []byte, ok bool) {
	sp, _, s, pl, ok := decodeFakeTCPFrameFull(raw, expectedFlag, expectedDstPort, mask)
	return sp, s, pl, ok
}

func decodeFakeTCPFrameFull(raw []byte, expectedFlag byte, expectedDstPort uint16, mask [fakeTCPInnerHeaderLen]byte) (innerSrcPort, outerSrcPort uint16, seq uint32, payload []byte, ok bool) {
	// 1. Try standard Go IPConn offset (IPv4 header already stripped by runtime)
	if isp, osp, s, pl, ok := decodeFakeTCPAtOffset(raw, expectedFlag, expectedDstPort, mask); ok {
		return isp, osp, s, pl, true
	}
	// 2. Fallback if raw buffer includes a leading IPv4 header
	if len(raw) >= 20 && (raw[0]>>4) == 4 {
		ihl := int(raw[0]&0x0f) * 4
		if ihl >= 20 && len(raw) >= ihl+fakeTCPHeaderLen+fakeTCPInnerHeaderLen {
			return decodeFakeTCPAtOffset(raw[ihl:], expectedFlag, expectedDstPort, mask)
		}
	}
	return 0, 0, 0, nil, false
}

func (c *fakeTCPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 2048)
	expectedFlag := fakeTCPDirS2C
	if c.isServer {
		expectedFlag = fakeTCPDirC2S
	}

	for {
		n, raddr, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		var srcIP net.IP
		switch a := raddr.(type) {
		case *net.IPAddr:
			srcIP = a.IP.To4()
		case *net.UDPAddr:
			srcIP = a.IP.To4()
		}
		if srcIP == nil {
			continue
		}
		if !c.isServer && c.remoteIP != nil && !srcIP.Equal(c.remoteIP) {
			continue
		}

		innerSrcPort, outerSrcPort, peerSeq, payload, ok := decodeFakeTCPFrameFull(buf[:n], expectedFlag, c.localPort, c.mask)
		if !ok {
			continue
		}

		nextAck := peerSeq + uint32(fakeTCPInnerHeaderLen+len(payload))
		uaddr := &net.UDPAddr{IP: srcIP, Port: int(innerSrcPort)}

		if c.isServer {
			key := uaddr.String()
			val, loaded := c.peers.LoadOrStore(key, &fakeTCPPeerState{})
			st := val.(*fakeTCPPeerState)
			if !loaded {
				st.seq.Store(randomUint32())
				if !c.localIP.IsUnspecified() {
					st.localIP = c.localIP
				} else {
					st.localIP = detectOutboundIPv4(srcIP)
				}
			}
			st.outerPort.Store(uint32(outerSrcPort))
			st.peerSeq.Store(nextAck)
		} else {
			c.peerSeq.Store(nextAck)
		}

		copied := copy(p, payload)
		return copied, uaddr, nil
	}
}

func (c *fakeTCPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var dstIP net.IP
	var dstPort uint16

	switch a := addr.(type) {
	case *net.UDPAddr:
		dstIP = a.IP.To4()
		dstPort = uint16(a.Port)
	case *net.IPAddr:
		dstIP = a.IP.To4()
		dstPort = c.remotePort
	default:
		if u, err := net.ResolveUDPAddr("udp4", addr.String()); err == nil && u != nil {
			dstIP = u.IP.To4()
			dstPort = uint16(u.Port)
		}
	}
	if dstIP == nil {
		dstIP = c.remoteIP
	}
	if dstPort == 0 {
		dstPort = c.remotePort
	}
	if dstIP == nil {
		return 0, fmt.Errorf("faketcp WriteTo: missing destination IPv4 address")
	}

	dirFlag := fakeTCPDirC2S
	srcIP := c.localIP
	advance := uint32(fakeTCPInnerHeaderLen + len(p))
	var seq, ack uint32
	outerSrcPort := c.localPort
	outerDstPort := dstPort

	if c.isServer {
		dirFlag = fakeTCPDirS2C
		key := (&net.UDPAddr{IP: dstIP, Port: int(dstPort)}).String()
		if val, ok := c.peers.Load(key); ok {
			st := val.(*fakeTCPPeerState)
			seq = st.seq.Add(advance) - advance
			ack = st.peerSeq.Load()
			if op := uint16(st.outerPort.Load()); op != 0 {
				outerDstPort = op
			}
			if st.localIP != nil {
				srcIP = st.localIP
			}
		} else {
			seq = randomUint32()
			ack = randomUint32()
		}
	} else {
		pktIdx := c.txPkts.Add(1)
		// Rotate the dialer's outer TCP source port every 512 packets (~650 KB)
		// so stateful ISP byte-counters per TCP 5-tuple do not freeze long flows
		// while avoiding excessive port churn during multi-megabyte uploads.
		if pktIdx > 1 && (pktIdx%512) == 1 {
			newPort := randomEphemeralPort()
			c.outerPort.Store(uint32(newPort))
			newSeq := randomUint32()
			c.seq.Store(newSeq + advance)
			seq = newSeq
			if srcIP != nil && !srcIP.IsUnspecified() {
				sendLowTTLSYNDecoy(srcIP, dstIP, newPort, dstPort, newSeq-1)
			}
		} else {
			seq = c.seq.Add(advance) - advance
		}
		outerSrcPort = uint16(c.outerPort.Load())
		if outerSrcPort == 0 {
			outerSrcPort = c.localPort
		}
		ack = c.peerSeq.Load()
	}
	if srcIP == nil || srcIP.IsUnspecified() {
		srcIP = detectOutboundIPv4(dstIP)
	}

	seg := encodeFakeTCPFrameWithOuter(srcIP, dstIP, outerSrcPort, outerDstPort, c.localPort, dstPort, seq, ack, dirFlag, c.mask, p)
	if _, err := c.conn.WriteTo(seg, &net.IPAddr{IP: dstIP}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *fakeTCPPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.rstCleanup != nil {
			c.rstCleanup()
		}
	})
	return c.conn.Close()
}

func (c *fakeTCPPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.localIP, Port: int(c.localPort)}
}

func (c *fakeTCPPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *fakeTCPPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *fakeTCPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *fakeTCPPacketConn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

func (c *fakeTCPPacketConn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}
