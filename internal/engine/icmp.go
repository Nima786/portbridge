package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const (
	icmpTypeEchoReply   byte = 0
	icmpTypeEchoRequest byte = 8

	icmpHeaderLen      = 8
	icmpInnerHeaderLen = 8

	icmpFlagC2S byte = 0x01
	icmpFlagS2C byte = 0x02

	// icmpSocketMark tags raw ICMP packets sent by PortBridge ("pb" = 0x7062)
	// so an iptables OUTPUT rule can drop the Linux kernel's automatic
	// duplicate ICMP Echo Reply reflections without dropping PortBridge's own
	// Echo Reply frames.
	icmpSocketMark = 0x7062
)

var icmpMagic = [3]byte{'P', 'B', 'I'}

type icmpClientMeta struct {
	id  uint16
	seq uint32
}

type icmpRxPkt struct {
	data []byte
	addr *net.UDPAddr
}

type icmpDialHub struct {
	conn  *net.IPConn
	mask  [icmpInnerHeaderLen]byte
	mu    sync.RWMutex
	conns map[uint16]*icmpPacketConn
}

var (
	icmpDialHubsMu sync.Mutex
	icmpDialHubs   = make(map[[icmpInnerHeaderLen]byte]*icmpDialHub)
)

// icmpPacketConn implements net.PacketConn over raw IPv4 ICMP Echo Request
// (Type 8) and Echo Reply (Type 0) packets so KCP + FEC can run directly inside
// ping traffic when TCP and UDP are completely blocked or throttled.
type icmpPacketConn struct {
	conn           *net.IPConn
	hub            *icmpDialHub
	rxCh           chan icmpRxPkt
	closed         chan struct{}
	closeOnce      sync.Once
	readDeadline   atomic.Value // time.Time
	reflectCleanup func()
	isServer       bool
	localIP        net.IP
	localPort      uint16
	remoteIP       net.IP
	remotePort     uint16
	icmpID         uint16
	seq            atomic.Uint32
	mask           [icmpInnerHeaderLen]byte
	clients        sync.Map // string(ip:port) -> *icmpClientMeta
}

func deriveICMPMask(secret []byte) [icmpInnerHeaderLen]byte {
	h := sha256.Sum256(append([]byte("portbridge-icmp-v1:"), secret...))
	var mask [icmpInnerHeaderLen]byte
	copy(mask[:], h[:icmpInnerHeaderLen])
	return mask
}

func randomEphemeralPort() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return 32768 + (binary.BigEndian.Uint16(b[:]) % 28000)
}

func installICMPReflectDrop() func() {
	if os.Geteuid() != 0 {
		return func() {}
	}
	ruleSpec := []string{"-p", "icmp", "--icmp-type", "echo-reply", "-m", "mark", "!", "--mark", "0x7062", "-j", "DROP"}
	checkCmd := exec.Command("iptables", append([]string{"-C", "OUTPUT"}, ruleSpec...)...)
	if checkCmd.Run() == nil {
		return func() {}
	}
	addCmd := exec.Command("iptables", append([]string{"-I", "OUTPUT", "1"}, ruleSpec...)...)
	if addCmd.Run() != nil {
		return func() {}
	}
	return func() {
		_ = exec.Command("iptables", append([]string{"-D", "OUTPUT"}, ruleSpec...)...).Run()
	}
}

func openRawICMPSocket(bindIP string) (*net.IPConn, error) {
	rawConn, err := net.ListenPacket("ip4:icmp", bindIP)
	if err != nil {
		return nil, err
	}
	ipConn, ok := rawConn.(*net.IPConn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T for ip4:icmp", rawConn)
	}
	_ = ipConn.SetReadBuffer(8 * 1024 * 1024)
	_ = ipConn.SetWriteBuffer(8 * 1024 * 1024)
	return ipConn, nil
}

func (h *icmpDialHub) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, raddr, err := h.conn.ReadFrom(buf)
		if err != nil {
			return
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
		_, _, srcPort, dstPort, payload, ok := decodeICMPFrameWithDst(buf[:n], icmpFlagS2C, 0, h.mask)
		if !ok || dstPort == 0 {
			continue
		}
		h.mu.RLock()
		c := h.conns[dstPort]
		h.mu.RUnlock()
		if c == nil {
			continue
		}
		if c.remoteIP != nil && !srcIP.Equal(c.remoteIP) {
			continue
		}
		cp := make([]byte, len(payload))
		copy(cp, payload)
		pkt := icmpRxPkt{
			data: cp,
			addr: &net.UDPAddr{IP: srcIP, Port: int(srcPort)},
		}
		select {
		case c.rxCh <- pkt:
		case <-c.closed:
		default:
		}
	}
}

func newICMPDialConn(addr string, secret []byte) (*icmpPacketConn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving icmp target %q: %w", addr, err)
	}
	if raddr.IP == nil || raddr.IP.To4() == nil {
		return nil, fmt.Errorf("icmp transport requires an IPv4 target address, got %q", addr)
	}
	mask := deriveICMPMask(secret)

	icmpDialHubsMu.Lock()
	defer icmpDialHubsMu.Unlock()

	hub := icmpDialHubs[mask]
	if hub == nil {
		ipConn, err := openRawICMPSocket("0.0.0.0")
		if err != nil {
			return nil, fmt.Errorf("opening raw icmp socket (requires root/CAP_NET_RAW): %w", err)
		}
		_ = setIPConnSocketMark(ipConn, icmpSocketMark)
		hub = &icmpDialHub{
			conn:  ipConn,
			mask:  mask,
			conns: make(map[uint16]*icmpPacketConn),
		}
		icmpDialHubs[mask] = hub
		go hub.readLoop()
	}

	hub.mu.Lock()
	lport := randomEphemeralPort()
	for i := 0; i < 64; i++ {
		if _, exists := hub.conns[lport]; !exists {
			break
		}
		lport = randomEphemeralPort()
	}
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	icmpID := binary.BigEndian.Uint16(idBytes[:])
	if icmpID == 0 {
		icmpID = lport
	}

	c := &icmpPacketConn{
		conn:       hub.conn,
		hub:        hub,
		rxCh:       make(chan icmpRxPkt, 1024),
		closed:     make(chan struct{}),
		isServer:   false,
		localIP:    net.IPv4zero,
		localPort:  lport,
		remoteIP:   raddr.IP.To4(),
		remotePort: uint16(raddr.Port),
		icmpID:     icmpID,
		mask:       mask,
	}
	hub.conns[lport] = c
	hub.mu.Unlock()
	return c, nil
}

func newICMPListenConn(addr string, secret []byte) (*icmpPacketConn, error) {
	laddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving icmp listen addr %q: %w", addr, err)
	}
	bindIP := "0.0.0.0"
	if laddr.IP != nil && laddr.IP.To4() != nil && !laddr.IP.IsUnspecified() {
		bindIP = laddr.IP.To4().String()
	}
	ipConn, err := openRawICMPSocket(bindIP)
	if err != nil {
		return nil, fmt.Errorf("listening raw icmp socket (requires root/CAP_NET_RAW): %w", err)
	}
	cleanup := func() {}
	if setIPConnSocketMark(ipConn, icmpSocketMark) == nil {
		cleanup = installICMPReflectDrop()
	}

	localIP := net.IPv4zero
	if laddr.IP != nil && laddr.IP.To4() != nil {
		localIP = laddr.IP.To4()
	}

	return &icmpPacketConn{
		conn:           ipConn,
		closed:         make(chan struct{}),
		reflectCleanup: cleanup,
		isServer:       true,
		localIP:        localIP,
		localPort:      uint16(laddr.Port),
		mask:           deriveICMPMask(secret),
	}, nil
}

// encodeICMPFrame builds a complete ICMP Echo Request/Reply packet containing
// the 8-byte XOR-masked PortBridge header followed by payload.
func encodeICMPFrame(icmpType byte, id, seq, srcPort, dstPort uint16, dirFlag byte, mask [icmpInnerHeaderLen]byte, payload []byte) []byte {
	total := icmpHeaderLen + icmpInnerHeaderLen + len(payload)
	pkt := make([]byte, total)
	pkt[0] = icmpType
	pkt[1] = 0 // Code 0
	// pkt[2:4] is checksum
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)

	inner := pkt[icmpHeaderLen : icmpHeaderLen+icmpInnerHeaderLen]
	inner[0] = icmpMagic[0]
	inner[1] = icmpMagic[1]
	inner[2] = icmpMagic[2]
	inner[3] = dirFlag
	binary.BigEndian.PutUint16(inner[4:6], srcPort)
	binary.BigEndian.PutUint16(inner[6:8], dstPort)
	for i := 0; i < icmpInnerHeaderLen; i++ {
		inner[i] ^= mask[i]
	}

	copy(pkt[icmpHeaderLen+icmpInnerHeaderLen:], payload)
	csum := internetChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], csum)
	return pkt
}

// decodeICMPFrame extracts the inner PortBridge header and KCP payload from a
// raw ICMP message (with or without a leading IPv4 header).
func decodeICMPFrame(raw []byte, expectedFlag byte, expectedDstPort uint16, mask [icmpInnerHeaderLen]byte) (icmpID, icmpSeq, srcPort uint16, payload []byte, ok bool) {
	id, seq, sPort, _, pl, valid := decodeICMPFrameWithDst(raw, expectedFlag, expectedDstPort, mask)
	return id, seq, sPort, pl, valid
}

func decodeICMPFrameWithDst(raw []byte, expectedFlag byte, expectedDstPort uint16, mask [icmpInnerHeaderLen]byte) (icmpID, icmpSeq, srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(raw) >= 20 && (raw[0]>>4) == 4 {
		ihl := int(raw[0]&0x0f) * 4
		if ihl >= 20 && len(raw) >= ihl+icmpHeaderLen+icmpInnerHeaderLen {
			raw = raw[ihl:]
		}
	}
	if len(raw) < icmpHeaderLen+icmpInnerHeaderLen {
		return 0, 0, 0, 0, nil, false
	}
	icmpType := raw[0]
	if icmpType != icmpTypeEchoRequest && icmpType != icmpTypeEchoReply {
		return 0, 0, 0, 0, nil, false
	}

	var hdr [icmpInnerHeaderLen]byte
	for i := 0; i < icmpInnerHeaderLen; i++ {
		hdr[i] = raw[icmpHeaderLen+i] ^ mask[i]
	}
	if hdr[0] != icmpMagic[0] || hdr[1] != icmpMagic[1] || hdr[2] != icmpMagic[2] {
		return 0, 0, 0, 0, nil, false
	}
	if hdr[3] != expectedFlag {
		return 0, 0, 0, 0, nil, false
	}
	dstPort = binary.BigEndian.Uint16(hdr[6:8])
	if expectedDstPort != 0 && dstPort != expectedDstPort {
		return 0, 0, 0, 0, nil, false
	}
	srcPort = binary.BigEndian.Uint16(hdr[4:6])
	icmpID = binary.BigEndian.Uint16(raw[4:6])
	icmpSeq = binary.BigEndian.Uint16(raw[6:8])
	return icmpID, icmpSeq, srcPort, dstPort, raw[icmpHeaderLen+icmpInnerHeaderLen:], true
}

func internetChecksum(b []byte) uint16 {
	var sum uint32
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

func (c *icmpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.hub != nil {
		var timerC <-chan time.Time
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			rem := time.Until(dl)
			if rem <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(rem)
			defer t.Stop()
			timerC = t.C
		}
		select {
		case pkt := <-c.rxCh:
			return copy(p, pkt.data), pkt.addr, nil
		case <-c.closed:
			return 0, nil, net.ErrClosed
		case <-timerC:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}

	buf := make([]byte, 2048)
	expectedFlag := icmpFlagS2C
	if c.isServer {
		expectedFlag = icmpFlagC2S
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

		icmpID, icmpSeq, srcPort, payload, ok := decodeICMPFrame(buf[:n], expectedFlag, c.localPort, c.mask)
		if !ok {
			continue
		}

		uaddr := &net.UDPAddr{IP: srcIP, Port: int(srcPort)}
		if c.isServer {
			key := uaddr.String()
			val, loaded := c.clients.LoadOrStore(key, &icmpClientMeta{id: icmpID, seq: uint32(icmpSeq)})
			if loaded {
				meta := val.(*icmpClientMeta)
				meta.id = icmpID
				atomic.StoreUint32(&meta.seq, uint32(icmpSeq))
			}
		}

		copied := copy(p, payload)
		return copied, uaddr, nil
	}
}

func (c *icmpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
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
		if host, portStr, err := net.SplitHostPort(addr.String()); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				dstIP = ip.To4()
			}
			if u, err := net.ResolveUDPAddr("udp4", addr.String()); err == nil && u != nil {
				dstIP = u.IP.To4()
				dstPort = uint16(u.Port)
			}
			_ = portStr
		}
	}
	if dstIP == nil {
		dstIP = c.remoteIP
	}
	if dstPort == 0 {
		dstPort = c.remotePort
	}
	if dstIP == nil {
		return 0, fmt.Errorf("icmp WriteTo: missing destination IPv4 address")
	}

	icmpType := icmpTypeEchoRequest
	dirFlag := icmpFlagC2S
	id := c.icmpID
	seq := uint16(c.seq.Add(1))

	if c.isServer {
		icmpType = icmpTypeEchoReply
		dirFlag = icmpFlagS2C
		key := (&net.UDPAddr{IP: dstIP, Port: int(dstPort)}).String()
		if val, ok := c.clients.Load(key); ok {
			meta := val.(*icmpClientMeta)
			id = meta.id
			seq = uint16(atomic.AddUint32(&meta.seq, 1))
		}
	}

	pkt := encodeICMPFrame(icmpType, id, seq, c.localPort, dstPort, dirFlag, c.mask, p)
	if _, err := c.conn.WriteTo(pkt, &net.IPAddr{IP: dstIP}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *icmpPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
		if c.reflectCleanup != nil {
			c.reflectCleanup()
		}
		if c.hub != nil {
			icmpDialHubsMu.Lock()
			c.hub.mu.Lock()
			delete(c.hub.conns, c.localPort)
			remaining := len(c.hub.conns)
			c.hub.mu.Unlock()
			if remaining == 0 {
				delete(icmpDialHubs, c.mask)
				err = c.hub.conn.Close()
			}
			icmpDialHubsMu.Unlock()
			return
		}
		err = c.conn.Close()
	})
	return err
}

func (c *icmpPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.localIP, Port: int(c.localPort)}
}

func (c *icmpPacketConn) SetDeadline(t time.Time) error {
	if c.hub != nil {
		c.readDeadline.Store(t)
		return nil
	}
	return c.conn.SetDeadline(t)
}

func (c *icmpPacketConn) SetReadDeadline(t time.Time) error {
	if c.hub != nil {
		c.readDeadline.Store(t)
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

func (c *icmpPacketConn) SetWriteDeadline(t time.Time) error {
	if c.hub != nil {
		return nil
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *icmpPacketConn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

func (c *icmpPacketConn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}
