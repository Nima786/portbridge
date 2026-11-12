package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Twin-Path 1+1 Redundant UDP Transport Layer (net.PacketConn) for KCP + FEC.
//
// Purpose:
//   Eliminates latency/jitter spikes caused by random packet loss, ISP micro-bursts,
//   or single-queue router congestion during gaming, VoIP, SSH, and interactive sessions.
//
// Wire Format (20-byte obfuscated header prepended to each UDP datagram):
//   [0:4]   Salt (4 bytes): Cryptographically random per-copy salt (crypto/rand).
//           Duplicated copies sent on Leg 0 and Leg 1 carry independent random salts
//           so wire headers share zero identical bytes across the two legs.
//   [4:16]  Masked Meta (12 bytes): (RawSessionID [8B] || SeqNum [4B BE]) XOR KeyStream12(Salt, PSK).
//   [16:20] Auth Tag (4 bytes): Truncated HMAC-SHA256 over (Salt || MaskedMeta || Payload)
//           keyed with PSK.
//
// Mechanics:
//   - Latency-critical packets (len(payload) <= maxDupBytes, default 700 bytes, covering
//     all game ticks, VoIP frames, SSH keystrokes, Mux control frames, and KCP ACKs) are
//     transmitted 1+1 simultaneously across two independent ephemeral UDP sockets targeting
//     distinct destination ports (basePort and basePort+1, with automatic fallback to basePort
//     if basePort+1 is filtered upstream while retaining two distinct local source ports).
//   - Bulk full-MTU data segments (> maxDupBytes) are sent once on the healthiest active leg
//     so large downloads run at full link speed without 2x upload overhead.
//   - Both ends deduplicate incoming packets in O(1) via a 2048-packet sliding sequence
//     bitmap: whichever copy arrives first is delivered immediately to KCP; the trailing
//     duplicate is silently discarded.

const (
	// DefaultTwinPathMaxDupBytes is the maximum payload size duplicated across both
	// UDP legs (700B covers <=600B user/gaming frames plus Mux + KCP + FEC headers).
	DefaultTwinPathMaxDupBytes = 700

	twinHeaderSize  = 20
	twinSaltSize    = 4
	twinMetaSize    = 12 // 8B sessionID + 4B uint32 seq
	twinTagSize     = 4
	twinDedupBits   = 2048
	twinDedupWords  = twinDedupBits / 64 // 32 uint64 words
	twinSessionIdle = 5 * time.Minute
	twinLegActiveNS = int64(30 * time.Second)
	twinLegStaleNS  = int64(3 * time.Second)
)

func (c *Config) EffectiveTwinPathMaxBytes() int {
	if c != nil && c.TwinPathMaxBytes > 0 {
		return c.TwinPathMaxBytes
	}
	return DefaultTwinPathMaxDupBytes
}

// twinSeqWindow is a 2048-packet sliding sequence bitmap for O(1) duplicate and
// replay suppression. Not safe for concurrent use without an external mutex.
type twinSeqWindow struct {
	maxSeq      uint32
	words       [twinDedupWords]uint64
	initialized bool
}

// Accept records seq and returns true if seq has not been seen before and lies
// within (or ahead of) the 2048-packet window. Seq 0 is reserved for control pings.
func (w *twinSeqWindow) Accept(seq uint32) bool {
	if seq == 0 {
		return false
	}
	if !w.initialized {
		w.initialized = true
		w.maxSeq = seq
		w.words = [twinDedupWords]uint64{}
		w.words[0] = 1
		return true
	}

	diff := int32(seq - w.maxSeq)
	if diff == 0 {
		return false
	}
	if diff > 0 {
		shift := uint32(diff)
		if shift >= twinDedupBits {
			w.words = [twinDedupWords]uint64{}
		} else {
			wordShift := int(shift / 64)
			bitShift := shift % 64
			if wordShift > 0 {
				for i := twinDedupWords - 1; i >= 0; i-- {
					if i >= wordShift {
						w.words[i] = w.words[i-wordShift]
					} else {
						w.words[i] = 0
					}
				}
			}
			if bitShift > 0 {
				for i := twinDedupWords - 1; i >= 0; i-- {
					val := w.words[i] << bitShift
					if i > 0 {
						val |= w.words[i-1] >> (64 - bitShift)
					}
					w.words[i] = val
				}
			}
		}
		w.maxSeq = seq
		w.words[0] |= 1
		return true
	}

	back := uint32(-diff)
	if back >= twinDedupBits {
		return false
	}
	wordIdx := back / 64
	bitMask := uint64(1) << (back % 64)
	if (w.words[wordIdx] & bitMask) != 0 {
		return false
	}
	w.words[wordIdx] |= bitMask
	return true
}

type twinPathKeys struct {
	ksKey  [32]byte
	macKey [32]byte
}

func deriveTwinPathKeys(psk []byte) twinPathKeys {
	ksMac := hmac.New(sha256.New, psk)
	ksMac.Write([]byte("portbridge-twinpath-ks-v1"))
	var ks [32]byte
	ksMac.Sum(ks[:0])

	authMac := hmac.New(sha256.New, psk)
	authMac.Write([]byte("portbridge-twinpath-mac-v1"))
	var mk [32]byte
	authMac.Sum(mk[:0])

	return twinPathKeys{ksKey: ks, macKey: mk}
}

func twinKeyStream12(ksKey *[32]byte, salt []byte) [twinMetaSize]byte {
	mac := hmac.New(sha256.New, ksKey[:])
	mac.Write(salt[:twinSaltSize])
	var sum [32]byte
	mac.Sum(sum[:0])
	var out [twinMetaSize]byte
	copy(out[:], sum[:twinMetaSize])
	return out
}

func twinAuthTag(macKey *[32]byte, header16 []byte, payload []byte) [twinTagSize]byte {
	mac := hmac.New(sha256.New, macKey[:])
	mac.Write(header16[:16])
	if len(payload) > 0 {
		mac.Write(payload)
	}
	var sum [32]byte
	mac.Sum(sum[:0])
	var tag [twinTagSize]byte
	copy(tag[:], sum[:twinTagSize])
	return tag
}

func encodeTwinPathPacket(dst []byte, keys *twinPathKeys, sessionID [8]byte, seq uint32, payload []byte) ([]byte, error) {
	total := twinHeaderSize + len(payload)
	if cap(dst) < total {
		dst = make([]byte, total)
	} else {
		dst = dst[:total]
	}

	if _, err := rand.Read(dst[0:twinSaltSize]); err != nil {
		return nil, err
	}

	var rawMeta [twinMetaSize]byte
	copy(rawMeta[0:8], sessionID[:])
	binary.BigEndian.PutUint32(rawMeta[8:12], seq)

	ks := twinKeyStream12(&keys.ksKey, dst[0:twinSaltSize])
	for i := 0; i < twinMetaSize; i++ {
		dst[twinSaltSize+i] = rawMeta[i] ^ ks[i]
	}

	tag := twinAuthTag(&keys.macKey, dst[0:16], payload)
	copy(dst[16:20], tag[:])
	copy(dst[twinHeaderSize:], payload)
	return dst, nil
}

func decodeTwinPathPacket(pkt []byte, keys *twinPathKeys) (sessionID [8]byte, seq uint32, payload []byte, ok bool) {
	if len(pkt) < twinHeaderSize {
		return sessionID, 0, nil, false
	}
	payload = pkt[twinHeaderSize:]

	wantTag := twinAuthTag(&keys.macKey, pkt[0:16], payload)
	if subtle.ConstantTimeCompare(pkt[16:20], wantTag[:]) != 1 {
		return sessionID, 0, nil, false
	}

	ks := twinKeyStream12(&keys.ksKey, pkt[0:twinSaltSize])
	var rawMeta [twinMetaSize]byte
	for i := 0; i < twinMetaSize; i++ {
		rawMeta[i] = pkt[twinSaltSize+i] ^ ks[i]
	}
	copy(sessionID[:], rawMeta[0:8])
	seq = binary.BigEndian.Uint32(rawMeta[8:12])
	return sessionID, seq, payload, true
}

type twinPathSessionAddr struct {
	id  [8]byte
	str string
}

func newTwinPathSessionAddr(id [8]byte) twinPathSessionAddr {
	return twinPathSessionAddr{
		id:  id,
		str: "twinpath:" + hex.EncodeToString(id[:]),
	}
}

func (a twinPathSessionAddr) Network() string { return "udp" }
func (a twinPathSessionAddr) String() string  { return a.str }

type twinLegEndpoint struct {
	sock     net.PacketConn
	peerAddr net.Addr
	key      string
	lastSeen int64
}

type twinPeerSession struct {
	mu       sync.Mutex
	legs     [2]twinLegEndpoint
	dedup    twinSeqWindow
	txSeq    atomic.Uint32
	lastSeen atomic.Int64
	vaddr    twinPathSessionAddr
}

func makeLegKey(sock net.PacketConn, raddr net.Addr) string {
	lStr := ""
	if sock != nil && sock.LocalAddr() != nil {
		lStr = sock.LocalAddr().String()
	}
	return lStr + "|" + raddr.String()
}

func (s *twinPeerSession) recordInboundAndCheckDup(sock net.PacketConn, raddr net.Addr, seq uint32, now int64) bool {
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
		}
	} else if s.legs[0].sock == nil {
		s.legs[0] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
	} else if s.legs[1].sock == nil {
		s.legs[1] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
	} else if s.legs[0].lastSeen <= s.legs[1].lastSeen {
		s.legs[0] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
	} else {
		s.legs[1] = twinLegEndpoint{sock: sock, peerAddr: raddr, key: key, lastSeen: now}
	}

	return s.dedup.Accept(seq)
}

func (s *twinPeerSession) activeLegs(now int64) (primary twinLegEndpoint, secondary twinLegEndpoint, hasPrimary bool, hasBoth bool) {
	s.mu.Lock()
	l0 := s.legs[0]
	l1 := s.legs[1]
	s.mu.Unlock()

	ok0 := l0.sock != nil && l0.peerAddr != nil && now-l0.lastSeen < twinLegActiveNS
	ok1 := l1.sock != nil && l1.peerAddr != nil && now-l1.lastSeen < twinLegActiveNS && l1.key != l0.key

	if ok0 && ok1 {
		if l1.lastSeen-l0.lastSeen > twinLegStaleNS {
			return l1, l0, true, true
		}
		return l0, l1, true, true
	}
	if ok0 {
		return l0, twinLegEndpoint{}, true, false
	}
	if ok1 {
		return l1, twinLegEndpoint{}, true, false
	}
	if l0.sock != nil && l0.peerAddr != nil {
		return l0, twinLegEndpoint{}, true, false
	}
	return twinLegEndpoint{}, twinLegEndpoint{}, false, false
}

// twinServerMux holds server-side Twin-Path state so both dedicated TwinPathListenConn
// and shared multi-protocol listeners (ProbeListener / asymEdgeRuntime) can process
// Twin-Path sessions identically.
type twinServerMux struct {
	keys        twinPathKeys
	maxDupBytes int
	sessions    sync.Map // [8]byte -> *twinPeerSession
}

func newTwinServerMux(psk []byte, maxDupBytes int) *twinServerMux {
	if maxDupBytes <= 0 {
		maxDupBytes = DefaultTwinPathMaxDupBytes
	}
	return &twinServerMux{
		keys:        deriveTwinPathKeys(psk),
		maxDupBytes: maxDupBytes,
	}
}

// tryHandlePacket attempts to authenticate and decode raw[:n] as a Twin-Path packet.
// Returns (matched=false) when raw[:n] is not a valid Twin-Path packet for this PSK.
// When matched=true and deliver=true, the caller should deliver raw[:payloadLen] with vaddr.
func (m *twinServerMux) tryHandlePacket(sock net.PacketConn, raddr net.Addr, buf []byte, n int) (payloadLen int, vaddr net.Addr, matched bool, deliver bool) {
	sid, seq, payload, ok := decodeTwinPathPacket(buf[:n], &m.keys)
	if !ok {
		return 0, nil, false, false
	}
	if seq == 0 && len(payload) == 0 {
		var ackArr [twinHeaderSize]byte
		if ack, err := encodeTwinPathPacket(ackArr[:0], &m.keys, sid, 0, nil); err == nil {
			_, _ = sock.WriteTo(ack, raddr)
		}
		return 0, nil, true, false
	}
	if len(payload) == 0 {
		return 0, nil, true, false
	}

	now := time.Now().UnixNano()
	var sess *twinPeerSession
	if existing, loaded := m.sessions.Load(sid); loaded {
		sess = existing.(*twinPeerSession)
	} else {
		fresh := &twinPeerSession{vaddr: newTwinPathSessionAddr(sid)}
		fresh.lastSeen.Store(now)
		actual, _ := m.sessions.LoadOrStore(sid, fresh)
		sess = actual.(*twinPeerSession)
	}

	if !sess.recordInboundAndCheckDup(sock, raddr, seq, now) {
		return 0, nil, true, false
	}

	pLen := len(payload)
	copy(buf[:pLen], payload)
	return pLen, sess.vaddr, true, true
}

func (m *twinServerMux) writeSessionPacket(sid [8]byte, p []byte) (int, error) {
	val, exists := m.sessions.Load(sid)
	if !exists {
		return len(p), nil
	}
	sess := val.(*twinPeerSession)
	now := time.Now().UnixNano()
	primary, secondary, hasPrimary, hasBoth := sess.activeLegs(now)
	if !hasPrimary {
		return len(p), nil
	}

	seq := sess.txSeq.Add(1)
	if seq == 0 {
		seq = sess.txSeq.Add(1)
	}

	sendCopy := func(leg twinLegEndpoint) error {
		need := twinHeaderSize + len(p)
		if need <= 2048 {
			bp := portHopBufPool.Get().(*[]byte)
			pkt, err := encodeTwinPathPacket((*bp)[:0], &m.keys, sid, seq, p)
			if err != nil {
				portHopBufPool.Put(bp)
				return err
			}
			_, err = leg.sock.WriteTo(pkt, leg.peerAddr)
			portHopBufPool.Put(bp)
			return err
		}
		pkt, err := encodeTwinPathPacket(nil, &m.keys, sid, seq, p)
		if err != nil {
			return err
		}
		_, err = leg.sock.WriteTo(pkt, leg.peerAddr)
		return err
	}

	err0 := sendCopy(primary)
	if hasBoth && len(p) <= m.maxDupBytes {
		err1 := sendCopy(secondary)
		if err0 != nil && err1 == nil {
			return len(p), nil
		}
	}
	if err0 != nil {
		return 0, err0
	}
	return len(p), nil
}

func (m *twinServerMux) sweepIdle(cutoff int64) {
	m.sessions.Range(func(k, v any) bool {
		s := v.(*twinPeerSession)
		if s.lastSeen.Load() < cutoff {
			m.sessions.Delete(k)
		}
		return true
	})
}

// TwinPathListenConn implements net.PacketConn across 2 (or hopCount) server UDP ports
// with sequence-bitmap deduplication and symmetric dual-leg reply duplication.
type TwinPathListenConn struct {
	mux        *twinServerMux
	primary    net.PacketConn
	companions []*net.UDPConn
	rxCh       chan portHopRxItem
	rdl        *deadline
	wdl        *deadline
	closed     atomic.Bool
	closedCh   chan struct{}
	once       sync.Once
}

// ListenTwinPath binds a pair (or pool) of server UDP ports starting at basePort
// and multiplexes deduplicated Twin-Path datagrams into a single net.PacketConn.
func ListenTwinPath(basePort int, portCount int, psk []byte) (net.PacketConn, error) {
	if basePort < 0 || basePort > 65535 {
		return nil, fmt.Errorf("invalid twin-path basePort %d", basePort)
	}
	if len(psk) == 0 {
		return nil, errors.New("twin-path PSK must not be empty")
	}
	if portCount <= 0 {
		portCount = 2
	}
	addr := net.JoinHostPort("", strconv.Itoa(basePort))
	return newTwinPathListenConnWithParams(addr, portCount, DefaultTwinPathMaxDupBytes, psk, nil)
}

func newTwinPathListenConn(addr string, cfg *Config, avoid map[int]bool) (*TwinPathListenConn, error) {
	portCount := 2
	if cfg.PortHop {
		portCount = cfg.EffectivePortHopPorts()
	}
	return newTwinPathListenConnWithParams(addr, portCount, cfg.EffectiveTwinPathMaxBytes(), cfg.secret, avoid)
}

func newTwinPathListenConnWithParams(addr string, portCount int, maxDupBytes int, psk []byte, avoid map[int]bool) (*TwinPathListenConn, error) {
	if len(psk) == 0 {
		return nil, errors.New("twin-path secret must not be empty")
	}
	network := "udp"
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolving twin-path listen addr: %w", err)
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
		return nil, fmt.Errorf("listening twin-path primary udp: %w", err)
	}
	tuneUDPSocket(primary)

	c := &TwinPathListenConn{
		mux:      newTwinServerMux(psk, maxDupBytes),
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

func (c *TwinPathListenConn) BoundPorts() []int {
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

func (c *TwinPathListenConn) readLoop(sock net.PacketConn) {
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

func (c *TwinPathListenConn) janitorLoop() {
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

func (c *TwinPathListenConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *TwinPathListenConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if ta, ok := addr.(twinPathSessionAddr); ok {
		return c.mux.writeSessionPacket(ta.id, p)
	}
	return 0, errors.New("unknown twin-path session address")
}

func (c *TwinPathListenConn) Close() error {
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

func (c *TwinPathListenConn) LocalAddr() net.Addr                { return c.primary.LocalAddr() }
func (c *TwinPathListenConn) SetDeadline(t time.Time) error      { c.rdl.set(t); c.wdl.set(t); return nil }
func (c *TwinPathListenConn) SetReadDeadline(t time.Time) error  { c.rdl.set(t); return nil }
func (c *TwinPathListenConn) SetWriteDeadline(t time.Time) error { c.wdl.set(t); return nil }

type twinClientLeg struct {
	sock   *net.UDPConn
	dst    *net.UDPAddr
	dstIdx int
	rxPkts atomic.Uint64
	txPkts atomic.Uint64
	opened int64
}

// TwinPathDialConn implements client-side 1+1 UDP packet duplication across two
// independent ephemeral local UDP sockets with sliding-bitmap deduplication.
type TwinPathDialConn struct {
	keys        twinPathKeys
	sessionID   [8]byte
	network     string
	localBind   *net.UDPAddr
	targets     []*net.UDPAddr
	maxDupBytes int
	hopInterval time.Duration
	drainWindow time.Duration

	mu         sync.RWMutex
	legs       [2]*twinClientLeg
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

// DialTwinPath opens a Twin-Path 1+1 redundant client net.PacketConn to serverAddr
// across [basePort .. basePort+portCount-1] (default 2 ports).
func DialTwinPath(serverAddr string, basePort int, portCount int, psk []byte) (*TwinPathDialConn, error) {
	if portCount <= 0 {
		portCount = 2
	}
	addr := net.JoinHostPort(serverAddr, strconv.Itoa(basePort))
	return dialTwinPathInternal(addr, nil, portCount, 0, DefaultPortHopDrainWindow, DefaultTwinPathMaxDupBytes, psk)
}

func newTwinPathDialConn(addr string, cfg *Config) (*TwinPathDialConn, error) {
	var localBind *net.UDPAddr
	if src := cfg.sourceFor(addr); src != nil {
		if ta, ok := src.(*net.TCPAddr); ok && len(ta.IP) > 0 {
			localBind = &net.UDPAddr{IP: ta.IP, Zone: ta.Zone}
		}
	}
	portCount := 2
	var hopInterval time.Duration
	if cfg.PortHop {
		portCount = cfg.EffectivePortHopPorts()
		hopInterval = cfg.EffectivePortHopInterval()
	}
	return dialTwinPathInternal(addr, localBind, portCount, hopInterval, DefaultPortHopDrainWindow, cfg.EffectiveTwinPathMaxBytes(), cfg.secret)
}

func dialTwinPathInternal(addr string, localBind *net.UDPAddr, portCount int, hopInterval, drainWindow time.Duration, maxDupBytes int, psk []byte) (*TwinPathDialConn, error) {
	if len(psk) == 0 {
		return nil, errors.New("twin-path PSK must not be empty")
	}
	if portCount <= 0 {
		portCount = 2
	}
	if maxDupBytes <= 0 {
		maxDupBytes = DefaultTwinPathMaxDupBytes
	}

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolving twin-path server %q: %w", addr, err)
	}
	if raddr.Port <= 0 || raddr.Port > 65535 {
		return nil, fmt.Errorf("invalid twin-path basePort %d", raddr.Port)
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
		return nil, fmt.Errorf("generating twin-path session ID: %w", err)
	}

	c := &TwinPathDialConn{
		keys:        deriveTwinPathKeys(psk),
		sessionID:   sid,
		network:     network,
		localBind:   localBind,
		targets:     targets,
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
	dst1Idx := 0
	if len(targets) > 1 {
		dst1Idx = 1
	}
	leg1, err := c.openLeg(dst1Idx)
	if err != nil {
		_ = leg0.sock.Close()
		return nil, err
	}
	c.legs[0] = leg0
	c.legs[1] = leg1
	c.portCursor = dst1Idx

	go c.readLegLoop(leg0)
	go c.readLegLoop(leg1)

	// Probe Leg 1 reachability immediately when targeting a companion port so we
	// fall back dstPort1 to basePort automatically if a cloud firewall only opened basePort.
	if dst1Idx > 0 {
		c.sendProbePing(leg1)
		go c.watchCompanionLeg(leg1)
	}
	if hopInterval > 0 {
		go c.rotationLoop()
	}

	return c, nil
}

func (c *TwinPathDialConn) openLeg(dstIdx int) (*twinClientLeg, error) {
	var bindAddr *net.UDPAddr
	if c.localBind != nil {
		bindAddr = &net.UDPAddr{IP: c.localBind.IP, Port: 0, Zone: c.localBind.Zone}
	}
	sock, err := net.ListenUDP(c.network, bindAddr)
	if err != nil {
		return nil, fmt.Errorf("opening twin-path local udp socket: %w", err)
	}
	tuneUDPSocket(sock)
	if dstIdx < 0 || dstIdx >= len(c.targets) {
		dstIdx = 0
	}
	return &twinClientLeg{
		sock:   sock,
		dst:    c.targets[dstIdx],
		dstIdx: dstIdx,
		opened: time.Now().UnixNano(),
	}, nil
}

func (c *TwinPathDialConn) sendProbePing(leg *twinClientLeg) {
	var buf [twinHeaderSize]byte
	if pkt, err := encodeTwinPathPacket(buf[:0], &c.keys, c.sessionID, 0, nil); err == nil {
		_, _ = leg.sock.WriteToUDP(pkt, leg.dst)
	}
}

func (c *TwinPathDialConn) watchCompanionLeg(leg *twinClientLeg) {
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
	if c.closed.Load() || c.legs[1] != leg || leg.rxPkts.Load() > 0 {
		c.mu.Unlock()
		return
	}
	c.lockBase = true
	rebound, err := c.openLeg(0)
	if err != nil {
		c.mu.Unlock()
		return
	}
	old := c.legs[1]
	c.legs[1] = rebound
	c.mu.Unlock()

	go c.readLegLoop(rebound)
	c.retireLeg(old)
}

func (c *TwinPathDialConn) rotationLoop() {
	ticker := time.NewTicker(c.hopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			c.rotatePair()
		}
	}
}

func (c *TwinPathDialConn) rotatePair() {
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return
	}
	idx0, idx1 := 0, 0
	if !c.lockBase && len(c.targets) > 1 {
		c.portCursor = (c.portCursor + 1) % len(c.targets)
		idx0 = c.portCursor
		idx1 = (c.portCursor + 1) % len(c.targets)
	}
	new0, err0 := c.openLeg(idx0)
	if err0 != nil {
		c.mu.Unlock()
		return
	}
	new1, err1 := c.openLeg(idx1)
	if err1 != nil {
		_ = new0.sock.Close()
		c.mu.Unlock()
		return
	}
	old0, old1 := c.legs[0], c.legs[1]
	c.legs[0], c.legs[1] = new0, new1
	c.mu.Unlock()

	go c.readLegLoop(new0)
	go c.readLegLoop(new1)
	if idx0 > 0 {
		c.sendProbePing(new0)
	}
	if idx1 > 0 {
		c.sendProbePing(new1)
		go c.watchCompanionLeg(new1)
	}
	c.retireLeg(old0)
	c.retireLeg(old1)
}

func (c *TwinPathDialConn) retireLeg(leg *twinClientLeg) {
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

func (c *TwinPathDialConn) readLegLoop(leg *twinClientLeg) {
	for {
		bp := portHopBufPool.Get().(*[]byte)
		buf := *bp
		n, _, err := leg.sock.ReadFromUDP(buf)
		if err != nil {
			portHopBufPool.Put(bp)
			if c.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		if n <= 0 {
			portHopBufPool.Put(bp)
			continue
		}
		sid, seq, payload, ok := decodeTwinPathPacket(buf[:n], &c.keys)
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

func (c *TwinPathDialConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *TwinPathDialConn) WriteTo(p []byte, _ net.Addr) (int, error) {
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

	sendOn := func(leg *twinClientLeg) error {
		if leg == nil {
			return net.ErrClosed
		}
		need := twinHeaderSize + len(p)
		if need <= 2048 {
			bp := portHopBufPool.Get().(*[]byte)
			pkt, err := encodeTwinPathPacket((*bp)[:0], &c.keys, c.sessionID, seq, p)
			if err != nil {
				portHopBufPool.Put(bp)
				return err
			}
			_, err = leg.sock.WriteToUDP(pkt, leg.dst)
			portHopBufPool.Put(bp)
			if err == nil {
				leg.txPkts.Add(1)
			}
			return err
		}
		pkt, err := encodeTwinPathPacket(nil, &c.keys, c.sessionID, seq, p)
		if err != nil {
			return err
		}
		_, err = leg.sock.WriteToUDP(pkt, leg.dst)
		if err == nil {
			leg.txPkts.Add(1)
		}
		return err
	}

	if len(p) <= c.maxDupBytes && l0 != nil && l1 != nil {
		err0 := sendOn(l0)
		err1 := sendOn(l1)
		if err0 != nil && err1 != nil {
			return 0, err0
		}
		return len(p), nil
	}

	// For bulk full-MTU segments (> maxDupBytes), prefer Leg 0 unless Leg 0 has
	// zero inbound packets while Leg 1 is actively receiving.
	chosen := l0
	if chosen == nil || (l1 != nil && l0.rxPkts.Load() == 0 && l1.rxPkts.Load() > 0) {
		chosen = l1
	}
	if err := sendOn(chosen); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *TwinPathDialConn) Close() error {
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

func (c *TwinPathDialConn) LocalAddr() net.Addr {
	c.mu.RLock()
	l0 := c.legs[0]
	c.mu.RUnlock()
	if l0 != nil {
		return l0.sock.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *TwinPathDialConn) RemoteAddr() net.Addr               { return c.targets[0] }
func (c *TwinPathDialConn) SetDeadline(t time.Time) error      { c.rdl.set(t); c.wdl.set(t); return nil }
func (c *TwinPathDialConn) SetReadDeadline(t time.Time) error  { c.rdl.set(t); return nil }
func (c *TwinPathDialConn) SetWriteDeadline(t time.Time) error { c.wdl.set(t); return nil }
