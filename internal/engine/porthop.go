package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Dynamic Port-Hopping UDP transport layer (net.PacketConn) for KCP + FEC + Smux.
//
// Wire Format (16-byte header prepended to every UDP datagram):
//   [0:4]   Salt (4 bytes): Cryptographically random bytes (crypto/rand).
//   [4:12]  Masked Session ID (8 bytes): RawSessionID XOR KeyStream(Salt, PSK).
//   [12:16] Auth Tag (4 bytes): Truncated HMAC-SHA256 over (Salt || MaskedSessionID || Payload)
//           keyed with PSK.
//
// Properties:
//   - Zero static magic bytes on the wire; header bytes are indistinguishable
//     from uniform random data.
//   - Constant-time HMAC tag verification; invalid, unauthenticated, or
//     malformed packets are silently discarded without errors or ICMP replies.
//   - Server binds a continuous pool of UDP ports [basePort .. basePort+hopCount-1],
//     multiplexes validated datagrams by 8-byte sessionID, and replies symmetrically
//     from the exact server UDP socket (dstPort) to the client's latest (IP, srcPort)
//     for full stateful firewall and 1:1 cloud NAT (AWS / Oracle Cloud) compatibility.
//   - Client starts on basePort via an ephemeral UDP socket, rotates both local
//     ephemeral srcPort and target dstPort every 15s, keeps the previous socket
//     draining in the background for 4s for zero-loss handoff, and automatically
//     locks dstPort back to basePort (while continuing srcPort rotation) if hopped
//     ports are filtered upstream.

const (
	// DefaultPortHopPorts is the default server UDP port pool size when hopCount <= 0.
	DefaultPortHopPorts = 8

	// DefaultPortHopInterval is the default client socket + port rotation period.
	DefaultPortHopInterval = 15 * time.Second

	// DefaultPortHopDrainWindow is how long an old client UDP socket stays open
	// for background reads after rotation so in-flight packets and ACKs never drop.
	DefaultPortHopDrainWindow = 4 * time.Second

	// defaultPortHopFallbackWait is how long a hopped destination port may go
	// with outbound traffic and zero inbound replies before locking dstPort back
	// to basePort.
	defaultPortHopFallbackWait = 1200 * time.Millisecond

	portHopHeaderSize  = 16
	portHopSaltSize    = 4
	portHopSessionSize = 8
	portHopTagSize     = 4
	portHopSessionIdle = 5 * time.Minute
)

type portHopKeys struct {
	ksKey  [32]byte // KeyStream subkey derived from PSK
	macKey [32]byte // Auth-tag HMAC key derived from PSK
}

func derivePortHopKeys(psk []byte) portHopKeys {
	ksMac := hmac.New(sha256.New, psk)
	ksMac.Write([]byte("portbridge-porthop-ks-v1"))
	var ks [32]byte
	ksMac.Sum(ks[:0])

	authMac := hmac.New(sha256.New, psk)
	authMac.Write([]byte("portbridge-porthop-mac-v1"))
	var mk [32]byte
	authMac.Sum(mk[:0])

	return portHopKeys{ksKey: ks, macKey: mk}
}

// portHopKeyStream computes an 8-byte keystream mask from (Salt, PSK) using
// HMAC-SHA256 without heap allocations on the digest output.
func portHopKeyStream(ksKey *[32]byte, salt []byte) [8]byte {
	mac := hmac.New(sha256.New, ksKey[:])
	mac.Write(salt[:portHopSaltSize])
	var sum [32]byte
	mac.Sum(sum[:0])
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

// portHopAuthTag computes the 4-byte truncated HMAC-SHA256 over
// (Salt + MaskedSessionID + Payload).
func portHopAuthTag(macKey *[32]byte, header12 []byte, payload []byte) [4]byte {
	mac := hmac.New(sha256.New, macKey[:])
	mac.Write(header12[:12])
	if len(payload) > 0 {
		mac.Write(payload)
	}
	var sum [32]byte
	mac.Sum(sum[:0])
	var tag [4]byte
	copy(tag[:], sum[:4])
	return tag
}

// encodePortHopPacket wraps payload with the 16-byte obfuscated + authenticated
// header: [4B crypto/rand Salt][8B MaskedSessionID][4B HMAC-SHA256 Tag].
func encodePortHopPacket(dst []byte, keys *portHopKeys, sessionID [8]byte, payload []byte) ([]byte, error) {
	total := portHopHeaderSize + len(payload)
	if cap(dst) < total {
		dst = make([]byte, total)
	} else {
		dst = dst[:total]
	}

	if _, err := rand.Read(dst[0:portHopSaltSize]); err != nil {
		return nil, err
	}

	ks := portHopKeyStream(&keys.ksKey, dst[0:portHopSaltSize])
	for i := 0; i < portHopSessionSize; i++ {
		dst[portHopSaltSize+i] = sessionID[i] ^ ks[i]
	}

	tag := portHopAuthTag(&keys.macKey, dst[0:12], payload)
	copy(dst[12:16], tag[:])
	copy(dst[portHopHeaderSize:], payload)
	return dst, nil
}

// decodePortHopPacket verifies the 4-byte HMAC-SHA256 auth tag in constant time
// and unmasks the 8-byte sessionID.
func decodePortHopPacket(pkt []byte, keys *portHopKeys) (sessionID [8]byte, payload []byte, ok bool) {
	if len(pkt) < portHopHeaderSize {
		return sessionID, nil, false
	}
	payload = pkt[portHopHeaderSize:]

	wantTag := portHopAuthTag(&keys.macKey, pkt[0:12], payload)
	if subtle.ConstantTimeCompare(pkt[12:16], wantTag[:]) != 1 {
		return sessionID, nil, false
	}

	ks := portHopKeyStream(&keys.ksKey, pkt[0:portHopSaltSize])
	for i := 0; i < portHopSessionSize; i++ {
		sessionID[i] = pkt[portHopSaltSize+i] ^ ks[i]
	}
	return sessionID, payload, true
}

// portHopSessionAddr implements net.Addr for logical multiplexing by sessionID
// inside kcp.ServeConn so source/destination port hops remain one continuous
// KCP session.
type portHopSessionAddr struct {
	id  [8]byte
	str string
}

func newPortHopSessionAddr(id [8]byte) portHopSessionAddr {
	return portHopSessionAddr{
		id:  id,
		str: "porthop:" + hex.EncodeToString(id[:]),
	}
}

func (a portHopSessionAddr) Network() string { return "udp" }
func (a portHopSessionAddr) String() string  { return a.str }

var portHopBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

type portHopRxItem struct {
	bufPtr *[]byte
	n      int
	addr   net.Addr
}

type portHopPeerRoute struct {
	mu       sync.RWMutex
	sock     net.PacketConn
	peerAddr net.Addr
	lastSeen int64
	vaddr    portHopSessionAddr
}

// PortHopListenConn implements net.PacketConn across a pool of server UDP ports.
type PortHopListenConn struct {
	keys             portHopKeys
	primary          net.PacketConn
	companions       []*net.UDPConn
	allowPassthrough bool
	webrtcMux        *webrtcServerMux
	twinMux          *twinServerMux

	sessions sync.Map // [8]byte -> *portHopPeerRoute
	rxCh     chan portHopRxItem
	rdl      *deadline
	wdl      *deadline

	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

// ListenPortHop binds a continuous pool of UDP ports starting at basePort up to
// basePort + hopCount - 1 (default 8 ports when hopCount <= 0) and multiplexes
// all HMAC-authenticated datagrams into a single net.PacketConn keyed by sessionID.
func ListenPortHop(basePort int, hopCount int, psk []byte) (net.PacketConn, error) {
	if basePort < 0 || basePort > 65535 {
		return nil, fmt.Errorf("invalid port-hop basePort %d", basePort)
	}
	if len(psk) == 0 {
		return nil, errors.New("port-hop PSK must not be empty")
	}
	return ListenPortHopAddr(net.JoinHostPort("", strconv.Itoa(basePort)), hopCount, psk)
}

// ListenPortHopAddr is ListenPortHop with an explicit host:port listen address
// (for example "0.0.0.0:7465", "127.0.0.1:0", or "[::]:7465").
func ListenPortHopAddr(listenAddr string, hopCount int, psk []byte) (*PortHopListenConn, error) {
	if len(psk) == 0 {
		return nil, errors.New("port-hop PSK must not be empty")
	}
	if hopCount <= 0 {
		hopCount = DefaultPortHopPorts
	}
	if hopCount > 64 {
		hopCount = 64
	}

	network := "udp"
	laddr, err := net.ResolveUDPAddr(network, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolving port-hop listen addr %q: %w", listenAddr, err)
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
		return nil, fmt.Errorf("listening port-hop primary udp %s: %w", listenAddr, err)
	}
	tuneUDPSocket(primary)

	return wrapPortHopListenConn(primary, network, hopCount, psk, false, nil)
}

func newPortHopListenConn(addr string, cfg *Config, avoid map[int]bool) (*PortHopListenConn, error) {
	if len(cfg.secret) == 0 {
		return nil, errors.New("port-hop secret must not be empty")
	}
	network := "udp"
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolving port-hop listen addr: %w", err)
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
		return nil, fmt.Errorf("listening port-hop primary udp: %w", err)
	}
	tuneUDPSocket(primary)

	return wrapPortHopListenConn(primary, network, cfg.EffectivePortHopPorts(), cfg.secret, false, avoid)
}

func wrapPortHopListenConn(primary net.PacketConn, companionNet string, hopPorts int, psk []byte, allowPassthrough bool, avoid map[int]bool) (*PortHopListenConn, error) {
	c := &PortHopListenConn{
		keys:             derivePortHopKeys(psk),
		primary:          primary,
		allowPassthrough: allowPassthrough,
		rxCh:             make(chan portHopRxItem, 4096),
		rdl:              newDeadline(),
		wdl:              newDeadline(),
		closedCh:         make(chan struct{}),
	}
	if allowPassthrough {
		c.webrtcMux = newWebRTCServerMux(psk, DefaultTwinPathMaxDupBytes)
		c.twinMux = newTwinServerMux(psk, DefaultTwinPathMaxDupBytes)
	}

	if hopPorts > 1 {
		if ua, ok := primary.LocalAddr().(*net.UDPAddr); ok && ua != nil && ua.Port > 0 {
			netName := companionNet
			if netName == "" {
				netName = "udp"
				if ua.IP != nil {
					if ua.IP.To4() != nil {
						netName = "udp4"
					} else if len(ua.IP) == net.IPv6len {
						netName = "udp6"
					}
				}
			}
			for i := 1; i < hopPorts; i++ {
				port := ua.Port + i
				if port > 65535 || (avoid != nil && avoid[port]) {
					continue
				}
				compAddr := &net.UDPAddr{IP: ua.IP, Port: port, Zone: ua.Zone}
				uc, err := net.ListenUDP(netName, compAddr)
				if err != nil {
					continue
				}
				tuneUDPSocket(uc)
				c.companions = append(c.companions, uc)
			}
		}
	}

	go c.readSocketLoop(primary, true)
	for _, comp := range c.companions {
		go c.readSocketLoop(comp, false)
	}
	go c.janitorLoop()

	return c, nil
}

// BoundPorts returns all UDP port numbers bound by this listener (primary first).
func (c *PortHopListenConn) BoundPorts() []int {
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

func (c *PortHopListenConn) readSocketLoop(sock net.PacketConn, isPrimary bool) {
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

		if c.webrtcMux != nil {
			pLen, vaddr, matched, deliver := c.webrtcMux.tryHandlePacket(sock, raddr, buf, n)
			if matched {
				if deliver {
					select {
					case c.rxCh <- portHopRxItem{bufPtr: bp, n: pLen, addr: vaddr}:
					case <-c.closedCh:
						portHopBufPool.Put(bp)
						return
					default:
						portHopBufPool.Put(bp)
					}
				} else {
					portHopBufPool.Put(bp)
				}
				continue
			}
		}

		if c.twinMux != nil {
			pLen, vaddr, matched, deliver := c.twinMux.tryHandlePacket(sock, raddr, buf, n)
			if matched {
				if deliver {
					select {
					case c.rxCh <- portHopRxItem{bufPtr: bp, n: pLen, addr: vaddr}:
					case <-c.closedCh:
						portHopBufPool.Put(bp)
						return
					default:
						portHopBufPool.Put(bp)
					}
				} else {
					portHopBufPool.Put(bp)
				}
				continue
			}
		}

		sid, payload, ok := decodePortHopPacket(buf[:n], &c.keys)
		if !ok {
			if isPrimary && c.allowPassthrough {
				select {
				case c.rxCh <- portHopRxItem{bufPtr: bp, n: n, addr: raddr}:
				case <-c.closedCh:
					portHopBufPool.Put(bp)
					return
				default:
					portHopBufPool.Put(bp)
				}
				continue
			}
			// Silently discard invalid, unauthenticated, or malformed packets.
			portHopBufPool.Put(bp)
			continue
		}

		// Zero-length authenticated packet acts as a port-reachability ping:
		// reply symmetrically with a zero-length authenticated echo on the same
		// socket without passing an empty datagram up to KCP.
		if len(payload) == 0 {
			var ackArr [portHopHeaderSize]byte
			if ack, encErr := encodePortHopPacket(ackArr[:0], &c.keys, sid, nil); encErr == nil {
				_, _ = sock.WriteTo(ack, raddr)
			}
			portHopBufPool.Put(bp)
			continue
		}

		now := time.Now().UnixNano()
		var route *portHopPeerRoute
		if existing, loaded := c.sessions.Load(sid); loaded {
			route = existing.(*portHopPeerRoute)
			route.mu.Lock()
			route.sock = sock
			route.peerAddr = raddr
			route.lastSeen = now
			route.mu.Unlock()
		} else {
			fresh := &portHopPeerRoute{
				sock:     sock,
				peerAddr: raddr,
				lastSeen: now,
				vaddr:    newPortHopSessionAddr(sid),
			}
			actual, loaded := c.sessions.LoadOrStore(sid, fresh)
			route = actual.(*portHopPeerRoute)
			if loaded {
				route.mu.Lock()
				route.sock = sock
				route.peerAddr = raddr
				route.lastSeen = now
				route.mu.Unlock()
			}
		}

		pLen := len(payload)
		copy(buf[:pLen], payload)
		select {
		case c.rxCh <- portHopRxItem{bufPtr: bp, n: pLen, addr: route.vaddr}:
		case <-c.closedCh:
			portHopBufPool.Put(bp)
			return
		default:
			portHopBufPool.Put(bp)
		}
	}
}

func (c *PortHopListenConn) janitorLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-portHopSessionIdle).UnixNano()
			if c.webrtcMux != nil {
				c.webrtcMux.sweepIdle(cutoff)
			}
			if c.twinMux != nil {
				c.twinMux.sweepIdle(cutoff)
			}
			c.sessions.Range(func(k, v any) bool {
				r := v.(*portHopPeerRoute)
				r.mu.RLock()
				stale := r.lastSeen < cutoff
				r.mu.RUnlock()
				if stale {
					c.sessions.Delete(k)
				}
				return true
			})
		}
	}
}

func (c *PortHopListenConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *PortHopListenConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if wa, ok := addr.(webrtcSessionAddr); ok && c.webrtcMux != nil {
		return c.webrtcMux.writeSessionPacket(wa.id, p)
	}
	if ta, ok := addr.(twinPathSessionAddr); ok && c.twinMux != nil {
		return c.twinMux.writeSessionPacket(ta.id, p)
	}
	if ha, ok := addr.(portHopSessionAddr); ok {
		val, exists := c.sessions.Load(ha.id)
		if !exists {
			return len(p), nil
		}
		route := val.(*portHopPeerRoute)
		route.mu.RLock()
		sock := route.sock
		peer := route.peerAddr
		route.mu.RUnlock()
		if sock == nil || peer == nil {
			return len(p), nil
		}

		need := portHopHeaderSize + len(p)
		if need <= 2048 {
			bp := portHopBufPool.Get().(*[]byte)
			pkt, err := encodePortHopPacket((*bp)[:0], &c.keys, ha.id, p)
			if err != nil {
				portHopBufPool.Put(bp)
				return 0, err
			}
			_, err = sock.WriteTo(pkt, peer)
			portHopBufPool.Put(bp)
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}
		pkt, err := encodePortHopPacket(nil, &c.keys, ha.id, p)
		if err != nil {
			return 0, err
		}
		if _, err := sock.WriteTo(pkt, peer); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	if c.allowPassthrough {
		return c.primary.WriteTo(p, addr)
	}
	return 0, errors.New("unknown port-hop session address")
}

func (c *PortHopListenConn) Close() error {
	var firstErr error
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
		firstErr = c.primary.Close()
		for _, comp := range c.companions {
			_ = comp.Close()
		}
	})
	return firstErr
}

func (c *PortHopListenConn) LocalAddr() net.Addr {
	return c.primary.LocalAddr()
}

func (c *PortHopListenConn) SetDeadline(t time.Time) error {
	c.rdl.set(t)
	c.wdl.set(t)
	return nil
}

func (c *PortHopListenConn) SetReadDeadline(t time.Time) error {
	c.rdl.set(t)
	return nil
}

func (c *PortHopListenConn) SetWriteDeadline(t time.Time) error {
	c.wdl.set(t)
	return nil
}

// ---------------------------------------------------------------------------
// Client / Dialer Side
// ---------------------------------------------------------------------------

// PortHopDialConfig configures optional timing overrides for PortHopDialConn.
type PortHopDialConfig struct {
	HopInterval  time.Duration
	DrainWindow  time.Duration
	FallbackWait time.Duration
}

// PortHopDialConn implements net.PacketConn on the client side with periodic
// local ephemeral srcPort + target dstPort rotation, 4s drain windows, and
// automatic fallback to basePort if hopped destination ports are blocked.
type PortHopDialConn struct {
	keys          portHopKeys
	sessionID     [8]byte
	network       string
	remoteIP      net.IP
	remoteZone    string
	basePort      int
	hopPorts      int
	hopInterval   time.Duration
	drainWindow   time.Duration
	fallbackWait  time.Duration
	canonicalPeer *net.UDPAddr
	peerAddrVal   atomic.Value // net.Addr expected by kcp.NewConn / kcp.NewConn2

	mu             sync.RWMutex
	activeSock     *net.UDPConn
	activeDst      *net.UDPAddr
	allSocks       map[*net.UDPConn]struct{}
	hopStep        int
	fallbackLocked bool // true once hopped target ports failed and dstPort locked to basePort

	hopEpoch   atomic.Uint64
	txSinceHop atomic.Uint64
	rxSinceHop atomic.Uint64
	hopCount   atomic.Uint64

	rxCh chan portHopRxItem
	rdl  *deadline
	wdl  *deadline

	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

// DialPortHop creates a client net.PacketConn starting on basePort via an
// ephemeral local UDP socket and rotating both local srcPort and target dstPort
// across [basePort .. basePort+hopCount-1] every 15 seconds.
//
// serverAddr may be either a bare host/IP ("203.0.113.10", "cp.example.com",
// "::1") or a host:port string; when basePort > 0, basePort takes precedence.
func DialPortHop(serverAddr string, basePort int, hopCount int, psk []byte) (net.PacketConn, error) {
	return DialPortHopWithConfig(serverAddr, basePort, hopCount, psk, PortHopDialConfig{})
}

// DialPortHopWithConfig is DialPortHop with explicit rotation/drain/fallback
// timing (used by fast deterministic tests and benchmarks).
func DialPortHopWithConfig(serverAddr string, basePort int, hopCount int, psk []byte, dcfg PortHopDialConfig) (*PortHopDialConn, error) {
	if len(psk) == 0 {
		return nil, errors.New("port-hop PSK must not be empty")
	}
	serverAddr = strings.TrimSpace(serverAddr)
	if serverAddr == "" {
		return nil, errors.New("port-hop serverAddr must not be empty")
	}

	host := serverAddr
	if h, pStr, splitErr := net.SplitHostPort(serverAddr); splitErr == nil {
		host = h
		if basePort <= 0 {
			if p, convErr := strconv.Atoi(pStr); convErr == nil {
				basePort = p
			}
		}
	} else {
		host = strings.Trim(host, "[]")
	}
	if basePort <= 0 || basePort > 65535 {
		return nil, fmt.Errorf("invalid port-hop basePort %d", basePort)
	}
	if hopCount <= 0 {
		hopCount = DefaultPortHopPorts
	}
	if hopCount > 64 {
		hopCount = 64
	}

	target := net.JoinHostPort(host, strconv.Itoa(basePort))
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil || raddr == nil || raddr.Port <= 0 {
		return nil, fmt.Errorf("resolving port-hop peer %q: %w", target, err)
	}

	network := "udp4"
	if raddr.IP.To4() == nil {
		network = "udp6"
	}

	sock0, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, fmt.Errorf("opening port-hop udp socket: %w", err)
	}
	tuneUDPSocket(sock0)

	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		_ = sock0.Close()
		return nil, err
	}

	interval := dcfg.HopInterval
	if interval <= 0 {
		interval = DefaultPortHopInterval
	}
	drainWin := dcfg.DrainWindow
	if drainWin <= 0 {
		drainWin = DefaultPortHopDrainWindow
	}
	fbWait := dcfg.FallbackWait
	if fbWait <= 0 {
		fbWait = defaultPortHopFallbackWait
	}
	if maxFB := (interval * 2) / 3; maxFB > 0 && fbWait > maxFB {
		fbWait = maxFB
		if fbWait < 40*time.Millisecond {
			fbWait = 40 * time.Millisecond
		}
	}

	c := &PortHopDialConn{
		keys:          derivePortHopKeys(psk),
		sessionID:     sid,
		network:       network,
		remoteIP:      raddr.IP,
		remoteZone:    raddr.Zone,
		basePort:      raddr.Port,
		hopPorts:      hopCount,
		hopInterval:   interval,
		drainWindow:   drainWin,
		fallbackWait:  fbWait,
		canonicalPeer: raddr,
		activeSock:    sock0,
		activeDst:     &net.UDPAddr{IP: raddr.IP, Port: raddr.Port, Zone: raddr.Zone},
		allSocks:      map[*net.UDPConn]struct{}{sock0: {}},
		rxCh:          make(chan portHopRxItem, 4096),
		rdl:           newDeadline(),
		wdl:           newDeadline(),
		closedCh:      make(chan struct{}),
	}
	c.peerAddrVal.Store(net.Addr(raddr))

	go c.readSocketLoop(sock0)
	go c.hopLoop()

	return c, nil
}

func newPortHopDialConn(addr string, cfg *Config) (*PortHopDialConn, error) {
	return DialPortHopWithConfig(addr, 0, cfg.EffectivePortHopPorts(), cfg.secret, PortHopDialConfig{
		HopInterval: cfg.PortHopInterval,
	})
}

// RemoteAddr returns the canonical server UDPAddr (serverIP:basePort) suitable
// for passing directly to kcp.NewConn2.
func (c *PortHopDialConn) RemoteAddr() net.Addr {
	return c.canonicalPeer
}

// HopCount returns the number of socket/port rotations completed so far.
func (c *PortHopDialConn) HopCount() uint64 {
	return c.hopCount.Load()
}

// FallbackLocked reports whether target destination port hopping fell back and
// locked onto basePort while continuing local srcPort rotation.
func (c *PortHopDialConn) FallbackLocked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fallbackLocked
}

func (c *PortHopDialConn) hopLoop() {
	ticker := time.NewTicker(c.hopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			c.rotateOnce()
		}
	}
}

func (c *PortHopDialConn) rotateOnce() {
	if c.closed.Load() {
		return
	}
	newSock, err := net.ListenUDP(c.network, nil)
	if err != nil {
		return
	}
	tuneUDPSocket(newSock)

	// Start reading on the new socket BEFORE directing outbound packets through
	// it so even sub-millisecond loopback replies are never missed.
	go c.readSocketLoop(newSock)

	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		_ = newSock.Close()
		return
	}

	maxOffset := c.hopPorts
	if c.basePort+maxOffset-1 > 65535 {
		maxOffset = 65535 - c.basePort + 1
	}
	if maxOffset < 1 {
		maxOffset = 1
	}

	if c.activeDst != nil && c.activeDst.Port != c.basePort && c.txSinceHop.Load() > 0 && c.rxSinceHop.Load() == 0 {
		c.fallbackLocked = true
	}

	c.hopStep++
	nextPort := c.basePort
	if !c.fallbackLocked && maxOffset > 1 {
		nextPort = c.basePort + (c.hopStep % maxOffset)
	}

	oldSock := c.activeSock
	c.activeSock = newSock
	c.activeDst = &net.UDPAddr{IP: c.remoteIP, Port: nextPort, Zone: c.remoteZone}
	c.allSocks[newSock] = struct{}{}

	epoch := c.hopEpoch.Add(1)
	c.txSinceHop.Store(0)
	c.rxSinceHop.Store(0)
	c.hopCount.Add(1)
	c.mu.Unlock()

	// Send an immediate 0-byte authenticated reachability ping on hopped ports so
	// blocked cloud security rules are detected even when the stream is idle or
	// waiting on ACKs.
	if nextPort != c.basePort {
		var pingArr [portHopHeaderSize]byte
		if pingPkt, encErr := encodePortHopPacket(pingArr[:0], &c.keys, c.sessionID, nil); encErr == nil {
			dst := &net.UDPAddr{IP: c.remoteIP, Port: nextPort, Zone: c.remoteZone}
			if _, wErr := newSock.WriteToUDP(pingPkt, dst); wErr == nil {
				c.txSinceHop.Add(1)
			}
		}
		time.AfterFunc(c.fallbackWait, func() {
			c.checkHopFallback(epoch, nextPort)
		})
	}

	// Keep the previous socket open and reading in the background for the 4s
	// drain window so delayed packets and ACKs are not dropped, then close it.
	if oldSock != nil {
		time.AfterFunc(c.drainWindow, func() {
			c.mu.Lock()
			if c.allSocks == nil {
				c.mu.Unlock()
				return
			}
			if c.activeSock != oldSock {
				delete(c.allSocks, oldSock)
				c.mu.Unlock()
				_ = oldSock.Close()
				return
			}
			c.mu.Unlock()
		})
	}
}

func (c *PortHopDialConn) checkHopFallback(epoch uint64, hoppedPort int) {
	if c.closed.Load() || c.hopEpoch.Load() != epoch {
		return
	}
	if c.txSinceHop.Load() == 0 || c.rxSinceHop.Load() > 0 {
		return
	}

	c.mu.Lock()
	if !c.closed.Load() && c.hopEpoch.Load() == epoch && c.activeDst != nil && c.activeDst.Port == hoppedPort {
		c.fallbackLocked = true
		c.activeDst = &net.UDPAddr{IP: c.remoteIP, Port: c.basePort, Zone: c.remoteZone}
	}
	c.mu.Unlock()
}

func (c *PortHopDialConn) readSocketLoop(sock *net.UDPConn) {
	for {
		bp := portHopBufPool.Get().(*[]byte)
		buf := *bp
		n, raddr, err := sock.ReadFromUDP(buf)
		if err != nil {
			portHopBufPool.Put(bp)
			return
		}
		if n < portHopHeaderSize {
			portHopBufPool.Put(bp)
			continue
		}

		sid, payload, ok := decodePortHopPacket(buf[:n], &c.keys)
		if !ok || sid != c.sessionID {
			// Silently discard invalid, unauthenticated, or foreign packets.
			portHopBufPool.Put(bp)
			continue
		}

		// Only count inbound packets on the currently active socket and target
		// port toward hop reachability, so delayed packets draining on the
		// previous socket from basePort cannot mask a blocked companion port.
		c.mu.RLock()
		onActiveHop := c.activeSock == sock && c.activeDst != nil && raddr != nil && raddr.Port == c.activeDst.Port
		c.mu.RUnlock()
		if onActiveHop {
			c.rxSinceHop.Add(1)
		}
		if len(payload) == 0 {
			portHopBufPool.Put(bp)
			continue
		}

		pLen := len(payload)
		copy(buf[:pLen], payload)
		peerAddr, _ := c.peerAddrVal.Load().(net.Addr)
		if peerAddr == nil {
			peerAddr = c.canonicalPeer
		}

		select {
		case c.rxCh <- portHopRxItem{bufPtr: bp, n: pLen, addr: peerAddr}:
		case <-c.closedCh:
			portHopBufPool.Put(bp)
			return
		default:
			portHopBufPool.Put(bp)
		}
	}
}

func (c *PortHopDialConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *PortHopDialConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if addr != nil {
		if cur, _ := c.peerAddrVal.Load().(net.Addr); cur == nil || cur.String() != addr.String() {
			c.peerAddrVal.Store(addr)
		}
	}

	c.mu.RLock()
	sock := c.activeSock
	dst := c.activeDst
	c.mu.RUnlock()
	if sock == nil || dst == nil {
		return 0, net.ErrClosed
	}

	need := portHopHeaderSize + len(p)
	if need <= 2048 {
		bp := portHopBufPool.Get().(*[]byte)
		pkt, err := encodePortHopPacket((*bp)[:0], &c.keys, c.sessionID, p)
		if err != nil {
			portHopBufPool.Put(bp)
			return 0, err
		}
		_, err = sock.WriteToUDP(pkt, dst)
		portHopBufPool.Put(bp)
		if err != nil {
			return 0, err
		}
		c.txSinceHop.Add(1)
		return len(p), nil
	}

	pkt, err := encodePortHopPacket(nil, &c.keys, c.sessionID, p)
	if err != nil {
		return 0, err
	}
	if _, err := sock.WriteToUDP(pkt, dst); err != nil {
		return 0, err
	}
	c.txSinceHop.Add(1)
	return len(p), nil
}

func (c *PortHopDialConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
		c.mu.Lock()
		socks := make([]*net.UDPConn, 0, len(c.allSocks))
		for s := range c.allSocks {
			socks = append(socks, s)
		}
		c.allSocks = nil
		c.activeSock = nil
		c.mu.Unlock()
		for _, s := range socks {
			_ = s.Close()
		}
	})
	return nil
}

func (c *PortHopDialConn) LocalAddr() net.Addr {
	c.mu.RLock()
	sock := c.activeSock
	c.mu.RUnlock()
	if sock != nil {
		return sock.LocalAddr()
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *PortHopDialConn) SetDeadline(t time.Time) error {
	c.rdl.set(t)
	c.wdl.set(t)
	return nil
}

func (c *PortHopDialConn) SetReadDeadline(t time.Time) error {
	c.rdl.set(t)
	return nil
}

func (c *PortHopDialConn) SetWriteDeadline(t time.Time) error {
	c.wdl.set(t)
	return nil
}

func tuneUDPSocket(uc *net.UDPConn) {
	if uc == nil {
		return
	}
	_ = uc.SetReadBuffer(4 * 1024 * 1024)
	_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	growSocketBuffers(uc, 4*1024*1024)
}

// EffectivePortHopPorts returns the configured number of UDP ports in the
// port-hopping pool (clamped to 1..64, defaulting to DefaultPortHopPorts).
func (c *Config) EffectivePortHopPorts() int {
	if c == nil || c.PortHopPorts <= 0 {
		return DefaultPortHopPorts
	}
	if c.PortHopPorts > 64 {
		return 64
	}
	return c.PortHopPorts
}

// EffectivePortHopInterval returns the configured client socket/port rotation
// period, defaulting to DefaultPortHopInterval when unset.
func (c *Config) EffectivePortHopInterval() time.Duration {
	if c == nil || c.PortHopInterval <= 0 {
		return DefaultPortHopInterval
	}
	return c.PortHopInterval
}

// PortHopEndPort returns the highest UDP port number in the port-hop range
// starting at basePort for hopPorts consecutive ports.
func PortHopEndPort(basePort, hopPorts int) int {
	if hopPorts <= 0 {
		hopPorts = DefaultPortHopPorts
	}
	end := basePort + hopPorts - 1
	if end > 65535 {
		end = 65535
	}
	return end
}

// FormatPortHopRange formats "7465–7472" (or "7465" when hopPorts <= 1).
func FormatPortHopRange(portStr string, hopPorts int) string {
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 {
		return portStr
	}
	end := PortHopEndPort(p, hopPorts)
	if end <= p {
		return strconv.Itoa(p)
	}
	return fmt.Sprintf("%d–%d", p, end)
}

// ---------------------------------------------------------------------------
// Firewall Helpers (iptables / ip6tables / nftables)
// ---------------------------------------------------------------------------

// PortHopFirewallTag formats a sanitized firewall comment tag ("portbridge-<id>")
// for clean rule identification and teardown.
func PortHopFirewallTag(sessionID string) string {
	var b strings.Builder
	b.WriteString("portbridge-")
	for i := 0; i < len(sessionID); i++ {
		ch := sessionID[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			b.WriteByte(ch)
		}
	}
	if b.Len() == len("portbridge-") {
		b.WriteString("default")
	}
	return b.String()
}

// BuildPortHopIPTablesRules builds the ordered iptables/ip6tables INPUT rule
// specifications to lock UDP port range basePort:endPort exclusively to peerIP
// (plus loopback), tagged with comment "portbridge-<sessionID>".
func BuildPortHopIPTablesRules(peerIP string, basePort, hopCount int, sessionID string) (tool string, rules [][]string, err error) {
	ip := net.ParseIP(strings.TrimSpace(peerIP))
	if ip == nil {
		return "", nil, fmt.Errorf("invalid peer IP %q", peerIP)
	}
	if basePort <= 0 || basePort > 65535 {
		return "", nil, fmt.Errorf("invalid basePort %d", basePort)
	}
	endPort := PortHopEndPort(basePort, hopCount)
	portSpec := strconv.Itoa(basePort)
	if endPort > basePort {
		portSpec = fmt.Sprintf("%d:%d", basePort, endPort)
	}
	tag := PortHopFirewallTag(sessionID)

	loopback := "127.0.0.1"
	tool = "iptables"
	if ip.To4() == nil {
		tool = "ip6tables"
		loopback = "::1"
	}

	// Inserted at top of INPUT (-I INPUT 1) in order: DROP first, then loopback
	// ACCEPT, then peer ACCEPT so allowed sources sit above DROP.
	rules = [][]string{
		{"-I", "INPUT", "1", "-p", "udp", "--dport", portSpec, "-m", "comment", "--comment", tag, "-j", "DROP"},
		{"-I", "INPUT", "1", "-s", loopback, "-p", "udp", "--dport", portSpec, "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
		{"-I", "INPUT", "1", "-s", ip.String(), "-p", "udp", "--dport", portSpec, "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
	}
	return tool, rules, nil
}

// BuildPortHopNFTablesRules builds an nftables command snippet that creates a
// dedicated inet chain tagged with "portbridge-<sessionID>" locking UDP port
// range basePort-endPort to peerIP, and a matching teardown command.
func BuildPortHopNFTablesRules(peerIP string, basePort, hopCount int, sessionID string) (applyScript, teardownScript string, err error) {
	ip := net.ParseIP(strings.TrimSpace(peerIP))
	if ip == nil {
		return "", "", fmt.Errorf("invalid peer IP %q", peerIP)
	}
	if basePort <= 0 || basePort > 65535 {
		return "", "", fmt.Errorf("invalid basePort %d", basePort)
	}
	endPort := PortHopEndPort(basePort, hopCount)
	portRange := strconv.Itoa(basePort)
	if endPort > basePort {
		portRange = fmt.Sprintf("%d-%d", basePort, endPort)
	}
	tag := PortHopFirewallTag(sessionID)
	chain := strings.ReplaceAll(tag, "-", "_")

	addrFamily := "ip"
	loopback := "127.0.0.1"
	if ip.To4() == nil {
		addrFamily = "ip6"
		loopback = "::1"
	}

	applyScript = fmt.Sprintf(
		"nft add table inet portbridge\n"+
			"nft 'add chain inet portbridge %s { type filter hook input priority -10; policy accept; }'\n"+
			"nft flush chain inet portbridge %s\n"+
			"nft add rule inet portbridge %s %s saddr %s udp dport %s accept comment %q\n"+
			"nft add rule inet portbridge %s %s saddr %s udp dport %s accept comment %q\n"+
			"nft add rule inet portbridge %s udp dport %s drop comment %q\n",
		chain, chain,
		chain, addrFamily, ip.String(), portRange, tag,
		chain, addrFamily, loopback, portRange, tag,
		chain, portRange, tag,
	)
	teardownScript = fmt.Sprintf(
		"nft flush chain inet portbridge %s 2>/dev/null || true\n"+
			"nft delete chain inet portbridge %s 2>/dev/null || true\n",
		chain, chain,
	)
	return applyScript, teardownScript, nil
}
