package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	asymPrefaceLen   = 64
	asymUpMagic      = "ASYMU1"
	asymDownMagic    = "ASYMD1"
	asymReadyAckByte = 0xA5
	asymSkewSeconds  = 120

	asymLegKCPHop byte = 1
	asymLegKCP    byte = 2
	asymLegTLS    byte = 3
	asymLegH3     byte = 4
)

var errAsymHandshake = errors.New("asymmetric pairing handshake failed")

// ValidAsymUplink reports whether s is a supported Asymmetric uplink leg transport.
func ValidAsymUplink(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "xhttp", "split", "wss", "tls", "h3":
		return true
	}
	return false
}

// ValidAsymDownlink reports whether s is a supported Asymmetric downlink leg transport.
func ValidAsymDownlink(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "kcp-hop", "kcp", "tls", "h3":
		return true
	}
	return false
}

func (c *Config) EffectiveAsymUplink() string {
	v := strings.ToLower(strings.TrimSpace(c.AsymUplink))
	if v == "" {
		return "xhttp"
	}
	return v
}

func (c *Config) EffectiveAsymDownlink() string {
	v := strings.ToLower(strings.TrimSpace(c.AsymDownlink))
	if v == "" {
		return "kcp-hop"
	}
	return v
}

func (c *Config) EffectiveAsymDownPort() int {
	if c.AsymDownPort > 0 {
		return c.AsymDownPort
	}
	if _, portStr, err := net.SplitHostPort(c.TunnelAddr); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			return p
		}
	}
	return 443
}

func buildAsymPreface(magic string, domain string, protoOrPurpose byte, flags byte, sid [16]byte, secret []byte) [asymPrefaceLen]byte {
	var buf [asymPrefaceLen]byte
	copy(buf[0:6], magic)
	buf[6] = protoOrPurpose
	buf[7] = flags
	copy(buf[8:24], sid[:])
	binary.BigEndian.PutUint64(buf[24:32], uint64(time.Now().Unix()))

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(domain))
	mac.Write(buf[0:32])
	sum := mac.Sum(nil)
	copy(buf[32:64], sum[:32])
	return buf
}

func verifyAsymPreface(buf [asymPrefaceLen]byte, magic string, domain string, secret []byte, guard *replayGuard) (protoOrPurpose byte, flags byte, sid [16]byte, err error) {
	if string(buf[0:6]) != magic {
		return 0, 0, sid, fmt.Errorf("%w: unexpected magic", errAsymHandshake)
	}
	ts := int64(binary.BigEndian.Uint64(buf[24:32]))
	diff := time.Now().Unix() - ts
	if diff < -asymSkewSeconds || diff > asymSkewSeconds {
		return 0, 0, sid, errAuthSkew
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(domain))
	mac.Write(buf[0:32])
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(buf[32:64], want[:32]) != 1 {
		return 0, 0, sid, errAuthMAC
	}

	if guard != nil {
		var replayTok [authNonceLen]byte
		copy(replayTok[:], buf[32:32+authNonceLen])
		if !guard.admit(replayTok) {
			return 0, 0, sid, errAuthReplay
		}
	}

	protoOrPurpose = buf[6]
	flags = buf[7]
	copy(sid[:], buf[8:24])
	return protoOrPurpose, flags, sid, nil
}

func ensureAsymCert(cfg *Config) (tls.Certificate, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return EnsureCert(cfg.CertFile, cfg.KeyFile, cfg.EffectiveServerName())
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	sni := cfg.EffectiveServerName()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---------------------------------------------------------------------------
// Unified Paired Connection (asymConn)
// ---------------------------------------------------------------------------

type asymConn struct {
	txConn    net.Conn
	rxConn    net.Conn
	closeOnce sync.Once
}

func newAsymConn(txConn, rxConn net.Conn) *asymConn {
	ac := &asymConn{
		txConn: txConn,
		rxConn: rxConn,
	}
	// Drain any transport-layer keepalives arriving on txConn's unused read half
	// (such as SplitHTTP/XHTTP periodic downlink keepalive frames).
	go func() {
		_, _ = io.Copy(io.Discard, txConn)
	}()
	return ac
}

func (a *asymConn) Read(p []byte) (int, error)  { return a.rxConn.Read(p) }
func (a *asymConn) Write(p []byte) (int, error) { return a.txConn.Write(p) }
func (a *asymConn) LocalAddr() net.Addr         { return a.txConn.LocalAddr() }
func (a *asymConn) RemoteAddr() net.Addr        { return a.txConn.RemoteAddr() }

func (a *asymConn) SetDeadline(t time.Time) error {
	_ = a.rxConn.SetReadDeadline(t)
	return a.txConn.SetWriteDeadline(t)
}

func (a *asymConn) SetReadDeadline(t time.Time) error {
	return a.rxConn.SetReadDeadline(t)
}

func (a *asymConn) SetWriteDeadline(t time.Time) error {
	return a.txConn.SetWriteDeadline(t)
}

func (a *asymConn) CloseWrite() error {
	if cw, ok := a.txConn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (a *asymConn) Close() error {
	a.closeOnce.Do(func() {
		_ = a.txConn.Close()
		_ = a.rxConn.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Edge Runtime: Reverse Downlink Listeners + Session Pairing Dialer
// ---------------------------------------------------------------------------

type asymPendingDownlink struct {
	ch   chan net.Conn
	once sync.Once
}

func (p *asymPendingDownlink) deliver(c net.Conn) bool {
	delivered := false
	p.once.Do(func() {
		p.ch <- c
		delivered = true
	})
	return delivered
}

type asymEdgeRuntime struct {
	cfg    *Config
	upCfg  *Config
	cert   tls.Certificate
	guard  *replayGuard
	upOnly *replayGuard

	mu      sync.Mutex
	pending map[[16]byte]*asymPendingDownlink

	kcpLn     net.Listener
	h3Ln      net.Listener
	tcpLn     net.Listener
	boundPort int

	closedCh  chan struct{}
	cancelBg  context.CancelFunc
	closeOnce sync.Once
}

func newAsymEdgeRuntime(cfg *Config, cert tls.Certificate) (*asymEdgeRuntime, error) {
	bgCtx, cancelBg := context.WithCancel(context.Background())
	upCfg := *cfg
	upCfg.Asymmetric = false
	switch cfg.EffectiveAsymUplink() {
	case "xhttp":
		upCfg.Transport = TransportXHTTP
		upCfg.AntiFreeze = false
	case "split":
		upCfg.Transport = TransportTLS
		upCfg.AntiFreeze = true
		upCfg.CDN = false
	case "wss":
		upCfg.Transport = TransportWSS
		upCfg.AntiFreeze = false
	case "tls":
		upCfg.Transport = TransportTLS
		upCfg.AntiFreeze = false
		upCfg.CDN = false
	case "h3":
		upCfg.Transport = TransportH3
		upCfg.AntiFreeze = false
	}
	upCfg.prepareTLS(nil)

	rt := &asymEdgeRuntime{
		cfg:      cfg,
		upCfg:    &upCfg,
		cert:     cert,
		guard:    newReplayGuard(bgCtx),
		upOnly:   newReplayGuard(bgCtx),
		pending:  make(map[[16]byte]*asymPendingDownlink),
		closedCh: make(chan struct{}),
		cancelBg: cancelBg,
	}

	downPort := cfg.EffectiveAsymDownPort()
	listenAddr := net.JoinHostPort("", strconv.Itoa(downPort))

	// Avoid user_listen ports when binding companion Port-Hop UDP sockets.
	avoid := make(map[int]bool)
	for _, ul := range cfg.UserListens {
		if _, pStr, err := net.SplitHostPort(ul); err == nil {
			if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
				avoid[p] = true
			}
		}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolving asymmetric downlink UDP %s: %w", listenAddr, err)
	}
	baseUDP, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("binding asymmetric downlink UDP %s: %w", listenAddr, err)
	}
	tuneUDPSocket(baseUDP)
	if ua, ok := baseUDP.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		rt.boundPort = ua.Port
	} else {
		rt.boundPort = downPort
	}

	quicPC, otherPC := demuxQUICAndPacketConn(baseUDP)

	hopPC, err := wrapPortHopListenConn(otherPC, "", cfg.EffectivePortHopPorts(), cfg.secret, true, avoid)
	if err != nil {
		_ = quicPC.Close()
		_ = otherPC.Close()
		return nil, fmt.Errorf("wrapping asymmetric port-hop UDP: %w", err)
	}

	kcpCfg := *cfg
	kcpCfg.Asymmetric = false
	kcpCfg.Transport = TransportKCP
	kcpCfg.PortHop = true
	kcpCfg.allowPlainKCP = true

	kcpLn, err := kcpServePacketConn(hopPC, &kcpCfg)
	if err != nil {
		_ = quicPC.Close()
		_ = hopPC.Close()
		return nil, fmt.Errorf("serving asymmetric KCP downlink: %w", err)
	}
	rt.kcpLn = kcpLn

	h3Cfg := *cfg
	h3Cfg.Asymmetric = false
	h3Cfg.CDN = false
	h3Cfg.Transport = TransportH3
	h3Ln, err := h3ListenPacketConn(quicPC, true, &h3Cfg, &cert, rt.upOnly)
	if err != nil {
		_ = kcpLn.Close()
		_ = quicPC.Close()
		return nil, fmt.Errorf("serving asymmetric H3 downlink: %w", err)
	}
	rt.h3Ln = h3Ln

	tcpAddr := net.JoinHostPort("", strconv.Itoa(rt.boundPort))
	tcpLn, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		_ = h3Ln.Close()
		_ = kcpLn.Close()
		return nil, fmt.Errorf("binding asymmetric TCP fallback %s: %w", tcpAddr, err)
	}
	rt.tcpLn = tcpLn

	go rt.acceptLoop(rt.kcpLn, false)
	go rt.acceptLoop(rt.h3Ln, false)
	go rt.acceptLoop(rt.tcpLn, true)

	return rt, nil
}

func (rt *asymEdgeRuntime) BoundPort() int {
	return rt.boundPort
}

func (rt *asymEdgeRuntime) acceptLoop(ln net.Listener, wrapTLS bool) {
	tlsServerCfg := &tls.Config{
		Certificates: []tls.Certificate{rt.cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	for {
		raw, err := ln.Accept()
		if err != nil {
			select {
			case <-rt.closedCh:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(25 * time.Millisecond)
			continue
		}
		go rt.handleInboundDownlink(raw, wrapTLS, tlsServerCfg)
	}
}

func (rt *asymEdgeRuntime) handleInboundDownlink(raw net.Conn, wrapTLS bool, tlsCfg *tls.Config) {
	conn := raw
	if wrapTLS {
		tuneSocket(raw)
		ts := tls.Server(raw, tlsCfg)
		_ = raw.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		if err := ts.Handshake(); err != nil {
			_ = raw.Close()
			return
		}
		_ = raw.SetDeadline(time.Time{})
		conn = ts
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var hdr [asymPrefaceLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	_, _, sid, err := verifyAsymPreface(hdr, asymDownMagic, "pb-asym-dn-v1:", rt.cfg.secret, rt.guard)
	if err != nil {
		_ = conn.Close()
		return
	}

	rt.mu.Lock()
	pend := rt.pending[sid]
	rt.mu.Unlock()
	if pend == nil || !pend.deliver(conn) {
		_ = conn.Close()
		return
	}
}

// Dial opens the Uplink leg to Origin (using routeIdx if >= 0, or router.dialIdx
// if routeIdx < 0), transmits ASYMU1, waits for Origin's Reverse Downlink leg
// (ASYMD1), confirms pairing with 0xA5 on the Uplink, and returns the paired
// bidirectional net.Conn after end-to-end purpose authentication.
func (rt *asymEdgeRuntime) Dial(ctx context.Context, routes *router, routeIdx int, timeout time.Duration, purpose byte) (net.Conn, int, error) {
	var raw net.Conn
	var idx int
	var err error

	// Ensure router dials with the Uplink transport (e.g. XHTTP or H3 rather than KCP).
	if routeIdx >= 0 {
		raw, err = rt.dialOneRoute(routes, routeIdx, timeout)
		idx = routeIdx
	} else {
		raw, idx, err = rt.dialAnyRoute(routes, timeout)
	}
	if err != nil {
		return nil, -1, err
	}
	if !rt.upCfg.Transport.IsPacketBased() && rt.upCfg.Transport != TransportH3 {
		tuneSocket(raw)
	}

	rc := rt.routeUpConfig(routes, idx)
	upConn, err := wrapDialPurpose(raw, rc, purpose)
	if err != nil {
		_ = raw.Close()
		if routeIdx < 0 && routes != nil {
			routes.handshakeFailed(idx, err)
		}
		return nil, -1, err
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		_ = upConn.Close()
		return nil, -1, err
	}

	pend := &asymPendingDownlink{ch: make(chan net.Conn, 1)}
	rt.mu.Lock()
	rt.pending[sid] = pend
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		delete(rt.pending, sid)
		rt.mu.Unlock()
	}()

	preface := buildAsymPreface(asymUpMagic, "pb-asym-up-v1:", purpose, 0, sid, rt.cfg.secret)
	_ = upConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := upConn.Write(preface[:]); err != nil {
		_ = upConn.Close()
		if routeIdx < 0 && routes != nil {
			routes.handshakeFailed(idx, err)
		}
		return nil, -1, fmt.Errorf("sending asymmetric uplink preface: %w", err)
	}
	_ = upConn.SetWriteDeadline(time.Time{})

	waitDur := 12 * time.Second
	if timeout > 0 && timeout+4*time.Second > waitDur {
		waitDur = timeout + 4*time.Second
	}
	timer := time.NewTimer(waitDur)
	defer timer.Stop()

	var downConn net.Conn
	select {
	case downConn = <-pend.ch:
	case <-ctx.Done():
		_ = upConn.Close()
		return nil, -1, ctx.Err()
	case <-rt.closedCh:
		_ = upConn.Close()
		return nil, -1, net.ErrClosed
	case <-timer.C:
		_ = upConn.Close()
		if routeIdx < 0 && routes != nil {
			routes.handshakeFailed(idx, errAsymHandshake)
		}
		return nil, -1, fmt.Errorf("%w: timed out waiting for reverse downlink from %s on port %d",
			errAsymHandshake, rt.cfg.PeerIP, rt.boundPort)
	}

	// Signal Origin over upConn that downConn arrived and was authenticated.
	var ack [1]byte
	ack[0] = asymReadyAckByte
	_ = upConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := upConn.Write(ack[:]); err != nil {
		_ = upConn.Close()
		_ = downConn.Close()
		return nil, -1, fmt.Errorf("sending asymmetric ready ack: %w", err)
	}
	_ = upConn.SetWriteDeadline(time.Time{})

	paired := newAsymConn(upConn, downConn)
	if err := sendAuthPurpose(paired, rt.cfg.secret, purpose); err != nil {
		_ = paired.Close()
		if routeIdx < 0 && routes != nil {
			routes.handshakeFailed(idx, err)
		}
		return nil, -1, fmt.Errorf("asymmetric end-to-end auth failed: %w", err)
	}
	if routeIdx < 0 && routes != nil {
		routes.handshakeOK(idx)
	}
	return paired, idx, nil
}

func (rt *asymEdgeRuntime) routeUpConfig(routes *router, idx int) *Config {
	if routes == nil || idx < 0 || idx >= len(routes.targets) {
		return rt.upCfg
	}
	return rt.upCfg.withRoute(routes.targets[idx].name, routes.targets[idx].cdn)
}

func (rt *asymEdgeRuntime) dialOneRoute(routes *router, i int, timeout time.Duration) (net.Conn, error) {
	if routes == nil || i < 0 || i >= len(routes.targets) {
		return nil, errors.New("no such route")
	}
	addr := routes.targets[i].addr
	rc := rt.routeUpConfig(routes, i)
	if rc.Transport == TransportH3 {
		return dialH3QUIC(addr, rc, timeout)
	}
	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: rc.sourceFor(addr),
	}
	return d.Dial("tcp", addr)
}

func (rt *asymEdgeRuntime) dialAnyRoute(routes *router, timeout time.Duration) (net.Conn, int, error) {
	if routes == nil {
		return nil, -1, errors.New("no router configured")
	}
	order := routes.order()
	first := order[0]
	var lastErr error
	for _, i := range order {
		c, err := rt.dialOneRoute(routes, i, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		if i != first {
			log.Printf("reaching the other server via %s instead of %s",
				routes.targets[i].addr, routes.targets[first].addr)
		}
		routes.settle(i)
		return c, i, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no route to the other server is configured")
	}
	return nil, -1, lastErr
}

func (rt *asymEdgeRuntime) Close() error {
	rt.closeOnce.Do(func() {
		close(rt.closedCh)
		if rt.cancelBg != nil {
			rt.cancelBg()
		}
		if rt.tcpLn != nil {
			_ = rt.tcpLn.Close()
		}
		if rt.h3Ln != nil {
			_ = rt.h3Ln.Close()
		}
		if rt.kcpLn != nil {
			_ = rt.kcpLn.Close()
		}
	})
	return nil
}

// ---------------------------------------------------------------------------
// Origin Runtime: Uplink Preface Reader + Reverse Downlink Dialer (+ Fallback)
// ---------------------------------------------------------------------------

type asymOriginRuntime struct {
	cfg              *Config
	guard            *replayGuard
	tcpFallbackUntil atomic.Int64
	fallbackLog      *throttled
}

func newAsymOriginRuntime(ctx context.Context, cfg *Config) *asymOriginRuntime {
	return &asymOriginRuntime{
		cfg:         cfg,
		guard:       newReplayGuard(ctx),
		fallbackLog: newThrottled(),
	}
}

// PairAcceptedUplink reads ASYMU1 from an accepted Uplink connection, dials the
// Reverse Downlink back to Edge (automatically falling back to Reverse TLS over
// TCP if UDP is blocked), waits for Edge's 0xA5 confirmation on upConn, and
// returns the unified bidirectional *asymConn.
func (ao *asymOriginRuntime) PairAcceptedUplink(ctx context.Context, upConn net.Conn) (net.Conn, error) {
	_ = upConn.SetReadDeadline(time.Now().Add(tlsHandshakeTimeout))
	var hdr [asymPrefaceLen]byte
	if _, err := io.ReadFull(upConn, hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: reading uplink preface: %v", errAsymHandshake, err)
	}
	_ = upConn.SetReadDeadline(time.Time{})

	_, _, sid, err := verifyAsymPreface(hdr, asymUpMagic, "pb-asym-up-v1:", ao.cfg.secret, ao.guard)
	if err != nil {
		return nil, err
	}

	targetAddr, err := ao.downlinkTargetAddr(upConn)
	if err != nil {
		return nil, err
	}

	primaryKind := ao.cfg.EffectiveAsymDownlink()
	now := time.Now().UnixNano()
	preferTCPFallback := primaryKind != "tls" && now < ao.tcpFallbackUntil.Load()

	if !preferTCPFallback {
		downConn, legByte, dialErr := ao.dialOneDownlink(ctx, targetAddr, primaryKind)
		if dialErr == nil {
			if ackErr := ao.sendPrefaceAndAwaitAck(upConn, downConn, legByte, 0, sid, 3*time.Second); ackErr == nil {
				return newAsymConn(downConn, upConn), nil
			}
			_ = downConn.Close()
		}
		if primaryKind == "tls" {
			if dialErr != nil {
				return nil, fmt.Errorf("dialing asymmetric TLS downlink %s: %w", targetAddr, dialErr)
			}
			return nil, fmt.Errorf("%w: reverse TLS downlink %s did not receive ready ack", errAsymHandshake, targetAddr)
		}
	}

	// Automatic UDP-blackhole fallback: dial Reverse TLS over TCP to the same Edge port.
	tlsDown, _, tlsErr := ao.dialOneDownlink(ctx, targetAddr, "tls")
	if tlsErr != nil {
		return nil, fmt.Errorf("asymmetric downlink %s failed on both %s and TCP TLS fallback: %w",
			targetAddr, primaryKind, tlsErr)
	}
	if ackErr := ao.sendPrefaceAndAwaitAck(upConn, tlsDown, asymLegTLS, 1, sid, 6*time.Second); ackErr != nil {
		_ = tlsDown.Close()
		return nil, fmt.Errorf("asymmetric TCP TLS fallback %s ack failed: %w", targetAddr, ackErr)
	}
	ao.tcpFallbackUntil.Store(time.Now().Add(2 * time.Minute).UnixNano())
	ao.fallbackLog.printf("asymmetric UDP downlink (%s) to %s was unreachable; fell back automatically to Reverse TLS over TCP",
		primaryKind, targetAddr)
	return newAsymConn(tlsDown, upConn), nil
}

func (ao *asymOriginRuntime) downlinkTargetAddr(upConn net.Conn) (string, error) {
	host := strings.TrimSpace(ao.cfg.PeerIP)
	if host == "" && upConn.RemoteAddr() != nil {
		if h, _, err := net.SplitHostPort(upConn.RemoteAddr().String()); err == nil {
			host = h
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", errors.New("asymmetric origin requires peer_ip to dial back to the relay server")
	}
	return net.JoinHostPort(host, strconv.Itoa(ao.cfg.EffectiveAsymDownPort())), nil
}

func (ao *asymOriginRuntime) sendPrefaceAndAwaitAck(
	upConn net.Conn,
	downConn net.Conn,
	legByte byte,
	flags byte,
	sid [16]byte,
	ackTimeout time.Duration,
) error {
	dnPreface := buildAsymPreface(asymDownMagic, "pb-asym-dn-v1:", legByte, flags, sid, ao.cfg.secret)
	_ = downConn.SetWriteDeadline(time.Now().Add(6 * time.Second))
	if _, err := downConn.Write(dnPreface[:]); err != nil {
		return err
	}
	_ = downConn.SetWriteDeadline(time.Time{})

	_ = upConn.SetReadDeadline(time.Now().Add(ackTimeout))
	var ack [1]byte
	_, err := io.ReadFull(upConn, ack[:])
	_ = upConn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	if ack[0] != asymReadyAckByte {
		return fmt.Errorf("%w: invalid ready ack 0x%02x", errAsymHandshake, ack[0])
	}
	return nil
}

func (ao *asymOriginRuntime) dialOneDownlink(ctx context.Context, targetAddr string, kind string) (net.Conn, byte, error) {
	switch kind {
	case "kcp-hop":
		dnCfg := *ao.cfg
		dnCfg.Asymmetric = false
		dnCfg.CDN = false
		dnCfg.Transport = TransportKCP
		dnCfg.PortHop = true
		c, err := kcpDial(targetAddr, &dnCfg)
		return c, asymLegKCPHop, err

	case "kcp":
		dnCfg := *ao.cfg
		dnCfg.Asymmetric = false
		dnCfg.CDN = false
		dnCfg.Transport = TransportKCP
		dnCfg.PortHop = false
		c, err := kcpDial(targetAddr, &dnCfg)
		return c, asymLegKCP, err

	case "h3":
		dnCfg := *ao.cfg
		dnCfg.Asymmetric = false
		dnCfg.CDN = false
		dnCfg.Transport = TransportH3
		pre, err := dialH3QUIC(targetAddr, &dnCfg, 5*time.Second)
		if err != nil {
			return nil, asymLegH3, err
		}
		c, err := h3DialPurpose(pre, &dnCfg, authPurposeTunnelPooled)
		if err != nil {
			_ = pre.Close()
			return nil, asymLegH3, err
		}
		return c, asymLegH3, nil

	case "tls":
		d := net.Dialer{
			Timeout:   6 * time.Second,
			LocalAddr: ao.cfg.sourceFor(targetAddr),
		}
		raw, err := d.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, asymLegTLS, err
		}
		tuneSocket(raw)
		tcfg := &tls.Config{
			ServerName:         ao.cfg.EffectiveServerName(),
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
		}
		tc := tls.Client(raw, tcfg)
		_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
		if err := tc.Handshake(); err != nil {
			_ = raw.Close()
			return nil, asymLegTLS, err
		}
		_ = raw.SetDeadline(time.Time{})
		return tc, asymLegTLS, nil

	default:
		return nil, 0, fmt.Errorf("unsupported asymmetric downlink %q", kind)
	}
}
