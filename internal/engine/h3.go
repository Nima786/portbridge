package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	defaultH3Path    = "/api/v3/stream"
	h3HelloMagicByte = 0x31
)

var errH3Handshake = errors.New("h3 handshake failed")

func (c *Config) effectiveH3Path() string {
	if c != nil && c.WSPath != "" {
		clean := strings.TrimRight(c.WSPath, "/")
		if clean != "" {
			return clean
		}
	}
	return defaultH3Path
}

func h3HelloToken(secret []byte, nonce [16]byte) [9]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pb-h3-hello-v1:"))
	mac.Write(nonce[:])
	sum := mac.Sum(nil)
	var out [9]byte
	out[0] = h3HelloMagicByte
	copy(out[1:], sum[:8])
	return out
}

func h3QUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 90 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          1024,
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 4 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
	}
}

func h3ClientTLSConfig(cfg *Config) *tls.Config {
	sni := cfg.EffectiveServerName()
	if cfg != nil && cfg.Dials() {
		sni = cfg.effectiveClientName()
	}
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // Authenticated via HMAC-SHA256 session token + server hello proof
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http3.NextProtoH3},
	}
}

// h3PreConn holds a freshly dialed QUIC v1 connection returned by router.dialRoute
// before wrapDialPurpose opens the HTTP/3 stream(s) on top of it.
// Once wrapDialPurpose takes ownership (markHandedOff), calling Close() on h3PreConn
// (for example via `defer raw.Close()` in speedtest/edge helpers) becomes a no-op.
type h3PreConn struct {
	uconn     *net.UDPConn
	qtr       *quic.Transport
	qconn     *quic.Conn
	handedOff atomic.Bool
	closeOnce sync.Once
}

func dialH3QUICRaw(targetAddr string, cfg *Config, timeout time.Duration) (*net.UDPConn, *quic.Transport, *quic.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	udpAddr, err := resolveUDPTarget(targetAddr, timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	var localAddr *net.UDPAddr
	if cfg != nil {
		localAddr = cfg.sourceForUDP(udpAddr.String())
	}
	netProto := "udp"
	if udpAddr.IP != nil {
		if udpAddr.IP.To4() != nil {
			netProto = "udp4"
		} else {
			netProto = "udp6"
		}
	}
	uconn, err := net.ListenUDP(netProto, localAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	tuneUDPSocket(uconn)

	qtr := &quic.Transport{Conn: uconn}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	qconn, err := qtr.Dial(ctx, udpAddr, h3ClientTLSConfig(cfg), h3QUICConfig())
	if err != nil {
		_ = qtr.Close()
		_ = uconn.Close()
		return nil, nil, nil, err
	}
	return uconn, qtr, qconn, nil
}

func resolveUDPTarget(targetAddr string, timeout time.Duration) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid UDP port in %q", targetAddr)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no IP addresses found for %s", host)
		}
		return nil, err
	}
	// Prefer IPv4 first for broad UDP route compatibility unless only IPv6 exists.
	for _, ipa := range ips {
		if v4 := ipa.IP.To4(); v4 != nil {
			return &net.UDPAddr{IP: v4, Port: port}, nil
		}
	}
	return &net.UDPAddr{IP: ips[0].IP, Zone: ips[0].Zone, Port: port}, nil
}

func dialH3QUIC(targetAddr string, cfg *Config, timeout time.Duration) (net.Conn, error) {
	uconn, qtr, qconn, err := dialH3QUICRaw(targetAddr, cfg, timeout)
	if err != nil {
		return nil, err
	}
	return &h3PreConn{
		uconn: uconn,
		qtr:   qtr,
		qconn: qconn,
	}, nil
}

func (p *h3PreConn) takeOwnership() {
	p.handedOff.Store(true)
}

func (p *h3PreConn) forceClose() {
	p.closeOnce.Do(func() {
		if p.qconn != nil {
			_ = p.qconn.CloseWithError(0, "")
		}
		if p.qtr != nil {
			_ = p.qtr.Close()
		}
		if p.uconn != nil {
			_ = p.uconn.Close()
		}
	})
}

func (p *h3PreConn) Read([]byte) (int, error) {
	return 0, errors.New("h3PreConn cannot be read directly")
}
func (p *h3PreConn) Write([]byte) (int, error) {
	return 0, errors.New("h3PreConn cannot be written directly")
}
func (p *h3PreConn) LocalAddr() net.Addr  { return p.qconn.LocalAddr() }
func (p *h3PreConn) RemoteAddr() net.Addr { return p.qconn.RemoteAddr() }
func (p *h3PreConn) SetDeadline(t time.Time) error {
	if !t.IsZero() && !time.Now().Before(t) && !p.handedOff.Load() {
		p.forceClose()
	}
	return nil
}
func (p *h3PreConn) SetReadDeadline(time.Time) error  { return nil }
func (p *h3PreConn) SetWriteDeadline(time.Time) error { return nil }
func (p *h3PreConn) Close() error {
	if p.handedOff.Load() {
		return nil
	}
	p.forceClose()
	return nil
}

// ---------------------------------------------------------------------------
// Client Side: Direct HTTP/3 Stream & CDN HTTP/3 Split-Stream (XHTTP over H3)
// ---------------------------------------------------------------------------

func h3DialPurpose(raw net.Conn, cfg *Config, purpose byte) (net.Conn, error) {
	var pre *h3PreConn
	if p, ok := raw.(*h3PreConn); ok {
		pre = p
	} else {
		target := ""
		if raw != nil && raw.RemoteAddr() != nil {
			target = raw.RemoteAddr().String()
		}
		if raw != nil {
			_ = raw.Close()
		}
		if target == "" {
			target = cfg.dialTarget()
		}
		dialed, err := dialH3QUIC(target, cfg, tlsHandshakeTimeout)
		if err != nil {
			return nil, err
		}
		pre = dialed.(*h3PreConn)
	}

	if cfg.CDN {
		return h3DialCDN(pre, cfg, purpose)
	}
	return h3DialDirect(pre, cfg, purpose)
}

func h3DialDirect(pre *h3PreConn, cfg *Config, purpose byte) (net.Conn, error) {
	frame, err := buildAuthFrameV2(cfg.secret, purpose)
	if err != nil {
		pre.forceClose()
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(frame)

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		pre.forceClose()
		return nil, err
	}

	h3tr := &http3.Transport{
		TLSClientConfig:    h3ClientTLSConfig(cfg),
		QUICConfig:         h3QUICConfig(),
		DisableCompression: true,
	}
	cc := h3tr.NewClientConn(pre.qconn)

	ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
	defer cancel()

	rstream, err := cc.OpenRequestStream(ctx)
	if err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: open stream: %v", errH3Handshake, err)
	}

	host := cfg.EffectiveServerName()
	reqURL := "https://" + host + cfg.effectiveH3Path()
	req, err := http.NewRequest(http.MethodPost, reqURL, http.NoBody)
	if err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, err
	}
	req.ContentLength = -1
	req.Header.Set("User-Agent", browserProfiles[0].userAgent)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Session-Token", token)
	req.Header.Set("X-Request-Nonce", hex.EncodeToString(nonce[:]))
	req.Header.Set("X-Padding", xhttpPaddingHeader())

	_ = rstream.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := rstream.SendRequestHeader(req); err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: send headers: %v", errH3Handshake, err)
	}

	resp, err := rstream.ReadResponse()
	if err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: read response: %v", errH3Handshake, err)
	}
	if resp.StatusCode != http.StatusOK {
		rstream.CancelRead(0)
		rstream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: status %s", errH3Handshake, resp.Status)
	}

	var gotHello [9]byte
	if _, err := io.ReadFull(rstream, gotHello[:]); err != nil {
		rstream.CancelRead(0)
		rstream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: reading hello: %v", errH3Handshake, err)
	}
	wantHello := h3HelloToken(cfg.secret, nonce)
	if subtle.ConstantTimeCompare(gotHello[:], wantHello[:]) != 1 {
		rstream.CancelRead(0)
		rstream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: invalid server hello signature", errH3Handshake)
	}
	_ = rstream.SetDeadline(time.Time{})

	pre.takeOwnership()
	return &h3ClientConn{
		rstream:       rstream,
		h3tr:          h3tr,
		pre:           pre,
		earlyPurposeB: purpose,
	}, nil
}

type h3ClientConn struct {
	rstream       *http3.RequestStream
	h3tr          *http3.Transport
	pre           *h3PreConn
	earlyPurposeB byte
	closeOnce     sync.Once
}

func (c *h3ClientConn) isEarlyAuthed() bool                { return true }
func (c *h3ClientConn) earlyPurpose() byte                 { return c.earlyPurposeB }
func (c *h3ClientConn) Read(p []byte) (int, error)         { return c.rstream.Read(p) }
func (c *h3ClientConn) Write(p []byte) (int, error)        { return c.rstream.Write(p) }
func (c *h3ClientConn) LocalAddr() net.Addr                { return c.pre.LocalAddr() }
func (c *h3ClientConn) RemoteAddr() net.Addr               { return c.pre.RemoteAddr() }
func (c *h3ClientConn) SetDeadline(t time.Time) error      { return c.rstream.SetDeadline(t) }
func (c *h3ClientConn) SetReadDeadline(t time.Time) error  { return c.rstream.SetReadDeadline(t) }
func (c *h3ClientConn) SetWriteDeadline(t time.Time) error { return c.rstream.SetWriteDeadline(t) }
func (c *h3ClientConn) CloseWrite() error                  { return c.rstream.Close() }
func (c *h3ClientConn) Close() error {
	c.closeOnce.Do(func() {
		c.rstream.CancelRead(0)
		c.rstream.CancelWrite(0)
		_ = c.rstream.Close()
		_ = c.h3tr.Close()
		c.pre.forceClose()
	})
	return nil
}

// h3DialCDN establishes an HTTP/3 SplitHTTP/XHTTP session:
//   - Downlink: HTTP/3 GET stream (<basePath>/<sid>) reading framed chunks
//   - Uplink:   Sequenced HTTP/3 POST streams (<basePath>/<sid>/<seq>)
//
// When traversing Cloudflare or another HTTP/3 CDN, Cloudflare terminates UDP
// HTTP/3 at its edge and forwards standard HTTP/1.1 GET + POST requests over
// TLS/TCP to the Origin server (stripping HTTP/1.1 chunked framing when packing
// HTTP/3 DATA frames back to the client).
func h3DialCDN(pre *h3PreConn, cfg *Config, purpose byte) (net.Conn, error) {
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		pre.forceClose()
		return nil, err
	}
	sidHex := hex.EncodeToString(sid[:])

	frame, err := buildAuthFrameV2(cfg.secret, purpose)
	if err != nil {
		pre.forceClose()
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(frame)

	host := cfg.EffectiveServerName()
	basePath := cfg.effectiveXHTTPPath()

	h3tr := &http3.Transport{
		TLSClientConfig:    h3ClientTLSConfig(cfg),
		QUICConfig:         h3QUICConfig(),
		DisableCompression: true,
	}
	mainCC := h3tr.NewClientConn(pre.qconn)

	ctx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
	defer cancel()

	downStream, err := mainCC.OpenRequestStream(ctx)
	if err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: open downlink stream: %v", errH3Handshake, err)
	}

	getReq, err := http.NewRequest(http.MethodGet, "https://"+host+basePath+"/"+sidHex, nil)
	if err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, err
	}
	getReq.Header.Set("User-Agent", browserProfiles[0].userAgent)
	getReq.Header.Set("Accept", "*/*")
	getReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	getReq.Header.Set("Cache-Control", "no-cache")
	getReq.Header.Set("X-Session-Token", token)
	getReq.Header.Set("X-Padding", xhttpPaddingHeader())

	_ = downStream.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := downStream.SendRequestHeader(getReq); err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: send GET headers: %v", errH3Handshake, err)
	}
	_ = downStream.Close()

	resp, err := downStream.ReadResponse()
	if err != nil {
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: read GET response: %v", errH3Handshake, err)
	}
	if resp.StatusCode != http.StatusOK {
		downStream.CancelRead(0)
		downStream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: GET status %s", errH3Handshake, resp.Status)
	}

	var helloHdr [5]byte
	if _, err := io.ReadFull(downStream, helloHdr[:]); err != nil {
		downStream.CancelRead(0)
		downStream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: reading greeting header: %v", errH3Handshake, err)
	}
	if helloHdr[0] != xhttpFrameHello || binary.BigEndian.Uint32(helloHdr[1:5]) != 4 {
		downStream.CancelRead(0)
		downStream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: invalid greeting frame", errH3Handshake)
	}
	var gotHello [4]byte
	if _, err := io.ReadFull(downStream, gotHello[:]); err != nil {
		downStream.CancelRead(0)
		downStream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: reading greeting token: %v", errH3Handshake, err)
	}
	wantHello := xhttpHelloToken(cfg.secret, sid)
	if subtle.ConstantTimeCompare(gotHello[:], wantHello[:]) != 1 {
		downStream.CancelRead(0)
		downStream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		return nil, fmt.Errorf("%w: greeting signature mismatch", errH3Handshake)
	}
	_ = downStream.SetDeadline(time.Time{})

	pre.takeOwnership()

	// Pool state for HTTP/3 POST streams: reuses mainCC by default and dials a
	// fresh QUIC connection if mainCC ever exhausts streams or rotates across CleanIPs.
	var postMu sync.Mutex
	activePostCC := mainCC
	var extraPreConns []*h3PreConn
	var cleanIdx atomic.Uint32
	targetAddr := pre.RemoteAddr().String()
	_, defaultPort, _ := net.SplitHostPort(targetAddr)
	if defaultPort == "" {
		defaultPort = "443"
	}

	getPostCC := func(forceNew bool) (*http3.ClientConn, error) {
		postMu.Lock()
		defer postMu.Unlock()
		if !forceNew && activePostCC != nil && activePostCC.Context().Err() == nil {
			return activePostCC, nil
		}
		addr := targetAddr
		if len(cfg.CleanIPs) > 0 {
			idx := int(cleanIdx.Add(1)-1) % len(cfg.CleanIPs)
			if ca := cleanAddr(cfg.CleanIPs[idx], defaultPort); ca != "" {
				addr = ca
			}
		}
		u2, qtr2, qc2, err := dialH3QUICRaw(addr, cfg, 8*time.Second)
		if err != nil && addr != targetAddr {
			u2, qtr2, qc2, err = dialH3QUICRaw(targetAddr, cfg, 8*time.Second)
		}
		if err != nil {
			return nil, err
		}
		extra := &h3PreConn{uconn: u2, qtr: qtr2, qconn: qc2}
		extra.takeOwnership()
		extraPreConns = append(extraPreConns, extra)
		activePostCC = h3tr.NewClientConn(qc2)
		return activePostCC, nil
	}

	secretCopy := append([]byte(nil), cfg.secret...)
	postRT := func(seq uint64, payload []byte, fin bool) error {
		pcc, err := getPostCC(false)
		if err != nil {
			return err
		}
		pctx, pcancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer pcancel()

		buildReq := func() (*http.Request, error) {
			ts := time.Now().Unix()
			mac := xhttpPostMAC(secretCopy, sid, seq, ts, fin)
			postURL := "https://" + host + basePath + "/" + sidHex + "/" + strconv.FormatUint(seq, 10)
			var bodyReader io.Reader
			if len(payload) > 0 {
				bodyReader = bytes.NewReader(payload)
			}
			req, err := http.NewRequestWithContext(pctx, http.MethodPost, postURL, bodyReader)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", browserProfiles[0].userAgent)
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Cache-Control", "no-cache")
			req.Header.Set("X-Request-TS", strconv.FormatInt(ts, 10))
			req.Header.Set("X-Request-Auth", hex.EncodeToString(mac[:]))
			if fin {
				req.Header.Set("X-Stream-Close", "1")
			}
			req.Header.Set("X-Padding", xhttpPaddingHeader())
			return req, nil
		}

		req, err := buildReq()
		if err != nil {
			return err
		}
		presp, err := pcc.RoundTrip(req)
		if err != nil {
			pcc, err = getPostCC(true)
			if err != nil {
				return err
			}
			req, err = buildReq()
			if err != nil {
				return err
			}
			presp, err = pcc.RoundTrip(req)
			if err != nil {
				return err
			}
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(presp.Body, 4096))
		_ = presp.Body.Close()
		if presp.StatusCode != http.StatusOK {
			return fmt.Errorf("h3 xhttp post rejected: %s", presp.Status)
		}
		return nil
	}

	downAdapter := &h3DownStreamConn{
		rstream: downStream,
		local:   pre.LocalAddr(),
		remote:  pre.RemoteAddr(),
	}

	cleanupAll := func() {
		downStream.CancelRead(0)
		downStream.CancelWrite(0)
		_ = h3tr.Close()
		pre.forceClose()
		postMu.Lock()
		extras := extraPreConns
		extraPreConns = nil
		postMu.Unlock()
		for _, ex := range extras {
			ex.forceClose()
		}
	}

	return newXHTTPClientOverH3(
		sid,
		basePath,
		host,
		cfg.secret,
		purpose,
		downAdapter,
		io.NopCloser(downStream),
		postRT,
		cleanupAll,
	), nil
}

type h3DownStreamConn struct {
	rstream *http3.RequestStream
	local   net.Addr
	remote  net.Addr
}

func (d *h3DownStreamConn) Read(p []byte) (int, error)         { return d.rstream.Read(p) }
func (d *h3DownStreamConn) Write(p []byte) (int, error)        { return d.rstream.Write(p) }
func (d *h3DownStreamConn) LocalAddr() net.Addr                { return d.local }
func (d *h3DownStreamConn) RemoteAddr() net.Addr               { return d.remote }
func (d *h3DownStreamConn) SetDeadline(t time.Time) error      { return d.rstream.SetDeadline(t) }
func (d *h3DownStreamConn) SetReadDeadline(t time.Time) error  { return d.rstream.SetReadDeadline(t) }
func (d *h3DownStreamConn) SetWriteDeadline(t time.Time) error { return d.rstream.SetWriteDeadline(t) }
func (d *h3DownStreamConn) Close() error {
	d.rstream.CancelRead(0)
	d.rstream.CancelWrite(0)
	return d.rstream.Close()
}

// ---------------------------------------------------------------------------
// Server Side: HTTP/3 Listener & Dual UDP+TCP CDN Origin Listener
// ---------------------------------------------------------------------------

type h3ConnCtxKey struct{}

type h3Listener struct {
	pconn     net.PacketConn
	ownsConn  bool
	qtr       *quic.Transport
	qln       *quic.Listener
	srv       *http3.Server
	acceptCh  chan net.Conn
	closedCh  chan struct{}
	closeOnce sync.Once
}

func h3Listen(addr string, cfg *Config, cert *tls.Certificate, guard *replayGuard) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	tuneUDPSocket(uconn)

	udpLn, err := h3ListenPacketConn(uconn, true, cfg, cert, guard)
	if err != nil {
		_ = uconn.Close()
		return nil, err
	}

	if cfg != nil && cfg.CDN {
		tcpAddr := addr
		if ua, ok := uconn.LocalAddr().(*net.UDPAddr); ok && ua != nil {
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr == nil {
				tcpAddr = net.JoinHostPort(host, strconv.Itoa(ua.Port))
			}
		}
		tcpLn, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			_ = udpLn.Close()
			return nil, err
		}
		return newCombinedListener(udpLn, tcpLn), nil
	}
	return udpLn, nil
}

func h3ListenPacketConn(pconn net.PacketConn, ownsConn bool, cfg *Config, cert *tls.Certificate, guard *replayGuard) (*h3Listener, error) {
	if cert == nil {
		return nil, errors.New("h3 listener requires a TLS certificate")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{http3.NextProtoH3},
	}

	qtr := &quic.Transport{Conn: pconn}
	qln, err := qtr.Listen(tlsCfg, h3QUICConfig())
	if err != nil {
		_ = qtr.Close()
		return nil, err
	}

	ln := &h3Listener{
		pconn:    pconn,
		ownsConn: ownsConn,
		qtr:      qtr,
		qln:      qln,
		acceptCh: make(chan net.Conn, 128),
		closedCh: make(chan struct{}),
	}

	srv := &http3.Server{
		TLSConfig:  tlsCfg,
		QUICConfig: h3QUICConfig(),
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, h3ConnCtxKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ln.handleH3Request(w, r, cfg, guard)
		}),
	}
	ln.srv = srv

	go func() {
		_ = srv.ServeListener(qln)
	}()

	return ln, nil
}

func (l *h3Listener) handleH3Request(w http.ResponseWriter, r *http.Request, cfg *Config, guard *replayGuard) {
	localAddr := l.pconn.LocalAddr()
	var remoteAddr net.Addr
	if qc, ok := r.Context().Value(h3ConnCtxKey{}).(*quic.Conn); ok && qc != nil {
		localAddr = qc.LocalAddr()
		remoteAddr = qc.RemoteAddr()
	} else if ua, err := net.ResolveUDPAddr("udp", r.RemoteAddr); err == nil {
		remoteAddr = ua
	} else {
		remoteAddr = &net.UDPAddr{}
	}

	directPath := cfg.effectiveH3Path()
	xhttpPrefix := cfg.effectiveXHTTPPath() + "/"

	// 1. Direct / Reverse full-duplex HTTP/3 stream: POST <effectiveH3Path>
	if r.Method == http.MethodPost && r.URL.Path == directPath {
		token := strings.TrimSpace(r.Header.Get("X-Session-Token"))
		frame, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(frame) == 0 {
			writeH3Decoy404(w)
			return
		}
		purpose, err := verifyAuthFrameBytes(frame, cfg.secret, guard)
		if err != nil {
			writeH3Decoy404(w)
			return
		}
		nonceBytes, err := hex.DecodeString(strings.TrimSpace(r.Header.Get("X-Request-Nonce")))
		if err != nil || len(nonceBytes) != 16 {
			writeH3Decoy404(w)
			return
		}
		var nonce [16]byte
		copy(nonce[:], nonceBytes)

		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			writeH3Decoy404(w)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("X-Padding", xhttpPaddingHeader())
		w.WriteHeader(http.StatusOK)

		str := streamer.HTTPStream()
		hello := h3HelloToken(cfg.secret, nonce)
		_ = str.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := str.Write(hello[:]); err != nil {
			str.CancelRead(0)
			str.CancelWrite(0)
			_ = str.Close()
			return
		}
		_ = str.SetWriteDeadline(time.Time{})

		sc := &h3ServerConn{
			stream:        str,
			local:         localAddr,
			remote:        remoteAddr,
			earlyPurposeB: purpose,
		}
		select {
		case l.acceptCh <- sc:
		case <-l.closedCh:
			_ = sc.Close()
		}
		return
	}

	// 2. SplitHTTP / XHTTP over HTTP/3: GET <xhttpPath>/<sid> or POST <xhttpPath>/<sid>/<seq>
	if strings.HasPrefix(r.URL.Path, xhttpPrefix) {
		rest := strings.TrimPrefix(r.URL.Path, xhttpPrefix)
		switch r.Method {
		case http.MethodGet:
			sidBytes, err := hex.DecodeString(rest)
			if err != nil || len(sidBytes) != 16 {
				writeH3Decoy404(w)
				return
			}
			var sid [16]byte
			copy(sid[:], sidBytes)

			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				writeH3Decoy404(w)
				return
			}
			adapter := &h3ServerStreamAdapter{
				local:  localAddr,
				remote: remoteAddr,
			}
			sc, hello, err := defaultXHTTPManager.AcceptH3Get(sid, adapter, r.Header.Get("X-Session-Token"), cfg, guard)
			if err != nil {
				writeH3Decoy404(w)
				return
			}

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store, no-transform")
			w.Header().Set("X-Accel-Buffering", "no")
			w.Header().Set("X-Padding", xhttpPaddingHeader())
			w.WriteHeader(http.StatusOK)

			str := streamer.HTTPStream()
			adapter.attach(str)

			_ = str.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := writeXHTTPDownFrameMode(str, xhttpFrameHello, hello[:], true); err != nil {
				_ = sc.Close()
				return
			}
			var flushPad [1024]byte
			_, _ = rand.Read(flushPad[:])
			if err := writeXHTTPDownFrameMode(str, xhttpFrameKeepAlive, flushPad[:], true); err != nil {
				_ = sc.Close()
				return
			}
			_ = str.SetWriteDeadline(time.Time{})

			sc.startBackground(nil)
			select {
			case l.acceptCh <- sc:
			case <-l.closedCh:
				_ = sc.Close()
			}
			return

		case http.MethodPost:
			status, err := defaultXHTTPManager.DeliverH3Post(rest, r.Header, r.Body, cfg)
			if err != nil {
				if status == http.StatusNotFound {
					writeH3Decoy404(w)
				} else {
					w.WriteHeader(status)
				}
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Padding", xhttpPaddingHeader())
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if r.Body != nil {
		_ = r.Body.Close()
	}
	writeH3Decoy404(w)
}

func writeH3Decoy404(w http.ResponseWriter) {
	const body = "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, body)
}

func (l *h3Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.closedCh:
		return nil, net.ErrClosed
	}
}

func (l *h3Listener) Addr() net.Addr {
	return l.pconn.LocalAddr()
}

func (l *h3Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closedCh)
		if l.srv != nil {
			_ = l.srv.Close()
		}
		if l.qln != nil {
			_ = l.qln.Close()
		}
		if l.qtr != nil {
			_ = l.qtr.Close()
		}
		if l.ownsConn && l.pconn != nil {
			_ = l.pconn.Close()
		}
		for {
			select {
			case c := <-l.acceptCh:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

type h3ServerConn struct {
	stream        *http3.Stream
	local         net.Addr
	remote        net.Addr
	earlyPurposeB byte
	closeOnce     sync.Once
}

func (s *h3ServerConn) isEarlyAuthed() bool                { return true }
func (s *h3ServerConn) earlyPurpose() byte                 { return s.earlyPurposeB }
func (s *h3ServerConn) Read(p []byte) (int, error)         { return s.stream.Read(p) }
func (s *h3ServerConn) Write(p []byte) (int, error)        { return s.stream.Write(p) }
func (s *h3ServerConn) LocalAddr() net.Addr                { return s.local }
func (s *h3ServerConn) RemoteAddr() net.Addr               { return s.remote }
func (s *h3ServerConn) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *h3ServerConn) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *h3ServerConn) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
func (s *h3ServerConn) CloseWrite() error                  { return s.stream.Close() }
func (s *h3ServerConn) Close() error {
	s.closeOnce.Do(func() {
		s.stream.CancelRead(0)
		s.stream.CancelWrite(0)
		_ = s.stream.Close()
	})
	return nil
}

type h3ServerStreamAdapter struct {
	mu     sync.RWMutex
	stream *http3.Stream
	local  net.Addr
	remote net.Addr
}

func (a *h3ServerStreamAdapter) attach(s *http3.Stream) {
	a.mu.Lock()
	a.stream = s
	a.mu.Unlock()
}

func (a *h3ServerStreamAdapter) get() *http3.Stream {
	a.mu.RLock()
	s := a.stream
	a.mu.RUnlock()
	return s
}

func (a *h3ServerStreamAdapter) Read(p []byte) (int, error) {
	s := a.get()
	if s == nil {
		return 0, io.EOF
	}
	return s.Read(p)
}

func (a *h3ServerStreamAdapter) Write(p []byte) (int, error) {
	s := a.get()
	if s == nil {
		return 0, net.ErrClosed
	}
	return s.Write(p)
}

func (a *h3ServerStreamAdapter) LocalAddr() net.Addr  { return a.local }
func (a *h3ServerStreamAdapter) RemoteAddr() net.Addr { return a.remote }

func (a *h3ServerStreamAdapter) SetDeadline(t time.Time) error {
	if s := a.get(); s != nil {
		return s.SetDeadline(t)
	}
	return nil
}

func (a *h3ServerStreamAdapter) SetReadDeadline(t time.Time) error {
	if s := a.get(); s != nil {
		return s.SetReadDeadline(t)
	}
	return nil
}

func (a *h3ServerStreamAdapter) SetWriteDeadline(t time.Time) error {
	if s := a.get(); s != nil {
		return s.SetWriteDeadline(t)
	}
	return nil
}

func (a *h3ServerStreamAdapter) Close() error {
	if s := a.get(); s != nil {
		s.CancelRead(0)
		s.CancelWrite(0)
		return s.Close()
	}
	return nil
}

func (a *h3ServerStreamAdapter) Done() <-chan struct{} {
	if s := a.get(); s != nil {
		return s.Context().Done()
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// combinedListener merges multiple net.Listeners (such as UDP HTTP/3 + TCP TLS
// for CDN origins) into a single net.Listener.
type combinedListener struct {
	listeners []net.Listener
	acceptCh  chan net.Conn
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newCombinedListener(listeners ...net.Listener) net.Listener {
	cl := &combinedListener{
		listeners: listeners,
		acceptCh:  make(chan net.Conn, 128),
		closedCh:  make(chan struct{}),
	}
	for _, ln := range listeners {
		go cl.pump(ln)
	}
	return cl
}

func (cl *combinedListener) pump(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-cl.closedCh:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(25 * time.Millisecond)
			continue
		}
		select {
		case cl.acceptCh <- c:
		case <-cl.closedCh:
			_ = c.Close()
			return
		}
	}
}

func (cl *combinedListener) Accept() (net.Conn, error) {
	select {
	case c := <-cl.acceptCh:
		return c, nil
	case <-cl.closedCh:
		return nil, net.ErrClosed
	}
}

func (cl *combinedListener) Addr() net.Addr {
	if len(cl.listeners) > 0 {
		return cl.listeners[0].Addr()
	}
	return &net.UDPAddr{}
}

func (cl *combinedListener) Close() error {
	cl.closeOnce.Do(func() {
		close(cl.closedCh)
		for _, ln := range cl.listeners {
			_ = ln.Close()
		}
		for {
			select {
			case c := <-cl.acceptCh:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

// ---------------------------------------------------------------------------
// Single-Socket UDP Demultiplexer (QUIC v1/v2 vs PortHop/KCP)
// ---------------------------------------------------------------------------

type udpDemuxPacket struct {
	data []byte
	addr net.Addr
}

type udpDemuxHub struct {
	base      net.PacketConn
	quicPeers sync.Map // addrKey(string) -> int64(unixNano)
	closedRef atomic.Int32
	baseOnce  sync.Once
}

type udpDemuxBranch struct {
	hub              *udpDemuxHub
	rxCh             chan udpDemuxPacket
	rdl              *deadline
	readDeadlineNano atomic.Int64
	closed           atomic.Bool
	closedCh         chan struct{}
	closeOnce        sync.Once
}

// demuxQUICAndPacketConn splits a single UDP net.PacketConn into two virtual
// net.PacketConns: quicPC receives QUIC v1/v2 packets (identified by RFC 9000
// >=1200B Long Header Initial packets and pinned per peer UDP address), while
// otherPC receives all remaining UDP datagrams (such as PortHop and KCP).
func demuxQUICAndPacketConn(base net.PacketConn) (quicPC, otherPC net.PacketConn) {
	hub := &udpDemuxHub{base: base}
	qBranch := &udpDemuxBranch{
		hub:      hub,
		rxCh:     make(chan udpDemuxPacket, 1024),
		rdl:      newDeadline(),
		closedCh: make(chan struct{}),
	}
	oBranch := &udpDemuxBranch{
		hub:      hub,
		rxCh:     make(chan udpDemuxPacket, 1024),
		rdl:      newDeadline(),
		closedCh: make(chan struct{}),
	}

	go func() {
		var buf [65535]byte
		var pktCount uint32
		for {
			n, addr, err := base.ReadFrom(buf[:])
			if err != nil {
				if hub.closedRef.Load() >= 2 || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if n <= 0 || addr == nil {
				continue
			}
			now := time.Now().UnixNano()
			pktCount++
			if pktCount&0x3ff == 0 {
				cutoff := now - int64(3*time.Minute)
				hub.quicPeers.Range(func(k, v any) bool {
					if ts, ok := v.(int64); ok && ts < cutoff {
						hub.quicPeers.Delete(k)
					}
					return true
				})
			}

			raw := buf[:n]
			key := addr.String()
			toQUIC := false
			if isQUICInitialPacket(raw) {
				hub.quicPeers.Store(key, now)
				toQUIC = true
			} else if v, ok := hub.quicPeers.Load(key); ok {
				if ts, ok := v.(int64); ok && now-ts < int64(3*time.Minute) {
					hub.quicPeers.Store(key, now)
					toQUIC = true
				} else {
					hub.quicPeers.Delete(key)
				}
			}

			cp := make([]byte, n)
			copy(cp, raw)
			target := oBranch
			if toQUIC {
				target = qBranch
			}
			if !target.closed.Load() {
				select {
				case target.rxCh <- udpDemuxPacket{data: cp, addr: addr}:
				default:
				}
			}
		}
	}()

	return qBranch, oBranch
}

func isQUICInitialPacket(pkt []byte) bool {
	// RFC 9000 §14.1 & §17.2: QUIC Initial UDP datagrams are >= 1200 bytes,
	// start with Long Header + Fixed Bit (0xc0), carry QUIC v1 (0x00000001),
	// QUIC v2 (0x6b3343cf), or Version Negotiation (0x00000000), and have DCID
	// and SCID lengths <= 20 bytes.
	if len(pkt) < 1200 || (pkt[0]&0xc0) != 0xc0 {
		return false
	}
	ver := binary.BigEndian.Uint32(pkt[1:5])
	if ver != 0x00000001 && ver != 0x6b3343cf && ver != 0x00000000 {
		return false
	}
	dcidLen := int(pkt[5])
	if dcidLen > 20 || 6+dcidLen >= len(pkt) {
		return false
	}
	scidLen := int(pkt[6+dcidLen])
	return scidLen <= 20
}

func (b *udpDemuxBranch) ReadFrom(p []byte) (int, net.Addr, error) {
	if b.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if dl := b.readDeadlineNano.Load(); dl != 0 && time.Now().UnixNano() >= dl {
		return 0, nil, os.ErrDeadlineExceeded
	}
	select {
	case pkt := <-b.rxCh:
		return copy(p, pkt.data), pkt.addr, nil
	case <-b.closedCh:
		return 0, nil, net.ErrClosed
	case <-b.rdl.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (b *udpDemuxBranch) WriteTo(p []byte, addr net.Addr) (int, error) {
	if b.closed.Load() {
		return 0, net.ErrClosed
	}
	return b.hub.base.WriteTo(p, addr)
}

func (b *udpDemuxBranch) LocalAddr() net.Addr {
	return b.hub.base.LocalAddr()
}

func (b *udpDemuxBranch) SetDeadline(t time.Time) error {
	_ = b.SetReadDeadline(t)
	return b.SetWriteDeadline(t)
}

func (b *udpDemuxBranch) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		b.readDeadlineNano.Store(0)
	} else {
		b.readDeadlineNano.Store(t.UnixNano())
	}
	b.rdl.set(t)
	return nil
}

func (b *udpDemuxBranch) SetWriteDeadline(t time.Time) error {
	return b.hub.base.SetWriteDeadline(t)
}

func (b *udpDemuxBranch) SetReadBuffer(bytes int) error {
	if rb, ok := b.hub.base.(interface{ SetReadBuffer(int) error }); ok {
		return rb.SetReadBuffer(bytes)
	}
	return nil
}

func (b *udpDemuxBranch) SetWriteBuffer(bytes int) error {
	if wb, ok := b.hub.base.(interface{ SetWriteBuffer(int) error }); ok {
		return wb.SetWriteBuffer(bytes)
	}
	return nil
}

func (b *udpDemuxBranch) Close() error {
	b.closeOnce.Do(func() {
		b.closed.Store(true)
		close(b.closedCh)
		if b.hub.closedRef.Add(1) >= 2 {
			b.hub.baseOnce.Do(func() {
				_ = b.hub.base.Close()
			})
		}
	})
	return nil
}
