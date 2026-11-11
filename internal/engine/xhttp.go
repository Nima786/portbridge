package engine

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
)

// SplitHTTP (XHTTP) bidirectional HTTP/1.1 streaming transport.
//
// Each logical stream is carried over standard HTTP/1.1 requests without
// Upgrade headers:
//   - Downlink: HTTP/1.1 GET returning 200 OK with Transfer-Encoding: chunked.
//   - Uplink:   Sequenced HTTP/1.1 POST requests over pooled keep-alive TLS
//               connections that automatically rotate before request/byte caps.

const (
	defaultXHTTPPath = "/api/v1/stream"

	xhttpMaxPostBytes      = 512 * 1024
	xhttpMaxSendBuf        = 2 * 1024 * 1024
	xhttpMaxRecvBuf        = 8 * 1024 * 1024
	xhttpMaxReorderSlots   = 32
	xhttpMaxWorkers        = 4
	xhttpMaxReqsPerSocket  = 64
	xhttpMaxBytesPerSocket = 4 * 1024 * 1024
	xhttpMaxDownChunk      = 32 * 1024
	xhttpKeepAliveEvery    = 30 * time.Second
	xhttpSkewSeconds       = 180

	xhttpFrameHello     byte = 0x00
	xhttpFrameData      byte = 0x01
	xhttpFrameKeepAlive byte = 0x02
	xhttpFrameClose     byte = 0x03
)

var (
	errXHTTPHandshake      = errors.New("the other end did not complete the xhttp stream handshake")
	errXHTTPUplinkAttached = errors.New("xhttp uplink connection attached to existing session")

	defaultXHTTPManager = newXHTTPSessionManager()
)

func (c *Config) effectiveXHTTPPath() string {
	p := strings.TrimSpace(c.WSPath)
	if p == "" || p == "/" || p == defaultWSPath {
		return defaultXHTTPPath
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func xhttpHelloToken(secret []byte, sid [16]byte) [4]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pb-xhttp-hello:"))
	mac.Write(sid[:])
	sum := mac.Sum(nil)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
}

func xhttpPostMAC(secret []byte, sid [16]byte, seq uint64, ts int64, fin bool) [16]byte {
	var meta [17]byte
	binary.BigEndian.PutUint64(meta[0:8], seq)
	binary.BigEndian.PutUint64(meta[8:16], uint64(ts))
	if fin {
		meta[16] = 1
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pb-xhttp-post:"))
	mac.Write(sid[:])
	mac.Write(meta[:])
	sum := mac.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func xhttpPaddingHeader() string {
	var b [25]byte
	_, _ = rand.Read(b[:])
	n := 12 + int(b[0]%13) // 12..24 raw bytes -> 16..32 base64url chars
	return base64.RawURLEncoding.EncodeToString(b[1 : 1+n])
}

func writeHTTPChunk(w io.Writer, payload []byte) error {
	var hdr [24]byte
	s := strconv.AppendInt(hdr[:0], int64(len(payload)), 16)
	s = append(s, '\r', '\n')
	buf := make([]byte, len(s)+len(payload)+2)
	copy(buf, s)
	copy(buf[len(s):], payload)
	buf[len(buf)-2] = '\r'
	buf[len(buf)-1] = '\n'
	_, err := w.Write(buf)
	return err
}

func writeXHTTPDownFrame(w io.Writer, ftype byte, data []byte) error {
	frame := make([]byte, 5+len(data))
	frame[0] = ftype
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
	copy(frame[5:], data)
	return writeHTTPChunk(w, frame)
}

// ---------------------------------------------------------------------------
// Server-side Session Manager & Connection
// ---------------------------------------------------------------------------

type xhttpSessionManager struct {
	mu       sync.Mutex
	sessions map[[16]byte]*xhttpServerConn
	closed   bool
}

func newXHTTPSessionManager() *xhttpSessionManager {
	return &xhttpSessionManager{
		sessions: make(map[[16]byte]*xhttpServerConn),
	}
}

func (m *xhttpSessionManager) Close() {
	m.mu.Lock()
	m.closed = true
	list := make([]*xhttpServerConn, 0, len(m.sessions))
	for k, sc := range m.sessions {
		delete(m.sessions, k)
		list = append(list, sc)
	}
	m.mu.Unlock()
	for _, sc := range list {
		_ = sc.Close()
	}
}

// AcceptConn handles an incoming TLS/TCP connection on an XHTTP listener.
// A GET request creates a new logical stream and returns (*xhttpServerConn, nil).
// A POST request attaches uplink payload(s) to an existing session and returns
// (nil, errXHTTPUplinkAttached).
func (m *xhttpSessionManager) AcceptConn(c net.Conn, cfg *Config, guard *replayGuard) (net.Conn, error) {
	if err := c.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, 32*1024)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errXHTTPHandshake, err)
	}
	return m.AcceptParsedRequest(c, br, req, cfg, guard)
}

func (m *xhttpSessionManager) AcceptParsedRequest(c net.Conn, br *bufio.Reader, req *http.Request, cfg *Config, guard *replayGuard) (net.Conn, error) {
	basePath := cfg.effectiveXHTTPPath()
	prefix := basePath + "/"
	if !strings.HasPrefix(req.URL.Path, prefix) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		writeDecoyResponse(c)
		return nil, fmt.Errorf("%w: unexpected path %s", errXHTTPHandshake, req.URL.Path)
	}
	rest := strings.TrimPrefix(req.URL.Path, prefix)

	switch req.Method {
	case http.MethodGet:
		if req.Body != nil {
			_ = req.Body.Close()
		}
		sidBytes, err := hex.DecodeString(rest)
		if err != nil || len(sidBytes) != 16 {
			writeDecoyResponse(c)
			return nil, fmt.Errorf("%w: malformed stream identifier", errXHTTPHandshake)
		}
		var sid [16]byte
		copy(sid[:], sidBytes)

		token := strings.TrimSpace(req.Header.Get("X-Session-Token"))
		frame, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(frame) == 0 {
			writeDecoyResponse(c)
			return nil, fmt.Errorf("%w: missing session token", errXHTTPHandshake)
		}
		purpose, err := verifyAuthFrameBytes(frame, cfg.secret, guard)
		if err != nil {
			writeDecoyResponse(c)
			return nil, fmt.Errorf("%w: session auth failed: %v", errXHTTPHandshake, err)
		}

		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			_ = c.Close()
			return nil, net.ErrClosed
		}
		if _, dup := m.sessions[sid]; dup {
			m.mu.Unlock()
			writeDecoyResponse(c)
			return nil, fmt.Errorf("%w: duplicate session identifier", errXHTTPHandshake)
		}
		sc := newXHTTPServerConn(sid, c, purpose, func() {
			m.mu.Lock()
			delete(m.sessions, sid)
			m.mu.Unlock()
		})
		m.sessions[sid] = sc
		m.mu.Unlock()

		hello := xhttpHelloToken(cfg.secret, sid)
		var respBuf bytes.Buffer
		respBuf.WriteString("HTTP/1.1 200 OK\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Cache-Control: no-store, no-transform\r\n" +
			"X-Accel-Buffering: no\r\n" +
			"X-Padding: " + xhttpPaddingHeader() + "\r\n" +
			"Connection: keep-alive\r\n\r\n")
		_ = writeXHTTPDownFrame(&respBuf, xhttpFrameHello, hello[:])

		if _, err := c.Write(respBuf.Bytes()); err != nil {
			_ = sc.Close()
			return nil, err
		}
		if err := c.SetDeadline(time.Time{}); err != nil {
			_ = sc.Close()
			return nil, err
		}
		sc.startBackground(br)
		return sc, nil

	case http.MethodPost:
		if err := m.handleOnePost(c, req, rest, cfg); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			_ = c.Close()
			return nil, err
		}
		if req.Close {
			_ = c.Close()
			return nil, errXHTTPUplinkAttached
		}
		go m.serveUplinkKeepAlive(c, br, cfg)
		return nil, errXHTTPUplinkAttached

	default:
		if req.Body != nil {
			_ = req.Body.Close()
		}
		writeDecoyResponse(c)
		return nil, fmt.Errorf("%w: unsupported method %s", errXHTTPHandshake, req.Method)
	}
}

func (m *xhttpSessionManager) handleOnePost(c net.Conn, req *http.Request, rest string, cfg *Config) error {
	sidPart, seqPart, ok := strings.Cut(rest, "/")
	if !ok {
		writeDecoyResponse(c)
		return fmt.Errorf("%w: malformed post path", errXHTTPHandshake)
	}
	sidBytes, err := hex.DecodeString(sidPart)
	if err != nil || len(sidBytes) != 16 {
		writeDecoyResponse(c)
		return fmt.Errorf("%w: invalid post session id", errXHTTPHandshake)
	}
	seq, err := strconv.ParseUint(seqPart, 10, 64)
	if err != nil {
		writeDecoyResponse(c)
		return fmt.Errorf("%w: invalid post sequence", errXHTTPHandshake)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(req.Header.Get("X-Request-TS")), 10, 64)
	if err != nil {
		writeDecoyResponse(c)
		return fmt.Errorf("%w: invalid post timestamp", errXHTTPHandshake)
	}
	diff := time.Now().Unix() - ts
	if diff < -xhttpSkewSeconds || diff > xhttpSkewSeconds {
		writeDecoyResponse(c)
		return errAuthSkew
	}
	fin := req.Header.Get("X-Stream-Close") == "1"
	gotMAC, err := hex.DecodeString(strings.TrimSpace(req.Header.Get("X-Request-Auth")))
	if err != nil || len(gotMAC) != 16 {
		writeDecoyResponse(c)
		return errAuthMAC
	}
	var sid [16]byte
	copy(sid[:], sidBytes)
	wantMAC := xhttpPostMAC(cfg.secret, sid, seq, ts, fin)
	if subtle.ConstantTimeCompare(gotMAC, wantMAC[:]) != 1 {
		writeDecoyResponse(c)
		return errAuthMAC
	}

	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, xhttpMaxPostBytes+1))
	_ = req.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > xhttpMaxPostBytes {
		return errors.New("xhttp post body exceeds limit")
	}

	sc := m.lookupSessionWait(sid)
	if sc == nil {
		writeDecoyResponse(c)
		return fmt.Errorf("%w: unknown or expired session", errXHTTPHandshake)
	}
	if err := sc.deliverUplink(seq, body, fin); err != nil {
		return err
	}

	connHdr := "keep-alive"
	if req.Close {
		connHdr = "close"
	}
	reply := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Padding: " + xhttpPaddingHeader() + "\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: " + connHdr + "\r\n\r\n"
	if err := c.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	_, err = io.WriteString(c, reply)
	_ = c.SetDeadline(time.Time{})
	return err
}

func (m *xhttpSessionManager) lookupSessionWait(sid [16]byte) *xhttpServerConn {
	m.mu.Lock()
	sc := m.sessions[sid]
	m.mu.Unlock()
	for i := 0; i < 100 && sc == nil; i++ {
		time.Sleep(15 * time.Millisecond)
		m.mu.Lock()
		sc = m.sessions[sid]
		m.mu.Unlock()
	}
	return sc
}

func (m *xhttpSessionManager) serveUplinkKeepAlive(c net.Conn, br *bufio.Reader, cfg *Config) {
	defer func() { _ = c.Close() }()
	basePrefix := cfg.effectiveXHTTPPath() + "/"
	for {
		if err := c.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
			return
		}
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, basePrefix) {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			writeDecoyResponse(c)
			return
		}
		rest := strings.TrimPrefix(req.URL.Path, basePrefix)
		if err := m.handleOnePost(c, req, rest, cfg); err != nil {
			return
		}
		if req.Close {
			return
		}
	}
}

type xhttpServerConn struct {
	sid           [16]byte
	downConn      net.Conn
	earlyPurposeB byte
	onClose       func()

	wmu        sync.Mutex
	lastWrite  atomic.Int64
	writeEnded bool

	rmu        sync.Mutex
	rxBuf      bytes.Buffer
	reorder    map[uint64][]byte
	nextSeq    uint64
	hasFin     bool
	finSeq     uint64
	remoteEOF  bool
	rxNotify   chan struct{}
	spaceFreed chan struct{}

	rdl              *deadline
	wdl              *deadline
	readDeadlineNano atomic.Int64

	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

func newXHTTPServerConn(sid [16]byte, downConn net.Conn, purpose byte, onClose func()) *xhttpServerConn {
	sc := &xhttpServerConn{
		sid:           sid,
		downConn:      downConn,
		earlyPurposeB: purpose,
		onClose:       onClose,
		reorder:       make(map[uint64][]byte),
		rxNotify:      make(chan struct{}, 1),
		spaceFreed:    make(chan struct{}, 1),
		rdl:           newDeadline(),
		wdl:           newDeadline(),
		closedCh:      make(chan struct{}),
	}
	sc.lastWrite.Store(time.Now().UnixNano())
	return sc
}

func (s *xhttpServerConn) NetConn() net.Conn   { return s.downConn }
func (s *xhttpServerConn) isEarlyAuthed() bool { return true }
func (s *xhttpServerConn) earlyPurpose() byte  { return s.earlyPurposeB }

func (s *xhttpServerConn) startBackground(downBr *bufio.Reader) {
	// Watch downlink socket closure from client/CDN.
	go func() {
		var b [1]byte
		_, _ = downBr.Read(b[:])
		// Allow brief window for any concurrently racing final POST to land.
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-s.closedCh:
			timer.Stop()
			return
		case <-timer.C:
		}
		s.rmu.Lock()
		s.remoteEOF = true
		s.rmu.Unlock()
		s.signalRx()
	}()

	// Periodic downlink keepalive frame so CDN idle timers never cut parked links.
	go func() {
		ticker := time.NewTicker(xhttpKeepAliveEvery)
		defer ticker.Stop()
		for {
			select {
			case <-s.closedCh:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, s.lastWrite.Load())) < xhttpKeepAliveEvery-2*time.Second {
					continue
				}
				s.wmu.Lock()
				if !s.closed.Load() && !s.writeEnded {
					_ = s.downConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					err := writeXHTTPDownFrame(s.downConn, xhttpFrameKeepAlive, nil)
					_ = s.downConn.SetWriteDeadline(time.Time{})
					s.lastWrite.Store(time.Now().UnixNano())
					if err != nil {
						s.wmu.Unlock()
						_ = s.Close()
						return
					}
				}
				s.wmu.Unlock()
			}
		}
	}()
}

func (s *xhttpServerConn) signalRx() {
	select {
	case s.rxNotify <- struct{}{}:
	default:
	}
}

func (s *xhttpServerConn) deliverUplink(seq uint64, payload []byte, fin bool) error {
	for {
		if s.closed.Load() {
			return net.ErrClosed
		}
		s.rmu.Lock()
		if seq < s.nextSeq {
			// Idempotent retry of an already-reassembled sequence number.
			if fin && (!s.hasFin || seq < s.finSeq) {
				s.hasFin = true
				s.finSeq = seq
				if s.nextSeq >= s.finSeq {
					s.remoteEOF = true
				}
			}
			s.rmu.Unlock()
			s.signalRx()
			return nil
		}
		if seq > s.nextSeq+xhttpMaxReorderSlots {
			s.rmu.Unlock()
			select {
			case <-s.closedCh:
				return net.ErrClosed
			case <-s.spaceFreed:
				continue
			case <-time.After(15 * time.Second):
				return errors.New("xhttp uplink reorder window stalled")
			}
		}
		if seq == s.nextSeq && s.rxBuf.Len()+len(payload) > xhttpMaxRecvBuf && s.rxBuf.Len() > 0 {
			s.rmu.Unlock()
			select {
			case <-s.closedCh:
				return net.ErrClosed
			case <-s.spaceFreed:
				continue
			case <-time.After(15 * time.Second):
				return errors.New("xhttp uplink receive buffer full")
			}
		}

		if fin && (!s.hasFin || seq+1 < s.finSeq) {
			s.hasFin = true
			if len(payload) == 0 {
				s.finSeq = seq
			} else {
				s.finSeq = seq + 1
			}
		}

		if seq == s.nextSeq {
			if len(payload) > 0 {
				_, _ = s.rxBuf.Write(payload)
			}
			if !fin || len(payload) > 0 {
				s.nextSeq++
			}
			for {
				next, ok := s.reorder[s.nextSeq]
				if !ok {
					break
				}
				delete(s.reorder, s.nextSeq)
				if len(next) > 0 {
					_, _ = s.rxBuf.Write(next)
				}
				s.nextSeq++
			}
		} else if len(payload) > 0 {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			s.reorder[seq] = cp
		}

		if s.hasFin && s.nextSeq >= s.finSeq {
			s.remoteEOF = true
		}
		s.rmu.Unlock()
		s.signalRx()
		return nil
	}
}

func (s *xhttpServerConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.rmu.Lock()
		if s.rxBuf.Len() > 0 {
			n, _ := s.rxBuf.Read(p)
			s.rmu.Unlock()
			select {
			case s.spaceFreed <- struct{}{}:
			default:
			}
			return n, nil
		}
		eof := s.remoteEOF
		s.rmu.Unlock()

		if eof {
			return 0, io.EOF
		}
		if s.closed.Load() {
			return 0, net.ErrClosed
		}
		if dl := s.readDeadlineNano.Load(); dl != 0 && time.Now().UnixNano() >= dl {
			return 0, os.ErrDeadlineExceeded
		}

		select {
		case <-s.rxNotify:
		case <-s.closedCh:
			s.rmu.Lock()
			if s.rxBuf.Len() > 0 {
				n, _ := s.rxBuf.Read(p)
				s.rmu.Unlock()
				return n, nil
			}
			s.rmu.Unlock()
			return 0, net.ErrClosed
		case <-s.rdl.wait():
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *xhttpServerConn) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() || s.writeEnded {
		return 0, net.ErrClosed
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > xhttpMaxDownChunk {
			chunk = chunk[:xhttpMaxDownChunk]
		}
		if err := writeXHTTPDownFrame(s.downConn, xhttpFrameData, chunk); err != nil {
			return written, err
		}
		s.lastWrite.Store(time.Now().UnixNano())
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (s *xhttpServerConn) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.closedCh)
		if s.onClose != nil {
			s.onClose()
		}
		s.wmu.Lock()
		if !s.writeEnded {
			s.writeEnded = true
			_ = s.downConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_ = writeXHTTPDownFrame(s.downConn, xhttpFrameClose, nil)
			_, _ = io.WriteString(s.downConn, "0\r\n\r\n")
		}
		s.wmu.Unlock()
		_ = s.downConn.Close()
	})
	return nil
}

func (s *xhttpServerConn) LocalAddr() net.Addr  { return s.downConn.LocalAddr() }
func (s *xhttpServerConn) RemoteAddr() net.Addr { return s.downConn.RemoteAddr() }

func (s *xhttpServerConn) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	_ = s.SetWriteDeadline(t)
	return nil
}

func (s *xhttpServerConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		s.readDeadlineNano.Store(0)
	} else {
		s.readDeadlineNano.Store(t.UnixNano())
	}
	s.rdl.set(t)
	return nil
}

func (s *xhttpServerConn) SetWriteDeadline(t time.Time) error {
	s.wdl.set(t)
	return s.downConn.SetWriteDeadline(t)
}

// ---------------------------------------------------------------------------
// Client-side Connection (GET Downlink + Pooled Keep-Alive POST Uplink)
// ---------------------------------------------------------------------------

type xhttpUplinkSocket struct {
	conn  net.Conn
	br    *bufio.Reader
	reqs  int
	bytes int64
}

func (u *xhttpUplinkSocket) close() {
	if u != nil && u.conn != nil {
		_ = u.conn.Close()
	}
}

type xhttpClientConn struct {
	sid           [16]byte
	sidHex        string
	basePath      string
	host          string
	secret        []byte
	earlyPurposeB byte

	downConn net.Conn
	downBody io.ReadCloser
	rmu      sync.Mutex
	readBuf  []byte
	readEOF  bool

	dialUplink func() (net.Conn, error)

	smu        sync.Mutex
	sendBuf    bytes.Buffer
	nextSeq    uint64
	workers    int
	sendErr    error
	closingTx  bool
	finSent    bool
	sendNotify chan struct{}
	spaceCh    chan struct{}
	flushedCh  chan struct{}

	warmMu   sync.Mutex
	warmSock *xhttpUplinkSocket

	wdl               *deadline
	writeDeadlineNano atomic.Int64

	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

func xhttpDialPurpose(downConn net.Conn, remoteAddr net.Addr, cfg *Config, purpose byte) (net.Conn, error) {
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		_ = downConn.Close()
		return nil, err
	}
	sidHex := hex.EncodeToString(sid[:])
	host := cfg.EffectiveServerName()
	basePath := cfg.effectiveXHTTPPath()

	frame, err := buildAuthFrameV2(cfg.secret, purpose)
	if err != nil {
		_ = downConn.Close()
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(frame)

	targetAddr := ""
	if remoteAddr != nil {
		targetAddr = remoteAddr.String()
	}
	if targetAddr == "" {
		targetAddr = cfg.dialTarget()
	}
	var cleanIdx atomic.Uint32
	_, defaultPort, _ := net.SplitHostPort(targetAddr)
	if defaultPort == "" {
		_, defaultPort, _ = net.SplitHostPort(cfg.TunnelAddr)
	}
	if defaultPort == "" {
		defaultPort = "443"
	}

	dialUplink := func() (net.Conn, error) {
		addr := targetAddr
		if len(cfg.CleanIPs) > 0 {
			idx := int(cleanIdx.Add(1)-1) % len(cfg.CleanIPs)
			if ca := cleanAddr(cfg.CleanIPs[idx], defaultPort); ca != "" {
				addr = ca
			}
		}
		d := net.Dialer{
			Timeout:   8 * time.Second,
			LocalAddr: cfg.sourceFor(addr),
		}
		raw, err := d.Dial("tcp", addr)
		if err != nil && addr != targetAddr {
			d.LocalAddr = cfg.sourceFor(targetAddr)
			raw, err = d.Dial("tcp", targetAddr)
		}
		if err != nil {
			return nil, err
		}
		tuneSocket(raw)
		return wrapDialPurposeTLSOnly(raw, cfg, purpose)
	}

	cc := &xhttpClientConn{
		sid:           sid,
		sidHex:        sidHex,
		basePath:      basePath,
		host:          host,
		secret:        append([]byte(nil), cfg.secret...),
		earlyPurposeB: purpose,
		downConn:      downConn,
		dialUplink:    dialUplink,
		sendNotify:    make(chan struct{}, 1),
		spaceCh:       make(chan struct{}, 1),
		flushedCh:     make(chan struct{}),
		wdl:           newDeadline(),
		closedCh:      make(chan struct{}),
	}

	// Pre-warm one uplink keep-alive TLS socket in parallel with the GET handshake
	// so the first Write incurs zero extra TLS handshake round-trips.
	go func() {
		uconn, uerr := dialUplink()
		if uerr != nil {
			return
		}
		if cc.closed.Load() {
			_ = uconn.Close()
			return
		}
		cc.warmMu.Lock()
		if cc.closed.Load() || cc.warmSock != nil {
			cc.warmMu.Unlock()
			_ = uconn.Close()
			return
		}
		cc.warmSock = &xhttpUplinkSocket{
			conn: uconn,
			br:   bufio.NewReaderSize(uconn, 8*1024),
		}
		cc.warmMu.Unlock()
	}()

	ua := browserProfiles[0].userAgent
	reqStr := "GET " + basePath + "/" + sidHex + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Cache-Control: no-cache\r\n" +
		"X-Session-Token: " + token + "\r\n" +
		"X-Padding: " + xhttpPaddingHeader() + "\r\n" +
		"Connection: keep-alive\r\n\r\n"

	if err := downConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		_ = cc.Close()
		return nil, err
	}
	if _, err := io.WriteString(downConn, reqStr); err != nil {
		_ = cc.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(downConn, 64*1024)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = cc.Close()
		return nil, fmt.Errorf("%w: %v", errXHTTPHandshake, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = cc.Close()
		return nil, fmt.Errorf("%w: got %s", errXHTTPHandshake, resp.Status)
	}

	// Verify 9-byte server greeting frame inside the chunked body.
	var helloHdr [5]byte
	if _, err := io.ReadFull(resp.Body, helloHdr[:]); err != nil {
		_ = resp.Body.Close()
		_ = cc.Close()
		return nil, fmt.Errorf("%w: reading greeting: %v", errXHTTPHandshake, err)
	}
	helloLen := binary.BigEndian.Uint32(helloHdr[1:5])
	if helloHdr[0] != xhttpFrameHello || helloLen != 4 {
		_ = resp.Body.Close()
		_ = cc.Close()
		return nil, fmt.Errorf("%w: invalid greeting frame", errXHTTPHandshake)
	}
	var gotHello [4]byte
	if _, err := io.ReadFull(resp.Body, gotHello[:]); err != nil {
		_ = resp.Body.Close()
		_ = cc.Close()
		return nil, fmt.Errorf("%w: reading greeting token: %v", errXHTTPHandshake, err)
	}
	wantHello := xhttpHelloToken(cfg.secret, sid)
	if subtle.ConstantTimeCompare(gotHello[:], wantHello[:]) != 1 {
		_ = resp.Body.Close()
		_ = cc.Close()
		return nil, fmt.Errorf("%w: greeting signature mismatch", errXHTTPHandshake)
	}

	if err := downConn.SetDeadline(time.Time{}); err != nil {
		_ = resp.Body.Close()
		_ = cc.Close()
		return nil, err
	}
	cc.downBody = resp.Body
	return cc, nil
}

func (c *xhttpClientConn) NetConn() net.Conn   { return c.downConn }
func (c *xhttpClientConn) isEarlyAuthed() bool { return true }
func (c *xhttpClientConn) earlyPurpose() byte  { return c.earlyPurposeB }

func (c *xhttpClientConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()

	for {
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		if c.readEOF {
			return 0, io.EOF
		}
		if c.closed.Load() {
			return 0, net.ErrClosed
		}

		var hdr [5]byte
		if _, err := io.ReadFull(c.downBody, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				c.readEOF = true
				return 0, io.EOF
			}
			return 0, err
		}
		ftype := hdr[0]
		flen := binary.BigEndian.Uint32(hdr[1:5])
		if flen > 4*1024*1024 {
			return 0, errors.New("xhttp downlink frame exceeds limit")
		}

		switch ftype {
		case xhttpFrameData:
			if flen == 0 {
				continue
			}
			if int(flen) <= len(p) {
				if _, err := io.ReadFull(c.downBody, p[:flen]); err != nil {
					return 0, err
				}
				return int(flen), nil
			}
			buf := make([]byte, flen)
			if _, err := io.ReadFull(c.downBody, buf); err != nil {
				return 0, err
			}
			n := copy(p, buf)
			c.readBuf = buf[n:]
			return n, nil

		case xhttpFrameKeepAlive:
			if flen > 0 {
				if _, err := io.CopyN(io.Discard, c.downBody, int64(flen)); err != nil {
					return 0, err
				}
			}

		case xhttpFrameClose:
			c.readEOF = true
			return 0, io.EOF

		default:
			return 0, fmt.Errorf("unknown xhttp downlink frame 0x%02x", ftype)
		}
	}
}

func (c *xhttpClientConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		if c.closed.Load() {
			return total, net.ErrClosed
		}
		if dl := c.writeDeadlineNano.Load(); dl != 0 && time.Now().UnixNano() >= dl {
			return total, os.ErrDeadlineExceeded
		}

		c.smu.Lock()
		if c.sendErr != nil {
			err := c.sendErr
			c.smu.Unlock()
			return total, err
		}
		if c.closingTx {
			c.smu.Unlock()
			return total, net.ErrClosed
		}
		avail := xhttpMaxSendBuf - c.sendBuf.Len()
		if avail <= 0 {
			c.smu.Unlock()
			select {
			case <-c.spaceCh:
				continue
			case <-c.closedCh:
				return total, net.ErrClosed
			case <-c.wdl.wait():
				return total, os.ErrDeadlineExceeded
			}
		}

		take := len(p)
		if take > avail {
			take = avail
		}
		_, _ = c.sendBuf.Write(p[:take])
		total += take
		p = p[take:]

		desired := 1
		if c.sendBuf.Len() > 32*1024 {
			desired = 2
		}
		if c.sendBuf.Len() > 192*1024 {
			desired = xhttpMaxWorkers
		}
		for c.workers < desired {
			c.workers++
			go c.uplinkWorker()
		}
		c.smu.Unlock()

		select {
		case c.sendNotify <- struct{}{}:
		default:
		}
	}
	return total, nil
}

func (c *xhttpClientConn) takeWarmSocket() *xhttpUplinkSocket {
	c.warmMu.Lock()
	defer c.warmMu.Unlock()
	s := c.warmSock
	c.warmSock = nil
	return s
}

func (c *xhttpClientConn) uplinkWorker() {
	sock := c.takeWarmSocket()
	defer func() {
		sock.close()
		c.smu.Lock()
		c.workers--
		done := c.closingTx && c.sendBuf.Len() == 0 && c.workers == 0
		c.smu.Unlock()
		if done {
			select {
			case <-c.flushedCh:
			default:
				close(c.flushedCh)
			}
		}
	}()

	idleTimer := time.NewTimer(20 * time.Second)
	defer idleTimer.Stop()

	for {
		c.smu.Lock()
		if c.sendErr != nil {
			c.smu.Unlock()
			return
		}
		if c.sendBuf.Len() == 0 {
			if c.closingTx {
				if !c.finSent {
					c.finSent = true
					seq := c.nextSeq
					c.nextSeq++
					c.smu.Unlock()
					_ = c.postChunk(&sock, seq, nil, true)
				} else {
					c.smu.Unlock()
				}
				return
			}
			// Extra workers exit once the burst drains; keep 1 warm worker for 20s.
			if c.workers > 1 {
				c.smu.Unlock()
				return
			}
			c.smu.Unlock()

			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(20 * time.Second)

			select {
			case <-c.sendNotify:
				continue
			case <-idleTimer.C:
				c.smu.Lock()
				empty := c.sendBuf.Len() == 0 && !c.closingTx
				c.smu.Unlock()
				if empty {
					return
				}
			case <-c.closedCh:
				return
			}
			continue
		}

		take := c.sendBuf.Len()
		if take > xhttpMaxPostBytes {
			take = xhttpMaxPostBytes
		}
		payload := make([]byte, take)
		_, _ = c.sendBuf.Read(payload)
		seq := c.nextSeq
		c.nextSeq++
		fin := c.closingTx && c.sendBuf.Len() == 0 && !c.finSent
		if fin {
			c.finSent = true
		}
		more := c.sendBuf.Len() > 0
		c.smu.Unlock()

		select {
		case c.spaceCh <- struct{}{}:
		default:
		}
		if more {
			select {
			case c.sendNotify <- struct{}{}:
			default:
			}
		}

		if err := c.postChunk(&sock, seq, payload, fin); err != nil {
			c.smu.Lock()
			if c.sendErr == nil {
				c.sendErr = err
			}
			c.smu.Unlock()
			select {
			case c.spaceCh <- struct{}{}:
			default:
			}
			return
		}
		if fin {
			return
		}
	}
}

func (c *xhttpClientConn) postChunk(sockPtr **xhttpUplinkSocket, seq uint64, payload []byte, fin bool) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if c.closed.Load() && !fin {
			// Allow brief flush during Close(), abort if completely torn down.
		}
		sock := *sockPtr
		reused := sock != nil && sock.reqs > 0
		if sock == nil {
			uconn, err := c.dialUplink()
			if err != nil {
				lastErr = err
				time.Sleep(time.Duration(attempt+1) * 80 * time.Millisecond)
				continue
			}
			sock = &xhttpUplinkSocket{
				conn: uconn,
				br:   bufio.NewReaderSize(uconn, 8*1024),
			}
			*sockPtr = sock
		}

		rotateAfter := fin ||
			sock.reqs+1 >= xhttpMaxReqsPerSocket ||
			sock.bytes+int64(len(payload)) >= xhttpMaxBytesPerSocket

		err := c.doSinglePost(sock, seq, payload, fin, rotateAfter)
		if err == nil {
			sock.reqs++
			sock.bytes += int64(len(payload))
			if rotateAfter {
				sock.close()
				*sockPtr = nil
			}
			return nil
		}

		sock.close()
		*sockPtr = nil
		lastErr = err
		if !reused && attempt >= 1 {
			break
		}
	}
	return lastErr
}

func (c *xhttpClientConn) doSinglePost(sock *xhttpUplinkSocket, seq uint64, payload []byte, fin bool, closeConn bool) error {
	ts := time.Now().Unix()
	mac := xhttpPostMAC(c.secret, c.sid, seq, ts, fin)
	connHdr := "keep-alive"
	if closeConn {
		connHdr = "close"
	}

	var hdr bytes.Buffer
	hdr.Grow(384)
	hdr.WriteString("POST ")
	hdr.WriteString(c.basePath)
	hdr.WriteByte('/')
	hdr.WriteString(c.sidHex)
	hdr.WriteByte('/')
	hdr.WriteString(strconv.FormatUint(seq, 10))
	hdr.WriteString(" HTTP/1.1\r\nHost: ")
	hdr.WriteString(c.host)
	hdr.WriteString("\r\nUser-Agent: ")
	hdr.WriteString(browserProfiles[0].userAgent)
	hdr.WriteString("\r\nContent-Type: application/octet-stream\r\nAccept: */*\r\nCache-Control: no-cache\r\nX-Request-TS: ")
	hdr.WriteString(strconv.FormatInt(ts, 10))
	hdr.WriteString("\r\nX-Request-Auth: ")
	hdr.WriteString(hex.EncodeToString(mac[:]))
	if fin {
		hdr.WriteString("\r\nX-Stream-Close: 1")
	}
	hdr.WriteString("\r\nX-Padding: ")
	hdr.WriteString(xhttpPaddingHeader())
	hdr.WriteString("\r\nContent-Length: ")
	hdr.WriteString(strconv.Itoa(len(payload)))
	hdr.WriteString("\r\nConnection: ")
	hdr.WriteString(connHdr)
	hdr.WriteString("\r\n\r\n")

	if err := sock.conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	if len(payload) <= 64*1024 {
		hdr.Write(payload)
		if _, err := sock.conn.Write(hdr.Bytes()); err != nil {
			return err
		}
	} else {
		if _, err := sock.conn.Write(hdr.Bytes()); err != nil {
			return err
		}
		if _, err := sock.conn.Write(payload); err != nil {
			return err
		}
	}

	resp, err := http.ReadResponse(sock.br, nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	_ = sock.conn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp post rejected: %s", resp.Status)
	}
	return nil
}

func (c *xhttpClientConn) Close() error {
	c.once.Do(func() {
		c.smu.Lock()
		c.closingTx = true
		needFlush := c.sendErr == nil && (c.sendBuf.Len() > 0 || (c.nextSeq > 0 && !c.finSent) || c.workers > 0)
		if needFlush && c.workers == 0 && (c.sendBuf.Len() > 0 || c.nextSeq > 0) {
			c.workers = 1
			go c.uplinkWorker()
		}
		c.smu.Unlock()

		if needFlush {
			select {
			case c.sendNotify <- struct{}{}:
			default:
			}
			select {
			case <-c.flushedCh:
			case <-time.After(1200 * time.Millisecond):
			}
		}

		c.closed.Store(true)
		close(c.closedCh)

		if ws := c.takeWarmSocket(); ws != nil {
			ws.close()
		}
		if c.downBody != nil {
			_ = c.downBody.Close()
		}
		_ = c.downConn.Close()
	})
	return nil
}

func (c *xhttpClientConn) LocalAddr() net.Addr  { return c.downConn.LocalAddr() }
func (c *xhttpClientConn) RemoteAddr() net.Addr { return c.downConn.RemoteAddr() }

func (c *xhttpClientConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *xhttpClientConn) SetReadDeadline(t time.Time) error {
	return c.downConn.SetReadDeadline(t)
}

func (c *xhttpClientConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadlineNano.Store(0)
	} else {
		c.writeDeadlineNano.Store(t.UnixNano())
	}
	c.wdl.set(t)
	return nil
}
