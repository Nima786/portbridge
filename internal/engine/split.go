package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Anti-Freeze Split-Stream (multi-connection byte-cap rotation).
//
// Why this exists:
// On heavily filtered routes (such as Direct IPv4 out of Iran), stateful DPI
// middleboxes often allow the TCP + TLS handshake and the first ~32-64 KB of
// payload, and then freeze/blackhole that specific TCP 5-tuple mid-stream once
// its cumulative byte counter crosses a threshold.
//
// splitConn presents a single continuous net.Conn to the rest of PortBridge
// (mux, pool, relay, and benchmark probes) while transparently rotating the
// underlying TLS/TCP carrier sockets ("legs") every 24 KB (splitLegMaxBytes).
// Before a leg reaches its 24 KB cap, the dialer pre-warms the next leg in the
// background so the handoff is seamless and no single TCP connection ever
// transfers enough bytes to trigger the ISP's mid-stream freeze.

const (
	splitMagic = "SPLIT1" // 6 bytes, starts with 'S' (0x53)

	// splitLegPrefaceLen: 6B magic + 1B role + 1B reserved + 16B sessionID + 8B timestamp + 4B seq + 32B HMAC = 68 bytes
	splitLegPrefaceLen = 68

	splitRoleInitial       byte = 0x00 // Leg #0: initial bidirectional leg
	splitRoleDialerWrite   byte = 0x01 // Rotated leg carrying Dialer -> Listener bytes
	splitRoleListenerWrite byte = 0x02 // Rotated leg carrying Listener -> Dialer bytes

	splitCmdData   byte = 0x01
	splitCmdRotate byte = 0x02
	splitCmdFin    byte = 0x03

	// Cap each underlying TCP/TLS leg at 14 KB of payload so the total bytes on
	// any single TCP 5-tuple stay well below strict ~20-32 KB ISP/DPI freeze caps.
	splitLegMaxBytes   = 14 * 1024
	splitPrewarmAt     = 3 * 1024
	splitMaxFrameBytes = 7 * 1024
)

type legRef struct {
	net.Conn
	refs           atomic.Int32
	pendingPreface []byte
}

func newLegRef(c net.Conn, initialRefs int32) *legRef {
	lr := &legRef{Conn: c}
	lr.refs.Store(initialRefs)
	return lr
}

func (l *legRef) Write(b []byte) (int, error) {
	if len(l.pendingPreface) > 0 {
		combined := make([]byte, len(l.pendingPreface)+len(b))
		copy(combined, l.pendingPreface)
		copy(combined[len(l.pendingPreface):], b)
		l.pendingPreface = nil
		if _, err := l.Conn.Write(combined); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return l.Conn.Write(b)
}

func (l *legRef) release() {
	if l == nil {
		return
	}
	if l.refs.Add(-1) <= 0 {
		_ = l.Conn.Close()
	}
}

func (l *legRef) releaseDelayed(d time.Duration) {
	if l == nil {
		return
	}
	if l.refs.Add(-1) <= 0 {
		time.AfterFunc(d, func() {
			_ = l.Conn.Close()
		})
	}
}

func buildSplitPreface(secret []byte, sessionID [16]byte, role byte, seq uint32) []byte {
	buf := make([]byte, splitLegPrefaceLen)
	copy(buf[0:6], splitMagic)
	buf[6] = role
	buf[7] = 0
	copy(buf[8:24], sessionID[:])
	binary.BigEndian.PutUint64(buf[24:32], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint32(buf[32:36], seq)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pb-split-v1:"))
	mac.Write(buf[:36])
	copy(buf[36:68], mac.Sum(nil))
	return buf
}

func writeSplitPreface(c net.Conn, secret []byte, sessionID [16]byte, role byte, seq uint32) error {
	buf := buildSplitPreface(secret, sessionID, role, seq)
	_, err := c.Write(buf)
	return err
}

func readSplitPreface(c net.Conn, secret []byte) (sessionID [16]byte, role byte, seq uint32, err error) {
	var buf [splitLegPrefaceLen]byte
	if _, err = io.ReadFull(c, buf[:]); err != nil {
		return sessionID, 0, 0, err
	}
	if string(buf[0:6]) != splitMagic {
		return sessionID, 0, 0, errors.New("invalid split stream preface")
	}
	role = buf[6]
	copy(sessionID[:], buf[8:24])
	ts := int64(binary.BigEndian.Uint64(buf[24:32]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > 180 {
		return sessionID, 0, 0, errAuthSkew
	}
	seq = binary.BigEndian.Uint32(buf[32:36])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("pb-split-v1:"))
	mac.Write(buf[:36])
	expected := mac.Sum(nil)
	if !hmac.Equal(buf[36:68], expected) {
		return sessionID, 0, 0, errAuthMAC
	}
	return sessionID, role, seq, nil
}

// splitSessionManager groups incoming rotated TCP/TLS legs on the accepting side
// by their 16-byte sessionID.
type splitSessionManager struct {
	mu       sync.Mutex
	sessions map[[16]byte]*splitConn
}

func newSplitSessionManager() *splitSessionManager {
	return &splitSessionManager{
		sessions: make(map[[16]byte]*splitConn),
	}
}

var (
	defaultSplitManager = newSplitSessionManager()
	errSplitLegAttached = errors.New("split-stream leg attached to existing session")
)

// AcceptLeg reads and verifies the Split Leg Preface from rawConn.
// For Leg #0 (splitRoleInitial), it creates a new *splitConn and returns (conn, true, nil).
// For rotated legs (splitRoleDialerWrite / splitRoleListenerWrite), it attaches the
// leg to the existing session and returns (nil, false, errSplitLegAttached).
func (m *splitSessionManager) AcceptLeg(rawConn net.Conn, secret []byte) (net.Conn, bool, error) {
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))
	sid, role, seq, err := readSplitPreface(rawConn, secret)
	if err != nil {
		_ = rawConn.Close()
		return nil, false, err
	}
	_ = rawConn.SetDeadline(time.Time{})

	m.mu.Lock()
	existing := m.sessions[sid]
	if role == splitRoleInitial && existing == nil {
		sc := newSplitServerConn(sid, rawConn, func() {
			m.mu.Lock()
			delete(m.sessions, sid)
			m.mu.Unlock()
		})
		m.sessions[sid] = sc
		m.mu.Unlock()
		return sc, true, nil
	}
	m.mu.Unlock()

	for i := 0; i < 100 && existing == nil; i++ {
		time.Sleep(15 * time.Millisecond)
		m.mu.Lock()
		existing = m.sessions[sid]
		m.mu.Unlock()
	}

	if existing == nil || existing.closed.Load() {
		_ = rawConn.Close()
		return nil, false, errSplitLegAttached
	}

	lr := newLegRef(rawConn, 1)
	existing.attachServerLeg(role, seq, lr)
	return nil, false, errSplitLegAttached
}

type splitConn struct {
	sessionID [16]byte
	isClient  bool
	dialLeg   func(role byte, seq uint32) (*legRef, error)
	onClose   func()

	legPtrMu          sync.Mutex
	readDeadlineNano  atomic.Int64
	writeDeadlineNano atomic.Int64

	rmu            sync.Mutex
	readLeg        *legRef
	readBytesOnLeg int
	readPrewarmed  bool
	readBuf        []byte
	remoteEOF      atomic.Bool
	nextReadLegCh  chan *legRef
	readLegSeq     atomic.Uint32

	wmu            sync.Mutex
	writeLeg       *legRef
	writeBytesLeg  int
	writePrewarmed bool
	writeClosed    atomic.Bool
	nextWriteLegCh chan *legRef
	writeLegSeq    atomic.Uint32

	pendingMu        sync.Mutex
	pendingReadLegs  map[uint32]*legRef
	pendingWriteLegs map[uint32]*legRef
	legNotifyCh      chan struct{}

	prewarmReadFlight  atomic.Bool
	prewarmWriteFlight atomic.Bool

	rdl *deadline
	wdl *deadline

	localAddr  net.Addr
	remoteAddr net.Addr

	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

func newSplitServerConn(sid [16]byte, leg0 net.Conn, onClose func()) *splitConn {
	lr0 := newLegRef(leg0, 2)
	sc := &splitConn{
		sessionID:        sid,
		isClient:         false,
		onClose:          onClose,
		readLeg:          lr0,
		writeLeg:         lr0,
		nextReadLegCh:    make(chan *legRef, 8),
		nextWriteLegCh:   make(chan *legRef, 8),
		pendingReadLegs:  make(map[uint32]*legRef),
		pendingWriteLegs: make(map[uint32]*legRef),
		legNotifyCh:      make(chan struct{}, 1),
		rdl:              newDeadline(),
		wdl:              newDeadline(),
		localAddr:        leg0.LocalAddr(),
		remoteAddr:       leg0.RemoteAddr(),
		closedCh:         make(chan struct{}),
	}
	return sc
}

func (s *splitConn) attachServerLeg(role byte, seq uint32, lr *legRef) {
	if s.closed.Load() {
		lr.release()
		return
	}
	s.pendingMu.Lock()
	if s.closed.Load() {
		s.pendingMu.Unlock()
		lr.release()
		return
	}
	switch role {
	case splitRoleDialerWrite:
		if old := s.pendingReadLegs[seq]; old != nil {
			old.release()
		}
		s.pendingReadLegs[seq] = lr
	case splitRoleListenerWrite:
		if old := s.pendingWriteLegs[seq]; old != nil {
			old.release()
		}
		s.pendingWriteLegs[seq] = lr
	default:
		s.pendingMu.Unlock()
		lr.release()
		return
	}
	s.pendingMu.Unlock()
	select {
	case s.legNotifyCh <- struct{}{}:
	default:
	}
}

func newSplitClientConn(leg0 net.Conn, remoteAddr net.Addr, cfg *Config, purpose byte) (net.Conn, error) {
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		_ = leg0.Close()
		return nil, err
	}

	targetAddr := ""
	if remoteAddr != nil {
		targetAddr = remoteAddr.String()
	}
	if targetAddr == "" {
		targetAddr = cfg.dialTarget()
	}
	baseCfg := *cfg
	baseCfg.AntiFreeze = false

	lr0 := newLegRef(leg0, 2)
	lr0.pendingPreface = buildSplitPreface(cfg.secret, sid, splitRoleInitial, 0)
	sc := &splitConn{
		sessionID:      sid,
		isClient:       true,
		readLeg:        lr0,
		writeLeg:       lr0,
		nextReadLegCh:  make(chan *legRef, 8),
		nextWriteLegCh: make(chan *legRef, 8),
		rdl:            newDeadline(),
		wdl:            newDeadline(),
		localAddr:      leg0.LocalAddr(),
		remoteAddr:     leg0.RemoteAddr(),
		closedCh:       make(chan struct{}),
	}

	sc.dialLeg = func(role byte, seq uint32) (*legRef, error) {
		d := net.Dialer{Timeout: 4 * time.Second}
		d.LocalAddr = baseCfg.sourceFor(targetAddr)
		raw, err := d.Dial("tcp", targetAddr)
		if err != nil {
			return nil, err
		}
		tuneSocket(raw)
		wrapped, err := wrapDialPurpose(raw, &baseCfg, purpose)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		if err := writeSplitPreface(wrapped, baseCfg.secret, sid, role, seq); err != nil {
			_ = wrapped.Close()
			return nil, err
		}
		return newLegRef(wrapped, 1), nil
	}

	return sc, nil
}

func (s *splitConn) prewarmClientWriteLeg() {
	if !s.isClient || s.closed.Load() {
		return
	}
	if len(s.nextWriteLegCh) >= 2 {
		return
	}
	if !s.prewarmWriteFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		for {
			for !s.closed.Load() && len(s.nextWriteLegCh) < 2 {
				seq := s.writeLegSeq.Add(1)
				lr, err := s.dialLeg(splitRoleDialerWrite, seq)
				if err != nil {
					s.prewarmWriteFlight.Store(false)
					return
				}
				select {
				case s.nextWriteLegCh <- lr:
				case <-s.closedCh:
					lr.release()
					s.prewarmWriteFlight.Store(false)
					return
				}
			}
			s.prewarmWriteFlight.Store(false)
			if s.closed.Load() || len(s.nextWriteLegCh) >= 2 {
				return
			}
			if !s.prewarmWriteFlight.CompareAndSwap(false, true) {
				return
			}
		}
	}()
}

func (s *splitConn) prewarmServerWriteLeg() {
	if !s.isClient || s.closed.Load() {
		return
	}
	if len(s.nextReadLegCh) >= 3 {
		return
	}
	if !s.prewarmReadFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		for {
			for !s.closed.Load() && len(s.nextReadLegCh) < 3 {
				seq := s.readLegSeq.Add(1)
				lr, err := s.dialLeg(splitRoleListenerWrite, seq)
				if err != nil {
					s.prewarmReadFlight.Store(false)
					return
				}
				select {
				case s.nextReadLegCh <- lr:
				case <-s.closedCh:
					lr.release()
					s.prewarmReadFlight.Store(false)
					return
				}
			}
			s.prewarmReadFlight.Store(false)
			if s.closed.Load() || len(s.nextReadLegCh) >= 3 {
				return
			}
			if !s.prewarmReadFlight.CompareAndSwap(false, true) {
				return
			}
		}
	}()
}

func (s *splitConn) acquireNextWriteLeg() (*legRef, error) {
	if s.isClient {
		select {
		case lr := <-s.nextWriteLegCh:
			s.prewarmClientWriteLeg()
			return lr, nil
		default:
		}
		s.prewarmClientWriteLeg()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case lr := <-s.nextWriteLegCh:
			s.prewarmClientWriteLeg()
			return lr, nil
		case <-s.wdl.wait():
			return nil, timeoutError{}
		case <-timer.C:
			return nil, fmt.Errorf("timed out dialing rotated split-stream write leg")
		case <-s.closedCh:
			return nil, net.ErrClosed
		}
	}

	// Server side waits for the client to provide the exact next splitRoleListenerWrite leg by seq.
	want := s.writeLegSeq.Add(1)
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	for {
		s.pendingMu.Lock()
		if lr := s.pendingWriteLegs[want]; lr != nil {
			delete(s.pendingWriteLegs, want)
			s.pendingMu.Unlock()
			return lr, nil
		}
		s.pendingMu.Unlock()
		select {
		case <-s.legNotifyCh:
		case <-s.wdl.wait():
			return nil, timeoutError{}
		case <-timer.C:
			return nil, fmt.Errorf("timed out waiting for rotated split-stream leg")
		case <-s.closedCh:
			return nil, net.ErrClosed
		}
	}
}

func (s *splitConn) acquireNextReadLeg() (*legRef, error) {
	if s.isClient {
		select {
		case lr := <-s.nextReadLegCh:
			s.prewarmServerWriteLeg()
			return lr, nil
		default:
		}
		s.prewarmServerWriteLeg()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case lr := <-s.nextReadLegCh:
			s.prewarmServerWriteLeg()
			return lr, nil
		case <-s.rdl.wait():
			return nil, timeoutError{}
		case <-timer.C:
			return nil, fmt.Errorf("timed out dialing rotated split-stream read leg")
		case <-s.closedCh:
			return nil, net.ErrClosed
		}
	}

	// Server side waits for the client to provide the exact next splitRoleDialerWrite leg by seq.
	want := s.readLegSeq.Add(1)
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	for {
		s.pendingMu.Lock()
		if lr := s.pendingReadLegs[want]; lr != nil {
			delete(s.pendingReadLegs, want)
			s.pendingMu.Unlock()
			return lr, nil
		}
		s.pendingMu.Unlock()
		select {
		case <-s.legNotifyCh:
		case <-s.rdl.wait():
			return nil, timeoutError{}
		case <-timer.C:
			return nil, fmt.Errorf("timed out waiting for rotated split-stream leg")
		case <-s.closedCh:
			return nil, net.ErrClosed
		}
	}
}

func (s *splitConn) applyReadDeadlineTo(lr *legRef) {
	if lr == nil {
		return
	}
	if ns := s.readDeadlineNano.Load(); ns > 0 {
		_ = lr.SetReadDeadline(time.Unix(0, ns))
	} else {
		_ = lr.SetReadDeadline(time.Time{})
	}
}

func (s *splitConn) applyWriteDeadlineTo(lr *legRef) {
	if lr == nil {
		return
	}
	if ns := s.writeDeadlineNano.Load(); ns > 0 {
		_ = lr.SetWriteDeadline(time.Unix(0, ns))
	} else {
		_ = lr.SetWriteDeadline(time.Time{})
	}
}

func (s *splitConn) Write(p []byte) (int, error) {
	if s.closed.Load() || s.writeClosed.Load() {
		return 0, net.ErrClosed
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()

	total := 0
	for len(p) > 0 {
		if s.closed.Load() {
			return total, net.ErrClosed
		}
		s.legPtrMu.Lock()
		wleg := s.writeLeg
		s.legPtrMu.Unlock()
		if wleg == nil {
			return total, net.ErrClosed
		}

		// Rotate underlying TCP leg if we have reached the per-leg byte budget.
		if s.writeBytesLeg >= splitLegMaxBytes {
			var rot [3]byte
			rot[0] = splitCmdRotate
			_ = wleg.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := wleg.Write(rot[:]); err != nil {
				return total, err
			}
			nextLeg, err := s.acquireNextWriteLeg()
			if err != nil {
				return total, err
			}
			s.applyWriteDeadlineTo(nextLeg)
			s.legPtrMu.Lock()
			s.writeLeg = nextLeg
			s.legPtrMu.Unlock()
			wleg.releaseDelayed(1500 * time.Millisecond)
			wleg = nextLeg
			s.writeBytesLeg = 0
			s.writePrewarmed = true
			if s.isClient {
				s.prewarmClientWriteLeg()
			}
		}

		remOnLeg := splitLegMaxBytes - s.writeBytesLeg
		chunk := len(p)
		if chunk > splitMaxFrameBytes {
			chunk = splitMaxFrameBytes
		}
		if chunk > remOnLeg {
			chunk = remOnLeg
		}

		frame := make([]byte, 3+chunk)
		frame[0] = splitCmdData
		binary.BigEndian.PutUint16(frame[1:3], uint16(chunk))
		copy(frame[3:], p[:chunk])

		_ = wleg.SetWriteDeadline(time.Now().Add(8 * time.Second))
		if _, err := wleg.Write(frame); err != nil {
			return total, err
		}
		s.applyWriteDeadlineTo(wleg)

		total += chunk
		p = p[chunk:]
		s.writeBytesLeg += chunk

		if s.isClient && !s.writePrewarmed && s.writeBytesLeg >= 1024 {
			s.writePrewarmed = true
			s.prewarmClientWriteLeg()
		}
	}
	return total, nil
}

func (s *splitConn) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()

	for {
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}
		if s.remoteEOF.Load() {
			return 0, io.EOF
		}
		s.legPtrMu.Lock()
		rleg := s.readLeg
		s.legPtrMu.Unlock()
		if s.closed.Load() || rleg == nil {
			return 0, net.ErrClosed
		}

		var hdr [3]byte
		if _, err := io.ReadFull(rleg, hdr[:]); err != nil {
			return 0, err
		}
		cmd := hdr[0]
		length := int(binary.BigEndian.Uint16(hdr[1:3]))

		switch cmd {
		case splitCmdData:
			if length == 0 {
				continue
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(rleg, payload); err != nil {
				return 0, err
			}
			s.readBytesOnLeg += length
			if s.isClient && !s.readPrewarmed && s.readBytesOnLeg > 0 {
				s.readPrewarmed = true
				s.prewarmServerWriteLeg()
			}
			n := copy(p, payload)
			if n < length {
				s.readBuf = payload[n:]
			}
			return n, nil

		case splitCmdRotate:
			nextLeg, err := s.acquireNextReadLeg()
			if err != nil {
				return 0, err
			}
			s.applyReadDeadlineTo(nextLeg)
			s.legPtrMu.Lock()
			s.readLeg = nextLeg
			s.legPtrMu.Unlock()
			rleg.release()
			s.readBytesOnLeg = 0
			s.readPrewarmed = true
			if s.isClient {
				s.prewarmServerWriteLeg()
			}
			continue

		case splitCmdFin:
			s.remoteEOF.Store(true)
			return 0, io.EOF

		default:
			return 0, fmt.Errorf("unexpected split-stream frame command 0x%02x", cmd)
		}
	}
}

func (s *splitConn) CloseWrite() error {
	if !s.writeClosed.CompareAndSwap(false, true) {
		return nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.legPtrMu.Lock()
	wleg := s.writeLeg
	s.legPtrMu.Unlock()
	if wleg == nil {
		return nil
	}
	var fin [3]byte
	fin[0] = splitCmdFin
	_, err := wleg.Write(fin[:])
	return err
}

func (s *splitConn) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.closedCh)
		if s.onClose != nil {
			s.onClose()
		}
		s.legPtrMu.Lock()
		rleg := s.readLeg
		wleg := s.writeLeg
		s.readLeg = nil
		s.writeLeg = nil
		s.legPtrMu.Unlock()

		if rleg != nil {
			_ = rleg.SetDeadline(time.Now())
			rleg.release()
		}
		if wleg != nil {
			_ = wleg.SetDeadline(time.Now())
			wleg.release()
		}

		s.pendingMu.Lock()
		for k, lr := range s.pendingReadLegs {
			delete(s.pendingReadLegs, k)
			lr.release()
		}
		for k, lr := range s.pendingWriteLegs {
			delete(s.pendingWriteLegs, k)
			lr.release()
		}
		s.pendingMu.Unlock()

		for {
			select {
			case lr := <-s.nextReadLegCh:
				lr.release()
			default:
				goto drainWrite
			}
		}
	drainWrite:
		for {
			select {
			case lr := <-s.nextWriteLegCh:
				lr.release()
			default:
				return
			}
		}
	})
	return nil
}

func (s *splitConn) LocalAddr() net.Addr  { return s.localAddr }
func (s *splitConn) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *splitConn) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	_ = s.SetWriteDeadline(t)
	return nil
}

func (s *splitConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		s.readDeadlineNano.Store(0)
	} else {
		s.readDeadlineNano.Store(t.UnixNano())
	}
	s.rdl.set(t)
	s.legPtrMu.Lock()
	rleg := s.readLeg
	s.legPtrMu.Unlock()
	if rleg != nil {
		_ = rleg.SetReadDeadline(t)
	}
	return nil
}

func (s *splitConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		s.writeDeadlineNano.Store(0)
	} else {
		s.writeDeadlineNano.Store(t.UnixNano())
	}
	s.wdl.set(t)
	s.legPtrMu.Lock()
	wleg := s.writeLeg
	s.legPtrMu.Unlock()
	if wleg != nil {
		_ = wleg.SetWriteDeadline(t)
	}
	return nil
}
