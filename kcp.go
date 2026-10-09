package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

type kcpIndicator interface {
	isKCP() bool
}

func needsKeepalive(c net.Conn) bool {
	if _, ok := c.(kcpIndicator); ok {
		return true
	}
	_, isTCP := c.(*net.TCPConn)
	return !isTCP
}

const (
	kcpCmdData byte = 0x01
	kcpCmdFin  byte = 0x02
	kcpCmdPing byte = 0x03
	kcpCmdPong byte = 0x04

	kcpMaxFrame = 32 * 1024
)

type kcpConn struct {
	*kcp.UDPSession
	closed      atomic.Bool
	writeClosed atomic.Bool
	remoteEOF   atomic.Bool
	wrote       atomic.Bool // something has been written since the connection opened

	rmu     sync.Mutex
	readBuf []byte

	wmu sync.Mutex
}

func newKCPConn(sess *kcp.UDPSession) net.Conn {
	return &kcpConn{UDPSession: sess}
}

func (c *kcpConn) isKCP() bool {
	return true
}

func (c *kcpConn) isAlive() bool {
	return !c.closed.Load() && !c.remoteEOF.Load()
}

// CloseWrite sends a FIN frame across the KCP stream and marks the local write
// half as closed. The session stays open to receive incoming replies until the
// peer also finishes.
func (c *kcpConn) CloseWrite() error {
	if !c.writeClosed.CompareAndSwap(false, true) {
		return nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var fin [3]byte
	fin[0] = kcpCmdFin
	_, err := c.UDPSession.Write(fin[:])
	return err
}

func (c *kcpConn) Write(b []byte) (int, error) {
	if c.writeClosed.Load() || c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.wrote.Store(true)

	total := len(b)
	for len(b) > 0 {
		chunk := len(b)
		if chunk > kcpMaxFrame {
			chunk = kcpMaxFrame
		}
		buf := make([]byte, 3+chunk)
		buf[0] = kcpCmdData
		binary.BigEndian.PutUint16(buf[1:], uint16(chunk))
		copy(buf[3:], b[:chunk])
		if _, err := c.UDPSession.Write(buf); err != nil {
			return total - len(b), err
		}
		b = b[chunk:]
	}
	return total, nil
}

func (c *kcpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	for {
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		if c.remoteEOF.Load() {
			return 0, io.EOF
		}
		if c.closed.Load() {
			return 0, net.ErrClosed
		}

		var hdr [3]byte
		if _, err := io.ReadFull(c.UDPSession, hdr[:]); err != nil {
			return 0, err
		}
		cmd := hdr[0]
		length := int(binary.BigEndian.Uint16(hdr[1:]))

		switch cmd {
		case kcpCmdData:
			if length == 0 {
				continue
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(c.UDPSession, payload); err != nil {
				return 0, err
			}
			n := copy(p, payload)
			if n < length {
				c.readBuf = payload[n:]
			}
			return n, nil

		case kcpCmdFin:
			c.remoteEOF.Store(true)
			return 0, io.EOF

		case kcpCmdPing:
			c.wmu.Lock()
			var pong [3]byte
			pong[0] = kcpCmdPong
			_, _ = c.UDPSession.Write(pong[:])
			c.wmu.Unlock()
			continue

		case kcpCmdPong:
			continue

		default:
			return 0, fmt.Errorf("unknown kcp frame command: 0x%02x", cmd)
		}
	}
}

// kcpLinger is how long Close waits after data was written, so the last packets
// get on the wire. Closing a KCP session discards whatever it has not yet sent,
// which ended the tail of a reply early when a session finished right after its
// final write. The session's send queue is not visible from outside the library,
// so this is a short fixed wait, and only when something was actually written.
const kcpLinger = 250 * time.Millisecond

func (c *kcpConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.wrote.Load() {
			time.Sleep(kcpLinger)
		}
		return c.UDPSession.Close()
	}
	return nil
}

// kcpDial opens an encrypted, FEC-protected KCP stream over UDP.
func kcpDial(addr string, cfg *Config) (net.Conn, error) {
	key := sha256.Sum256(cfg.secret)
	block, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		return nil, fmt.Errorf("kcp crypto: %w", err)
	}

	dataShards := 10
	parityShards := 3
	if cfg.KCPDataShards > 0 {
		dataShards = cfg.KCPDataShards
	}
	if cfg.KCPParityShards >= 0 {
		parityShards = cfg.KCPParityShards
	}

	sess, err := kcp.DialWithOptions(addr, block, dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("dialing kcp: %w", err)
	}

	tuneKCP(sess, cfg)
	return newKCPConn(sess), nil
}

// What KCP does when nothing is set. The window used to be 128 packets, which on
// a route with a delay of 90 ms limits one connection to about 2 MB per second
// however much room the route has; measured between a real Iran server and a
// foreign one, 2048 moved a download about five times faster on a route losing
// 12% of its packets, and about six times faster on a clean one. The other
// settings (repair shards, tick, resend, packet size) made no measurable
// difference, so they are as they were.
const (
	kcpDefaultWindow   = 2048
	kcpDefaultMTU      = 1400
	kcpDefaultInterval = 10
	kcpDefaultResend   = 2
)

// validateKCP checks the pacing settings. A zero means "not set", which is how a
// Config built by hand, without a file, arrives.
func (c *Config) validateKCP() error {
	if c.KCPWindow != 0 && (c.KCPWindow < 16 || c.KCPWindow > 32768) {
		return fmt.Errorf("kcp_window must be between 16 and 32768 packets, got %d", c.KCPWindow)
	}
	if c.KCPMTU != 0 && (c.KCPMTU < 500 || c.KCPMTU > 1500) {
		return fmt.Errorf("kcp_mtu must be between 500 and 1500 bytes, got %d", c.KCPMTU)
	}
	if c.KCPInterval != 0 && (c.KCPInterval < 5 || c.KCPInterval > 100) {
		return fmt.Errorf("kcp_interval must be between 5 and 100 milliseconds, got %d", c.KCPInterval)
	}
	if c.KCPResend < 0 || c.KCPResend > 10 {
		return fmt.Errorf("kcp_resend must be between 0 and 10, got %d", c.KCPResend)
	}
	return nil
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// tuneKCP applies the buffer sizes and pacing to one session. Both ends call it,
// one for sessions it opens and one for sessions it accepts.
func tuneKCP(sess *kcp.UDPSession, cfg *Config) {
	_ = sess.SetReadBuffer(4 * 1024 * 1024)
	_ = sess.SetWriteBuffer(4 * 1024 * 1024)
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	nc := 1
	if cfg.KCPCongestion {
		nc = 0
	}
	// nodelay=1 sends the first resend early; nc=1 turns off the congestion
	// window, which on a route that loses packets for reasons other than load
	// only slows the link down for nothing.
	resend := cfg.KCPResend
	if resend == 0 && !cfg.resendSet {
		resend = kcpDefaultResend
	}
	sess.SetNoDelay(1, orDefault(cfg.KCPInterval, kcpDefaultInterval), resend, nc)
	w := orDefault(cfg.KCPWindow, kcpDefaultWindow)
	sess.SetWindowSize(w, w)
	if m := orDefault(cfg.KCPMTU, kcpDefaultMTU); m != kcpDefaultMTU {
		sess.SetMtu(m)
	}
	sess.SetACKNoDelay(true)
}

// kcpListen listens for incoming KCP connections over UDP.
func kcpListen(addr string, cfg *Config) (net.Listener, error) {
	key := sha256.Sum256(cfg.secret)
	block, err := kcp.NewAESBlockCrypt(key[:16])
	if err != nil {
		return nil, fmt.Errorf("kcp crypto: %w", err)
	}

	dataShards := 10
	parityShards := 3
	if cfg.KCPDataShards > 0 {
		dataShards = cfg.KCPDataShards
	}
	if cfg.KCPParityShards >= 0 {
		parityShards = cfg.KCPParityShards
	}

	ln, err := kcp.ListenWithOptions(addr, block, dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("listening kcp: %w", err)
	}
	_ = ln.SetReadBuffer(4 * 1024 * 1024)
	_ = ln.SetWriteBuffer(4 * 1024 * 1024)
	return &kcpListenerWrap{Listener: ln, cfg: cfg}, nil
}

type kcpListenerWrap struct {
	*kcp.Listener
	cfg *Config
}

func (l *kcpListenerWrap) Accept() (net.Conn, error) {
	sess, err := l.Listener.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tuneKCP(sess, l.cfg)
	return newKCPConn(sess), nil
}
