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

	_ = sess.SetReadBuffer(4 * 1024 * 1024)
	_ = sess.SetWriteBuffer(4 * 1024 * 1024)
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	// nodelay=1, interval=10ms, resend=2, nc=1 (no congestion window throttling on lossy WAN)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(128, 128)
	sess.SetACKNoDelay(true)
	return newKCPConn(sess), nil
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
	return &kcpListenerWrap{Listener: ln}, nil
}

type kcpListenerWrap struct {
	*kcp.Listener
}

func (l *kcpListenerWrap) Accept() (net.Conn, error) {
	sess, err := l.Listener.AcceptKCP()
	if err != nil {
		return nil, err
	}
	_ = sess.SetReadBuffer(4 * 1024 * 1024)
	_ = sess.SetWriteBuffer(4 * 1024 * 1024)
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(128, 128)
	sess.SetACKNoDelay(true)
	return newKCPConn(sess), nil
}
