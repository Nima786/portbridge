package main

import (
	"crypto/sha256"
	"fmt"
	"net"

	"github.com/xtaci/kcp-go/v5"
)

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
	return sess, nil
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
	return sess, nil
}
