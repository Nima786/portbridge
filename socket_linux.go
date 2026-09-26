//go:build linux

package main

import (
	"net"
	"syscall"
	"time"
)

// tuneSocket enables keepalive aggressive enough to notice a silently dropped
// path within roughly 45 seconds: probe after 30s idle, then three probes five
// seconds apart.
//
// This does two jobs. It detects a dead tunnel connection quickly, so capacity
// is not held by connections that will never carry traffic again. And the probe
// traffic keeps stateful firewalls and NAT devices along the route from
// forgetting a parked spare, which is what makes long-lived spares safe and
// keeps connection churn across the border low.
func tuneSocket(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)

	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	// Applied after SetKeepAlivePeriod, which writes both TCP_KEEPIDLE and
	// TCP_KEEPINTVL; these calls deliberately override the interval and count.
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 30)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
	})
}

// socketAlive reports whether a parked connection has already been closed or
// reset by the far side, using a peek that never blocks and never consumes data.
//
// It cannot see a path that died silently with no FIN and no RST. The keepalive
// settings above catch that within about 45 seconds, and the spare age cap is
// the backstop. Treat true as "not known to be dead" rather than a guarantee.
// The activation acknowledgement is what actually proves a path works.
func socketAlive(c net.Conn) bool {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return true
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return false
	}

	alive := true
	_ = raw.Read(func(fd uintptr) bool {
		var probe [1]byte
		n, _, err := syscall.Recvfrom(int(fd), probe[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			alive = true // nothing pending, socket healthy
		case err != nil || n == 0:
			alive = false // reset, or a clean close from the far side
		}
		return true // always done: never block waiting for readability
	})
	return alive
}
