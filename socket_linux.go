//go:build linux

package main

import (
	"net"
	"syscall"
	"time"
)

// hasKernelCopy says the kernel can move bytes straight from one socket to
// another on its own, via splice(2), so a plain link needs no copy buffer of
// ours at all.
const hasKernelCopy = true

// tuneSocket enables keepalive aggressive enough to notice a silently dropped
// path within roughly 45 seconds: probe after 30s idle, then three probes five
// seconds apart.
//
// This does two jobs. It detects a dead tunnel connection quickly, so capacity
// is not held by connections that will never carry traffic again. And the probe
// traffic keeps stateful firewalls and NAT devices along the route from
// forgetting a parked spare, which is what makes long-lived spares safe and
// keeps connection churn across the border low.
// Everything is set in one go, deliberately. The obvious way, through the
// standard keepalive helpers, takes three separate trips into the socket and
// writes two of these values only to have them overwritten a moment later. Every
// connection on both servers passes through here, so the difference shows up in
// the processor time per user.
func tuneSocket(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		// Fall back to the portable helpers rather than leaving a connection
		// with no keepalive at all.
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
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
	if lc, ok := c.(interface{ isAlive() bool }); ok {
		if !lc.isAlive() {
			return false
		}
	}
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
		case n > 0:
			// Something arrived on a connection that is only waiting. The far
			// side has nothing to say to a parked connection unprompted, so a
			// byte here is a refusal (wrong password, clocks apart, the two
			// ends disagreeing about shared connections) that was sent just
			// before it hung up. Treating that as alive left refused
			// connections filling the pool as if they were ready.
			alive = false
		}
		return true // always done: never block waiting for readability
	})
	return alive
}

// pendingByte reads the one byte waiting on a connection that socketAlive found
// dead, if there is one, so the reason the far side gave can be reported.
func pendingByte(c net.Conn) (byte, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	_ = tc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	defer func() { _ = tc.SetReadDeadline(time.Time{}) }()
	var b [1]byte
	n, err := tc.Read(b[:])
	if n == 1 && (err == nil) {
		return b[0], true
	}
	return 0, false
}
