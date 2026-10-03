//go:build !linux

package main

import (
	"net"
	"time"
)

// Portable stand-ins so the program compiles and can be tested off Linux.
// Production runs on Linux and uses socket_linux.go.

// hasKernelCopy is false here because splice(2) is a Linux facility. Copying
// goes through a borrowed buffer instead, which is correct everywhere and only
// slower than the kernel doing it.
const hasKernelCopy = false

// tuneSocket applies only the portable part of the tuning. Probe interval and
// probe count need platform-specific calls, so dead-path detection here falls
// back to the operating system default, which is far slower than on Linux.
func tuneSocket(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// socketAlive has no portable non-destructive peek available, so it reports
// "not known to be dead". Spares are then filtered by age alone, and the
// activation acknowledgement still catches a broken path before a user is
// affected.
func socketAlive(c net.Conn) bool {
	if lc, ok := c.(interface{ isAlive() bool }); ok {
		if !lc.isAlive() {
			return false
		}
	}
	return true
}

// pendingByte is only meaningful on Linux, where socketAlive can see that a
// byte is waiting. Elsewhere nothing is ever reported waiting.
func pendingByte(net.Conn) (byte, bool) { return 0, false }
