//go:build !linux

package main

import (
	"net"
	"time"
)

// Portable stand-ins so the program compiles and can be tested off Linux.
// Production runs on Linux and uses socket_linux.go.

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
func socketAlive(net.Conn) bool {
	return true
}
