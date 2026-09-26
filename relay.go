package main

import (
	"errors"
	"io"
	"net"
	"sync"
)

// Only reached for non-TCP connections. TCP-to-TCP on Linux goes through
// splice(2) inside io.CopyBuffer, which ignores the buffer entirely.
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

// relay moves bytes both ways until both directions finish.
//
// Each direction closes only its own write half when it runs dry. Closing the
// whole connection instead would truncate the other direction, which shows up
// as cut-off downloads whenever a client finishes uploading before the reply
// has fully arrived.
func relay(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	tuneSocket(a)
	tuneSocket(b)

	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)

		_, _ = io.CopyBuffer(dst, src, *buf)

		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go pipe(b, a)
	go pipe(a, b)
	wg.Wait()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
