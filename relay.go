package main

import (
	"errors"
	"io"
	"net"
	"sync"
)

// closeWriter is anything that can finish sending without closing the whole
// connection: plain TCP, TLS, and our websocket wrapper all can.
type closeWriter interface {
	CloseWrite() error
}

// Used whenever the kernel's own copy path does not apply, which now includes
// every disguised link. Plain TCP on Linux still goes through splice(2) inside
// io.CopyBuffer, which ignores the buffer entirely.
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

		// Close only our own write half. Asking by capability rather than for a
		// plain TCP connection matters once the link is wrapped in TLS or a
		// websocket: those can half-close too, and falling back to closing the
		// whole thing would truncate the other direction.
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
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
