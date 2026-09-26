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
// local is the user or the published service; tunnel is the cross-border side.
// The distinction is only used for reporting: an error on the local side is
// everyday life, because clients hang up mid-download all the time, while an
// error bringing data in over the tunnel means something went wrong with the
// tunnel itself, and is worth saying out loud.
//
// It returns the error that ended the incoming direction, or nil if it ended
// normally. Discarding that error was how a truncation bug stayed invisible:
// downloads stopped short and nothing anywhere said why.
//
// Each direction closes only its own write half when it runs dry. Closing the
// whole connection instead would truncate the other direction, which shows up
// as cut-off downloads whenever a client finishes uploading before the reply
// has fully arrived.
func relay(local, tunnel net.Conn) error {
	defer local.Close()
	defer tunnel.Close()

	tuneSocket(local)
	tuneSocket(tunnel)

	var wg sync.WaitGroup
	wg.Add(2)

	var incomingErr error

	pipe := func(dst, src net.Conn, watch bool) {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)

		_, err := io.CopyBuffer(dst, src, *buf)
		if watch && worthReporting(err) {
			// Written by this goroutine only, and read after both have
			// finished, so no lock is needed.
			incomingErr = err
		}

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

	go pipe(tunnel, local, false)
	go pipe(local, tunnel, true)
	wg.Wait()

	return incomingErr
}

// worthReporting decides whether an error that ended the incoming direction says
// something about the tunnel, or is just everyday life.
//
// The copy being watched reads from the tunnel and writes to the user or the
// service. A failure to read is the tunnel's fault and is worth knowing about. A
// failure to write is the other end hanging up, which clients do constantly in
// the middle of a download, and logging that would bury the interesting case.
func worthReporting(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "write" {
		return false
	}
	return true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
