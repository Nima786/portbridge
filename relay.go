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

// copyChunk is how much a single copy step moves. Large enough that the
// per-step cost disappears against the work of actually sending the bytes.
const copyChunk = 32 * 1024

// Borrowed only when the kernel's own copy path does not apply, which means
// every disguised link and every shared session. A plain link never touches one.
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, copyChunk)
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

	// Only the local side is tuned here. The cross-border connection was already
	// tuned when it was dialled or accepted, well before any user arrived, and
	// once a disguise wraps it there is no socket left underneath to tune.
	tuneSocket(local)

	var wg sync.WaitGroup
	wg.Add(2)

	var incomingErr error

	pipe := func(dst, src net.Conn, watch bool) {
		defer wg.Done()

		_, err := copyStream(dst, src)
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

// copyStream moves everything from src to dst, choosing between the kernel's own
// copy path and a buffer borrowed from the shared pool.
//
// The choice matters more than it looks. When both sides are plain TCP the kernel
// moves the bytes itself and never looks at a buffer, so borrowing one ties up
// 32 KB per direction per session to hold nothing at all: at full capacity that
// is well over a hundred megabytes of idle buffers.
//
// When a disguise or a shared link is in the way the kernel path does not apply,
// and there the obvious io.CopyBuffer is worse than useless: it hands the job to
// the destination's own ReadFrom, which allocates a fresh 32 KB buffer for every
// direction of every session and ignores the one just handed to it. Copying by
// hand is what makes the shared pool actually do its job.
func copyStream(dst, src net.Conn) (int64, error) {
	if kernelCanCopy(dst, src) {
		return io.Copy(dst, src)
	}
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	return copyThrough(dst, src, *buf)
}

// kernelCanCopy reports whether io.Copy will hand this pair straight to the
// kernel instead of moving the bytes through this program.
func kernelCanCopy(dst, src net.Conn) bool {
	if !hasKernelCopy {
		return false
	}
	_, dstTCP := dst.(*net.TCPConn)
	_, srcTCP := src.(*net.TCPConn)
	return dstTCP && srcTCP
}

// copyThrough is io.Copy's inner loop over a buffer we chose ourselves.
//
// Reaching the end of the stream ends the copy without an error, matching
// io.Copy: one side finishing is how every session is meant to end, and
// reporting it would turn every normal session into a logged failure.
func copyThrough(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return written, nil
			}
			return written, rerr
		}
	}
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
