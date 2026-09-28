package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
)

// The hand-written copy loop replaced io.CopyBuffer, so it has to behave exactly
// as io.Copy did: deliver every byte, in order, and treat the end of the stream
// as a normal finish rather than a failure. A payload well over the buffer size
// forces many rounds through the loop.
func TestCopyThroughDeliversEverything(t *testing.T) {
	t.Parallel()

	payload := make([]byte, copyChunk*5+1234)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("building a payload: %v", err)
	}

	var got bytes.Buffer
	buf := make([]byte, copyChunk)
	n, err := copyThrough(&got, bytes.NewReader(payload), buf)
	if err != nil {
		t.Fatalf("copy reported an error at the end of a stream: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("the copied bytes do not match what went in")
	}
}

// A source that hands back a few bytes at a time, the way a decrypting or
// framing reader does, must not lose or reorder anything.
func TestCopyThroughHandlesDribblingReads(t *testing.T) {
	t.Parallel()

	payload := []byte("the quick brown fox jumps over the lazy dog, repeatedly")
	var got bytes.Buffer
	buf := make([]byte, copyChunk)
	if _, err := copyThrough(&got, iotest3(payload), buf); err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("got %q, want %q", got.String(), payload)
	}
}

// A read failure partway through must be reported, not swallowed. Swallowing it
// is exactly how a truncation bug stayed invisible once before.
func TestCopyThroughReportsAReadFailure(t *testing.T) {
	t.Parallel()

	boom := errors.New("the link went away")
	src := io.MultiReader(bytes.NewReader([]byte("some data")), errorReader{boom})

	var got bytes.Buffer
	buf := make([]byte, copyChunk)
	n, err := copyThrough(&got, src, buf)
	if !errors.Is(err, boom) {
		t.Fatalf("got error %v, want the read failure", err)
	}
	if n != int64(len("some data")) {
		t.Fatalf("reported %d bytes copied before the failure, want %d", n, len("some data"))
	}
}

// The whole point of the kernel copy path is that a plain link borrows no buffer
// at all. Only a pair of bare sockets qualifies: as soon as a disguise or a
// shared link is in the way there is no socket for the kernel to splice.
func TestOnlyBareSocketPairsUseTheKernelCopy(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	tcpA, tcpB := loopbackPair(t)
	defer tcpA.Close()
	defer tcpB.Close()

	if kernelCanCopy(a, b) {
		t.Fatal("claimed the kernel can copy between two things that are not sockets")
	}
	if kernelCanCopy(tcpA, b) || kernelCanCopy(a, tcpB) {
		t.Fatal("claimed the kernel can copy with only one side a socket")
	}
	if got := kernelCanCopy(tcpA, tcpB); got != hasKernelCopy {
		t.Fatalf("for two sockets got %v, want %v on this platform", got, hasKernelCopy)
	}
}

// relay is what actually carries traffic, so check it end to end over a pair
// that does not qualify for the kernel path, which is the branch the borrowed
// buffer now serves.
func TestRelayCarriesBulkOverAWrappedLink(t *testing.T) {
	t.Parallel()

	payload := make([]byte, copyChunk*3+77)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("building a payload: %v", err)
	}

	local, localPeer := net.Pipe()
	tunnel, tunnelPeer := net.Pipe()

	go func() {
		_ = relay(local, tunnel)
	}()

	// The far side of the tunnel echoes the payload back.
	go func() {
		defer tunnelPeer.Close()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(tunnelPeer, got); err != nil {
			return
		}
		_, _ = tunnelPeer.Write(got)
	}()

	go func() {
		_, _ = localPeer.Write(payload)
	}()

	back := make([]byte, len(payload))
	if _, err := io.ReadFull(localPeer, back); err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("the payload came back changed")
	}
	_ = localPeer.Close()
}

// ---------------------------------------------------------------------------

type errorReader struct{ err error }

func (e errorReader) Read([]byte) (int, error) { return 0, e.err }

// iotest3 hands back at most three bytes per read.
func iotest3(b []byte) io.Reader { return &dribble{rest: b} }

type dribble struct{ rest []byte }

func (d *dribble) Read(p []byte) (int, error) {
	if len(d.rest) == 0 {
		return 0, io.EOF
	}
	n := 3
	if n > len(d.rest) {
		n = len(d.rest)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, d.rest[:n])
	d.rest = d.rest[n:]
	return n, nil
}

// loopbackPair returns two ends of a real TCP connection.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	got := <-accepted
	if got.err != nil {
		t.Fatalf("accepting: %v", got.err)
	}
	return dialed, got.c
}
