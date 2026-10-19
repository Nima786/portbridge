package engine

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSplitConnRotatesLegsSeamlessly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	secret := []byte("0123456789abcdef0123456789abcdef")
	cfg := &Config{
		Transport:  TransportPlain,
		AntiFreeze: true,
		secret:     secret,
	}

	var acceptLegsMu sync.Mutex
	acceptLegs := 0
	serverConnCh := make(chan net.Conn, 1)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			acceptLegsMu.Lock()
			acceptLegs++
			acceptLegsMu.Unlock()
			go func(c net.Conn) {
				sc, err := wrapAccept(c, cfg, nil)
				if errors.Is(err, errSplitLegAttached) {
					return
				}
				if err != nil {
					_ = c.Close()
					return
				}
				select {
				case serverConnCh <- sc:
				default:
				}
			}(raw)
		}
	}()

	raw0, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial leg 0: %v", err)
	}
	clientConn, err := wrapDial(raw0, cfg)
	if err != nil {
		t.Fatalf("wrapDial: %v", err)
	}
	defer clientConn.Close()

	// Transfer 64 KB in each direction (>20x splitLegMaxBytes = 3 KB) so multiple
	// leg rotations happen concurrently while data is in flight.
	const payloadSize = 64 * 1024
	c2sWant := make([]byte, payloadSize)
	s2cWant := make([]byte, payloadSize)
	_, _ = rand.Read(c2sWant)
	_, _ = rand.Read(s2cWant)

	errCh := make(chan error, 2)
	go func() {
		for off := 0; off < len(c2sWant); off += 4096 {
			end := min(off+4096, len(c2sWant))
			if _, err := clientConn.Write(c2sWant[off:end]); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	var serverConn net.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server splitConn")
	}
	defer serverConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(15 * time.Second))
	go func() {
		for off := 0; off < len(s2cWant); off += 4096 {
			end := min(off+4096, len(s2cWant))
			if _, err := serverConn.Write(s2cWant[off:end]); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	c2sGot := make([]byte, payloadSize)
	s2cGot := make([]byte, payloadSize)

	readErrCh := make(chan error, 2)
	go func() {
		_, err := io.ReadFull(serverConn, c2sGot)
		readErrCh <- err
	}()
	go func() {
		_, err := io.ReadFull(clientConn, s2cGot)
		readErrCh <- err
	}()

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("write error: %v", err)
		}
	}
	for range 2 {
		if err := <-readErrCh; err != nil {
			t.Fatalf("read error: %v", err)
		}
	}

	if !bytes.Equal(c2sGot, c2sWant) {
		t.Fatal("client-to-server payload mismatch across split-stream rotations")
	}
	if !bytes.Equal(s2cGot, s2cWant) {
		t.Fatal("server-to-client payload mismatch across split-stream rotations")
	}

	acceptLegsMu.Lock()
	legsUsed := acceptLegs
	acceptLegsMu.Unlock()
	if legsUsed < 5 {
		t.Fatalf("expected at least 5 underlying TCP legs to be accepted for 160 KB transfer, got %d", legsUsed)
	}
}
