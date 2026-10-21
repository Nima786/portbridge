package engine

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestH2ResponseStatusIsReadProperly(t *testing.T) {
	if s, err := h2ResponseStatus([]byte{0x88}); err != nil || s != "200" {
		t.Fatalf("indexed 200: %q %v", s, err)
	}
	if s, err := h2ResponseStatus([]byte{0x8d}); err != nil || s != "404" {
		t.Fatalf("indexed 404: %q %v", s, err)
	}
	// A reply that merely contains the byte 0x88 or the text "200" somewhere
	// is not a 200: here a 404 followed by a header whose value holds both.
	hdr := []byte{0x8d, 0x00, 0x01, 'x', 0x05, '2', '0', '0', 0x88, 0x88}
	if s, err := h2ResponseStatus(hdr); err != nil || s != "404" {
		t.Fatalf("a 404 with 200 in other fields: %q %v", s, err)
	}
	if _, err := h2ResponseStatus([]byte{0x00, 0x01, 'x', 0x01, 'y'}); err == nil {
		t.Fatal("a reply with no :status was accepted")
	}
}

// h2RawPeer is the far end of an h2Conn, spoken to by hand.
type h2RawPeer struct {
	t *testing.T
	c net.Conn
}

func (p *h2RawPeer) frame() (typ, flags byte, sid uint32, payload []byte) {
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, flags, sid, payload, err := readH2Frame(p.c)
	if err != nil {
		p.t.Fatalf("reading a frame from the connection: %v", err)
	}
	return
}

func (p *h2RawPeer) windowUpdate(sid uint32, n uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	if err := writeH2Frame(p.c, h2FrameWindowUpdate, 0, sid, b[:]); err != nil {
		p.t.Fatal(err)
	}
}

func TestH2WriterNeverSendsPastTheWindow(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	h := newH2Conn(a, 1, false, h2Flow{conn: 100, stream: 100, initial: 100})
	defer h.Close()
	peer := &h2RawPeer{t: t, c: b}

	// The reader is what takes in the window credit, as in real use.
	go func() { _, _ = io.Copy(io.Discard, h) }()

	data := make([]byte, 250)
	done := make(chan error, 1)
	go func() {
		_, err := h.Write(data)
		done <- err
	}()

	got := 0
	for got < 100 {
		typ, _, _, payload := peer.frame()
		if typ != h2FrameData {
			t.Fatalf("unexpected frame type %d", typ)
		}
		got += len(payload)
	}
	if got != 100 {
		t.Fatalf("sent %d bytes into a window of 100", got)
	}
	// Nothing more may arrive until credit is given.
	_ = b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if typ, _, _, _, err := readH2Frame(b); err == nil {
		t.Fatalf("a frame (type %d) was sent with no window left", typ)
	}
	select {
	case err := <-done:
		t.Fatalf("the write finished early: %v", err)
	default:
	}
	// Credit for the stream alone is not enough; the connection needs it too.
	peer.windowUpdate(1, 1000)
	_ = b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if typ, _, _, _, err := readH2Frame(b); err == nil {
		t.Fatalf("a frame (type %d) was sent with no connection window left", typ)
	}
	peer.windowUpdate(0, 1000)
	for got < 250 {
		typ, _, _, payload := peer.frame()
		if typ != h2FrameData {
			t.Fatalf("unexpected frame type %d", typ)
		}
		got += len(payload)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if got != 250 {
		t.Fatalf("sent %d bytes, want 250", got)
	}
}

func TestH2GRPCWindowCountsTheEnvelope(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	h := newH2Conn(a, 1, true, h2Flow{conn: 50, stream: 50, initial: 50})
	defer h.Close()
	peer := &h2RawPeer{t: t, c: b}
	go func() { _, _ = io.Copy(io.Discard, h) }()
	go func() { _, _ = h.Write(make([]byte, 200)) }()
	got := 0
	for got < 50 {
		_, _, _, payload := peer.frame()
		got += len(payload)
	}
	if got != 50 {
		t.Fatalf("sent %d bytes (envelopes included) into a window of 50", got)
	}
}

func TestH2WriterWaitingIsReleasedWhenTheConnectionEnds(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	h := newH2Conn(a, 1, false, h2Flow{conn: 0, stream: 0, initial: 0})
	done := make(chan error, 1)
	go func() {
		_, err := h.Write([]byte("x"))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = h.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a write with no window succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a waiting writer was never released")
	}
}

func TestH2InitialWindowSettingMovesTheStreamWindow(t *testing.T) {
	f := newH2Flow()
	var s [6]byte
	binary.BigEndian.PutUint16(s[:2], 0x4)
	binary.BigEndian.PutUint32(s[2:], 1000)
	f.settings(s[:])
	if f.stream != 1000 || f.conn != 65535 {
		t.Fatalf("after the setting: stream %d conn %d", f.stream, f.conn)
	}
	f.stream -= 400
	binary.BigEndian.PutUint32(s[2:], 500)
	f.settings(s[:])
	if f.stream != 100 {
		t.Fatalf("a smaller initial window should lower the stream window by the difference, got %d", f.stream)
	}
}

func TestH2GRPCReadEndsWhenTheStreamEndsMidMessage(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	h := newH2Conn(a, 1, true, newH2Flow())
	defer h.Close()
	go func() {
		// An envelope promising 10 bytes, 3 of them delivered, then the end.
		payload := []byte{0, 0, 0, 0, 10, 'a', 'b', 'c'}
		_ = writeH2Frame(b, h2FrameData, h2FlagEndStream, 1, payload)
		// Read the window update the reader owes, so the pipe does not stall.
		_, _ = io.Copy(io.Discard, b)
	}()
	buf := make([]byte, 64)
	done := make(chan error, 1)
	go func() {
		var err error
		for err == nil {
			_, err = h.Read(buf)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("got %v, want an unexpected-EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read hung after the stream ended in the middle of a message")
	}
}

func TestH2TrailersEndTheStream(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	h := newH2Conn(a, 1, true, newH2Flow())
	defer h.Close()
	go func() {
		_ = writeH2Frame(b, h2FrameData, 0, 1, []byte{0, 0, 0, 0, 2, 'o', 'k'})
		_ = writeH2Frame(b, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, []byte{0x88})
		_, _ = io.Copy(io.Discard, b)
	}()
	done := make(chan string, 1)
	go func() {
		var all []byte
		buf := make([]byte, 16)
		for {
			n, err := h.Read(buf)
			all = append(all, buf[:n]...)
			if err != nil {
				done <- string(all) + "|" + err.Error()
				return
			}
		}
	}()
	select {
	case got := <-done:
		if got != "ok|EOF" {
			t.Fatalf("got %q, want the message then a clean end", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read hung after the server's trailers ended the stream")
	}
}

// The default stream window of 64 KB caps one stream at about 6.5 Mbit/s on an
// 80 ms link, whatever the link can carry. What this end offers must be far more.
func TestH2OffersALargeStreamWindow(t *testing.T) {
	f := newH2Flow()
	f.settings(h2OurSettings())
	if f.stream < 16<<20 {
		t.Fatalf("a peer that read our settings would let us send only %d bytes before credit", f.stream)
	}
}
