package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

// HTTP/2 and gRPC transport disguise.
//
// Wraps the connection in valid HTTP/2 framing (RFC 7540) over TLS, presenting
// as an HTTP/2 or gRPC streaming session. This defeats DPI protocol fingerprinting
// on direct connections (which expect valid H2 frames/preface after TLS handshake)
// and enables proxying through CDNs like Cloudflare with gRPC support enabled.

const (
	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// HTTP/2 frame types
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FramePriority     = 0x2
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	// Flags
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagAck        = 0x1

	h2MaxFrameSize = 16384
	defaultH2Path  = "/portbridge.Tunnel/Stream"
)

var errH2Handshake = errors.New("the other end did not complete the HTTP/2 handshake")

// writeH2Frame writes an HTTP/2 frame header followed by payload.
func writeH2Frame(w io.Writer, fType byte, flags byte, streamID uint32, payload []byte) error {
	length := len(payload)
	if length > h2MaxFrameSize {
		return fmt.Errorf("h2 frame too large: %d", length)
	}
	buf := make([]byte, 9+length)
	buf[0] = byte(length >> 16)
	buf[1] = byte(length >> 8)
	buf[2] = byte(length)
	buf[3] = fType
	buf[4] = flags
	binary.BigEndian.PutUint32(buf[5:9], streamID&0x7fffffff)
	if length > 0 {
		copy(buf[9:], payload)
	}
	_, err := w.Write(buf)
	return err
}

// readH2Frame reads one HTTP/2 frame from r.
func readH2Frame(r io.Reader) (byte, byte, uint32, []byte, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	length := (int(hdr[0]) << 16) | (int(hdr[1]) << 8) | int(hdr[2])
	fType := hdr[3]
	flags := hdr[4]
	streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

	if length > 1<<20 { // 1 MB sanity limit
		return 0, 0, 0, nil, fmt.Errorf("h2 frame payload exceeds sanity limit: %d", length)
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	return fType, flags, streamID, payload, nil
}

// encodeH2Headers builds a minimal HPACK header block for an HTTP/2 request.
func encodeH2Headers(host, path string, isGRPC bool) []byte {
	var buf bytes.Buffer
	// :method: POST (index 3 -> 0x83)
	buf.WriteByte(0x83)
	// :scheme: https (index 7 -> 0x87)
	buf.WriteByte(0x87)

	// :path (index 4)
	if path == "/" {
		buf.WriteByte(0x84)
	} else {
		buf.WriteByte(0x04) // literal without indexing, name index 4
		buf.WriteByte(byte(len(path)))
		buf.WriteString(path)
	}

	// :authority (index 1)
	buf.WriteByte(0x01) // literal without indexing, name index 1
	buf.WriteByte(byte(len(host)))
	buf.WriteString(host)

	// content-type (index 31: 0x0f, 0x10)
	buf.Write([]byte{0x0f, 0x10})
	if isGRPC {
		ct := "application/grpc"
		buf.WriteByte(byte(len(ct)))
		buf.WriteString(ct)

		// te: trailers
		// In HPACK (RFC 7541), 'te' is not in the static table (index 57 is transfer-encoding, which is illegal in HTTP/2).
		// Literal without indexing (0x00): name len 2 "te", val len 8 "trailers"
		buf.Write([]byte{0x00, 0x02, 't', 'e', 0x08, 't', 'r', 'a', 'i', 'l', 'e', 'r', 's'})

		// user-agent (index 58: 0x0f, 0x2b)
		ua := "grpc-go/1.50.0"
		buf.Write([]byte{0x0f, 0x2b, byte(len(ua))})
		buf.WriteString(ua)
	} else {
		ct := "application/octet-stream"
		buf.WriteByte(byte(len(ct)))
		buf.WriteString(ct)

		// user-agent (index 58: 0x0f, 0x2b)
		ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
		buf.Write([]byte{0x0f, 0x2b, byte(len(ua))})
		buf.WriteString(ua)
	}

	return buf.Bytes()
}

// encodeH2Response builds a minimal HPACK header block for an HTTP/2 200 reply.
func encodeH2Response(isGRPC bool) []byte {
	var buf bytes.Buffer
	// :status: 200 (index 8 -> 0x88)
	buf.WriteByte(0x88)

	// content-type (index 31: 0x0f, 0x10)
	buf.Write([]byte{0x0f, 0x10})
	if isGRPC {
		ct := "application/grpc"
		buf.WriteByte(byte(len(ct)))
		buf.WriteString(ct)
	} else {
		ct := "application/octet-stream"
		buf.WriteByte(byte(len(ct)))
		buf.WriteString(ct)
	}
	return buf.Bytes()
}

// h2Dial performs the HTTP/2 connection preface and handshake as a client.
func h2Dial(c net.Conn, cfg *Config) (net.Conn, error) {
	if err := c.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}

	// 1. Send client preface
	if _, err := io.WriteString(c, h2ClientPreface); err != nil {
		return nil, err
	}

	// 2. Send initial SETTINGS frame
	if err := writeH2Frame(c, h2FrameSettings, 0, 0, h2OurSettings()); err != nil {
		return nil, err
	}

	// 3. Send WINDOW_UPDATE on stream 0 to grant generous window
	var winInc [4]byte
	binary.BigEndian.PutUint32(winInc[:], 0x3fffffff)
	if err := writeH2Frame(c, h2FrameWindowUpdate, 0, 0, winInc[:]); err != nil {
		return nil, err
	}

	// 4. Send HEADERS for Stream 1
	host := cfg.EffectiveServerName()
	path := cfg.effectiveWSPath()
	if path == "" || path == "/" || path == defaultWSPath {
		path = defaultH2Path
	}
	isGRPC := (cfg.Transport == TransportGRPC)
	hdrPayload := encodeH2Headers(host, path, isGRPC)
	if err := writeH2Frame(c, h2FrameHeaders, h2FlagEndHeaders, 1, hdrPayload); err != nil {
		return nil, err
	}

	// 5. Read server frames until Stream 1 headers arrive
	flow := newH2Flow()
	gotHeaders := false
	for !gotHeaders {
		fType, flags, streamID, payload, err := readH2Frame(c)
		if err != nil {
			return nil, fmt.Errorf("%w: reading reply: %v", errH2Handshake, err)
		}
		switch fType {
		case h2FrameSettings:
			if flags&h2FlagAck == 0 {
				flow.settings(payload)
				_ = writeH2Frame(c, h2FrameSettings, h2FlagAck, 0, nil)
			}
		case h2FrameWindowUpdate:
			flow.windowUpdate(streamID, 1, payload)
		case h2FrameHeaders:
			if streamID == 1 {
				gotHeaders = true
				block, err := h2HeaderBlock(c, flags, streamID, payload)
				if err != nil {
					return nil, fmt.Errorf("%w: %v", errH2Handshake, err)
				}
				status, err := h2ResponseStatus(block)
				if err != nil {
					return nil, fmt.Errorf("%w: reading the reply headers: %v", errH2Handshake, err)
				}
				if status != "200" {
					return nil, fmt.Errorf("%w: server did not return HTTP 200 (it said %q)", errH2Handshake, status)
				}
			}
		case h2FrameGoAway, h2FrameRSTStream:
			return nil, fmt.Errorf("%w: connection rejected by server", errH2Handshake)
		}
	}

	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return newH2Conn(c, 1, isGRPC, flow), nil
}

// h2HeaderBlock returns the whole header block of a HEADERS frame: without
// the padding and priority fields, and joined with any CONTINUATION frames that
// carry the rest of it.
func h2HeaderBlock(c io.Reader, flags byte, streamID uint32, payload []byte) ([]byte, error) {
	const (
		flagPadded   = 0x8
		flagPriority = 0x20
	)
	p := payload
	if flags&flagPadded != 0 {
		if len(p) < 1 || int(p[0]) >= len(p) {
			return nil, errors.New("bad padding in the headers")
		}
		pad := int(p[0])
		p = p[1 : len(p)-pad]
	}
	if flags&flagPriority != 0 {
		if len(p) < 5 {
			return nil, errors.New("short priority field in the headers")
		}
		p = p[5:]
	}
	block := append([]byte(nil), p...)
	for n := 0; flags&h2FlagEndHeaders == 0; n++ {
		if n >= 16 || len(block) > 64<<10 {
			return nil, errors.New("the headers are too long")
		}
		fType, f, sid, more, err := readH2Frame(c)
		if err != nil {
			return nil, err
		}
		if fType != h2FrameContinuation || sid != streamID {
			return nil, errors.New("the headers were cut short")
		}
		block = append(block, more...)
		flags = f
	}
	return block, nil
}

// h2ResponseStatus reads :status out of a response header block.
func h2ResponseStatus(block []byte) (string, error) {
	status := ""
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" && status == "" {
			status = f.Value
		}
	})
	if _, err := dec.Write(block); err != nil {
		return "", err
	}
	if err := dec.Close(); err != nil {
		return "", err
	}
	if status == "" {
		return "", errors.New("no :status in the reply")
	}
	return status, nil
}

// h2Flow is how much the other end has said it will take: the whole connection
// and the one stream, each as a number of bytes that may still be sent.
type h2Flow struct {
	conn    int64
	stream  int64
	initial int64 // the stream window the other end started us with
}

func newH2Flow() h2Flow { return h2Flow{conn: 65535, stream: 65535, initial: 65535} }

// settings applies the one setting that matters for sending: a changed initial
// stream window moves the stream's window by the difference.
func (f *h2Flow) settings(payload []byte) {
	for ; len(payload) >= 6; payload = payload[6:] {
		if binary.BigEndian.Uint16(payload[:2]) != 0x4 {
			continue
		}
		v := int64(binary.BigEndian.Uint32(payload[2:6]))
		if v > 0x7fffffff {
			continue
		}
		f.stream += v - f.initial
		f.initial = v
	}
}

// windowUpdate adds credit given by the other end, for the connection (stream 0)
// or for the stream this connection carries.
func (f *h2Flow) windowUpdate(streamID, ours uint32, payload []byte) {
	if len(payload) != 4 {
		return
	}
	inc := int64(binary.BigEndian.Uint32(payload) & 0x7fffffff)
	switch streamID {
	case 0:
		f.conn = min(f.conn+inc, 0x7fffffff)
	case ours:
		f.stream = min(f.stream+inc, 0x7fffffff)
	}
}

// h2Accept handles the HTTP/2 connection preface and handshake as a server.
func h2Accept(c net.Conn, cfg *Config) (net.Conn, error) {
	if err := c.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}

	// 1. Read client preface
	var preface [24]byte
	if _, err := io.ReadFull(c, preface[:]); err != nil {
		return nil, fmt.Errorf("%w: reading preface: %v", errH2Handshake, err)
	}
	if string(preface[:]) != h2ClientPreface {
		return nil, fmt.Errorf("%w: unexpected preface %q", errH2Handshake, string(preface[:]))
	}

	// 2. Send server SETTINGS
	if err := writeH2Frame(c, h2FrameSettings, 0, 0, h2OurSettings()); err != nil {
		return nil, err
	}

	// 3. Send WINDOW_UPDATE on stream 0
	var winInc [4]byte
	binary.BigEndian.PutUint32(winInc[:], 0x3fffffff)
	if err := writeH2Frame(c, h2FrameWindowUpdate, 0, 0, winInc[:]); err != nil {
		return nil, err
	}

	// 4. Await client HEADERS on Stream 1
	isGRPC := (cfg.Transport == TransportGRPC)
	gotHeaders := false
	var clientStreamID uint32 = 1
	flow := newH2Flow()

	for !gotHeaders {
		fType, flags, streamID, payload, err := readH2Frame(c)
		if err != nil {
			return nil, fmt.Errorf("%w: reading client headers: %v", errH2Handshake, err)
		}
		switch fType {
		case h2FrameSettings:
			if flags&h2FlagAck == 0 {
				flow.settings(payload)
				_ = writeH2Frame(c, h2FrameSettings, h2FlagAck, 0, nil)
			}
		case h2FrameWindowUpdate:
			// Credit for the connection; credit for the stream cannot be
			// told apart yet, and the client opens stream 1 by convention.
			flow.windowUpdate(streamID, 1, payload)
		case h2FrameHeaders:
			if streamID == 0 || streamID%2 == 0 {
				return nil, fmt.Errorf("%w: bad stream number %d", errH2Handshake, streamID)
			}
			// The rest of the header block, if it comes in pieces, is read
			// and set aside.
			if _, err := h2HeaderBlock(c, flags, streamID, payload); err != nil {
				return nil, fmt.Errorf("%w: %v", errH2Handshake, err)
			}
			clientStreamID = streamID
			gotHeaders = true
		case h2FrameGoAway, h2FrameRSTStream:
			return nil, fmt.Errorf("%w: stream aborted", errH2Handshake)
		}
	}

	// 5. Send server response HEADERS (:status 200)
	respPayload := encodeH2Response(isGRPC)
	if err := writeH2Frame(c, h2FrameHeaders, h2FlagEndHeaders, clientStreamID, respPayload); err != nil {
		return nil, err
	}

	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return newH2Conn(c, clientStreamID, isGRPC, flow), nil
}

// h2Conn wraps a TLS connection and streams bidirectional data over an HTTP/2 stream.
type h2Conn struct {
	net.Conn
	streamID     uint32
	isGRPC       bool
	writeMu      sync.Mutex
	readMu       sync.Mutex
	readBuf      []byte
	remoteClosed bool

	// msgRemaining tracks bytes remaining in the currently deframed gRPC message payload.
	msgRemaining int

	// Replies the reader owes the other end (window updates, ping and settings
	// acknowledgements). The reader must never write them itself: writing takes
	// writeMu, and a writer holding it can be stuck behind a full socket while
	// the other end is stuck the same way, each waiting for the other to read.
	// With the reader blocked on that write, neither ever would. So the reader
	// only records what is owed, and a separate goroutine sends it.
	ctlMu     sync.Mutex
	ctlWindow uint32
	ctlFrames []h2Reply
	ctlWake   chan struct{}
	ctlOnce   sync.Once
	done      chan struct{}
	doneOnce  sync.Once

	// What the other end will still take. A writer waits here for credit
	// instead of sending past the window, which a strict HTTP/2 peer (a CDN's
	// edge, say) answers by dropping the whole connection. Waiting happens
	// outside writeMu, so the acknowledgements the reader owes can still go
	// out while a writer is waiting.
	dataMu sync.Mutex // one Write at a time, so their bytes never interleave
	flowMu sync.Mutex
	flow   h2Flow
	flowCh chan struct{} // closed, and replaced, whenever the window or the state changes
	dead   bool          // the connection is closed or the other end has gone
}

// h2StallLimit is how long a writer waits for the other end to make room before
// giving up on the connection.
const h2StallLimit = 2 * time.Minute

var errH2Stalled = &net.OpError{Op: "write", Err: errors.New("the other end stopped accepting data")}

// h2Reply is one acknowledgement waiting to be sent.
type h2Reply struct {
	typ     byte
	flags   byte
	payload []byte
}

// h2MaxPendingReplies bounds the backlog of acknowledgements; a peer that floods
// pings cannot make this grow without limit.
const h2MaxPendingReplies = 64

func newH2Conn(c net.Conn, streamID uint32, isGRPC bool, flow h2Flow) *h2Conn {
	h := &h2Conn{
		Conn:     c,
		streamID: streamID,
		isGRPC:   isGRPC,
		ctlWake:  make(chan struct{}, 1),
		done:     make(chan struct{}),
		flow:     flow,
		flowCh:   make(chan struct{}),
	}
	return h
}

// changed wakes every writer waiting on the window. Called with flowMu held.
func (h *h2Conn) changed() {
	close(h.flowCh)
	h.flowCh = make(chan struct{})
}

// markDead ends all waiting writers: the connection is gone.
func (h *h2Conn) markDead() {
	h.flowMu.Lock()
	h.dead = true
	h.changed()
	h.flowMu.Unlock()
}

// credit applies what the other end sent about its windows.
func (h *h2Conn) credit(fn func(f *h2Flow)) {
	h.flowMu.Lock()
	fn(&h.flow)
	h.changed()
	h.flowMu.Unlock()
}

// h2PollWait is how often a writer waiting for credit looks again at whether
// it should be reading the connection itself.
const h2PollWait = 20 * time.Millisecond

// reserve waits until the other end will take at least one byte (more than
// overhead bytes, if there is a fixed overhead per frame), and uses up as much
// of the window as the frame needs, up to want bytes of data. It returns how
// many bytes of data the next frame may carry.
//
// Credit only arrives as frames on the connection, and frames are only read by
// Read. A caller that writes a lot before it reads (a speed test, a bulk
// upload) would therefore wait for ever for credit nobody is reading. So a
// waiting writer reads the connection itself whenever no reader is doing so;
// anything it takes in that is kept for the next Read.
func (h *h2Conn) reserve(want, overhead int) (int, error) {
	start := time.Now()
	for {
		h.flowMu.Lock()
		if h.dead {
			h.flowMu.Unlock()
			return 0, io.ErrClosedPipe
		}
		avail := min(h.flow.conn, h.flow.stream) - int64(overhead)
		if avail > 0 {
			n := int(min(int64(want), avail))
			h.flow.conn -= int64(n + overhead)
			h.flow.stream -= int64(n + overhead)
			h.flowMu.Unlock()
			return n, nil
		}
		wake := h.flowCh
		h.flowMu.Unlock()

		if time.Since(start) > h2StallLimit {
			return 0, errH2Stalled
		}
		if h.readMu.TryLock() {
			// Nobody is reading: read one frame here.
			fType, flags, streamID, payload, err := readH2Frame(h.Conn)
			if err != nil {
				h.readMu.Unlock()
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// A deadline set for the reader has passed; wait a
					// moment rather than spin.
					time.Sleep(h2PollWait)
					continue
				}
				h.markDead()
				return 0, err
			}
			ended := h.onFrame(fType, flags, streamID, payload)
			h.readMu.Unlock()
			if ended {
				h.markDead()
				return 0, io.ErrClosedPipe
			}
			continue
		}
		// A reader is at work and will bring the credit.
		select {
		case <-wake:
		case <-h.done:
		case <-time.After(h2PollWait):
		}
	}
}

// owe records a reply (or window credit) to be sent soon, without ever blocking
// on the socket.
func (h *h2Conn) owe(window uint32, reply *h2Reply) {
	h.ctlMu.Lock()
	if window > 0 {
		if sum := uint64(h.ctlWindow) + uint64(window); sum > 0x7fffffff {
			h.ctlWindow = 0x7fffffff
		} else {
			h.ctlWindow = uint32(sum)
		}
	}
	if reply != nil && len(h.ctlFrames) < h2MaxPendingReplies {
		h.ctlFrames = append(h.ctlFrames, *reply)
	}
	h.ctlMu.Unlock()

	h.ctlOnce.Do(func() { go h.sendOwed() })
	select {
	case h.ctlWake <- struct{}{}:
	default:
	}
}

// sendOwed writes what the reader owes, on its own goroutine.
func (h *h2Conn) sendOwed() {
	for {
		select {
		case <-h.ctlWake:
		case <-h.done:
			return
		}

		h.ctlMu.Lock()
		window := h.ctlWindow
		h.ctlWindow = 0
		frames := h.ctlFrames
		h.ctlFrames = nil
		h.ctlMu.Unlock()

		h.writeMu.Lock()
		var err error
		for _, f := range frames {
			if err = writeH2Frame(h.Conn, f.typ, f.flags, 0, f.payload); err != nil {
				break
			}
		}
		if err == nil && window > 0 {
			var winBuf [4]byte
			binary.BigEndian.PutUint32(winBuf[:], window)
			// The connection as a whole, and this stream.
			if err = writeH2Frame(h.Conn, h2FrameWindowUpdate, 0, 0, winBuf[:]); err == nil {
				err = writeH2Frame(h.Conn, h2FrameWindowUpdate, 0, h.streamID, winBuf[:])
			}
		}
		h.writeMu.Unlock()
		if err != nil {
			// The connection is broken; the reader will find out on its own.
			return
		}
	}
}

func (h *h2Conn) CloseWrite() error {
	// After any Write in progress, so the end of the stream never overtakes
	// data. (An empty frame uses up no window.)
	h.dataMu.Lock()
	defer h.dataMu.Unlock()
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return writeH2Frame(h.Conn, h2FrameData, h2FlagEndStream, h.streamID, nil)
}

// h2CloseGrace is how long the socket is kept open after Close, so that what
// was just written reaches the other end before the connection is torn down.
const h2CloseGrace = 100 * time.Millisecond

// Close ends the connection. Writers stop at once; the socket itself is closed
// a moment later without making the caller wait for it.
func (h *h2Conn) Close() error {
	first := false
	h.doneOnce.Do(func() {
		first = true
		close(h.done)
	})
	h.markDead()
	if !first {
		return nil
	}
	time.AfterFunc(h2CloseGrace, func() { _ = h.Conn.Close() })
	return nil
}

func (h *h2Conn) Write(p []byte) (int, error) {
	h.dataMu.Lock()
	defer h.dataMu.Unlock()

	total := len(p)
	remaining := p

	maxChunk := h2MaxFrameSize
	overhead := 0
	if h.isGRPC {
		maxChunk = h2MaxFrameSize - 5
		overhead = 5
	}

	for len(remaining) > 0 {
		chunkSize := min(len(remaining), maxChunk)
		// Wait, if need be, until the other end has room; only as much is
		// sent as it will take.
		chunkSize, err := h.reserve(chunkSize, overhead)
		if err != nil {
			return total - len(remaining), err
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		var payload []byte
		if h.isGRPC {
			payload = make([]byte, 5+len(chunk))
			payload[0] = 0x00 // uncompressed
			binary.BigEndian.PutUint32(payload[1:5], uint32(len(chunk)))
			copy(payload[5:], chunk)
		} else {
			payload = chunk
		}

		h.writeMu.Lock()
		err = writeH2Frame(h.Conn, h2FrameData, 0, h.streamID, payload)
		h.writeMu.Unlock()
		if err != nil {
			h.markDead()
			return total - len(remaining) - len(chunk), err
		}
	}

	return total, nil
}

func (h *h2Conn) Read(p []byte) (int, error) {
	h.readMu.Lock()
	defer h.readMu.Unlock()

	for {
		if !h.isGRPC {
			if len(h.readBuf) > 0 {
				n := copy(p, h.readBuf)
				h.readBuf = h.readBuf[n:]
				return n, nil
			}
		} else {
			// gRPC streaming: deliver message bytes if in progress
			if h.msgRemaining > 0 && len(h.readBuf) > 0 {
				toCopy := len(h.readBuf)
				if toCopy > h.msgRemaining {
					toCopy = h.msgRemaining
				}
				n := copy(p, h.readBuf[:toCopy])
				h.readBuf = h.readBuf[n:]
				h.msgRemaining -= n
				return n, nil
			}

			// If no message in progress, check if we have the 5-byte gRPC envelope
			if h.msgRemaining == 0 && len(h.readBuf) >= 5 {
				msgLen := int(binary.BigEndian.Uint32(h.readBuf[1:5]))
				h.readBuf = h.readBuf[5:]
				h.msgRemaining = msgLen
				continue
			}
		}

		// Nothing more can be delivered from what is held. If the other end
		// has finished, that is the end; waiting for another frame would wait
		// for ever. A message cut off in the middle is an error, not a clean end.
		if h.remoteClosed {
			if h.isGRPC && (len(h.readBuf) > 0 || h.msgRemaining > 0) {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, io.EOF
		}

		// Read next frame from wire
		fType, flags, streamID, payload, err := readH2Frame(h.Conn)
		if err != nil {
			// A deadline passing is not the end of the connection.
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				h.markDead()
			}
			return 0, err
		}
		if h.onFrame(fType, flags, streamID, payload) {
			h.markDead()
		}
	}
}

// onFrame takes in one frame read from the connection. It must be called with
// readMu held. It reports whether the other end has ended the connection.
func (h *h2Conn) onFrame(fType, flags byte, streamID uint32, payload []byte) (ended bool) {
	switch fType {
	case h2FrameData:
		if streamID == h.streamID {
			if flags&h2FlagEndStream != 0 {
				h.remoteClosed = true
			}
			if len(payload) > 0 {
				// Replenish flow control window so throughput remains unconstrained
				h.owe(uint32(len(payload)), nil)

				h.readBuf = append(h.readBuf, payload...)
			}
		}

	case h2FrameHeaders:
		// Trailers: how a gRPC server ends the stream.
		if streamID == h.streamID && flags&h2FlagEndStream != 0 {
			h.remoteClosed = true
		}

	case h2FrameWindowUpdate:
		sid := h.streamID
		h.credit(func(f *h2Flow) { f.windowUpdate(streamID, sid, payload) })

	case h2FramePing:
		if flags&h2FlagAck == 0 {
			// The payload buffer may be reused by the next read, so the
			// reply keeps its own copy.
			h.owe(0, &h2Reply{typ: h2FramePing, flags: h2FlagAck, payload: append([]byte(nil), payload...)})
		}

	case h2FrameSettings:
		if flags&h2FlagAck == 0 {
			h.credit(func(f *h2Flow) { f.settings(payload) })
			h.owe(0, &h2Reply{typ: h2FrameSettings, flags: h2FlagAck})
		}

	case h2FrameRSTStream, h2FrameGoAway:
		h.remoteClosed = true
		return true
	}
	return false
}

// h2StreamWindow is the stream window this end offers the other. The protocol's
// default is 65535 bytes, which on a link with a 80 ms round trip caps one stream
// at about 6.5 Mbit/s however fast the link is: the sender must wait for credit
// every 64 KB. Credit is returned the moment data arrives, so a large window
// costs nothing.
const h2StreamWindow = 1 << 30

// h2OurSettings is the SETTINGS payload sent at the start of the connection:
// INITIAL_WINDOW_SIZE (0x4).
func h2OurSettings() []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b[:2], 0x4)
	binary.BigEndian.PutUint32(b[2:], h2StreamWindow)
	return b
}
