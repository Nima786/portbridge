package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
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
	if err := writeH2Frame(c, h2FrameSettings, 0, 0, nil); err != nil {
		return nil, err
	}

	// 3. Send WINDOW_UPDATE on stream 0 to grant generous window
	var winInc [4]byte
	binary.BigEndian.PutUint32(winInc[:], 0x3fffffff)
	if err := writeH2Frame(c, h2FrameWindowUpdate, 0, 0, winInc[:]); err != nil {
		return nil, err
	}

	// 4. Send HEADERS for Stream 1
	host := cfg.effectiveServerName()
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
	gotHeaders := false
	for !gotHeaders {
		fType, flags, streamID, payload, err := readH2Frame(c)
		if err != nil {
			return nil, fmt.Errorf("%w: reading reply: %v", errH2Handshake, err)
		}
		switch fType {
		case h2FrameSettings:
			if flags&h2FlagAck == 0 {
				_ = writeH2Frame(c, h2FrameSettings, h2FlagAck, 0, nil)
			}
		case h2FrameHeaders:
			if streamID == 1 {
				gotHeaders = true
				// Check for :status: 200 (0x88 in HPACK or literal with 200)
				if !bytes.Contains(payload, []byte{0x88}) && !bytes.Contains(payload, []byte("200")) {
					return nil, fmt.Errorf("%w: server did not return HTTP 200 (headers: %x)", errH2Handshake, payload)
				}
			}
		case h2FrameGoAway, h2FrameRSTStream:
			return nil, fmt.Errorf("%w: connection rejected by server", errH2Handshake)
		}
	}

	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return newH2Conn(c, 1, isGRPC), nil
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
	if err := writeH2Frame(c, h2FrameSettings, 0, 0, nil); err != nil {
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

	for !gotHeaders {
		fType, flags, streamID, _, err := readH2Frame(c)
		if err != nil {
			return nil, fmt.Errorf("%w: reading client headers: %v", errH2Handshake, err)
		}
		switch fType {
		case h2FrameSettings:
			if flags&h2FlagAck == 0 {
				_ = writeH2Frame(c, h2FrameSettings, h2FlagAck, 0, nil)
			}
		case h2FrameHeaders:
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

	return newH2Conn(c, clientStreamID, isGRPC), nil
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
}

func newH2Conn(c net.Conn, streamID uint32, isGRPC bool) *h2Conn {
	return &h2Conn{
		Conn:     c,
		streamID: streamID,
		isGRPC:   isGRPC,
	}
}

func (h *h2Conn) CloseWrite() error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return writeH2Frame(h.Conn, h2FrameData, h2FlagEndStream, h.streamID, nil)
}

func (h *h2Conn) Close() error {
	time.Sleep(100 * time.Millisecond)
	return h.Conn.Close()
}

func (h *h2Conn) Write(p []byte) (int, error) {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()

	total := len(p)
	remaining := p

	maxChunk := h2MaxFrameSize
	if h.isGRPC {
		maxChunk = h2MaxFrameSize - 5
	}

	for len(remaining) > 0 {
		chunkSize := len(remaining)
		if chunkSize > maxChunk {
			chunkSize = maxChunk
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

		if err := writeH2Frame(h.Conn, h2FrameData, 0, h.streamID, payload); err != nil {
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

		if h.remoteClosed {
			if len(h.readBuf) == 0 && (!h.isGRPC || h.msgRemaining == 0) {
				return 0, io.EOF
			}
		}

		// Read next frame from wire
		fType, flags, streamID, payload, err := readH2Frame(h.Conn)
		if err != nil {
			return 0, err
		}

		switch fType {
		case h2FrameData:
			if streamID == h.streamID {
				if flags&h2FlagEndStream != 0 {
					h.remoteClosed = true
				}
				if len(payload) > 0 {
					// Replenish flow control window so throughput remains unconstrained
					var winBuf [4]byte
					binary.BigEndian.PutUint32(winBuf[:], uint32(len(payload)))
					h.writeMu.Lock()
					_ = writeH2Frame(h.Conn, h2FrameWindowUpdate, 0, 0, winBuf[:])
					_ = writeH2Frame(h.Conn, h2FrameWindowUpdate, 0, h.streamID, winBuf[:])
					h.writeMu.Unlock()

					h.readBuf = append(h.readBuf, payload...)
				}
			}

		case h2FramePing:
			if flags&h2FlagAck == 0 {
				h.writeMu.Lock()
				_ = writeH2Frame(h.Conn, h2FramePing, h2FlagAck, 0, payload)
				h.writeMu.Unlock()
			}

		case h2FrameSettings:
			if flags&h2FlagAck == 0 {
				h.writeMu.Lock()
				_ = writeH2Frame(h.Conn, h2FrameSettings, h2FlagAck, 0, nil)
				h.writeMu.Unlock()
			}

		case h2FrameRSTStream, h2FrameGoAway:
			return 0, io.EOF
		}
	}
}
