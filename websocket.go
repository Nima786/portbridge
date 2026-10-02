package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A deliberately small websocket implementation: just enough for a CDN to accept
// and forward the connection, after which it hands back a plain two-way stream.
//
// Why bother, when TLS alone already disguises the link? Because a CDN will only
// carry arbitrary traffic if it is asked in the way it expects: TLS, then an HTTP
// request, then an upgrade to websocket. Once that exchange is done the
// connection carries whatever we put through it, and the CDN's own address is
// what the outside world sees rather than the foreign server's.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

var errWSUpgrade = errors.New("the other end did not complete the websocket upgrade")

// wsDial performs the client half of the upgrade over an already-secured
// connection, then returns a stream that frames everything as websocket data.
func wsDial(c net.Conn, cfg *Config) (net.Conn, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])

	host := cfg.effectiveServerName()
	path := cfg.effectiveWSPath()

	// Build v2 early-data auth frame for 0-RTT handshake
	var earlyDataProto string
	if len(cfg.secret) >= 16 {
		if frame, err := buildAuthFrameV2(cfg.secret, authPurposeTunnel); err == nil {
			earlyDataProto = "portbridge.v2." + base64.RawURLEncoding.EncodeToString(frame)
		}
	}

	// A perfectly ordinary upgrade request. Header order and the user agent are
	// chosen to look like a normal browser-driven websocket, because a CDN and
	// anything watching will both see this in the clear if TLS is terminated.
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n"
	if earlyDataProto != "" {
		req += "Sec-WebSocket-Protocol: " + earlyDataProto + "\r\n"
	}
	req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"\r\n"

	if err := c.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(c, req); err != nil {
		return nil, err
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWSUpgrade, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%w: got %s", errWSUpgrade, resp.Status)
	}
	want := wsAcceptKey(key)
	if resp.Header.Get("Sec-WebSocket-Accept") != want {
		return nil, fmt.Errorf("%w: the reply did not match the request", errWSUpgrade)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	earlyAuthed := resp.Header.Get("Sec-WebSocket-Protocol") == "portbridge.v2"
	// br may hold bytes already read past the response, so it must be kept.
	return &wsConn{Conn: c, br: br, mask: true, earlyAuthed: earlyAuthed}, nil
}

// wsAccept performs the server half. Anything that is not a correct upgrade for
// our path gets a plain 404, so a stray visitor sees an unremarkable web server
// rather than anything that hints at a tunnel.
func wsAccept(c net.Conn, cfg *Config, guard ...*replayGuard) (net.Conn, error) {
	if err := c.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWSUpgrade, err)
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	isUpgrade := strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")

	if !isUpgrade || key == "" || req.URL.Path != cfg.effectiveWSPath() {
		writeDecoyResponse(c)
		return nil, fmt.Errorf("%w: unexpected request for %s", errWSUpgrade, req.URL.Path)
	}

	earlyAuthed := false
	protoHeader := req.Header.Get("Sec-WebSocket-Protocol")
	if strings.HasPrefix(protoHeader, "portbridge.v2.") {
		token := strings.TrimPrefix(protoHeader, "portbridge.v2.")
		frame, err := base64.RawURLEncoding.DecodeString(token)
		if err == nil {
			var g *replayGuard
			if len(guard) > 0 && guard[0] != nil {
				g = guard[0]
			}
			_, err = verifyAuthFrameBytes(frame, cfg.secret, g)
			if err == nil {
				earlyAuthed = true
			} else {
				writeDecoyResponse(c)
				return nil, fmt.Errorf("%w: early auth failed: %v", errWSUpgrade, err)
			}
		}
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n"
	if earlyAuthed {
		resp += "Sec-WebSocket-Protocol: portbridge.v2\r\n"
	}
	resp += "\r\n"

	if _, err := io.WriteString(c, resp); err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &wsConn{Conn: c, br: br, mask: false, earlyAuthed: earlyAuthed}, nil
}

// writeDecoyResponse answers anything unexpected the way a small web server
// would, so probing the port reveals nothing interesting.
func writeDecoyResponse(c net.Conn) {
	body := "<html><head><title>404 Not Found</title></head>\n" +
		"<body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body>\n</html>\n"
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, fmt.Sprintf(
		"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Type: text/html\r\n"+
			"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body))
	_ = c.SetWriteDeadline(time.Time{})
}

func wsAcceptKey(key string) string {
	h := sha1.New() // required by the websocket standard; not used for security
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

// wsConn presents a websocket as an ordinary connection. Reads reassemble
// frames; writes produce one binary frame each.
type wsConn struct {
	net.Conn
	br          *bufio.Reader
	mask        bool // whichever side dialled must mask its frames
	earlyAuthed bool

	readBuf []byte // payload left over from the last frame
	closed  bool

	wmu sync.Mutex // frames must not interleave
}

func (w *wsConn) isEarlyAuthed() bool {
	return w.earlyAuthed
}

func (w *wsConn) Read(p []byte) (int, error) {
	for {
		if len(w.readBuf) > 0 {
			n := copy(p, w.readBuf)
			w.readBuf = w.readBuf[n:]
			return n, nil
		}
		if w.closed {
			return 0, io.EOF
		}
		payload, opcode, err := w.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case wsOpBinary, wsOpText, wsOpContinuation:
			w.readBuf = payload
		case wsOpPing:
			// Keep-alives from a CDN are normal and must be answered, or it
			// will drop the connection as unresponsive.
			_ = w.writeFrame(wsOpPong, payload)
		case wsOpPong:
			// Nothing to do.
		case wsOpClose:
			w.closed = true
			return 0, io.EOF
		}
	}
}

func (w *wsConn) readFrame() ([]byte, byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
		return nil, 0, err
	}
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	// A frame far larger than anything we send means the stream is out of step,
	// so stop rather than trying to allocate it.
	if length > 64<<20 {
		return nil, 0, errors.New("websocket frame is implausibly large")
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, maskKey[:]); err != nil {
			return nil, 0, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return payload, opcode, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	if err := w.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) writeFrame(opcode byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()

	// Header, then optionally a mask key, then the payload, in one write so the
	// pieces cannot be split across packets in an odd way.
	out := make([]byte, 0, len(payload)+14)
	out = append(out, 0x80|opcode) // always a complete frame

	n := len(payload)
	var lenByte byte
	switch {
	case n <= 125:
		lenByte = byte(n)
	case n <= 0xFFFF:
		lenByte = 126
	default:
		lenByte = 127
	}
	if w.mask {
		lenByte |= 0x80
	}
	out = append(out, lenByte)

	switch {
	case n > 0xFFFF:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		out = append(out, ext[:]...)
	case n > 125:
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		out = append(out, ext[:]...)
	}

	if w.mask {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		out = append(out, key[:]...)
		start := len(out)
		out = append(out, payload...)
		for i := 0; i < n; i++ {
			out[start+i] ^= key[i%4]
		}
	} else {
		out = append(out, payload...)
	}

	_, err := w.Conn.Write(out)
	return err
}

// CloseWrite ends our side politely, so the other end sees a clean finish rather
// than a broken connection. relay depends on this for half-close.
func (w *wsConn) CloseWrite() error {
	_ = w.writeFrame(wsOpClose, nil)
	if cw, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// How long to spend swallowing whatever is still arriving before closing. Long
// enough for the tail of a finished exchange, short enough not to hold a
// finished session open.
const wsDrainTime = 250 * time.Millisecond

// Close finishes with the connection, but reads off anything still arriving
// first.
//
// This is not tidiness. Reading a websocket Close frame ends the stream as far as
// this wrapper is concerned, while the bytes that follow it on the wire, the
// secure channel's own goodbye, have not been read. Closing a connection that
// still has unread data waiting makes the system send a reset rather than a
// polite finish, and a reset tells the other end to throw away everything it has
// not handed over yet.
//
// The result was a download that stopped a few hundred kilobytes short, now and
// then, with nothing in any log. Swallowing the tail first turns the close back
// into a polite one.
func (w *wsConn) Close() error {
	if wsDrainTime > 0 {
		_ = w.Conn.SetReadDeadline(time.Now().Add(wsDrainTime))
		_, _ = io.Copy(io.Discard, w.br)
	}
	return w.Conn.Close()
}
