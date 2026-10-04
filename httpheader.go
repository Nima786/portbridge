package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// A fake web exchange at the start of a plain link.
//
// Why it exists
//
// The plain option opens with a burst of random-looking bytes and then carries
// more of the same. Something that resembles no known protocol is exactly what
// some filters refuse, while anything that opens like ordinary web traffic is
// let through. Measured on a route out of Iran, configurations that begin with an
// HTTP header kept working on a day when unrecognisable streams did not.
//
// What it does
//
// The side that dials sends a short, believable web request naming a host of your
// choosing, and the side that accepts answers with a believable "200 OK". After
// that the connection carries the tunnel exactly as before. Nothing about the
// authentication, the sessions or the speed changes, and the connection is
// returned as the plain TCP connection it is, so the fast paths that depend on
// that still apply.
//
// What it does not do
//
// It does not encrypt anything and it is not real HTTP after the first lines, so
// a filter that follows the whole conversation would see through it. It helps
// against filters that judge a connection by how it starts. Both ends must have
// it on or off together; if they disagree each end says so.

// defaultHTTPHost is the name used when none is given. Any believable site name
// works, and it does not have to be one you own.
const defaultHTTPHost = "www.bing.com"

const (
	httpHeadTimeout = 10 * time.Second

	// httpHeadMax bounds the request or reply that is read, so a peer that never
	// finishes its header cannot make this hold memory.
	httpHeadMax = 8 * 1024
)

var (
	errHTTPNotHeader = errors.New("a connection arrived without the web header; " +
		"http_header must be on at both ends or off at both")
	errHTTPNoReply = errors.New("the other server did not answer the web header; " +
		"http_header must be on at both ends or off at both")
)

// httpHeaderRequest is what the dialling side sends.
func httpHeaderRequest(host string) []byte {
	if host == "" {
		host = defaultHTTPHost
	}
	var b bytes.Buffer
	b.WriteString("GET / HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n")
	b.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
	b.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	b.WriteString("Accept-Encoding: gzip, deflate\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// httpHeaderReply is what the accepting side answers with. The body is whatever
// follows, until the connection closes, which is what "Connection: close" says.
func httpHeaderReply() []byte {
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Server: nginx\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123) + "\r\n")
	b.WriteString("Content-Type: application/octet-stream\r\n")
	b.WriteString("Cache-Control: no-cache\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// readHTTPHead reads up to and including the blank line that ends an HTTP header,
// and not one byte further. The tunnel's own bytes follow directly, and reading
// any of them here would lose them, so it reads a byte at a time. It is done
// once per connection, for a few hundred bytes.
func readHTTPHead(c net.Conn) ([]byte, error) {
	return readHTTPHeadFrom(c, nil)
}

// readHTTPHeadFrom is readHTTPHead when the first bytes were already read.
func readHTTPHeadFrom(c net.Conn, head []byte) ([]byte, error) {
	var one [1]byte
	for len(head) < httpHeadMax {
		if _, err := io.ReadFull(c, one[:]); err != nil {
			return head, err
		}
		head = append(head, one[0])
		if n := len(head); n >= 4 && string(head[n-4:]) == "\r\n\r\n" {
			return head, nil
		}
	}
	return head, errors.New("the web header never ended")
}

// httpHeaderDial starts the fake exchange on a freshly connected plain link. It
// waits for the answer before anything else is sent, so the tunnel's first bytes
// follow a complete exchange the way a real client's would.
func httpHeaderDial(c net.Conn, host string) error {
	if err := c.SetDeadline(time.Now().Add(httpHeadTimeout)); err != nil {
		return err
	}
	if _, err := c.Write(httpHeaderRequest(host)); err != nil {
		return err
	}
	head, err := readHTTPHead(c)
	if err != nil || !bytes.HasPrefix(head, []byte("HTTP/1.")) {
		if err == nil {
			err = fmt.Errorf("got %q instead", firstLine(head))
		}
		return fmt.Errorf("%w (%v)", errHTTPNoReply, err)
	}
	return c.SetDeadline(time.Time{})
}

// httpHeaderAccept reads the request on a freshly accepted plain link and answers
// it. A connection that does not open with a web request is refused by name.
func httpHeaderAccept(c net.Conn) error {
	if err := c.SetDeadline(time.Now().Add(httpHeadTimeout)); err != nil {
		return err
	}
	// The first four bytes settle it at once. A peer that has not got the web
	// header on sends its own opening bytes and then waits, and it should be told
	// so now rather than after the timeout.
	var first [4]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		return fmt.Errorf("reading the web header: %w", err)
	}
	if string(first[:]) != "GET " {
		return errHTTPNotHeader
	}
	head, err := readHTTPHeadFrom(c, first[:])
	if err != nil {
		return fmt.Errorf("reading the web header: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(head)), "\r\nhost:") {
		return errHTTPNotHeader
	}
	if _, err := c.Write(httpHeaderReply()); err != nil {
		return err
	}
	return c.SetDeadline(time.Time{})
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 60 {
		b = b[:60]
	}
	return strings.TrimSpace(string(b))
}
