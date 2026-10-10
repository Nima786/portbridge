package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

var (
	browserProfiles = []struct {
		userAgent   string
		secChUa     string
		secPlatform string
		accept      string
		acceptLang  string
		acceptEnc   string
	}{
		{
			// Chrome on Windows
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			secChUa:     `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			secPlatform: `"Windows"`,
			accept:      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			acceptLang:  "en-US,en;q=0.9",
			acceptEnc:   "gzip, deflate, br, zstd",
		},
		{
			// Chrome on macOS
			userAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			secChUa:     `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			secPlatform: `"macOS"`,
			accept:      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			acceptLang:  "en-US,en;q=0.9",
			acceptEnc:   "gzip, deflate, br, zstd",
		},
		{
			// Edge on Windows
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
			secChUa:     `"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			secPlatform: `"Windows"`,
			accept:      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
			acceptLang:  "en-US,en;q=0.9",
			acceptEnc:   "gzip, deflate, br",
		},
		{
			// Firefox on Windows
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
			secChUa:     "",
			secPlatform: "",
			accept:      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			acceptLang:  "en-US,en;q=0.5",
			acceptEnc:   "gzip, deflate, br, zstd",
		},
		{
			// Safari on macOS
			userAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
			secChUa:     "",
			secPlatform: "",
			accept:      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			acceptLang:  "en-US,en;q=0.9",
			acceptEnc:   "gzip, deflate, br",
		},
	}

	serverNames = []string{
		"nginx/1.24.0",
		"nginx",
		"Apache/2.4.58 (Ubuntu)",
		"cloudflare",
		"Microsoft-IIS/10.0",
	}
)

// randInt returns a uniformly spread number in [0, n). It reads four random
// bytes, not one, so that large ranges (cookie numbers) really are spread
// across the whole range rather than only its first 256 values.
func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}

// generatePlausibleCookie follows the shape Google Analytics cookies really
// have: _ga is GA1.2.<random number>.<first-visit time>, _gid is
// GA1.2.<random number>.<time>.
func generatePlausibleCookie() string {
	var rnd [16]byte
	_, _ = rand.Read(rnd[:])
	hexPart := hex.EncodeToString(rnd[:])
	now := time.Now().Unix()
	// First visit was some days ago; _gid is from the last day or so.
	firstVisit := now - int64(86400*(1+randInt(60)))
	return fmt.Sprintf("_ga=GA1.2.%d.%d; _gid=GA1.2.%d.%d; session_token=%s",
		1000000000+randInt(1000000000), firstVisit,
		1000000000+randInt(1000000000), now-int64(randInt(86400)),
		hexPart)
}

// httpHeaderRequest is what the dialling side sends. It rotates across modern
// browser profiles, varies headers and cookies, and pads to realistic browser size (500-800+ bytes).
func httpHeaderRequest(host string) []byte {
	if host == "" {
		host = defaultHTTPHost
	}

	prof := browserProfiles[randInt(len(browserProfiles))]

	var b bytes.Buffer
	b.WriteString("GET / HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: " + prof.userAgent + "\r\n")
	b.WriteString("Accept: " + prof.accept + "\r\n")
	b.WriteString("Accept-Language: " + prof.acceptLang + "\r\n")
	b.WriteString("Accept-Encoding: " + prof.acceptEnc + "\r\n")
	b.WriteString("Upgrade-Insecure-Requests: 1\r\n")

	if prof.secChUa != "" {
		b.WriteString("Sec-Ch-Ua: " + prof.secChUa + "\r\n")
		b.WriteString("Sec-Ch-Ua-Mobile: ?0\r\n")
		b.WriteString("Sec-Ch-Ua-Platform: " + prof.secPlatform + "\r\n")
		b.WriteString("Sec-Fetch-Site: none\r\n")
		b.WriteString("Sec-Fetch-Mode: navigate\r\n")
		b.WriteString("Sec-Fetch-User: ?1\r\n")
		b.WriteString("Sec-Fetch-Dest: document\r\n")
	}

	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("Cookie: " + generatePlausibleCookie() + "\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// httpHeaderReply is what the accepting side answers with.
func httpHeaderReply() []byte {
	srv := serverNames[randInt(len(serverNames))]
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Server: " + srv + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Cache-Control: private, max-age=0\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// writeHTTPBadRequest answers probes and scanners with an authentic nginx 400 error page.
func writeHTTPBadRequest(c net.Conn) {
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	body := "<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	resp := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		time.Now().UTC().Format(http.TimeFormat), len(body), body)
	_, _ = c.Write([]byte(resp))
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
		writeHTTPBadRequest(c)
		return errHTTPNotHeader
	}
	head, err := readHTTPHeadFrom(c, first[:])
	if err != nil {
		writeHTTPBadRequest(c)
		return fmt.Errorf("reading the web header: %w", err)
	}
	if !strings.Contains(strings.ToLower(string(head)), "\r\nhost:") {
		writeHTTPBadRequest(c)
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
