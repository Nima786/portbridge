package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// RealSite Active Probing Defense
//
// A stranger or scanner connecting to a website-style disguised tunnel receives
// the genuine cover website (e.g. Microsoft/Bing), including Microsoft's real
// TLS certificate, cipher suites, and authentic pages. Our server never exposes
// its own certificate to strangers.
//
// An authentic PortBridge client embeds a cryptographic proof into the 32-byte
// Session ID (legacy_session_id) of its TLS ClientHello. Standard TLS 1.3
// servers ignore this field for fresh connections, making it completely
// undetectable to outside DPI sniffers while serving as an authentic proof.
//
// Frame layout of the 32-byte Session ID:
//   [0..3]   4 bytes  masked Unix timestamp (seconds, uint32 BE)
//   [4..11]  8 bytes  cryptographically random nonce
//   [12..31] 20 bytes HMAC-SHA256 authentication tag
//
// Mask key: HMAC(secret, "pb-rs-mask:" + nonce)
// Tag key:  HMAC(secret, "pb-rs-auth:" + unmaskedTimestamp + nonce)

const (
	realSiteProofLen    = 32
	realSiteTimeLen     = 4
	realSiteNonceLen    = 8
	realSiteTagLen      = 20
	realSiteSniffHeader = 5
	realSiteMinBytes    = 76 // 5B TLS header + 4B handshake + 2B ver + 32B rand + 1B sidLen + 32B sid

	strangerMaxBytes = 10 * 1024 * 1024 // 10MB limit per stranger session
	strangerTimeout  = 30 * time.Second // 30s idle timeout
	sniffTimeout     = 5 * time.Second
)

var (
	errStrangerForwarded = errors.New("connection passed to real site")
	errNotRealSiteProof  = errors.New("not a valid real-site proof")
)

// generateRealSiteProof constructs an authenticated 32-byte proof for ClientHello.
func generateRealSiteProof(secret []byte) ([]byte, error) {
	proof := make([]byte, realSiteProofLen)

	var nonce [realSiteNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("reading random nonce: %w", err)
	}
	copy(proof[realSiteTimeLen:realSiteTimeLen+realSiteNonceLen], nonce[:])

	now := uint32(time.Now().Unix())
	var timeBytes [realSiteTimeLen]byte
	binary.BigEndian.PutUint32(timeBytes[:], now)

	maskMAC := hmac.New(sha256.New, secret)
	maskMAC.Write([]byte("pb-rs-mask:"))
	maskMAC.Write(nonce[:])
	mask := maskMAC.Sum(nil)

	for i := 0; i < realSiteTimeLen; i++ {
		proof[i] = timeBytes[i] ^ mask[i]
	}

	authMAC := hmac.New(sha256.New, secret)
	authMAC.Write([]byte("pb-rs-auth:"))
	authMAC.Write(timeBytes[:])
	authMAC.Write(nonce[:])
	tag := authMAC.Sum(nil)

	copy(proof[realSiteTimeLen+realSiteNonceLen:], tag[:realSiteTagLen])
	return proof, nil
}

// verifyRealSiteProof verifies an extracted 32-byte Session ID proof.
func verifyRealSiteProof(secret []byte, sid []byte, guard *replayGuard) bool {
	if len(sid) != realSiteProofLen {
		return false
	}

	nonce := sid[realSiteTimeLen : realSiteTimeLen+realSiteNonceLen]

	maskMAC := hmac.New(sha256.New, secret)
	maskMAC.Write([]byte("pb-rs-mask:"))
	maskMAC.Write(nonce)
	mask := maskMAC.Sum(nil)

	var timeBytes [realSiteTimeLen]byte
	for i := 0; i < realSiteTimeLen; i++ {
		timeBytes[i] = sid[i] ^ mask[i]
	}
	ts := int64(binary.BigEndian.Uint32(timeBytes[:]))

	authMAC := hmac.New(sha256.New, secret)
	authMAC.Write([]byte("pb-rs-auth:"))
	authMAC.Write(timeBytes[:])
	authMAC.Write(nonce)
	expectedTag := authMAC.Sum(nil)[:realSiteTagLen]

	if subtle.ConstantTimeCompare(sid[realSiteTimeLen+realSiteNonceLen:], expectedTag) != 1 {
		return false
	}

	now := time.Now().Unix()
	diff := now - ts
	if diff < -int64(clockSkewWindow.Seconds()) || diff > int64(clockSkewWindow.Seconds()) {
		return false
	}

	if guard != nil {
		var n [authNonceLen]byte
		copy(n[:], nonce)
		if !guard.admit(n) {
			return false
		}
	}

	return true
}

// prefixConn wraps a net.Conn with a prepended read buffer.
type prefixConn struct {
	net.Conn
	pre []byte
}

func newPrefixConn(c net.Conn, prefix []byte) net.Conn {
	return &prefixConn{
		Conn: c,
		pre:  prefix,
	}
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// sniffAndCheckRealSite reads the initial message from raw.
// If it contains a valid proof, returns a prefixed net.Conn ready for TLS handshake.
// Otherwise, dials the genuine cover site, streams whatever was buffered, pipes
// the connection transparently, and returns errStrangerForwarded.
func sniffAndCheckRealSite(raw net.Conn, cfg *Config, guard *replayGuard) (net.Conn, error) {
	_ = raw.SetReadDeadline(time.Now().Add(sniffTimeout))

	buf := make([]byte, 1024)
	n, err := raw.Read(buf)
	if err != nil && n == 0 {
		_ = raw.SetReadDeadline(time.Time{})
		forwardStranger(raw, cfg.coverTarget(), nil)
		return nil, errStrangerForwarded
	}
	buffered := buf[:n]

	// Must start with TLS Handshake record: 0x16 0x03
	if len(buffered) < realSiteSniffHeader || buffered[0] != 0x16 || buffered[1] != 0x03 {
		_ = raw.SetReadDeadline(time.Time{})
		forwardStranger(raw, cfg.coverTarget(), buffered)
		return nil, errStrangerForwarded
	}

	recordLen := int(binary.BigEndian.Uint16(buffered[3:5]))
	needed := realSiteMinBytes
	if needed > 5+recordLen {
		needed = 5 + recordLen
	}

	// Read remaining bytes if ClientHello was split across packets
	for len(buffered) < needed {
		more := make([]byte, needed-len(buffered))
		nr, rerr := raw.Read(more)
		if nr > 0 {
			buffered = append(buffered, more[:nr]...)
		}
		if rerr != nil {
			break
		}
	}

	_ = raw.SetReadDeadline(time.Time{})

	// Check if this is a ClientHello with a 32-byte Session ID
	if len(buffered) >= realSiteMinBytes && buffered[5] == 0x01 && buffered[43] == 32 {
		sid := buffered[44 : 44+32]
		if verifyRealSiteProof(cfg.secret, sid, guard) {
			// Authentic client!
			return newPrefixConn(raw, buffered), nil
		}
	}

	// Stranger or replayed hello -> forward to genuine cover site
	forwardStranger(raw, cfg.coverTarget(), buffered)
	return nil, errStrangerForwarded
}

// forwardStranger transparently proxies a stranger to the cover website.
func forwardStranger(client net.Conn, coverTarget string, prefix []byte) {
	go func() {
		defer client.Close()

		cover, err := net.DialTimeout("tcp", coverTarget, 5*time.Second)
		if err != nil {
			return
		}
		defer cover.Close()

		if len(prefix) > 0 {
			_ = cover.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := cover.Write(prefix); err != nil {
				return
			}
		}

		_ = client.SetDeadline(time.Now().Add(strangerTimeout))
		_ = cover.SetDeadline(time.Now().Add(strangerTimeout))

		var wg sync.WaitGroup
		wg.Add(2)

		pipeHalf := func(dst, src net.Conn) {
			defer wg.Done()
			buf := make([]byte, 16*1024)
			var total int64
			for {
				_ = src.SetReadDeadline(time.Now().Add(strangerTimeout))
				n, rerr := src.Read(buf)
				if n > 0 {
					total += int64(n)
					if total > strangerMaxBytes {
						break
					}
					_ = dst.SetWriteDeadline(time.Now().Add(strangerTimeout))
					if _, werr := dst.Write(buf[:n]); werr != nil {
						break
					}
				}
				if rerr != nil {
					break
				}
			}
			_ = dst.Close()
		}

		go pipeHalf(cover, client)
		go pipeHalf(client, cover)

		wg.Wait()
	}()
}
