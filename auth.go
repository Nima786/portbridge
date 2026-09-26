package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Wire protocol.
//
// Whichever side opens the TCP connection sends the auth frame immediately, and
// the side that accepted it verifies. Authenticating up front rather than at
// activation time means an unknown peer can never hold resources for longer
// than authReadTimeout.
//
//	auth frame: [1B version][8B unix seconds BE][8B random nonce][32B HMAC]
//	            HMAC is SHA-256 over the preceding 17 bytes, keyed by the secret.
//
// The connection then parks, authenticated and idle, until a user arrives. The
// edge sends msgActivate (with the user's opening bytes appended, if any), the
// origin dials the local service and replies msgAck. Both sides then splice.
const (
	protoVersion = 1

	authTimeLen  = 8
	authNonceLen = 8
	authMACLen   = sha256.Size
	authSignLen  = 1 + authTimeLen + authNonceLen
	authFrameLen = authSignLen + authMACLen

	msgActivate = 0x01
	msgAck      = 0x06

	// Sent before closing, but only once the MAC has already verified, so these
	// never leak information to a peer that does not hold the secret.
	rejClockSkew = 0x11
	rejReplay    = 0x12

	authReadTimeout  = 10 * time.Second
	authWriteTimeout = 10 * time.Second

	// How far the two clocks may disagree. Generous, because a tunnel that is
	// down because of NTP drift is a miserable thing to diagnose.
	clockSkewWindow = 2 * time.Minute
)

var (
	errAuthMAC     = errors.New("wrong or missing secret")
	errAuthVersion = errors.New("peer speaks a different protocol version")
	errAuthSkew    = errors.New("the two servers' clocks differ by more than two minutes; check time sync")
	errAuthReplay  = errors.New("auth frame replayed")
	errRejected    = errors.New("peer rejected our credentials")
)

func hmacFor(secret, data []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil)
}

func buildAuthFrame(secret []byte) ([]byte, error) {
	frame := make([]byte, authFrameLen)
	frame[0] = protoVersion
	binary.BigEndian.PutUint64(frame[1:1+authTimeLen], uint64(time.Now().Unix()))
	if _, err := rand.Read(frame[1+authTimeLen : authSignLen]); err != nil {
		return nil, err
	}
	copy(frame[authSignLen:], hmacFor(secret, frame[:authSignLen]))
	return frame, nil
}

// replayGuard remembers recently seen nonces so that a captured auth frame
// cannot be reused inside the clock-skew window.
type replayGuard struct {
	mu   sync.Mutex
	seen map[[authNonceLen]byte]time.Time
}

func newReplayGuard(ctx context.Context) *replayGuard {
	g := &replayGuard{seen: make(map[[authNonceLen]byte]time.Time)}
	go g.collect(ctx)
	return g
}

func (g *replayGuard) collect(ctx context.Context) {
	ticker := time.NewTicker(clockSkewWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * clockSkewWindow)
			g.mu.Lock()
			for nonce, at := range g.seen {
				if at.Before(cutoff) {
					delete(g.seen, nonce)
				}
			}
			g.mu.Unlock()
		}
	}
}

func (g *replayGuard) admit(nonce [authNonceLen]byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = time.Now()
	return true
}

// verifyAuthFrame checks the MAC first, in constant time. Only a peer that
// already holds the secret can produce the version, clock-skew or replay
// errors, so those are safe to report in detail.
func verifyAuthFrame(frame, secret []byte, guard *replayGuard) error {
	if len(frame) != authFrameLen {
		return errAuthMAC
	}
	if !hmac.Equal(frame[authSignLen:], hmacFor(secret, frame[:authSignLen])) {
		return errAuthMAC
	}
	if frame[0] != protoVersion {
		return errAuthVersion
	}

	stamp := int64(binary.BigEndian.Uint64(frame[1 : 1+authTimeLen]))
	drift := time.Since(time.Unix(stamp, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > clockSkewWindow {
		return errAuthSkew
	}

	var nonce [authNonceLen]byte
	copy(nonce[:], frame[1+authTimeLen:authSignLen])
	if !guard.admit(nonce) {
		return errAuthReplay
	}
	return nil
}

// sendAuth is used by whichever side dials.
func sendAuth(c net.Conn, secret []byte) error {
	frame, err := buildAuthFrame(secret)
	if err != nil {
		return err
	}
	if err := c.SetWriteDeadline(time.Now().Add(authWriteTimeout)); err != nil {
		return err
	}
	if _, err := c.Write(frame); err != nil {
		return err
	}
	return c.SetWriteDeadline(time.Time{})
}

// recvAuth is used by whichever side accepts. On a credential problem that the
// peer could act on, it sends a one-byte reason first so the other end can log
// something useful instead of a bare disconnect.
func recvAuth(c net.Conn, secret []byte, guard *replayGuard) error {
	frame := make([]byte, authFrameLen)
	if err := c.SetReadDeadline(time.Now().Add(authReadTimeout)); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, frame); err != nil {
		return err
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	err := verifyAuthFrame(frame, secret, guard)
	switch err {
	case nil:
		return nil
	case errAuthSkew:
		writeReason(c, rejClockSkew)
	case errAuthReplay:
		writeReason(c, rejReplay)
	}
	return err
}

func writeReason(c net.Conn, reason byte) {
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{reason})
	_ = c.SetWriteDeadline(time.Time{})
}

// describeRejection turns a reason byte from the far side into something a log
// reader can act on.
func describeRejection(b byte) error {
	switch b {
	case rejClockSkew:
		return errAuthSkew
	case rejReplay:
		return errAuthReplay
	default:
		return errRejected
	}
}
