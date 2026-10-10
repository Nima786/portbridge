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
// Whichever side opens the connection authenticates immediately.
//
// Protocol v1 (legacy):
//	auth frame: [1B version=1][8B unix seconds BE][8B random nonce][32B HMAC]
//
// Protocol v2 (obfuscated, variable padding):
//	wire: [8B nonce (nonce[0] != 1)]
//	      [11B masked header: XOR(ver(1B) + purpose(1B) + timestamp(8B) + padLen(1B), mask[:11])]
//	      [padLen random bytes (16..64 bytes)]
//	      [32B HMAC over nonce + plaintext header + padding]
//	Total wire length: 67 to 115 bytes (completely variable, no static signature, no magic byte).
//	Mask key: HMAC(secret, "portbridge-v2-mask:" + nonce)
//
// When using TransportWSS, the v2 auth frame can also be carried in the HTTP Upgrade
// header (Sec-WebSocket-Protocol: portbridge.v2.<b64>) for 0-RTT instant activation.

const (
	protoVersion  = 1
	protoVersion2 = 2

	// authPurposeTunnel is what every build up to 0.4.5 sends for a tunnel
	// connection, and it still means "a tunnel connection, no claim made about
	// how it will be used". An acceptor must keep taking it as before.
	authPurposeTunnel byte = 0x00

	// These two say how the dialling side intends to use the connection: parked
	// one-per-user (pooled), or as one of a few long-lived shared links (mux).
	//
	// They exist so that a disagreement between the two servers is caught at the
	// handshake, by name, instead of surfacing later as users hanging for twenty
	// seconds while both ends report everything ready. Older acceptors treat any
	// purpose other than speedtest as a plain tunnel connection, so sending these
	// to an older build is harmless.
	authPurposeTunnelPooled byte = 0x01
	authPurposeTunnelMux    byte = 0x02

	authPurposeSpeedtest byte = 0x05

	authTimeLen  = 8
	authNonceLen = 8
	authMACLen   = sha256.Size // 32
	authSignLen  = 1 + authTimeLen + authNonceLen
	authFrameLen = authSignLen + authMACLen // 49 (v1)

	authV2HdrLen = 11 // 1B ver + 1B purpose + 8B time + 1B padLen

	msgActivate     = 0x01
	msgActivatePort = 0x02 // followed by 2B target port uint16 BE, then opening bytes
	msgTeardown     = 0x03 // request origin to delete this tunnel
	msgTeardownAck  = 0x04 // origin confirms teardown request
	msgSpeedtest    = 0x05 // in-tunnel speedtest request
	msgAck          = 0x06
	msgParkPing     = 0x07 // periodic heartbeat for parked spares (keeps UDP NAT alive)
	msgParkPong     = 0x08 // heartbeat reply

	// Sent before closing, but only once the MAC has already verified, so these
	// never leak information to a peer that does not hold the secret.
	rejClockSkew = 0x11
	rejReplay    = 0x12

	// rejMuxMismatch says the two servers disagree about shared connections.
	// Sent only after the MAC has verified, like the others.
	rejMuxMismatch = 0x13

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

	// The mismatch errors say which side has sharing turned on, because that is
	// the thing someone has to go and change.
	errMuxMismatch = errors.New("the two servers disagree about shared connections (mux): " +
		"one has it on and the other off; set it the same on both")
	errMuxOnlyThere = errors.New("the other server uses shared connections (mux) but this one does not; " +
		"set it the same on both")
	errMuxOnlyHere = errors.New("this server uses shared connections (mux) but the other one does not; " +
		"set it the same on both")
	errTeardownRequested = errors.New("remote teardown requested")
	errSpeedtestFinished = errors.New("speedtest completed")
)

func hmacFor(secret, data []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil)
}

// buildAuthFrame produces a legacy 49-byte v1 frame.
func buildAuthFrame(secret []byte) ([]byte, error) {
	return buildAuthFrameV1(secret)
}

// buildAuthFrameV2 builds an obfuscated, variable-length auth frame for purpose.
func buildAuthFrameV2(secret []byte, purpose byte) ([]byte, error) {
	// Generate random nonce where nonce[0] != protoVersion (1) to guarantee zero clash with v1
	var nonce [authNonceLen]byte
	for {
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		if nonce[0] != protoVersion {
			break
		}
	}

	// Variable random padding between 16 and 64 bytes
	var padLenByte [1]byte
	if _, err := rand.Read(padLenByte[:]); err != nil {
		return nil, err
	}
	padLen := 16 + int(padLenByte[0]%49) // 16..64
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}

	// Plaintext header: [ver(1B)][purpose(1B)][timestamp(8B)][padLen(1B)]
	plainHdr := make([]byte, authV2HdrLen)
	plainHdr[0] = protoVersion2
	plainHdr[1] = purpose
	binary.BigEndian.PutUint64(plainHdr[2:10], uint64(time.Now().Unix()))
	plainHdr[10] = byte(padLen)

	// Derive stream mask from secret + nonce
	maskKey := append([]byte("portbridge-v2-mask:"), nonce[:]...)
	mask := hmacFor(secret, maskKey)

	// XOR mask the header
	maskedHdr := make([]byte, authV2HdrLen)
	for i := 0; i < authV2HdrLen; i++ {
		maskedHdr[i] = plainHdr[i] ^ mask[i]
	}

	// Compute HMAC over nonce + plainHdr + padding
	macData := make([]byte, 0, len(nonce)+len(plainHdr)+len(padding))
	macData = append(macData, nonce[:]...)
	macData = append(macData, plainHdr...)
	macData = append(macData, padding...)
	mac := hmacFor(secret, macData)

	// Full frame: nonce + maskedHdr + padding + mac
	frame := make([]byte, 0, len(nonce)+len(maskedHdr)+len(padding)+len(mac))
	frame = append(frame, nonce[:]...)
	frame = append(frame, maskedHdr...)
	frame = append(frame, padding...)
	frame = append(frame, mac...)
	return frame, nil
}

// buildAuthFrameV1 produces a legacy 49-byte v1 frame.
func buildAuthFrameV1(secret []byte) ([]byte, error) {
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

// verifyAuthFrameBytes checks either v1 (49B) or v2 (67-115B) auth frames from a byte slice.
func verifyAuthFrameBytes(frame, secret []byte, guard *replayGuard) (byte, error) {
	if len(frame) == authFrameLen && frame[0] == protoVersion {
		// Legacy v1
		if !hmac.Equal(frame[authSignLen:], hmacFor(secret, frame[:authSignLen])) {
			return 0, errAuthMAC
		}
		stamp := int64(binary.BigEndian.Uint64(frame[1 : 1+authTimeLen]))
		drift := time.Since(time.Unix(stamp, 0))
		if drift < 0 {
			drift = -drift
		}
		if drift > clockSkewWindow {
			return 0, errAuthSkew
		}
		var nonce [authNonceLen]byte
		copy(nonce[:], frame[1+authTimeLen:authSignLen])
		if guard != nil && !guard.admit(nonce) {
			return 0, errAuthReplay
		}
		return authPurposeTunnel, nil
	}

	// v2: min length is 8 (nonce) + 11 (maskedHdr) + 16 (min pad) + 32 (mac) = 67
	// max length is 8 + 11 + 64 (max pad) + 32 = 115
	if len(frame) < 8+authV2HdrLen+16+authMACLen || len(frame) > 8+authV2HdrLen+64+authMACLen {
		return 0, errAuthMAC
	}

	var nonce [authNonceLen]byte
	copy(nonce[:], frame[:authNonceLen])
	maskedHdr := frame[authNonceLen : authNonceLen+authV2HdrLen]

	maskKey := append([]byte("portbridge-v2-mask:"), nonce[:]...)
	mask := hmacFor(secret, maskKey)

	plainHdr := make([]byte, authV2HdrLen)
	for i := 0; i < authV2HdrLen; i++ {
		plainHdr[i] = maskedHdr[i] ^ mask[i]
	}

	if plainHdr[0] != protoVersion2 {
		return 0, errAuthMAC
	}
	purpose := plainHdr[1]
	padLen := int(plainHdr[10])
	if padLen < 16 || padLen > 64 {
		return 0, errAuthMAC
	}

	expectedLen := authNonceLen + authV2HdrLen + padLen + authMACLen
	if len(frame) != expectedLen {
		return 0, errAuthMAC
	}

	padding := frame[authNonceLen+authV2HdrLen : authNonceLen+authV2HdrLen+padLen]
	macOnWire := frame[authNonceLen+authV2HdrLen+padLen:]

	macData := make([]byte, 0, len(nonce)+len(plainHdr)+len(padding))
	macData = append(macData, nonce[:]...)
	macData = append(macData, plainHdr...)
	macData = append(macData, padding...)
	expectedMAC := hmacFor(secret, macData)

	if !hmac.Equal(macOnWire, expectedMAC) {
		return 0, errAuthMAC
	}

	stamp := int64(binary.BigEndian.Uint64(plainHdr[2:10]))
	drift := time.Since(time.Unix(stamp, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > clockSkewWindow {
		return 0, errAuthSkew
	}

	if guard != nil && !guard.admit(nonce) {
		return 0, errAuthReplay
	}
	return purpose, nil
}

// verifyAuthFrame is the backward-compatible check function.
func verifyAuthFrame(frame, secret []byte, guard *replayGuard) error {
	_, err := verifyAuthFrameBytes(frame, secret, guard)
	return err
}

// sendAuth is used by whichever side dials, for a connection that makes no claim
// about how it will be used (teardown requests, and anything from an older
// caller).
func sendAuth(c net.Conn, secret []byte) error {
	return sendAuthPurpose(c, secret, authPurposeTunnel)
}

// tunnelPurposeFor is the purpose a dialling side announces for a tunnel
// connection: pooled or shared, according to its own settings.
func tunnelPurposeFor(cfg *Config) byte {
	if cfg.Mux {
		return authPurposeTunnelMux
	}
	return authPurposeTunnelPooled
}

// isTunnelPurpose reports whether a purpose means "a tunnel connection" in any of
// its spellings, as opposed to a speed test.
func isTunnelPurpose(p byte) bool {
	return p == authPurposeTunnel || p == authPurposeTunnelPooled || p == authPurposeTunnelMux
}

// checkTunnelPurpose compares what the dialling side said it will do with what
// this side is set up to do. The legacy purpose makes no claim, so it always
// passes: that is what keeps a mixed-version pair working as it did.
func checkTunnelPurpose(cfg *Config, purpose byte) error {
	switch purpose {
	case authPurposeTunnelMux:
		if !cfg.Mux {
			return errMuxOnlyThere
		}
	case authPurposeTunnelPooled:
		if cfg.Mux {
			return errMuxOnlyHere
		}
	}
	return nil
}

// sendAuthPurpose sends an auth frame with a specific purpose (tunnel or speedtest).
func sendAuthPurpose(c net.Conn, secret []byte, purpose byte) error {
	// A connection that was already authenticated during the websocket upgrade
	// has told the far side its purpose there. Only skip sending again when that
	// purpose is the one being asked for now; otherwise the far side would read a
	// second frame as if it were tunnel data.
	if ea, ok := c.(interface {
		isEarlyAuthed() bool
		earlyPurpose() byte
	}); ok && ea.isEarlyAuthed() && ea.earlyPurpose() == purpose {
		return nil
	}
	frame, err := buildAuthFrameV2(secret, purpose)
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

// recvAuth is used by whichever side accepts. Returns nil if valid.
func recvAuth(c net.Conn, secret []byte, guard *replayGuard) error {
	_, err := recvAuthPurpose(c, secret, guard)
	return err
}

// recvAuthPurpose reads the auth frame from c and returns the authenticated purpose.
func recvAuthPurpose(c net.Conn, secret []byte, guard *replayGuard) (byte, error) {
	if ea, ok := c.(interface {
		isEarlyAuthed() bool
		earlyPurpose() byte
	}); ok && ea.isEarlyAuthed() {
		// Already verified during the upgrade, including its purpose. Returning
		// a fixed "tunnel" here used to discard that, which quietly broke every
		// speed test over the websocket disguise.
		return ea.earlyPurpose(), nil
	}

	if err := c.SetReadDeadline(time.Now().Add(authReadTimeout)); err != nil {
		return 0, err
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var firstByte [1]byte
	if _, err := io.ReadFull(c, firstByte[:]); err != nil {
		return 0, err
	}

	if firstByte[0] == protoVersion {
		// Legacy v1: read remaining 48 bytes
		frame := make([]byte, authFrameLen)
		frame[0] = protoVersion
		if _, err := io.ReadFull(c, frame[1:]); err != nil {
			return 0, err
		}
		err := verifyAuthFrame(frame, secret, guard)
		if err != nil {
			if err == errAuthSkew {
				writeReason(c, rejClockSkew)
			} else if err == errAuthReplay {
				writeReason(c, rejReplay)
			}
			return 0, err
		}
		return authPurposeTunnel, nil
	}

	// v2: firstByte is nonce[0]
	// Read remaining 7 bytes of nonce + 11 bytes of maskedHdr (18 bytes total)
	hdrBuf := make([]byte, (authNonceLen-1)+authV2HdrLen)
	if _, err := io.ReadFull(c, hdrBuf); err != nil {
		return 0, err
	}

	var nonce [authNonceLen]byte
	nonce[0] = firstByte[0]
	copy(nonce[1:], hdrBuf[:authNonceLen-1])
	maskedHdr := hdrBuf[authNonceLen-1:]

	maskKey := append([]byte("portbridge-v2-mask:"), nonce[:]...)
	mask := hmacFor(secret, maskKey)

	plainHdr := make([]byte, authV2HdrLen)
	for i := 0; i < authV2HdrLen; i++ {
		plainHdr[i] = maskedHdr[i] ^ mask[i]
	}

	if plainHdr[0] != protoVersion2 {
		return 0, errAuthMAC
	}
	purpose := plainHdr[1]
	padLen := int(plainHdr[10])
	if padLen < 16 || padLen > 64 {
		return 0, errAuthMAC
	}

	// Read remaining padLen + 32 bytes (padding + mac)
	remBuf := make([]byte, padLen+authMACLen)
	if _, err := io.ReadFull(c, remBuf); err != nil {
		return 0, err
	}

	padding := remBuf[:padLen]
	macOnWire := remBuf[padLen:]

	macData := make([]byte, 0, len(nonce)+len(plainHdr)+len(padding))
	macData = append(macData, nonce[:]...)
	macData = append(macData, plainHdr...)
	macData = append(macData, padding...)
	expectedMAC := hmacFor(secret, macData)

	if !hmac.Equal(macOnWire, expectedMAC) {
		return 0, errAuthMAC
	}

	stamp := int64(binary.BigEndian.Uint64(plainHdr[2:10]))
	drift := time.Since(time.Unix(stamp, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > clockSkewWindow {
		writeReason(c, rejClockSkew)
		return 0, errAuthSkew
	}

	if guard != nil && !guard.admit(nonce) {
		writeReason(c, rejReplay)
		return 0, errAuthReplay
	}

	return purpose, nil
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
	case rejMuxMismatch:
		return errMuxMismatch
	default:
		return errRejected
	}
}

// isRejection reports whether b is one of the one-byte reasons a far side sends
// just before closing.
func isRejection(b byte) bool {
	return b == rejClockSkew || b == rejReplay || b == rejMuxMismatch
}

// sinkGarbageAndClose drains any trailing probe bytes and closes with a brief,
// realistic jitter so active scanners probing unauthenticated ports cannot detect
// an instantaneous cryptographic rejection reaction.
func sinkGarbageAndClose(c net.Conn) {
	go func() {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		buf := make([]byte, 1024)
		for {
			n, err := c.Read(buf)
			if n == 0 || err != nil {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}()
}
