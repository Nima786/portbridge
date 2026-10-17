package panel

// Parsing SSH private keys: OpenSSH, classic PEM, and PuTTY .ppk (v2 and v3).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa" //nolint:staticcheck // legacy PuTTY ssh-dss keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh"
)

var errPassphraseNeeded = errors.New("that private key is protected by a passphrase; give it too")

// parseAnyPrivateKey parses an OpenSSH, PEM, or PuTTY (.ppk v2/v3) private key.
// It always tries unencrypted parsing first so a browser-autofilled passphrase
// does not break an unencrypted key.
func parseAnyPrivateKey(rawKey, passphrase string) (ssh.Signer, error) {
	cleaned := normalizeKeyText(rawKey)
	if cleaned == "" {
		return nil, errors.New("give the server's private key")
	}

	if looksLikePublicKey(cleaned) {
		return nil, errors.New("that is a public key (authorized_keys format), not a private key; select or paste your private key file (OpenSSH key or PuTTY .ppk)")
	}

	if isPPK(cleaned) {
		signer, err := parsePPK(cleaned, "")
		if err == nil {
			return signer, nil
		}
		if errors.Is(err, errPassphraseNeeded) && passphrase != "" {
			return parsePPK(cleaned, passphrase)
		}
		return nil, err
	}

	pemBytes := []byte(cleaned + "\n")
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}

	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) || strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "encrypted") {
		if passphrase == "" {
			return nil, errPassphraseNeeded
		}
		signer, perr := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
		if perr != nil {
			return nil, fmt.Errorf("that private key could not be unlocked with the passphrase given: %v", perr)
		}
		return signer, nil
	}

	if passphrase != "" {
		if signer, perr := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase)); perr == nil {
			return signer, nil
		}
	}

	return nil, fmt.Errorf("that private key could not be read: %v", err)
}

// normalizeKeyText strips UTF-8 BOMs, normalizes line endings, and repairs
// single-line pasted PEM blocks where line breaks were turned into spaces.
func normalizeKeyText(s string) string {
	s = strings.TrimPrefix(s, "\xef\xbb\xbf")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\xef\xbb\xbf")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// If there is preamble text on the same line before -----BEGIN, put a newline before it.
	if idx := strings.Index(s, "-----BEGIN "); idx > 0 && s[idx-1] != '\n' {
		s = s[:idx] + "\n" + s[idx:]
	}

	// Repair single-line or space-collapsed PEM keys (without header lines like Proc-Type:).
	if strings.HasPrefix(s, "-----BEGIN ") && !strings.Contains(s, "Proc-Type:") && !strings.Contains(s, "DEK-Info:") {
		if endHdr := strings.Index(s[11:], "-----"); endHdr >= 0 {
			headerEnd := 11 + endHdr + 5
			if footerStart := strings.LastIndex(s, "-----END "); footerStart > headerEnd {
				header := strings.TrimSpace(s[:headerEnd])
				body := s[headerEnd:footerStart]
				footer := strings.TrimSpace(s[footerStart:])
				if !strings.Contains(body, "\n") || strings.ContainsAny(strings.TrimSpace(body), " \t") {
					compact := strings.Map(func(r rune) rune {
						if r == ' ' || r == '\t' || r == '\n' {
							return -1
						}
						return r
					}, body)
					if compact != "" {
						var wrapped strings.Builder
						wrapped.WriteString(header)
						wrapped.WriteByte('\n')
						for len(compact) > 64 {
							wrapped.WriteString(compact[:64])
							wrapped.WriteByte('\n')
							compact = compact[64:]
						}
						if len(compact) > 0 {
							wrapped.WriteString(compact)
							wrapped.WriteByte('\n')
						}
						wrapped.WriteString(footer)
						return wrapped.String()
					}
				}
			}
		}
	}
	return s
}

func looksLikePublicKey(s string) bool {
	if strings.HasPrefix(s, "---- BEGIN SSH2 PUBLIC KEY ----") ||
		strings.HasPrefix(s, "-----BEGIN PUBLIC KEY-----") ||
		strings.HasPrefix(s, "-----BEGIN RSA PUBLIC KEY-----") {
		return true
	}
	for _, prefix := range []string{"ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-", "ssh-dss ", "sk-ssh-ed25519@", "sk-ecdsa-"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func isPPK(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\xef\xbb\xbf"))
		if line == "" {
			continue
		}
		return strings.HasPrefix(line, "PuTTY-User-Key-File-")
	}
	return false
}

func parsePPK(text, passphrase string) (ssh.Signer, error) {
	lines := strings.Split(text, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return nil, errors.New("empty PuTTY key file")
	}

	first := strings.TrimSpace(strings.TrimPrefix(lines[0], "\xef\xbb\xbf"))
	var version int
	var algo string
	switch {
	case strings.HasPrefix(first, "PuTTY-User-Key-File-2:"):
		version = 2
		algo = strings.TrimSpace(strings.TrimPrefix(first, "PuTTY-User-Key-File-2:"))
	case strings.HasPrefix(first, "PuTTY-User-Key-File-3:"):
		version = 3
		algo = strings.TrimSpace(strings.TrimPrefix(first, "PuTTY-User-Key-File-3:"))
	default:
		return nil, fmt.Errorf("unsupported PuTTY key format (%s); versions 2 and 3 are supported", first)
	}

	var (
		encryption  string
		comment     string
		pubB64      strings.Builder
		privB64     strings.Builder
		privateMAC  string
		kdfType     string
		argonMem    uint32 = 8192
		argonPasses uint32 = 13
		argonPar    uint8  = 1
		argonSalt   []byte
	)

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Encryption":
			encryption = v
		case "Comment":
			comment = v
		case "Key-Derivation":
			kdfType = v
		case "Argon2-Memory":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				argonMem = uint32(n)
			}
		case "Argon2-Passes":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				argonPasses = uint32(n)
			}
		case "Argon2-Parallelism":
			if n, err := strconv.ParseUint(v, 10, 8); err == nil && n > 0 {
				argonPar = uint8(n)
			}
		case "Argon2-Salt":
			salt, err := hex.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("invalid Argon2-Salt in .ppk file: %w", err)
			}
			argonSalt = salt
		case "Public-Lines":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || i+n >= len(lines) {
				return nil, errors.New("invalid Public-Lines count in .ppk file")
			}
			for j := 1; j <= n; j++ {
				pubB64.WriteString(strings.TrimSpace(lines[i+j]))
			}
			i += n
		case "Private-Lines":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || i+n >= len(lines) {
				return nil, errors.New("invalid Private-Lines count in .ppk file")
			}
			for j := 1; j <= n; j++ {
				privB64.WriteString(strings.TrimSpace(lines[i+j]))
			}
			i += n
		case "Private-MAC":
			privateMAC = v
		}
	}

	pubBlob, err := base64.StdEncoding.DecodeString(pubB64.String())
	if err != nil || len(pubBlob) == 0 {
		return nil, errors.New("could not decode Public-Lines in .ppk file")
	}
	privBlob, err := base64.StdEncoding.DecodeString(privB64.String())
	if err != nil || len(privBlob) == 0 {
		return nil, errors.New("could not decode Private-Lines in .ppk file")
	}

	var macKey []byte
	var macHash func() hash.Hash
	if version == 2 {
		macHash = sha1.New
	} else {
		macHash = sha256.New
	}

	switch encryption {
	case "none", "":
		encryption = "none"
		if version == 2 {
			sum := sha1.Sum([]byte("putty-private-key-file-mac-key"))
			macKey = sum[:]
		}
	case "aes256-cbc":
		if passphrase == "" {
			return nil, errPassphraseNeeded
		}
		if len(privBlob)%aes.BlockSize != 0 {
			return nil, errors.New("encrypted .ppk private key length is not a multiple of AES block size")
		}
		var aesKey, aesIV []byte
		if version == 2 {
			h0 := sha1.New()
			h0.Write([]byte{0, 0, 0, 0})
			h0.Write([]byte(passphrase))
			s0 := h0.Sum(nil)

			h1 := sha1.New()
			h1.Write([]byte{0, 0, 0, 1})
			h1.Write([]byte(passphrase))
			s1 := h1.Sum(nil)

			aesKey = make([]byte, 32)
			copy(aesKey[:20], s0)
			copy(aesKey[20:], s1[:12])
			aesIV = make([]byte, aes.BlockSize)

			hm := sha1.New()
			hm.Write([]byte("putty-private-key-file-mac-key"))
			hm.Write([]byte(passphrase))
			macKey = hm.Sum(nil)
		} else {
			var derived []byte
			switch kdfType {
			case "Argon2i":
				derived = argon2.Key([]byte(passphrase), argonSalt, argonPasses, argonMem, argonPar, 80)
			case "Argon2id":
				derived = argon2.IDKey([]byte(passphrase), argonSalt, argonPasses, argonMem, argonPar, 80)
			case "Argon2d", "":
				derived = argon2dKey([]byte(passphrase), argonSalt, argonPasses, argonMem, argonPar, 80)
			default:
				return nil, fmt.Errorf("unsupported .ppk Key-Derivation %q", kdfType)
			}
			aesKey = derived[:32]
			aesIV = derived[32:48]
			macKey = derived[48:80]
		}
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		plain := make([]byte, len(privBlob))
		cipher.NewCBCDecrypter(block, aesIV).CryptBlocks(plain, privBlob)
		privBlob = plain
	default:
		return nil, fmt.Errorf("unsupported .ppk encryption %q", encryption)
	}

	if privateMAC != "" {
		wantMAC, err := hex.DecodeString(privateMAC)
		if err != nil {
			return nil, errors.New("invalid Private-MAC in .ppk file")
		}
		var macData bytes.Buffer
		writeSSHString(&macData, []byte(algo))
		writeSSHString(&macData, []byte(encryption))
		writeSSHString(&macData, []byte(comment))
		writeSSHString(&macData, pubBlob)
		writeSSHString(&macData, privBlob)

		mac := hmac.New(macHash, macKey)
		mac.Write(macData.Bytes())
		gotMAC := mac.Sum(nil)
		if subtle.ConstantTimeCompare(gotMAC, wantMAC) != 1 {
			if encryption != "none" {
				return nil, errors.New("the passphrase for that .ppk key is wrong")
			}
			return nil, errors.New("the .ppk key file is corrupted (Private-MAC mismatch)")
		}
	}

	return parsePPKBlobs(algo, pubBlob, privBlob)
}

func writeSSHString(buf *bytes.Buffer, b []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	buf.Write(lenBuf[:])
	buf.Write(b)
}

type sshReader struct {
	b []byte
}

func (r *sshReader) readBytes() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, errors.New("unexpected end of key data")
	}
	n := int(binary.BigEndian.Uint32(r.b[:4]))
	r.b = r.b[4:]
	if n < 0 || n > len(r.b) {
		return nil, errors.New("invalid field length in key data")
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, nil
}

func (r *sshReader) readString() (string, error) {
	b, err := r.readBytes()
	return string(b), err
}

func (r *sshReader) readBigInt() (*big.Int, error) {
	b, err := r.readBytes()
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func parsePPKBlobs(algo string, pubBlob, privBlob []byte) (ssh.Signer, error) {
	pubR := &sshReader{b: pubBlob}
	privR := &sshReader{b: privBlob}

	gotAlgo, err := pubR.readString()
	if err != nil {
		return nil, fmt.Errorf("reading .ppk public blob: %w", err)
	}
	if gotAlgo != algo {
		return nil, fmt.Errorf(".ppk key algorithm mismatch (%q vs %q)", algo, gotAlgo)
	}

	switch algo {
	case "ssh-ed25519":
		pubBytes, err := pubR.readBytes()
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 public key in .ppk file")
		}
		seed, err := privR.readBytes()
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("invalid ed25519 private seed in .ppk file")
		}
		privKey := ed25519.NewKeyFromSeed(seed)
		if !bytes.Equal(privKey.Public().(ed25519.PublicKey), pubBytes) {
			return nil, errors.New(".ppk ed25519 public and private keys do not match")
		}
		return ssh.NewSignerFromKey(privKey)

	case "ssh-rsa":
		e, err := pubR.readBigInt()
		if err != nil {
			return nil, err
		}
		n, err := pubR.readBigInt()
		if err != nil {
			return nil, err
		}
		d, err := privR.readBigInt()
		if err != nil {
			return nil, err
		}
		p, err := privR.readBigInt()
		if err != nil {
			return nil, err
		}
		q, err := privR.readBigInt()
		if err != nil {
			return nil, err
		}
		_, err = privR.readBigInt() // iqmp
		if err != nil {
			return nil, err
		}
		privKey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: int(e.Int64()),
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		if err := privKey.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA key in .ppk file: %w", err)
		}
		privKey.Precompute()
		return ssh.NewSignerFromKey(privKey)

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		var curve elliptic.Curve
		switch algo {
		case "ecdsa-sha2-nistp256":
			curve = elliptic.P256()
		case "ecdsa-sha2-nistp384":
			curve = elliptic.P384()
		case "ecdsa-sha2-nistp521":
			curve = elliptic.P521()
		}
		_, err := pubR.readString() // curve identifier
		if err != nil {
			return nil, err
		}
		point, err := pubR.readBytes()
		if err != nil {
			return nil, err
		}
		d, err := privR.readBigInt()
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(curve, point) //nolint:staticcheck // standard NIST uncompressed point in SSH wire format
		if x == nil {
			x, y = curve.ScalarBaseMult(d.Bytes())
		}
		privKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: d,
		}
		return ssh.NewSignerFromKey(privKey)

	case "ssh-dss":
		p, err := pubR.readBigInt()
		if err != nil {
			return nil, err
		}
		q, err := pubR.readBigInt()
		if err != nil {
			return nil, err
		}
		g, err := pubR.readBigInt()
		if err != nil {
			return nil, err
		}
		y, err := pubR.readBigInt()
		if err != nil {
			return nil, err
		}
		x, err := privR.readBigInt()
		if err != nil {
			return nil, err
		}
		privKey := &dsa.PrivateKey{
			PublicKey: dsa.PublicKey{
				Parameters: dsa.Parameters{P: p, Q: q, G: g},
				Y:          y,
			},
			X: x,
		}
		return ssh.NewSignerFromKey(privKey)

	default:
		return nil, fmt.Errorf("unsupported .ppk key algorithm %q", algo)
	}
}

// ---------------------------------------------------------------------------
// Argon2d (mode 0) for encrypted PuTTY-User-Key-File-3 keys
// ---------------------------------------------------------------------------

type argon2Block [128]uint64

func argon2dKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if threads < 1 {
		threads = 1
	}
	if time < 1 {
		time = 1
	}
	lanes := uint32(threads)
	memBlocks := memory
	if memBlocks < 2*4*lanes {
		memBlocks = 2 * 4 * lanes
	}
	segmentLength := memBlocks / (lanes * 4)
	laneLength := segmentLength * 4
	memBlocks = laneLength * lanes

	h0 := argon2InitHash(password, salt, nil, nil, keyLen, memory, time, uint32(threads), 0)
	B := make([]argon2Block, memBlocks)
	var block0In [72]byte
	copy(block0In[:64], h0[:])
	for lane := uint32(0); lane < lanes; lane++ {
		binary.LittleEndian.PutUint32(block0In[68:72], lane)
		binary.LittleEndian.PutUint32(block0In[64:68], 0)
		argon2HashBytes(B[lane*laneLength][:], block0In[:])
		binary.LittleEndian.PutUint32(block0In[64:68], 1)
		argon2HashBytes(B[lane*laneLength+1][:], block0In[:])
	}

	for pass := uint32(0); pass < time; pass++ {
		for slice := uint32(0); slice < 4; slice++ {
			for lane := uint32(0); lane < lanes; lane++ {
				index := uint32(0)
				if pass == 0 && slice == 0 {
					index = 2
				}
				for ; index < segmentLength; index++ {
					currOffset := lane*laneLength + slice*segmentLength + index
					var prevOffset uint32
					if slice == 0 && index == 0 {
						prevOffset = lane*laneLength + laneLength - 1
					} else {
						prevOffset = currOffset - 1
					}
					j1 := uint32(B[prevOffset][0])
					j2 := uint32(B[prevOffset][0] >> 32)
					refLane := j2 % lanes
					if pass == 0 && slice == 0 {
						refLane = lane
					}
					refIndex := argon2IndexAlpha(pass, slice, index, segmentLength, laneLength, j1, refLane == lane)
					refBlock := &B[refLane*laneLength+refIndex]
					argon2FillBlock(&B[prevOffset], refBlock, &B[currOffset], pass > 0)
				}
			}
		}
	}

	var finalBlock argon2Block
	for lane := uint32(0); lane < lanes; lane++ {
		last := &B[lane*laneLength+laneLength-1]
		for k := range finalBlock {
			finalBlock[k] ^= last[k]
		}
	}
	var finalBytes [1024]byte
	for k, v := range finalBlock {
		binary.LittleEndian.PutUint64(finalBytes[k*8:], v)
	}
	out := make([]byte, keyLen)
	argon2Blake2bLong(out, finalBytes[:])
	return out
}

func argon2InitHash(password, salt, key, data []byte, tagLen, memory, time, threads, mode uint32) [64]byte {
	h, _ := blake2b.New512(nil)
	var b4 [4]byte
	put32 := func(v uint32) {
		binary.LittleEndian.PutUint32(b4[:], v)
		h.Write(b4[:])
	}
	putBytes := func(p []byte) {
		put32(uint32(len(p)))
		h.Write(p)
	}
	put32(threads)
	put32(tagLen)
	put32(memory)
	put32(time)
	put32(0x13) // Argon2 version 1.3
	put32(mode) // 0 = Argon2d
	putBytes(password)
	putBytes(salt)
	putBytes(key)
	putBytes(data)
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

func argon2HashBytes(outWords []uint64, in []byte) {
	var buf [1024]byte
	argon2Blake2bLong(buf[:], in)
	for i := range outWords {
		outWords[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
}

func argon2Blake2bLong(out, in []byte) {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(out)))
	if len(out) <= 64 {
		h, _ := blake2b.New(len(out), nil)
		h.Write(lenBuf[:])
		h.Write(in)
		copy(out, h.Sum(nil))
		return
	}
	h, _ := blake2b.New512(nil)
	h.Write(lenBuf[:])
	h.Write(in)
	v := h.Sum(nil)
	copy(out[:32], v[:32])
	out = out[32:]
	for len(out) > 64 {
		vArr := blake2b.Sum512(v)
		v = vArr[:]
		copy(out[:32], v[:32])
		out = out[32:]
	}
	hLast, _ := blake2b.New(len(out), nil)
	hLast.Write(v)
	copy(out, hLast.Sum(nil))
}

func argon2IndexAlpha(pass, slice, index, segmentLength, laneLength, randJ1 uint32, sameLane bool) uint32 {
	var refAreaSize uint32
	if pass == 0 {
		if slice == 0 {
			refAreaSize = index - 1
		} else if sameLane {
			refAreaSize = slice*segmentLength + index - 1
		} else {
			refAreaSize = slice * segmentLength
			if index == 0 {
				refAreaSize--
			}
		}
	} else if sameLane {
		refAreaSize = laneLength - segmentLength + index - 1
	} else {
		refAreaSize = laneLength - segmentLength
		if index == 0 {
			refAreaSize--
		}
	}
	relPos := uint64(randJ1)
	relPos = (relPos * relPos) >> 32
	relPos = uint64(refAreaSize) - 1 - ((uint64(refAreaSize) * relPos) >> 32)
	var startPos uint32
	if pass != 0 && slice != 3 {
		startPos = (slice + 1) * segmentLength
	}
	return (startPos + uint32(relPos)) % laneLength
}

func argon2FillBlock(prev, ref, next *argon2Block, xor bool) {
	var r, z argon2Block
	for i := range r {
		r[i] = prev[i] ^ ref[i]
		z[i] = r[i]
	}
	for i := 0; i < 8; i++ {
		argon2BlaMka(&z[16*i], &z[16*i+1], &z[16*i+2], &z[16*i+3],
			&z[16*i+4], &z[16*i+5], &z[16*i+6], &z[16*i+7],
			&z[16*i+8], &z[16*i+9], &z[16*i+10], &z[16*i+11],
			&z[16*i+12], &z[16*i+13], &z[16*i+14], &z[16*i+15])
	}
	for i := 0; i < 8; i++ {
		argon2BlaMka(&z[2*i], &z[2*i+1], &z[2*i+16], &z[2*i+17],
			&z[2*i+32], &z[2*i+33], &z[2*i+48], &z[2*i+49],
			&z[2*i+64], &z[2*i+65], &z[2*i+80], &z[2*i+81],
			&z[2*i+96], &z[2*i+97], &z[2*i+112], &z[2*i+113])
	}
	if xor {
		for i := range next {
			next[i] ^= r[i] ^ z[i]
		}
	} else {
		for i := range next {
			next[i] = r[i] ^ z[i]
		}
	}
}

func argon2BlaMka(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 *uint64) {
	g := func(a, b, c, d *uint64) {
		*a = *a + *b + 2*uint64(uint32(*a))*uint64(uint32(*b))
		*d ^= *a
		*d = (*d >> 32) | (*d << 32)
		*c = *c + *d + 2*uint64(uint32(*c))*uint64(uint32(*d))
		*b ^= *c
		*b = (*b >> 24) | (*b << 40)
		*a = *a + *b + 2*uint64(uint32(*a))*uint64(uint32(*b))
		*d ^= *a
		*d = (*d >> 16) | (*d << 48)
		*c = *c + *d + 2*uint64(uint32(*c))*uint64(uint32(*d))
		*b ^= *c
		*b = (*b >> 63) | (*b << 1)
	}
	g(v0, v4, v8, v12)
	g(v1, v5, v9, v13)
	g(v2, v6, v10, v14)
	g(v3, v7, v11, v15)
	g(v0, v5, v10, v15)
	g(v1, v6, v11, v12)
	g(v2, v7, v8, v13)
	g(v3, v4, v9, v14)
}

func newAESTestCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func encryptCBCTest(block cipher.Block, iv, dst, src []byte) {
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
}

func computePPKV3MAC(algo, enc, comment string, pub, priv, macKey []byte) string {
	var macData bytes.Buffer
	writeSSHString(&macData, []byte(algo))
	writeSSHString(&macData, []byte(enc))
	writeSSHString(&macData, []byte(comment))
	writeSSHString(&macData, pub)
	writeSSHString(&macData, priv)
	m := hmac.New(sha256.New, macKey)
	m.Write(macData.Bytes())
	return hex.EncodeToString(m.Sum(nil))
}
