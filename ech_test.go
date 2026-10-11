package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// makeTestECHKey generates a real X25519 DHKEM(X25519, HKDF-SHA256) ECH key
// pair returning the server's tls.EncryptedClientHelloKey and the client's
// serialized ECHConfigList.
func makeTestECHKey(t *testing.T, keyID uint8, publicName string) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating X25519 key: %v", err)
	}
	pub := priv.PublicKey().Bytes()

	var contents bytes.Buffer
	contents.WriteByte(keyID)
	// KEM: DHKEM(X25519, HKDF-SHA256) = 0x0020
	_ = binary.Write(&contents, binary.BigEndian, uint16(0x0020))
	_ = binary.Write(&contents, binary.BigEndian, uint16(len(pub)))
	contents.Write(pub)
	// CipherSuites: length 4, HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001)
	_ = binary.Write(&contents, binary.BigEndian, uint16(4))
	_ = binary.Write(&contents, binary.BigEndian, uint16(0x0001))
	_ = binary.Write(&contents, binary.BigEndian, uint16(0x0001))
	// maximum_name_length
	contents.WriteByte(64)
	// public_name
	contents.WriteByte(byte(len(publicName)))
	contents.WriteString(publicName)
	// extensions (empty)
	_ = binary.Write(&contents, binary.BigEndian, uint16(0))

	var echConfig bytes.Buffer
	// ECH version 0xfe0d (draft-ietf-tls-esni-18 / RFC)
	_ = binary.Write(&echConfig, binary.BigEndian, uint16(0xfe0d))
	_ = binary.Write(&echConfig, binary.BigEndian, uint16(contents.Len()))
	echConfig.Write(contents.Bytes())

	var echConfigList bytes.Buffer
	_ = binary.Write(&echConfigList, binary.BigEndian, uint16(echConfig.Len()))
	echConfigList.Write(echConfig.Bytes())

	serverKey := tls.EncryptedClientHelloKey{
		Config:      echConfig.Bytes(),
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}
	return serverKey, echConfigList.Bytes()
}

// TestECHClientHelloHidesInnerSNIOnWireAndCompletesHandshake verifies that when
// ECH is active, the secret ServerName is encrypted inside the ECH payload and
// never appears in plaintext on the wire, while the outer ClientHello shows
// only the public outer name ("cloudflare-ech.com") and the TLS server decrypts
// the inner ServerName.
func TestECHClientHelloHidesInnerSNIOnWireAndCompletesHandshake(t *testing.T) {
	clearECHCache()
	defer clearECHCache()

	certFile, keyFile := certPaths(t)
	cert, err := ensureCert(certFile, keyFile, "secret-cdn.example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	echKey, echConfigList := makeTestECHKey(t, 7, "cloudflare-ech.com")

	for _, profile := range []string{"chrome", "firefox", "safari", "ios", "edge", "stdlib"} {
		t.Run(profile, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			wireBytesCh := make(chan []byte, 1)
			innerSNICh := make(chan string, 1)

			go func() {
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				defer raw.Close()

				buf := make([]byte, 2048)
				_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _ := raw.Read(buf)
				wireBytesCh <- append([]byte(nil), buf[:n]...)

				replay := &prefixConn{Conn: raw, pre: buf[:n]}
				ts := tls.Server(replay, &tls.Config{
					Certificates:             []tls.Certificate{cert},
					NextProtos:               []string{"h2", "http/1.1"},
					MinVersion:               tls.VersionTLS13,
					EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{echKey},
				})
				if err := ts.Handshake(); err != nil {
					return
				}
				innerSNICh <- ts.ConnectionState().ServerName
				_, _ = ts.Write([]byte("ok"))
			}()

			cfg := defaultConfig()
			cfg.Mode = ModeDirect
			cfg.Role = RoleEdge
			cfg.Transport = TransportTLS
			cfg.ServerName = "secret-cdn.example.com"
			cfg.TunnelAddr = ln.Addr().String()
			cfg.ECH = true
			cfg.echSet = true
			cfg.ECHConfig = base64.StdEncoding.EncodeToString(echConfigList)
			cfg.TLSFragment = false
			cfg.fragmentSet = true
			if profile == "stdlib" {
				cfg.UTLS = false
				cfg.utlsSet = true
			} else {
				cfg.UTLS = true
				cfg.utlsSet = true
				cfg.UTLSProfile = profile
			}
			cfg.prepareTLS(nil)

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			conn, err := wrapDial(raw, cfg)
			if err != nil {
				t.Fatalf("wrapDial (%s): %v", profile, err)
			}
			defer conn.Close()

			if uc, ok := conn.(*utls.UConn); ok {
				if !uc.ConnectionState().ECHAccepted {
					t.Fatalf("uTLS (%s) reported ECHAccepted=false", profile)
				}
			} else if tc, ok := conn.(*tls.Conn); ok {
				if !tc.ConnectionState().ECHAccepted {
					t.Fatalf("crypto/tls reported ECHAccepted=false")
				}
			}

			var reply [2]byte
			if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "ok" {
				t.Fatalf("read reply: %v (%q)", err, string(reply[:]))
			}

			wireBytes := <-wireBytesCh
			if bytes.Contains(wireBytes, []byte("secret-cdn.example.com")) {
				t.Fatalf("plaintext secret SNI leaked on the wire in profile %s!", profile)
			}
			if !bytes.Contains(wireBytes, []byte("cloudflare-ech.com")) {
				t.Fatalf("expected outer SNI cloudflare-ech.com on the wire in profile %s", profile)
			}

			innerSNI := <-innerSNICh
			if innerSNI != "secret-cdn.example.com" {
				t.Fatalf("server decrypted inner SNI %q, want secret-cdn.example.com", innerSNI)
			}
		})
	}
}

// TestECHRetryConfigListRotationRecovery verifies that when a server rotates its
// ECH key and rejects the first handshake with a RetryConfigList, wrapDial
// automatically caches the new RetryConfigList, redials with the updated key,
// and completes the ECH handshake.
func TestECHRetryConfigListRotationRecovery(t *testing.T) {
	clearECHCache()
	defer clearECHCache()

	certFile, keyFile := certPaths(t)
	cert, err := ensureCert(certFile, keyFile, "rotated.example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	_, staleConfigList := makeTestECHKey(t, 1, "cloudflare-ech.com")
	currentServerKey, _ := makeTestECHKey(t, 2, "cloudflare-ech.com")

	echLookupOverride = func(domain string) []byte {
		return staleConfigList
	}
	defer func() { echLookupOverride = nil }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				ts := tls.Server(c, &tls.Config{
					Certificates:             []tls.Certificate{cert},
					NextProtos:               []string{"h2", "http/1.1"},
					MinVersion:               tls.VersionTLS13,
					EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{currentServerKey},
				})
				if err := ts.Handshake(); err != nil {
					return
				}
				_, _ = ts.Write([]byte("rotated-ok"))
				time.Sleep(50 * time.Millisecond)
			}(raw)
		}
	}()

	cfg := defaultConfig()
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.Transport = TransportTLS
	cfg.CDN = true
	cfg.ServerName = "rotated.example.com"
	cfg.TunnelAddr = ln.Addr().String()
	cfg.prepareTLS(nil)

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := wrapDial(raw, cfg)
	if err != nil {
		t.Fatalf("wrapDial after ECH rotation failed: %v", err)
	}
	defer conn.Close()

	uc, ok := conn.(*utls.UConn)
	if !ok || !uc.ConnectionState().ECHAccepted {
		t.Fatalf("expected uTLS connection with ECHAccepted=true after RetryConfigList recovery")
	}

	var buf [10]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil || string(buf[:]) != "rotated-ok" {
		t.Fatalf("read after rotation: %v (%q)", err, string(buf[:]))
	}
	if got := accepts.Load(); got != 2 {
		t.Fatalf("expected 2 accepts (initial stale ECH + retry with RetryConfigList), got %d", got)
	}
}

// TestECHAutomaticFallbackWhenServerDoesNotSupportECH verifies that when a CDN
// or server does not support ECH, wrapDial automatically falls back to a
// non-ECH connection and caches the bypass so subsequent connections dial
// directly in a single attempt.
func TestECHAutomaticFallbackWhenServerDoesNotSupportECH(t *testing.T) {
	clearECHCache()
	defer clearECHCache()

	certFile, keyFile := certPaths(t)
	cert, err := ensureCert(certFile, keyFile, "no-ech.example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepts atomic.Int32
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				// Server has no EncryptedClientHelloKeys configured.
				ts := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"h2", "http/1.1"},
					MinVersion:   tls.VersionTLS12,
				})
				if err := ts.Handshake(); err != nil {
					return
				}
				_, _ = ts.Write([]byte("fallback-ok"))
				time.Sleep(50 * time.Millisecond)
			}(raw)
		}
	}()

	cfg := defaultConfig()
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.Transport = TransportTLS
	cfg.CDN = true // ECH is enabled by default for CDN
	cfg.ServerName = "no-ech.example.com"
	cfg.TunnelAddr = ln.Addr().String()
	cfg.prepareTLS(nil)

	if !cfg.useECH() {
		t.Fatal("expected ECH to be enabled by default when CDN is on")
	}

	// First connection: tries ECH, server rejects ECH, automatically redials without ECH.
	raw1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	conn1, err := wrapDial(raw1, cfg)
	if err != nil {
		t.Fatalf("first wrapDial should fall back cleanly when server lacks ECH: %v", err)
	}
	var buf [11]byte
	if _, err := io.ReadFull(conn1, buf[:]); err != nil || string(buf[:]) != "fallback-ok" {
		t.Fatalf("read 1: %v (%q)", err, string(buf[:]))
	}
	_ = conn1.Close()

	if got := accepts.Load(); got != 2 {
		t.Fatalf("expected 2 accepts on first connection (ECH attempt + fallback), got %d", got)
	}

	// Second connection: bypass is cached, so it connects directly in 1 attempt!
	raw2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	conn2, err := wrapDial(raw2, cfg)
	if err != nil {
		t.Fatalf("second wrapDial failed: %v", err)
	}
	if _, err := io.ReadFull(conn2, buf[:]); err != nil || string(buf[:]) != "fallback-ok" {
		t.Fatalf("read 2: %v (%q)", err, string(buf[:]))
	}
	_ = conn2.Close()

	if got := accepts.Load(); got != 3 {
		t.Fatalf("expected cached ECH bypass to use only 1 accept on second connection (total 3), got %d", got)
	}
}

func TestDNSHTTPSResponseParser(t *testing.T) {
	wantECH := defaultCloudflareECHList()

	// Build a DNS response with 1 question and 1 HTTPS (Type 65) answer containing
	// SvcParam key 1 (alpn) and key 5 (ech).
	q, err := buildDNSHTTPSQuery("quiccfuk.holoonet.com")
	if err != nil {
		t.Fatalf("buildDNSHTTPSQuery: %v", err)
	}

	var resp bytes.Buffer
	// Header: ID from query, QR=1 (0x8180), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	resp.Write(q[:2])
	resp.Write([]byte{0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	// Copy question section
	resp.Write(q[12:])

	// Answer section: compressed name pointer 0xC00C, Type 65 (0x0041), Class IN (0x0001), TTL 300
	resp.Write([]byte{0xC0, 0x0C, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C})

	// RDATA: SvcPriority = 1, TargetName = "." (0x00), SvcParam key 1 (alpn) + SvcParam key 5 (ech)
	var rdata bytes.Buffer
	_ = binary.Write(&rdata, binary.BigEndian, uint16(1)) // SvcPriority = 1
	rdata.WriteByte(0x00)                                 // TargetName = "."
	// Key 1 (alpn): value "\x02h2"
	_ = binary.Write(&rdata, binary.BigEndian, uint16(1))
	_ = binary.Write(&rdata, binary.BigEndian, uint16(3))
	rdata.Write([]byte{0x02, 'h', '2'})
	// Key 5 (ech): value wantECH
	_ = binary.Write(&rdata, binary.BigEndian, uint16(svcParamECH))
	_ = binary.Write(&rdata, binary.BigEndian, uint16(len(wantECH)))
	rdata.Write(wantECH)

	_ = binary.Write(&resp, binary.BigEndian, uint16(rdata.Len()))
	resp.Write(rdata.Bytes())

	got := parseDNSHTTPSResponse(resp.Bytes())
	if !bytes.Equal(got, wantECH) {
		t.Fatalf("parseDNSHTTPSResponse got %x, want %x", got, wantECH)
	}
}
