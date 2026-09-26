package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// Transport decides what the link between the two servers looks like on the wire.
//
// This matters because of what the plain option reveals. PortBridge's own
// handshake is 49 bytes of signed random data, so a plain link opens with a burst
// matching no known protocol and then carries traffic unwrapped. Something that
// fits no recognised pattern is exactly what modern filtering looks for, so plain
// is the fastest option and also the easiest to pick out.
type Transport string

const (
	// TransportPlain is raw TCP: fastest, no disguise.
	TransportPlain Transport = "plain"

	// TransportTLS wraps the link in a real TLS session, so it looks like a
	// browser talking to an HTTPS site: a genuine ClientHello carrying a server
	// name, a certificate in reply, ALPN, the lot.
	TransportTLS Transport = "tls"

	// TransportWSS is TLS with an HTTP upgrade on top, which is what a CDN
	// expects. That lets the link be routed through a provider such as
	// Cloudflare, so the foreign server's own address never appears on it.
	TransportWSS Transport = "wss"
)

const (
	tlsHandshakeTimeout = 15 * time.Second
	defaultWSPath       = "/tunnel"
)

func validTransport(t Transport) bool {
	switch t {
	case TransportPlain, TransportTLS, TransportWSS:
		return true
	}
	return false
}

// alpnFor keeps the advertised protocols consistent with what the disguise
// claims to be. An HTTPS site offers these; anything else would be a giveaway.
func alpnFor(t Transport) []string {
	if t == TransportWSS {
		return []string{"http/1.1"}
	}
	return []string{"h2", "http/1.1"}
}

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

// ensureCert returns a certificate for serverName, generating a self-signed one
// at certPath/keyPath the first time and reusing it afterwards.
//
// Self-signed is enough here: the tunnel's shared secret is what proves
// identity, and TLS is used for camouflage rather than trust. Anyone who
// connects without the secret gets nothing regardless of the certificate.
func ensureCert(certPath, keyPath, serverName string) (tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, errors.New("certificate paths are required")
	}
	if fileExists(certPath) && fileExists(keyPath) {
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			return c, nil
		}
		// A damaged pair is replaced rather than becoming a permanent failure.
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	// A year, like an ordinary site certificate. Nothing checks the dates, but
	// an absurd lifetime would stand out to anyone who looked.
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// ---------------------------------------------------------------------------
// Wrapping a connection
// ---------------------------------------------------------------------------

// wrapDial turns a freshly dialled TCP connection into whatever the transport
// requires, from the point of view of the side that dialled.
func wrapDial(raw net.Conn, cfg *Config) (net.Conn, error) {
	switch cfg.Transport {
	case TransportPlain:
		return raw, nil

	case TransportTLS, TransportWSS:
		name := cfg.ServerName
		if name == "" {
			name, _, _ = net.SplitHostPort(cfg.TunnelAddr)
		}
		tc := tls.Client(raw, &tls.Config{
			ServerName: name,
			NextProtos: alpnFor(cfg.Transport),
			MinVersion: tls.VersionTLS12,
			// The certificate is not what proves identity here; the shared
			// secret is, and it is checked immediately after. Requiring a
			// publicly trusted certificate would mean needing a real domain and
			// a renewal process for no security gain. Verified against the
			// secret, a forged certificate gets an attacker nothing.
			InsecureSkipVerify: true,
		})
		if err := raw.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
			return nil, err
		}
		if err := tc.Handshake(); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("securing the link failed: %w", err)
		}
		if err := raw.SetDeadline(time.Time{}); err != nil {
			return nil, err
		}
		if cfg.Transport == TransportTLS {
			return tc, nil
		}
		return wsDial(tc, cfg)

	default:
		return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
	}
}

// wrapAccept is the same from the point of view of the side that accepted.
func wrapAccept(raw net.Conn, cfg *Config, cert *tls.Certificate) (net.Conn, error) {
	switch cfg.Transport {
	case TransportPlain:
		return raw, nil

	case TransportTLS, TransportWSS:
		if cert == nil {
			return nil, errors.New("no certificate loaded")
		}
		ts := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   alpnFor(cfg.Transport),
			MinVersion:   tls.VersionTLS12,
		})
		if err := raw.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
			return nil, err
		}
		if err := ts.Handshake(); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("securing the link failed: %w", err)
		}
		if err := raw.SetDeadline(time.Time{}); err != nil {
			return nil, err
		}
		if cfg.Transport == TransportTLS {
			return ts, nil
		}
		return wsAccept(ts, cfg)

	default:
		return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
	}
}

// Describe is what the startup log says about the disguise, in plain terms.
func describeTransport(cfg *Config) string {
	switch cfg.Transport {
	case TransportTLS:
		return fmt.Sprintf("disguised as an HTTPS site (%s)", cfg.effectiveServerName())
	case TransportWSS:
		if cfg.CDN {
			return fmt.Sprintf("disguised as a websocket over HTTPS (%s%s) and routed through a CDN, so this server's address never appears on it",
				cfg.effectiveServerName(), cfg.effectiveWSPath())
		}
		return fmt.Sprintf("disguised as a websocket over HTTPS (%s%s)",
			cfg.effectiveServerName(), cfg.effectiveWSPath())
	default:
		return "plain, no disguise"
	}
}
