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

	// TransportH2 wraps the link in HTTP/2 streaming frames over TLS, appearing
	// as an active HTTP/2 web connection.
	TransportH2 Transport = "h2"

	// TransportGRPC wraps the link in gRPC envelope streaming over HTTP/2,
	// enabling direct compatibility with Cloudflare gRPC proxying and evading DPI.
	TransportGRPC Transport = "grpc"
)

const (
	tlsHandshakeTimeout = 15 * time.Second
	defaultWSPath       = "/tunnel"

	// How many resumable sessions the dialling side remembers. One per link is
	// all that is ever needed, but a handful costs nothing and covers a fallback
	// route being used alongside the main one.
	tlsResumeCache = 32
)

func validTransport(t Transport) bool {
	switch t {
	case TransportPlain, TransportTLS, TransportWSS, TransportH2, TransportGRPC:
		return true
	}
	return false
}

// alpnFor keeps the advertised protocols consistent with what the disguise
// claims to be. An HTTPS site offers these; anything else would be a giveaway.
func alpnFor(t Transport) []string {
	switch t {
	case TransportWSS:
		return []string{"http/1.1"}
	case TransportH2, TransportGRPC:
		return []string{"h2"}
	default:
		return []string{"h2", "http/1.1"}
	}
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
// Preparing the disguise once, rather than per connection
// ---------------------------------------------------------------------------

// Why this exists
//
// A disguised link used to build its TLS settings from scratch for every
// connection, and that turned out to be the most expensive thing either server
// did. Measured on a real machine, the handshake accounted for more than half of
// all the processor time spent on a disguised tunnel, because a connection is
// spent on each user and a full handshake is paid to replace it.
//
// Settings built fresh each time cannot be improved on, for a reason that is
// easy to miss: resuming a session requires both ends to remember something
// between connections. The side that accepts issues a ticket under a key held in
// its settings, and the side that dials keeps the ticket in a cache held in
// its settings. Throw the settings away after every connection and there is
// nothing left to resume from, so every connection pays in full, for ever.
//
// Preparing them once gives the resumption that was always meant to happen: the
// certificate no longer has to be sent and checked, a signature no longer has to
// be made and verified, and a round trip disappears from the time a user waits.
// It is also the more ordinary thing to look like, since a browser resumes
// sessions constantly.

// prepareTLS builds the settings this tunnel will reuse for every connection.
// Safe to call once at startup, before anything dials or accepts; after that the
// prepared values are only read.
//
// cert is required only on the side that accepts, and is ignored elsewhere.
func (c *Config) prepareTLS(cert *tls.Certificate) {
	if c.Transport == TransportPlain {
		return
	}

	if cert != nil {
		c.tlsServer = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   alpnFor(c.Transport),
			MinVersion:   tls.VersionTLS12,
		}
	}

	if !c.Dials() {
		return
	}

	// One cache shared by every name, so a fallback route does not start from
	// nothing.
	cache := tls.NewLRUClientSessionCache(tlsResumeCache)
	c.tlsClients = make(map[string]*tls.Config, 2)
	for _, name := range c.claimedNames() {
		c.tlsClients[name] = newClientTLS(name, c.Transport, cache)
	}
}

// claimedNames is every hostname this side may present, which is the main one
// and, where a fallback route names itself differently, that one too.
func (c *Config) claimedNames() []string {
	names := []string{c.effectiveClientName()}
	if c.AltServerName != "" && c.AltServerName != names[0] {
		names = append(names, c.AltServerName)
	}
	return names
}

// effectiveClientName is the name the dialling side puts in the handshake.
func (c *Config) effectiveClientName() string {
	if c.ServerName != "" {
		return c.ServerName
	}
	host, _, _ := net.SplitHostPort(c.TunnelAddr)
	return host
}

func newClientTLS(name string, t Transport, cache tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		ServerName:         name,
		NextProtos:         alpnFor(t),
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: cache,
		// The certificate is not what proves identity here; the shared secret
		// is, and it is checked immediately after. Requiring a publicly trusted
		// certificate would mean needing a real domain and a renewal process for
		// no security gain. Verified against the secret, a forged certificate
		// gets an attacker nothing.
		InsecureSkipVerify: true,
	}
}

// clientTLS returns the prepared settings for a name, building throwaway ones if
// this configuration was never prepared. The fallback keeps the function total
// for callers that build a Config by hand; it simply forgoes resumption.
func (c *Config) clientTLS(name string) *tls.Config {
	if cfg, ok := c.tlsClients[name]; ok {
		return cfg
	}
	return newClientTLS(name, c.Transport, nil)
}

// serverTLS returns the prepared settings for the accepting side.
func (c *Config) serverTLS(cert *tls.Certificate) (*tls.Config, error) {
	if c.tlsServer != nil {
		return c.tlsServer, nil
	}
	if cert == nil {
		return nil, errors.New("no certificate loaded")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   alpnFor(c.Transport),
		MinVersion:   tls.VersionTLS12,
	}, nil
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

	case TransportTLS, TransportWSS, TransportH2, TransportGRPC:
		tc := tls.Client(raw, cfg.clientTLS(cfg.effectiveClientName()))
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
		if cfg.Transport == TransportWSS {
			return wsDial(tc, cfg)
		}
		return h2Dial(tc, cfg)

	default:
		return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
	}
}

// wrapAccept is the same from the point of view of the side that accepted.
func wrapAccept(raw net.Conn, cfg *Config, cert *tls.Certificate) (net.Conn, error) {
	switch cfg.Transport {
	case TransportPlain:
		return raw, nil

	case TransportTLS, TransportWSS, TransportH2, TransportGRPC:
		serverCfg, err := cfg.serverTLS(cert)
		if err != nil {
			return nil, err
		}
		ts := tls.Server(raw, serverCfg)
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
		if cfg.Transport == TransportWSS {
			return wsAccept(ts, cfg)
		}
		return h2Accept(ts, cfg)

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
	case TransportH2:
		if cfg.CDN {
			return fmt.Sprintf("disguised as HTTP/2 (%s%s) and routed through a CDN, so this server's address never appears on it",
				cfg.effectiveServerName(), cfg.effectiveWSPath())
		}
		return fmt.Sprintf("disguised as HTTP/2 (%s)", cfg.effectiveServerName())
	case TransportGRPC:
		if cfg.CDN {
			return fmt.Sprintf("disguised as gRPC over HTTP/2 (%s) and routed through a CDN, so this server's address never appears on it",
				cfg.effectiveServerName())
		}
		return fmt.Sprintf("disguised as gRPC over HTTP/2 (%s)", cfg.effectiveServerName())
	default:
		return "plain, no disguise"
	}
}
