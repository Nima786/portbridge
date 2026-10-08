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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
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

	// TransportKCP wraps the link in encrypted KCP over UDP with Reed-Solomon Forward Error Correction.
	TransportKCP Transport = "kcp"
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
	case TransportPlain, TransportTLS, TransportWSS, TransportH2, TransportGRPC, TransportKCP:
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
		return []string{"h2", "http/1.1"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

// shapeUTLSHello builds the browser-style hello and makes it consistent with the
// transport: the protocols it offers are the ones the disguise claims, and the
// HTTP/2-only settings extension is dropped when HTTP/2 is not offered, since a
// browser that does not offer h2 does not send it.
func shapeUTLSHello(u *utls.UConn, t Transport) error {
	if err := u.BuildHandshakeState(); err != nil {
		return fmt.Errorf("preparing the browser-style hello failed: %w", err)
	}
	alpn := alpnFor(t)
	offersH2 := false
	for _, p := range alpn {
		if p == "h2" {
			offersH2 = true
		}
	}
	kept := u.Extensions[:0]
	for _, ext := range u.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = alpn
		case *utls.ApplicationSettingsExtension:
			if !offersH2 {
				continue
			}
		}
		kept = append(kept, ext)
	}
	u.Extensions = kept
	if err := u.MarshalClientHello(); err != nil {
		return fmt.Errorf("preparing the browser-style hello failed: %w", err)
	}
	return nil
}

// checkNegotiated makes sure the far end agreed to the protocol the disguise
// needs. An HTTP/2 transport that was negotiated down to HTTP/1.1 would fail
// later with a confusing framing error; this says what actually happened.
func checkNegotiated(proto string, t Transport) error {
	switch t {
	case TransportH2, TransportGRPC:
		if proto != "h2" {
			return fmt.Errorf("the far end did not agree to HTTP/2 (it chose %q); "+
				"an h2 or grpc tunnel needs a server or CDN that allows HTTP/2", proto)
		}
	case TransportWSS:
		if proto == "h2" {
			return errors.New("the far end chose HTTP/2 for a websocket tunnel, which needs HTTP/1.1")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ClientHello Fragmentation
// ---------------------------------------------------------------------------

// fragmentSkipLog reports, at most occasionally, that fragmentation was asked
// for and did not happen.
var fragmentSkipLog = newThrottled()

// fragmentConn wraps a raw net.Conn and fragments the very first Write()
// if it contains a TLS ClientHello (0x16 0x03).
//
// By splitting the TLS ClientHello record across two TCP segments with a brief
// micro-pause, DPI middleboxes doing shallow inspection see no SNI in the first
// packet and raw un-headered data in the second packet, allowing the connection
// to bypass censorship filters while being fully reassembled by the destination.
type fragmentConn struct {
	net.Conn
	firstWrite   sync.Once
	sawFirst     atomic.Bool
	fragmented   atomic.Bool
	fragmentSize int
	delay        time.Duration
}

func newFragmentConn(c net.Conn, size int, delay time.Duration) net.Conn {
	if size <= 0 {
		size = 40
	}
	if delay <= 0 {
		delay = 3 * time.Millisecond
	}
	return &fragmentConn{
		Conn:         c,
		fragmentSize: size,
		delay:        delay,
	}
}

func (fc *fragmentConn) Write(b []byte) (int, error) {
	var writeErr error
	var totalWritten int

	fc.firstWrite.Do(func() {
		// Only fragment if this looks like a TLS handshake record (0x16 0x03)
		// and has enough bytes to split meaningfully.
		if len(b) > fc.fragmentSize && b[0] == 0x16 && b[1] == 0x03 {
			split := fc.fragmentSize
			fc.fragmented.Store(true)
			n1, err := fc.Conn.Write(b[:split])
			totalWritten += n1
			if err != nil {
				writeErr = err
				return
			}
			if fc.delay > 0 {
				time.Sleep(fc.delay)
			}
			n2, err := fc.Conn.Write(b[split:])
			totalWritten += n2
			if err != nil {
				writeErr = err
				return
			}
		}
	})

	if totalWritten > 0 || writeErr != nil {
		return totalWritten, writeErr
	}
	if !fc.sawFirst.Swap(true) && !fc.fragmented.Load() {
		// Fragmentation is a setting someone turned on, and sending the hello
		// whole without a word would look exactly like it working.
		fragmentSkipLog.printf("ClientHello fragmentation is on but the first write was not a TLS hello " +
			"large enough to split; it was sent whole")
	}
	return fc.Conn.Write(b)
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
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

	// Also when only a backup route goes through a CDN: that route turns the
	// browser-style hello on for itself, and should have its settings ready.
	if c.useUTLS() || (c.hasCDNRoute() && !c.utlsSet) {
		c.utlsCache = utls.NewLRUClientSessionCache(tlsResumeCache)
		c.utlsClients = make(map[string]*utls.Config, 2)
		for _, name := range c.claimedNames() {
			c.utlsClients[name] = newClientUTLS(name, c.Transport, c.utlsCache)
		}
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

func newClientUTLS(name string, t Transport, cache utls.ClientSessionCache) *utls.Config {
	return &utls.Config{
		ServerName:         name,
		NextProtos:         alpnFor(t),
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
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

func (c *Config) clientUTLS(name string) *utls.Config {
	if cfg, ok := c.utlsClients[name]; ok {
		return cfg
	}
	return newClientUTLS(name, c.Transport, c.utlsCache)
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
	return wrapDialPurpose(raw, cfg, authPurposeTunnel)
}

// wrapDialPurpose is wrapDial for a caller that knows what the connection is
// for. The purpose only matters to the websocket disguise, which authenticates
// inside the upgrade request and so has to say it there.
func wrapDialPurpose(raw net.Conn, cfg *Config, purpose byte) (net.Conn, error) {
	switch cfg.Transport {
	case TransportPlain, TransportKCP:
		if cfg.Transport == TransportPlain && cfg.HTTPHeader {
			if err := httpHeaderDial(raw, cfg.HTTPHost); err != nil {
				_ = raw.Close()
				return nil, err
			}
		}
		return raw, nil

	case TransportTLS, TransportWSS, TransportH2, TransportGRPC:
		connToWrap := raw
		if cfg.useFragment() {
			size := cfg.TLSFragmentSize
			if size <= 0 {
				size = 40
			}
			sleep := cfg.TLSFragmentSleep
			if sleep <= 0 {
				sleep = 3 * time.Millisecond
			}
			connToWrap = newFragmentConn(raw, size, sleep)
		}

		if cfg.useUTLS() {
			// A copy for this connection. Building the hello changes the
			// settings it is given, and the prepared ones are shared by every
			// connection made at once; the copy keeps the shared session cache.
			uClient := utls.UClient(connToWrap, cfg.clientUTLS(cfg.effectiveClientName()).Clone(), cfg.utlsHelloID())
			// A hello that could not be built must stop the dial. Carrying on
			// with the library's default would send something other than what
			// was asked for, without saying so.
			if err := shapeUTLSHello(uClient, cfg.Transport); err != nil {
				_ = raw.Close()
				return nil, err
			}
			if err := raw.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
				return nil, err
			}
			if err := uClient.Handshake(); err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("securing the link with uTLS failed: %w", err)
			}
			if err := raw.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
			if err := checkNegotiated(uClient.ConnectionState().NegotiatedProtocol, cfg.Transport); err != nil {
				_ = raw.Close()
				return nil, err
			}
			if cfg.Transport == TransportTLS {
				return uClient, nil
			}
			if cfg.Transport == TransportWSS {
				return wsDialPurpose(uClient, cfg, purpose)
			}
			return h2Dial(uClient, cfg)
		}

		tc := tls.Client(connToWrap, cfg.clientTLS(cfg.effectiveClientName()))
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
		if err := checkNegotiated(tc.ConnectionState().NegotiatedProtocol, cfg.Transport); err != nil {
			_ = raw.Close()
			return nil, err
		}
		if cfg.Transport == TransportTLS {
			return tc, nil
		}
		if cfg.Transport == TransportWSS {
			return wsDialPurpose(tc, cfg, purpose)
		}
		return h2Dial(tc, cfg)

	default:
		return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
	}
}

// wrapAccept is the same from the point of view of the side that accepted.
func wrapAccept(raw net.Conn, cfg *Config, cert *tls.Certificate, guard ...*replayGuard) (net.Conn, error) {
	switch cfg.Transport {
	case TransportPlain, TransportKCP:
		if cfg.Transport == TransportPlain && cfg.HTTPHeader {
			if err := httpHeaderAccept(raw); err != nil {
				_ = raw.Close()
				return nil, err
			}
		}
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
			var g *replayGuard
			if len(guard) > 0 {
				g = guard[0]
			}
			return wsAccept(ts, cfg, g)
		}
		return h2Accept(ts, cfg)

	default:
		return nil, fmt.Errorf("unknown transport %q", cfg.Transport)
	}
}

// Describe is what the startup log says about the disguise, in plain terms.
func describeTransport(cfg *Config) string {
	base := ""
	switch cfg.Transport {
	case TransportTLS:
		base = fmt.Sprintf("disguised as an HTTPS site (%s)", cfg.effectiveServerName())
	case TransportWSS:
		if cfg.CDN {
			base = fmt.Sprintf("disguised as a websocket over HTTPS (%s%s) and routed through a CDN, so this server's address never appears on it",
				cfg.effectiveServerName(), cfg.effectiveWSPath())
		} else {
			base = fmt.Sprintf("disguised as a websocket over HTTPS (%s%s)",
				cfg.effectiveServerName(), cfg.effectiveWSPath())
		}
	case TransportH2:
		if cfg.CDN {
			base = fmt.Sprintf("disguised as HTTP/2 (%s%s) and routed through a CDN, so this server's address never appears on it",
				cfg.effectiveServerName(), cfg.effectiveWSPath())
		} else {
			base = fmt.Sprintf("disguised as HTTP/2 (%s)", cfg.effectiveServerName())
		}
	case TransportGRPC:
		if cfg.CDN {
			base = fmt.Sprintf("disguised as gRPC over HTTP/2 (%s) and routed through a CDN, so this server's address never appears on it",
				cfg.effectiveServerName())
		} else {
			base = fmt.Sprintf("disguised as gRPC over HTTP/2 (%s)", cfg.effectiveServerName())
		}
	case TransportKCP:
		return fmt.Sprintf("loss-resistant KCP/UDP transport with FEC (%d/%d shards)", cfg.KCPDataShards, cfg.KCPParityShards)
	default:
		if cfg.GRE {
			return "plain, carried over a private GRE link between the two servers (not encrypted)"
		}
		if cfg.HTTPHeader {
			host := cfg.HTTPHost
			if host == "" {
				host = defaultHTTPHost
			}
			return fmt.Sprintf("plain, opening like web traffic to %s (not encrypted)", host)
		}
		return "plain, no disguise"
	}

	if cfg.Dials() {
		var stealth []string
		backupOnly := !cfg.CDN && cfg.AltServerName != ""
		suffix := ""
		if backupOnly {
			suffix = " on the backup route"
		}
		if cfg.useUTLS() || (backupOnly && !cfg.utlsSet) {
			stealth = append(stealth, "uTLS browser hello"+suffix)
		}
		if cfg.useFragment() || (backupOnly && !cfg.fragmentSet) {
			stealth = append(stealth, "ClientHello fragmentation"+suffix)
		}
		if len(cfg.CleanIPs) > 0 {
			stealth = append(stealth, fmt.Sprintf("%d clean CF IPs", len(cfg.CleanIPs)))
		}
		if len(stealth) > 0 {
			base += fmt.Sprintf(" [%s]", strings.Join(stealth, ", "))
		}
	}
	return base
}
