package panel

// The panel's certificates.
//
// The panel always has a certificate it made itself. Servers that call the panel
// check that one by its fingerprint, and a browser can be told to accept it after
// comparing the same fingerprint by eye.
//
// When a domain name is set, the panel also gets a real certificate for it from
// Let's Encrypt and shows it to anyone who asks for the panel by that name, which
// is what a browser does, so there is no warning. It is renewed automatically
// well before it runs out, whatever the certificates' lifetime is at the time
// (Let's Encrypt is shortening it in steps, to 45 days by 2028).
//
// Let's Encrypt checks the domain belongs to this server by calling it back on
// port 80, or on 443 if the panel itself is on 443. The panel answers on port 80
// only when nothing else uses it, and only for those checks. If a certificate
// cannot be got, the panel keeps working with its own one and says why.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	certRetryMin       = 10 * time.Minute
	certRetryMax       = 6 * time.Hour
	certRecheck        = 12 * time.Hour
	letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// certs gets and renews the real certificate for the panel's domain.
type certs struct {
	domain    string
	m         *autocert.Manager
	onPort443 bool

	mu       sync.Mutex
	have     bool
	notAfter time.Time
	issuer   string
	lastErr  string
	backoff  time.Duration
	port80   bool
}

func newCerts(dir string, cfg Config) *certs {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(dir, "acme")),
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.Email,
	}
	switch cfg.ACMEDirectory {
	case "":
	case "staging":
		m.Client = &acme.Client{DirectoryURL: letsEncryptStaging}
	default:
		m.Client = &acme.Client{DirectoryURL: cfg.ACMEDirectory}
	}
	_, port, _ := net.SplitHostPort(cfg.Listen)
	return &certs{domain: cfg.Domain, m: m, onPort443: port == "443"}
}

// wants says whether a handshake asks for the panel by its domain name.
func (c *certs) wants(hello *tls.ClientHelloInfo) bool {
	return strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), c.domain)
}

func (c *certs) ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.have
}

// run gets the certificate, and keeps checking on it, until ctx ends. Renewal
// itself is done by the certificate manager, in the background, once it holds a
// certificate; looking again every few hours keeps what the panel reports fresh.
func (c *certs) run(ctx context.Context) {
	for {
		wait := certRecheck
		c.listenPort80(ctx)
		c.mu.Lock()
		canCheck := c.port80 || c.onPort443
		c.mu.Unlock()
		if !canCheck {
			c.failed(errors.New("port 80 is used by another program on this server, and Let's Encrypt checks " +
				"the domain on port 80 (or on 443, when the panel itself is on 443). Free port 80, or move the panel to port 443"))
			wait = certRetryMin
		} else if err := c.obtain(); err != nil {
			wait = c.failed(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// listenPort80 answers Let's Encrypt's checks on port 80, if the port is free.
func (c *certs) listenPort80(ctx context.Context) {
	c.mu.Lock()
	have := c.port80
	c.mu.Unlock()
	if have {
		return
	}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		return
	}
	// Anything that is not one of the checks gets "not found": port 80 is only
	// held for these, and gives nothing away about the panel.
	srv := &http.Server{
		Handler:           c.m.HTTPHandler(http.NotFoundHandler()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
		ErrorLog:          quietLogger(),
	}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	c.mu.Lock()
	c.port80 = true
	c.mu.Unlock()
}

// obtain asks for the certificate, which is quick once it is held.
func (c *certs) obtain() error {
	// Described as a modern browser would be, so the certificate got here is
	// the same kind (ECDSA) a browser is then given, not a second one.
	hello := &tls.ClientHelloInfo{
		ServerName:        c.domain,
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
	cert, err := c.m.GetCertificate(hello)
	if err != nil {
		return err
	}
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return err
		}
	}
	if leaf == nil {
		return errors.New("the certificate authority sent no certificate")
	}
	c.mu.Lock()
	c.have = true
	c.notAfter = leaf.NotAfter
	c.issuer = issuerName(leaf)
	c.lastErr = ""
	c.backoff = 0
	c.mu.Unlock()
	return nil
}

// failed records why there is no certificate, and says how long to wait before
// trying again. Each failure waits longer, so a domain that does not point here
// cannot run into Let's Encrypt's limits on failed attempts.
func (c *certs) failed(err error) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = plainCertError(err)
	if c.backoff == 0 {
		c.backoff = certRetryMin
	} else if c.backoff *= 2; c.backoff > certRetryMax {
		c.backoff = certRetryMax
	}
	logf("no certificate for %s yet: %s (trying again in %s)", c.domain, c.lastErr, c.backoff)
	return c.backoff
}

func plainCertError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "rateLimited"), strings.Contains(msg, "too many"):
		return "Let's Encrypt has had too many requests for this domain recently; the panel will try again later"
	case strings.Contains(msg, "NXDOMAIN"), strings.Contains(msg, "no valid A records"), strings.Contains(msg, "DNS problem"):
		return "the domain name does not point at this server yet (check its A record)"
	case strings.Contains(msg, "Connection refused"), strings.Contains(msg, "Timeout"), strings.Contains(msg, "connection"):
		return "Let's Encrypt could not reach this server to check the domain; port 80 may be blocked from outside, " +
			"or the domain may point somewhere else"
	}
	return msg
}

func issuerName(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.CommonName
}

// certStatus is what the panel says about its certificate.
type certStatus struct {
	Domain string `json:"domain,omitempty"`
	Real   bool   `json:"real"`
	Issuer string `json:"issuer,omitempty"`
	Until  string `json:"until,omitempty"`
	Note   string `json:"note,omitempty"`
}

func (c *certs) status() certStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := certStatus{Domain: c.domain, Real: c.have, Issuer: c.issuer}
	if c.have {
		s.Until = c.notAfter.UTC().Format(time.RFC3339)
	} else if c.lastErr != "" {
		s.Note = c.lastErr
	} else {
		s.Note = "getting it now"
	}
	return s
}

// getCertificate picks the certificate for a handshake: the real one for the
// domain once it is held, and the panel's own one for everything else.
func (p *Panel) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := p.certs; c != nil && c.wants(hello) {
		// Let's Encrypt checking the domain on port 443.
		if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
			return c.m.GetCertificate(hello)
		}
		if c.ready() {
			if cert, err := c.m.GetCertificate(hello); err == nil {
				return cert, nil
			}
		}
	}
	return &p.selfCert, nil
}

// cachedCert reads the real certificate the panel saved for its domain, if any,
// for "portbridge panel status", which runs apart from the panel itself.
func cachedCert(dir, domain string) *x509.Certificate {
	if domain == "" {
		return nil
	}
	for _, name := range []string{domain, domain + "+rsa"} {
		data, err := os.ReadFile(filepath.Join(dir, "acme", name))
		if err != nil {
			continue
		}
		for {
			var b *pem.Block
			b, data = pem.Decode(data)
			if b == nil {
				break
			}
			if b.Type == "CERTIFICATE" {
				if c, err := x509.ParseCertificate(b.Bytes); err == nil {
					return c
				}
				break
			}
		}
	}
	return nil
}

// fingerprintOf is the SHA-256 of a certificate, as lower-case hex with colons,
// the same form the agent prints its own in.
func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
