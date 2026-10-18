// Package panel is PortBridge's web panel.
//
// It is the same program as everything else, run as "portbridge panel run" by its
// own service on one server. It serves one page and a small API behind a login,
// over HTTPS, and shows every server it manages and the tunnels between them.
// It reaches each server's management agent at the agent's own port, or, for a
// server it cannot reach, the agent calls in on the panel's port (see hub.go).
package panel

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

//go:embed web
var webFS embed.FS

const defaultTunnelsDir = "/etc/portbridge/tunnels"

// Panel is one running panel.
type Panel struct {
	dir        string
	cfg        Config
	store      *store
	sessions   *sessions
	hub        *hub
	fleet      *fleet
	tunnelsDir string

	jobsMu sync.Mutex
	jobs   map[string]*job

	// Tokens of servers being added that have been asked to call the panel,
	// so the hub lets them in before they are saved.
	pendingMu sync.Mutex
	pending   map[string]string

	selfCert tls.Certificate
	selfFP   string
	certs    *certs // nil without a domain

	// Each password check takes a fair amount of memory on purpose, so only a
	// couple run at once, however many logins arrive together.
	loginSem chan struct{}

	// The panel's own server is managed through the agent's code, run here
	// in-process, so it is handled exactly like every other server.
	local      http.Handler
	localToken string

	updates *updater
	healer  *autoHealer
}

func newPanel(dir string, cfg Config, st *store) *Panel {
	p := &Panel{
		dir:        dir,
		cfg:        cfg,
		store:      st,
		sessions:   newSessions(),
		tunnelsDir: defaultTunnelsDir,
		jobs:       map[string]*job{},
		pending:    map[string]string{},
		loginSem:   make(chan struct{}, 2),
	}
	p.hub = newHub(p.hubTokens)
	p.fleet = newFleet(p)
	p.setLocal(defaultTunnelsDir)
	p.updates = newUpdater(p)
	p.healer = newAutoHealer(p)
	return p
}

// setLocal points the panel at the tunnels folder of its own server.
func (p *Panel) setLocal(tunnelsDir string) {
	p.tunnelsDir = tunnelsDir
	p.localToken = randomToken()
	// The panel runs as root on its own server, so it may update it.
	p.local = agent.NewHandler(p.localToken, tunnelsDir, func() bool { return true })
}

// loadSelfCert makes the panel's own certificate the first time and loads it
// after that. It is kept for good: servers that call the panel know it by it.
func (p *Panel) loadSelfCert() error {
	certDir := filepath.Join(p.dir, "cert")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	c, err := engine.EnsureCert(filepath.Join(certDir, "panel.crt"), filepath.Join(certDir, "panel.key"), "portbridge-panel")
	if err != nil {
		return err
	}
	if len(c.Certificate) == 0 {
		return errors.New("the panel's certificate is empty")
	}
	p.selfCert = c
	p.selfFP = fingerprintOf(c.Certificate[0])
	return nil
}

func (p *Panel) ownFingerprint() string { return p.selfFP }

func (p *Panel) addPending(id, token string) {
	p.pendingMu.Lock()
	p.pending[id] = token
	p.pendingMu.Unlock()
}

func (p *Panel) dropPending(id string) {
	p.pendingMu.Lock()
	delete(p.pending, id)
	p.pendingMu.Unlock()
}

// hubTokens is the token of every server allowed to call the panel.
func (p *Panel) hubTokens() map[string]string {
	out := map[string]string{}
	for _, s := range p.store.get().Servers {
		if !s.CallsPanel && !s.StandbyHub {
			continue
		}
		if t, err := p.store.open(s.TokenEnc); err == nil {
			out[s.ID] = t
		}
	}
	p.pendingMu.Lock()
	for id, t := range p.pending {
		out[id] = t
	}
	p.pendingMu.Unlock()
	return out
}

// publicURL is the address servers that call the panel are given.
func (p *Panel) publicURL() string { return publicURLFor(p.cfg) }

// allCallbackURLs returns comma-separated callback URLs (domain, IPv4, IPv6)
// that remote agents can use to reach this panel on /hub/poll.
func (p *Panel) allCallbackURLs() string {
	var list []string
	seen := map[string]bool{}
	add := func(u string) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u != "" && !seen[u] {
			seen[u] = true
			list = append(list, u)
		}
	}
	if p.cfg.PublicURL != "" {
		add(p.cfg.PublicURL)
	}
	_, port, err := net.SplitHostPort(p.cfg.Listen)
	if err == nil && port != "" {
		if p.cfg.Domain != "" {
			add("https://" + net.JoinHostPort(p.cfg.Domain, port))
		}
		v4, v6 := agent.PublicAddresses()
		for _, ip := range v4 {
			add("https://" + net.JoinHostPort(ip, port))
		}
		for _, ip := range v6 {
			add("https://" + net.JoinHostPort(ip, port))
		}
	}
	return strings.Join(list, ",")
}

func publicURLFor(cfg Config) string {
	if cfg.PublicURL != "" {
		return cfg.PublicURL
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return ""
	}
	v4, v6 := agent.PublicAddresses()
	switch {
	case len(v4) > 0:
		return "https://" + net.JoinHostPort(v4[0], port)
	case len(v6) > 0:
		return "https://" + net.JoinHostPort(v6[0], port)
	}
	return ""
}

// addresses is every address the panel can be opened at, for people.
func (p *Panel) addresses() []string { return addressesFor(p.cfg) }

func addressesFor(cfg Config) []string {
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil
	}
	suffix := ":" + port
	if port == "443" {
		suffix = ""
	}
	var out []string
	if cfg.Domain != "" {
		out = append(out, "https://"+cfg.Domain+suffix)
	}
	if u := publicURLFor(cfg); u != "" {
		if pu, err := url.Parse(u); err == nil && !strings.EqualFold(pu.Hostname(), cfg.Domain) {
			out = append(out, u)
		}
	}
	return out
}

func (p *Panel) certStatus() certStatus {
	if p.certs == nil {
		return certStatus{Note: "no domain name is set, so the panel uses its own certificate"}
	}
	return p.certs.status()
}

// server is the panel's HTTPS server.
func (p *Panel) server() *http.Server {
	tc := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	if p.certs != nil {
		tc.NextProtos = append(tc.NextProtos, acme.ALPNProto)
	}
	return &http.Server{
		Handler:           p.routes(),
		TLSConfig:         tc,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// A server calling in waits up to HubPollWait for its next request.
		WriteTimeout:   agent.HubPollWait + 30*time.Second,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 32 * 1024,
		ErrorLog:       quietLogger(),
	}
}

// Run runs the panel kept in dir until it is told to stop.
func Run(dir string) error {
	cfg, err := readConfig(dir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("the panel is not set up yet; set it up with: portbridge-menu -> Web panel")
	}
	if err != nil {
		return err
	}
	st, err := openStore(dir)
	if err != nil {
		return err
	}
	if st.get().Admin.Hash == "" {
		return errors.New("the panel has no login yet; set it up with: portbridge-menu -> Web panel")
	}
	p := newPanel(dir, cfg, st)
	if err := p.loadSelfCert(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go p.fleet.run(ctx)
	go p.updates.run(ctx)
	go p.healer.run(ctx)
	// An update that restarted the panel carries on from where it was.
	p.updates.resume()
	if cfg.Domain != "" {
		p.certs = newCerts(dir, cfg)
		go p.certs.run(ctx)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv := p.server()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			_ = srv.Close()
		}
	}()
	logf("PortBridge web panel %s on %s, certificate fingerprint %s", engine.Version, cfg.Listen, p.selfFP)
	for _, a := range p.addresses() {
		logf("open it at %s", a)
	}
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// quietLogger drops the HTTP server's notes about failed handshakes, which every
// scanner on the internet causes, so the journal keeps what matters.
func quietLogger() *log.Logger { return log.New(quietWriter{}, "", 0) }

type quietWriter struct{}

func (quietWriter) Write(b []byte) (int, error) {
	s := string(b)
	if strings.Contains(s, "TLS handshake error") || strings.Contains(s, "http2: server") {
		return len(b), nil
	}
	log.Print("[panel] " + strings.TrimRight(s, "\n"))
	return len(b), nil
}
