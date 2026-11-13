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
	dir         string
	cfgMu       sync.RWMutex
	cfg         Config
	runCtx      context.Context
	certsCancel context.CancelFunc
	store       *store
	sessions    *sessions
	hub         *hub
	fleet       *fleet
	tunnelsDir  string

	jobsMu sync.Mutex
	jobs   map[string]*job

	// Tokens of servers being added that have been asked to call the panel,
	// so the hub lets them in before they are saved.
	pendingMu sync.Mutex
	pending   map[string]string

	ticketsMu sync.Mutex
	tickets   map[string]*joinTicket

	selfCertMu sync.RWMutex
	selfCert   tls.Certificate
	selfFP     string
	certs      *certs // nil without a domain

	// Each password check takes a fair amount of memory on purpose, so only a
	// couple run at once, however many logins arrive together.
	loginSem chan struct{}

	// The panel's own server is managed through the agent's code, run here
	// in-process, so it is handled exactly like every other server.
	local      http.Handler
	localToken string

	updates  *updater
	healer   *autoHealer
	notifier *notifier
	traffic  *trafficTracker
}

func newPanel(dir string, cfg Config, st *store) *Panel {
	p := &Panel{
		dir:        dir,
		cfg:        cfg,
		store:      st,
		sessions:   newSessionsWithStore(st),
		tunnelsDir: defaultTunnelsDir,
		jobs:       map[string]*job{},
		pending:    map[string]string{},
		tickets:    map[string]*joinTicket{},
		loginSem:   make(chan struct{}, 2),
	}
	p.hub = newHub(p.hubTokens)
	p.fleet = newFleet(p)
	p.setLocal(defaultTunnelsDir)
	p.updates = newUpdater(p)
	p.healer = newAutoHealer(p)
	p.notifier = newNotifier(p)
	p.traffic = newTrafficTracker(p)
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
	p.selfCertMu.Lock()
	p.selfCert = c
	p.selfFP = fingerprintOf(c.Certificate[0])
	p.selfCertMu.Unlock()
	return nil
}

func (p *Panel) ownFingerprint() string {
	p.selfCertMu.RLock()
	defer p.selfCertMu.RUnlock()
	return p.selfFP
}

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

func (p *Panel) getConfig() Config {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.cfg
}

func (p *Panel) basePath() string {
	return p.getConfig().BasePath
}

func (p *Panel) activeCerts() *certs {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.certs
}

func (p *Panel) startCertManager(ctx context.Context) {
	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()
	p.runCtx = ctx
	if p.cfg.Domain != "" {
		cctx, cancel := context.WithCancel(ctx)
		p.certsCancel = cancel
		p.certs = newCerts(p.dir, p.cfg)
		go p.certs.run(cctx)
	}
}

// updateAccessSettings updates the panel's domain, certificate email, and/or
// secret login URL path live in memory and persists them to panel.conf without
// restarting the HTTPS server.
func (p *Panel) updateAccessSettings(domainRaw, emailRaw, basePathRaw string, retryCert bool) error {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainRaw)), ".")
	if strings.EqualFold(domain, "off") || strings.EqualFold(domain, "none") {
		domain = ""
	}
	if domain != "" && !validDomain(domain) {
		return errors.New("that does not look like a domain or subdomain (for example: panel.example.com)")
	}
	email := strings.TrimSpace(emailRaw)
	if strings.EqualFold(email, "off") || strings.EqualFold(email, "none") || domain == "" {
		email = ""
	}
	if email != "" && !validEmail(email) {
		return errors.New("that does not look like an email address")
	}
	bp, err := normalizeBasePath(basePathRaw)
	if err != nil {
		return err
	}

	p.cfgMu.Lock()
	next := p.cfg
	next.Domain = domain
	next.Email = email
	next.BasePath = bp
	if p.dir != "" {
		if err := writeConfig(p.dir, next); err != nil {
			p.cfgMu.Unlock()
			return err
		}
	}
	certChanged := next.Domain != p.cfg.Domain || next.Email != p.cfg.Email
	p.cfg = next

	var oldCerts *certs
	var oldCancel context.CancelFunc
	var startCerts *certs
	var startCtx context.Context
	var retryTarget *certs

	if certChanged {
		oldCerts = p.certs
		oldCancel = p.certsCancel
		p.certs = nil
		p.certsCancel = nil
		if next.Domain != "" {
			c := newCerts(p.dir, next)
			p.certs = c
			if p.runCtx != nil {
				cctx, cancel := context.WithCancel(p.runCtx)
				p.certsCancel = cancel
				startCerts = c
				startCtx = cctx
			}
		}
	} else if retryCert && p.certs != nil {
		retryTarget = p.certs
	}
	p.cfgMu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldCerts != nil {
		oldCerts.stopPort80()
	}
	if startCerts != nil {
		go startCerts.run(startCtx)
	}
	if retryTarget != nil {
		retryTarget.triggerRetry()
	}
	return nil
}

// publicURL is the address servers that call the panel are given.
func (p *Panel) publicURL() string { return publicURLFor(p.getConfig()) }

// allCallbackURLs returns comma-separated callback URLs (domain, IPv4, IPv6)
// that remote agents can use to reach this panel on /hub/poll.
func (p *Panel) allCallbackURLs() string {
	cfg := p.getConfig()
	var list []string
	seen := map[string]bool{}
	add := func(u string) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u != "" && !seen[u] {
			seen[u] = true
			list = append(list, u)
		}
	}
	if cfg.PublicURL != "" {
		add(cfg.PublicURL)
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err == nil && port != "" {
		if cfg.Domain != "" {
			add("https://" + net.JoinHostPort(cfg.Domain, port))
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
func (p *Panel) addresses() []string { return addressesFor(p.getConfig()) }

func addressesFor(cfg Config) []string {
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil
	}
	suffix := ":" + port
	if port == "443" {
		suffix = ""
	}
	pathSuffix := ""
	if cfg.BasePath != "" {
		pathSuffix = cfg.BasePath + "/"
	}
	var out []string
	if cfg.Domain != "" {
		out = append(out, "https://"+cfg.Domain+suffix+pathSuffix)
	}
	if u := publicURLFor(cfg); u != "" {
		if pu, err := url.Parse(u); err == nil && !strings.EqualFold(pu.Hostname(), cfg.Domain) {
			out = append(out, strings.TrimRight(u, "/")+pathSuffix)
		}
	}
	return out
}

func (p *Panel) certStatus() certStatus {
	c := p.activeCerts()
	if c == nil {
		return certStatus{Note: "no domain name is set, so the panel uses its own certificate"}
	}
	return c.status()
}

// server is the panel's HTTPS server.
func (p *Panel) server() *http.Server {
	tc := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.getCertificate,
		// Always advertise acme-tls/1 so adding a domain live in Panel Settings
		// on port 443 works immediately without restarting the service.
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
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
	go p.traffic.run(ctx)
	// An update that restarted the panel carries on from where it was.
	p.updates.resume()
	p.startCertManager(ctx)

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
