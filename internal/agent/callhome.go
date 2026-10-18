package agent

// Calling the panel, for servers the panel cannot reach.
//
// An Iranian server is often unreachable from abroad, so a panel there cannot
// call its agent. Instead the agent calls the panel and keeps asking it, over
// ordinary HTTPS, whether there is anything to do. The panel answers with a
// request (the same kind it would otherwise have sent to the agent's own port),
// the agent runs it through its own handler and posts back the answer. Nothing
// needs to be able to reach the agent at all.
//
// The agent proves who it is with its own token, and checks the panel is the
// panel by the fingerprint it was given when it was set up, or by the panel's
// certificate when it has a real one.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

// HubRequest is one request the panel hands to an agent that is calling it.
type HubRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body,omitempty"`
}

// HubReply is the agent's answer to a HubRequest.
type HubReply struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
	Body   []byte `json:"body,omitempty"`
}

// The panel holds each poll open for up to this long when it has nothing to ask.
const (
	HubPollWait = 25 * time.Second
	// hubAnswerWait is how long a poll waits for the panel to start answering:
	// a connection that has gone silently dead, as they do in a shutdown, is
	// given up on after this. Once the answer has started it may take far
	// longer (transferTime), since it can carry a whole release.
	hubAnswerWait = HubPollWait + 20*time.Second
	hubBackoffMin = 2 * time.Second
	hubBackoffMax = time.Minute
	// HubBodyLimit is the most one request or answer through the hub may be:
	// room for a release, base64-encoded, and a little more.
	HubBodyLimit = MaxReleaseSize*4/3 + 1<<20
)

// NewPinnedClient is an HTTPS client that trusts exactly one certificate, by its
// fingerprint, or the usual certificate authorities when no fingerprint is given.
func NewPinnedClient(fingerprint, targetURL string, timeout time.Duration) *http.Client {
	if fingerprint == "" {
		return &http.Client{Timeout: timeout, Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		}}
	}
	c := makeAgentHTTPClient(agentTrust{Fingerprint: fingerprint}, targetURL)
	c.Timeout = timeout
	return c
}

// panelClient is the client an agent calls the panel with. It trusts the panel's
// own certificate, by the fingerprint it was given, and, when the panel is reached
// by name rather than by address, also a certificate a public authority issued
// for that name: the real one the panel gets for its domain, or a CDN's in front
// of it. Either is proof enough that it is the panel.
func panelClient(fingerprint, panelURL string, timeout time.Duration) *http.Client {
	if fingerprint == "" {
		return NewPinnedClient("", panelURL, timeout)
	}
	host := ""
	if u, err := url.Parse(panelURL); err == nil {
		host = u.Hostname()
	}
	byName := host != "" && net.ParseIP(host) == nil
	want := normalizeFingerprint(fingerprint)
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The usual check is replaced, not dropped: see VerifyPeerCertificate.
		InsecureSkipVerify: true,
		ServerName:         agentSNI(panelURL),
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the panel sent no certificate")
			}
			if normalizeFingerprint(fingerprintOf(raw[0])) == want {
				return nil
			}
			if byName {
				if verifyChainFor(raw, host) == nil {
					return nil
				}
				return fmt.Errorf("the panel's certificate is neither the one it had when this server was added "+
					"nor one issued for %s; this could be the wrong server or someone in between", host)
			}
			return errors.New("the panel's certificate is not the one it had when this server was added; " +
				"this could be the wrong server or someone in between")
		},
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tc}}
}

// verifyChainFor checks a certificate chain the ordinary way, against the system's
// certificate authorities, for the given name.
func verifyChainFor(raw [][]byte, host string) error {
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return err
}

var (
	callHomeMu     sync.Mutex
	callHomeCancel context.CancelFunc
	callHomeSpec   string
)

// configureCallHome persists panel_url / panel_fingerprint (when on the real
// system) and starts or updates the in-process callHome loop immediately without
// needing to restart the agent service.
func configureCallHome(panelURL, fingerprint, token, confDir string, h http.Handler) error {
	panelURL = strings.TrimSpace(panelURL)
	fingerprint = strings.TrimSpace(fingerprint)

	if confDir == "" || confDir == defaultTunnelsDir {
		if ac, err := readAgentConfig(defaultAgentConf); err == nil {
			if panelURL == "" || panelURL == "off" {
				ac.PanelURL = ""
				ac.PanelFingerprint = ""
			} else {
				ac.PanelURL = panelURL
				ac.PanelFingerprint = fingerprint
			}
			_ = writeAgentConfig(defaultAgentConf, ac)
		}
	}

	callHomeMu.Lock()
	defer callHomeMu.Unlock()
	spec := panelURL + "|" + fingerprint
	if panelURL == "" || panelURL == "off" {
		if callHomeCancel != nil {
			callHomeCancel()
			callHomeCancel = nil
		}
		callHomeSpec = ""
		return nil
	}
	if callHomeSpec == spec && callHomeCancel != nil {
		return nil
	}
	if callHomeCancel != nil {
		callHomeCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	callHomeCancel = cancel
	callHomeSpec = spec
	go callHome(ctx, panelURL, fingerprint, token, h)
	return nil
}

// CallHome is callHome, for the panel's tests.
func CallHome(ctx context.Context, panelURL, fingerprint, token string, h http.Handler) {
	callHome(ctx, panelURL, fingerprint, token, h)
}

func splitPanelURLs(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// callHome keeps asking the panel for work until ctx ends. When given multiple
// comma-separated URLs (e.g. domain, IPv4, IPv6), it rotates across them on
// failure and stays pinned to whichever URL is currently answering.
func callHome(ctx context.Context, panelURL, fingerprint, token string, h http.Handler) {
	urls := splitPanelURLs(panelURL)
	if len(urls) == 0 {
		return
	}
	clients := make([]*http.Client, len(urls))
	for i, u := range urls {
		c := panelClient(fingerprint, u, 0)
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.ResponseHeaderTimeout = hubAnswerWait
		}
		clients[i] = c
	}
	logs := newCallHomeLog()
	backoff := time.Duration(0)
	idx := 0
	log.Printf("[agent] calling the panel at %s", strings.Join(urls, ", "))
	for ctx.Err() == nil {
		curURL := urls[idx]
		curClient := clients[idx]
		req, err := hubPoll(ctx, curClient, curURL, token)
		if err != nil {
			// If another callback URL is available, try it next before backing off long.
			idx = (idx + 1) % len(urls)
			if idx != 0 {
				continue
			}
			if backoff == 0 {
				backoff = hubBackoffMin
			} else if backoff *= 2; backoff > hubBackoffMax {
				backoff = hubBackoffMax
			}
			logs.failed(err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		if backoff != 0 {
			log.Printf("[agent] reaching the panel again at %s", curURL)
		}
		backoff = 0
		if req == nil {
			continue // nothing to do this time
		}
		go func(r HubRequest, c *http.Client, u string) {
			rep := runHubRequest(r, token, h)
			if err := hubReply(ctx, c, u, token, rep); err != nil {
				log.Printf("[agent] could not give the panel its answer: %v", err)
			}
		}(*req, curClient, curURL)
	}
}

// hubPoll asks once. It returns nil, nil when the panel had nothing to ask.
func hubPoll(ctx context.Context, client *http.Client, panelURL, token string) (*HubRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, panelURL+"/hub/poll", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-PortBridge-Version", engine.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var r HubRequest
		if err := json.NewDecoder(io.LimitReader(resp.Body, HubBodyLimit)).Decode(&r); err != nil {
			return nil, fmt.Errorf("the panel sent something that is not a request: %w", err)
		}
		return &r, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, errors.New("the panel does not recognise this agent's token; add the server to the panel again")
	default:
		return nil, fmt.Errorf("the panel answered HTTP %d", resp.StatusCode)
	}
}

// runHubRequest runs a request through the agent's own handler, exactly as if it
// had arrived on the agent's port with the agent's token.
func runHubRequest(r HubRequest, token string, h http.Handler) HubReply {
	if !strings.HasPrefix(r.Path, "/api/") {
		return HubReply{ID: r.ID, Status: http.StatusNotFound, Body: []byte(`{"error":"not found"}`)}
	}
	req, err := http.NewRequest(r.Method, "https://agent"+r.Path, bytes.NewReader(r.Body))
	if err != nil {
		return HubReply{ID: r.ID, Status: http.StatusBadRequest, Body: []byte(`{"error":"bad request"}`)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(r.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return HubReply{ID: r.ID, Status: rec.Code, Body: rec.Body.Bytes()}
}

func hubReply(ctx context.Context, client *http.Client, panelURL, token string, rep HubReply) error {
	body, _ := json.Marshal(rep)
	// An answer can carry a release downloaded for the panel.
	ctx, cancel := context.WithTimeout(ctx, transferTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, panelURL+"/hub/reply", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the panel answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// callHomeLog says when the panel cannot be reached, once, and again only if the
// reason changes, so a long outage does not fill the journal.
type callHomeLog struct{ last string }

func newCallHomeLog() *callHomeLog { return &callHomeLog{} }

func (l *callHomeLog) failed(err error, retry time.Duration) {
	msg := err.Error()
	var uerr x509.UnknownAuthorityError
	if errors.As(err, &uerr) {
		msg = "the panel's certificate is not trusted; add the server to the panel again"
	}
	if msg != l.last {
		log.Printf("[agent] cannot reach the panel: %s (trying again, at most every %s)", msg, retry)
		l.last = msg
	}
}
