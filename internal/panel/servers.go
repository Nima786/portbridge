package panel

// Talking to the servers the panel manages, and keeping a fresh picture of each.
//
// A server is reached either at its agent's own port, with the agent's
// certificate pinned, or, if it calls the panel, through the hub. Each one is
// asked for its overview every little while in the background, so pages load at
// once from what was last heard instead of waiting on every server.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

const (
	refreshEvery  = 15 * time.Second
	agentTimeout  = 20 * time.Second
	overviewLimit = 4 << 20
)

// serverView is one server as the panel shows it.
type serverView struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Group      string          `json:"group"`
	Address    string          `json:"address"`
	This       bool            `json:"this"`
	CallsPanel bool            `json:"calls_panel"`
	Online     bool            `json:"online"`
	Problem    string          `json:"problem,omitempty"`
	LastSeen   string          `json:"last_seen,omitempty"`
	Overview   *agent.Overview `json:"overview,omitempty"`
}

type heard struct {
	overview   *agent.Overview
	err        error
	at         time.Time // last time it answered
	tried      time.Time
	seededHome bool
}

// fleet is every server, and what was last heard from each.
type fleet struct {
	p  *Panel
	mu sync.Mutex
	by map[string]*heard
}

func newFleet(p *Panel) *fleet { return &fleet{p: p, by: map[string]*heard{}} }

// call sends one request to a server's agent and returns its answer.
func (f *fleet) call(ctx context.Context, srv Server, method, path string, body []byte) (int, []byte, error) {
	return f.callLimit(ctx, srv, method, path, body, overviewLimit)
}

func agentURLPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return ""
	}
	return port
}

// callLimit is call for an answer that may be larger, such as a release.
// It tries every available control path so the panel can still manage a
// foreign server even when Iran -> Foreign IPv4 is blocked:
//  1. Direct IPv4/Primary URL (or Reverse Hub first if CallsPanel is set)
//  2. Direct IPv6 agent URLs (https://[<ipv6>]:<port>)
//  3. Reverse Hub (/hub/poll) if the server is calling in to the panel
func (f *fleet) callLimit(ctx context.Context, srv Server, method, path string, body []byte, limit int64) (int, []byte, error) {
	token, err := f.p.store.open(srv.TokenEnc)
	if err != nil {
		return 0, nil, err
	}

	tryDirectURL := func(baseURL string, maxWait time.Duration) (int, []byte, error) {
		rctx := ctx
		var cancel context.CancelFunc
		if maxWait > 0 {
			rctx, cancel = context.WithTimeout(ctx, maxWait)
			defer cancel()
		}
		req, err := http.NewRequestWithContext(rctx, method, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := agent.NewPinnedClient(srv.Fingerprint, baseURL, 10*time.Minute).Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		return resp.StatusCode, b, err
	}

	var v6URLs []string
	if port := agentURLPort(srv.AgentURL); port != "" {
		for _, ip := range srv.IPv6 {
			cand := "https://" + net.JoinHostPort(ip, port)
			if !strings.EqualFold(cand, strings.TrimRight(srv.AgentURL, "/")) {
				v6URLs = append(v6URLs, cand)
			}
		}
	}

	if srv.CallsPanel {
		status, b, herr := f.p.hub.do(ctx, srv.ID, method, path, body)
		if herr == nil || srv.AgentURL == "" {
			return status, b, herr
		}
		for _, u := range append([]string{srv.AgentURL}, v6URLs...) {
			if st, rb, derr := tryDirectURL(u, 6*time.Second); derr == nil {
				return st, rb, nil
			}
		}
		return status, b, herr
	}

	hasFallback := len(v6URLs) > 0 || f.p.hub.connected(srv.ID)
	var perTry time.Duration
	if hasFallback && method == http.MethodGet && limit <= overviewLimit {
		perTry = 6 * time.Second
	}

	status, b, derr := tryDirectURL(srv.AgentURL, perTry)
	if derr == nil {
		return status, b, nil
	}
	if strings.Contains(derr.Error(), "does not match the saved fingerprint") {
		return 0, nil, derr
	}

	for _, u := range v6URLs {
		st, rb, err6 := tryDirectURL(u, perTry)
		if err6 == nil {
			return st, rb, nil
		}
		if strings.Contains(err6.Error(), "does not match the saved fingerprint") {
			return 0, nil, err6
		}
	}

	if f.p.hub.connected(srv.ID) {
		if st, rb, herr := f.p.hub.do(ctx, srv.ID, method, path, body); herr == nil {
			return st, rb, nil
		}
	}

	return 0, nil, derr
}

// overview asks a server for its overview.
func (f *fleet) overview(ctx context.Context, srv Server) (*agent.Overview, error) {
	status, body, err := f.call(ctx, srv, http.MethodGet, "/api/overview", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("PortBridge on this server is too old for the panel; update it there")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("the server's agent no longer accepts the panel's token; add the server again")
	default:
		return nil, fmt.Errorf("the server's agent answered HTTP %d", status)
	}
	var ov agent.Overview
	if err := json.Unmarshal(body, &ov); err != nil {
		return nil, fmt.Errorf("the server's agent sent something unreadable: %w", err)
	}
	return &ov, nil
}

// refresh asks one server and remembers what it said.
func (f *fleet) refresh(srv Server) {
	ctx, cancel := context.WithTimeout(context.Background(), agentTimeout)
	defer cancel()
	ov, err := f.overview(ctx, srv)
	var needSeed bool
	f.mu.Lock()
	h := f.by[srv.ID]
	if h == nil {
		h = &heard{}
		f.by[srv.ID] = h
	}
	h.tried = time.Now()
	h.err = err
	if err == nil {
		h.overview = ov
		h.at = time.Now()
		if !h.seededHome {
			needSeed = true
		}
	}
	f.mu.Unlock()

	if err == nil && ov != nil {
		if len(ov.IPv6) > 0 && !slices.Equal(srv.IPv6, ov.IPv6) {
			_ = f.p.store.update(func(st *State) error {
				for i := range st.Servers {
					if st.Servers[i].ID == srv.ID {
						st.Servers[i].IPv6 = append([]string(nil), ov.IPv6...)
						break
					}
				}
				return nil
			})
		}
		if needSeed {
			f.seedCallHome(srv)
		}
	}
}

// seedCallHome registers the panel's callback URLs and certificate fingerprint
// with a remote server's agent so it maintains a standby reverse connection on
// /hub/poll in case direct IPv4 from Iran to Foreign is later blocked.
func (f *fleet) seedCallHome(srv Server) {
	cbURLs := f.p.allCallbackURLs()
	fp := f.p.ownFingerprint()
	if cbURLs == "" || fp == "" {
		return
	}
	if !srv.StandbyHub && !srv.CallsPanel {
		_ = f.p.store.update(func(st *State) error {
			for i := range st.Servers {
				if st.Servers[i].ID == srv.ID {
					st.Servers[i].StandbyHub = true
					srv.StandbyHub = true
					break
				}
			}
			return nil
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{
		"panel_url":         cbURLs,
		"panel_fingerprint": fp,
	})
	status, _, err := f.call(ctx, srv, http.MethodPost, "/api/callhome", body)
	if err == nil && (status == http.StatusOK || status == http.StatusNotFound) {
		f.mu.Lock()
		if h := f.by[srv.ID]; h != nil {
			h.seededHome = true
		}
		f.mu.Unlock()
	}
}

// run keeps every server's picture fresh until ctx ends.
func (f *fleet) run(ctx context.Context) {
	tick := time.NewTicker(refreshEvery)
	defer tick.Stop()
	for {
		f.refreshAll()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (f *fleet) refreshAll() {
	var wg sync.WaitGroup
	for _, srv := range f.p.store.get().Servers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			f.refresh(s)
		}(srv)
	}
	wg.Wait()
}

func (f *fleet) forget(id string) {
	f.mu.Lock()
	delete(f.by, id)
	f.mu.Unlock()
}

// views is every server, the panel's own first, as the pages show them.
func (f *fleet) views() []serverView {
	st := f.p.store.get()
	var out []serverView

	this := serverView{ID: "this", Name: st.ThisName, Group: st.ThisGroup, This: true, Online: true}
	ov := agent.LocalOverview(f.p.tunnelsDir)
	this.Overview = &ov
	if this.Name == "" {
		this.Name = ov.Hostname
	}
	if len(ov.IPv4) > 0 {
		this.Address = ov.IPv4[0]
	} else if len(ov.IPv6) > 0 {
		this.Address = ov.IPv6[0]
	}
	out = append(out, this)

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, srv := range st.Servers {
		v := serverView{ID: srv.ID, Name: srv.Name, Group: srv.Group, Address: srv.Address, CallsPanel: srv.CallsPanel}
		if h := f.by[srv.ID]; h != nil {
			v.Overview = h.overview
			if !h.at.IsZero() {
				v.LastSeen = h.at.UTC().Format(time.RFC3339)
			}
			v.Online = h.err == nil && time.Since(h.at) < 3*refreshEvery
			if h.err != nil {
				v.Problem = plainAgentError(h.err)
			}
		} else {
			v.Problem = "not checked yet"
		}
		out = append(out, v)
	}
	return out
}

// plainAgentError turns a network error into something a person can act on.
func plainAgentError(err error) string {
	msg := err.Error()
	switch {
	case err == errNotCalling:
		return "it is not calling the panel right now; it may be offline, or unable to reach the panel"
	case strings.Contains(msg, "does not match the saved fingerprint"):
		return "the server answered with a different certificate than when it was added; " +
			"if it was reinstalled, remove it and add it again"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "it did not answer in time; it may be offline, or the route to it blocked"
	case strings.Contains(msg, "connection refused"):
		return "nothing answers on its agent's port; the agent may be stopped"
	}
	return msg
}

func logf(format string, args ...any) { log.Printf("[panel] "+format, args...) }
