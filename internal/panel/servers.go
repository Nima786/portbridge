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
	"net/http"
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
	overview *agent.Overview
	err      error
	at       time.Time // last time it answered
	tried    time.Time
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

// callLimit is call for an answer that may be larger, such as a release.
func (f *fleet) callLimit(ctx context.Context, srv Server, method, path string, body []byte, limit int64) (int, []byte, error) {
	token, err := f.p.store.open(srv.TokenEnc)
	if err != nil {
		return 0, nil, err
	}
	if srv.CallsPanel {
		return f.p.hub.do(ctx, srv.ID, method, path, body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(srv.AgentURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	// The context sets how long this may take; the client's own limit is only
	// a backstop, long enough for a release to cross a slow link.
	resp, err := agent.NewPinnedClient(srv.Fingerprint, srv.AgentURL, 10*time.Minute).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, b, err
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
	f.mu.Lock()
	defer f.mu.Unlock()
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
