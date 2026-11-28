package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

func TestAgentConfigMultiPanelRoundTrip(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "agent.conf")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")

	p1 := panelLink{URLs: "https://panel1.example.com:2053,https://198.51.100.1:2053", Fingerprint: "aa:bb:cc:11"}
	p2 := panelLink{URLs: "https://panel2.example.com:2083", Fingerprint: "dd:ee:ff:22"}
	p3 := panelLink{URLs: "https://panel3.example.com:8443", Fingerprint: "11:22:33:44"}

	ac := agentConfig{
		Listen:       "0.0.0.0:2083",
		Token:        "pba_testtoken123",
		CertFile:     certPath,
		KeyFile:      keyPath,
		AllowUpdates: "on",
	}
	ac.setPanels(mergePanelLink(nil, p1.URLs, p1.Fingerprint))
	ac.setPanels(mergePanelLink(ac.allPanels(), p2.URLs, p2.Fingerprint))
	ac.setPanels(mergePanelLink(ac.allPanels(), p3.URLs, p3.Fingerprint))

	if err := writeAgentConfig(confPath, ac); err != nil {
		t.Fatalf("writeAgentConfig: %v", err)
	}

	got, err := readAgentConfig(confPath)
	if err != nil {
		t.Fatalf("readAgentConfig: %v", err)
	}
	panels := got.allPanels()
	if len(panels) != 3 {
		t.Fatalf("expected 3 panels after round-trip, got %d: %+v", len(panels), panels)
	}
	if got.PanelURL != p1.URLs || got.PanelFingerprint != p1.Fingerprint {
		t.Fatalf("primary panel mismatch: got (%q, %q)", got.PanelURL, got.PanelFingerprint)
	}
	if panels[1] != p2 || panels[2] != p3 {
		t.Fatalf("extra panels mismatch: got %+v", panels)
	}

	// Updating Panel #2's URL with the same fingerprint replaces only Panel #2.
	updatedURL2 := "https://panel2-new.example.com:2083"
	got.setPanels(mergePanelLink(got.allPanels(), updatedURL2, strings.ToUpper(p2.Fingerprint)))
	panels = got.allPanels()
	if len(panels) != 3 || panels[1].URLs != updatedURL2 || panels[0] != p1 || panels[2] != p3 {
		t.Fatalf("merge update broke other panels: %+v", panels)
	}

	// Removing Panel #2 by fingerprint keeps Panel #1 and Panel #3 untouched.
	got.setPanels(removePanelLink(got.allPanels(), strings.ToUpper(p2.Fingerprint)))
	if err := writeAgentConfig(confPath, got); err != nil {
		t.Fatalf("writeAgentConfig after remove: %v", err)
	}
	got2, err := readAgentConfig(confPath)
	if err != nil {
		t.Fatalf("readAgentConfig after remove: %v", err)
	}
	panels = got2.allPanels()
	if len(panels) != 2 || panels[0] != p1 || panels[1] != p3 {
		t.Fatalf("expected panels [p1, p3] after selective removal, got %+v", panels)
	}

	// ReadLocalAgentShareInfo reads port, token, and generates/loads fingerprint.
	port, tok, fp, err := ReadLocalAgentShareInfo(confPath)
	if err != nil {
		t.Fatalf("ReadLocalAgentShareInfo: %v", err)
	}
	if port != 2083 || tok != "pba_testtoken123" || fp == "" {
		t.Fatalf("unexpected share info: port=%d tok=%q fp=%q", port, tok, fp)
	}
}

type mockHubPanel struct {
	srv      *httptest.Server
	fp       string
	polls    atomic.Int64
	mu       sync.Mutex
	pending  chan HubRequest
	replies  map[string]chan HubReply
	wantAuth string
}

func newMockHubPanel(t *testing.T, tok string) *mockHubPanel {
	t.Helper()
	m := &mockHubPanel{
		pending:  make(chan HubRequest, 4),
		replies:  map[string]chan HubReply{},
		wantAuth: "Bearer " + tok,
	}
	certDir := t.TempDir()
	cert, err := engine.EnsureCert(filepath.Join(certDir, "panel.crt"), filepath.Join(certDir, "panel.key"), "mock-panel")
	if err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != m.wantAuth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/hub/poll":
			m.polls.Add(1)
			select {
			case req := <-m.pending:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(req)
			case <-time.After(150 * time.Millisecond):
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			}
		case "/hub/reply":
			var rep HubReply
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				http.Error(w, "bad reply", http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			ch := m.replies[rep.ID]
			delete(m.replies, rep.ID)
			m.mu.Unlock()
			if ch != nil {
				ch <- rep
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	m.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	m.srv.StartTLS()
	m.fp = fingerprintOf(cert.Certificate[0])
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockHubPanel) roundTrip(t *testing.T, id, method, path string) HubReply {
	t.Helper()
	ch := make(chan HubReply, 1)
	m.mu.Lock()
	m.replies[id] = ch
	m.mu.Unlock()
	m.pending <- HubRequest{ID: id, Method: method, Path: path}
	select {
	case rep := <-ch:
		return rep
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for reply %s from agent", id)
		return HubReply{}
	}
}

func TestMultiPanelConcurrentCallHomeAndSelectiveRemoval(t *testing.T) {
	StopCallHome()

	const tok = "pba_multipanel_secret"
	h := NewHandler(tok, t.TempDir(), nil)

	p1 := newMockHubPanel(t, tok)
	p2 := newMockHubPanel(t, tok)
	t.Cleanup(StopCallHome)
	if p1.fp == p2.fp {
		t.Fatalf("expected distinct mock panel fingerprints")
	}

	doCallHome := func(method string, payload map[string]string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(method, "/api/callhome", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Register Panel #1, then Panel #2 on the same agent.
	if rec := doCallHome(http.MethodPost, map[string]string{"panel_url": p1.srv.URL, "panel_fingerprint": p1.fp}); rec.Code != http.StatusOK {
		t.Fatalf("register panel 1 failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doCallHome(http.MethodPost, map[string]string{"panel_url": p2.srv.URL, "panel_fingerprint": p2.fp}); rec.Code != http.StatusOK {
		t.Fatalf("register panel 2 failed: %d %s", rec.Code, rec.Body.String())
	}

	// Both panels must be served concurrently by the single agent.
	rep1 := p1.roundTrip(t, "req-p1-a", http.MethodGet, "/api/overview")
	rep2 := p2.roundTrip(t, "req-p2-a", http.MethodGet, "/api/overview")
	if rep1.Status != http.StatusOK || rep2.Status != http.StatusOK {
		t.Fatalf("expected 200 from both panels, got p1=%d p2=%d", rep1.Status, rep2.Status)
	}

	// DELETE /api/callhome without panel_fingerprint must be rejected so callers
	// can never accidentally wipe all panels.
	if rec := doCallHome(http.MethodDelete, map[string]string{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for DELETE without fingerprint, got %d", rec.Code)
	}

	// Selectively remove ONLY Panel #2 via DELETE /api/callhome.
	if rec := doCallHome(http.MethodDelete, map[string]string{"panel_fingerprint": p2.fp}); rec.Code != http.StatusOK {
		t.Fatalf("remove panel 2 failed: %d %s", rec.Code, rec.Body.String())
	}

	// Panel #1 must continue working without interruption.
	rep1b := p1.roundTrip(t, "req-p1-b", http.MethodGet, "/api/overview")
	if rep1b.Status != http.StatusOK {
		t.Fatalf("panel 1 stopped working after removing panel 2: status=%d", rep1b.Status)
	}

	// Panel #2 must stop receiving new polls.
	before := p2.polls.Load()
	time.Sleep(350 * time.Millisecond)
	after := p2.polls.Load()
	if after != before {
		t.Fatalf("panel 2 kept receiving polls after removal: before=%d after=%d", before, after)
	}
}
