package agent

// What the agent does for the web panel: describing its tunnels, its settings
// file, and calling the panel.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

func TestPairIDIsSharedByBothHalvesAndHidesThePassword(t *testing.T) {
	a := PairID("0123456789abcdef0123456789abcdef")
	if a != PairID("0123456789abcdef0123456789abcdef\n") {
		t.Fatalf("a trailing line break changed the pair id")
	}
	if a == PairID("0123456789abcdef0123456789abcdee") {
		t.Fatalf("two different passwords gave the same pair id")
	}
	if len(a) != 12 || strings.Contains("0123456789abcdef0123456789abcdef", a) {
		t.Fatalf("pair id %q is not a short fingerprint", a)
	}
}

func TestTunnelsReportDescribesEachTunnelWithoutItsPassword(t *testing.T) {
	withHost(t, &recordingHost{activeAfter: true})
	dir := t.TempDir()
	p := goodPairing("shop")
	if err := applyPairingData(p, dir); err != nil {
		t.Fatalf("making a tunnel to describe: %v", err)
	}
	got := TunnelsReport(dir)
	if len(got) != 1 {
		t.Fatalf("want 1 tunnel, got %d", len(got))
	}
	ti := got[0]
	if ti.Name != "shop" || ti.Role != "origin" || ti.Mode != "direct" || ti.LinkPort != 8443 {
		t.Fatalf("wrong description: %+v", ti)
	}
	if len(ti.ServicePorts) != 1 || ti.ServicePorts[0] != 8080 {
		t.Fatalf("service ports: want [8080], got %v", ti.ServicePorts)
	}
	if ti.PairID != PairID(p.Secret) {
		t.Fatalf("pair id %q is not the password's", ti.PairID)
	}
	if !ti.Running || ti.Problem != "" || ti.Link == "" {
		t.Fatalf("a sound running tunnel was reported as %+v", ti)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), p.Secret) {
		t.Fatalf("the report contains the tunnel's password")
	}
}

func TestTunnelsReportShowsAFreshStatusOnly(t *testing.T) {
	withHost(t, &recordingHost{activeAfter: true})
	dir := t.TempDir()
	if err := applyPairingData(goodPairing("live"), dir); err != nil {
		t.Fatal(err)
	}
	// The status normally goes in /run/portbridge; point it somewhere writable.
	statusFile := filepath.Join(dir, "live.json")
	f, err := os.OpenFile(filepath.Join(dir, "live.conf"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\nstatus_file = " + statusFile + "\n")
	_ = f.Close()

	write := func(at time.Time) {
		b, _ := json.Marshal(map[string]any{"active_sessions": 3, "updated_at": at.UTC().Format(time.RFC3339)})
		if err := os.WriteFile(statusFile, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(time.Now())
	if ti := TunnelsReport(dir)[0]; ti.Live == nil || ti.Live.ActiveSessions != 3 {
		t.Fatalf("a fresh status was not shown: %+v", ti.Live)
	}
	write(time.Now().Add(-2 * statusStaleAfter))
	if ti := TunnelsReport(dir)[0]; ti.Live != nil {
		t.Fatalf("an old status, left by a tunnel that stopped, was shown as live")
	}
}

func TestOverviewEndpointNeedsTheToken(t *testing.T) {
	h := newAgentHandler("pba_right", t.TempDir(), nil)
	for _, tc := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {"pba_wrong", http.StatusUnauthorized}, {"pba_right", http.StatusOK}} {
		req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("token %q: want HTTP %d, got %d", tc.token, tc.want, rec.Code)
		}
		if tc.want == http.StatusOK {
			var ov Overview
			if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil || !ov.OK || ov.Version == "" {
				t.Fatalf("not an overview: %s", rec.Body.String())
			}
		}
	}
}

func TestAgentConfigKeepsEverySetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.conf")
	want := agentConfig{
		Listen: "0.0.0.0:4356", Token: "pba_abc", CertFile: "/x.crt", KeyFile: "/x.key",
		PanelURL: "https://203.0.113.5:2096", PanelFingerprint: "aa:bb",
	}
	if err := writeAgentConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readAgentConfig(path)
	if err != nil || got != want {
		t.Fatalf("read back %+v (%v), want %+v", got, err, want)
	}
	// The menu reads the same file with its own simple reader.
	text, _ := os.ReadFile(path)
	if !strings.Contains(string(text), "listen = 0.0.0.0:4356\n") || !strings.Contains(string(text), "token = pba_abc\n") {
		t.Fatalf("the menu would not find listen and token in:\n%s", text)
	}
	// Without a panel, nothing about one is written.
	want.PanelURL, want.PanelFingerprint = "", ""
	_ = writeAgentConfig(path, want)
	text, _ = os.ReadFile(path)
	if strings.Contains(string(text), "panel") {
		t.Fatalf("panel settings were left behind:\n%s", text)
	}
}

func TestHubRequestsAreOnlyForTheAPI(t *testing.T) {
	h := newAgentHandler("pba_t", t.TempDir(), nil)
	rep := runHubRequest(HubRequest{ID: "1", Method: http.MethodGet, Path: "/debug/pprof"}, "pba_t", h)
	if rep.Status != http.StatusNotFound || rep.ID != "1" {
		t.Fatalf("a path outside the API was run: %+v", rep)
	}
	rep = runHubRequest(HubRequest{ID: "2", Method: http.MethodGet, Path: "/api/overview"}, "pba_t", h)
	if rep.Status != http.StatusOK || rep.ID != "2" {
		t.Fatalf("the overview through the hub failed: %d %s", rep.Status, rep.Body)
	}
}

// A small stand-in for the panel's hub, to watch the agent call it.
func TestCallHomeAnswersThePanelsRequests(t *testing.T) {
	const token = "pba_calling"
	var polls atomic.Int32
	replies := make(chan HubReply, 1)
	panel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/hub/poll":
			if polls.Add(1) == 1 {
				_ = json.NewEncoder(w).Encode(HubRequest{ID: "r1", Method: http.MethodGet, Path: "/api/overview"})
				return
			}
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			w.WriteHeader(http.StatusNoContent)
		case "/hub/reply":
			var rep HubReply
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &rep)
			replies <- rep
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer panel.Close()
	fp := fingerprintOf(panel.Certificate().Raw)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go callHome(ctx, panel.URL, fp, token, newAgentHandler(token, t.TempDir(), nil))
	select {
	case rep := <-replies:
		if rep.ID != "r1" || rep.Status != http.StatusOK {
			t.Fatalf("wrong answer: %+v", rep)
		}
		var ov Overview
		if err := json.Unmarshal(rep.Body, &ov); err != nil || !ov.OK {
			t.Fatalf("the answer is not an overview: %s", rep.Body)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the agent never answered the panel")
	}
}

func TestPanelClientTrustsOnlyThePanelsCertificate(t *testing.T) {
	panel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer panel.Close()
	dir := t.TempDir()
	otherCert, err := engine.EnsureCert(filepath.Join(dir, "o.crt"), filepath.Join(dir, "o.key"), "someone-else")
	if err != nil {
		t.Fatal(err)
	}
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	other.TLS = &tls.Config{Certificates: []tls.Certificate{otherCert}}
	other.StartTLS()
	defer other.Close()

	good := fingerprintOf(panel.Certificate().Raw)
	if _, err := panelClient(good, panel.URL, 5*time.Second).Get(panel.URL); err != nil {
		t.Fatalf("the panel's own certificate was refused: %v", err)
	}
	// The same fingerprint against a server with another certificate.
	if _, err := panelClient(good, other.URL, 5*time.Second).Get(other.URL); err == nil {
		t.Fatalf("a server with a different certificate was trusted")
	}
}
