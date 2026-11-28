package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

func TestShareLinkCodeValidation(t *testing.T) {
	valid := serverSharePayload{
		V:           1,
		Name:        "Aeza",
		Group:       GroupForeign,
		Address:     "79.137.202.176",
		AgentURL:    "https://79.137.202.176:2083",
		Fingerprint: "aa:bb:cc:dd",
		Token:       "pba_secret123",
		IPv6:        []string{"2001:db8::1", "not-an-ip", "1.2.3.4"},
	}
	code, err := encodeServerShare(valid)
	if err != nil {
		t.Fatalf("encodeServerShare: %v", err)
	}
	if !strings.HasPrefix(code, panelSharePrefix) {
		t.Fatalf("expected %s prefix, got %q", panelSharePrefix, code)
	}

	got, err := decodeServerShare("  `" + code + "` \n")
	if err != nil {
		t.Fatalf("decodeServerShare valid: %v", err)
	}
	if got.Name != "Aeza" || got.Address != "79.137.202.176" || got.AgentURL != "https://79.137.202.176:2083" || got.Token != "pba_secret123" {
		t.Fatalf("unexpected decoded payload: %+v", got)
	}
	if len(got.IPv6) != 1 || got.IPv6[0] != "2001:db8::1" {
		t.Fatalf("expected sanitized single IPv6, got %+v", got.IPv6)
	}

	badCodes := []string{
		"",
		"http://example.com",
		"pbpanel://",
		"pbpanel://!!!not-base64!!!",
	}
	for _, bc := range badCodes {
		if _, err := decodeServerShare(bc); err == nil {
			t.Fatalf("expected error for bad code %q", bc)
		}
	}

	// Non-HTTPS AgentURL must be rejected.
	badHTTP := valid
	badHTTP.AgentURL = "http://79.137.202.176:2083"
	rawHTTP, _ := encodeServerShare(badHTTP)
	if _, err := decodeServerShare(rawHTTP); err == nil {
		t.Fatalf("expected error for http:// AgentURL")
	}
}

func TestShareAndLinkAcrossTwoPanelsWithoutSSH(t *testing.T) {
	t.Cleanup(agent.StopCallHome)

	// Panel #1
	p1 := newTestPanel(t)
	ts1 := startPanel(t, p1)
	p1.cfgMu.Lock()
	p1.cfg.PublicURL = ts1.URL
	p1.cfgMu.Unlock()
	b1 := newBrowser(t, ts1)
	if code := b1.login("admin", testPassword); code != http.StatusOK {
		t.Fatalf("panel 1 login: %d", code)
	}

	// Panel #2 (completely independent panel with its own TLS certificate)
	p2 := newTestPanel(t)
	ts2 := startPanel(t, p2)
	p2.cfgMu.Lock()
	p2.cfg.PublicURL = ts2.URL
	p2.cfgMu.Unlock()
	b2 := newBrowser(t, ts2)
	if code := b2.login("admin", testPassword); code != http.StatusOK {
		t.Fatalf("panel 2 login: %d", code)
	}

	if p1.ownFingerprint() == p2.ownFingerprint() {
		t.Fatalf("expected distinct panel fingerprints")
	}

	// One remote Foreign server running a real PortBridge management agent.
	const tok = "pba_shared_foreign_server"
	agentSrv := httptest.NewTLSServer(agent.NewHandler(tok, t.TempDir(), nil))
	t.Cleanup(agentSrv.Close)
	t.Cleanup(agent.StopCallHome)
	agentFP := fingerprintOf(agentSrv.Certificate().Raw)

	s1 := addTestServer(t, p1, Server{
		ID:          "aeza1",
		Name:        "Aeza",
		Group:       GroupForeign,
		Address:     "127.0.0.1",
		AgentURL:    agentSrv.URL,
		Fingerprint: agentFP,
	}, tok)
	p1.fleet.refresh(s1)

	waitHub := func(label string, p *Panel, id string) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for !p.hub.connected(id) {
			if time.Now().After(deadline) {
				t.Fatalf("%s hub never connected for server %s", label, id)
			}
			time.Sleep(40 * time.Millisecond)
		}
	}
	waitHub("panel 1", p1, s1.ID)

	// 1. Export Share Link Code from Panel #1.
	code, shareResp, _ := b1.do(http.MethodPost, "/api/servers/"+s1.ID+"/share", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("panel 1 share failed: %d %+v", code, shareResp)
	}
	linkCode, _ := shareResp["code"].(string)
	if !strings.HasPrefix(linkCode, panelSharePrefix) {
		t.Fatalf("expected pbpanel:// code, got %q", linkCode)
	}

	// 2. Import that code into Panel #2 without SSH.
	code, linkResp, _ := b2.do(http.MethodPost, "/api/servers/link", map[string]string{
		"code": linkCode,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("panel 2 link failed: %d %+v", code, linkResp)
	}
	s2ID, _ := linkResp["server_id"].(string)
	if s2ID == "" || linkResp["name"] != "Aeza" || linkResp["group"] != GroupForeign {
		t.Fatalf("unexpected link response: %+v", linkResp)
	}

	// 3. Duplicate link on Panel #2 must return 409 Conflict.
	dupCode, _, _ := b2.do(http.MethodPost, "/api/servers/link", map[string]string{
		"code": linkCode,
	}, nil)
	if dupCode != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate link, got %d", dupCode)
	}

	// 4. Both Panel #1 and Panel #2 must be concurrently connected via hub!
	waitHub("panel 2", p2, s2ID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if st1, _, err := p1.hub.do(ctx, s1.ID, http.MethodGet, "/api/overview", nil); err != nil || st1 != http.StatusOK {
		t.Fatalf("panel 1 hub call failed after panel 2 linked: status=%d err=%v", st1, err)
	}
	if st2, _, err := p2.hub.do(ctx, s2ID, http.MethodGet, "/api/overview", nil); err != nil || st2 != http.StatusOK {
		t.Fatalf("panel 2 hub call failed: status=%d err=%v", st2, err)
	}

	// 5. Removing the server from Panel #2 must unregister ONLY Panel #2 while
	//    Panel #1 continues managing the agent over its hub connection.
	rmCode, _, _ := b2.do(http.MethodDelete, "/api/servers/"+s2ID, nil, nil)
	if rmCode != http.StatusOK {
		t.Fatalf("panel 2 remove failed: %d", rmCode)
	}
	time.Sleep(250 * time.Millisecond)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if st1, _, err := p1.hub.do(ctx2, s1.ID, http.MethodGet, "/api/overview", nil); err != nil || st1 != http.StatusOK {
		t.Fatalf("panel 1 broke after server was removed from panel 2: status=%d err=%v", st1, err)
	}
}
