package panel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

func addTestServer(t *testing.T, p *Panel, srv Server, token string) Server {
	t.Helper()
	sealed, err := p.store.seal(token)
	if err != nil {
		t.Fatal(err)
	}
	srv.TokenEnc = sealed
	if err := p.store.update(func(s *State) error { s.Servers = append(s.Servers, srv); return nil }); err != nil {
		t.Fatal(err)
	}
	return srv
}

// The whole way round: a real agent calls a real panel, pinned to the panel's
// certificate, and the panel asks it for its overview through that call.
func TestAServerThatCallsInIsReached(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	const token = "pba_calls_in"
	srv := addTestServer(t, p, Server{ID: "far", Name: "far", Group: GroupRelay, CallsPanel: true}, token)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, err := p.hub.do(ctx, srv.ID, http.MethodGet, "/api/overview", nil); !errors.Is(err, errNotCalling) {
		t.Fatalf("before it calls, asking it should say it is not calling, not %v", err)
	}
	go agent.CallHome(ctx, ts.URL, p.ownFingerprint(), token, agent.NewHandler(token, t.TempDir()))

	deadline := time.Now().Add(10 * time.Second)
	for !p.hub.connected(srv.ID) {
		if time.Now().After(deadline) {
			t.Fatalf("the agent never called")
		}
		time.Sleep(50 * time.Millisecond)
	}
	octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
	defer ocancel()
	ov, err := p.fleet.overview(octx, srv)
	if err != nil || !ov.OK || ov.Version == "" {
		t.Fatalf("asking through the call failed: %+v %v", ov, err)
	}

	p.fleet.refreshAll()
	for _, v := range p.fleet.views() {
		if v.ID == srv.ID && (!v.Online || v.Overview == nil) {
			t.Fatalf("the server is not shown as online: %+v", v)
		}
	}
}

func TestOnlyKnownServersMayCallIn(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	addTestServer(t, p, Server{ID: "known", CallsPanel: true}, "pba_known")
	addTestServer(t, p, Server{ID: "direct", CallsPanel: false}, "pba_direct")
	b := newBrowser(t, ts)
	for _, tok := range []string{"", "pba_wrong", "pba_direct"} {
		hdr := map[string]string{}
		if tok != "" {
			hdr["Authorization"] = "Bearer " + tok
		}
		if code, _, _ := b.do(http.MethodGet, "/hub/poll", nil, hdr); code != http.StatusUnauthorized {
			t.Fatalf("token %q could poll (%d)", tok, code)
		}
		if code, _, _ := b.do(http.MethodPost, "/hub/reply", map[string]string{"id": "x"}, hdr); code != http.StatusUnauthorized {
			t.Fatalf("token %q could reply (%d)", tok, code)
		}
	}

	// A server being added is let in for as long as the adding takes.
	p.addPending("new", "pba_new")
	req := httptest.NewRequest(http.MethodGet, "/hub/poll", nil)
	req.Header.Set("Authorization", "Bearer pba_new")
	if p.hub.who(req) != "new" {
		t.Fatalf("a server being added was not let in")
	}
	p.dropPending("new")
	if p.hub.who(req) != "" {
		t.Fatalf("a server that was not added is still let in")
	}
}

func TestAServerReachedDirectlyIsPinned(t *testing.T) {
	p := newTestPanel(t)
	const token = "pba_direct"
	agentSrv := httptest.NewTLSServer(agent.NewHandler(token, t.TempDir()))
	defer agentSrv.Close()

	srv := addTestServer(t, p, Server{ID: "d", AgentURL: agentSrv.URL, Fingerprint: fingerprintOf(agentSrv.Certificate().Raw)}, token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ov, err := p.fleet.overview(ctx, srv); err != nil || !ov.OK {
		t.Fatalf("the pinned agent could not be reached: %v", err)
	}

	srv.Fingerprint = strings.Repeat("00:", 31) + "00"
	_, err := p.fleet.overview(ctx, srv)
	if err == nil {
		t.Fatalf("an agent with another certificate was trusted")
	}
	if msg := plainAgentError(err); !strings.Contains(msg, "different certificate") {
		t.Fatalf("the problem is not explained: %s", msg)
	}

	srv.Fingerprint = fingerprintOf(agentSrv.Certificate().Raw)
	wrong, _ := p.store.seal("pba_not_it")
	srv.TokenEnc = wrong
	if _, err := p.fleet.overview(ctx, srv); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("a refused token is not explained: %v", err)
	}
}
