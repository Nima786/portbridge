package panel

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

// twoServers is a panel whose own server is a relay, managing one foreign server
// whose agent runs here on a folder of its own.
func twoServers(t *testing.T) (p *Panel, foreignID, foreignDir string) {
	t.Helper()
	p = newTestPanel(t)
	_ = p.store.update(func(s *State) error { s.ThisGroup = GroupRelay; return nil })
	const token = "pba_foreign"
	foreignDir = t.TempDir()
	srv := httptest.NewTLSServer(agent.NewHandler(token, foreignDir, nil))
	t.Cleanup(srv.Close)
	f := addTestServer(t, p, Server{ID: "far", Name: "Aeza", Group: GroupForeign, Address: "203.0.113.20",
		AgentURL: srv.URL, Fingerprint: fingerprintOf(srv.Certificate().Raw)}, token)
	p.fleet.refresh(f)
	return p, f.ID, foreignDir
}

func waitJob(t *testing.T, p *Panel, id string) jobView {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		p.jobsMu.Lock()
		j := p.jobs[id]
		p.jobsMu.Unlock()
		if v := j.view(); v.Done {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s never finished", id)
	return jobView{}
}

func newTunnel(name string) createRequest {
	return createRequest{Name: name, Relay: "this", Foreign: "far", Mode: "reverse", Link: "website",
		ServerName: "www.bing.com", ServicePorts: "39001", UserPorts: "29311", LinkPort: 2217, RelayIP: "198.51.100.1"}
}

func confs(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	for i := range m {
		m[i] = filepath.Base(m[i])
	}
	return m
}

func TestATunnelIsMadeOnBothServersFromThePanel(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)
	id, err := p.startCreate(newTunnel("shop"))
	if err != nil {
		t.Fatal(err)
	}
	if v := waitJob(t, p, id); v.Error != "" {
		t.Fatalf("not made: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edge, origin := agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if len(edge) != 1 || len(origin) != 1 || edge[0].PairID == "" || edge[0].PairID != origin[0].PairID {
		t.Fatalf("the two halves are not one tunnel: %+v %+v", edge, origin)
	}
	if edge[0].Role != "edge" || origin[0].Role != "origin" || edge[0].Mode != "reverse" || origin[0].Transport != "tls" {
		t.Fatalf("wrong halves: %+v %+v", edge[0], origin[0])
	}

	// It is shown as one tunnel with both ends.
	var found bool
	for _, tv := range pairTunnels(p.fleet.views()) {
		if tv.Name == "shop" && tv.Edge != nil && tv.Origin != nil && tv.Edge.ServerID == "this" && tv.Origin.ServerID == foreignID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the tunnels page does not show it with both ends")
	}

	// Its code, for pasting by hand, is the one the foreign half was made from.
	code, err := p.tunnelCode("this", "shop")
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := base64.StdEncoding.DecodeString(code); err != nil || !strings.Contains(string(raw), "name=shop\n") {
		t.Fatalf("not the tunnel's code: %v", err)
	}

	for _, action := range []string{"stop", "start", "restart"} {
		for _, o := range p.serviceTunnel(tunnelTarget{Name: "shop", Edge: "this", Origin: foreignID}, action) {
			if !o.OK {
				t.Fatalf("%s on %s: %s", action, o.Server, o.Error)
			}
		}
	}

	results := p.deleteTunnel(tunnelTarget{Name: "shop", Edge: "this", Origin: foreignID})
	if len(results) != 2 || !results[0].OK || !results[1].OK {
		t.Fatalf("not deleted from both: %+v", results)
	}
	if len(confs(p.tunnelsDir)) != 0 || len(confs(foreignDir)) != 0 {
		t.Fatalf("files were left behind: %v %v", confs(p.tunnelsDir), confs(foreignDir))
	}
}

func TestIfTheForeignHalfFailsNothingIsLeftBehind(t *testing.T) {
	p, _, foreignDir := twoServers(t)
	// The foreign server already has a tunnel of that name, so it refuses.
	_ = os.WriteFile(filepath.Join(foreignDir, "taken.conf"), []byte("name = taken\n"), 0o600)
	id, err := p.startCreate(newTunnel("taken"))
	if err != nil {
		t.Fatal(err)
	}
	v := waitJob(t, p, id)
	if v.Error == "" || !strings.Contains(v.Error, "Nothing was left behind") {
		t.Fatalf("the failure was not reported plainly: %q", v.Error)
	}
	if len(confs(p.tunnelsDir)) != 0 {
		t.Fatalf("the Iran half was left behind: %v", confs(p.tunnelsDir))
	}
}

func TestAPortClashOnTheForeignServerIsCaughtFirst(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)
	// A tunnel already there uses port 39001 for its own link.
	first := newTunnel("first")
	first.Mode, first.LinkPort, first.ServicePorts, first.UserPorts = "direct", 39001, "443", "443"
	if v := waitJob(t, p, mustCreate(t, p, first)); v.Error != "" {
		t.Fatalf("setting up: %s", v.Error)
	}
	clash := newTunnel("second")
	clash.ServicePorts, clash.UserPorts = "39001", "29312"
	v := waitJob(t, p, mustCreate(t, p, clash))
	if v.Error == "" || !strings.Contains(v.Error, "39001") {
		t.Fatalf("the clash was not caught: %q", v.Error)
	}
	if got := confs(p.tunnelsDir); len(got) != 1 {
		t.Fatalf("the Iran half was made despite the clash: %v", got)
	}
	_ = foreignID
	_ = foreignDir
}

func mustCreate(t *testing.T, p *Panel, r createRequest) string {
	t.Helper()
	id, err := p.startCreate(r)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTheNewTunnelFormIsChecked(t *testing.T) {
	p, _, _ := twoServers(t)
	for name, change := range map[string]func(*createRequest){
		"no relay":                 func(r *createRequest) { r.Relay = "" },
		"the same server twice":    func(r *createRequest) { r.Foreign = "this" },
		"relay in the wrong group": func(r *createRequest) { r.Relay, r.Foreign = "far", "this" },
		"no link type":             func(r *createRequest) { r.Link = "" },
		"CDN with no domain":       func(r *createRequest) { r.Link = "cdn" },
		"CDN backup in reverse":    func(r *createRequest) { r.Link, r.Domain = "website-cdn-backup", "x.example.com" },
	} {
		r := newTunnel("x")
		change(&r)
		if _, err := p.startCreate(r); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// IPv6 between the servers needs both to have an IPv6 address. Whether this
	// machine has one depends on where the test runs, so the foreign server is
	// told to have none.
	p.fleet.mu.Lock()
	p.fleet.by["far"].overview = &agent.Overview{OK: true, Version: "v0.15.0", IPv4: []string{"203.0.113.20"}}
	p.fleet.mu.Unlock()
	r6 := newTunnel("x")
	r6.IPv6 = true
	if _, err := p.startCreate(r6); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("IPv6 without a foreign IPv6 address: %v", err)
	}
	// The users' ports default to the service ports.
	r := newTunnel("x")
	r.UserPorts = ""
	s, err := p.toSpec(r)
	if err != nil || s.UserPorts != "39001" {
		t.Fatalf("users' ports did not default to the service ports: %q %v", s.UserPorts, err)
	}
}

func TestDeletingSaysWhatToDoByHand(t *testing.T) {
	p, foreignID, _ := twoServers(t)
	// The foreign server's agent goes away.
	_ = p.store.update(func(s *State) error {
		s.Servers[0].AgentURL = "https://127.0.0.1:1"
		return nil
	})
	results := p.deleteTunnel(tunnelTarget{Name: "gone", Edge: "this", Origin: foreignID})
	var foreign halfOutcome
	for _, r := range results {
		if r.Server == "Aeza" {
			foreign = r
		}
	}
	if foreign.OK || !strings.Contains(foreign.Manual, "Delete a tunnel") || !strings.Contains(foreign.Manual, "gone") {
		t.Fatalf("no plain instructions for the server that could not be reached: %+v", foreign)
	}
}

func TestTunnelCapacityAndMuxSwitchingOnBothServers(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)

	// 1. Create a Dedicated Pool tunnel with custom Pool (45) and MaxConn (3500).
	req := newTunnel("cap")
	req.Shared = false
	req.Pool = 45
	req.MaxConn = 3500
	if v := waitJob(t, p, mustCreate(t, p, req)); v.Error != "" {
		t.Fatalf("create failed: %s", v.Error)
	}

	edge, origin := agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if len(edge) != 1 || len(origin) != 1 {
		t.Fatalf("expected 1 tunnel on both ends, got %d and %d", len(edge), len(origin))
	}
	if edge[0].Mux || edge[0].PoolSize != 45 || edge[0].MaxConn != 3500 {
		t.Fatalf("edge capacity mismatch after create: mux=%v pool=%d max_conn=%d", edge[0].Mux, edge[0].PoolSize, edge[0].MaxConn)
	}
	if origin[0].Mux || origin[0].PoolSize != 45 || origin[0].MaxConn != 3500 {
		t.Fatalf("origin capacity mismatch after create: mux=%v pool=%d max_conn=%d", origin[0].Mux, origin[0].PoolSize, origin[0].MaxConn)
	}

	// 2. Edit the tunnel to switch from Dedicated Pool (mux=off) to Shared Mux (mux=on, mux_links=8, max_conn=6000).
	editJob1, err := p.startEditTunnel(editTunnelRequest{
		Name:         "cap",
		Edge:         "this",
		Origin:       foreignID,
		ServicePorts: "39001",
		UserPorts:    "29311",
		LinkPort:     2217,
		Mux:          "on",
		MuxLinks:     8,
		MaxConn:      6000,
		Firewall:     "on",
	})
	if err != nil {
		t.Fatalf("startEditTunnel (to mux) failed: %v", err)
	}
	if v := waitJob(t, p, editJob1); v.Error != "" {
		t.Fatalf("edit to mux failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge, origin = agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if !edge[0].Mux || edge[0].MuxLinks != 8 || edge[0].MaxConn != 6000 {
		t.Fatalf("edge did not switch to mux=on (links=8, max=6000): %+v", edge[0])
	}
	if !origin[0].Mux || origin[0].MuxLinks != 8 || origin[0].MaxConn != 6000 {
		t.Fatalf("origin did not switch to mux=on (links=8, max=6000): %+v", origin[0])
	}

	// 3. Edit the tunnel back to Dedicated Pool (mux=off, pool=80, max_conn=2500).
	editJob2, err := p.startEditTunnel(editTunnelRequest{
		Name:         "cap",
		Edge:         "this",
		Origin:       foreignID,
		ServicePorts: "39001",
		UserPorts:    "29311",
		LinkPort:     2217,
		Mux:          "off",
		Pool:         80,
		MaxConn:      2500,
		Firewall:     "on",
	})
	if err != nil {
		t.Fatalf("startEditTunnel (to pool) failed: %v", err)
	}
	if v := waitJob(t, p, editJob2); v.Error != "" {
		t.Fatalf("edit to pool failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge, origin = agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if edge[0].Mux || edge[0].PoolSize != 80 || edge[0].MaxConn != 2500 {
		t.Fatalf("edge did not switch back to mux=off (pool=80, max=2500): %+v", edge[0])
	}
	if origin[0].Mux || origin[0].PoolSize != 80 || origin[0].MaxConn != 2500 {
		t.Fatalf("origin did not switch back to mux=off (pool=80, max=2500): %+v", origin[0])
	}
}

func TestWebsiteBridgeCreateAndEditOnBothServers(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)

	req := newTunnel("wpbridge")
	req.ServicePorts = "18081,18443"
	req.UserPorts = "18081,18443"
	req.LinkPort = 28443
	req.ProxyProtocol = "v1"
	req.SharedLinks = 8
	req.MaxConn = 4000
	req.WebsiteBridge = true
	req.WebsiteDomains = "myshop.ir, example.com"
	req.OutboundProxy = true
	req.OutboundProxyPort = 28080
	req.OutboundProxyMode = "split"
	req.OutboundIranDomains = ".ir, shaparak.ir, kavenegar.com"
	req.OutboundBypassDomains = "telegram.org, api.telegram.org"

	if v := waitJob(t, p, mustCreate(t, p, req)); v.Error != "" {
		t.Fatalf("create website bridge failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge, origin := agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if len(edge) != 1 || len(origin) != 1 {
		t.Fatalf("expected 1 website bridge on both ends, got %d and %d", len(edge), len(origin))
	}
	for _, side := range []struct {
		name string
		ti   agent.TunnelInfo
	}{
		{"edge", edge[0]},
		{"origin", origin[0]},
	} {
		if !side.ti.WebsiteBridge || !side.ti.OutboundProxy || !side.ti.Mux {
			t.Fatalf("%s missing website_bridge/outbound_proxy/mux: %+v", side.name, side.ti)
		}
		if side.ti.OutboundProxyPort != 28080 || side.ti.OutboundProxyMode != "split" {
			t.Fatalf("%s outbound proxy port/mode mismatch: %+v", side.name, side.ti)
		}
		if side.ti.WebsiteDomains != "myshop.ir, example.com" {
			t.Fatalf("%s website_domains mismatch: %q", side.name, side.ti.WebsiteDomains)
		}
	}

	// Edit the Website Bridge outbound proxy port, mode, and domain lists.
	editJob, err := p.startEditTunnel(editTunnelRequest{
		Name:                  "wpbridge",
		Edge:                  "this",
		Origin:                foreignID,
		ServicePorts:          "18081,18443",
		UserPorts:             "18081,18443",
		LinkPort:              28443,
		ProxyProtocol:         "v1",
		Mux:                   "on",
		MuxLinks:              12,
		MaxConn:               6000,
		WebsiteDomains:        "myshop.ir, example.com, pay.myshop.ir",
		OutboundProxy:         "on",
		OutboundProxyPort:     28081,
		OutboundProxyMode:     "all",
		OutboundIranDomains:   ".ir, zarinpal.com",
		OutboundBypassDomains: "telegram.org, t.me, stripe.com",
	})
	if err != nil {
		t.Fatalf("startEditTunnel failed: %v", err)
	}
	if v := waitJob(t, p, editJob); v.Error != "" {
		t.Fatalf("edit website bridge failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge, origin = agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	for _, side := range []struct {
		name string
		ti   agent.TunnelInfo
	}{
		{"edge", edge[0]},
		{"origin", origin[0]},
	} {
		if side.ti.OutboundProxyPort != 28081 || side.ti.OutboundProxyMode != "all" {
			t.Fatalf("%s updated outbound proxy port/mode mismatch: %+v", side.name, side.ti)
		}
		if side.ti.WebsiteDomains != "myshop.ir, example.com, pay.myshop.ir" {
			t.Fatalf("%s updated website_domains mismatch: %q", side.name, side.ti.WebsiteDomains)
		}
		if side.ti.MuxLinks != 12 || side.ti.MaxConn != 6000 {
			t.Fatalf("%s updated mux_links/max_conn mismatch: %+v", side.name, side.ti)
		}
	}
}

func TestAProbeStepMustPointAtAServerOfTheFleet(t *testing.T) {
	p, _, _ := twoServers(t)
	p.fleet.mu.Lock()
	p.fleet.by["far"].overview = &agent.Overview{OK: true, Version: "v0.15.0", IPv4: []string{"203.0.113.20"}}
	p.fleet.mu.Unlock()
	good := engine.ProbeCandidateSpec{TargetAddr: "203.0.113.20:2053"}
	if err := p.checkProbeStep("far", "s3cret", good); err != nil {
		t.Fatalf("a step at a fleet server was refused: %v", err)
	}
	for name, c := range map[string]struct {
		dialer, secret string
		spec           engine.ProbeCandidateSpec
	}{
		"unknown dialer":    {"nobody", "s", good},
		"no secret":         {"far", "", good},
		"outside address":   {"far", "s", engine.ProbeCandidateSpec{TargetAddr: "10.0.0.5:22"}},
		"loopback":          {"far", "s", engine.ProbeCandidateSpec{TargetAddr: "127.0.0.1:22", CDN: true}},
		"name without CDN":  {"far", "s", engine.ProbeCandidateSpec{TargetAddr: "example.com:443"}},
		"bad port":          {"far", "s", engine.ProbeCandidateSpec{TargetAddr: "203.0.113.20:0"}},
		"not host and port": {"far", "s", engine.ProbeCandidateSpec{TargetAddr: "203.0.113.20"}},
	} {
		if err := p.checkProbeStep(c.dialer, c.secret, c.spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := p.checkProbeStep("far", "s", engine.ProbeCandidateSpec{TargetAddr: "cdn.example.com:443", CDN: true}); err != nil {
		t.Errorf("a CDN name was refused: %v", err)
	}
}

func TestProbeSessionHonorsAndAvoidsUserPorts(t *testing.T) {
	p, foreignID, _ := twoServers(t)
	const relayToken = "pba_relay"
	relayDir := t.TempDir()
	relaySrv := httptest.NewTLSServer(agent.NewHandler(relayToken, relayDir, nil))
	t.Cleanup(relaySrv.Close)
	r := addTestServer(t, p, Server{
		ID:          "near",
		Name:        "Tehran",
		Group:       GroupRelay,
		Address:     "198.51.100.10",
		AgentURL:    relaySrv.URL,
		Fingerprint: fingerprintOf(relaySrv.Certificate().Raw),
	}, relayToken)
	p.fleet.refresh(r)

	ctx := context.Background()

	// 1. When linkPort conflicts with servicePorts, the probe session avoids
	// all service/user ports on both servers and records a note.
	sess, err := p.startProbeSessionWithPorts(ctx, r.ID, foreignID, "", "2053, 2083", "8443", 2053)
	if err != nil {
		t.Fatalf("startProbeSessionWithPorts failed: %v", err)
	}
	p.finishProbeSession(*sess, nil)

	avoided := map[int]bool{2053: true, 2083: true, 8443: true}
	for _, c := range sess.Candidates {
		if avoided[c.Port] {
			t.Fatalf("candidate %s used avoided port %d", c.ID, c.Port)
		}
	}
	if !strings.Contains(strings.Join(sess.Notes, "\n"), "Port note:") {
		t.Fatalf("expected port clash note in %v", sess.Notes)
	}

	// 2. When a distinct linkPort is requested, at least one listener binds it
	// (the second server in this in-process test shares 0.0.0.0 so it falls
	// back to another port and records a listener note).
	sess2, err := p.startProbeSessionWithPorts(ctx, r.ID, foreignID, "", "443, 2096", "", 37443)
	if err != nil {
		t.Fatalf("startProbeSessionWithPorts (custom linkPort) failed: %v", err)
	}
	defer p.finishProbeSession(*sess2, nil)

	usedCustom := false
	for _, c := range sess2.Candidates {
		if c.Port == 443 || c.Port == 2096 {
			t.Fatalf("candidate %s used avoided inbound port %d", c.ID, c.Port)
		}
		if c.Port == 37443 {
			usedCustom = true
		}
	}
	if !usedCustom {
		t.Fatalf("expected at least one direction to test on requested port 37443, got candidates %+v", sess2.Candidates)
	}
}
