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

	// 3. A server behind 1:1 NAT (like Oracle Cloud) added by hostname has no
	// public IP on its local NIC, so checkProbeStep must accept both its
	// resolved IP and its configured hostname.
	natSrv := addTestServer(t, p, Server{
		ID:          "oracle",
		Name:        "Oracle_AU",
		Group:       GroupForeign,
		Address:     "cp.example.invalid",
		AgentURL:    relaySrv.URL,
		Fingerprint: fingerprintOf(relaySrv.Certificate().Raw),
	}, relayToken)
	p.fleet.refresh(natSrv)
	if err := p.checkProbeStep(r.ID, "sec", engine.ProbeCandidateSpec{
		Mode:       "direct",
		Transport:  "tls",
		TargetAddr: "cp.example.invalid:3466",
		Port:       3466,
	}); err != nil {
		t.Fatalf("checkProbeStep rejected server added by hostname: %v", err)
	}
}

func TestPhase2H3AndAsymmetricTunnelSpecsAndAutoHeal(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)
	_ = foreignID

	// 1. toSpec mappings & validation for h3, h3-cdn, asymmetric, asymmetric-cdn.
	h3Spec, err := p.toSpec(createRequest{
		Name: "q1", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "h3", ServicePorts: "443", UserPorts: "443", LinkPort: 8443, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(h3) failed: %v", err)
	}
	if h3Spec.Transport != "h3" || h3Spec.ServerName != "www.google.com" || h3Spec.CDN == "on" {
		t.Fatalf("unexpected h3 spec: %+v", h3Spec)
	}

	if _, err := p.toSpec(createRequest{
		Name: "q2", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "h3-cdn", ServicePorts: "443", LinkPort: 443, RelayIP: "198.51.100.1",
	}); err == nil {
		t.Fatal("expected toSpec(h3-cdn) without domain to fail")
	}
	h3CDNSpec, err := p.toSpec(createRequest{
		Name: "q2", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "h3-cdn", Domain: "h3.example.com", CleanIPs: "104.16.1.1",
		ServicePorts: "443", LinkPort: 443, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(h3-cdn) failed: %v", err)
	}
	if h3CDNSpec.Transport != "h3" || h3CDNSpec.CDN != "on" || h3CDNSpec.ServerName != "h3.example.com" {
		t.Fatalf("unexpected h3-cdn spec: %+v", h3CDNSpec)
	}

	if _, err := p.toSpec(createRequest{
		Name: "a0", Relay: "this", Foreign: "far", Mode: "reverse",
		Link: "asymmetric", ServicePorts: "443", LinkPort: 2053, RelayIP: "198.51.100.1",
	}); err == nil {
		t.Fatal("expected toSpec(asymmetric) in reverse mode to fail")
	}
	asymSpec, err := p.toSpec(createRequest{
		Name: "a1", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "asymmetric", ServicePorts: "443", LinkPort: 2053, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(asymmetric) failed: %v", err)
	}
	if asymSpec.Asymmetric != "on" || asymSpec.AsymUplink != "xhttp" || asymSpec.AsymDownlink != "kcp-hop" {
		t.Fatalf("unexpected asymmetric spec: %+v", asymSpec)
	}

	asymCDNSpec, err := p.toSpec(createRequest{
		Name: "a2", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "asymmetric-cdn", Domain: "cdn.example.com", AsymUplink: "h3", AsymDownPort: 24500,
		ServicePorts: "443", LinkPort: 2083, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(asymmetric-cdn) failed: %v", err)
	}
	if asymCDNSpec.Asymmetric != "on" || asymCDNSpec.CDN != "on" || asymCDNSpec.AsymUplink != "h3" || asymCDNSpec.AsymDownPort != 24500 {
		t.Fatalf("unexpected asymmetric-cdn spec: %+v", asymCDNSpec)
	}

	// 2. Full create/join across Relay + Foreign for asymmetric tunnel.
	asymReq := newTunnel("asymshop")
	asymReq.Mode = "direct"
	asymReq.Link = "asymmetric"
	asymReq.LinkPort = 2053
	asymReq.AsymDownPort = 25010
	if v := waitJob(t, p, mustCreate(t, p, asymReq)); v.Error != "" {
		t.Fatalf("creating asymmetric tunnel failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edges, origins := agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if len(edges) != 1 || len(origins) != 1 {
		t.Fatalf("expected 1 tunnel on each side, got %+v / %+v", edges, origins)
	}
	if !edges[0].Asymmetric || !origins[0].Asymmetric || edges[0].AsymUplink != "xhttp" || origins[0].AsymDownlink != "kcp-hop" {
		t.Fatalf("asymmetric flags not paired properly: edge=%+v origin=%+v", edges[0], origins[0])
	}

	// 3. Auto-Heal pickBestCandidate selects synthesized Asymmetric Hybrid when top-ranked.
	rep := &engine.ProbeBenchmarkReport{
		Results: []engine.ProbeCandidateResult{
			{
				ProbeCandidateSpec: engine.ProbeCandidateSpec{
					ID: "direct-asymmetric", Mode: "direct", Transport: "xhttp",
					Asymmetric: true, AsymUplink: "xhttp", AsymDownlink: "kcp-hop", Port: 2053,
				},
				Hybrid: true, Status: "ok", Score: 96,
			},
			{
				ProbeCandidateSpec: engine.ProbeCandidateSpec{
					ID: "direct-tls-v4", Mode: "direct", Transport: "tls", Port: 8443,
				},
				Status: "ok", Score: 82,
			},
		},
	}
	cur := agent.TunnelInfo{Name: "main", Mode: "direct", Transport: "tls", LinkPort: 8443}
	best, ok := p.healer.pickBestCandidate(rep, cur, false)
	if !ok || best.ID != "direct-asymmetric" || !best.Asymmetric {
		t.Fatalf("expected pickBestCandidate to select direct-asymmetric, got ok=%v best=%+v", ok, best)
	}
	if desc := describeCandidate(best); !strings.Contains(desc, "ASYMMETRIC") {
		t.Fatalf("unexpected describeCandidate output: %q", desc)
	}
}

func TestPhase3WebRTCAndTwinPathSpecsAndAutoHeal(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)
	_ = foreignID

	// 1. toSpec mappings & validation for webrtc and twin.
	rtcSpec, err := p.toSpec(createRequest{
		Name: "rtc1", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "webrtc", SNISpoof: true, ServicePorts: "443", UserPorts: "443", LinkPort: 24050, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(webrtc) failed: %v", err)
	}
	if rtcSpec.Transport != "webrtc" || rtcSpec.Mux != "on" || rtcSpec.SNISpoof == "on" {
		t.Fatalf("unexpected webrtc spec: %+v", rtcSpec)
	}

	rtcCombo, err := p.toSpec(createRequest{
		Name: "rtc2", Relay: "this", Foreign: "far", Mode: "reverse",
		Link: "webrtc", PortHop: true, TwinPath: true,
		ServicePorts: "443", LinkPort: 24100, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(webrtc+hop+twin) failed: %v", err)
	}
	if rtcCombo.Transport != "webrtc" || rtcCombo.PortHop != "on" || rtcCombo.TwinPath != "on" || rtcCombo.Mux != "on" {
		t.Fatalf("unexpected webrtc+hop+twin spec: %+v", rtcCombo)
	}

	twinSpec, err := p.toSpec(createRequest{
		Name: "tw1", Relay: "this", Foreign: "far", Mode: "direct",
		Link: "twin", ServicePorts: "443", LinkPort: 24200, RelayIP: "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("toSpec(twin) failed: %v", err)
	}
	if twinSpec.Transport != "kcp" || twinSpec.TwinPath != "on" || twinSpec.Mux != "on" {
		t.Fatalf("unexpected twin spec: %+v", twinSpec)
	}

	// 2. Full create/join across Relay + Foreign for WebRTC and Twin-Path tunnels.
	rtcReq := newTunnel("voipcall")
	rtcReq.Mode = "direct"
	rtcReq.Link = "webrtc"
	rtcReq.LinkPort = 26100
	if v := waitJob(t, p, mustCreate(t, p, rtcReq)); v.Error != "" {
		t.Fatalf("creating webrtc tunnel failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	twinReq := newTunnel("twingame")
	twinReq.Mode = "direct"
	twinReq.Link = "twin"
	twinReq.ServicePorts = "2096"
	twinReq.UserPorts = "2096"
	twinReq.LinkPort = 26200
	if v := waitJob(t, p, mustCreate(t, p, twinReq)); v.Error != "" {
		t.Fatalf("creating twin tunnel failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edges, origins := agent.TunnelsReport(p.tunnelsDir), agent.TunnelsReport(foreignDir)
	if len(edges) != 2 || len(origins) != 2 {
		t.Fatalf("expected 2 tunnels on each side, got %+v / %+v", edges, origins)
	}
	byNameEdge := map[string]agent.TunnelInfo{}
	byNameOrig := map[string]agent.TunnelInfo{}
	for _, ti := range edges {
		byNameEdge[ti.Name] = ti
	}
	for _, ti := range origins {
		byNameOrig[ti.Name] = ti
	}
	if byNameEdge["voipcall"].Transport != "webrtc" || byNameOrig["voipcall"].Transport != "webrtc" {
		t.Fatalf("webrtc tunnel mismatch: edge=%+v origin=%+v", byNameEdge["voipcall"], byNameOrig["voipcall"])
	}
	if !byNameEdge["twingame"].TwinPath || !byNameOrig["twingame"].TwinPath || byNameEdge["twingame"].Transport != "kcp" {
		t.Fatalf("twin tunnel mismatch: edge=%+v origin=%+v", byNameEdge["twingame"], byNameOrig["twingame"])
	}

	// 3. Auto-Heal descriptions, matching, and failover candidate selection.
	if desc := describeTunnelInfo(byNameEdge["twingame"]); !strings.Contains(desc, "Twin-Path 1+1") {
		t.Fatalf("unexpected describeTunnelInfo for twin: %q", desc)
	}
	twinCand := engine.ProbeCandidateResult{
		ProbeCandidateSpec: engine.ProbeCandidateSpec{
			ID: "direct-twin-v4", Mode: "direct", Transport: "kcp", Link: "twin",
			TwinPath: true, Shared: true, Port: 26200,
		},
		Status: "ok", Score: 95,
	}
	kcpPlainInfo := agent.TunnelInfo{Name: "main", Mode: "direct", Transport: "kcp", LinkPort: 26200}
	if sameCandidateAsCurrent(twinCand, kcpPlainInfo) {
		t.Fatal("sameCandidateAsCurrent must distinguish TwinPath=true from plain KCP")
	}
	if !sameCandidateAsCurrent(twinCand, byNameEdge["twingame"]) {
		t.Fatal("sameCandidateAsCurrent should match Twin-Path tunnel against Twin-Path candidate")
	}
	if desc := describeCandidate(twinCand); !strings.Contains(desc, "Twin-Path 1+1") {
		t.Fatalf("unexpected describeCandidate for twin: %q", desc)
	}
	rtcCand := engine.ProbeCandidateResult{
		ProbeCandidateSpec: engine.ProbeCandidateSpec{
			ID: "direct-webrtc-v4", Mode: "direct", Transport: "webrtc", Link: "webrtc",
			Shared: true, Port: 26100,
		},
		Status: "ok", Score: 92,
	}
	rep := &engine.ProbeBenchmarkReport{Results: []engine.ProbeCandidateResult{twinCand, rtcCand}}
	best, ok := p.healer.pickBestCandidate(rep, byNameEdge["twingame"], false)
	if !ok || best.ID != "direct-webrtc-v4" {
		t.Fatalf("expected unhealthy twin tunnel to fail over to webrtc candidate, got ok=%v best=%+v", ok, best)
	}
}

func TestSwitchTunnelPreservesSecretAndUpdatesBothHalvesAtomically(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)
	_ = foreignID

	// 1. Create an initial Direct Fake TLS tunnel on bridge port 27443.
	initReq := newTunnel("hotswap")
	initReq.Mode = "direct"
	initReq.Link = "website"
	initReq.ServerName = "www.bing.com"
	initReq.ServicePorts = "39100"
	initReq.UserPorts = "29100"
	initReq.LinkPort = 27443
	if v := waitJob(t, p, mustCreate(t, p, initReq)); v.Error != "" {
		t.Fatalf("initial create failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge0 := agent.TunnelsReport(p.tunnelsDir)
	orig0 := agent.TunnelsReport(foreignDir)
	if len(edge0) != 1 || len(orig0) != 1 || edge0[0].PairID == "" || edge0[0].PairID != orig0[0].PairID {
		t.Fatalf("initial pair mismatch: edge=%+v orig=%+v", edge0, orig0)
	}
	pairID := edge0[0].PairID

	// 2. Switch in-place to Reverse WebRTC on the same bridge port (27443).
	sw1 := initReq
	sw1.Mode = "reverse"
	sw1.Link = "webrtc"
	sw1.Shared = true
	sw1.SharedLinks = 4
	sw1.AutoHeal = true
	job1, err := p.startSwitchTunnel(sw1)
	if err != nil {
		t.Fatalf("startSwitchTunnel (webrtc): %v", err)
	}
	if v := waitJob(t, p, job1); v.Error != "" {
		t.Fatalf("switch to webrtc failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge1 := agent.TunnelsReport(p.tunnelsDir)
	orig1 := agent.TunnelsReport(foreignDir)
	if len(edge1) != 1 || len(orig1) != 1 {
		t.Fatalf("expected 1 tunnel after switch, got %d / %d", len(edge1), len(orig1))
	}
	if edge1[0].PairID != pairID || orig1[0].PairID != pairID {
		t.Fatalf("PairID changed across mode switch: want %s, got edge=%s orig=%s", pairID, edge1[0].PairID, orig1[0].PairID)
	}
	if edge1[0].Mode != "reverse" || orig1[0].Mode != "reverse" || edge1[0].Transport != "webrtc" || orig1[0].Transport != "webrtc" {
		t.Fatalf("expected reverse webrtc on both halves, got edge=%+v orig=%+v", edge1[0], orig1[0])
	}

	// 3. Switch in-place again from Reverse WebRTC -> Direct SplitHTTP CDN on port 2053.
	sw2 := initReq
	sw2.Mode = "direct"
	sw2.Link = "xhttp-cdn"
	sw2.Domain = "edge1.example.com"
	sw2.LinkPort = 2053
	sw2.Shared = true
	sw2.SharedLinks = 6
	sw2.AutoHeal = true
	job2, err := p.startSwitchTunnel(sw2)
	if err != nil {
		t.Fatalf("startSwitchTunnel (xhttp-cdn): %v", err)
	}
	if v := waitJob(t, p, job2); v.Error != "" {
		t.Fatalf("switch to xhttp-cdn failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge2 := agent.TunnelsReport(p.tunnelsDir)
	orig2 := agent.TunnelsReport(foreignDir)
	if edge2[0].PairID != pairID || orig2[0].PairID != pairID {
		t.Fatalf("PairID changed across second switch: want %s, got edge=%s orig=%s", pairID, edge2[0].PairID, orig2[0].PairID)
	}
	if edge2[0].Mode != "direct" || orig2[0].Mode != "direct" || edge2[0].Transport != "xhttp" || !edge2[0].CDN || !orig2[0].CDN || orig2[0].LinkPort != 2053 {
		t.Fatalf("expected direct xhttp-cdn on port 2053, got edge=%+v orig=%+v", edge2[0], orig2[0])
	}

	// Auto-Heal state should store CDN domain and manual switch history.
	st := p.store.get()
	ahCfg, ok := st.AutoHeal[healKeyFor("this", "hotswap")]
	if !ok || !ahCfg.Enabled || ahCfg.CDNDomain != "edge1.example.com" || len(ahCfg.History) < 2 {
		t.Fatalf("expected AutoHeal config & history to be updated, got ok=%v cfg=%+v", ok, ahCfg)
	}
	if ahCfg.History[0].Reason != "manual mode switch" || !ahCfg.History[0].Success {
		t.Fatalf("expected latest history entry to be successful manual mode switch, got %+v", ahCfg.History[0])
	}

	// 4. Switching onto a port owned by a DIFFERENT tunnel must still be rejected.
	other := newTunnel("other")
	other.Mode = "direct"
	other.LinkPort = 28443
	other.ServicePorts = "39200"
	other.UserPorts = "29200"
	if v := waitJob(t, p, mustCreate(t, p, other)); v.Error != "" {
		t.Fatalf("creating second tunnel failed: %s", v.Error)
	}
	clashSwitch := sw2
	clashSwitch.Link = "website"
	clashSwitch.LinkPort = 28443
	job3, err := p.startSwitchTunnel(clashSwitch)
	if err != nil {
		t.Fatalf("startSwitchTunnel (clash): %v", err)
	}
	if v := waitJob(t, p, job3); v.Error == "" || !strings.Contains(v.Error, "28443") {
		t.Fatalf("expected port clash on 28443 to be rejected, got error=%q", v.Error)
	}
}
