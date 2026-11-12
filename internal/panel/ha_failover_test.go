package panel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

func TestUDPForwardProtoCreateEditAndSwitch(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)

	// 1. Create a tunnel with forward_proto = "both" (TCP + UDP).
	req := newTunnel("wgdual")
	req.ForwardProto = "both"
	if v := waitJob(t, p, mustCreate(t, p, req)); v.Error != "" {
		t.Fatalf("create failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edgeRep := agent.TunnelsReport(p.tunnelsDir)
	origRep := agent.TunnelsReport(foreignDir)
	if len(edgeRep) != 1 || len(origRep) != 1 {
		t.Fatalf("expected 1 tunnel on each server, got %+v / %+v", edgeRep, origRep)
	}
	if edgeRep[0].ForwardProto != "both" || origRep[0].ForwardProto != "both" {
		t.Fatalf("expected forward_proto=both on both halves, got edge=%q origin=%q",
			edgeRep[0].ForwardProto, origRep[0].ForwardProto)
	}

	// 2. Edit the tunnel to forward_proto = "udp" (UDP only).
	editID, err := p.startEditTunnel(editTunnelRequest{
		Name:         "wgdual",
		Edge:         "this",
		Origin:       foreignID,
		ServicePorts: "39001",
		UserPorts:    "29311",
		LinkPort:     2217,
		ForwardProto: "udp",
		Pool:         25,
		MaxConn:      2000,
	})
	if err != nil {
		t.Fatalf("startEditTunnel: %v", err)
	}
	if v := waitJob(t, p, editID); v.Error != "" {
		t.Fatalf("edit to udp failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edgeRep = agent.TunnelsReport(p.tunnelsDir)
	origRep = agent.TunnelsReport(foreignDir)
	if edgeRep[0].ForwardProto != "udp" || origRep[0].ForwardProto != "udp" {
		t.Fatalf("expected forward_proto=udp after edit, got edge=%q origin=%q",
			edgeRep[0].ForwardProto, origRep[0].ForwardProto)
	}

	// 3. Switch transport mode while keeping forward_proto = "udp".
	swReq := req
	swReq.Mode = "direct"
	swReq.Link = "xhttp"
	swReq.LinkPort = 2053
	swReq.ForwardProto = "udp"
	swID, err := p.startSwitchTunnel(swReq)
	if err != nil {
		t.Fatalf("startSwitchTunnel: %v", err)
	}
	if v := waitJob(t, p, swID); v.Error != "" {
		t.Fatalf("switchTunnel failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edgeRep = agent.TunnelsReport(p.tunnelsDir)
	origRep = agent.TunnelsReport(foreignDir)
	if edgeRep[0].Transport != "xhttp" || edgeRep[0].ForwardProto != "udp" || origRep[0].ForwardProto != "udp" {
		t.Fatalf("expected xhttp + udp after switch, got edge=%+v origin=%+v", edgeRep[0], origRep[0])
	}

	// 4. Edit back to default "tcp" and ensure forward_proto is omitted from .conf.
	editBackID, err := p.startEditTunnel(editTunnelRequest{
		Name:         "wgdual",
		Edge:         "this",
		Origin:       foreignID,
		ServicePorts: "39001",
		UserPorts:    "29311",
		LinkPort:     2053,
		ForwardProto: "tcp",
		Mux:          "on",
		MuxLinks:     4,
		MaxConn:      2000,
	})
	if err != nil {
		t.Fatalf("startEditTunnel back to tcp: %v", err)
	}
	if v := waitJob(t, p, editBackID); v.Error != "" {
		t.Fatalf("edit back to tcp failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	confBytes, _ := os.ReadFile(filepath.Join(p.tunnelsDir, "wgdual.conf"))
	if strings.Contains(string(confBytes), "forward_proto") {
		t.Fatalf("expected forward_proto key to be dropped on default tcp config, got:\n%s", string(confBytes))
	}
}

func TestBackupForeignServerHAFailoverAndFailback(t *testing.T) {
	p := newTestPanel(t)
	_ = p.store.update(func(s *State) error {
		s.ThisGroup = GroupRelay
		s.ThisName = "Iran-Relay"
		return nil
	})

	// Primary Foreign server ("f1") with a toggleable offline switch so we can
	// simulate complete datacenter outage and later recovery.
	const tok1 = "pba_primary"
	dir1 := t.TempDir()
	var f1Offline atomic.Bool
	baseHandler1 := agent.NewHandler(tok1, dir1, nil)
	srv1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f1Offline.Load() {
			hj, ok := w.(http.Hijacker)
			if ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			http.Error(w, "offline", http.StatusBadGateway)
			return
		}
		baseHandler1.ServeHTTP(w, r)
	}))
	t.Cleanup(srv1.Close)

	// Standby Foreign server ("f2") —Added AFTER f1 so f1 appears earlier in servers list!
	const tok2 = "pba_standby"
	dir2 := t.TempDir()
	srv2 := httptest.NewTLSServer(agent.NewHandler(tok2, dir2, nil))
	t.Cleanup(srv2.Close)

	s1 := addTestServer(t, p, Server{
		ID: "f1", Name: "Germany-Primary", Group: GroupForeign, Address: "203.0.113.10",
		AgentURL: srv1.URL, Fingerprint: fingerprintOf(srv1.Certificate().Raw),
	}, tok1)
	s2 := addTestServer(t, p, Server{
		ID: "f2", Name: "Finland-Backup", Group: GroupForeign, Address: "198.51.100.20",
		AgentURL: srv2.URL, Fingerprint: fingerprintOf(srv2.Certificate().Raw),
	}, tok2)
	p.fleet.refresh(s1)
	p.fleet.refresh(s2)

	// Stub benchmark hook so failover/failback tests run deterministically in milliseconds.
	p.healer.probeFn = func(_ context.Context, _, foreignID, cdnDomain string) (*engine.ProbeBenchmarkReport, error) {
		if foreignID == "f1" && f1Offline.Load() {
			return nil, errors.New("primary foreign unreachable")
		}
		// Ensure CDN domain is NOT used when failing over to Standby Foreign!
		if foreignID == "f2" && cdnDomain != "" {
			t.Errorf("expected empty cdnDomain when probing Standby Foreign f2, got %q", cdnDomain)
		}
		return &engine.ProbeBenchmarkReport{
			Results: []engine.ProbeCandidateResult{
				{
					ProbeCandidateSpec: engine.ProbeCandidateSpec{
						ID:        "direct-xhttp-v4",
						Label:     "Direct · SplitHTTP / XHTTP",
						Mode:      "direct",
						Transport: "xhttp",
						Stealth:   true,
						Shared:    true,
						Port:      2053,
					},
					Status:    "ok",
					Score:     94,
					Successes: 1,
					Summary:   "Healthy 94/100",
				},
			},
		}, nil
	}

	// Create UDP+TCP tunnel on (this -> f1).
	req := createRequest{
		Name: "mainvpn", Relay: "this", Foreign: "f1", Mode: "direct", Link: "website",
		ServerName: "www.bing.com", ServicePorts: "443", UserPorts: "443", LinkPort: 8443,
		ForwardProto: "both", RelayIP: "198.51.100.1",
	}
	if v := waitJob(t, p, mustCreate(t, p, req)); v.Error != "" {
		t.Fatalf("create mainvpn: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	// Configure Auto-Heal with Backup Foreign Server = "f2" and a CDN domain for Primary.
	standbyID := "f2"
	if err := p.healer.setConfig("this", "mainvpn", true, "edge1.example.com", &standbyID); err != nil {
		t.Fatalf("setConfig standby f2: %v", err)
	}

	// Reject setting Primary as its own Standby.
	sameID := "f1"
	if err := p.healer.setConfig("this", "mainvpn", true, "", &sameID); err == nil {
		t.Fatalf("expected error when setting standby_foreign_id equal to primary_foreign_id")
	}

	// Simulate Primary Foreign ("f1") going completely offline!
	f1Offline.Store(true)
	p.fleet.refresh(s1)
	if v1, _ := p.viewOf("f1"); v1.Online {
		t.Fatalf("expected f1 to be marked offline")
	}

	ctx := context.Background()
	// Check 1: increments foreignDownCount (1/2) without migrating yet.
	p.healer.checkAll(ctx)
	if cfg := p.store.get().AutoHeal["this/mainvpn"]; cfg.OnStandby {
		t.Fatalf("should not fail over on 1st offline check")
	}

	// Check 2: reaches autoHealThreshold (2/2) and migrates tunnel to Standby Foreign ("f2")!
	p.healer.checkAll(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cfg := p.store.get().AutoHeal["this/mainvpn"]
		if cfg.OnStandby {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	cfg := p.store.get().AutoHeal["this/mainvpn"]
	if !cfg.OnStandby || cfg.PrimaryForeignID != "f1" || cfg.PendingCleanupForeignID != "f1" {
		t.Fatalf("unexpected AutoHealConfig after HA failover to Standby: %+v", cfg)
	}

	// Verify Origin half is now deployed on f2 with the same PairID and forward_proto=both!
	edgeRep := agent.TunnelsReport(p.tunnelsDir)
	f2Rep := agent.TunnelsReport(dir2)
	if len(edgeRep) != 1 || len(f2Rep) != 1 || edgeRep[0].PairID != f2Rep[0].PairID {
		t.Fatalf("tunnel not paired between Relay and Standby f2: edge=%+v f2=%+v", edgeRep, f2Rep)
	}
	if edgeRep[0].PeerIP != "198.51.100.20" || edgeRep[0].ForwardProto != "both" || f2Rep[0].ForwardProto != "both" {
		t.Fatalf("expected Relay PeerIP=198.51.100.20 and forward_proto=both on f2: edge=%+v f2=%+v", edgeRep[0], f2Rep[0])
	}

	// Verify filterAndAttachViews pairs Relay with online f2 AND hides offline f1's stale cached duplicate!
	visible := p.healer.filterAndAttachViews(pairTunnels(p.fleet.views()))
	if len(visible) != 1 {
		t.Fatalf("expected exactly 1 visible tunnel (no stale duplicate card), got %d: %+v", len(visible), visible)
	}
	if visible[0].Origin == nil || visible[0].Origin.ServerID != "f2" || visible[0].Stale {
		t.Fatalf("expected visible tunnel to be paired with online Standby f2, got %+v", visible[0])
	}
	if visible[0].AutoHeal == nil || !visible[0].AutoHeal.OnStandby || visible[0].AutoHeal.StandbyForeignName != "Finland-Backup" {
		t.Fatalf("expected AutoHeal view to show OnStandby on Finland-Backup, got %+v", visible[0].AutoHeal)
	}

	// Now bring Primary Foreign ("f1") back online and expire cooldown so failback can proceed!
	f1Offline.Store(false)
	p.fleet.refresh(s1)
	p.healer.mu.Lock()
	p.healer.runtimeOf("this/mainvpn").lastHeal = time.Now().Add(-3 * time.Minute)
	p.healer.mu.Unlock()

	// Check 1 after f1 recovery: cleanupPendingForeignHalves deletes stale half on f1, and primaryUpStreak = 1/3.
	p.healer.checkAll(ctx)
	if got := confs(dir1); len(got) != 0 {
		t.Fatalf("expected stale half on recovered f1 to be cleaned up immediately, got %v", got)
	}
	if p.store.get().AutoHeal["this/mainvpn"].PendingCleanupForeignID != "" {
		t.Fatalf("expected PendingCleanupForeignID to be cleared after cleanup")
	}

	// Check 2: primaryUpStreak = 2/3.
	p.healer.checkAll(ctx)
	if !p.store.get().AutoHeal["this/mainvpn"].OnStandby {
		t.Fatalf("should wait 3 consecutive online checks before failback")
	}

	// Check 3: primaryUpStreak = 3/3 -> triggers automatic failback to Primary Foreign ("f1")!
	p.healer.checkAll(ctx)
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !p.store.get().AutoHeal["this/mainvpn"].OnStandby {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	cfgAfter := p.store.get().AutoHeal["this/mainvpn"]
	if cfgAfter.OnStandby {
		t.Fatalf("expected OnStandby=false after automatic failback to Primary f1: %+v", cfgAfter)
	}
	// Verify tunnel is back on f1, deleted from Standby f2, and still preserves PairID + forward_proto=both!
	edgeAfter := agent.TunnelsReport(p.tunnelsDir)
	f1After := agent.TunnelsReport(dir1)
	f2After := agent.TunnelsReport(dir2)
	if len(f2After) != 0 {
		t.Fatalf("expected Standby f2 tunnel half to be removed after failback, got %+v", f2After)
	}
	if len(edgeAfter) != 1 || len(f1After) != 1 || edgeAfter[0].PairID != f1After[0].PairID {
		t.Fatalf("expected tunnel paired back on Primary f1: edge=%+v f1=%+v", edgeAfter, f1After)
	}
	if edgeAfter[0].PeerIP != "203.0.113.10" || edgeAfter[0].ForwardProto != "both" || f1After[0].ForwardProto != "both" {
		t.Fatalf("expected Relay PeerIP=203.0.113.10 and forward_proto=both after failback: edge=%+v f1=%+v", edgeAfter[0], f1After[0])
	}
}
