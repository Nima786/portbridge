package panel

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

func TestCloudflareCleanIPScanAndApplyEndpoints(t *testing.T) {
	p, foreignID, _ := twoServers(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	if b.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}

	// 1. Pre-tunnel Clean-IP scan using ephemeral ProbeListener on Foreign + Relay agent dialer.
	code, out, _ := b.do(http.MethodPost, "/api/probe/cf-scan", map[string]any{
		"relay":      "this",
		"foreign":    foreignID,
		"domain":     "edge1.example.com",
		"transport":  "xhttp-cdn",
		"candidates": []string{"127.0.0.1"},
		"max_select": 3,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/probe/cf-scan answered %d: %v", code, out)
	}
	repMap, _ := out["report"].(map[string]any)
	if repMap == nil {
		t.Fatalf("missing report in response: %v", out)
	}
	recAny, _ := repMap["recommended"].([]any)
	if len(recAny) != 1 || recAny[0] != "127.0.0.1" {
		t.Fatalf("unexpected recommended Clean IPs: %v", recAny)
	}

	// 2. Create a CDN tunnel with initial CleanIPs and verify TunnelInfo.CleanIPs.
	jobID, err := p.startCreate(createRequest{
		Name:         "cfmain",
		Relay:        "this",
		Foreign:      foreignID,
		Mode:         "direct",
		Link:         "cdn",
		Domain:       "edge1.example.com",
		CleanIPs:     "104.16.12.50, 172.67.18.90",
		ServicePorts: "39101",
		UserPorts:    "29101",
		LinkPort:     2053,
		RelayIP:      "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("startCreate(cfmain): %v", err)
	}
	if v := waitJob(t, p, jobID); v.Error != "" {
		t.Fatalf("cfmain creation failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edgeRep := agent.TunnelsReport(p.tunnelsDir)
	if len(edgeRep) != 1 || !slices.Equal(edgeRep[0].CleanIPs, []string{"104.16.12.50", "172.67.18.90"}) {
		t.Fatalf("expected initial CleanIPs on edge report, got %+v", edgeRep)
	}

	// 3. Hot-apply new Clean IPs via POST /api/tunnels/clean-ips.
	code, out, _ = b.do(http.MethodPost, "/api/tunnels/clean-ips", map[string]any{
		"name":      "cfmain",
		"edge":      "this",
		"clean_ips": "162.159.36.44, 198.41.200.55",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/tunnels/clean-ips answered %d: %v", code, out)
	}
	edgeRep = agent.TunnelsReport(p.tunnelsDir)
	if !slices.Equal(edgeRep[0].CleanIPs, []string{"162.159.36.44", "198.41.200.55"}) {
		t.Fatalf("CleanIPs after hot-apply = %v, want [162.159.36.44 198.41.200.55]", edgeRep[0].CleanIPs)
	}

	// 4. Clear Clean IPs via POST /api/tunnels/clean-ips with empty string.
	code, out, _ = b.do(http.MethodPost, "/api/tunnels/clean-ips", map[string]any{
		"name":      "cfmain",
		"edge":      "this",
		"clean_ips": "",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("clearing Clean IPs answered %d: %v", code, out)
	}
	edgeRep = agent.TunnelsReport(p.tunnelsDir)
	if len(edgeRep[0].CleanIPs) != 0 {
		t.Fatalf("expected CleanIPs to be cleared, got %v", edgeRep[0].CleanIPs)
	}

	// 5. Verify website-cdn-backup carries CleanIPs too.
	jobID2, err := p.startCreate(createRequest{
		Name:         "cfbkp",
		Relay:        "this",
		Foreign:      foreignID,
		Mode:         "direct",
		Link:         "website-cdn-backup",
		Domain:       "bkp.example.com",
		CleanIPs:     "104.21.11.77",
		ServicePorts: "39102",
		UserPorts:    "29102",
		LinkPort:     2083,
		RelayIP:      "198.51.100.1",
	})
	if err != nil {
		t.Fatalf("startCreate(cfbkp): %v", err)
	}
	if v := waitJob(t, p, jobID2); v.Error != "" {
		t.Fatalf("cfbkp creation failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	bkpConf, err := os.ReadFile(filepath.Join(p.tunnelsDir, "cfbkp.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bkpConf), "clean_ips = 104.21.11.77") {
		t.Fatalf("website-cdn-backup conf missing clean_ips:\n%s", string(bkpConf))
	}
}

func TestCloudflareCleanIPAutoHealRotation(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)

	jobID, err := p.startCreate(createRequest{
		Name:         "cfheal",
		Relay:        "this",
		Foreign:      foreignID,
		Mode:         "direct",
		Link:         "xhttp-cdn",
		Domain:       "heal.example.com",
		CleanIPs:     "104.16.12.50",
		ServicePorts: "39201",
		UserPorts:    "29201",
		LinkPort:     2053,
		RelayIP:      "198.51.100.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := waitJob(t, p, jobID); v.Error != "" {
		t.Fatalf("cfheal create failed: %s", v.Error)
	}

	// Point status_file in both test .conf files at their temp dirs and write a blocked status.
	nowStr := time.Now().UTC().Format(time.RFC3339)
	blockedJSON := `{"uptime_seconds":120,"path_state":"blocked","path_note":"CDN edge timeout","links":0,"updated_at":"` + nowStr + `"}`
	for _, dir := range []string{p.tunnelsDir, foreignDir} {
		stPath := filepath.Join(dir, "cfheal.status")
		if err := os.WriteFile(stPath, []byte(blockedJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		confPath := filepath.Join(dir, "cfheal.conf")
		rawConf, err := os.ReadFile(confPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(confPath, append(rawConf, []byte("\nstatus_file = "+stPath+"\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p.refreshOne("this")
	p.refreshOne(foreignID)

	key := healKeyFor("this", "cfheal")
	_ = p.store.update(func(s *State) error {
		if s.AutoHeal == nil {
			s.AutoHeal = map[string]AutoHealConfig{}
		}
		s.AutoHeal[key] = AutoHealConfig{Enabled: true, CDNDomain: "heal.example.com"}
		return nil
	})

	probeCalled := false
	p.healer.probeFn = func(_ context.Context, _, _, _ string) (*engine.ProbeBenchmarkReport, error) {
		probeCalled = true
		return nil, nil
	}
	p.healer.cfScanFn = func(_ context.Context, req cfScanPanelRequest) (*engine.CFScanReport, error) {
		return &engine.CFScanReport{
			Domain:        req.Domain,
			Port:          req.Port,
			Transport:     req.Transport,
			ScannedCount:  44,
			PassedStage1:  6,
			VerifiedCount: 2,
			Recommended:   []string{"188.114.97.42", "198.41.209.18"},
			Results: []engine.CFScanResult{
				{IP: "188.114.97.42", Status: "ok", Selected: true, Score: 92},
				{IP: "198.41.209.18", Status: "ok", Selected: true, Score: 88},
			},
		}, nil
	}

	if err := p.healer.healTunnel(context.Background(), nil, key, "cfheal", "this", foreignID, "heal.example.com", "CDN edge timeout", false); err != nil {
		t.Fatalf("healTunnel failed: %v", err)
	}
	if probeCalled {
		t.Fatal("expected Stage-0 Clean-IP rotation to succeed without invoking full 19-mode probe")
	}

	edgeRep := agent.TunnelsReport(p.tunnelsDir)
	if len(edgeRep) != 1 || !slices.Equal(edgeRep[0].CleanIPs, []string{"188.114.97.42", "198.41.209.18"}) {
		t.Fatalf("expected rotated CleanIPs on Relay, got %+v", edgeRep)
	}
	hist := p.store.get().AutoHeal[key].History
	if len(hist) != 1 || hist[0].Candidate != "cf-clean-rotate" || !hist[0].Success {
		t.Fatalf("expected cf-clean-rotate history entry, got %+v", hist)
	}
}
