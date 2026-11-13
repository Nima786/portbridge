package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAgentAbuseShieldAndClientGuard(t *testing.T) {
	base := t.TempDir()
	confDir := filepath.Join(base, "tunnels")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	host := &recordingHost{activeAfter: true}
	withHost(t, host)

	// 1. Outbound Abuse Shield lifecycle (torrent=true, torrent=false, off).
	torTrue := true
	fw, err := applyFirewallAction(confDir, "abuse-on", &torTrue)
	if err != nil {
		t.Fatalf("applyFirewallAction(abuse-on, true): %v", err)
	}
	if !fw.AbuseShieldActive || !fw.AbuseBlockTorrent || !host.did("abuse:true:true") {
		t.Fatalf("unexpected firewall state after abuse-on(true): %+v, calls=%v", fw, host.calls)
	}
	rawConf, err := os.ReadFile(abuseShieldConfPath(confDir))
	if err != nil {
		t.Fatalf("read abuse-shield.conf: %v", err)
	}
	if !strings.Contains(string(rawConf), "enabled = on") || !strings.Contains(string(rawConf), "block_torrent = on") {
		t.Fatalf("abuse-shield.conf does not match helper format:\n%s", string(rawConf))
	}
	ov := LocalOverview(confDir)
	if !ov.AbuseShieldActive || !ov.AbuseBlockTorrent {
		t.Fatalf("LocalOverview did not report active abuse shield: %+v", ov)
	}

	torFalse := false
	fw, err = applyFirewallAction(confDir, "abuse-on", &torFalse)
	if err != nil {
		t.Fatalf("applyFirewallAction(abuse-on, false): %v", err)
	}
	if !fw.AbuseShieldActive || fw.AbuseBlockTorrent || !host.did("abuse:true:false") {
		t.Fatalf("unexpected firewall state after abuse-on(false): %+v, calls=%v", fw, host.calls)
	}

	fw, err = applyFirewallAction(confDir, "abuse-off", nil)
	if err != nil {
		t.Fatalf("applyFirewallAction(abuse-off): %v", err)
	}
	if fw.AbuseShieldActive || !host.did("abuse:false:false") {
		t.Fatalf("expected abuse shield disabled: %+v, calls=%v", fw, host.calls)
	}

	// 2. Create Edge tunnel with per-IP guard rules and verify TunnelsReport + UpdateClientGuard.
	spec := EdgeSpec{
		Name:         "guardtun",
		Mode:         "direct",
		Transport:    "plain",
		PeerIP:       "203.0.113.5",
		LocalIP:      "198.51.100.1",
		LinkPort:     2053,
		UserPorts:    "29311",
		ServicePorts: "39001",
		MaxConnPerIP: 128,
		MaxRatePerIP: 30,
		BlockedIPs:   "198.51.100.7, 203.0.113.0/24",
	}
	if _, err := CreateEdge(spec, confDir); err != nil {
		t.Fatalf("CreateEdge: %v", err)
	}

	repList := TunnelsReport(confDir)
	if len(repList) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(repList))
	}
	ti := repList[0]
	if ti.MaxConnPerIP != 128 || ti.MaxRatePerIP != 30 || !slices.Equal(ti.BlockedIPs, []string{"198.51.100.7", "203.0.113.0/24"}) {
		t.Fatalf("unexpected TunnelInfo guard fields: %+v", ti)
	}

	insp, err := ReadClientInspector(confDir, "guardtun")
	if err != nil {
		t.Fatalf("ReadClientInspector: %v", err)
	}
	if insp.MaxConnPerIP != 128 || insp.MaxRatePerIP != 30 || len(insp.BlockedIPs) != 2 {
		t.Fatalf("unexpected ReadClientInspector report: %+v", insp)
	}

	// Block an additional IP and raise MaxConnPerIP via UpdateClientGuard.
	newMax := 200
	insp, err = UpdateClientGuard(confDir, ClientGuardUpdateRequest{
		Name:         "guardtun",
		MaxConnPerIP: &newMax,
		BlockIP:      "192.0.2.99",
	})
	if err != nil {
		t.Fatalf("UpdateClientGuard(block): %v", err)
	}
	if insp.MaxConnPerIP != 200 || !slices.Contains(insp.BlockedIPs, "192.0.2.99") {
		t.Fatalf("expected 192.0.2.99 blocked and max_per_ip=200: %+v", insp)
	}

	// Unblock 198.51.100.7.
	insp, err = UpdateClientGuard(confDir, ClientGuardUpdateRequest{
		Name:      "guardtun",
		UnblockIP: "198.51.100.7",
	})
	if err != nil {
		t.Fatalf("UpdateClientGuard(unblock): %v", err)
	}
	if slices.Contains(insp.BlockedIPs, "198.51.100.7") {
		t.Fatalf("expected 198.51.100.7 unblocked: %+v", insp.BlockedIPs)
	}
}
