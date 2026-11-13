package panel

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/agent"
)

func TestPanelAbuseShieldAndClientGuardEndpoints(t *testing.T) {
	p, foreignID, _ := twoServers(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	if b.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}

	// 1. Enable Outbound Abuse Shield on Foreign server via panel API.
	code, fwOut, _ := b.do(http.MethodPost, "/api/servers/"+foreignID+"/firewall", map[string]any{
		"action":        "abuse-on",
		"block_torrent": true,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/servers/%s/firewall(abuse-on) answered %d: %v", foreignID, code, fwOut)
	}
	if fwOut["abuse_shield_active"] != true || fwOut["abuse_block_torrent"] != true {
		t.Fatalf("expected abuse_shield_active=true & abuse_block_torrent=true, got: %v", fwOut)
	}

	// Toggle BitTorrent off while keeping Netscan shield active.
	code, fwOut, _ = b.do(http.MethodPost, "/api/servers/"+foreignID+"/firewall", map[string]any{
		"action":        "abuse-on",
		"block_torrent": false,
	}, nil)
	if code != http.StatusOK || fwOut["abuse_shield_active"] != true || fwOut["abuse_block_torrent"] != false {
		t.Fatalf("expected abuse_block_torrent=false while active, got (%d): %v", code, fwOut)
	}

	// Disable Outbound Abuse Shield.
	code, fwOut, _ = b.do(http.MethodPost, "/api/servers/"+foreignID+"/firewall", map[string]any{
		"action": "abuse-off",
	}, nil)
	if code != http.StatusOK || fwOut["abuse_shield_active"] != false {
		t.Fatalf("expected abuse_shield_active=false after abuse-off, got (%d): %v", code, fwOut)
	}

	// 2. Create tunnel with per-IP connection & rate guard.
	jobID, err := p.startCreate(createRequest{
		Name:         "hetznertun",
		Relay:        "this",
		Foreign:      foreignID,
		Mode:         "direct",
		Link:         "website",
		ServerName:   "www.bing.com",
		ServicePorts: "39201",
		UserPorts:    "29201",
		LinkPort:     2053,
		RelayIP:      "198.51.100.1",
		MaxConnPerIP: 128,
		MaxRatePerIP: 30,
	})
	if err != nil {
		t.Fatalf("startCreate(hetznertun): %v", err)
	}
	if v := waitJob(t, p, jobID); v.Error != "" {
		t.Fatalf("hetznertun creation failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	// 3. Query /api/tunnels/clients and verify initial guard rules.
	code, clOut, _ := b.do(http.MethodPost, "/api/tunnels/clients", map[string]any{
		"name":   "hetznertun",
		"edge":   "this",
		"origin": foreignID,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/tunnels/clients answered %d: %v", code, clOut)
	}
	if int(clOut["max_per_ip"].(float64)) != 128 || int(clOut["rate_per_ip"].(float64)) != 30 {
		t.Fatalf("unexpected initial client guard limits: %v", clOut)
	}

	// 4. Block a scanner IP via /api/tunnels/client-guard.
	code, clOut, _ = b.do(http.MethodPost, "/api/tunnels/client-guard", map[string]any{
		"name":     "hetznertun",
		"edge":     "this",
		"block_ip": "198.51.100.77",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/tunnels/client-guard(block) answered %d: %v", code, clOut)
	}
	edgeRep := agent.TunnelsReport(p.tunnelsDir)
	if len(edgeRep) != 1 || !slices.Equal(edgeRep[0].BlockedIPs, []string{"198.51.100.77"}) {
		t.Fatalf("expected BlockedIPs=[198.51.100.77], got %+v", edgeRep)
	}

	// 5. Unblock the IP and update limits via /api/tunnels/client-guard.
	code, clOut, _ = b.do(http.MethodPost, "/api/tunnels/client-guard", map[string]any{
		"name":        "hetznertun",
		"edge":        "this",
		"unblock_ip":  "198.51.100.77",
		"max_per_ip":  64,
		"rate_per_ip": 20,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/tunnels/client-guard(unblock+limits) answered %d: %v", code, clOut)
	}
	edgeRep = agent.TunnelsReport(p.tunnelsDir)
	if len(edgeRep[0].BlockedIPs) != 0 || edgeRep[0].MaxConnPerIP != 64 || edgeRep[0].MaxRatePerIP != 20 {
		t.Fatalf("unexpected guard config after update: %+v", edgeRep[0])
	}
}
