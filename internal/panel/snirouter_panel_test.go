package panel

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/agent"
)

func TestPanelSharedPortSNITunnelsAndPortCheck(t *testing.T) {
	p, foreignID, _ := twoServers(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	if b.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}

	// 1. Create two VPN tunnels + one Website Bridge all sharing user port 29443!
	for _, cr := range []createRequest{
		{
			Name:         "vpn-de",
			Relay:        "this",
			Foreign:      foreignID,
			Mode:         "direct",
			Link:         "website",
			ServerName:   "www.bing.com",
			ServicePorts: "39401",
			UserPorts:    "29443",
			LinkPort:     2053,
			RelayIP:      "198.51.100.1",
			RouteHosts:   "de.vpn.example.com",
		},
		{
			Name:         "vpn-nl",
			Relay:        "this",
			Foreign:      foreignID,
			Mode:         "direct",
			Link:         "website",
			ServerName:   "www.bing.com",
			ServicePorts: "39402",
			UserPorts:    "29443",
			LinkPort:     2083,
			RelayIP:      "198.51.100.1",
			RouteHosts:   "*.nl.vpn.example.com",
			RouteDefault: true,
		},
		{
			Name:           "wb-shop",
			Relay:          "this",
			Foreign:        foreignID,
			Mode:           "direct",
			Link:           "website",
			ServerName:     "www.bing.com",
			ServicePorts:   "39403",
			UserPorts:      "29443",
			LinkPort:       2087,
			RelayIP:        "198.51.100.1",
			WebsiteBridge:  true,
			WebsiteDomains: "shop.example.com",
		},
	} {
		jobID, err := p.startCreate(cr)
		if err != nil {
			t.Fatalf("startCreate(%s): %v", cr.Name, err)
		}
		if v := waitJob(t, p, jobID); v.Error != "" {
			t.Fatalf("%s creation failed: %s\n%s", cr.Name, v.Error, strings.Join(v.Lines, "\n"))
		}
	}

	// 2. Check /api/ports on "this" for port 29443 -> Shared=true with all 3 tunnels!
	code, portsOut, _ := b.do(http.MethodPost, "/api/ports", map[string]any{
		"server": "this",
		"ports":  "29443",
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /api/ports answered %d: %v", code, portsOut)
	}
	portsList, ok := portsOut["ports"].([]any)
	if !ok || len(portsList) != 1 {
		t.Fatalf("expected 1 port entry, got %v", portsOut)
	}
	p0 := portsList[0].(map[string]any)
	if p0["shared"] != true {
		t.Fatalf("expected port 29443 shared=true, got %v", p0)
	}
	rawTunnels, _ := p0["shared_tunnels"].([]any)
	var gotTunnels []string
	for _, rt := range rawTunnels {
		gotTunnels = append(gotTunnels, rt.(string))
	}
	for _, want := range []string{"vpn-de", "vpn-nl", "wb-shop"} {
		if !slices.Contains(gotTunnels, want) {
			t.Fatalf("expected shared_tunnels %v to contain %q", gotTunnels, want)
		}
	}

	// 3. Edit vpn-de's route_hosts via /api/tunnels/edit and verify report reflects it.
	code, editOut, _ := b.do(http.MethodPost, "/api/tunnels/edit", map[string]any{
		"name":               "vpn-de",
		"edge":               "this",
		"origin":             foreignID,
		"user_ports":         "29443",
		"service_ports":      "39401",
		"link_port":          2053,
		"route_hosts":        "fr.vpn.example.com, uk.vpn.example.com",
		"update_route_hosts": true,
		"route_default":      "off",
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("POST /api/tunnels/edit answered %d: %v", code, editOut)
	}
	if v := waitJob(t, p, editOut["job"].(string)); v.Error != "" {
		t.Fatalf("edit vpn-de failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edgeRep := agent.TunnelsReport(p.tunnelsDir)
	var sawDE, sawNL bool
	for _, ti := range edgeRep {
		switch ti.Name {
		case "vpn-de":
			sawDE = true
			if ti.RouteHosts != "fr.vpn.example.com, uk.vpn.example.com" || !ti.SharedPort {
				t.Fatalf("unexpected vpn-de report after edit: %+v", ti)
			}
		case "vpn-nl":
			sawNL = true
			if !ti.RouteDefault || !ti.SharedPort {
				t.Fatalf("unexpected vpn-nl report: %+v", ti)
			}
		}
	}
	if !sawDE || !sawNL {
		t.Fatalf("missing tunnels in edge report: %+v", edgeRep)
	}
}
