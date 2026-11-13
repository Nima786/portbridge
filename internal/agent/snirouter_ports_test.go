package agent

import (
	"slices"
	"strings"
	"testing"
)

func TestSharedUserPortCreateEditAndReport(t *testing.T) {
	oldLocal := hasLocalAddress
	hasLocalAddress = func(string) bool { return true }
	t.Cleanup(func() { hasLocalAddress = oldLocal })

	relayDir := t.TempDir()

	// 1. Create a Website Bridge on :80,:443 for shop.example.com
	resShop, err := CreateEdge(EdgeSpec{
		Name:           "wb-shop",
		Mode:           "direct",
		Transport:      "tls",
		ServerName:     "www.bing.com",
		PeerIP:         "203.0.113.10",
		LocalIP:        "198.51.100.10",
		ServicePorts:   "80,443",
		UserPorts:      "80,443",
		LinkPort:       8443,
		Mux:            "on",
		MuxLinks:       4,
		WebsiteBridge:  "on",
		WebsiteDomains: "shop.example.com",
	}, relayDir)
	if err != nil || !resShop.OK {
		t.Fatalf("expected Website Bridge wb-shop on :80,:443 to succeed: err=%v res=%+v", err, resShop)
	}

	// 2. Create an SNI-routed VPN tunnel sharing :443 for de.vpn.example.com
	resDE, err := CreateEdge(EdgeSpec{
		Name:         "vpn-de",
		Mode:         "direct",
		Transport:    "tls",
		ServerName:   "www.bing.com",
		PeerIP:       "203.0.113.11",
		LocalIP:      "198.51.100.10",
		ServicePorts: "2053",
		UserPorts:    "443",
		LinkPort:     8444,
		Mux:          "on",
		MuxLinks:     4,
		RouteHosts:   "de.vpn.example.com",
	}, relayDir)
	if err != nil || !resDE.OK {
		t.Fatalf("expected SNI-routed tunnel vpn-de sharing :443 to succeed: err=%v res=%+v", err, resDE)
	}

	// 3. Create a wildcard + Default Fallback VPN tunnel sharing :443
	resWild, err := CreateEdge(EdgeSpec{
		Name:         "vpn-wild",
		Mode:         "direct",
		Transport:    "tls",
		ServerName:   "www.bing.com",
		PeerIP:       "203.0.113.12",
		LocalIP:      "198.51.100.10",
		ServicePorts: "2083",
		UserPorts:    "443",
		LinkPort:     8445,
		Mux:          "on",
		MuxLinks:     4,
		RouteHosts:   "*.vpn.example.com",
		RouteDefault: "on",
	}, relayDir)
	if err != nil || !resWild.OK {
		t.Fatalf("expected wildcard + default tunnel vpn-wild sharing :443 to succeed: err=%v res=%+v", err, resWild)
	}

	// Verify portReport marks :443 as Shared with all 3 tunnels and domains listed.
	rep := portReport(relayDir, []int{80, 443, 8443}, noHost{})
	byPort := map[int]portStatus{}
	for _, p := range rep {
		byPort[p.Port] = p
	}
	p443 := byPort[443]
	if !p443.Shared {
		t.Fatalf("expected port 443 to report Shared=true, got %+v", p443)
	}
	for _, wantTun := range []string{"wb-shop", "vpn-de", "vpn-wild"} {
		if !slices.Contains(p443.SharedTunnels, wantTun) {
			t.Fatalf("expected port 443 SharedTunnels %v to include %q", p443.SharedTunnels, wantTun)
		}
	}

	// 4. Reject an exclusive (non-routed) tunnel trying to grab :443
	resExcl, err := CreateEdge(EdgeSpec{
		Name:         "vpn-excl",
		Mode:         "direct",
		Transport:    "plain",
		PeerIP:       "203.0.113.13",
		LocalIP:      "198.51.100.10",
		ServicePorts: "443",
		UserPorts:    "443",
		LinkPort:     8446,
	}, relayDir)
	if resExcl.OK || err == nil || !strings.Contains(err.Error(), "SNI/Host routing") {
		t.Fatalf("expected exclusive tunnel on shared :443 to be rejected, got err=%v res=%+v", err, resExcl)
	}

	// 5. Reject duplicate domain pattern on :443
	resDupDom, err := CreateEdge(EdgeSpec{
		Name:         "vpn-dup",
		Mode:         "direct",
		Transport:    "plain",
		PeerIP:       "203.0.113.14",
		LocalIP:      "198.51.100.10",
		ServicePorts: "443",
		UserPorts:    "443",
		LinkPort:     8447,
		RouteHosts:   "de.vpn.example.com",
	}, relayDir)
	if resDupDom.OK || err == nil || !strings.Contains(err.Error(), "de.vpn.example.com") {
		t.Fatalf("expected duplicate SNI domain on :443 to be rejected, got err=%v res=%+v", err, resDupDom)
	}

	// 6. Reject a second route_default = on on :443
	resDupDef, err := CreateEdge(EdgeSpec{
		Name:         "vpn-def2",
		Mode:         "direct",
		Transport:    "plain",
		PeerIP:       "203.0.113.15",
		LocalIP:      "198.51.100.10",
		ServicePorts: "443",
		UserPorts:    "443",
		LinkPort:     8448,
		RouteDefault: "on",
	}, relayDir)
	if resDupDef.OK || err == nil || !strings.Contains(err.Error(), "default fallback") {
		t.Fatalf("expected second default fallback on :443 to be rejected, got err=%v res=%+v", err, resDupDef)
	}

	// 7. Reject UDP / TCP+UDP forwarding with shared-port routing
	resUDP, err := CreateEdge(EdgeSpec{
		Name:         "vpn-udp",
		Mode:         "direct",
		Transport:    "plain",
		PeerIP:       "203.0.113.16",
		LocalIP:      "198.51.100.10",
		ServicePorts: "443",
		UserPorts:    "443",
		LinkPort:     8449,
		ForwardProto: "both",
		RouteHosts:   "udp.vpn.example.com",
	}, relayDir)
	if resUDP.OK || err == nil {
		t.Fatalf("expected forward_proto=both with route_hosts to be rejected, got err=%v res=%+v", err, resUDP)
	}

	// 8. Reject sharing a port owned by an external non-PortBridge process (e.g. nginx)
	oldHost := agentHostOverride
	agentHostOverride = portHost{taken: map[int]string{2096: "nginx"}}
	t.Cleanup(func() { agentHostOverride = oldHost })

	resExt, err := CreateEdge(EdgeSpec{
		Name:         "vpn-nginx-clash",
		Mode:         "direct",
		Transport:    "plain",
		PeerIP:       "203.0.113.17",
		LocalIP:      "198.51.100.10",
		ServicePorts: "2096",
		UserPorts:    "2096",
		LinkPort:     8450,
		RouteHosts:   "clash.vpn.example.com",
	}, relayDir)
	if resExt.OK || err == nil || (!strings.Contains(err.Error(), "another program") && !strings.Contains(err.Error(), "nginx")) {
		t.Fatalf("expected external nginx owner on :2096 to be rejected, got err=%v res=%+v", err, resExt)
	}
	agentHostOverride = oldHost

	// 9. Reject EditEdge clearing route_hosts on vpn-de while siblings still share :443,
	//    and allow EditEdge updating vpn-de to a fresh non-conflicting domain fr.vpn.example.com!
	editBad, err := EditEdge(EditSpec{
		Name:             "vpn-de",
		UserPorts:        "443",
		ServicePorts:     "2053",
		LinkPort:         8444,
		RouteHosts:       "",
		UpdateRouteHosts: true,
		RouteDefault:     "off",
	}, relayDir)
	if editBad.OK || err == nil {
		t.Fatalf("expected clearing route_hosts on shared :443 to be rejected, got err=%v res=%+v", err, editBad)
	}

	editGood, err := EditEdge(EditSpec{
		Name:             "vpn-de",
		UserPorts:        "443",
		ServicePorts:     "2053",
		LinkPort:         8444,
		RouteHosts:       "fr.vpn.example.com",
		UpdateRouteHosts: true,
		RouteDefault:     "off",
	}, relayDir)
	if err != nil || !editGood.OK {
		t.Fatalf("expected updating vpn-de route_hosts to fr.vpn.example.com to succeed: err=%v res=%+v", err, editGood)
	}
}
