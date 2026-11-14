package panel

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

func TestWebsiteBridgeAutoHealRawMuxCapStallGuardAndRestore(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)

	// 1. Create a Website Bridge (defaults to 8 parallel Mux trunks + Smart Outbound Proxy).
	initReq := createRequest{
		Name:                  "wbtest",
		Relay:                 "this",
		Foreign:               foreignID,
		Mode:                  "direct",
		Link:                  "website",
		ServerName:            "www.bing.com",
		Shared:                true,
		SharedLinks:           8,
		MaxConn:               4000,
		ServicePorts:          "18081,18443",
		UserPorts:             "18081,18443",
		LinkPort:              28443,
		ProxyProtocol:         "v1",
		RelayIP:               "198.51.100.1",
		AutoHeal:              true,
		WebsiteBridge:         true,
		WebsiteDomains:        "test.homplast.com",
		OutboundProxy:         true,
		OutboundProxyPort:     28080,
		OutboundProxyMode:     "split",
		OutboundIranDomains:   ".ir,shaparak.ir",
		OutboundBypassDomains: "api.telegram.org",
	}
	jobID, err := p.startCreate(initReq)
	if err != nil {
		t.Fatalf("startCreate Website Bridge: %v", err)
	}
	if v := waitJob(t, p, jobID); v.Error != "" {
		t.Fatalf("create Website Bridge failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge0 := agent.TunnelsReport(p.tunnelsDir)
	orig0 := agent.TunnelsReport(foreignDir)
	if len(edge0) != 1 || len(orig0) != 1 {
		t.Fatalf("expected 1 Website Bridge on both servers, got %d / %d", len(edge0), len(orig0))
	}
	if !edge0[0].WebsiteBridge || !orig0[0].WebsiteBridge || edge0[0].MuxLinks != 8 || orig0[0].MuxLinks != 8 {
		t.Fatalf("unexpected initial Website Bridge mux/flags: edge=%+v orig=%+v", edge0[0], orig0[0])
	}
	if !edge0[0].OutboundProxy || !orig0[0].OutboundProxy || orig0[0].OutboundProxyPort != 28080 {
		t.Fatalf("expected OutboundProxy on port 28080: edge=%+v orig=%+v", edge0[0], orig0[0])
	}

	// 2. Verify sameCandidateAsCurrent distinguishes SNISpoof and IPSpoof from base TLS/KCP.
	sniSpoofCand := engine.ProbeCandidateResult{
		ProbeCandidateSpec: engine.ProbeCandidateSpec{
			ID: "direct-sni-spoof", Mode: "direct", Transport: "tls", Link: "sni-spoof",
			SNISpoof: true, SpoofSNI: "challenges.cloudflare.com", Shared: true, Port: 2053,
		},
		Status: "ok", Score: 88,
	}
	if sameCandidateAsCurrent(sniSpoofCand, edge0[0]) {
		t.Fatal("sameCandidateAsCurrent must distinguish sni-spoof from normal Fake TLS website")
	}
	ipSpoofCand := engine.ProbeCandidateResult{
		ProbeCandidateSpec: engine.ProbeCandidateSpec{
			ID: "direct-ip-spoof", Mode: "direct", Transport: "kcp", Link: "ip-spoof",
			IPSpoof: true, Shared: true, Port: 2053,
		},
		Status: "ok", Score: 82,
	}
	kcpInfo := agent.TunnelInfo{Name: "k", Mode: "direct", Transport: "kcp", LinkPort: 2053}
	if sameCandidateAsCurrent(ipSpoofCand, kcpInfo) {
		t.Fatal("sameCandidateAsCurrent must distinguish ip-spoof from normal KCP")
	}

	// 3. Auto-Heal fails over the unhealthy Website Bridge onto FakeTCP:
	//    MuxLinks MUST be capped from 8 -> 2 while keeping WebsiteBridge & OutboundProxy intact.
	fakeTCPCand := engine.ProbeCandidateResult{
		ProbeCandidateSpec: engine.ProbeCandidateSpec{
			ID:        "direct-faketcp",
			Label:     "Direct · FakeTCP · Paqet (KCP)",
			Mode:      "direct",
			Link:      "faketcp",
			Transport: "faketcp",
			Shared:    true,
			Port:      2053,
		},
		Status:    "ok",
		Score:     78,
		Successes: 1,
		Summary:   "Healthy 78/100",
	}
	spec1, port1, err := p.healer.buildFailoverEditSpec(context.Background(), "wbtest", "this", foreignID, "", edge0[0], fakeTCPCand, false, false)
	if err != nil {
		t.Fatalf("buildFailoverEditSpec (faketcp): %v", err)
	}
	if spec1.Mux != "on" || spec1.MuxLinks != 2 {
		t.Fatalf("expected Website Bridge on faketcp to force Mux=on and cap MuxLinks=2, got Mux=%q MuxLinks=%d", spec1.Mux, spec1.MuxLinks)
	}
	if err := switchBothHalves(context.Background(), p.callJSON, func(string, ...any) {}, "wbtest", "this", foreignID, "Relay", "Aeza", "DIRECT · FAKETCP · IPv4", port1, spec1); err != nil {
		t.Fatalf("switchBothHalves to faketcp: %v", err)
	}

	edge1 := agent.TunnelsReport(p.tunnelsDir)
	orig1 := agent.TunnelsReport(foreignDir)
	if edge1[0].Transport != "faketcp" || orig1[0].Transport != "faketcp" || edge1[0].MuxLinks != 2 || orig1[0].MuxLinks != 2 {
		t.Fatalf("expected faketcp with MuxLinks=2 on both halves, got edge=%+v orig=%+v", edge1[0], orig1[0])
	}
	if !edge1[0].WebsiteBridge || edge1[0].WebsiteDomains != "test.homplast.com" || !orig1[0].OutboundProxy {
		t.Fatalf("WebsiteBridge/OutboundProxy lost after Auto-Heal switch: edge=%+v orig=%+v", edge1[0], orig1[0])
	}

	// 4. Verify pickBestCandidate repairs a legacy 8-link raw-socket tunnel once,
	//    but refuses to loop on an already-capped running stalled FakeTCP tunnel.
	onlyFakeRep := &engine.ProbeBenchmarkReport{Results: []engine.ProbeCandidateResult{fakeTCPCand}}
	legacyOverloaded := edge1[0]
	legacyOverloaded.Running = true
	legacyOverloaded.MuxLinks = 8
	if _, ok := p.healer.pickBestCandidate(onlyFakeRep, legacyOverloaded, false); !ok {
		t.Fatal("expected pickBestCandidate to accept faketcp once when repairing overloaded MuxLinks=8 -> 2")
	}

	alreadyCappedRunning := edge1[0]
	alreadyCappedRunning.Running = true
	alreadyCappedRunning.MuxLinks = 2
	if _, ok := p.healer.pickBestCandidate(onlyFakeRep, alreadyCappedRunning, false); ok {
		t.Fatal("expected pickBestCandidate (force=false) to reject re-applying identical stalled faketcp (MuxLinks=2)")
	}

	// 5. Auto-Heal later recovers from FakeTCP (MuxLinks=2) onto SplitHTTP / XHTTP:
	//    MuxLinks MUST automatically restore back to 8 for Website Bridges!
	xhttpCand := engine.ProbeCandidateResult{
		ProbeCandidateSpec: engine.ProbeCandidateSpec{
			ID:         "direct-xhttp",
			Label:      "Direct · SplitHTTP / XHTTP",
			Mode:       "direct",
			Link:       "xhttp",
			Transport:  "xhttp",
			Stealth:    true,
			Shared:     true,
			ServerName: "www.bing.com",
			Port:       2083,
		},
		Status:    "ok",
		Score:     93,
		Successes: 1,
		Summary:   "Healthy 93/100",
	}
	spec2, port2, err := p.healer.buildFailoverEditSpec(context.Background(), "wbtest", "this", foreignID, "", edge1[0], xhttpCand, false, false)
	if err != nil {
		t.Fatalf("buildFailoverEditSpec (xhttp): %v", err)
	}
	if spec2.Mux != "on" || spec2.MuxLinks != 8 {
		t.Fatalf("expected Website Bridge healing off faketcp -> xhttp to restore MuxLinks=8, got Mux=%q MuxLinks=%d", spec2.Mux, spec2.MuxLinks)
	}
	if err := switchBothHalves(context.Background(), p.callJSON, func(string, ...any) {}, "wbtest", "this", foreignID, "Relay", "Aeza", "DIRECT · XHTTP · IPv4", port2, spec2); err != nil {
		t.Fatalf("switchBothHalves to xhttp: %v", err)
	}
	edge2 := agent.TunnelsReport(p.tunnelsDir)
	orig2 := agent.TunnelsReport(foreignDir)
	if edge2[0].Transport != "xhttp" || orig2[0].Transport != "xhttp" || edge2[0].MuxLinks != 8 || orig2[0].MuxLinks != 8 {
		t.Fatalf("expected xhttp with restored MuxLinks=8 on both halves, got edge=%+v orig=%+v", edge2[0], orig2[0])
	}
}

func TestWebsiteBridgeSwitchModeAllTransportsPreservesSettings(t *testing.T) {
	p, foreignID, foreignDir := twoServers(t)

	initReq := createRequest{
		Name:                  "wbswitch",
		Relay:                 "this",
		Foreign:               foreignID,
		Mode:                  "direct",
		Link:                  "website",
		ServerName:            "www.bing.com",
		Shared:                true,
		SharedLinks:           8,
		MaxConn:               4000,
		ServicePorts:          "18082,18444",
		UserPorts:             "18082,18444",
		LinkPort:              28444,
		ProxyProtocol:         "v1",
		RelayIP:               "198.51.100.1",
		AutoHeal:              true,
		WebsiteBridge:         true,
		WebsiteDomains:        "shop.homplast.com,pay.homplast.com",
		OutboundProxy:         true,
		OutboundProxyPort:     28081,
		OutboundProxyMode:     "split",
		OutboundIranDomains:   ".ir,zarinpal.com",
		OutboundBypassDomains: "api.telegram.org",
	}
	job0, err := p.startCreate(initReq)
	if err != nil {
		t.Fatalf("startCreate: %v", err)
	}
	if v := waitJob(t, p, job0); v.Error != "" {
		t.Fatalf("create failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	pairID := agent.TunnelsReport(p.tunnelsDir)[0].PairID

	// 1. Switch Website Bridge to Cloudflare CDN SplitHTTP (xhttp-cdn) with Clean IPs.
	swCDN := initReq
	swCDN.Mode = "direct"
	swCDN.Link = "xhttp-cdn"
	swCDN.Domain = "cdn-bridge.homplast.com"
	swCDN.CleanIPs = "104.16.12.34,172.67.45.67"
	swCDN.LinkPort = 2053
	swCDN.SharedLinks = 8
	job1, err := p.startSwitchTunnel(swCDN)
	if err != nil {
		t.Fatalf("startSwitchTunnel (xhttp-cdn): %v", err)
	}
	if v := waitJob(t, p, job1); v.Error != "" {
		t.Fatalf("switch to xhttp-cdn failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}

	edge1 := agent.TunnelsReport(p.tunnelsDir)
	orig1 := agent.TunnelsReport(foreignDir)
	if edge1[0].PairID != pairID || orig1[0].PairID != pairID {
		t.Fatalf("PairID changed across Website Bridge mode switch: want %s, got %s / %s", pairID, edge1[0].PairID, orig1[0].PairID)
	}
	if edge1[0].Transport != "xhttp" || !edge1[0].CDN || !orig1[0].CDN || orig1[0].LinkPort != 2053 {
		t.Fatalf("expected xhttp-cdn on port 2053, got edge=%+v orig=%+v", edge1[0], orig1[0])
	}
	if !slices.Equal(edge1[0].CleanIPs, []string{"104.16.12.34", "172.67.45.67"}) {
		t.Fatalf("expected CleanIPs on edge, got %+v", edge1[0].CleanIPs)
	}
	if !edge1[0].WebsiteBridge || edge1[0].WebsiteDomains != "shop.homplast.com, pay.homplast.com" || !orig1[0].OutboundProxy || orig1[0].OutboundProxyPort != 28081 {
		t.Fatalf("WebsiteBridge/OutboundProxy not preserved across CDN switch: edge=%+v orig=%+v", edge1[0], orig1[0])
	}
	if gotCDN := p.store.get().AutoHeal[healKeyFor("this", "wbswitch")].CDNDomain; gotCDN != "cdn-bridge.homplast.com" {
		t.Fatalf("expected AutoHeal CDNDomain saved as cdn-bridge.homplast.com, got %q", gotCDN)
	}

	// 2. Switch Website Bridge to FakeTCP (passing SharedLinks=8) -> must cap MuxLinks to 2.
	swRaw := initReq
	swRaw.Mode = "direct"
	swRaw.Link = "faketcp"
	swRaw.LinkPort = 2087
	swRaw.SharedLinks = 8
	job2, err := p.startSwitchTunnel(swRaw)
	if err != nil {
		t.Fatalf("startSwitchTunnel (faketcp): %v", err)
	}
	if v := waitJob(t, p, job2); v.Error != "" {
		t.Fatalf("switch to faketcp failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edge2 := agent.TunnelsReport(p.tunnelsDir)
	orig2 := agent.TunnelsReport(foreignDir)
	if edge2[0].Transport != "faketcp" || edge2[0].MuxLinks != 2 || orig2[0].MuxLinks != 2 {
		t.Fatalf("expected faketcp with capped MuxLinks=2, got edge=%+v orig=%+v", edge2[0], orig2[0])
	}

	// 3. Switch Website Bridge to Reverse HTTP-Header disguise -> restores 8 trunks and keeps OutboundProxy.
	swRev := initReq
	swRev.Mode = "reverse"
	swRev.Link = "http-header"
	swRev.ServerName = "www.bing.com"
	swRev.LinkPort = 28445
	swRev.SharedLinks = 8
	job3, err := p.startSwitchTunnel(swRev)
	if err != nil {
		t.Fatalf("startSwitchTunnel (reverse http-header): %v", err)
	}
	if v := waitJob(t, p, job3); v.Error != "" {
		t.Fatalf("switch to reverse http-header failed: %s\n%s", v.Error, strings.Join(v.Lines, "\n"))
	}
	edge3 := agent.TunnelsReport(p.tunnelsDir)
	orig3 := agent.TunnelsReport(foreignDir)
	if edge3[0].Mode != "reverse" || orig3[0].Mode != "reverse" || edge3[0].Transport != "plain" || edge3[0].MuxLinks != 8 {
		t.Fatalf("expected reverse plain+header with MuxLinks=8, got edge=%+v orig=%+v", edge3[0], orig3[0])
	}
	if !strings.Contains(strings.ToLower(edge3[0].Link), "opening like web traffic to www.bing.com") {
		t.Fatalf("expected HTTP website header disguise in Link, got %q", edge3[0].Link)
	}
	if !edge3[0].WebsiteBridge || !orig3[0].OutboundProxy || orig3[0].OutboundIranDomains != ".ir, zarinpal.com" {
		t.Fatalf("WebsiteBridge/OutboundProxy lost after reverse switch: edge=%+v orig=%+v", edge3[0], orig3[0])
	}
}
