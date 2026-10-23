package panel

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

func notesText(rep *exploreReport) string {
	var b strings.Builder
	for _, n := range rep.Notes {
		b.WriteString(n.Level + ": " + n.Text + "\n")
	}
	return b.String()
}

func TestExploreSummaryForAFilterThatLetsWebPortsAndNamesThrough(t *testing.T) {
	rep := &exploreReport{
		RelayName: "Iran", ForeignName: "Berlin",
		Ports: []engine.ExplorePortResult{
			{Port: 443, TCP: "data", UDP: "blocked"},
			{Port: 8443, TCP: "data", UDP: "blocked"},
			{Port: 2053, TCP: "stalled", UDP: "blocked"},
			{Port: 80, TCP: "blocked", UDP: "blocked"},
		},
		ICMP:      "blocked",
		NamesPort: 443,
		Names: []engine.SNIScanResult{
			{SNI: "a.example", Reachable: true, RTTMs: 90},
			{SNI: "b.example", Reachable: true, RTTMs: 95},
			{SNI: "c.example", Reachable: false, Error: "reset"},
		},
		Reach: []engine.ExploreReachResult{
			{Group: "Cloudflare", Name: "x", OK: true},
			{Group: "Cloudflare", Name: "y", OK: true},
			{Group: "Hosting", Name: "z", Stage: "connect"},
			{Group: "Hosting", Name: "w", Stage: "dns"},
		},
	}
	summariseExplore(rep)
	txt := notesText(rep)

	if !rep.TCPWorks || rep.UDPWorks || rep.ICMPWorks {
		t.Fatalf("modes: tcp=%v udp=%v icmp=%v, want only tcp", rep.TCPWorks, rep.UDPWorks, rep.ICMPWorks)
	}
	if rep.BestPort != 443 || rep.BestName != "a.example" {
		t.Fatalf("best port %d name %q, want 443 and a.example", rep.BestPort, rep.BestName)
	}
	for _, want := range []string{
		"good: TCP works from Iran to Berlin on 2 of 4 ports: 443, 8443",
		"2053 the connection opens but no data comes back",
		"warn: No UDP packet got through",
		"warn: Pings get no answer",
		"2 of 3 domain names got through on port 443",
		"Cloudflare (2/2)",
		"Not reachable at all: Hosting",
		"1 names could not be looked up",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("the notes lack %q:\n%s", want, txt)
		}
	}
}

func TestExploreSummaryWhenNothingGetsThrough(t *testing.T) {
	rep := &exploreReport{
		RelayName: "Iran", ForeignName: "Berlin",
		Ports: []engine.ExplorePortResult{{Port: 443, TCP: "blocked", UDP: "blocked"}, {Port: 80, TCP: "blocked", UDP: "blocked"}},
		ICMP:  "untested",
		Reach: []engine.ExploreReachResult{{Group: "Google", OK: false, Stage: "connect"}},
	}
	summariseExplore(rep)
	txt := notesText(rep)
	if rep.TCPWorks || rep.BestPort != 0 || rep.BestName != "" {
		t.Fatalf("something was offered when nothing works: %+v", rep)
	}
	for _, want := range []string{"bad: No TCP port got through", "bad: Iran could not connect to any", "Domain names were not tested", "ICMP could not be tested"} {
		if !strings.Contains(txt, want) {
			t.Errorf("the notes lack %q:\n%s", want, txt)
		}
	}
}

func TestExploreSummaryWhenNamesAreCut(t *testing.T) {
	rep := &exploreReport{
		RelayName: "Iran", ForeignName: "Berlin",
		Ports:     []engine.ExplorePortResult{{Port: 443, TCP: "data", UDP: "data"}},
		ICMP:      "data",
		ICMPMS:    90,
		NamesPort: 443,
		Names:     []engine.SNIScanResult{{SNI: "a.example"}, {SNI: "b.example"}},
	}
	summariseExplore(rep)
	txt := notesText(rep)
	if !rep.UDPWorks || !rep.ICMPWorks {
		t.Fatalf("udp=%v icmp=%v, want both", rep.UDPWorks, rep.ICMPWorks)
	}
	if !strings.Contains(txt, "bad: None of the 2 domain names got through on port 443") {
		t.Errorf("a name filter was not called out:\n%s", txt)
	}
	if rep.BestName != "" {
		t.Errorf("a name was offered although none got through: %q", rep.BestName)
	}
}

// The whole scan, through the panel, with the "foreign" server's responder and
// the "relay" both on this machine: the responder opens the ports, the relay
// checks them and the names, and the responder is closed again afterwards.
func TestTheDeepScanRunsEndToEnd(t *testing.T) {
	p, _, _ := twoServers(t)
	p.fleet.mu.Lock()
	p.fleet.by["far"].overview = &agent.Overview{OK: true, Version: engine.Version, IPv4: []string{"127.0.0.1"}}
	p.fleet.mu.Unlock()
	exploreReach = false
	defer func() { exploreReach = true }()

	rep, err := p.exploreNetwork(context.Background(), "this", "far", []string{"one.example", "two.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.ForeignIP != "127.0.0.1" || len(rep.Ports) == 0 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	var data []int
	for _, r := range rep.Ports {
		if r.TCP == "data" {
			data = append(data, r.Port)
		}
	}
	if len(data) == 0 {
		t.Skip("none of the scan's ports could be opened on this machine")
	}
	if !rep.TCPWorks || rep.BestPort == 0 || rep.NamesPort == 0 {
		t.Fatalf("tcp works on %v but the report says %+v", data, rep)
	}
	if len(rep.Names) != 2 || !rep.Names[0].Reachable || rep.BestName == "" {
		t.Fatalf("names were not tested over the working port: %+v", rep.Names)
	}

	// The responder is gone again: its ports now refuse.
	time.Sleep(200 * time.Millisecond)
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(rep.NamesPort)), time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatalf("port %d still answers after the scan", rep.NamesPort)
	}
}
