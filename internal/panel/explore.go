package panel

// The deep scan, as the panel runs it: what the network between a relay and a
// foreign server actually lets through. The foreign server opens a temporary
// responder on a list of ports; the relay then checks which ports and protocols
// reach it, which domain names survive, and which well-known public endpoints it
// can connect to at all. See engine/explore.go for what each check does.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

// exploreNote is one finding, in words. Level is good, warn, bad or note.
type exploreNote struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// exploreReport is what the deep scan found.
type exploreReport struct {
	OK          bool                        `json:"ok"`
	RelayName   string                      `json:"relay_name"`
	ForeignName string                      `json:"foreign_name"`
	ForeignIP   string                      `json:"foreign_ip"`
	ForeignIPv6 string                      `json:"foreign_ipv6,omitempty"`
	Reach       []engine.ExploreReachResult `json:"reach"`
	Ports       []engine.ExplorePortResult  `json:"ports"`
	ICMP        string                      `json:"icmp"`
	ICMPMS      int64                       `json:"icmp_ms,omitempty"`
	IPv6Port    int                         `json:"ipv6_port,omitempty"`
	IPv6TCP     string                      `json:"ipv6_tcp,omitempty"`
	IPv6UDP     string                      `json:"ipv6_udp,omitempty"`
	IPv6MS      int64                       `json:"ipv6_ms,omitempty"`
	NamesPort   int                         `json:"names_port,omitempty"`
	Names       []engine.SNIScanResult      `json:"names,omitempty"`
	Notes       []exploreNote               `json:"notes"`
	BestPort    int                         `json:"best_port,omitempty"`
	BestName    string                      `json:"best_name,omitempty"`
	// What kinds of link can work, from what was found.
	TCPWorks  bool `json:"tcp_works"`
	UDPWorks  bool `json:"udp_works"`
	ICMPWorks bool `json:"icmp_works"`
	IPv6Works bool `json:"ipv6_works"`
}

// exploreReach says whether the scan also tries the public endpoints. A variable
// so tests need not reach out to the internet.
var exploreReach = true

func (p *Panel) exploreNetwork(parent context.Context, relayID, foreignID string, snis []string) (*exploreReport, error) {
	rv, rok := p.viewOf(relayID)
	fv, fok := p.viewOf(foreignID)
	if !rok || !fok {
		return nil, errors.New("choose both the Relay (Iran) and Foreign servers first")
	}
	if !rv.Online {
		return nil, fmt.Errorf("Relay server %s is currently offline", rv.Name)
	}
	if !fv.Online {
		return nil, fmt.Errorf("Foreign server %s is currently offline", fv.Name)
	}
	_, relayV6 := serverAddresses(rv)
	foreignV4, foreignV6 := serverAddresses(fv)
	if foreignV4 == "" && foreignV6 == "" {
		return nil, fmt.Errorf("%s has no IPv4 or IPv6 address the panel knows of, which the scan needs", fv.Name)
	}
	hostV6 := ""
	if relayV6 != "" && foreignV6 != "" {
		hostV6 = foreignV6
	}

	token := newID(12)

	// 1. The foreign server starts answering on the ports.
	lctx, lcancel := context.WithTimeout(parent, 20*time.Second)
	var lrep struct {
		OK    bool                     `json:"ok"`
		Ports []engine.ExplorePortInfo `json:"ports"`
		Error string                   `json:"error"`
	}
	_, err := p.callJSON(lctx, foreignID, "/api/explore/listen", map[string]any{
		"ports": engine.DefaultExplorePorts,
		"token": token,
	}, &lrep)
	lcancel()
	if err != nil {
		if errors.Is(err, errTooOld) {
			return nil, fmt.Errorf("%s is running an older PortBridge release; update it first to use the deep scan", fv.Name)
		}
		return nil, fmt.Errorf("%s: %s", fv.Name, plainAgentError(err))
	}
	if !lrep.OK {
		return nil, fmt.Errorf("%s could not start answering: %s", fv.Name, lrep.Error)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = p.callJSON(sctx, foreignID, "/api/explore/stop", map[string]string{}, nil)
	}()
	specs := make([]engine.ExplorePortSpec, 0, len(lrep.Ports))
	for _, in := range lrep.Ports {
		specs = append(specs, engine.ExplorePortSpec{Port: in.Port, TCP: in.TCP, UDP: in.UDP})
	}

	// 2. The relay makes its checks.
	time.Sleep(300 * time.Millisecond)
	rctx, rcancel := context.WithTimeout(parent, 80*time.Second)
	defer rcancel()
	var rrep struct {
		OK     bool                    `json:"ok"`
		Report engine.ExploreRunReport `json:"report"`
		Error  string                  `json:"error"`
	}
	_, err = p.callJSON(rctx, relayID, "/api/explore/run", engine.ExploreRequest{
		Host: foreignV4, HostV6: hostV6, Token: token, Ports: specs, SNIs: snis, Reach: exploreReach,
	}, &rrep)
	if err != nil {
		if errors.Is(err, errTooOld) {
			return nil, fmt.Errorf("%s is running an older PortBridge release; update it first to use the deep scan", rv.Name)
		}
		return nil, fmt.Errorf("%s: %s", rv.Name, plainAgentError(err))
	}
	if !rrep.OK {
		return nil, fmt.Errorf("%s could not run the scan: %s", rv.Name, rrep.Error)
	}
	rep := &exploreReport{
		OK:          true,
		RelayName:   rv.Name,
		ForeignName: fv.Name,
		ForeignIP:   foreignV4,
		ForeignIPv6: hostV6,
		Reach:       rrep.Report.Reach,
		Ports:       rrep.Report.Ports,
		ICMP:        rrep.Report.ICMP,
		ICMPMS:      rrep.Report.ICMPMS,
		IPv6Port:    rrep.Report.IPv6Port,
		IPv6TCP:     rrep.Report.IPv6TCP,
		IPv6UDP:     rrep.Report.IPv6UDP,
		IPv6MS:      rrep.Report.IPv6MS,
		NamesPort:   rrep.Report.NamesPort,
		Names:       rrep.Report.Names,
	}
	summariseExplore(rep)
	return rep, nil
}

func joinPorts(ports []int) string {
	sort.Ints(ports)
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// summariseExplore turns the raw findings into plain notes, and picks the port
// and name worth using.
func summariseExplore(rep *exploreReport) {
	var tcpData, tcpOpen, tcpStalled, tcpBlocked, tcpClosed, udpData, udpBlocked []int
	for _, r := range rep.Ports {
		switch r.TCP {
		case "data":
			tcpData = append(tcpData, r.Port)
		case "open":
			tcpOpen = append(tcpOpen, r.Port)
		case "stalled":
			tcpStalled = append(tcpStalled, r.Port)
		case "blocked":
			tcpBlocked = append(tcpBlocked, r.Port)
		case "closed":
			tcpClosed = append(tcpClosed, r.Port)
		}
		switch r.UDP {
		case "data":
			udpData = append(udpData, r.Port)
		case "blocked":
			udpBlocked = append(udpBlocked, r.Port)
		}
	}
	rep.TCPWorks = len(tcpData) > 0
	rep.UDPWorks = len(udpData) > 0
	rep.ICMPWorks = rep.ICMP == "data"
	rep.IPv6Works = rep.IPv6TCP == "data" || rep.IPv6UDP == "data"
	add := func(level, format string, a ...any) {
		rep.Notes = append(rep.Notes, exploreNote{Level: level, Text: fmt.Sprintf(format, a...)})
	}
	fn, rn := rep.ForeignName, rep.RelayName

	// TCP
	total := len(rep.Ports)
	switch {
	case len(tcpData) > 0:
		add("good", "TCP works from %s to %s on %d of %d ports: %s. The disguised-HTTPS, gRPC, plain and Split links use TCP, so they can use these.",
			rn, fn, len(tcpData), total, joinPorts(tcpData))
	case len(tcpOpen) > 0:
		add("warn", "Connections open to %s on ports %s, but data could not be checked there (another program already uses them on that server).", fn, joinPorts(tcpOpen))
	default:
		add("bad", "No TCP port got through from %s to %s. Either the route to this server is blocked, or its own firewall blocks these ports. A different foreign server (or one in a different hosting range) may do better.", rn, fn)
	}
	if len(tcpStalled) > 0 {
		add("warn", "On ports %s the connection opens but no data comes back. That is how a filter that cuts a connection after it starts looks; avoid these ports.", joinPorts(tcpStalled))
	}
	if len(tcpBlocked) > 0 && len(tcpData) > 0 {
		add("note", "Blocked outright (no answer at all): %s.", joinPorts(tcpBlocked))
	}
	if len(tcpClosed) > 0 {
		add("note", "Ports %s reached the server, which answered that nothing listens there. The route is open; the port is simply not in use or is held by the server's own firewall.", joinPorts(tcpClosed))
	}

	// UDP
	switch {
	case len(udpData) > 0:
		add("good", "UDP works on ports: %s. The KCP and IP-spoof links use UDP, so they can use these.", joinPorts(udpData))
	case len(udpBlocked) > 0:
		add("warn", "No UDP packet got through on any port tried, so the KCP and IP-spoof links will not work on this route.")
	}

	// ICMP
	switch rep.ICMP {
	case "data":
		add("good", "ICMP (ping) works: the ICMP link can be used (round trip %d ms).", rep.ICMPMS)
	case "blocked":
		add("warn", "Pings get no answer, so the ICMP link will not work on this route. (If %s already runs an ICMP tunnel from %s this is expected: that tunnel hides the server's own ping replies to its peer.)", fn, rn)
	default:
		add("note", "ICMP could not be tested from %s.", rn)
	}

	// IPv6
	switch {
	case rep.IPv6TCP == "data" && rep.IPv6UDP == "data":
		add("good", "IPv6 works from %s to %s (both TCP and UDP on port %d, %d ms). Turning on IPv6 for the tunnel link is an option.", rn, fn, rep.IPv6Port, rep.IPv6MS)
	case rep.IPv6TCP == "data":
		add("good", "IPv6 TCP works from %s to %s (port %d, %d ms). Turning on IPv6 for the tunnel link is an option.", rn, fn, rep.IPv6Port, rep.IPv6MS)
	case rep.IPv6UDP == "data":
		add("good", "IPv6 UDP works from %s to %s (port %d). KCP over IPv6 can use this.", rn, fn, rep.IPv6Port)
	case rep.IPv6TCP == "blocked" || rep.IPv6TCP == "stalled":
		add("warn", "Both servers have IPv6, but IPv6 traffic from %s to %s did not get through on port %d.", rn, fn, rep.IPv6Port)
	}

	// Names
	if rep.NamesPort == 0 {
		add("note", "Domain names were not tested, because no TCP port got data across to test them on.")
	} else {
		ok := 0
		var best []string
		for _, n := range rep.Names {
			if n.Reachable {
				ok++
				if len(best) < 4 {
					best = append(best, n.SNI)
				}
			}
		}
		switch {
		case len(rep.Names) == 0:
		case ok == len(rep.Names):
			add("good", "Every domain name tested (%d) got through on port %d, so names are not being filtered there.", ok, rep.NamesPort)
		case ok == 0:
			add("bad", "None of the %d domain names got through on port %d, though the port itself works. The filter looks at the name: try other names, or a CDN.", len(rep.Names), rep.NamesPort)
		default:
			add("good", "%d of %d domain names got through on port %d. Best: %s.", ok, len(rep.Names), rep.NamesPort, strings.Join(best, ", "))
		}
	}

	// Public endpoints
	if len(rep.Reach) > 0 {
		type tally struct{ ok, all int }
		groups := map[string]*tally{}
		var order []string
		dnsFail := 0
		for _, r := range rep.Reach {
			t := groups[r.Group]
			if t == nil {
				t = &tally{}
				groups[r.Group] = t
				order = append(order, r.Group)
			}
			t.all++
			if r.OK {
				t.ok++
			}
			if r.Stage == "dns" {
				dnsFail++
			}
		}
		var reach, cut []string
		anyOK := false
		for _, g := range order {
			t := groups[g]
			if t.ok > 0 {
				anyOK = true
				reach = append(reach, fmt.Sprintf("%s (%d/%d)", g, t.ok, t.all))
			} else {
				cut = append(cut, g)
			}
		}
		switch {
		case !anyOK:
			add("bad", "%s could not connect to any of the well-known public endpoints tried. It may have no international access except to specific places.", rn)
		case len(cut) == 0:
			add("good", "%s can reach every group of well-known endpoints tried: %s.", rn, strings.Join(reach, ", "))
		default:
			add("good", "%s can reach: %s.", rn, strings.Join(reach, ", "))
			add("warn", "Not reachable at all: %s. A foreign server hosted in these ranges would probably be blocked too.", strings.Join(cut, ", "))
		}
		if dnsFail > 0 {
			add("note", "%d names could not be looked up from %s (the name service may be filtered).", dnsFail, rn)
		}
	}

	// What is worth using.
	rep.BestPort = rep.NamesPort
	if rep.BestPort == 0 && len(tcpData) > 0 {
		sort.Ints(tcpData)
		rep.BestPort = tcpData[0]
	}
	if rep.BestPort == 0 && rep.IPv6Works && rep.IPv6Port != 0 {
		rep.BestPort = rep.IPv6Port
	}
	for _, n := range rep.Names {
		if n.Reachable {
			rep.BestName = n.SNI
			break
		}
	}
}
