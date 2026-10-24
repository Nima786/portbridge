package panel

// Making, changing and removing tunnels from the panel.
//
// A tunnel has two halves. The Iran half is made by the relay server's agent
// exactly as the menu would make it (agent.CreateEdge), and gives back the
// pairing code; the foreign half is then made from that code by the foreign
// server's agent, as "Join a tunnel" would. If the foreign half cannot be made,
// the Iran half is taken away again, so nothing is left half-made. The panel's
// own server is handled the same way, through the agent's code run in-process.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

const tunnelOpTimeout = 2 * time.Minute

// serverByID finds a server the panel manages; "this" is the panel's own.
func (p *Panel) serverByID(id string) (Server, bool) {
	for _, s := range p.store.get().Servers {
		if s.ID == id {
			return s, true
		}
	}
	return Server{}, false
}

// callServer sends one request to a server's agent: to the agent's code here
// for the panel's own server, and as fleet.call does for every other.
func (p *Panel) callServer(ctx context.Context, id, method, path string, body []byte, limit int64) (int, []byte, error) {
	if id == "this" {
		req := httptest.NewRequest(method, "https://this"+path, bytes.NewReader(body)).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+p.localToken)
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		p.local.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes(), nil
	}
	srv, ok := p.serverByID(id)
	if !ok {
		return 0, nil, errNoServer
	}
	return p.fleet.callLimit(ctx, srv, method, path, body, limit)
}

// callJSON sends in as JSON and reads the answer into out.
func (p *Panel) callJSON(ctx context.Context, id, path string, in, out any) (int, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	status, rb, err := p.callServer(ctx, id, http.MethodPost, path, body, overviewLimit)
	if err != nil {
		return 0, err
	}
	if status == http.StatusNotFound {
		return status, errTooOld
	}
	if status == http.StatusUnauthorized {
		return status, errors.New("the server's agent no longer accepts the panel's token; add the server again")
	}
	if out != nil && len(rb) > 0 {
		if err := json.Unmarshal(rb, out); err != nil {
			return status, fmt.Errorf("the server's agent sent something unreadable (HTTP %d)", status)
		}
	}
	return status, nil
}

var errTooOld = errors.New("PortBridge on that server is too old for this; update it first")

// serverName is a server's name as the panel shows it.
func (p *Panel) serverName(id string) string {
	for _, v := range p.fleet.views() {
		if v.ID == id {
			if v.Name != "" {
				return v.Name
			}
			return v.Address
		}
	}
	return id
}

// viewOf is one server as the pages show it.
func (p *Panel) viewOf(id string) (serverView, bool) {
	for _, v := range p.fleet.views() {
		if v.ID == id {
			return v, true
		}
	}
	return serverView{}, false
}

// createRequest is what the "New tunnel" form sends.
type createRequest struct {
	Name    string `json:"name"`
	Relay   string `json:"relay"`   // server ID of the relay (Iran) server
	Foreign string `json:"foreign"` // server ID of the foreign server
	Mode    string `json:"mode"`    // direct or reverse

	// Link is how the link between the servers looks: plain, website, cdn,
	// website-cdn-backup, grpc, grpc-cdn or kcp.
	Link       string `json:"link"`
	ServerName string `json:"server_name"` // the name it claims
	Domain     string `json:"domain"`      // the domain pointed at the CDN
	CleanIPs   string `json:"clean_ips"`
	Stealth    bool   `json:"stealth"`    // a browser's hello, split up
	WebHeader  bool   `json:"web_header"` // a plain link opening like web traffic
	WebHost    string `json:"web_host"`
	RealSite   bool   `json:"real_site"`
	GRE        bool   `json:"gre"`
	SIT        bool   `json:"sit"`
	AntiFreeze bool   `json:"anti_freeze"`
	SNISpoof   bool   `json:"sni_spoof"`
	SpoofSNI   string `json:"spoof_sni"`
	IPSpoof    bool   `json:"ip_spoof"`
	SpoofIP    string `json:"spoof_ip"`
	IPv6       bool   `json:"ipv6"`

	Shared      bool `json:"shared"`
	SharedLinks int  `json:"shared_links"`
	Pool        int  `json:"pool"`
	MaxConn     int  `json:"max_conn"`

	ServicePorts string `json:"service_ports"`
	UserPorts    string `json:"user_ports"`
	LinkPort     int    `json:"link_port"`

	ProxyProtocol string `json:"proxy_protocol"`
	RelayIP       string `json:"relay_ip"` // optional: the relay's address users connect to
	AutoHeal      bool   `json:"auto_heal"`

	WebsiteBridge         bool   `json:"website_bridge"`
	WebsiteDomains        string `json:"website_domains"`
	OutboundProxy         bool   `json:"outbound_proxy"`
	OutboundProxyPort     int    `json:"outbound_proxy_port"`
	OutboundProxyMode     string `json:"outbound_proxy_mode"`
	OutboundIranDomains   string `json:"outbound_iran_domains"`
	OutboundBypassDomains string `json:"outbound_bypass_domains"`
}

func firstIP(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

// addressesOf is a server's public IPv4 and IPv6 addresses, as far as is known.
func addressesOf(v serverView) (v4, v6 string) {
	if v.Overview != nil {
		v4, v6 = firstIP(v.Overview.IPv4), firstIP(v.Overview.IPv6)
	}
	if ip := net.ParseIP(v.Address); ip != nil {
		if ip.To4() != nil && v4 == "" {
			v4 = v.Address
		} else if ip.To4() == nil && v6 == "" {
			v6 = v.Address
		}
	}
	return v4, v6
}

// toSpec turns the form into the menu's answers, checking it makes sense.
func (p *Panel) toSpec(r createRequest) (agent.EdgeSpec, error) {
	pool := r.Pool
	if pool <= 0 {
		pool = 25
	}
	s := agent.EdgeSpec{Name: strings.TrimSpace(r.Name), Mode: r.Mode, Pool: pool, MaxConn: r.MaxConn,
		ServicePorts: r.ServicePorts, UserPorts: r.UserPorts, LinkPort: r.LinkPort, ProxyProtocol: r.ProxyProtocol}
	if r.WebsiteBridge {
		s.WebsiteBridge = "on"
		s.WebsiteDomains = strings.TrimSpace(r.WebsiteDomains)
		r.Shared = true
	}
	if r.OutboundProxy {
		s.OutboundProxy = "on"
		s.OutboundProxyPort = r.OutboundProxyPort
		if s.OutboundProxyPort <= 0 {
			s.OutboundProxyPort = 18080
		}
		s.OutboundProxyMode = strings.TrimSpace(r.OutboundProxyMode)
		if s.OutboundProxyMode == "" {
			s.OutboundProxyMode = "split"
		}
		s.OutboundIranDomains = strings.TrimSpace(r.OutboundIranDomains)
		s.OutboundBypassDomains = strings.TrimSpace(r.OutboundBypassDomains)
	}
	if r.Relay == "" || r.Foreign == "" || r.Relay == r.Foreign {
		return s, errors.New("choose a relay (Iran) server and a different, foreign server")
	}
	relay, ok := p.viewOf(r.Relay)
	if !ok {
		return s, errors.New("that relay server is not in the panel")
	}
	foreign, ok := p.viewOf(r.Foreign)
	if !ok {
		return s, errors.New("that foreign server is not in the panel")
	}
	if relay.Group != GroupRelay {
		return s, fmt.Errorf("%s is not in the relay (Iran) group; move it there first if it is one", relay.Name)
	}
	if foreign.Group != GroupForeign {
		return s, fmt.Errorf("%s is not in the foreign group; move it there first if it is one", foreign.Name)
	}
	if strings.TrimSpace(s.UserPorts) == "" {
		s.UserPorts = s.ServicePorts
	}
	on := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	claimed := strings.TrimSpace(r.ServerName)
	domain := strings.TrimSpace(r.Domain)
	switch r.Link {
	case "plain":
		s.Transport = "plain"
		if r.WebHeader {
			s.HTTPHeader = "on"
			s.HTTPHost = strings.TrimSpace(r.WebHost)
			if s.HTTPHost == "" {
				s.HTTPHost = "www.bing.com"
			}
		}
	case "website":
		s.Transport = "tls"
		s.ServerName = claimed
		if s.ServerName == "" {
			s.ServerName = "www.bing.com"
		}
		s.UTLS, s.TLSFragment = on(r.Stealth), on(r.Stealth)
		s.RealSite = on(r.RealSite)
	case "split":
		s.Transport = "tls"
		s.ServerName = claimed
		if s.ServerName == "" {
			s.ServerName = engine.DefaultSpoofSNI
		}
		s.UTLS, s.TLSFragment = "on", "on"
		s.SNISpoof, s.SpoofSNI = "on", s.ServerName
		s.RealSite = on(r.RealSite)
		s.AntiFreeze = "on"
	case "sit":
		s.Transport = "tls"
		s.ServerName = claimed
		if s.ServerName == "" {
			s.ServerName = "www.bing.com"
		}
		s.UTLS, s.TLSFragment = on(r.Stealth), on(r.Stealth)
		s.RealSite = on(r.RealSite)
		s.SIT = "on"
	case "cdn":
		s.Transport, s.CDN, s.ServerName, s.CleanIPs = "wss", "on", domain, r.CleanIPs
		if domain == "" {
			return s, errors.New("a link through a CDN needs your domain, pointed at the CDN")
		}
	case "website-cdn-backup":
		if r.Mode != "direct" {
			return s, errors.New("the CDN standing by is only for direct tunnels")
		}
		s.Transport, s.AltHost, s.ServerName = "wss", domain, claimed
		if s.ServerName == "" {
			s.ServerName = "www.bing.com"
		}
		if domain == "" {
			return s, errors.New("the CDN standing by needs your domain, pointed at the CDN")
		}
	case "grpc":
		s.Transport, s.ServerName = "grpc", claimed
		if s.ServerName == "" {
			s.ServerName = "www.google.com"
		}
		s.UTLS, s.TLSFragment = on(r.Stealth), on(r.Stealth)
		s.RealSite = on(r.RealSite)
	case "grpc-cdn":
		s.Transport, s.CDN, s.ServerName, s.CleanIPs = "grpc", "on", domain, r.CleanIPs
		if domain == "" {
			return s, errors.New("HTTP/2 through Cloudflare needs your domain, pointed at Cloudflare")
		}
	case "kcp":
		s.Transport = "kcp"
	case "faketcp":
		s.Transport = "faketcp"
	case "icmp":
		s.Transport = "icmp"
	case "sni-spoof":
		s.Transport = "tls"
		s.SNISpoof = "on"
		s.SpoofSNI = strings.TrimSpace(r.SpoofSNI)
		if s.SpoofSNI == "" {
			s.SpoofSNI = engine.DefaultSpoofSNI
		}
		s.ServerName = claimed
		if s.ServerName == "" {
			s.ServerName = s.SpoofSNI
		}
		s.UTLS, s.TLSFragment = "on", "on"
		s.RealSite = on(r.RealSite)
	case "ip-spoof":
		s.Transport = "kcp"
		s.IPSpoof = "on"
	default:
		return s, errors.New("choose how the link between the servers should look")
	}
	// Tidy what the form leaves on: these are "off" when not wanted.
	for _, f := range []*string{&s.UTLS, &s.TLSFragment, &s.RealSite} {
		if *f == "off" {
			*f = ""
		}
	}
	if r.GRE {
		s.GRE = "on"
	} else if r.SIT || s.SIT == "on" {
		s.SIT = "on"
	} else {
		if r.AntiFreeze {
			s.AntiFreeze = "on"
		}
		if r.SNISpoof {
			s.SNISpoof = "on"
			s.SpoofSNI = strings.TrimSpace(r.SpoofSNI)
			if s.SpoofSNI == "" {
				s.SpoofSNI = engine.DefaultSpoofSNI
			}
		}
		if r.IPSpoof || s.IPSpoof == "on" {
			s.Transport = "kcp"
			s.IPSpoof = "on"
			s.SpoofIP = strings.TrimSpace(r.SpoofIP)
			if s.SpoofIP == "" {
				s.SpoofIP = engine.DefaultSpoofIP
			}
			s.SpoofSNI = strings.TrimSpace(r.SpoofSNI)
			if s.SpoofSNI == "" {
				s.SpoofSNI = engine.DefaultSpoofSNI
			}
		}
	}
	if r.Shared {
		s.Mux, s.MuxLinks = "on", r.SharedLinks
		if s.MuxLinks == 0 {
			if s.Transport == "icmp" || s.Transport == "faketcp" || s.IPSpoof == "on" {
				s.MuxLinks = 2
			} else {
				s.MuxLinks = 4
			}
		}
	}
	if s.ProxyProtocol == "off" {
		s.ProxyProtocol = ""
	}

	rv4, rv6 := addressesOf(relay)
	fv4, fv6 := addressesOf(foreign)
	if r.IPv6 && s.GRE != "on" && s.SIT != "on" {
		if rv6 == "" || fv6 == "" {
			return s, errors.New("both servers need a public IPv6 address for IPv6 between them")
		}
		s.IPv6, s.LocalIP, s.PeerIP = true, rv6, fv6
	} else {
		s.LocalIP, s.PeerIP = rv4, fv4
		if ip := strings.TrimSpace(r.RelayIP); ip != "" {
			s.LocalIP = ip
		}
		if s.LocalIP == "" {
			return s, fmt.Errorf("the panel does not know %s's public IPv4 address; give it under \"This relay's address\"", relay.Name)
		}
		if s.PeerIP == "" {
			return s, fmt.Errorf("the panel does not know %s's public IPv4 address", foreign.Name)
		}
	}
	return s, nil
}

// portsThere asks a server which of these ports it can give a tunnel.
func (p *Panel) portsThere(ctx context.Context, id string, ports []int) (map[int]portState, error) {
	var list []string
	for _, n := range ports {
		list = append(list, strconv.Itoa(n))
	}
	var rep struct {
		OK    bool        `json:"ok"`
		Error string      `json:"error"`
		Ports []portState `json:"ports"`
	}
	if _, err := p.callJSON(ctx, id, "/api/ports", map[string]string{"ports": strings.Join(list, ",")}, &rep); err != nil {
		return nil, err
	}
	if !rep.OK {
		return nil, errors.New(rep.Error)
	}
	out := map[int]portState{}
	for _, ps := range rep.Ports {
		out[ps.Port] = ps
	}
	return out, nil
}

type portState struct {
	Port  int    `json:"port"`
	State string `json:"state"`
	By    string `json:"by,omitempty"`
}

func intsOf(list string) []int {
	var out []int
	for _, f := range strings.Split(list, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// checkForeignPorts is what the menu asks the foreign server as the ports are
// typed: the link's port (direct) must be free there, and the service ports must
// not be another tunnel's. It is asked first, so a clash is caught before the
// Iran half is made.
func (p *Panel) checkForeignPorts(ctx context.Context, j *job, foreignID string, s agent.EdgeSpec) error {
	ask := intsOf(s.ServicePorts)
	if s.Mode == "direct" {
		ask = append(ask, s.LinkPort)
	}
	if s.OutboundProxy == "on" && s.OutboundProxyPort > 0 {
		ask = append(ask, s.OutboundProxyPort)
	}
	st, err := p.portsThere(ctx, foreignID, ask)
	if err != nil {
		j.say("Could not ask the foreign server about its ports first (%s); it checks them itself.", plainAgentError(err))
		return nil
	}
	var problems []string
	if s.Mode == "direct" {
		if ps := st[s.LinkPort]; ps.State == "busy" || ps.State == "reserved" {
			problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already used on the foreign server%s",
				s.LinkPort, byWhom(ps.By)))
		}
	}
	if s.OutboundProxy == "on" && s.OutboundProxyPort > 0 {
		if ps := st[s.OutboundProxyPort]; ps.State == "busy" || ps.State == "reserved" {
			problems = append(problems, fmt.Sprintf("the outbound local proxy port, %d, is already used on the foreign server%s",
				s.OutboundProxyPort, byWhom(ps.By)))
		}
	}
	for _, n := range intsOf(s.ServicePorts) {
		ps := st[n]
		switch {
		case strings.HasPrefix(ps.By, "PortBridge tunnel "):
			problems = append(problems, fmt.Sprintf("service port %d on the foreign server is used by %s, so it cannot also be your service",
				n, strings.TrimPrefix(ps.By, "PortBridge ")))
		case ps.State == "free":
			if s.WebsiteBridge == "on" {
				j.say("Note: nothing is listening on port %d on the foreign server yet. Make sure your web server (LiteSpeed / CyberPanel / Nginx) is running there.", n)
			} else {
				j.say("Note: nothing is listening on port %d on the foreign server yet. Make sure your service (Xray) is running there.", n)
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s. Change the ports and try again", strings.Join(problems, "; "))
	}
	return nil
}

func byWhom(by string) string {
	if by == "" {
		return ""
	}
	return " (by " + strings.TrimPrefix(by, "PortBridge ") + ")"
}

// startCreate checks a "New tunnel" form and starts making the tunnel.
func (p *Panel) startCreate(r createRequest) (string, error) {
	spec, err := p.toSpec(r)
	if err != nil {
		return "", err
	}
	return p.startJob(func(j *job) (string, error) {
		if err := p.createTunnel(j, r.Relay, r.Foreign, spec); err != nil {
			return "", err
		}
		if r.AutoHeal {
			_ = p.healer.setConfig(r.Relay, spec.Name, true, strings.TrimSpace(r.Domain))
		}
		return "", nil
	}), nil
}

// startJob runs work in the background as a job the page can follow.
func (p *Panel) startJob(work func(*job) (string, error)) string {
	id := newID(9)
	j := &job{id: id, started: time.Now()}
	p.jobsMu.Lock()
	p.jobs[id] = j
	for k, o := range p.jobs {
		if o.view().Done && time.Since(o.started) > time.Hour {
			delete(p.jobs, k)
		}
	}
	p.jobsMu.Unlock()
	go func() {
		res, err := work(j)
		if err != nil {
			logf("%v", err)
		}
		j.finish(res, err)
	}()
	return id
}

func (p *Panel) createTunnel(j *job, relayID, foreignID string, spec agent.EdgeSpec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*tunnelOpTimeout)
	defer cancel()
	relay, foreign := p.serverName(relayID), p.serverName(foreignID)

	j.say("Checking the ports on %s...", foreign)
	if err := p.checkForeignPorts(ctx, j, foreignID, spec); err != nil {
		return err
	}

	j.say("Making the Iran half on %s...", relay)
	var edge agent.EdgeResult
	status, err := p.callJSON(ctx, relayID, "/api/tunnel/create-edge", spec, &edge)
	if errors.Is(err, errTooOld) {
		return fmt.Errorf("PortBridge on %s is too old to make tunnels from the panel; update it first", relay)
	}
	if err != nil {
		return fmt.Errorf("%s could not be reached: %s", relay, plainAgentError(err))
	}
	if !edge.OK {
		if edge.Error == "" {
			edge.Error = fmt.Sprintf("it answered HTTP %d", status)
		}
		return fmt.Errorf("%s could not make its half: %s", relay, edge.Error)
	}
	for _, w := range edge.Warnings {
		j.say("Note from %s: %s", relay, w)
	}
	j.say("The Iran half is running on %s.", relay)

	j.say("Making the foreign half on %s...", foreign)
	var join struct {
		OK       bool     `json:"ok"`
		Error    string   `json:"error"`
		Warnings []string `json:"warnings"`
	}
	_, jerr := p.callJSON(ctx, foreignID, "/api/tunnel/join", map[string]string{"code": edge.Code}, &join)
	if jerr == nil && !join.OK {
		jerr = errors.New(join.Error)
	}
	if jerr != nil {
		reason := jerr.Error()
		if !errors.Is(jerr, errTooOld) {
			reason = plainAgentError(jerr)
		}
		j.say("%s could not make its half: %s", foreign, reason)
		j.say("Taking the Iran half away again, so nothing is left half-made...")
		if err := p.deleteHalf(ctx, relayID, spec.Name); err != nil {
			return fmt.Errorf("%s could not make its half (%s), and the Iran half on %s could not be taken away (%s). "+
				"Delete it there by hand: portbridge-menu, then \"Delete a tunnel\", then %s", foreign, reason, relay,
				plainAgentError(err), spec.Name)
		}
		return fmt.Errorf("%s could not make its half: %s. Nothing was left behind; change what it says and try again", foreign, reason)
	}
	for _, w := range join.Warnings {
		j.say("Note from %s: %s", foreign, w)
	}
	j.say("Tunnel %q is running on both servers.", spec.Name)
	p.refreshOne(relayID)
	p.refreshOne(foreignID)
	return nil
}

// refreshOne asks a server for a fresh picture now, rather than at the next round.
func (p *Panel) refreshOne(id string) {
	if srv, ok := p.serverByID(id); ok {
		p.fleet.refresh(srv)
	}
}

func (p *Panel) deleteHalf(ctx context.Context, id, name string) error {
	var rep struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if _, err := p.callJSON(ctx, id, "/api/tunnel/delete", map[string]string{"name": name}, &rep); err != nil {
		return err
	}
	if !rep.OK {
		return errors.New(rep.Error)
	}
	return nil
}

// halfOutcome is what happened to one half of a tunnel.
type halfOutcome struct {
	Server string `json:"server"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	// Manual says what to do by hand when the panel could not do it.
	Manual string `json:"manual,omitempty"`
}

// tunnelTarget names a tunnel and the servers its halves are on; either may be
// empty when that half is on a server the panel does not manage.
type tunnelTarget struct {
	Name   string `json:"name"`
	Edge   string `json:"edge"`
	Origin string `json:"origin"`
}

func (t tunnelTarget) servers() []string {
	var out []string
	for _, id := range []string{t.Edge, t.Origin} {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

// deleteTunnel removes both halves, the foreign one first, and says what to do
// by hand for any half the panel could not remove.
func (p *Panel) deleteTunnel(t tunnelTarget) []halfOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), tunnelOpTimeout)
	defer cancel()
	var out []halfOutcome
	for _, id := range []string{t.Origin, t.Edge} {
		if id == "" {
			continue
		}
		o := halfOutcome{Server: p.serverName(id)}
		if err := p.deleteHalf(ctx, id, t.Name); err != nil {
			o.Error = plainAgentError(err)
			o.Manual = fmt.Sprintf("On %s, open portbridge-menu, choose \"Delete a tunnel\" and pick %s.", o.Server, t.Name)
		} else {
			o.OK = true
			p.refreshOne(id)
		}
		out = append(out, o)
	}
	p.healer.forget(t.Edge, t.Name)
	logf("deleted tunnel %q", t.Name)
	return out
}

// serviceTunnel starts, stops or restarts both halves.
func (p *Panel) serviceTunnel(t tunnelTarget, action string) []halfOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), tunnelOpTimeout)
	defer cancel()
	var out []halfOutcome
	for _, id := range t.servers() {
		o := halfOutcome{Server: p.serverName(id)}
		var rep struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_, err := p.callJSON(ctx, id, "/api/tunnel/service", map[string]string{"name": t.Name, "action": action}, &rep)
		switch {
		case errors.Is(err, errTooOld):
			o.Error = "PortBridge there is too old for this; update it first"
			o.Manual = fmt.Sprintf("On %s, open portbridge-menu, choose \"Start, stop or restart a tunnel\" and pick %s.", o.Server, t.Name)
		case err != nil:
			o.Error = plainAgentError(err)
		case !rep.OK:
			o.Error = rep.Error
		default:
			o.OK = true
			p.refreshOne(id)
		}
		out = append(out, o)
	}
	return out
}

// tunnelCode is the pairing code of a tunnel, from its relay server.
func (p *Panel) tunnelCode(edgeID, name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), agentTimeout)
	defer cancel()
	var rep struct {
		OK    bool   `json:"ok"`
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if _, err := p.callJSON(ctx, edgeID, "/api/tunnel/code", map[string]string{"name": name}, &rep); err != nil {
		return "", err
	}
	if !rep.OK {
		return "", errors.New(rep.Error)
	}
	return rep.Code, nil
}

// editTunnelRequest is what the "Edit tunnel" dialog sends.
type editTunnelRequest struct {
	Name                  string `json:"name"`
	Edge                  string `json:"edge"`
	Origin                string `json:"origin"`
	ServicePorts          string `json:"service_ports"`
	UserPorts             string `json:"user_ports"`
	LinkPort              int    `json:"link_port"`
	ProxyProtocol         string `json:"proxy_protocol"`
	Mux                   string `json:"mux"`
	Pool                  int    `json:"pool"`
	MuxLinks              int    `json:"mux_links"`
	MaxConn               int    `json:"max_conn"`
	SpareTTL              string `json:"spare_ttl"`
	Drain                 string `json:"drain"`
	PeerIP                string `json:"peer_ip"`
	Firewall              string `json:"firewall"`
	WebsiteDomains        string `json:"website_domains"`
	OutboundProxy         string `json:"outbound_proxy"`
	OutboundProxyPort     int    `json:"outbound_proxy_port"`
	OutboundProxyMode     string `json:"outbound_proxy_mode"`
	OutboundIranDomains   string `json:"outbound_iran_domains"`
	OutboundBypassDomains string `json:"outbound_bypass_domains"`
}

func (p *Panel) startEditTunnel(r editTunnelRequest) (string, error) {
	t := tunnelTarget{Name: strings.TrimSpace(r.Name), Edge: r.Edge, Origin: r.Origin}
	if err := p.knownTarget(t); err != nil {
		return "", err
	}
	if strings.TrimSpace(r.UserPorts) == "" && strings.TrimSpace(r.ServicePorts) != "" {
		r.UserPorts = r.ServicePorts
	}
	return p.startJob(func(j *job) (string, error) { return "", p.editTunnel(j, r) }), nil
}

func (p *Panel) editTunnel(j *job, r editTunnelRequest) error {
	// An Auto-Heal switch works on the same servers' settings files. The two
	// must not take turns in the middle of each other's prepare and commit.
	if p.healer != nil {
		defer p.healer.lockServers(r.Edge, r.Origin)()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*tunnelOpTimeout)
	defer cancel()

	spec := agent.EditSpec{
		Name:                  strings.TrimSpace(r.Name),
		UserPorts:             strings.TrimSpace(r.UserPorts),
		ServicePorts:          strings.TrimSpace(r.ServicePorts),
		LinkPort:              r.LinkPort,
		ProxyProtocol:         strings.TrimSpace(r.ProxyProtocol),
		Mux:                   strings.TrimSpace(r.Mux),
		Pool:                  r.Pool,
		MuxLinks:              r.MuxLinks,
		MaxConn:               r.MaxConn,
		SpareTTL:              strings.TrimSpace(r.SpareTTL),
		Drain:                 strings.TrimSpace(r.Drain),
		PeerIP:                strings.TrimSpace(r.PeerIP),
		Firewall:              strings.TrimSpace(r.Firewall),
		WebsiteDomains:        strings.TrimSpace(r.WebsiteDomains),
		OutboundProxy:         strings.TrimSpace(r.OutboundProxy),
		OutboundProxyPort:     r.OutboundProxyPort,
		OutboundProxyMode:     strings.TrimSpace(r.OutboundProxyMode),
		OutboundIranDomains:   strings.TrimSpace(r.OutboundIranDomains),
		OutboundBypassDomains: strings.TrimSpace(r.OutboundBypassDomains),
	}

	if r.Edge == "" && r.Origin != "" {
		foreign := p.serverName(r.Origin)
		j.say("Updating tunnel settings on %s...", foreign)
		var res agent.EdgeResult
		status, err := p.callJSON(ctx, r.Origin, "/api/tunnel/edit-edge", spec, &res)
		if errors.Is(err, errTooOld) {
			return fmt.Errorf("PortBridge on %s is too old to edit settings from the panel; update it first", foreign)
		}
		if err != nil {
			return fmt.Errorf("%s could not be reached: %s", foreign, plainAgentError(err))
		}
		if !res.OK {
			if res.Error == "" {
				res.Error = fmt.Sprintf("HTTP %d", status)
			}
			return fmt.Errorf("%s refused the change: %s", foreign, res.Error)
		}
		for _, w := range res.Warnings {
			j.say("Note from %s: %s", foreign, w)
		}
		j.say("Tunnel %q updated and restarted on %s.", spec.Name, foreign)
		p.refreshOne(r.Origin)
		return nil
	}

	relay := p.serverName(r.Edge)
	if r.Origin == "" {
		j.say("Updating tunnel %q on %s...", spec.Name, relay)
		var edge agent.EdgeResult
		status, err := p.callJSON(ctx, r.Edge, "/api/tunnel/edit-edge", spec, &edge)
		if errors.Is(err, errTooOld) {
			return fmt.Errorf("PortBridge on %s is too old to edit tunnels from the panel; update it first", relay)
		}
		if err != nil {
			return fmt.Errorf("%s could not be reached: %s", relay, plainAgentError(err))
		}
		if !edge.OK {
			if edge.Error == "" {
				edge.Error = fmt.Sprintf("HTTP %d", status)
			}
			return fmt.Errorf("%s refused the change: %s", relay, edge.Error)
		}
		for _, w := range edge.Warnings {
			j.say("Note from %s: %s", relay, w)
		}
		j.say("Tunnel %q updated and restarted on %s.", spec.Name, relay)
		p.refreshOne(r.Edge)
		return nil
	}

	foreign := p.serverName(r.Origin)
	j.say("Validating and preparing new settings on %s...", relay)
	spec.Stage = "prepare"
	var prep agent.EdgeResult
	status, err := p.callJSON(ctx, r.Edge, "/api/tunnel/edit-edge", spec, &prep)
	if errors.Is(err, errTooOld) {
		return fmt.Errorf("PortBridge on %s is too old to edit tunnels from the panel; update it first", relay)
	}
	if err != nil {
		return fmt.Errorf("%s could not be reached: %s", relay, plainAgentError(err))
	}
	if !prep.OK {
		if prep.Error == "" {
			prep.Error = fmt.Sprintf("HTTP %d", status)
		}
		return fmt.Errorf("%s refused the change: %s", relay, prep.Error)
	}
	for _, w := range prep.Warnings {
		j.say("Note from %s: %s", relay, w)
	}

	j.say("Applying firewall rules and restarting %s...", relay)
	var commit agent.EdgeResult
	cstatus, cerr := p.callJSON(ctx, r.Edge, "/api/tunnel/edit-edge", agent.EditSpec{
		Name:    spec.Name,
		Stage:   "commit",
		OldConf: prep.OldConf,
	}, &commit)
	if cerr != nil {
		return fmt.Errorf("%s could not finish restarting: %s", relay, plainAgentError(cerr))
	}
	if !commit.OK {
		if commit.Error == "" {
			commit.Error = fmt.Sprintf("HTTP %d", cstatus)
		}
		return fmt.Errorf("%s could not restart on the new settings: %s", relay, commit.Error)
	}
	for _, w := range commit.Warnings {
		j.say("Note from %s: %s", relay, w)
	}

	j.say("Applying updated configuration to %s...", foreign)
	var upd struct {
		OK       bool     `json:"ok"`
		Error    string   `json:"error"`
		Warnings []string `json:"warnings"`
	}
	_, uerr := p.callJSON(ctx, r.Origin, "/api/tunnel/update", map[string]string{"code": prep.Code}, &upd)
	if uerr == nil && !upd.OK {
		uerr = errors.New(upd.Error)
	}
	if uerr != nil {
		reason := uerr.Error()
		if !errors.Is(uerr, errTooOld) {
			reason = plainAgentError(uerr)
		}
		j.say("%s did not accept the change: %s", foreign, reason)
		j.say("Restoring previous settings on %s so nothing is left out of sync...", relay)
		var rb agent.EdgeResult
		_, _ = p.callJSON(ctx, r.Edge, "/api/tunnel/edit-edge", agent.EditSpec{
			Name:    spec.Name,
			Stage:   "rollback",
			OldConf: prep.OldConf,
		}, &rb)
		return fmt.Errorf("%s refused the change: %s. Nothing was changed on either server", foreign, reason)
	}
	for _, w := range upd.Warnings {
		j.say("Note from %s: %s", foreign, w)
	}
	j.say("%s updated and restarted.", foreign)

	j.say("Tunnel %q is updated and running on both servers.", spec.Name)
	p.refreshOne(r.Edge)
	p.refreshOne(r.Origin)
	return nil
}

type halfLogs struct {
	Server string `json:"server"`
	Role   string `json:"role"`
	OK     bool   `json:"ok"`
	Logs   string `json:"logs,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (p *Panel) tunnelLogs(parent context.Context, t tunnelTarget) []halfLogs {
	ctx, cancel := context.WithTimeout(parent, agentTimeout)
	defer cancel()
	var out []halfLogs
	for _, pair := range []struct {
		id, role string
	}{
		{t.Edge, "Relay (Iran)"},
		{t.Origin, "Foreign"},
	} {
		if pair.id == "" {
			continue
		}
		hl := halfLogs{Server: p.serverName(pair.id), Role: pair.role}
		var rep struct {
			OK    bool   `json:"ok"`
			Logs  string `json:"logs"`
			Error string `json:"error"`
		}
		_, err := p.callJSON(ctx, pair.id, "/api/tunnel/logs", map[string]any{"name": t.Name, "lines": 60}, &rep)
		switch {
		case errors.Is(err, errTooOld):
			hl.Error = "PortBridge on this server is from an older release; update it in Settings -> Software Updates to view logs from the panel."
		case err != nil:
			hl.Error = plainAgentError(err)
		case !rep.OK:
			hl.Error = rep.Error
		default:
			hl.OK = true
			hl.Logs = rep.Logs
		}
		out = append(out, hl)
	}
	return out
}

type halfCheck struct {
	Server string            `json:"server"`
	Role   string            `json:"role"`
	OK     bool              `json:"ok"`
	Checks []agent.CheckItem `json:"checks,omitempty"`
	Error  string            `json:"error,omitempty"`
}

func (p *Panel) checkTunnel(parent context.Context, t tunnelTarget) []halfCheck {
	ctx, cancel := context.WithTimeout(parent, agentTimeout)
	defer cancel()
	var out []halfCheck
	for _, pair := range []struct {
		id, role string
	}{
		{t.Edge, "Relay (Iran) · Entry"},
		{t.Origin, "Foreign · Exit"},
	} {
		if pair.id == "" {
			continue
		}
		hc := halfCheck{Server: p.serverName(pair.id), Role: pair.role}
		var rep struct {
			OK     bool              `json:"ok"`
			Checks []agent.CheckItem `json:"checks"`
			Error  string            `json:"error"`
		}
		_, err := p.callJSON(ctx, pair.id, "/api/tunnel/check", map[string]string{"name": t.Name}, &rep)
		switch {
		case errors.Is(err, errTooOld):
			// Build diagnostic checks from the cached Overview and /api/ports so
			// even an older server gives useful answers.
			if checks, ok := p.fallbackCheck(ctx, pair.id, t.Name); ok {
				hc.OK = true
				hc.Checks = checks
			} else {
				hc.Error = "PortBridge on this server is from an older release; update it to run deep diagnostics."
			}
		case err != nil:
			hc.Error = plainAgentError(err)
		case !rep.OK:
			hc.Error = rep.Error
		default:
			hc.OK = true
			hc.Checks = rep.Checks
		}
		out = append(out, hc)
	}
	return out
}

func (p *Panel) fallbackCheck(ctx context.Context, id, name string) ([]agent.CheckItem, bool) {
	v, ok := p.viewOf(id)
	if !ok || v.Overview == nil {
		return nil, false
	}
	var ti *agent.TunnelInfo
	for i := range v.Overview.Tunnels {
		if v.Overview.Tunnels[i].Name == name {
			ti = &v.Overview.Tunnels[i]
			break
		}
	}
	if ti == nil {
		return nil, false
	}
	var checks []agent.CheckItem
	add := func(label, status, detail, note string) {
		checks = append(checks, agent.CheckItem{Label: label, Status: status, Detail: detail, Note: note})
	}
	if ti.Running {
		add("Tunnel service", "ok", "Active and running", "")
	} else {
		add("Tunnel service", "bad", "Stopped", ti.ServiceNote)
	}
	if ti.Role == "origin" && len(ti.ServicePorts) > 0 {
		if st, err := p.portsThere(ctx, id, ti.ServicePorts); err == nil {
			for _, sp := range ti.ServicePorts {
				if ps, exists := st[sp]; exists {
					if ps.State == "free" {
						add(fmt.Sprintf("Inbound service port %d", sp), "bad", fmt.Sprintf("Nothing listening on port %d", sp), "Make sure your X-UI / Xray / inbound service is running.")
					} else {
						add(fmt.Sprintf("Inbound service port %d", sp), "ok", fmt.Sprintf("Active service listening%s", byWhom(ps.By)), "")
					}
				}
			}
		}
	}
	if ti.Live != nil {
		if ti.Mux {
			if ti.Live.Links > 0 {
				add("Inter-server link", "ok", fmt.Sprintf("Connected (%d / %d shared Mux links open)", ti.Live.Links, max(1, ti.Live.LinkTarget)), "")
			} else {
				add("Inter-server link", "bad", "0 shared links open", "")
			}
		} else {
			if ti.Live.ParkedSpares > 0 {
				add("Inter-server link", "ok", fmt.Sprintf("Connected (%d / %d spare connections ready)", ti.Live.ParkedSpares, max(1, ti.Live.PoolTarget)), "")
			} else {
				add("Inter-server link", "bad", "0 spare connections ready", "")
			}
		}
		switch ti.Live.PathState {
		case "ok":
			add("End-to-end data flow", "ok", "Healthy", "")
		case "degraded":
			add("End-to-end data flow", "warn", "Degraded", ti.Live.PathNote)
		case "blocked":
			add("End-to-end data flow", "bad", "Blocked", ti.Live.PathNote)
		}
	}
	return checks, true
}

func (p *Panel) speedtestTunnel(parent context.Context, t tunnelTarget) (string, string, error) {
	// A test can run for up to two minutes on a slow link (the longer timed
	// transfers); 90 seconds cut it off and left no time to try the other half.
	ctx, cancel := context.WithTimeout(parent, 160*time.Second)
	defer cancel()

	// Prefer running the speedtest from the panel's own server ("this") when it is
	// one of the tunnel's endpoints, or from the Relay server first.
	order := []string{}
	if t.Edge == "this" || (t.Edge != "" && t.Origin != "this") {
		if t.Edge != "" {
			order = append(order, t.Edge)
		}
		if t.Origin != "" {
			order = append(order, t.Origin)
		}
	} else {
		if t.Origin != "" {
			order = append(order, t.Origin)
		}
		if t.Edge != "" {
			order = append(order, t.Edge)
		}
	}

	var lastErr error
	var lastSrv, lastOut string
	for _, id := range order {
		srvName := p.serverName(id)
		var rep struct {
			OK     bool   `json:"ok"`
			Output string `json:"output"`
			Error  string `json:"error"`
		}
		_, err := p.callJSON(ctx, id, "/api/tunnel/speedtest", map[string]any{"name": t.Name, "size_mb": 1.0}, &rep)
		if err == nil && rep.OK {
			return srvName, rep.Output, nil
		}
		lastSrv = srvName
		lastOut = rep.Output
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New(rep.Error)
		}
	}
	return lastSrv, lastOut, lastErr
}

func (p *Panel) getServerTune(parent context.Context, id string) (agent.TuneInfo, error) {
	ctx, cancel := context.WithTimeout(parent, agentTimeout)
	defer cancel()
	status, rb, err := p.callServer(ctx, id, http.MethodGet, "/api/tune", nil, overviewLimit)
	if err != nil {
		return agent.TuneInfo{}, err
	}
	if status == http.StatusNotFound {
		return agent.TuneInfo{}, errTooOld
	}
	var info agent.TuneInfo
	if err := json.Unmarshal(rb, &info); err != nil {
		return agent.TuneInfo{}, err
	}
	return info, nil
}

func (p *Panel) setServerTune(parent context.Context, id string, enable bool) (agent.TuneInfo, error) {
	ctx, cancel := context.WithTimeout(parent, agentTimeout)
	defer cancel()
	var rep struct {
		agent.TuneInfo
		Error string `json:"error"`
	}
	_, err := p.callJSON(ctx, id, "/api/tune", map[string]bool{"enable": enable}, &rep)
	if err != nil {
		return agent.TuneInfo{}, err
	}
	if !rep.OK {
		return agent.TuneInfo{}, errors.New(rep.Error)
	}
	return rep.TuneInfo, nil
}

func (p *Panel) getServerFirewall(parent context.Context, id string) (agent.FirewallInfo, error) {
	ctx, cancel := context.WithTimeout(parent, agentTimeout)
	defer cancel()
	status, rb, err := p.callServer(ctx, id, http.MethodGet, "/api/firewall", nil, overviewLimit)
	if err != nil {
		return agent.FirewallInfo{}, err
	}
	if status == http.StatusNotFound {
		// Fallback for older agents using cached Overview.
		if v, ok := p.viewOf(id); ok && v.Overview != nil {
			var rules []agent.FirewallTunnelRule
			var lines []string
			for _, ti := range v.Overview.Tunnels {
				dials := (ti.Mode == "direct" && ti.Role == "edge") || (ti.Mode == "reverse" && ti.Role == "origin")
				cdnOrGRE := ti.CDN || ti.GRE
				locked := ti.Firewall && !dials && !cdnOrGRE
				rules = append(rules, agent.FirewallTunnelRule{
					Name:     ti.Name,
					Role:     ti.Role,
					Mode:     ti.Mode,
					DialsOut: dials,
					LinkPort: ti.LinkPort,
					PeerIP:   ti.PeerIP,
					Locked:   locked,
					CDNOrGRE: cdnOrGRE,
				})
				switch {
				case dials:
					lines = append(lines, fmt.Sprintf("%s: dials out to %s:%d", ti.Name, ti.PeerIP, ti.LinkPort))
				case cdnOrGRE:
					lines = append(lines, fmt.Sprintf("%s: bridge port %d open (CDN / GRE)", ti.Name, ti.LinkPort))
				case locked:
					lines = append(lines, fmt.Sprintf("%s: bridge port %d locked to %s", ti.Name, ti.LinkPort, ti.PeerIP))
				default:
					lines = append(lines, fmt.Sprintf("%s: bridge port %d open to any IP", ti.Name, ti.LinkPort))
				}
			}
			st := strings.Join(lines, "\n")
			if st == "" {
				st = "No tunnels on this server."
			}
			return agent.FirewallInfo{OK: true, Status: st, Tunnels: rules}, nil
		}
		return agent.FirewallInfo{}, errTooOld
	}
	var info agent.FirewallInfo
	if err := json.Unmarshal(rb, &info); err != nil {
		return agent.FirewallInfo{}, err
	}
	return info, nil
}

func (p *Panel) setServerFirewall(parent context.Context, id, action string) (agent.FirewallInfo, error) {
	ctx, cancel := context.WithTimeout(parent, agentTimeout)
	defer cancel()
	var rep struct {
		agent.FirewallInfo
		Error string `json:"error"`
	}
	_, err := p.callJSON(ctx, id, "/api/firewall", map[string]string{"action": action}, &rep)
	if err != nil {
		return agent.FirewallInfo{}, err
	}
	if !rep.OK {
		return agent.FirewallInfo{}, errors.New(rep.Error)
	}
	return rep.FirewallInfo, nil
}

func serverAddresses(v serverView) (v4, v6 string) {
	if v.Overview != nil {
		if len(v.Overview.IPv4) > 0 {
			v4 = v.Overview.IPv4[0]
		}
		if len(v.Overview.IPv6) > 0 {
			v6 = v.Overview.IPv6[0]
		}
	}
	if v4 == "" && v.Address != "" {
		if ip := net.ParseIP(v.Address); ip != nil && ip.To4() == nil {
			if v6 == "" {
				v6 = v.Address
			}
		} else {
			v4 = v.Address
		}
	}
	return v4, v6
}

type probeSession struct {
	RelayID         string                      `json:"relay_id"`
	ForeignID       string                      `json:"foreign_id"`
	CDNDomain       string                      `json:"cdn_domain"`
	DirectListenID  string                      `json:"direct_listen_id"`
	DirectSecret    string                      `json:"direct_secret"`
	ReverseListenID string                      `json:"reverse_listen_id"`
	ReverseSecret   string                      `json:"reverse_secret"`
	Candidates      []engine.ProbeCandidateSpec `json:"candidates"`
	Notes           []string                    `json:"notes,omitempty"`
}

type probeListenReply struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
	Error  string `json:"error"`
}

type probeDialReply struct {
	OK      bool                          `json:"ok"`
	Results []engine.ProbeCandidateResult `json:"results"`
	Error   string                        `json:"error"`
}

func (p *Panel) startProbeSession(parent context.Context, relayID, foreignID, cdnDomain string) (*probeSession, error) {
	rv, rok := p.viewOf(relayID)
	fv, fok := p.viewOf(foreignID)
	if !rok || !fok {
		return nil, errors.New("both the Relay and Foreign servers must be added to the panel first")
	}
	if !rv.Online {
		return nil, fmt.Errorf("Relay server %s is currently offline", rv.Name)
	}
	if !fv.Online {
		return nil, fmt.Errorf("Foreign server %s is currently offline", fv.Name)
	}

	relayV4, relayV6 := serverAddresses(rv)
	foreignV4, foreignV6 := serverAddresses(fv)
	fv6 := ""
	rv6 := ""
	if relayV6 != "" && foreignV6 != "" {
		fv6 = foreignV6
		rv6 = relayV6
	}

	startListen := func(listenerID string, prefPort int) (probeListenReply, error) {
		lctx, lcancel := context.WithTimeout(parent, 15*time.Second)
		defer lcancel()
		var lrep probeListenReply
		_, err := p.callJSON(lctx, listenerID, "/api/probe/listen", map[string]int{"preferred_port": prefPort}, &lrep)
		if err != nil {
			if errors.Is(err, errTooOld) {
				return probeListenReply{}, fmt.Errorf("%s is running an older PortBridge release; update it first to use Smart Benchmark", p.serverName(listenerID))
			}
			return probeListenReply{}, fmt.Errorf("%s listener: %s", p.serverName(listenerID), plainAgentError(err))
		}
		if !lrep.OK {
			return probeListenReply{}, fmt.Errorf("%s listener: %s", p.serverName(listenerID), lrep.Error)
		}
		return lrep, nil
	}

	var (
		wg      sync.WaitGroup
		dListen probeListenReply
		rListen probeListenReply
		dErr    error
		rErr    error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		dListen, dErr = startListen(foreignID, 2053)
	}()
	go func() {
		defer wg.Done()
		rListen, rErr = startListen(relayID, 2083)
	}()
	wg.Wait()

	if dErr != nil && rErr != nil {
		return nil, dErr
	}

	sess := &probeSession{
		RelayID:   relayID,
		ForeignID: foreignID,
		CDNDomain: cdnDomain,
	}
	if dErr == nil {
		sess.DirectListenID = dListen.ID
		sess.DirectSecret = dListen.Secret
		sess.Candidates = append(sess.Candidates, engine.BuildProbeCandidates("direct", foreignV4, fv6, dListen.Port, cdnDomain)...)
	} else {
		sess.Notes = append(sess.Notes, "Direct listener note: "+dErr.Error())
	}
	if rErr == nil {
		sess.ReverseListenID = rListen.ID
		sess.ReverseSecret = rListen.Secret
		sess.Candidates = append(sess.Candidates, engine.BuildProbeCandidates("reverse", relayV4, rv6, rListen.Port, "")...)
	} else {
		sess.Notes = append(sess.Notes, "Reverse listener note: "+rErr.Error())
	}
	return sess, nil
}

// checkProbeStep refuses a probe step that does not point at a server of the
// fleet: the step comes back from the browser, so it is checked again rather
// than trusted. A server made to dial an address outside the fleet could be
// used to reach things on its network.
func (p *Panel) checkProbeStep(dialerID, secret string, spec engine.ProbeCandidateSpec) error {
	if _, ok := p.viewOf(dialerID); !ok {
		return errors.New("that server is not in the panel")
	}
	if secret == "" {
		return errors.New("the probe has no secret")
	}
	host, portStr, err := net.SplitHostPort(spec.TargetAddr)
	if err != nil || host == "" {
		return errors.New("the probe target is not an address and port")
	}
	if port, err := strconv.Atoi(portStr); err != nil || port < 1 || port > 65535 {
		return errors.New("the probe target port is not valid")
	}
	if net.ParseIP(host) == nil {
		// A name is only for the CDN checks.
		if spec.CDN {
			return nil
		}
		return errors.New("the probe target is not one of the panel's servers")
	}
	for _, v := range p.fleet.views() {
		v4, v6 := serverAddresses(v)
		for _, a := range []string{v4, v6, v.Address} {
			if a != "" && net.ParseIP(a) != nil && net.ParseIP(a).Equal(net.ParseIP(host)) {
				return nil
			}
		}
	}
	return errors.New("the probe target is not one of the panel's servers")
}

func (p *Panel) runProbeStep(parent context.Context, dialerID, secret string, spec engine.ProbeCandidateSpec) (engine.ProbeCandidateResult, error) {
	if err := p.checkProbeStep(dialerID, secret, spec); err != nil {
		return engine.ProbeCandidateResult{}, err
	}
	// Two attempts must fit. Each is planned at 6.5 s (10 s with Anti-Freeze
	// rotation) but may run to 16 s (22 s) while a slow link's data is still
	// moving; cut short, a slow but working candidate came back as unreachable.
	stepTimeout := 40 * time.Second
	if spec.AntiFreeze {
		stepTimeout = 52 * time.Second
	}
	dctx, dcancel := context.WithTimeout(parent, stepTimeout)
	defer dcancel()
	burstBytes := 0
	if spec.Gaming {
		burstBytes = 64 * 1024
	}
	var drep probeDialReply
	_, err := p.callJSON(dctx, dialerID, "/api/probe/dial", map[string]any{
		"specs":       []engine.ProbeCandidateSpec{spec},
		"secret":      secret,
		"burst_bytes": burstBytes,
	}, &drep)
	if err != nil {
		return engine.ProbeCandidateResult{
			ProbeCandidateSpec: spec,
			Status:             "blocked",
			Attempts:           1,
			Error:              plainAgentError(err),
			Summary:            "Blocked / Unreachable — " + plainAgentError(err),
		}, nil
	}
	if !drep.OK || len(drep.Results) == 0 {
		msg := drep.Error
		if msg == "" {
			msg = "probe failed"
		}
		return engine.ProbeCandidateResult{
			ProbeCandidateSpec: spec,
			Status:             "blocked",
			Attempts:           1,
			Error:              msg,
			Summary:            "Blocked / Unreachable — " + msg,
		}, nil
	}
	res := drep.Results[0]
	if spec.Gaming && !res.Gaming {
		res.Gaming = true
		if res.Status == "ok" {
			res.Summary = engine.GamingSummary(res.RTTMS, res.JitterMS)
		}
	}
	return res, nil
}

func (p *Panel) finishProbeSession(sess probeSession, results []engine.ProbeCandidateResult) *engine.ProbeBenchmarkReport {
	var wg sync.WaitGroup
	if sess.ForeignID != "" && sess.DirectListenID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer scancel()
			var dummy map[string]any
			_, _ = p.callJSON(sctx, sess.ForeignID, "/api/probe/stop", map[string]string{"id": sess.DirectListenID}, &dummy)
		}()
	}
	if sess.RelayID != "" && sess.ReverseListenID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer scancel()
			var dummy map[string]any
			_, _ = p.callJSON(sctx, sess.RelayID, "/api/probe/stop", map[string]string{"id": sess.ReverseListenID}, &dummy)
		}()
	}
	wg.Wait()

	rep := engine.FinalizeProbeReport(results, sess.CDNDomain)
	rep.Notes = append(rep.Notes, sess.Notes...)
	return rep
}

func (p *Panel) probeBetweenServers(parent context.Context, relayID, foreignID, cdnDomain string) (*engine.ProbeBenchmarkReport, error) {
	sess, err := p.startProbeSession(parent, relayID, foreignID, cdnDomain)
	if err != nil {
		return nil, err
	}
	var directSpecs, reverseSpecs []engine.ProbeCandidateSpec
	for _, spec := range sess.Candidates {
		if spec.Mode == "reverse" {
			reverseSpecs = append(reverseSpecs, spec)
		} else {
			directSpecs = append(directSpecs, spec)
		}
	}

	var (
		wg         sync.WaitGroup
		directRes  []engine.ProbeCandidateResult
		reverseRes []engine.ProbeCandidateResult
	)
	if len(directSpecs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var drep probeDialReply
			_, err := p.callJSON(parent, sess.RelayID, "/api/probe/dial", map[string]any{
				"specs":       directSpecs,
				"secret":      sess.DirectSecret,
				"burst_bytes": 0,
			}, &drep)
			if err == nil && drep.OK {
				directRes = drep.Results
			}
		}()
	}
	if len(reverseSpecs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var rrep probeDialReply
			_, err := p.callJSON(parent, sess.ForeignID, "/api/probe/dial", map[string]any{
				"specs":       reverseSpecs,
				"secret":      sess.ReverseSecret,
				"burst_bytes": 0,
			}, &rrep)
			if err == nil && rrep.OK {
				reverseRes = rrep.Results
			}
		}()
	}
	wg.Wait()

	results := append(directRes, reverseRes...)
	return p.finishProbeSession(*sess, results), nil
}

type sniScanReport struct {
	OK      bool                   `json:"ok"`
	BestSNI string                 `json:"best_sni,omitempty"`
	Results []engine.SNIScanResult `json:"results"`
}

func (p *Panel) scanRelaySNIs(parent context.Context, relayID string, candidates []string) (*sniScanReport, error) {
	rv, rok := p.viewOf(relayID)
	if !rok {
		return nil, errors.New("choose a Relay (Iran) server first")
	}
	if !rv.Online {
		return nil, fmt.Errorf("Relay server %s is currently offline", rv.Name)
	}
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	var rep struct {
		OK      bool                   `json:"ok"`
		Results []engine.SNIScanResult `json:"results"`
		Error   string                 `json:"error"`
	}
	_, err := p.callJSON(ctx, relayID, "/api/probe/sni-scan", map[string]any{
		"candidates": candidates,
	}, &rep)
	if err != nil {
		if errors.Is(err, errTooOld) {
			return nil, fmt.Errorf("%s is running an older PortBridge release; update it first to scan whitelisted SNIs", p.serverName(relayID))
		}
		return nil, fmt.Errorf("%s: %s", p.serverName(relayID), plainAgentError(err))
	}
	if !rep.OK {
		return nil, errors.New(rep.Error)
	}
	best := ""
	for _, r := range rep.Results {
		if r.Reachable {
			best = r.SNI
			break
		}
	}
	return &sniScanReport{
		OK:      true,
		BestSNI: best,
		Results: rep.Results,
	}, nil
}

type sniSpoofTestReport struct {
	OK          bool                         `json:"ok"`
	SpoofSNI    string                       `json:"spoof_sni"`
	RelayName   string                       `json:"relay_name"`
	ForeignName string                       `json:"foreign_name"`
	Direct      *engine.ProbeCandidateResult `json:"direct,omitempty"`
	Reverse     *engine.ProbeCandidateResult `json:"reverse,omitempty"`
	Summary     string                       `json:"summary"`
}

func (p *Panel) testSNISpoofTunnel(parent context.Context, relayID, foreignID, spoofSNI string) (*sniSpoofTestReport, error) {
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
	spoofSNI = strings.TrimSpace(spoofSNI)
	if spoofSNI == "" {
		spoofSNI = engine.DefaultSpoofSNI
	}

	sess, err := p.startProbeSession(parent, relayID, foreignID, "")
	if err != nil {
		return nil, err
	}
	defer func() {
		p.finishProbeSession(*sess, nil)
	}()

	relayV4, relayV6 := serverAddresses(rv)
	foreignV4, foreignV6 := serverAddresses(fv)
	hasBothV6 := relayV6 != "" && foreignV6 != ""

	findPort := func(mode string) int {
		for _, c := range sess.Candidates {
			if c.Mode == mode && c.Port > 0 {
				return c.Port
			}
		}
		return 0
	}
	dPort := findPort("direct")
	rPort := findPort("reverse")

	var (
		wg        sync.WaitGroup
		directRes *engine.ProbeCandidateResult
		revRes    *engine.ProbeCandidateResult
	)

	if dPort > 0 && (foreignV4 != "" || hasBothV6) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			target := net.JoinHostPort(foreignV4, strconv.Itoa(dPort))
			isV6 := false
			if foreignV4 == "" && hasBothV6 {
				target = net.JoinHostPort(foreignV6, strconv.Itoa(dPort))
				isV6 = true
			}
			spec := engine.ProbeCandidateSpec{
				ID:         "direct-sni-spoof",
				Label:      fmt.Sprintf("Direct (%s -> %s)", rv.Name, fv.Name),
				Mode:       "direct",
				Link:       "sni-spoof",
				Transport:  "tls",
				Stealth:    true,
				SNISpoof:   true,
				SpoofSNI:   spoofSNI,
				IPv6:       isV6,
				ServerName: spoofSNI,
				TargetAddr: target,
				Port:       dPort,
			}
			res, _ := p.runProbeStep(parent, relayID, sess.DirectSecret, spec)
			if res.Status != "ok" && !isV6 && hasBothV6 {
				spec6 := spec
				spec6.ID = "direct-ipv6-sni-spoof"
				spec6.IPv6 = true
				spec6.TargetAddr = net.JoinHostPort(foreignV6, strconv.Itoa(dPort))
				res6, _ := p.runProbeStep(parent, relayID, sess.DirectSecret, spec6)
				if res6.Status == "ok" {
					res = res6
				}
			}
			directRes = &res
		}()
	}

	if rPort > 0 && (relayV4 != "" || hasBothV6) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			target := net.JoinHostPort(relayV4, strconv.Itoa(rPort))
			isV6 := false
			if relayV4 == "" && hasBothV6 {
				target = net.JoinHostPort(relayV6, strconv.Itoa(rPort))
				isV6 = true
			}
			spec := engine.ProbeCandidateSpec{
				ID:         "reverse-sni-spoof",
				Label:      fmt.Sprintf("Reverse (%s -> %s)", fv.Name, rv.Name),
				Mode:       "reverse",
				Link:       "sni-spoof",
				Transport:  "tls",
				Stealth:    true,
				SNISpoof:   true,
				SpoofSNI:   spoofSNI,
				IPv6:       isV6,
				ServerName: spoofSNI,
				TargetAddr: target,
				Port:       rPort,
			}
			res, _ := p.runProbeStep(parent, foreignID, sess.ReverseSecret, spec)
			if res.Status != "ok" && !isV6 && hasBothV6 {
				spec6 := spec
				spec6.ID = "reverse-ipv6-sni-spoof"
				spec6.IPv6 = true
				spec6.TargetAddr = net.JoinHostPort(relayV6, strconv.Itoa(rPort))
				res6, _ := p.runProbeStep(parent, foreignID, sess.ReverseSecret, spec6)
				if res6.Status == "ok" {
					res = res6
				}
			}
			revRes = &res
		}()
	}
	wg.Wait()

	dOK := directRes != nil && (directRes.Status == "ok" || directRes.Status == "degraded")
	rOK := revRes != nil && (revRes.Status == "ok" || revRes.Status == "degraded")
	var summary string
	switch {
	case dOK && rOK:
		summary = fmt.Sprintf("Decoy Whitelisted SNI Spoofing (%s) works in both Direct and Reverse mode between %s and %s!", spoofSNI, rv.Name, fv.Name)
	case dOK:
		summary = fmt.Sprintf("Decoy Whitelisted SNI Spoofing (%s) works in Direct Mode (%s -> %s)!", spoofSNI, rv.Name, fv.Name)
	case rOK:
		summary = fmt.Sprintf("Decoy Whitelisted SNI Spoofing (%s) works in Reverse Mode (%s -> %s)!", spoofSNI, fv.Name, rv.Name)
	default:
		summary = fmt.Sprintf("Direct TCP connection between %s and %s could not complete handshake with %s. Try scanning another SNI or using Cloudflare CDN / KCP.", rv.Name, fv.Name, spoofSNI)
	}

	return &sniSpoofTestReport{
		OK:          true,
		SpoofSNI:    spoofSNI,
		RelayName:   rv.Name,
		ForeignName: fv.Name,
		Direct:      directRes,
		Reverse:     revRes,
		Summary:     summary,
	}, nil
}

type spoofTestReport struct {
	SpoofIP                string `json:"spoof_ip"`
	RelayName              string `json:"relay_name"`
	ForeignName            string `json:"foreign_name"`
	ForeignToRelaySpoofOK  bool   `json:"foreign_to_relay_spoof_ok"`
	ForeignToRelayNormalOK bool   `json:"foreign_to_relay_normal_ok"`
	RelayToForeignSpoofOK  bool   `json:"relay_to_foreign_spoof_ok"`
	RelayToForeignNormalOK bool   `json:"relay_to_foreign_normal_ok"`
	ForeignRawError        string `json:"foreign_raw_error,omitempty"`
	RelayRawError          string `json:"relay_raw_error,omitempty"`
	Mode                   string `json:"mode"` // "symmetric", "asymmetric-foreign", "asymmetric-relay", "filtered"
	Summary                string `json:"summary"`
}

func (p *Panel) testSpoofSupport(parent context.Context, relayID, foreignID, spoofIP string) (*spoofTestReport, error) {
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
	relayV4, _ := serverAddresses(rv)
	foreignV4, _ := serverAddresses(fv)
	if relayV4 == "" || foreignV4 == "" {
		return nil, errors.New("both servers must have public IPv4 addresses for IP spoofing")
	}
	spoofIP = strings.TrimSpace(spoofIP)
	if spoofIP == "" {
		spoofIP = engine.DefaultSpoofIP
	}
	if ip := net.ParseIP(spoofIP); ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("spoof IP %q must be a valid IPv4 address", spoofIP)
	}

	runDir := func(senderID, receiverID, receiverIP string, port int) (engine.SpoofProbeListenResult, engine.SpoofProbeSendResult, error) {
		token := fmt.Sprintf("%d", time.Now().UnixNano())
		listenDone := make(chan struct{})
		var (
			wg      sync.WaitGroup
			lRes    engine.SpoofProbeListenResult
			sRes    engine.SpoofProbeSendResult
			lCallEr error
			sCallEr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer close(listenDone)
			lctx, lcancel := context.WithTimeout(parent, 14*time.Second)
			defer lcancel()
			var rep struct {
				OK     bool                          `json:"ok"`
				Result engine.SpoofProbeListenResult `json:"result"`
				Error  string                        `json:"error"`
			}
			_, lCallEr = p.callJSON(lctx, receiverID, "/api/probe/spoof-listen", map[string]any{
				"listen_addr": fmt.Sprintf("0.0.0.0:%d", port),
				"token":       token,
				"timeout_ms":  4800,
			}, &rep)
			lRes = rep.Result
		}()
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 3; attempt++ {
				wait := 300 * time.Millisecond
				if attempt > 0 {
					wait = 1300 * time.Millisecond
				}
				select {
				case <-listenDone:
					return
				case <-time.After(wait):
				}
				sctx, scancel := context.WithTimeout(parent, 8*time.Second)
				var rep struct {
					OK     bool                        `json:"ok"`
					Result engine.SpoofProbeSendResult `json:"result"`
					Error  string                      `json:"error"`
				}
				_, err := p.callJSON(sctx, senderID, "/api/probe/spoof-send", map[string]any{
					"target_addr": net.JoinHostPort(receiverIP, strconv.Itoa(port)),
					"spoof_ip":    spoofIP,
					"token":       token,
				}, &rep)
				scancel()
				if err == nil {
					sRes = rep.Result
					sCallEr = nil
				} else if attempt == 0 {
					sCallEr = err
				}
			}
		}()
		wg.Wait()
		if lCallEr != nil {
			return lRes, sRes, lCallEr
		}
		if sCallEr != nil {
			return lRes, sRes, sCallEr
		}
		return lRes, sRes, nil
	}

	// Direction 1: Foreign -> Relay (Iran) on standard Cloudflare UDP port 2083
	f2rListen, f2rSend, err1 := runDir(foreignID, relayID, relayV4, 2083)
	if err1 != nil {
		if errors.Is(err1, errTooOld) {
			return nil, errors.New("one or both servers are running an older PortBridge release; update both servers first")
		}
		return nil, fmt.Errorf("testing Foreign -> Relay: %s", plainAgentError(err1))
	}
	// Direction 2: Relay (Iran) -> Foreign on standard Cloudflare UDP port 2053
	r2fListen, r2fSend, err2 := runDir(relayID, foreignID, foreignV4, 2053)
	if err2 != nil {
		return nil, fmt.Errorf("testing Relay -> Foreign: %s", plainAgentError(err2))
	}

	rName := p.serverName(relayID)
	fName := p.serverName(foreignID)
	rep := &spoofTestReport{
		SpoofIP:                spoofIP,
		RelayName:              rName,
		ForeignName:            fName,
		ForeignToRelaySpoofOK:  f2rListen.ReceivedSpoofed,
		ForeignToRelayNormalOK: f2rListen.ReceivedNormal,
		RelayToForeignSpoofOK:  r2fListen.ReceivedSpoofed,
		RelayToForeignNormalOK: r2fListen.ReceivedNormal,
		ForeignRawError:        f2rSend.RawError,
		RelayRawError:          r2fSend.RawError,
	}

	switch {
	case rep.ForeignToRelaySpoofOK && rep.RelayToForeignSpoofOK:
		rep.Mode = "symmetric"
		rep.Summary = fmt.Sprintf("Both %s and %s allow outbound Source IP Spoofing (%s). Full two-way Source IP + SNI Spoofing works between these servers!",
			fName, rName, spoofIP)
	case rep.ForeignToRelaySpoofOK:
		rep.Mode = "asymmetric-foreign"
		rep.Summary = fmt.Sprintf("%s allows outbound Source IP Spoofing (%s -> %s), and %s will automatically use standard encrypted UDP for the other direction. You can create a Source IP + SNI Spoof tunnel!",
			fName, spoofIP, rName, rName)
	case rep.RelayToForeignSpoofOK:
		rep.Mode = "asymmetric-relay"
		rep.Summary = fmt.Sprintf("%s allows outbound Source IP Spoofing (%s -> %s), and %s will automatically use standard encrypted UDP for return packets. You can create a Source IP + SNI Spoof tunnel!",
			rName, spoofIP, fName, fName)
	default:
		rep.Mode = "filtered"
		rep.Summary = fmt.Sprintf("Neither datacenter allows forged source IPs (%s was dropped by the datacenter routers). Switch to \"Decoy Whitelisted SNI Spoof\" above — it works on all VPS providers without IP spoofing.",
			spoofIP)
	}
	return rep, nil
}

func (p *Panel) testOutboundTunnel(parent context.Context, t tunnelTarget, customHost string) (agent.OutboundTestResult, error) {
	if t.Origin == "" {
		return agent.OutboundTestResult{}, errors.New("the Foreign hosting server is not in the panel for this Website Bridge")
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	var rep agent.OutboundTestResult
	_, err := p.callJSON(ctx, t.Origin, "/api/tunnel/test-outbound", map[string]string{
		"name":        t.Name,
		"custom_host": strings.TrimSpace(customHost),
	}, &rep)
	if err != nil {
		if errors.Is(err, errTooOld) {
			return agent.OutboundTestResult{}, fmt.Errorf("%s is running an older PortBridge release; update it first to test Website Outbound Proxy routing", p.serverName(t.Origin))
		}
		return agent.OutboundTestResult{}, err
	}
	if !rep.OK && rep.Error != "" {
		return agent.OutboundTestResult{}, errors.New(rep.Error)
	}
	return rep, nil
}
