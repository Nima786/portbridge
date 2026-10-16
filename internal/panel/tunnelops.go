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
	"time"

	"github.com/Nima786/portbridge/internal/agent"
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
	IPv6       bool   `json:"ipv6"`

	Shared      bool `json:"shared"`
	SharedLinks int  `json:"shared_links"`

	ServicePorts string `json:"service_ports"`
	UserPorts    string `json:"user_ports"`
	LinkPort     int    `json:"link_port"`

	ProxyProtocol string `json:"proxy_protocol"`
	RelayIP       string `json:"relay_ip"` // optional: the relay's address users connect to
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
	s := agent.EdgeSpec{Name: strings.TrimSpace(r.Name), Mode: r.Mode, Pool: 25,
		ServicePorts: r.ServicePorts, UserPorts: r.UserPorts, LinkPort: r.LinkPort, ProxyProtocol: r.ProxyProtocol}
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
	}
	if r.Shared {
		s.Mux, s.MuxLinks = "on", r.SharedLinks
		if s.MuxLinks == 0 {
			s.MuxLinks = 4
		}
	}
	if s.ProxyProtocol == "off" {
		s.ProxyProtocol = ""
	}

	rv4, rv6 := addressesOf(relay)
	fv4, fv6 := addressesOf(foreign)
	if r.IPv6 {
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
	for _, n := range intsOf(s.ServicePorts) {
		ps := st[n]
		switch {
		case strings.HasPrefix(ps.By, "PortBridge tunnel "):
			problems = append(problems, fmt.Sprintf("service port %d on the foreign server is used by %s, so it cannot also be your service",
				n, strings.TrimPrefix(ps.By, "PortBridge ")))
		case ps.State == "free":
			j.say("Note: nothing is listening on port %d on the foreign server yet. Make sure your service (Xray) is running there.", n)
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
	return p.startJob(func(j *job) (string, error) { return "", p.createTunnel(j, r.Relay, r.Foreign, spec) }), nil
}

// startJob runs work in the background as a job the page can follow.
func (p *Panel) startJob(work func(*job) (string, error)) string {
	id := newID(9)
	j := &job{started: time.Now()}
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
