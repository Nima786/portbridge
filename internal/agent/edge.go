package agent

// Making the Iran half of a tunnel without the menu, for the web panel.
//
// The menu's "Create a tunnel" asks its questions and then writes the settings
// with write_tunnel. EdgeSpec is the answers to those questions, and
// buildEdgeConf writes exactly what write_tunnel writes for the same answers,
// line for line (a test runs the menu's own function and compares). So a tunnel
// made from the panel is the same tunnel the menu would have made, and the menu
// can show, edit and delete it as one of its own.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

// EdgeSpec is the answers to the menu's "Create a tunnel" questions.
type EdgeSpec struct {
	Name string `json:"name"`
	Mode string `json:"mode"` // direct or reverse

	// What the link looks like: plain, tls, wss, grpc or kcp.
	Transport   string `json:"transport"`
	ServerName  string `json:"server_name,omitempty"`  // the name the link claims
	WSPath      string `json:"ws_path,omitempty"`      // web-socket path, made up when empty
	CDN         string `json:"cdn,omitempty"`          // on when the link goes through a CDN
	AltHost     string `json:"alt_host,omitempty"`     // domain of the CDN backup route
	CleanIPs    string `json:"clean_ips,omitempty"`    // clean CDN addresses to dial
	UTLS        string `json:"utls,omitempty"`         // a browser's hello
	TLSFragment string `json:"tls_fragment,omitempty"` // the hello split up
	HTTPHeader  string `json:"http_header,omitempty"`  // a plain link opening like web traffic
	HTTPHost    string `json:"http_host,omitempty"`
	RealSite    string `json:"real_site,omitempty"` // strangers are shown the real website
	CoverSite   string `json:"cover_site,omitempty"`
	GRE         string `json:"gre,omitempty"`

	ProxyProtocol string `json:"proxy_protocol,omitempty"` // off, v1 or v2
	Mux           string `json:"mux,omitempty"`
	MuxLinks      int    `json:"mux_links,omitempty"`
	Pool          int    `json:"pool,omitempty"`

	PeerIP       string `json:"peer_ip"`        // the foreign server, as the link reaches it
	LocalIP      string `json:"local_ip"`       // this server, as the link reaches it
	IPv6         bool   `json:"ipv6,omitempty"` // the link uses both servers' IPv6 addresses
	LinkPort     int    `json:"link_port"`
	UserPorts    string `json:"user_ports"`    // where users connect here: "443, 8443"
	ServicePorts string `json:"service_ports"` // the service on the foreign server: "443,8443"
}

// EdgeResult is what making the Iran half gives back.
type EdgeResult struct {
	OK       bool     `json:"ok"`
	Name     string   `json:"name"`
	Code     string   `json:"code"` // the pairing code for the foreign server
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func (s *EdgeSpec) normalise() {
	def := func(v *string, d string) {
		if strings.TrimSpace(*v) == "" {
			*v = d
		}
	}
	def(&s.Transport, "plain")
	def(&s.CDN, "off")
	def(&s.Mux, "off")
	def(&s.GRE, "off")
	if s.MuxLinks == 0 {
		s.MuxLinks = 4
	}
	if s.Pool == 0 {
		s.Pool = 25
	}
	s.UserPorts = joinPorts(s.UserPorts, ", ")
	s.ServicePorts = joinPorts(s.ServicePorts, ",")
	// As the menu does for a GRE link: nothing to disguise, so nothing left over.
	if s.GRE == "on" {
		s.Transport = "plain"
		s.ServerName, s.WSPath, s.CDN, s.AltHost, s.CleanIPs = "", "", "off", "", ""
		s.UTLS, s.TLSFragment, s.HTTPHeader, s.HTTPHost, s.RealSite, s.CoverSite = "", "", "", "", "", ""
	}
	if s.Transport == "kcp" {
		s.ServerName, s.WSPath, s.CDN = "", "", "off"
	}
	if s.Transport == "wss" && s.WSPath == "" {
		s.WSPath = "/" + randomAlnum(10)
	}
	// As the menu does: showing the real website goes with a browser's hello.
	if s.RealSite == "on" {
		s.UTLS = "on"
	}
}

// joinPorts tidies a list of ports the way the menu's prompts do.
func joinPorts(list, sep string) string {
	var out []string
	for _, p := range strings.Split(list, ",") {
		if p = strings.Join(strings.Fields(p), ""); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func randomAlnum(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// newTunnelSecret is what the menu's gen_secret makes: 32 random bytes, base64.
func newTunnelSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// dialsOut says whether the Iran half is the one that starts the connection.
func (s *EdgeSpec) dialsOut() bool { return s.Mode == "direct" }

func (s *EdgeSpec) cdnInvolved() bool { return s.CDN == "on" || s.AltHost != "" }

// check refuses what the menu would not have let through.
func (s *EdgeSpec) check() error {
	if err := validTunnelName(s.Name); err != nil {
		return err
	}
	if s.Mode != "direct" && s.Mode != "reverse" {
		return fmt.Errorf("mode %q is not direct or reverse", s.Mode)
	}
	switch s.Transport {
	case "plain", "tls", "wss", "grpc", "kcp":
	default:
		return fmt.Errorf("link type %q is not one of plain, tls, wss, grpc or kcp", s.Transport)
	}
	for _, f := range []struct{ name, val string }{
		{"cdn", s.CDN}, {"mux", s.Mux}, {"utls", s.UTLS}, {"tls_fragment", s.TLSFragment},
		{"http_header", s.HTTPHeader}, {"gre", s.GRE}, {"real_site", s.RealSite},
	} {
		if f.val != "" && f.val != "on" && f.val != "off" {
			return fmt.Errorf("%s must be on or off, got %q", f.name, f.val)
		}
	}
	if net.ParseIP(s.PeerIP) == nil {
		return fmt.Errorf("the foreign server's address %q is not an IP address", s.PeerIP)
	}
	if net.ParseIP(s.LocalIP) == nil {
		return fmt.Errorf("this server's address %q is not an IP address", s.LocalIP)
	}
	if s.LinkPort < 1 || s.LinkPort > 65535 {
		return errors.New("the port between the servers must be from 1 to 65535")
	}
	users, services := portsIn(s.UserPorts), portsIn(s.ServicePorts)
	if len(users) == 0 || len(users) != len(strings.Split(s.UserPorts, ",")) {
		return errors.New("give the port or ports your users connect to, as numbers from 1 to 65535")
	}
	if len(services) == 0 || len(services) != len(strings.Split(s.ServicePorts, ",")) {
		return errors.New("give the port or ports of the service on the foreign server, as numbers from 1 to 65535")
	}
	if len(users) != len(services) {
		return errors.New("each users' port leads to one service port, in order, so give the same number of each")
	}
	for _, u := range users {
		if s.Mode == "reverse" && u == s.LinkPort {
			return fmt.Errorf("the port between the servers cannot also be a users' port (%d)", u)
		}
	}
	if s.Mode == "direct" {
		for _, sv := range services {
			if sv == s.LinkPort {
				return fmt.Errorf("the port between the servers cannot also be a service port on the foreign server (%d)", sv)
			}
		}
	}
	if s.MuxLinks < 1 || s.MuxLinks > 16 {
		return errors.New("the number of shared connections must be from 1 to 16")
	}
	switch s.ProxyProtocol {
	case "", "off", "v1", "v2":
	default:
		return fmt.Errorf("real visitor address must be off, v1 or v2, got %q", s.ProxyProtocol)
	}
	for _, h := range []struct{ what, val string }{
		{"the name the link claims", s.ServerName}, {"the CDN backup domain", s.AltHost}, {"the web header's site", s.HTTPHost},
	} {
		if h.val != "" && !engine.HostnameRe.MatchString(h.val) {
			return fmt.Errorf("%s, %q, is not a host name", h.what, h.val)
		}
	}
	if s.CoverSite != "" && !validCoverSite(s.CoverSite) {
		return fmt.Errorf("cover site %q is not a host name, or a host name and port", s.CoverSite)
	}
	if s.WSPath != "" && !wsPathRe.MatchString(s.WSPath) {
		return fmt.Errorf("web-socket path %q is not a plain path", s.WSPath)
	}
	for _, ip := range strings.Split(s.CleanIPs, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			if err := engine.CheckCleanIP(ip); err != nil {
				return fmt.Errorf("clean addresses: %w", err)
			}
		}
	}
	if s.CDN == "on" && s.ServerName == "" {
		return errors.New("a link through a CDN needs your domain name")
	}
	if s.AltHost != "" && s.Mode != "direct" {
		return errors.New("the CDN backup route is only for direct tunnels")
	}
	if s.HTTPHeader == "on" && s.Transport != "plain" {
		return errors.New("the web header only applies to a plain link")
	}
	if s.RealSite == "on" && (s.cdnInvolved() || s.Transport == "plain" || s.Transport == "kcp") {
		return errors.New("showing strangers the real website works only with the website or HTTP/2 link, without a CDN")
	}
	if s.IPv6 {
		if s.GRE == "on" || s.cdnInvolved() || s.Transport == "wss" {
			return errors.New("IPv6 between the servers is not offered with GRE, a CDN or the web-socket link")
		}
		if ip := net.ParseIP(s.PeerIP); ip == nil || ip.To4() != nil {
			return errors.New("for IPv6 between the servers, the foreign server's address must be its IPv6 one")
		}
		if ip := net.ParseIP(s.LocalIP); ip == nil || ip.To4() != nil {
			return errors.New("for IPv6 between the servers, this server's address must be its IPv6 one")
		}
	}
	return nil
}

// edgeLayout is the addresses write_tunnel is given, worked out as create_tunnel
// works them out.
type edgeLayout struct {
	tunnelAddr string
	peerConf   string // peer_ip in the file: the GRE link's address over GRE
	greLocal   string
	greRemote  string
}

func (s *EdgeSpec) layout() (edgeLayout, error) {
	var l edgeLayout
	switch {
	case s.Mode == "direct":
		l.tunnelAddr = hostPort(s.PeerIP, s.LinkPort)
	case s.IPv6:
		l.tunnelAddr = "[::]:" + strconv.Itoa(s.LinkPort)
	default:
		l.tunnelAddr = "0.0.0.0:" + strconv.Itoa(s.LinkPort)
	}
	l.peerConf = s.PeerIP
	if s.GRE == "on" {
		own, peer, err := engine.GREAddrs(s.LocalIP, s.PeerIP)
		if err != nil {
			return l, fmt.Errorf("a GRE link needs plain IPv4 addresses for both servers: %w", err)
		}
		l.greLocal, l.greRemote = s.LocalIP, s.PeerIP
		l.peerConf = peer
		if s.Mode == "direct" {
			l.tunnelAddr = net.JoinHostPort(peer, strconv.Itoa(s.LinkPort))
		} else {
			l.tunnelAddr = net.JoinHostPort(own, strconv.Itoa(s.LinkPort))
		}
	}
	return l, nil
}

// buildEdgeConf is the menu's write_tunnel for the Iran half, word for word. Only
// the first line, which says who wrote the file and when, differs.
func buildEdgeConf(s *EdgeSpec, l edgeLayout, confDir string, now time.Time) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	conf := func(ext string) string { return filepath.ToSlash(filepath.Join(confDir, s.Name+ext)) }

	w("# PortBridge tunnel %q, written by the web panel on %s\n", s.Name, now.UTC().Format("2006-01-02 15:04:05 UTC"))
	w("# Edit with: portbridge-menu  ->  Edit a tunnel\n\n")
	w("name = %s\n", s.Name)
	w("mode = %s\n", s.Mode)
	w("# edge = the Iran server, where users connect\n")
	w("role = edge\n\n")
	if s.dialsOut() {
		w("# This machine starts the connection, so this is the address it calls.\n")
	} else {
		w("# This machine waits for the other one to call, on this port.\n")
	}
	w("tunnel_addr = %s\n", l.tunnelAddr)
	if s.UserPorts != "" {
		w("\n# Where your users connect.\nuser_listen = %s\n", s.UserPorts)
	}
	if s.ServicePorts != "" {
		w("\n# The inbound port on the foreign server, kept for the code.\nserver_inbound_port = %s\n", s.ServicePorts)
	}
	w("\n# The other machine.\n")
	w("peer_ip = %s\n", l.peerConf)
	switch {
	case s.GRE == "on":
		w("# off because the port can only be reached through the private GRE link.\n")
		w("firewall = off\n")
	case s.cdnInvolved():
		w("# off because the link can arrive from a CDN, whose address is not\n")
		w("# the other server, so the port cannot be locked to one address.\n")
		w("firewall = off\n")
	default:
		w("# on = only the other machine may use the tunnel port. Change from the menu.\n")
		w("firewall = on\n")
	}
	if s.LocalIP != "" {
		w("local_ip = %s\n", s.LocalIP)
	}
	if s.GRE == "on" {
		w("\n# Runs over a private GRE link between the two servers: peer_ip and\n")
		w("# tunnel_addr are addresses on that link, and these are the real ones.\n")
		w("gre = on\n")
		w("gre_local = %s\n", l.greLocal)
		w("gre_remote = %s\n", l.greRemote)
	}
	w("\n# What the link looks like to anyone watching it. See the menu.\n")
	w("transport = %s\n", s.Transport)
	if s.Transport == "plain" && s.HTTPHeader == "on" {
		host := s.HTTPHost
		if host == "" {
			host = "www.bing.com"
		}
		w("# Opens with a fake web request and reply; both servers must have it.\n")
		w("http_header = on\n")
		w("http_host = %s\n", host)
	}
	if s.Transport != "plain" && s.Transport != "kcp" {
		if s.ServerName != "" {
			w("server_name = %s\n", s.ServerName)
		}
		if s.WSPath != "" {
			w("ws_path = %s\n", s.WSPath)
		}
		w("cdn = %s\n", s.CDN)
		w("cert_file = %s\n", conf(".crt"))
		w("key_file = %s\n", conf(".key"))
	}
	if s.AltHost != "" && s.dialsOut() {
		w("\n# If the address above cannot be reached, try this instead.\n")
		w("alt_target = %s:%d\n", s.AltHost, s.LinkPort)
		w("# The CDN routes by name, so this route has to name the domain,\n")
		w("# while the direct route above deliberately does not.\n")
		w("alt_server_name = %s\n", s.AltHost)
	}
	if s.CleanIPs != "" && s.dialsOut() {
		w("\n# Clean Cloudflare Anycast IPs for bypassing throttling/blocking\n")
		w("clean_ips = %s\n", s.CleanIPs)
	}
	if s.UTLS == "on" {
		w("utls = on\n")
	}
	if s.TLSFragment == "on" {
		w("tls_fragment = on\n")
	}
	if s.RealSite == "on" {
		w("real_site = on\n")
		if s.CoverSite != "" {
			w("cover_site = %s\n", s.CoverSite)
		}
	}
	if s.ProxyProtocol == "v1" || s.ProxyProtocol == "v2" {
		w("\n# Pass each user's real address on; the service must be set to expect it.\n")
		w("proxy_protocol = %s\n", s.ProxyProtocol)
	}
	w("\n# on = every user session shares a few long-lived connections.\n")
	w("mux = %s\n", s.Mux)
	if s.Mux == "on" {
		w("mux_links = %d\n", s.MuxLinks)
	}
	w("\npool_size = %d\n", s.Pool)
	w("max_conn = 2000\n")
	w("max_pending = 512\n")
	w("spare_ttl = 10m\n")
	w("park_timeout = 15m\n")
	w("drain = 5s\n")
	w("\nsecret_file = %s\n", conf(".secret"))
	return b.String()
}

// readConfKeys reads a settings file the way the menu's read_conf does: the last
// line for each key wins, with spaces and quotes around the value removed.
func readConfKeys(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kv := map[string]string{}
	for _, l := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		if i := strings.Index(v, "#"); i >= 0 {
			v = v[:i]
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return kv, nil
}

// EncodePairingCode is the menu's make_pairing_code: the same lines in the same
// order, the optional ones only when they are used, and the version the highest
// any of them needs.
func EncodePairingCode(p *PairingData) string {
	v := 6
	var extra strings.Builder
	if p.HTTPHeader == "on" {
		host := p.HTTPHost
		if host == "" {
			host = "www.bing.com"
		}
		fmt.Fprintf(&extra, "http_header=on\nhttp_host=%s\n", host)
		v = max(v, 7)
	}
	if p.GRE == "on" {
		extra.WriteString("gre=on\n")
		v = max(v, 8)
	}
	if p.RealSite == "on" {
		extra.WriteString("real_site=on\n")
		if p.CoverSite != "" {
			fmt.Fprintf(&extra, "cover_site=%s\n", p.CoverSite)
		}
		v = max(v, 9)
	}
	if p.ProxyProtocol == "v1" || p.ProxyProtocol == "v2" {
		fmt.Fprintf(&extra, "proxy_protocol=%s\n", p.ProxyProtocol)
		v = max(v, 10)
	}
	mux, links := p.Mux, p.MuxLinks
	if mux == "" {
		mux = "off"
	}
	if links == "" {
		links = "4"
	}
	raw := fmt.Sprintf("v=%d\nname=%s\nmode=%s\ntunnel_port=%s\nrelay_ip=%s\nserver_ip=%s\ninbound_port=%s\npool=%s\n"+
		"transport=%s\nserver_name=%s\nws_path=%s\ncdn=%s\nalt_host=%s\nmux=%s\nmux_links=%s\nutls=%s\n"+
		"tls_fragment=%s\nclean_ips=%s\n%ssecret=%s\n",
		v, p.Name, p.Mode, p.TunnelPort, p.RelayIP, p.ServerIP, p.InboundPort, p.Pool,
		p.Transport, p.ServerName, p.WSPath, p.CDN, p.AltHost, mux, links, p.UTLS,
		p.TLSFragment, p.CleanIPs, extra.String(), p.Secret)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// edgePairingCode is the menu's get_tunnel_pairing_code: the code for the foreign
// half, read back from the Iran half's own settings.
func edgePairingCode(confDir, name string) (string, error) {
	if err := validTunnelName(name); err != nil {
		return "", err
	}
	kv, err := readConfKeys(filepath.Join(confDir, name+".conf"))
	if err != nil {
		return "", fmt.Errorf("there is no tunnel %q on this server", name)
	}
	if kv["role"] != "edge" {
		return "", errors.New("codes are made on the Iran server, where the tunnel's users connect")
	}
	secret, err := os.ReadFile(filepath.Join(confDir, name+".secret"))
	if err != nil {
		return "", fmt.Errorf("reading the tunnel's password: %w", err)
	}
	tport := kv["tunnel_addr"]
	if i := strings.LastIndex(tport, ":"); i >= 0 {
		tport = tport[i+1:]
	}
	relayIP := kv["local_ip"]
	if relayIP == "" {
		if v4, _ := localPublicAddresses(); len(v4) > 0 {
			relayIP = v4[0]
		}
	}
	serverIP := kv["peer_ip"]
	if kv["gre"] == "on" {
		serverIP = kv["gre_remote"]
	}
	or := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	alt := kv["alt_target"]
	if i := strings.LastIndex(alt, ":"); i >= 0 {
		alt = alt[:i]
	}
	return EncodePairingCode(&PairingData{
		Name: name, Mode: kv["mode"], TunnelPort: tport, RelayIP: relayIP, ServerIP: serverIP,
		InboundPort: kv["server_inbound_port"], Pool: kv["pool_size"],
		Transport: or(kv["transport"], "plain"), ServerName: kv["server_name"], WSPath: kv["ws_path"],
		CDN: or(kv["cdn"], "off"), AltHost: alt, Mux: or(kv["mux"], "off"), MuxLinks: or(kv["mux_links"], "4"),
		UTLS: kv["utls"], TLSFragment: kv["tls_fragment"], CleanIPs: strings.ReplaceAll(kv["clean_ips"], " ", ""),
		HTTPHeader: kv["http_header"], HTTPHost: kv["http_host"], GRE: kv["gre"],
		RealSite: kv["real_site"], CoverSite: kv["cover_site"], ProxyProtocol: kv["proxy_protocol"],
		Secret: strings.TrimSpace(string(secret)),
	}), nil
}

// coverSiteCandidates are tried, in order, when strangers are to be shown the real
// website and this server is the one they reach: the same list the menu tries.
var coverSiteCandidates = []string{"www.bing.com", "www.varzesh3.com", "www.wikipedia.org"}

// reachable says whether this server can open https://host. Replaced in tests.
var reachable = func(host string) bool {
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Head("https://" + host)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// checkEdgePorts is what the menu checks as the ports are typed, all at once.
func checkEdgePorts(s *EdgeSpec, confDir string, host agentHost) error {
	var problems []string
	claimed := portsClaimedByOthers(confDir, s.Name)
	owner := func(p int) string {
		for _, c := range claimed {
			if c.port == p {
				return fmt.Sprintf("tunnel %q (%s)", c.tunnel, c.what)
			}
		}
		return ""
	}
	for _, u := range portsIn(s.UserPorts) {
		if o := owner(u); o != "" {
			problems = append(problems, fmt.Sprintf("users' port %d is already used on this server by %s", u, o))
		} else if err := host.PortFree(engine.TransportPlain, u); err != nil {
			problems = append(problems, fmt.Sprintf("users' port %d is already in use on this server by another program", u))
		}
	}
	if !s.dialsOut() {
		t := engine.TransportPlain
		if s.Transport == "kcp" {
			t = engine.TransportKCP
		}
		if o := owner(s.LinkPort); o != "" {
			problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already used on this server by %s", s.LinkPort, o))
		} else if err := host.PortFree(t, s.LinkPort); err != nil {
			problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already in use on this server", s.LinkPort))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("this server cannot use those ports:\n  - %s\nChange them and try again", strings.Join(problems, "\n  - "))
	}
	return nil
}

// CreateEdge makes and starts the Iran half of a tunnel, all or nothing, and gives
// back the code for the foreign half.
func CreateEdge(spec EdgeSpec, confDir string) (EdgeResult, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	res := EdgeResult{Name: spec.Name}
	s := &spec
	s.normalise()
	if err := s.check(); err != nil {
		return res, err
	}

	agentOpMu.Lock()
	defer agentOpMu.Unlock()
	host := hostFor(confDir)

	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return res, fmt.Errorf("creating the tunnels folder: %w", err)
	}
	_ = os.Chmod(confDir, 0o700)
	confFile := filepath.Join(confDir, s.Name+".conf")
	secretFile := filepath.Join(confDir, s.Name+".secret")
	for _, f := range []string{confFile, secretFile} {
		if _, err := os.Stat(f); err == nil {
			return res, fmt.Errorf("a tunnel named %q already exists on this server; choose another name", s.Name)
		}
	}
	if err := checkEdgePorts(s, confDir, host); err != nil {
		return res, err
	}

	l, err := s.layout()
	if err != nil {
		return res, err
	}
	if s.GRE == "on" {
		if err := greCheck(host); err != nil {
			return res, err
		}
		if !hasLocalAddress(s.LocalIP) {
			return res, fmt.Errorf("%s is not an address this server has on any of its network cards; "+
				"it sits behind address translation, and a GRE link cannot be made from it", s.LocalIP)
		}
	}

	// Strangers reaching this server are passed to the real website, so this
	// server has to be able to reach it.
	if s.RealSite == "on" && !s.dialsOut() {
		found := ""
		for _, c := range append([]string{s.ServerName}, coverSiteCandidates...) {
			if c != "" && reachable(c) {
				found = c
				break
			}
		}
		switch {
		case found == "":
			res.Warnings = append(res.Warnings, fmt.Sprintf("this server could not reach https://%s, which strangers are "+
				"passed to; if it stays unreachable they get no answer", s.ServerName))
		case found != s.ServerName:
			res.Warnings = append(res.Warnings, fmt.Sprintf("this server cannot reach %s, so the link claims %s instead, "+
				"which it can reach", s.ServerName, found))
			s.ServerName = found
		}
	}

	secret, err := newTunnelSecret()
	if err != nil {
		return res, err
	}
	certFile := filepath.Join(confDir, s.Name+".crt")
	keyFile := filepath.Join(confDir, s.Name+".key")
	undo := func() {
		for _, f := range []string{confFile, secretFile, certFile, keyFile} {
			_ = os.Remove(f)
		}
	}
	if err := writeFileAtomic(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		undo()
		return res, fmt.Errorf("writing the tunnel's password: %w", err)
	}
	if err := writeFileAtomic(confFile, []byte(buildEdgeConf(s, l, confDir, time.Now())), 0o600); err != nil {
		undo()
		return res, fmt.Errorf("writing the tunnel's settings: %w", err)
	}

	// The same check the menu makes ("portbridge check") before starting.
	cfg, err := engine.LoadConfig(confFile)
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		err = cfg.LoadSecret()
	}
	if err != nil {
		undo()
		return res, fmt.Errorf("those settings were refused, so nothing was started: %w", err)
	}

	if err := host.FirewallApply(s.Name); err != nil {
		if s.GRE == "on" {
			_ = host.FirewallRemove(s.Name)
			undo()
			_ = host.FirewallSweep()
			return res, fmt.Errorf("this server could not make the private GRE link: %w", err)
		}
		res.Warnings = append(res.Warnings, err.Error())
	}
	_ = host.Reload()
	if err := host.Enable(s.Name); err != nil && !errors.Is(err, errNoSystemd) {
		_ = host.Disable(s.Name)
		_ = host.FirewallRemove(s.Name)
		undo()
		_ = host.FirewallSweep()
		_ = host.Reload()
		return res, err
	}
	if err := confirmRunning(host, s.Name); err != nil {
		_ = host.Disable(s.Name)
		_ = host.FirewallRemove(s.Name)
		undo()
		_ = host.FirewallSweep()
		_ = host.Reload()
		return res, err
	}

	code, err := edgePairingCode(confDir, s.Name)
	if err != nil {
		return res, err
	}
	res.OK = true
	res.Code = code
	return res, nil
}

// greCheck asks the firewall helper whether this server can make GRE links.
func greCheck(host agentHost) error {
	if _, ok := host.(systemHost); !ok {
		return nil
	}
	if _, err := os.Stat(firewallHelper); err != nil {
		return nil
	}
	if out, err := hostRun(firewallHelper, "gre-check"); err != nil {
		return fmt.Errorf("a GRE link is not possible on this server: %s", out)
	}
	return nil
}

// hasLocalAddress says whether an address is on one of this server's network cards.
var hasLocalAddress = func(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	want := net.ParseIP(ip)
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(want) {
			return true
		}
	}
	return false
}

// tunnelService starts, stops or restarts a tunnel's service, as the menu's
// "Start, stop or restart a tunnel" does.
func tunnelService(confDir, name, action string) error {
	if err := validTunnelName(name); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(confDir, name+".conf")); err != nil {
		return fmt.Errorf("there is no tunnel %q on this server", name)
	}
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("%q is not start, stop or restart", action)
	}
	if _, ok := hostFor(confDir).(systemHost); !ok {
		return nil
	}
	if err := needRoot(); err != nil {
		return err
	}
	if out, err := hostRun("systemctl", action, "portbridge@"+name); err != nil {
		return fmt.Errorf("%s: %s", action, out)
	}
	return nil
}
