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
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	SIT         string `json:"sit,omitempty"`
	SNISpoof    string `json:"sni_spoof,omitempty"` // decoy ClientHello with whitelisted SNI
	SpoofSNI    string `json:"spoof_sni,omitempty"`
	IPSpoof     string `json:"ip_spoof,omitempty"` // source IP spoofing over raw sockets
	SpoofIP     string `json:"spoof_ip,omitempty"`
	AntiFreeze  string `json:"anti_freeze,omitempty"` // multi-connection split-stream leg rotation

	ProxyProtocol string `json:"proxy_protocol,omitempty"` // off, v1 or v2
	Mux           string `json:"mux,omitempty"`
	MuxLinks      int    `json:"mux_links,omitempty"`
	Pool          int    `json:"pool,omitempty"`
	MaxConn       int    `json:"max_conn,omitempty"`

	PeerIP       string `json:"peer_ip"`        // the foreign server, as the link reaches it
	LocalIP      string `json:"local_ip"`       // this server, as the link reaches it
	IPv6         bool   `json:"ipv6,omitempty"` // the link uses both servers' IPv6 addresses
	LinkPort     int    `json:"link_port"`
	UserPorts    string `json:"user_ports"`    // where users connect here: "443, 8443"
	ServicePorts string `json:"service_ports"` // the service on the foreign server: "443,8443"

	WebsiteBridge         string `json:"website_bridge,omitempty"`
	WebsiteDomains        string `json:"website_domains,omitempty"`
	OutboundProxy         string `json:"outbound_proxy,omitempty"`
	OutboundProxyPort     int    `json:"outbound_proxy_port,omitempty"`
	OutboundProxyMode     string `json:"outbound_proxy_mode,omitempty"`
	OutboundIranDomains   string `json:"outbound_iran_domains,omitempty"`
	OutboundBypassDomains string `json:"outbound_bypass_domains,omitempty"`
}

// EdgeResult is what making or editing the Iran half gives back.
type EdgeResult struct {
	OK       bool     `json:"ok"`
	Name     string   `json:"name"`
	Code     string   `json:"code"`               // the pairing code for the foreign server
	OldConf  string   `json:"old_conf,omitempty"` // previous config text when staging an edit
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func cleanDomainCSV(raw string) string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(strings.ReplaceAll(f, "=", ""))
		if f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, ", ")
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
	def(&s.SIT, "off")
	if s.MuxLinks == 0 {
		s.MuxLinks = 4
	}
	if s.Pool == 0 {
		s.Pool = 25
	}
	s.UserPorts = joinPorts(s.UserPorts, ", ")
	s.ServicePorts = joinPorts(s.ServicePorts, ",")
	s.WebsiteDomains = cleanDomainCSV(s.WebsiteDomains)
	s.OutboundIranDomains = cleanDomainCSV(s.OutboundIranDomains)
	s.OutboundBypassDomains = cleanDomainCSV(s.OutboundBypassDomains)
	if s.WebsiteBridge == "on" {
		if s.OutboundProxy == "" {
			s.OutboundProxy = "on"
		}
		if s.Mux == "" || s.Mux == "off" {
			// Website Bridges with OutboundProxy in Direct mode require Shared Mux.
			if s.OutboundProxy == "on" && s.Mode != "reverse" {
				s.Mux = "on"
			}
		}
	}
	if s.OutboundProxy == "on" {
		if s.OutboundProxyPort <= 0 {
			s.OutboundProxyPort = 18080
		}
		if s.OutboundProxyMode == "" {
			s.OutboundProxyMode = "split"
		}
	}
	// As the menu does for a GRE link: nothing to disguise, so nothing left over.
	if s.GRE == "on" {
		s.Transport = "plain"
		s.SIT = "off"
		s.ServerName, s.WSPath, s.CDN, s.AltHost, s.CleanIPs = "", "", "off", "", ""
		s.UTLS, s.TLSFragment, s.HTTPHeader, s.HTTPHost, s.RealSite, s.CoverSite = "", "", "", "", "", ""
		s.SNISpoof, s.SpoofSNI, s.IPSpoof, s.SpoofIP, s.AntiFreeze = "", "", "", "", ""
	}
	if s.SIT == "on" {
		s.Transport = "plain"
		s.GRE = "off"
		s.ServerName, s.WSPath, s.CDN, s.AltHost, s.CleanIPs = "", "", "off", "", ""
		s.UTLS, s.TLSFragment, s.HTTPHeader, s.HTTPHost, s.RealSite, s.CoverSite = "", "", "", "", "", ""
		s.SNISpoof, s.SpoofSNI, s.IPSpoof, s.SpoofIP, s.AntiFreeze = "", "", "", "", ""
	}
	if s.AntiFreeze == "on" {
		if s.Transport == "" || s.Transport == "plain" || engine.IsKCPFamily(engine.Transport(s.Transport)) {
			s.Transport = "tls"
		}
		if strings.TrimSpace(s.UTLS) == "" {
			s.UTLS = "on"
		}
		if strings.TrimSpace(s.TLSFragment) == "" {
			s.TLSFragment = "on"
		}
	}
	if s.IPSpoof == "on" {
		s.Transport = "kcp"
		if strings.TrimSpace(s.SpoofIP) == "" {
			s.SpoofIP = engine.DefaultSpoofIP
		}
		if strings.TrimSpace(s.SpoofSNI) == "" {
			s.SpoofSNI = engine.DefaultSpoofSNI
		}
	}
	if s.SNISpoof == "on" && strings.TrimSpace(s.SpoofSNI) == "" {
		s.SpoofSNI = engine.DefaultSpoofSNI
	}
	if engine.IsKCPFamily(engine.Transport(s.Transport)) {
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
	case "plain", "tls", "wss", "grpc", "kcp", "icmp", "faketcp":
	default:
		return fmt.Errorf("link type %q is not one of plain, tls, wss, grpc, kcp, icmp or faketcp", s.Transport)
	}
	for _, f := range []struct{ name, val string }{
		{"cdn", s.CDN}, {"mux", s.Mux}, {"utls", s.UTLS}, {"tls_fragment", s.TLSFragment},
		{"http_header", s.HTTPHeader}, {"gre", s.GRE}, {"sit", s.SIT}, {"real_site", s.RealSite},
		{"sni_spoof", s.SNISpoof}, {"ip_spoof", s.IPSpoof}, {"anti_freeze", s.AntiFreeze},
		{"website_bridge", s.WebsiteBridge}, {"outbound_proxy", s.OutboundProxy},
	} {
		if f.val != "" && f.val != "on" && f.val != "off" {
			return fmt.Errorf("%s must be on or off, got %q", f.name, f.val)
		}
	}
	if s.OutboundProxy == "on" {
		if s.OutboundProxyPort < 1 || s.OutboundProxyPort > 65535 {
			return errors.New("outbound proxy port must be from 1 to 65535")
		}
		if s.OutboundProxyMode != "" && s.OutboundProxyMode != "split" && s.OutboundProxyMode != "all" {
			return fmt.Errorf("outbound proxy mode must be split or all, got %q", s.OutboundProxyMode)
		}
		if s.Mux != "on" && s.Mode != "reverse" {
			return errors.New("website outbound proxy requires shared connections (mux = on) or reverse mode")
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
	if s.Pool < 1 || s.Pool > 10000 {
		return errors.New("connection pool size must be from 1 to 10000")
	}
	if s.MaxConn != 0 && (s.MaxConn < 1 || s.MaxConn > 100000) {
		return errors.New("max_conn must be from 1 to 100000")
	}
	switch s.ProxyProtocol {
	case "", "off", "v1", "v2":
	default:
		return fmt.Errorf("real visitor address must be off, v1 or v2, got %q", s.ProxyProtocol)
	}
	for _, h := range []struct{ what, val string }{
		{"the name the link claims", s.ServerName}, {"the CDN backup domain", s.AltHost}, {"the web header's site", s.HTTPHost},
		{"the spoofed whitelisted SNI", s.SpoofSNI},
	} {
		if h.val != "" && !engine.HostnameRe.MatchString(h.val) {
			return fmt.Errorf("%s, %q, is not a host name", h.what, h.val)
		}
	}
	if s.SpoofIP != "" {
		ip := net.ParseIP(s.SpoofIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("spoofed IP %q must be a valid IPv4 address", s.SpoofIP)
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
	if s.RealSite == "on" && (s.cdnInvolved() || s.Transport == "plain" || engine.IsKCPFamily(engine.Transport(s.Transport))) {
		return errors.New("showing strangers the real website works only with the website or HTTP/2 link, without a CDN")
	}
	if s.IPv6 {
		if s.GRE == "on" || s.SIT == "on" || s.cdnInvolved() || s.Transport == "wss" || s.IPSpoof == "on" || s.Transport == "icmp" || s.Transport == "faketcp" {
			return errors.New("IPv6 between the servers is not offered with GRE, 6in4 (SIT), source IP spoofing, ICMP, FakeTCP, a CDN or the web-socket link")
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
	peerConf   string // peer_ip in the file: the GRE/SIT link's address over GRE/SIT
	greLocal   string
	greRemote  string
	sitLocal   string
	sitRemote  string
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
	if s.SIT == "on" {
		own, peer, err := engine.SITAddrs(s.LocalIP, s.PeerIP)
		if err != nil {
			return l, fmt.Errorf("a 6in4 (SIT) link needs plain IPv4 addresses for both servers: %w", err)
		}
		l.sitLocal, l.sitRemote = s.LocalIP, s.PeerIP
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
	case s.SIT == "on":
		w("# off because the port can only be reached through the private 6in4 (SIT) link.\n")
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
	if s.SIT == "on" {
		w("\n# Runs over a private 6in4 (SIT) IPv6-over-IPv4 link between the two servers.\n")
		w("sit = on\n")
		w("sit_local = %s\n", l.sitLocal)
		w("sit_remote = %s\n", l.sitRemote)
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
	if s.Transport != "plain" && !engine.IsKCPFamily(engine.Transport(s.Transport)) {
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
	if s.SNISpoof == "on" {
		w("sni_spoof = on\n")
		if s.SpoofSNI != "" {
			w("spoof_sni = %s\n", s.SpoofSNI)
		}
	}
	if s.IPSpoof == "on" {
		w("ip_spoof = on\n")
		if s.SpoofIP != "" {
			w("spoof_ip = %s\n", s.SpoofIP)
		}
		if s.SpoofSNI != "" && s.SNISpoof != "on" {
			w("spoof_sni = %s\n", s.SpoofSNI)
		}
	}
	if s.AntiFreeze == "on" {
		w("anti_freeze = on\n")
	}
	if s.ProxyProtocol == "v1" || s.ProxyProtocol == "v2" {
		w("\n# Pass each user's real address on; the service must be set to expect it.\n")
		w("proxy_protocol = %s\n", s.ProxyProtocol)
	}
	if s.WebsiteBridge == "on" {
		w("\n# Dedicated Website Bridge settings\n")
		w("website_bridge = on\n")
		if s.WebsiteDomains != "" {
			w("website_domains = %s\n", s.WebsiteDomains)
		}
	}
	if s.OutboundProxy == "on" {
		w("outbound_proxy = on\n")
		if s.OutboundProxyPort > 0 {
			w("outbound_proxy_port = %d\n", s.OutboundProxyPort)
		}
		if s.OutboundProxyMode != "" {
			w("outbound_proxy_mode = %s\n", s.OutboundProxyMode)
		}
		if s.OutboundIranDomains != "" {
			w("outbound_iran_domains = %s\n", s.OutboundIranDomains)
		}
		if s.OutboundBypassDomains != "" {
			w("outbound_bypass_domains = %s\n", s.OutboundBypassDomains)
		}
	}
	w("\n# on = every user session shares a few long-lived connections.\n")
	w("mux = %s\n", s.Mux)
	if s.Mux == "on" {
		w("mux_links = %d\n", s.MuxLinks)
	}
	maxConn := s.MaxConn
	if maxConn <= 0 {
		maxConn = 2000
	}
	w("\npool_size = %d\n", s.Pool)
	w("max_conn = %d\n", maxConn)
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
	if p.SIT == "on" {
		extra.WriteString("sit=on\n")
		v = max(v, 10)
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
	if p.SNISpoof == "on" {
		extra.WriteString("sni_spoof=on\n")
		if p.SpoofSNI != "" {
			fmt.Fprintf(&extra, "spoof_sni=%s\n", p.SpoofSNI)
		}
		v = max(v, 10)
	}
	if p.IPSpoof == "on" {
		extra.WriteString("ip_spoof=on\n")
		if p.SpoofIP != "" {
			fmt.Fprintf(&extra, "spoof_ip=%s\n", p.SpoofIP)
		}
		if p.SpoofSNI != "" && p.SNISpoof != "on" {
			fmt.Fprintf(&extra, "spoof_sni=%s\n", p.SpoofSNI)
		}
		v = max(v, 10)
	}
	if p.AntiFreeze == "on" {
		extra.WriteString("anti_freeze=on\n")
		v = max(v, 10)
	}
	if mc := strings.TrimSpace(p.MaxConn); mc != "" && mc != "2000" {
		fmt.Fprintf(&extra, "max_conn=%s\n", mc)
		v = max(v, 10)
	}
	if p.WebsiteBridge == "on" {
		extra.WriteString("website_bridge=on\n")
		if wd := cleanDomainCSV(p.WebsiteDomains); wd != "" {
			fmt.Fprintf(&extra, "website_domains=%s\n", wd)
		}
		v = max(v, 10)
	}
	if p.OutboundProxy == "on" {
		extra.WriteString("outbound_proxy=on\n")
		if pp := strings.TrimSpace(p.OutboundProxyPort); pp != "" {
			fmt.Fprintf(&extra, "outbound_proxy_port=%s\n", pp)
		}
		if pm := strings.TrimSpace(p.OutboundProxyMode); pm != "" {
			fmt.Fprintf(&extra, "outbound_proxy_mode=%s\n", pm)
		}
		if id := cleanDomainCSV(p.OutboundIranDomains); id != "" {
			fmt.Fprintf(&extra, "outbound_iran_domains=%s\n", id)
		}
		if bd := cleanDomainCSV(p.OutboundBypassDomains); bd != "" {
			fmt.Fprintf(&extra, "outbound_bypass_domains=%s\n", bd)
		}
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
	if kv["sit"] == "on" {
		serverIP = kv["sit_remote"]
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
		HTTPHeader: kv["http_header"], HTTPHost: kv["http_host"], GRE: kv["gre"], SIT: kv["sit"],
		RealSite: kv["real_site"], CoverSite: kv["cover_site"], ProxyProtocol: kv["proxy_protocol"],
		SNISpoof: kv["sni_spoof"], SpoofSNI: kv["spoof_sni"], IPSpoof: kv["ip_spoof"], SpoofIP: kv["spoof_ip"],
		AntiFreeze: kv["anti_freeze"], MaxConn: kv["max_conn"],
		WebsiteBridge: kv["website_bridge"], WebsiteDomains: kv["website_domains"],
		OutboundProxy: kv["outbound_proxy"], OutboundProxyPort: kv["outbound_proxy_port"],
		OutboundProxyMode: kv["outbound_proxy_mode"], OutboundIranDomains: kv["outbound_iran_domains"],
		OutboundBypassDomains: kv["outbound_bypass_domains"],
		Secret:                strings.TrimSpace(string(secret)),
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
		t := engine.Transport(s.Transport)
		if !engine.IsKCPFamily(t) {
			t = engine.TransportPlain
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
	if s.SIT == "on" {
		if err := sitCheck(host); err != nil {
			return res, err
		}
		if !hasLocalAddress(s.LocalIP) {
			return res, fmt.Errorf("%s is not an address this server has on any of its network cards; "+
				"it sits behind address translation, and a 6in4 (SIT) link cannot be made from it", s.LocalIP)
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
		if s.GRE == "on" || s.SIT == "on" {
			_ = host.FirewallRemove(s.Name)
			undo()
			_ = host.FirewallSweep()
			if s.SIT == "on" {
				return res, fmt.Errorf("this server could not make the private 6in4 (SIT) link: %w", err)
			}
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

// sitCheck asks the firewall helper whether this server can make 6in4 (SIT) links.
func sitCheck(host agentHost) error {
	if _, ok := host.(systemHost); !ok {
		return nil
	}
	if _, err := os.Stat(firewallHelper); err != nil {
		return nil
	}
	if out, err := hostRun(firewallHelper, "sit-check"); err != nil {
		return fmt.Errorf("a 6in4 (SIT) link is not possible on this server: %s", out)
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

// ---------------------------------------------------------------------------
// Editing a tunnel, viewing logs, diagnostics, speed test, and BBR tuning
// ---------------------------------------------------------------------------

// EditSpec describes changes to an existing tunnel, matching the CLI menu's
// "Edit a tunnel" options (ports, real user IP, pool/mux links, max_conn, firewall)
// as well as full mode/transport hot-swaps for Auto-Heal and Smart Failover.
type EditSpec struct {
	Name          string `json:"name"`
	UserPorts     string `json:"user_ports,omitempty"`
	ServicePorts  string `json:"service_ports,omitempty"`
	LinkPort      int    `json:"link_port,omitempty"`
	ProxyProtocol string `json:"proxy_protocol,omitempty"` // "off", "v1" or "v2"
	Pool          int    `json:"pool,omitempty"`
	MuxLinks      int    `json:"mux_links,omitempty"`
	MaxConn       int    `json:"max_conn,omitempty"`
	SpareTTL      string `json:"spare_ttl,omitempty"`
	Drain         string `json:"drain,omitempty"`
	PeerIP        string `json:"peer_ip,omitempty"`
	LocalIP       string `json:"local_ip,omitempty"`
	Firewall      string `json:"firewall,omitempty"` // "on" or "off"
	Stage         string `json:"stage,omitempty"`    // "", "prepare", "commit", "rollback"
	OldConf       string `json:"old_conf,omitempty"`

	// Optional transport / mode replacement fields:
	Mode       string `json:"mode,omitempty"`        // "direct" or "reverse"
	Transport  string `json:"transport,omitempty"`   // "plain", "tls", "wss", "grpc", "kcp", "icmp", "faketcp"
	ServerName string `json:"server_name,omitempty"` // SNI / domain
	CDN        string `json:"cdn,omitempty"`         // "on" or "off"
	AltHost    string `json:"alt_host,omitempty"`    // CDN backup domain
	CleanIPs   string `json:"clean_ips,omitempty"`   // Clean Cloudflare IPs
	// KeepCleanIPs carries the tunnel's existing clean addresses over to a CDN
	// link when CleanIPs is empty. A mode switch by Auto-Heal sets it, so a
	// switch does not throw the list away; the Edit form leaves it off, so
	// clearing the list there still works.
	KeepCleanIPs bool   `json:"keep_clean_ips,omitempty"`
	UTLS         string `json:"utls,omitempty"`         // "on" or "off"
	TLSFragment  string `json:"tls_fragment,omitempty"` // "on" or "off"
	HTTPHeader   string `json:"http_header,omitempty"`  // "on" or "off"
	HTTPHost     string `json:"http_host,omitempty"`    // HTTP host header
	RealSite     string `json:"real_site,omitempty"`    // "on" or "off"
	GRE          string `json:"gre,omitempty"`          // "on" or "off"
	SIT          string `json:"sit,omitempty"`          // "on" or "off"
	SNISpoof     string `json:"sni_spoof,omitempty"`    // "on" or "off"
	SpoofSNI     string `json:"spoof_sni,omitempty"`    // whitelisted SNI hostname
	IPSpoof      string `json:"ip_spoof,omitempty"`     // "on" or "off"
	SpoofIP      string `json:"spoof_ip,omitempty"`     // whitelisted IPv4 address
	AntiFreeze   string `json:"anti_freeze,omitempty"`  // "on" or "off"
	IPv6         *bool  `json:"ipv6,omitempty"`         // true for IPv6 bridge, false for IPv4
	Mux          string `json:"mux,omitempty"`          // "on" or "off"

	WebsiteBridge         string `json:"website_bridge,omitempty"`
	WebsiteDomains        string `json:"website_domains,omitempty"`
	OutboundProxy         string `json:"outbound_proxy,omitempty"`
	OutboundProxyPort     int    `json:"outbound_proxy_port,omitempty"`
	OutboundProxyMode     string `json:"outbound_proxy_mode,omitempty"`
	OutboundIranDomains   string `json:"outbound_iran_domains,omitempty"`
	OutboundBypassDomains string `json:"outbound_bypass_domains,omitempty"`
}

func setConfKey(text, key, val string) string {
	lines := strings.Split(text, "\n")
	replaced := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, _, ok := strings.Cut(t, "=")
		if ok && strings.TrimSpace(k) == key {
			lines[i] = key + " = " + val
			replaced = true
		}
	}
	if !replaced {
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines[len(lines)-1] = key + " = " + val
			lines = append(lines, "")
		} else {
			lines = append(lines, key+" = "+val)
		}
	}
	return strings.Join(lines, "\n")
}

func replaceAddrPort(addr string, port int) string {
	p := strconv.Itoa(port)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return net.JoinHostPort(h, p)
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i+1] + p
	}
	return "0.0.0.0:" + p
}

func intInSlice(n int, list []int) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

// EditEdge changes the ports and settings of a tunnel on its Relay (edge) server
// and returns the updated pairing code for the Foreign server.
func EditEdge(spec EditSpec, confDir string) (EdgeResult, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	res := EdgeResult{Name: spec.Name}
	if err := validTunnelName(spec.Name); err != nil {
		return res, err
	}

	agentOpMu.Lock()
	defer agentOpMu.Unlock()
	host := hostFor(confDir)

	confFile := filepath.Join(confDir, spec.Name+".conf")
	certFile := filepath.Join(confDir, spec.Name+".crt")
	keyFile := filepath.Join(confDir, spec.Name+".key")
	oldBytes, err := os.ReadFile(confFile)
	if err != nil {
		return res, fmt.Errorf("there is no tunnel %q on this server", spec.Name)
	}
	oldConf := string(oldBytes)

	switch spec.Stage {
	case "rollback":
		if spec.OldConf != "" {
			_ = writeFileAtomic(confFile, []byte(spec.OldConf), 0o600)
			_ = host.FirewallApply(spec.Name)
			_ = host.Restart(spec.Name)
		}
		res.OK = true
		return res, nil

	case "commit":
		restore := func() {
			if spec.OldConf != "" {
				_ = writeFileAtomic(confFile, []byte(spec.OldConf), 0o600)
				_ = host.FirewallApply(spec.Name)
				_ = host.Restart(spec.Name)
			}
		}
		cfg, err := engine.LoadConfig(confFile)
		if err != nil {
			restore()
			return res, err
		}
		if cfg.Transport != engine.TransportPlain && !engine.IsKCPFamily(cfg.Transport) && !cfg.Dials() {
			if _, err := engine.EnsureCert(certFile, keyFile, cfg.EffectiveServerName()); err != nil {
				restore()
				return res, fmt.Errorf("preparing the certificate: %w", err)
			}
		}
		if err := host.FirewallApply(spec.Name); err != nil {
			if cfg.GRE || cfg.SIT {
				restore()
				if cfg.SIT {
					return res, fmt.Errorf("this server could not make the private 6in4 (SIT) link: %w", err)
				}
				return res, fmt.Errorf("this server could not make the private GRE link: %w", err)
			}
			res.Warnings = append(res.Warnings, err.Error())
		}
		if err := host.Restart(spec.Name); err != nil && !errors.Is(err, errNoSystemd) {
			restore()
			return res, err
		}
		if err := confirmRunning(host, spec.Name); err != nil {
			restore()
			return res, err
		}
		code, _ := edgePairingCode(confDir, spec.Name)
		res.OK = true
		res.Code = code
		return res, nil

	case "", "prepare":
	default:
		return res, fmt.Errorf("unknown edit stage %q", spec.Stage)
	}

	curCfg, err := engine.LoadConfig(confFile)
	if err != nil {
		return res, fmt.Errorf("reading current settings: %w", err)
	}
	kv, err := readConfKeys(confFile)
	if err != nil {
		return res, err
	}

	text := oldConf

	if curCfg.Role == engine.RoleEdge && (spec.Mode != "" || spec.Transport != "") {
		// Full mode / transport replacement while preserving user ports, service ports,
		// secret, proxy_protocol, pool, max_conn, spare_ttl, and drain.
		curUsers := portsIn(curCfg.UserListen)
		curLink := 0
		if ps := portsIn(curCfg.TunnelAddr); len(ps) > 0 {
			curLink = ps[0]
		}
		uPorts := joinPorts(spec.UserPorts, ", ")
		if uPorts == "" {
			uPorts = joinPorts(curCfg.UserListen, ", ")
		}
		sPorts := joinPorts(spec.ServicePorts, ",")
		if sPorts == "" {
			sPorts = joinPorts(curCfg.ServerInboundPort, ",")
			if sPorts == "" {
				sPorts = joinPorts(uPorts, ",")
			}
		}
		linkPort := spec.LinkPort
		if linkPort == 0 {
			linkPort = curLink
		}
		mode := spec.Mode
		if mode == "" {
			mode = kv["mode"]
		}
		transport := spec.Transport
		if transport == "" {
			transport = kv["transport"]
		}
		peerIP := strings.Trim(strings.TrimSpace(spec.PeerIP), "[]")
		if peerIP == "" {
			peerIP = kv["peer_ip"]
			if kv["gre"] == "on" && kv["gre_remote"] != "" {
				peerIP = kv["gre_remote"]
			}
			if kv["sit"] == "on" && kv["sit_remote"] != "" {
				peerIP = kv["sit_remote"]
			}
		}
		localIP := strings.Trim(strings.TrimSpace(spec.LocalIP), "[]")
		if localIP == "" {
			localIP = kv["local_ip"]
		}
		useV6 := strings.Contains(peerIP, ":") || strings.Contains(localIP, ":")
		if spec.IPv6 != nil {
			useV6 = *spec.IPv6
		}
		mux := spec.Mux
		if mux == "" {
			mux = kv["mux"]
		}
		muxLinks := spec.MuxLinks
		if muxLinks == 0 {
			muxLinks = curCfg.MuxLinks
		}
		pool := spec.Pool
		if pool == 0 {
			pool = curCfg.PoolSize
		}
		pp := spec.ProxyProtocol
		if pp == "" {
			pp = kv["proxy_protocol"]
		}
		if pp == "off" {
			pp = ""
		}

		wb := spec.WebsiteBridge
		if wb == "" {
			wb = kv["website_bridge"]
		}
		wd := spec.WebsiteDomains
		if wd == "" {
			wd = kv["website_domains"]
		}
		op := spec.OutboundProxy
		if op == "" {
			op = kv["outbound_proxy"]
		}
		opp := spec.OutboundProxyPort
		if opp == 0 {
			opp = curCfg.OutboundProxyPort
		}
		opm := spec.OutboundProxyMode
		if opm == "" {
			opm = kv["outbound_proxy_mode"]
		}
		oid := spec.OutboundIranDomains
		if oid == "" {
			oid = kv["outbound_iran_domains"]
		}
		obd := spec.OutboundBypassDomains
		if obd == "" {
			obd = kv["outbound_bypass_domains"]
		}

		cleanIPs := spec.CleanIPs
		if cleanIPs == "" && spec.KeepCleanIPs && spec.CDN == "on" {
			cleanIPs = strings.ReplaceAll(kv["clean_ips"], " ", "")
		}

		es := EdgeSpec{
			Name:                  spec.Name,
			Mode:                  mode,
			Transport:             transport,
			ServerName:            spec.ServerName,
			WSPath:                kv["ws_path"],
			CDN:                   spec.CDN,
			AltHost:               spec.AltHost,
			CleanIPs:              cleanIPs,
			UTLS:                  spec.UTLS,
			TLSFragment:           spec.TLSFragment,
			HTTPHeader:            spec.HTTPHeader,
			HTTPHost:              spec.HTTPHost,
			RealSite:              spec.RealSite,
			GRE:                   spec.GRE,
			SIT:                   spec.SIT,
			SNISpoof:              spec.SNISpoof,
			SpoofSNI:              spec.SpoofSNI,
			IPSpoof:               spec.IPSpoof,
			SpoofIP:               spec.SpoofIP,
			AntiFreeze:            spec.AntiFreeze,
			ProxyProtocol:         pp,
			Mux:                   mux,
			MuxLinks:              muxLinks,
			Pool:                  pool,
			PeerIP:                peerIP,
			LocalIP:               localIP,
			IPv6:                  useV6,
			LinkPort:              linkPort,
			UserPorts:             uPorts,
			ServicePorts:          sPorts,
			WebsiteBridge:         wb,
			WebsiteDomains:        wd,
			OutboundProxy:         op,
			OutboundProxyPort:     opp,
			OutboundProxyMode:     opm,
			OutboundIranDomains:   oid,
			OutboundBypassDomains: obd,
		}
		es.normalise()
		if err := es.check(); err != nil {
			return res, err
		}

		// Check port clashes on this Relay server, ignoring ports already held by this tunnel.
		var problems []string
		claimed := portsClaimedByOthers(confDir, spec.Name)
		owner := func(p int) string {
			for _, c := range claimed {
				if c.port == p {
					return fmt.Sprintf("tunnel %q (%s)", c.tunnel, c.what)
				}
			}
			return ""
		}
		for _, u := range portsIn(es.UserPorts) {
			if o := owner(u); o != "" {
				problems = append(problems, fmt.Sprintf("user listen port %d is already used on this server by %s", u, o))
			} else if !intInSlice(u, curUsers) && !(curCfg.Mode == engine.ModeReverse && u == curLink) {
				if err := host.PortFree(engine.TransportPlain, u); err != nil {
					problems = append(problems, fmt.Sprintf("user listen port %d is already in use on this server by another program", u))
				}
			}
		}
		if !es.dialsOut() {
			t := engine.Transport(es.Transport)
			if !engine.IsKCPFamily(t) {
				t = engine.TransportPlain
			}
			if o := owner(es.LinkPort); o != "" {
				problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already used on this server by %s", es.LinkPort, o))
			} else if !(curCfg.Mode == engine.ModeReverse && es.LinkPort == curLink) && !intInSlice(es.LinkPort, curUsers) {
				if err := host.PortFree(t, es.LinkPort); err != nil {
					problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already in use on this server", es.LinkPort))
				}
			}
		}
		if len(problems) > 0 {
			return res, fmt.Errorf("this server cannot use those ports:\n  - %s\nChange them and try again", strings.Join(problems, "\n  - "))
		}

		l, err := es.layout()
		if err != nil {
			return res, err
		}
		if es.RealSite == "on" && !es.dialsOut() {
			found := ""
			for _, c := range append([]string{es.ServerName}, coverSiteCandidates...) {
				if c != "" && reachable(c) {
					found = c
					break
				}
			}
			if found != "" && found != es.ServerName {
				es.ServerName = found
			}
		}
		text = buildEdgeConf(&es, l, confDir, time.Now())
		if curCfg.MaxConn > 0 && curCfg.MaxConn != 2000 && spec.MaxConn == 0 {
			text = setConfKey(text, "max_conn", strconv.Itoa(curCfg.MaxConn))
		}
		if kv["spare_ttl"] != "" && spec.SpareTTL == "" {
			text = setConfKey(text, "spare_ttl", kv["spare_ttl"])
		}
		if kv["drain"] != "" && spec.Drain == "" {
			text = setConfKey(text, "drain", kv["drain"])
		}
	} else if curCfg.Role == engine.RoleEdge {
		curUsers := portsIn(curCfg.UserListen)
		curServices := portsIn(curCfg.ServerInboundPort)
		if len(curServices) == 0 {
			curServices = curUsers
		}
		curLink := 0
		if ps := portsIn(curCfg.TunnelAddr); len(ps) > 0 {
			curLink = ps[0]
		}

		uPorts := joinPorts(spec.UserPorts, ", ")
		sPorts := joinPorts(spec.ServicePorts, ",")
		if uPorts == "" && sPorts != "" {
			uPorts = joinPorts(sPorts, ", ")
		}
		if uPorts == "" {
			uPorts = joinPorts(curCfg.UserListen, ", ")
		}
		if sPorts == "" {
			sPorts = joinPorts(curCfg.ServerInboundPort, ",")
			if sPorts == "" {
				sPorts = joinPorts(uPorts, ",")
			}
		}
		linkPort := spec.LinkPort
		if linkPort == 0 {
			linkPort = curLink
		}
		if linkPort < 1 || linkPort > 65535 {
			return res, errors.New("the port between the servers must be from 1 to 65535")
		}

		users, services := portsIn(uPorts), portsIn(sPorts)
		if len(users) == 0 || len(users) != len(strings.Split(uPorts, ",")) {
			return res, errors.New("give the port or ports your users connect to, as numbers from 1 to 65535")
		}
		if len(services) == 0 || len(services) != len(strings.Split(sPorts, ",")) {
			return res, errors.New("give the inbound port or ports on the foreign server, as numbers from 1 to 65535")
		}
		if len(users) != len(services) {
			return res, errors.New("each user listen port leads to one inbound port, in order, so give the same number of each")
		}
		for _, u := range users {
			if curCfg.Mode == engine.ModeReverse && u == linkPort {
				return res, fmt.Errorf("the port between the servers cannot also be a user listen port (%d)", u)
			}
		}
		if curCfg.Mode == engine.ModeDirect {
			for _, sv := range services {
				if sv == linkPort {
					return res, fmt.Errorf("the port between the servers cannot also be an inbound port on the foreign server (%d)", sv)
				}
			}
		}

		// Check port clashes on this Relay server, ignoring ports already held by this tunnel itself.
		var problems []string
		claimed := portsClaimedByOthers(confDir, spec.Name)
		owner := func(p int) string {
			for _, c := range claimed {
				if c.port == p {
					return fmt.Sprintf("tunnel %q (%s)", c.tunnel, c.what)
				}
			}
			return ""
		}
		for _, u := range users {
			if o := owner(u); o != "" {
				problems = append(problems, fmt.Sprintf("user listen port %d is already used on this server by %s", u, o))
			} else if !intInSlice(u, curUsers) && !(curCfg.Mode == engine.ModeReverse && u == curLink) {
				if err := host.PortFree(engine.TransportPlain, u); err != nil {
					problems = append(problems, fmt.Sprintf("user listen port %d is already in use on this server by another program", u))
				}
			}
		}
		if curCfg.Mode == engine.ModeReverse {
			t := curCfg.Transport
			if !engine.IsKCPFamily(t) {
				t = engine.TransportPlain
			}
			if o := owner(linkPort); o != "" {
				problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already used on this server by %s", linkPort, o))
			} else if linkPort != curLink && !intInSlice(linkPort, curUsers) {
				if err := host.PortFree(t, linkPort); err != nil {
					problems = append(problems, fmt.Sprintf("the port between the servers, %d, is already in use on this server", linkPort))
				}
			}
		}
		if len(problems) > 0 {
			return res, fmt.Errorf("this server cannot use those ports:\n  - %s\nChange them and try again", strings.Join(problems, "\n  - "))
		}

		text = setConfKey(text, "user_listen", uPorts)
		text = setConfKey(text, "server_inbound_port", sPorts)
		text = setConfKey(text, "tunnel_addr", replaceAddrPort(kv["tunnel_addr"], linkPort))
		if kv["alt_target"] != "" {
			text = setConfKey(text, "alt_target", replaceAddrPort(kv["alt_target"], linkPort))
		}
	}

	if spec.ProxyProtocol != "" {
		switch spec.ProxyProtocol {
		case "off", "v1", "v2":
			text = setConfKey(text, "proxy_protocol", spec.ProxyProtocol)
		default:
			return res, fmt.Errorf("real user IP (proxy_protocol) must be off, v1 or v2, got %q", spec.ProxyProtocol)
		}
	}
	if spec.WebsiteBridge == "on" || spec.WebsiteBridge == "off" {
		text = setConfKey(text, "website_bridge", spec.WebsiteBridge)
	}
	if spec.WebsiteDomains != "" || curCfg.WebsiteBridge || spec.WebsiteBridge == "on" {
		if spec.WebsiteDomains != "" {
			text = setConfKey(text, "website_domains", cleanDomainCSV(spec.WebsiteDomains))
		}
	}
	if spec.OutboundProxy == "on" || spec.OutboundProxy == "off" {
		text = setConfKey(text, "outbound_proxy", spec.OutboundProxy)
	}
	if spec.OutboundProxyPort > 0 {
		if spec.OutboundProxyPort < 1 || spec.OutboundProxyPort > 65535 {
			return res, errors.New("outbound proxy port must be from 1 to 65535")
		}
		text = setConfKey(text, "outbound_proxy_port", strconv.Itoa(spec.OutboundProxyPort))
	}
	if spec.OutboundProxyMode != "" {
		if spec.OutboundProxyMode != "split" && spec.OutboundProxyMode != "all" {
			return res, fmt.Errorf("outbound proxy mode must be split or all, got %q", spec.OutboundProxyMode)
		}
		text = setConfKey(text, "outbound_proxy_mode", spec.OutboundProxyMode)
	}
	if spec.OutboundIranDomains != "" {
		text = setConfKey(text, "outbound_iran_domains", cleanDomainCSV(spec.OutboundIranDomains))
	}
	if spec.OutboundBypassDomains != "" {
		text = setConfKey(text, "outbound_bypass_domains", cleanDomainCSV(spec.OutboundBypassDomains))
	}
	muxNow := curCfg.Mux
	if spec.Mux != "" {
		switch spec.Mux {
		case "on":
			muxNow = true
			text = setConfKey(text, "mux", "on")
		case "off":
			muxNow = false
			text = setConfKey(text, "mux", "off")
		default:
			return res, fmt.Errorf("mux must be on or off, got %q", spec.Mux)
		}
	}
	if muxNow {
		links := spec.MuxLinks
		if links == 0 {
			links = curCfg.MuxLinks
		}
		if links == 0 {
			links = 4
		}
		if links < 1 || links > 16 {
			return res, errors.New("the number of shared connections must be from 1 to 16")
		}
		text = setConfKey(text, "mux_links", strconv.Itoa(links))
	}
	if spec.Pool > 0 {
		if spec.Pool < 1 || spec.Pool > 10000 {
			return res, errors.New("connection pool size must be from 1 to 10000")
		}
		text = setConfKey(text, "pool_size", strconv.Itoa(spec.Pool))
	}
	if spec.MaxConn > 0 {
		if spec.MaxConn < 1 || spec.MaxConn > 100000 {
			return res, errors.New("max_conn must be from 1 to 100000")
		}
		text = setConfKey(text, "max_conn", strconv.Itoa(spec.MaxConn))
	}
	if ttl := strings.TrimSpace(spec.SpareTTL); ttl != "" && !muxNow {
		if d, err := time.ParseDuration(ttl); err != nil || d < 5*time.Second || d > 24*time.Hour {
			return res, errors.New("spare connection lifetime (spare_ttl) must be a duration between 5s and 24h, such as 60s or 2m")
		}
		text = setConfKey(text, "spare_ttl", ttl)
	}
	if dr := strings.TrimSpace(spec.Drain); dr != "" {
		if d, err := time.ParseDuration(dr); err != nil || d < 0 || d > 10*time.Minute {
			return res, errors.New("restart drain timeout (drain) must be a duration between 0s and 10m, such as 10s")
		}
		text = setConfKey(text, "drain", dr)
	}
	if pip := strings.TrimSpace(spec.PeerIP); pip != "" && pip != curCfg.PeerIP && spec.Mode == "" && spec.Transport == "" {
		if curCfg.GRE || curCfg.SIT {
			res.Warnings = append(res.Warnings, "peer_ip cannot be changed on a private GRE or 6in4 (SIT) tunnel")
		} else {
			pip = strings.Trim(pip, "[]")
			if net.ParseIP(pip) == nil && !engine.HostnameRe.MatchString(pip) {
				return res, fmt.Errorf("peer IP %q is not a valid IP address or hostname", pip)
			}
			text = setConfKey(text, "peer_ip", pip)
			curTAddr := kv["tunnel_addr"]
			if h, p, err := net.SplitHostPort(curTAddr); err == nil && h != "0.0.0.0" && h != "::" && h != "" {
				if spec.LinkPort > 0 {
					p = strconv.Itoa(spec.LinkPort)
				}
				text = setConfKey(text, "tunnel_addr", net.JoinHostPort(pip, p))
			}
		}
	}
	if spec.Firewall != "" {
		switch spec.Firewall {
		case "on":
			if curCfg.CDN || curCfg.AltTarget != "" || curCfg.GRE || curCfg.SIT || spec.CDN == "on" || spec.AltHost != "" || spec.GRE == "on" || spec.SIT == "on" {
				res.Warnings = append(res.Warnings, "firewall stays off for CDN, GRE and 6in4 (SIT) tunnels")
			} else {
				text = setConfKey(text, "firewall", "on")
			}
		case "off":
			text = setConfKey(text, "firewall", "off")
		default:
			return res, fmt.Errorf("firewall must be on or off, got %q", spec.Firewall)
		}
	}

	if err := writeFileAtomic(confFile, []byte(text), 0o600); err != nil {
		return res, fmt.Errorf("writing updated settings: %w", err)
	}
	newCfg, err := engine.LoadConfig(confFile)
	if err == nil {
		err = newCfg.Validate()
	}
	if err == nil {
		err = newCfg.LoadSecret()
	}
	if err != nil {
		_ = writeFileAtomic(confFile, []byte(oldConf), 0o600)
		return res, fmt.Errorf("those settings were refused: %w", err)
	}
	if newCfg.Transport != engine.TransportPlain && !engine.IsKCPFamily(newCfg.Transport) && !newCfg.Dials() {
		if _, err := engine.EnsureCert(certFile, keyFile, newCfg.EffectiveServerName()); err != nil {
			_ = writeFileAtomic(confFile, []byte(oldConf), 0o600)
			return res, fmt.Errorf("preparing the certificate: %w", err)
		}
	}

	var code string
	if newCfg.Role == engine.RoleEdge {
		code, err = edgePairingCode(confDir, spec.Name)
		if err != nil {
			_ = writeFileAtomic(confFile, []byte(oldConf), 0o600)
			return res, err
		}
	}

	if spec.Stage == "prepare" {
		res.OK = true
		res.Code = code
		res.OldConf = oldConf
		return res, nil
	}

	// Single-step commit (when no remote server needs to be updated first).
	restore := func() {
		_ = writeFileAtomic(confFile, []byte(oldConf), 0o600)
		_ = host.FirewallApply(spec.Name)
		_ = host.Restart(spec.Name)
	}
	if err := host.FirewallApply(spec.Name); err != nil {
		if newCfg.GRE || newCfg.SIT {
			restore()
			if newCfg.SIT {
				return res, fmt.Errorf("this server could not make the private 6in4 (SIT) link: %w", err)
			}
			return res, fmt.Errorf("this server could not make the private GRE link: %w", err)
		}
		res.Warnings = append(res.Warnings, err.Error())
	}
	if err := host.Restart(spec.Name); err != nil && !errors.Is(err, errNoSystemd) {
		restore()
		return res, err
	}
	if err := confirmRunning(host, spec.Name); err != nil {
		restore()
		return res, err
	}

	if wpNotes := syncWebsiteBridgeOrigin(newCfg, curCfg, confDir); len(wpNotes) > 0 {
		res.Warnings = append(res.Warnings, wpNotes...)
	}

	res.OK = true
	res.Code = code
	return res, nil
}

// tunnelLogs returns the recent systemd journal lines for one tunnel.
func tunnelLogs(confDir, name string, lines int) (string, error) {
	if err := validTunnelName(name); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(confDir, name+".conf")); err != nil {
		return "", fmt.Errorf("there is no tunnel %q on this server", name)
	}
	if lines <= 0 || lines > 500 {
		lines = 60
	}
	if _, ok := hostFor(confDir).(systemHost); !ok {
		return fmt.Sprintf("(test environment: no systemd journal for portbridge@%s)", name), nil
	}
	out, err := hostRun("journalctl", "-u", "portbridge@"+name, "-n", strconv.Itoa(lines), "--no-pager")
	if err != nil && out == "" {
		return "", fmt.Errorf("reading journal: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return "(no log entries yet)", nil
	}
	return out, nil
}

// CheckItem is one diagnostic check line, matching the CLI menu's "Check a tunnel".
type CheckItem struct {
	Label  string `json:"label"`
	Status string `json:"status"` // "ok", "warn", "bad", "note"
	Detail string `json:"detail"`
	Note   string `json:"note,omitempty"`
}

// TunnelCheckReport is the diagnostic report for one half of a tunnel.
type TunnelCheckReport struct {
	OK     bool        `json:"ok"`
	Name   string      `json:"name"`
	Role   string      `json:"role"`
	Checks []CheckItem `json:"checks"`
}

// CheckTunnel inspects one half of a tunnel on this server, mirroring the CLI
// menu's test_tunnel (Option 8).
func CheckTunnel(confDir, name string) (TunnelCheckReport, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	if err := validTunnelName(name); err != nil {
		return TunnelCheckReport{}, err
	}
	confPath := filepath.Join(confDir, name+".conf")
	if _, err := os.Stat(confPath); err != nil {
		return TunnelCheckReport{}, fmt.Errorf("there is no tunnel %q on this server", name)
	}
	host := hostFor(confDir)
	ti := tunnelInfo(confPath, host)
	cfg, cfgErr := engine.LoadConfig(confPath)

	rep := TunnelCheckReport{OK: true, Name: name, Role: ti.Role}
	add := func(label, status, detail, note string) {
		rep.Checks = append(rep.Checks, CheckItem{Label: label, Status: status, Detail: detail, Note: note})
	}

	if ti.Running {
		add("Tunnel service", "ok", "Active and running", "")
	} else {
		add("Tunnel service", "bad", "Stopped", ti.ServiceNote)
	}

	if cfgErr != nil {
		add("Configuration", "bad", cfgErr.Error(), "")
		return rep, nil
	}

	if cfg.GRE {
		if _, isSys := host.(systemHost); isSys {
			if out, err := hostRun(firewallHelper, "gre-test", name); err == nil {
				add("Private GRE link", "ok", out, "")
			} else {
				add("Private GRE link", "bad", out, "GRE (IP protocol 47) may be filtered between these servers.")
			}
		} else {
			add("Private GRE link", "ok", "Configured", "")
		}
	}
	if cfg.SIT {
		if _, isSys := host.(systemHost); isSys {
			if out, err := hostRun(firewallHelper, "sit-test", name); err == nil {
				add("Private 6in4 (SIT) link", "ok", out, "")
			} else {
				add("Private 6in4 (SIT) link", "bad", out, "6in4 / SIT (IP protocol 41) may be filtered between these servers.")
			}
		} else {
			add("Private 6in4 (SIT) link", "ok", "Configured", "")
		}
	}

	if cfg.Role == engine.RoleEdge {
		for _, p := range ti.UserPorts {
			if host.Listening(p) {
				add(fmt.Sprintf("User listen port %d", p), "ok", "Listening for user connections", "")
			} else {
				add(fmt.Sprintf("User listen port %d", p), "bad", fmt.Sprintf("Nothing listening on port %d", p), "Start the tunnel service to accept user connections.")
			}
		}
	} else {
		for _, p := range ti.ServicePorts {
			if host.Listening(p) {
				add(fmt.Sprintf("Inbound service port %d", p), "ok", fmt.Sprintf("Local service answering at 127.0.0.1:%d", p), "")
			} else {
				add(fmt.Sprintf("Inbound service port %d", p), "bad", fmt.Sprintf("Nothing answering at 127.0.0.1:%d", p), "Make sure your X-UI / Xray / inbound service is running on this port.")
			}
		}
	}

	if cfg.Dials() {
		if engine.IsKCPFamily(cfg.Transport) {
			add("Peer bridge port", "note", fmt.Sprintf("%s (%s) — verified by link state below", strings.ToUpper(string(cfg.Transport)), cfg.TunnelAddr), "")
		} else if _, isSys := host.(systemHost); isSys {
			c, err := net.DialTimeout("tcp", cfg.TunnelAddr, 3*time.Second)
			if err == nil {
				_ = c.Close()
				add("Peer bridge port", "ok", fmt.Sprintf("Reachable (%s)", cfg.TunnelAddr), "")
			} else {
				add("Peer bridge port", "bad", fmt.Sprintf("Cannot reach %s", cfg.TunnelAddr), "Check that the other server's tunnel half is running and its firewall allows this server.")
			}
		} else {
			add("Peer bridge port", "ok", fmt.Sprintf("Configured (%s)", cfg.TunnelAddr), "")
		}
	} else {
		busy := host.PortFree(cfg.Transport, ti.LinkPort) != nil
		if _, isNo := host.(noHost); isNo || cfg.Transport == engine.TransportICMP || cfg.Transport == engine.TransportFakeTCP {
			busy = ti.Running
		}
		if busy {
			add("Bridge listener", "ok", fmt.Sprintf("Waiting for peer on port %d", ti.LinkPort), "")
		} else {
			add("Bridge listener", "bad", fmt.Sprintf("Not listening on bridge port %d", ti.LinkPort), "")
		}
	}

	if ti.Live != nil {
		if cfg.Mux {
			if ti.Live.Links > 0 {
				add("Inter-server link", "ok", fmt.Sprintf("Connected (%d / %d shared Mux links open)", ti.Live.Links, max(1, ti.Live.LinkTarget)), "")
			} else {
				add("Inter-server link", "bad", "0 shared links open — servers are not connected", "Check that both halves are running and have matching pairing codes and system clocks.")
			}
		} else {
			if ti.Live.ParkedSpares > 0 {
				add("Inter-server link", "ok", fmt.Sprintf("Connected (%d / %d spare connections ready)", ti.Live.ParkedSpares, max(1, ti.Live.PoolTarget)), "")
			} else {
				add("Inter-server link", "bad", "0 spare connections ready — servers are not talking", "Check that both halves are running and have matching pairing codes and system clocks.")
			}
		}
		switch ti.Live.PathState {
		case "ok":
			add("End-to-end data flow", "ok", "Healthy — verified by active tunnel probe", "")
		case "degraded":
			add("End-to-end data flow", "warn", "Degraded", ti.Live.PathNote)
		case "blocked":
			add("End-to-end data flow", "bad", "Blocked — connections open but data is dropped", ti.Live.PathNote)
		default:
			add("End-to-end data flow", "note", "Measuring...", "")
		}
	} else if ti.Running {
		add("Inter-server link", "warn", "Waiting for live telemetry from service", "")
	}

	if cfg.AltTarget != "" {
		if _, isSys := host.(systemHost); isSys {
			c, err := net.DialTimeout("tcp", cfg.AltTarget, 3*time.Second)
			if err == nil {
				_ = c.Close()
				add("CDN backup route", "ok", fmt.Sprintf("Ready (%s)", cfg.AltTarget), "")
			} else {
				add("CDN backup route", "bad", fmt.Sprintf("Cannot reach %s", cfg.AltTarget), "Check that the domain points to your CDN with proxy enabled.")
			}
		} else {
			add("CDN backup route", "ok", fmt.Sprintf("Configured (%s)", cfg.AltTarget), "")
		}
	}

	if !cfg.Dials() {
		if ti.Firewall {
			add("Bridge port firewall", "ok", fmt.Sprintf("Enabled (bridge port locked to %s)", ti.PeerIP), "")
		} else {
			add("Bridge port firewall", "note", "Disabled (bridge port open to any IP)", "")
		}
	}

	return rep, nil
}

// tunnelSpeedtest runs an in-tunnel latency and throughput test.
func tunnelSpeedtest(confDir, name string, sizeMB float64) (string, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	if err := validTunnelName(name); err != nil {
		return "", err
	}
	confPath := filepath.Join(confDir, name+".conf")
	if _, err := os.Stat(confPath); err != nil {
		return "", fmt.Errorf("there is no tunnel %q on this server", name)
	}
	if sizeMB <= 0 || sizeMB > 16 {
		sizeMB = 1.0
	}
	if _, isSys := hostFor(confDir).(systemHost); !isSys {
		return fmt.Sprintf("🚀 PortBridge Speed Test: %s\n   RTT: 18.40 ms | Jitter: 1.20 ms\n   Download: 12.50 MB/s (100.0 Mbps) in 0.08s\n   Upload: 11.80 MB/s (94.4 Mbps) in 0.08s\n", name), nil
	}
	return engine.RunSpeedtest(confPath, sizeMB)
}

// TuneInfo describes a server's Linux kernel network & BBR tuning state.
type TuneInfo struct {
	OK                bool   `json:"ok"`
	BBRActive         bool   `json:"bbr_active"`
	TunedByPB         bool   `json:"tuned_by_pb"`
	CongestionControl string `json:"congestion_control"`
	Qdisc             string `json:"qdisc"`
	WmemMax           string `json:"wmem_max"`
	RmemMax           string `json:"rmem_max"`
	FileMax           string `json:"file_max"`
	FastOpen          string `json:"fast_open"`
	Output            string `json:"output,omitempty"`
}

const tuneHelper = "/usr/local/bin/portbridge-tune"
const tuneConfPath = "/etc/sysctl.d/99-portbridge-tuning.conf"

func readProcSys(rel string) string {
	b, err := os.ReadFile("/proc/sys/" + rel)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readTuneStatus(confDir string) TuneInfo {
	if _, isSys := hostFor(confDir).(systemHost); !isSys {
		return TuneInfo{
			OK:                true,
			BBRActive:         false,
			TunedByPB:         false,
			CongestionControl: "cubic",
			Qdisc:             "fq_codel",
		}
	}
	cc := readProcSys("net/ipv4/tcp_congestion_control")
	_, err := os.Stat(tuneConfPath)
	return TuneInfo{
		OK:                true,
		BBRActive:         cc == "bbr",
		TunedByPB:         err == nil,
		CongestionControl: cc,
		Qdisc:             readProcSys("net/core/default_qdisc"),
		WmemMax:           readProcSys("net/core/wmem_max"),
		RmemMax:           readProcSys("net/core/rmem_max"),
		FileMax:           readProcSys("fs/file-max"),
		FastOpen:          readProcSys("net/ipv4/tcp_fastopen"),
	}
}

const builtinSysctlConf = `# written by portbridge-tune
# Remove this file and reboot (or run: portbridge-tune undo) to go back.

net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
fs.file-max = 2097152
`

func applyTune(confDir string, enable bool) (TuneInfo, error) {
	if _, isSys := hostFor(confDir).(systemHost); !isSys {
		return TuneInfo{
			OK:                true,
			BBRActive:         enable,
			TunedByPB:         enable,
			CongestionControl: map[bool]string{true: "bbr", false: "cubic"}[enable],
			Qdisc:             map[bool]string{true: "fq", false: "fq_codel"}[enable],
		}, nil
	}
	if err := needRoot(); err != nil {
		return TuneInfo{}, err
	}
	action := "undo"
	if enable {
		action = "apply"
	}
	var out string
	if _, err := os.Stat(tuneHelper); err == nil {
		var runErr error
		out, runErr = hostRun(tuneHelper, action)
		if runErr != nil {
			return TuneInfo{}, fmt.Errorf("tuning (%s): %s", action, out)
		}
	} else {
		// Fallback if only the portbridge binary was installed on this server.
		if enable {
			_, _ = hostRun("modprobe", "tcp_bbr")
			if err := os.WriteFile(tuneConfPath, []byte(builtinSysctlConf), 0o644); err != nil {
				return TuneInfo{}, err
			}
			if _, err := os.Stat("/etc/modules-load.d"); err == nil {
				_ = os.WriteFile("/etc/modules-load.d/portbridge-bbr.conf", []byte("tcp_bbr\n"), 0o644)
			}
			_, _ = hostRun("sysctl", "-p", tuneConfPath)
			out = "BBR and high-throughput TCP buffers applied."
		} else {
			_ = os.Remove(tuneConfPath)
			_ = os.Remove("/etc/modules-load.d/portbridge-bbr.conf")
			_, _ = hostRun("sysctl", "--system")
			out = "PortBridge network tuning removed."
		}
	}
	info := readTuneStatus(confDir)
	info.Output = out
	return info, nil
}

// FirewallTunnelRule summarizes the bridge-port firewall state for one tunnel on this server.
type FirewallTunnelRule struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Mode     string `json:"mode"`
	DialsOut bool   `json:"dials_out"`
	LinkPort int    `json:"link_port"`
	PeerIP   string `json:"peer_ip"`
	Locked   bool   `json:"locked"`
	CDNOrGRE bool   `json:"cdn_or_gre"`
}

// FirewallInfo describes the PortBridge bridge-port firewall rules on a server.
type FirewallInfo struct {
	OK      bool                 `json:"ok"`
	Status  string               `json:"status"`
	Output  string               `json:"output,omitempty"`
	Tunnels []FirewallTunnelRule `json:"tunnels"`
}

func readFirewallStatus(confDir string) FirewallInfo {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	host := hostFor(confDir)
	var rules []FirewallTunnelRule
	for _, ti := range TunnelsReport(confDir) {
		cfg, err := engine.LoadConfig(filepath.Join(confDir, ti.Name+".conf"))
		dials := false
		cdnOrGRE := ti.CDN || ti.GRE || ti.SIT
		if err == nil {
			dials = cfg.Dials()
			cdnOrGRE = cdnOrGRE || cfg.AltTarget != ""
		}
		rules = append(rules, FirewallTunnelRule{
			Name:     ti.Name,
			Role:     ti.Role,
			Mode:     ti.Mode,
			DialsOut: dials,
			LinkPort: ti.LinkPort,
			PeerIP:   ti.PeerIP,
			Locked:   ti.Firewall && !dials && !cdnOrGRE,
			CDNOrGRE: cdnOrGRE,
		})
	}
	statusText := ""
	if _, isSys := host.(systemHost); isSys {
		if _, err := os.Stat(firewallHelper); err == nil {
			if out, err := hostRun(firewallHelper, "status"); err == nil || out != "" {
				statusText = out
			}
		}
	}
	if statusText == "" {
		if len(rules) == 0 {
			statusText = "No tunnels on this server."
		} else {
			var lines []string
			for _, r := range rules {
				switch {
				case r.DialsOut:
					lines = append(lines, fmt.Sprintf("%s: dials out to %s:%d (no bridge listener on this server)", r.Name, r.PeerIP, r.LinkPort))
				case r.CDNOrGRE:
					lines = append(lines, fmt.Sprintf("%s: bridge port %d open (CDN / GRE / 6in4 tunnel)", r.Name, r.LinkPort))
				case r.Locked:
					lines = append(lines, fmt.Sprintf("%s: bridge port %d locked to %s", r.Name, r.LinkPort, r.PeerIP))
				default:
					lines = append(lines, fmt.Sprintf("%s: bridge port %d open to any IP (firewall off)", r.Name, r.LinkPort))
				}
			}
			statusText = strings.Join(lines, "\n")
		}
	}
	return FirewallInfo{
		OK:      true,
		Status:  statusText,
		Tunnels: rules,
	}
}

func applyFirewallAction(confDir, action string) (FirewallInfo, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	agentOpMu.Lock()
	defer agentOpMu.Unlock()
	host := hostFor(confDir)

	var outMsg string
	switch action {
	case "sweep":
		if err := host.FirewallSweep(); err != nil {
			return FirewallInfo{}, err
		}
		outMsg = "Cleaned up any leftover firewall rules and GRE/6in4 links from removed tunnels."
	case "on-all", "off-all":
		val := "on"
		if action == "off-all" {
			val = "off"
		}
		entries, _ := os.ReadDir(confDir)
		changed := 0
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".conf")
			confPath := filepath.Join(confDir, e.Name())
			cfg, err := engine.LoadConfig(confPath)
			if err != nil {
				continue
			}
			if val == "on" && (cfg.CDN || cfg.AltTarget != "" || cfg.GRE || cfg.SIT) {
				continue
			}
			raw, err := os.ReadFile(confPath)
			if err != nil {
				continue
			}
			updated := setConfKey(string(raw), "firewall", val)
			if err := writeFileAtomic(confPath, []byte(updated), 0o600); err == nil {
				_ = host.FirewallApply(name)
				changed++
			}
		}
		if val == "on" {
			outMsg = fmt.Sprintf("Locked bridge port firewall on %d tunnel(s).", changed)
		} else {
			outMsg = fmt.Sprintf("Turned off bridge port firewall on %d tunnel(s).", changed)
		}
	default:
		return FirewallInfo{}, fmt.Errorf("unknown firewall action %q", action)
	}

	info := readFirewallStatus(confDir)
	info.Output = outMsg
	return info, nil
}

// TunnelSnapshot holds the on-disk files and pairing code for one tunnel half
// so it can be backed up and restored onto the same or another server.
type TunnelSnapshot struct {
	Name        string `json:"name"`
	Role        string `json:"role"` // "edge" or "origin"
	Mode        string `json:"mode"` // "direct" or "reverse"
	Conf        string `json:"conf"`
	Secret      string `json:"secret"`
	CertPEM     string `json:"cert_pem,omitempty"`
	KeyPEM      string `json:"key_pem,omitempty"`
	PairingCode string `json:"pairing_code,omitempty"`
}

// ExportTunnels reads all tunnel configurations and secrets in confDir for backup.
func ExportTunnels(confDir string) ([]TunnelSnapshot, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	entries, err := os.ReadDir(confDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []TunnelSnapshot
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".conf")
		if validTunnelName(name) != nil {
			continue
		}
		confBytes, err := os.ReadFile(filepath.Join(confDir, name+".conf"))
		if err != nil {
			continue
		}
		kv, _ := readConfKeys(filepath.Join(confDir, name+".conf"))
		secBytes, _ := os.ReadFile(filepath.Join(confDir, name+".secret"))
		crtBytes, _ := os.ReadFile(filepath.Join(confDir, name+".crt"))
		keyBytes, _ := os.ReadFile(filepath.Join(confDir, name+".key"))
		code := ""
		if kv["role"] == "edge" {
			code, _ = edgePairingCode(confDir, name)
		}
		out = append(out, TunnelSnapshot{
			Name:        name,
			Role:        kv["role"],
			Mode:        kv["mode"],
			Conf:        string(confBytes),
			Secret:      strings.TrimSpace(string(secBytes)),
			CertPEM:     string(crtBytes),
			KeyPEM:      string(keyBytes),
			PairingCode: code,
		})
	}
	return out, nil
}

// ImportTunnel restores one tunnel half into confDir and starts its service.
// If newLocalIP is non-empty, local_ip is updated (used when migrating a panel's
// local tunnels onto a new server with a different IP).
func ImportTunnel(snap TunnelSnapshot, confDir string, overwrite bool, newLocalIP string) (EdgeResult, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	res := EdgeResult{Name: snap.Name}
	if err := validTunnelName(snap.Name); err != nil {
		return res, err
	}
	if strings.TrimSpace(snap.Conf) == "" || strings.TrimSpace(snap.Secret) == "" {
		return res, errors.New("tunnel backup is missing configuration or secret")
	}

	agentOpMu.Lock()
	defer agentOpMu.Unlock()
	host := hostFor(confDir)

	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return res, err
	}
	_ = os.Chmod(confDir, 0o700)

	confFile := filepath.Join(confDir, snap.Name+".conf")
	secretFile := filepath.Join(confDir, snap.Name+".secret")
	certFile := filepath.Join(confDir, snap.Name+".crt")
	keyFile := filepath.Join(confDir, snap.Name+".key")

	if !overwrite {
		if _, err := os.Stat(confFile); err == nil {
			res.OK = true
			if code, err := edgePairingCode(confDir, snap.Name); err == nil {
				res.Code = code
			}
			return res, nil
		}
	}

	confText := snap.Conf
	confPath := func(ext string) string { return filepath.ToSlash(filepath.Join(confDir, snap.Name+ext)) }
	confText = setConfKey(confText, "secret_file", confPath(".secret"))
	if strings.Contains(confText, "cert_file") {
		confText = setConfKey(confText, "cert_file", confPath(".crt"))
		confText = setConfKey(confText, "key_file", confPath(".key"))
	}
	if newLocalIP != "" && net.ParseIP(newLocalIP) != nil {
		confText = setConfKey(confText, "local_ip", newLocalIP)
	}

	if err := writeFileAtomic(secretFile, []byte(strings.TrimSpace(snap.Secret)+"\n"), 0o600); err != nil {
		return res, err
	}
	if snap.CertPEM != "" && snap.KeyPEM != "" {
		_ = writeFileAtomic(certFile, []byte(snap.CertPEM), 0o644)
		_ = writeFileAtomic(keyFile, []byte(snap.KeyPEM), 0o600)
	}
	if err := writeFileAtomic(confFile, []byte(confText), 0o600); err != nil {
		return res, err
	}

	cfg, err := engine.LoadConfig(confFile)
	if err == nil {
		if cfg.Transport != engine.TransportPlain && !engine.IsKCPFamily(cfg.Transport) && !cfg.Dials() {
			_, _ = engine.EnsureCert(certFile, keyFile, cfg.EffectiveServerName())
		}
		err = cfg.Validate()
	}
	if err == nil {
		err = cfg.LoadSecret()
	}
	if err != nil {
		return res, fmt.Errorf("restored tunnel config invalid: %w", err)
	}

	if err := host.FirewallApply(snap.Name); err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	}
	_ = host.Reload()
	if err := host.Enable(snap.Name); err != nil && !errors.Is(err, errNoSystemd) {
		res.Warnings = append(res.Warnings, err.Error())
	}
	_ = host.Restart(snap.Name)

	res.OK = true
	if cfg.Role == engine.RoleEdge {
		res.Code, _ = edgePairingCode(confDir, snap.Name)
	}
	return res, nil
}

// OutboundRouteProbe is one target checked through the Website Bridge's local outbound proxy.
type OutboundRouteProbe struct {
	Target        string `json:"target"`
	Label         string `json:"label"`
	ExpectedRoute string `json:"expected_route"`
	ActualRoute   string `json:"actual_route"`
	ExitIP        string `json:"exit_ip,omitempty"`
	LatencyMS     int64  `json:"latency_ms"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
}

// OutboundTestResult is the complete report from testing a Website Bridge's local outbound proxy.
type OutboundTestResult struct {
	OK        bool                 `json:"ok"`
	Name      string               `json:"name"`
	ProxyAddr string               `json:"proxy_addr"`
	ProxyMode string               `json:"proxy_mode"`
	IranIP    string               `json:"iran_ip,omitempty"`
	ForeignIP string               `json:"foreign_ip,omitempty"`
	Probes    []OutboundRouteProbe `json:"probes"`
	Error     string               `json:"error,omitempty"`
}

// TestOutboundProxy verifies the local smart outbound proxy on the Foreign server
// by sending test requests for Iran-routed traffic, Direct-bypassed traffic (Telegram),
// and an optional custom host.
func TestOutboundProxy(confDir, name, customHost string) (OutboundTestResult, error) {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	res := OutboundTestResult{Name: name}
	if err := validTunnelName(name); err != nil {
		return res, err
	}
	cfg, err := engine.LoadConfig(filepath.Join(confDir, name+".conf"))
	if err != nil {
		return res, fmt.Errorf("tunnel %q not found on this server", name)
	}
	_ = cfg.Validate()
	if !cfg.OutboundProxy {
		return res, fmt.Errorf("outbound proxy is not enabled on %q", name)
	}
	port := cfg.OutboundProxyPort
	if port <= 0 {
		port = 18080
	}
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	res.ProxyAddr = proxyAddr
	res.ProxyMode = cfg.OutboundProxyMode
	res.ForeignIP = cfg.LocalIP
	res.IranIP = cfg.PeerIP

	// 1. Deterministic Iran Tunnel Self-Check (http://portbridge-iran-check.ir/)
	iranProbe := OutboundRouteProbe{
		Target:        engine.OutboundCheckHost,
		Label:         "Iran Tunnel Exit Verification (Gateway / SMS Route)",
		ExpectedRoute: "iran",
	}
	t0 := time.Now()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	hc := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}
	resp, err := hc.Get("http://" + engine.OutboundCheckHost + "/")
	iranProbe.LatencyMS = time.Since(t0).Milliseconds()
	if err != nil {
		iranProbe.Error = err.Error()
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		iranProbe.ActualRoute = resp.Header.Get("X-PortBridge-Route")
		var parsed struct {
			OK     bool   `json:"ok"`
			Route  string `json:"route"`
			IranIP string `json:"iran_ip"`
		}
		if json.Unmarshal(body, &parsed) == nil && parsed.OK {
			iranProbe.OK = true
			if parsed.Route != "" {
				iranProbe.ActualRoute = parsed.Route
			}
			if parsed.IranIP != "" {
				iranProbe.ExitIP = parsed.IranIP
				res.IranIP = parsed.IranIP
			}
		} else if resp.StatusCode == http.StatusOK {
			iranProbe.OK = true
		} else {
			iranProbe.Error = strings.TrimSpace(string(body))
			if iranProbe.Error == "" {
				iranProbe.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
			}
		}
	}
	if iranProbe.ExitIP == "" && iranProbe.OK {
		iranProbe.ExitIP = res.IranIP
	}
	res.Probes = append(res.Probes, iranProbe)

	// Helper to test HTTP CONNECT through the local proxy
	probeConnect := func(hostPort, label string) OutboundRouteProbe {
		h := hostPort
		if sh, _, err := net.SplitHostPort(hostPort); err == nil {
			h = sh
		} else {
			hostPort = net.JoinHostPort(hostPort, "443")
		}
		exp := "direct"
		if engine.ShouldRouteViaIran(h, cfg) {
			exp = "iran"
		}
		p := OutboundRouteProbe{
			Target:        hostPort,
			Label:         label,
			ExpectedRoute: exp,
		}
		start := time.Now()
		c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			p.LatencyMS = time.Since(start).Milliseconds()
			p.Error = fmt.Sprintf("connecting to local proxy %s: %v", proxyAddr, err)
			return p
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
		br := bufio.NewReader(c)
		httpResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		p.LatencyMS = time.Since(start).Milliseconds()
		if err != nil {
			p.Error = err.Error()
			return p
		}
		defer httpResp.Body.Close()
		p.ActualRoute = httpResp.Header.Get("X-PortBridge-Route")
		if httpResp.StatusCode == http.StatusOK {
			p.OK = true
			if p.ActualRoute == "iran" {
				p.ExitIP = res.IranIP
			} else {
				p.ExitIP = res.ForeignIP
			}
		} else {
			b, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
			p.Error = strings.TrimSpace(string(b))
			if p.Error == "" {
				p.Error = httpResp.Status
			}
		}
		return p
	}

	// 2. Direct Bypass Check (api.telegram.org:443)
	res.Probes = append(res.Probes, probeConnect("api.telegram.org:443", "Telegram API Direct Bypass (api.telegram.org)"))

	// 3. Optional Custom Host Check (or default Iranian gateway domain check)
	ch := strings.TrimSpace(customHost)
	if ch != "" {
		ch = strings.TrimPrefix(strings.TrimPrefix(ch, "https://"), "http://")
		if idx := strings.IndexByte(ch, '/'); idx >= 0 {
			ch = ch[:idx]
		}
		if ch != "" {
			res.Probes = append(res.Probes, probeConnect(ch, "Custom Domain Check ("+ch+")"))
		}
	}

	res.OK = true
	return res, nil
}
