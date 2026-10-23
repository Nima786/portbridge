package engine

// The deep scan: what the network between two servers actually lets through.
//
// The benchmark answers "which of our modes is fastest". This answers a step
// before it: "what gets across at all". A strict filter may pass only certain
// addresses, ports, protocols and names, and then the question is which of those
// can carry a tunnel. Three things are checked from the relay (the Iran side):
//
//   - which well-known public endpoints it can connect to (a connection only,
//     nothing is sent), which shows which providers' address ranges are let
//     through, and so where a foreign server could be hosted;
//   - which ports and protocols reach the foreign server, by asking a temporary
//     responder there to answer on each port;
//   - which domain names (TLS server names) survive on a port that works.

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ExploreTarget is a public endpoint the relay tries to connect to.
type ExploreTarget struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Addr  string `json:"addr"` // host:port
}

// ExploreEndpoints is the built-in list. Names (not addresses) are used where an
// address would not stay put; a failure to find the name is reported as such,
// apart from a failure to connect.
var ExploreEndpoints = []ExploreTarget{
	{"Cloudflare", "Cloudflare DNS", "1.1.1.1:443"},
	{"Cloudflare", "Cloudflare DNS (second)", "1.0.0.1:443"},
	{"Cloudflare", "cloudflare.com", "cloudflare.com:443"},
	{"Cloudflare", "Cloudflare challenges", "challenges.cloudflare.com:443"},
	{"Google", "Google DNS", "8.8.8.8:443"},
	{"Google", "Google DNS (second)", "8.8.4.4:443"},
	{"Google", "google.com", "www.google.com:443"},
	{"Google", "Google Cloud Storage", "storage.googleapis.com:443"},
	{"DNS services", "Quad9", "9.9.9.9:443"},
	{"DNS services", "OpenDNS", "208.67.222.222:443"},
	{"DNS services", "AdGuard DNS", "94.140.14.14:443"},
	{"CDN", "Fastly", "www.fastly.com:443"},
	{"CDN", "jsDelivr", "cdn.jsdelivr.net:443"},
	{"CDN", "Akamai", "www.akamai.com:443"},
	{"CDN", "Amazon CloudFront", "d1.awsstatic.com:443"},
	{"Amazon", "Amazon AWS", "dynamodb.us-east-1.amazonaws.com:443"},
	{"Microsoft", "Microsoft", "www.microsoft.com:443"},
	{"Microsoft", "Azure", "management.azure.com:443"},
	{"Hosting", "Hetzner", "fsn1-speed.hetzner.com:443"},
	{"Hosting", "OVH", "proof.ovh.net:443"},
	{"Hosting", "DigitalOcean", "speedtest-nyc1.digitalocean.com:443"},
	{"Hosting", "Vultr", "fra-de-ping.vultr.com:443"},
	{"Hosting", "Linode", "speedtest.london.linode.com:443"},
	{"Hosting", "Oracle Cloud", "objectstorage.us-ashburn-1.oraclecloud.com:443"},
	{"Hosting", "Leaseweb", "speedtest.ams1.nl.leaseweb.net:443"},
	{"Popular", "GitHub", "github.com:443"},
	{"Popular", "Apple", "www.apple.com:443"},
	{"Popular", "Wikipedia", "www.wikipedia.org:443"},
	{"Popular", "Telegram", "149.154.167.99:443"},
}

// ExploreReachResult is what trying one endpoint showed.
type ExploreReachResult struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	OK    bool   `json:"ok"`
	MS    int64  `json:"ms,omitempty"`
	Stage string `json:"stage,omitempty"` // "dns" or "connect" when it failed
	Error string `json:"error,omitempty"`
}

// ExploreReach tries a plain connection to each endpoint. Nothing is sent over
// it. It says whether the name could be found apart from whether the connection
// opened: a name that cannot be found is a different thing from an address that
// is cut off.
func ExploreReach(ctx context.Context, targets []ExploreTarget) []ExploreReachResult {
	results := make([]ExploreReachResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t ExploreTarget) {
			defer wg.Done()
			res := ExploreReachResult{Group: t.Group, Name: t.Name, Addr: t.Addr}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				res.Stage, res.Error = "connect", ctx.Err().Error()
				results[i] = res
				return
			}
			host, port, err := net.SplitHostPort(t.Addr)
			if err != nil {
				res.Stage, res.Error = "connect", err.Error()
				results[i] = res
				return
			}
			dest := t.Addr
			if net.ParseIP(host) == nil {
				rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
				cancel()
				if err != nil || len(ips) == 0 {
					res.Stage, res.Error = "dns", "the name could not be found"
					results[i] = res
					return
				}
				dest = net.JoinHostPort(ips[0].String(), port)
			}
			start := time.Now()
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, "tcp4", dest)
			if err != nil {
				res.Stage, res.Error = "connect", simpleDialError(err)
				results[i] = res
				return
			}
			_ = c.Close()
			res.OK = true
			res.MS = max(time.Since(start).Milliseconds(), 1)
			results[i] = res
		}(i, t)
	}
	wg.Wait()
	return results
}

// simpleDialError is a short reason for a failed connection.
func simpleDialError(err error) string {
	switch {
	case err == nil:
		return ""
	case isTimeout(err):
		return "no answer (timed out)"
	case strings.Contains(err.Error(), "refused"):
		return "refused"
	default:
		return "could not connect"
	}
}

// ---------------------------------------------------------------------------
// The responder on the foreign server
// ---------------------------------------------------------------------------

// DefaultExplorePorts are the ports the scan tries on the foreign server: the
// web ports (including the ones a CDN accepts), mail and chat ports that are
// often left open, and the ports of well-known VPN and voice protocols.
var DefaultExplorePorts = []int{
	443, 8443, 2053, 2083, 2087, 2096, 2052, 2082, 2086, 2095,
	80, 8080, 8880, 53, 123, 500, 4500, 1194, 51820, 3478,
	5228, 993, 995, 587, 465, 853, 5222, 9001,
}

const exploreHello = "PBX?"

// ExplorePortInfo is how the responder fared on one port.
type ExplorePortInfo struct {
	Port int    `json:"port"`
	TCP  string `json:"tcp"` // "listening", "busy" (something else uses it) or "failed"
	UDP  string `json:"udp"`
}

// ExploreResponder answers the scan's probes on a set of ports for a short time.
// A TCP connection that starts like a TLS handshake gets a TLS answer (with a
// throwaway certificate, whatever name it asks for), so names can be tested on
// the same ports; anything else gets the token back. A UDP packet that starts
// with the hello gets the token back.
//
// A port something else already uses is never touched: it is reported busy, and
// the scan then only checks that a connection opens.
type ExploreResponder struct {
	token string
	cert  tls.Certificate

	mu     sync.Mutex
	tcp    []net.Listener
	udp    []net.PacketConn
	closed bool
	timer  *time.Timer
}

// StartExploreResponder opens the ports and closes them again after ttl.
func StartExploreResponder(ports []int, token string, ttl time.Duration) (*ExploreResponder, []ExplorePortInfo, error) {
	cert, err := makeEphemeralCert("www.example.com")
	if err != nil {
		return nil, nil, err
	}
	r := &ExploreResponder{token: token, cert: cert}
	seen := map[int]bool{}
	var infos []ExplorePortInfo
	for _, p := range ports {
		if p < 1 || p > 65535 || p == 22 || seen[p] {
			continue
		}
		seen[p] = true
		if len(infos) >= 64 {
			break
		}
		info := ExplorePortInfo{Port: p, TCP: "failed", UDP: "failed"}
		addr := ":" + strconv.Itoa(p)
		if ln, err := net.Listen("tcp", addr); err == nil {
			r.tcp = append(r.tcp, ln)
			go r.serveTCP(ln)
			info.TCP = "listening"
		} else if isAddrInUse(err) {
			info.TCP = "busy"
		}
		if pc, err := net.ListenPacket("udp", addr); err == nil {
			r.udp = append(r.udp, pc)
			go r.serveUDP(pc)
			info.UDP = "listening"
		} else if isAddrInUse(err) {
			info.UDP = "busy"
		}
		infos = append(infos, info)
	}
	if ttl > 0 {
		r.timer = time.AfterFunc(ttl, r.Close)
	}
	return r, infos, nil
}

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// Linux says "address already in use"; Windows words it differently.
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address")
}

// Close stops answering and frees the ports.
func (r *ExploreResponder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.timer != nil {
		r.timer.Stop()
	}
	for _, l := range r.tcp {
		_ = l.Close()
	}
	for _, p := range r.udp {
		_ = p.Close()
	}
}

func (r *ExploreResponder) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errorsIsClosed(err) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go r.handleTCP(c)
	}
}

func errorsIsClosed(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "use of closed"))
}

// exploreBufConn gives back the bytes already looked at.
type exploreBufConn struct {
	net.Conn
	br *bufio.Reader
}

func (p *exploreBufConn) Read(b []byte) (int, error) { return p.br.Read(b) }

func (r *ExploreResponder) handleTCP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x16 { // the start of a TLS handshake
		tc := tls.Server(&exploreBufConn{Conn: c, br: br}, &tls.Config{
			Certificates: []tls.Certificate{r.cert},
			MinVersion:   tls.VersionTLS12,
		})
		if tc.Handshake() != nil {
			return
		}
		_, _ = tc.Write([]byte(r.token))
		_ = tc.Close()
		return
	}
	buf := make([]byte, 64)
	n, _ := br.Read(buf)
	if n > 0 && strings.HasPrefix(string(buf[:n]), "PBX") {
		_, _ = c.Write([]byte(r.token))
	}
}

func (r *ExploreResponder) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 256)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errorsIsClosed(err) {
				return
			}
			continue
		}
		if n >= 3 && string(buf[:3]) == "PBX" {
			_, _ = pc.WriteTo([]byte(r.token), from)
		}
	}
}

// ---------------------------------------------------------------------------
// The checks from the relay
// ---------------------------------------------------------------------------

// ExplorePortSpec is one port to check and what the responder did with it.
type ExplorePortSpec struct {
	Port int    `json:"port"`
	TCP  string `json:"tcp"`
	UDP  string `json:"udp"`
}

// ExplorePortResult says what got across on one port. For TCP: "data" (the
// answer came back), "stalled" (the connection opened but no answer came, which
// is how a filter that cuts a connection after it starts looks), "open" (it
// opened, and nothing more could be tested because something else uses the
// port), "closed" (the server answered that nothing listens there, so the route
// is open), "blocked" (no answer at all) or "untested". For UDP: "data",
// "blocked" or "untested".
type ExplorePortResult struct {
	Port  int    `json:"port"`
	TCP   string `json:"tcp"`
	UDP   string `json:"udp"`
	TCPMS int64  `json:"tcp_ms,omitempty"`
}

// ExplorePorts checks each port, TCP and UDP, against the responder at host.
func ExplorePorts(ctx context.Context, host string, specs []ExplorePortSpec, token string) []ExplorePortResult {
	results := make([]ExplorePortResult, len(specs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for i, s := range specs {
		wg.Add(1)
		go func(i int, s ExplorePortSpec) {
			defer wg.Done()
			res := ExplorePortResult{Port: s.Port, TCP: "untested", UDP: "untested"}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = res
				return
			}
			addr := net.JoinHostPort(host, strconv.Itoa(s.Port))
			var inner sync.WaitGroup
			inner.Add(2)
			go func() {
				defer inner.Done()
				res.TCP, res.TCPMS = exploreTCP(ctx, addr, s.TCP, token)
			}()
			go func() {
				defer inner.Done()
				res.UDP = exploreUDP(ctx, addr, s.UDP, token)
			}()
			inner.Wait()
			results[i] = res
		}(i, s)
	}
	wg.Wait()
	return results
}

func exploreTCP(ctx context.Context, addr, responder, token string) (string, int64) {
	return exploreTCPNet(ctx, "tcp4", addr, responder, token)
}

func exploreTCPNet(ctx context.Context, network, addr, responder, token string) (string, int64) {
	if responder == "failed" {
		return "untested", 0
	}
	start := time.Now()
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		// A refusal means the packet got there and the server answered that
		// nothing listens: the route is open, the port just is not used. That is
		// not the same as a connection that never gets an answer.
		if strings.Contains(strings.ToLower(err.Error()), "refused") {
			return "closed", 0
		}
		return "blocked", 0
	}
	defer c.Close()
	ms := max(time.Since(start).Milliseconds(), 1)
	if responder != "listening" {
		return "open", ms
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(exploreHello)); err != nil {
		return "stalled", ms
	}
	buf := make([]byte, len(token))
	if _, err := readFull(c, buf); err != nil || string(buf) != token {
		return "stalled", ms
	}
	return "data", ms
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func exploreUDP(ctx context.Context, addr, responder, token string) string {
	return exploreUDPNet(ctx, "udp4", addr, responder, token)
}

func exploreUDPNet(ctx context.Context, network, addr, responder, token string) string {
	if responder != "listening" {
		return "untested"
	}
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return "blocked"
	}
	c, err := net.DialUDP(network, nil, ua)
	if err != nil {
		return "blocked"
	}
	defer c.Close()
	deadline := time.Now().Add(2200 * time.Millisecond)
	_ = c.SetReadDeadline(deadline)
	// A packet or two can simply be lost; three tries, spread out.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for i := 0; i < 3; i++ {
			_, _ = c.Write([]byte(exploreHello))
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-time.After(600 * time.Millisecond):
			}
		}
	}()
	buf := make([]byte, 64)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return "blocked"
		}
		if string(buf[:n]) == token {
			return "data"
		}
	}
}

// ExploreIPv6 checks whether TCP and UDP reach the responder over IPv6 on a
// port where the responder is listening.
func ExploreIPv6(ctx context.Context, hostV6 string, specs []ExplorePortSpec, token string) (port int, tcpState string, udpState string, ms int64) {
	hostV6 = strings.TrimSpace(hostV6)
	if hostV6 == "" {
		return 0, "", "", 0
	}
	spec, ok := pickIPv6Spec(specs)
	if !ok {
		return 0, "", "", 0
	}
	addr := net.JoinHostPort(hostV6, strconv.Itoa(spec.Port))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tcpState, ms = exploreTCPNet(ctx, "tcp6", addr, spec.TCP, token)
	}()
	go func() {
		defer wg.Done()
		udpState = exploreUDPNet(ctx, "udp6", addr, spec.UDP, token)
	}()
	wg.Wait()
	return spec.Port, tcpState, udpState, ms
}

func pickIPv6Spec(specs []ExplorePortSpec) (ExplorePortSpec, bool) {
	byPort := map[int]ExplorePortSpec{}
	for _, s := range specs {
		if s.TCP == "listening" || s.UDP == "listening" {
			byPort[s.Port] = s
		}
	}
	for _, p := range namesPortOrder {
		if s, ok := byPort[p]; ok && s.TCP == "listening" {
			return s, true
		}
	}
	for _, s := range specs {
		if s.TCP == "listening" {
			return s, true
		}
	}
	for _, s := range specs {
		if s.UDP == "listening" {
			return s, true
		}
	}
	return ExplorePortSpec{}, false
}

// ExploreICMP sends a few pings to host. It needs the right to open a raw
// socket, which the agent has; without it the result is "untested".
func ExploreICMP(ctx context.Context, host string) (state string, ms int64) {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return "untested", 0
	}
	pc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return "untested", 0
	}
	defer pc.Close()
	id := int(time.Now().UnixNano() & 0xffff)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	go func() {
		for seq := 1; seq <= 3; seq++ {
			msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("portbridge-explore")}}
			b, err := msg.Marshal(nil)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b, &net.IPAddr{IP: ip})
			select {
			case <-ctx.Done():
				return
			case <-time.After(700 * time.Millisecond):
			}
		}
	}()
	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return "blocked", 0
		}
		if pa, ok := peer.(*net.IPAddr); !ok || !pa.IP.Equal(ip) {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id {
			return "data", max(time.Since(start).Milliseconds(), 1)
		}
	}
}

// ---------------------------------------------------------------------------
// The whole run on the relay
// ---------------------------------------------------------------------------

// ExploreRequest is what the relay is asked to do.
type ExploreRequest struct {
	Host   string            `json:"host"`              // the foreign server's IPv4 address
	HostV6 string            `json:"host_v6,omitempty"` // the foreign server's IPv6 address, when both servers have IPv6
	Token  string            `json:"token"`
	Ports  []ExplorePortSpec `json:"ports"`
	SNIs   []string          `json:"snis,omitempty"` // empty means the built-in list
	Reach  bool              `json:"reach"`          // also try the public endpoints
}

// ExploreRunReport is everything the relay found.
type ExploreRunReport struct {
	Reach     []ExploreReachResult `json:"reach,omitempty"`
	Ports     []ExplorePortResult  `json:"ports"`
	ICMP      string               `json:"icmp"`
	ICMPMS    int64                `json:"icmp_ms,omitempty"`
	IPv6Port  int                  `json:"ipv6_port,omitempty"`
	IPv6TCP   string               `json:"ipv6_tcp,omitempty"`
	IPv6UDP   string               `json:"ipv6_udp,omitempty"`
	IPv6MS    int64                `json:"ipv6_ms,omitempty"`
	NamesPort int                  `json:"names_port,omitempty"`
	Names     []SNIScanResult      `json:"names,omitempty"`
}

// namesPortOrder is the order in which a port that works is picked to test names
// on: a port that is normally web traffic first.
var namesPortOrder = []int{443, 8443, 2053, 2083, 2087, 2096, 2052, 2082, 2086, 2095, 8080, 80, 8880}

// pickNamesPort chooses the port to test names on, or 0 if no TCP port got data
// across.
func pickNamesPort(res []ExplorePortResult) int {
	ok := map[int]bool{}
	for _, r := range res {
		if r.TCP == "data" {
			ok[r.Port] = true
		}
	}
	for _, p := range namesPortOrder {
		if ok[p] {
			return p
		}
	}
	var rest []int
	for p := range ok {
		rest = append(rest, p)
	}
	sort.Ints(rest)
	if len(rest) > 0 {
		return rest[0]
	}
	return 0
}

// RunExplore does the checks.
func RunExplore(ctx context.Context, req ExploreRequest) ExploreRunReport {
	var rep ExploreRunReport
	var wg sync.WaitGroup
	if req.Reach {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.Reach = ExploreReach(ctx, ExploreEndpoints)
		}()
	}
	if req.Host != "" {
		wg.Add(2)
		go func() {
			defer wg.Done()
			rep.Ports = ExplorePorts(ctx, req.Host, req.Ports, req.Token)
		}()
		go func() {
			defer wg.Done()
			rep.ICMP, rep.ICMPMS = ExploreICMP(ctx, req.Host)
		}()
	} else {
		rep.ICMP = "untested"
	}
	if req.HostV6 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.IPv6Port, rep.IPv6TCP, rep.IPv6UDP, rep.IPv6MS = ExploreIPv6(ctx, req.HostV6, req.Ports, req.Token)
		}()
	}
	wg.Wait()
	sort.Slice(rep.Ports, func(i, j int) bool { return rep.Ports[i].Port < rep.Ports[j].Port })

	if port := pickNamesPort(rep.Ports); port != 0 {
		rep.NamesPort = port
		rep.Names = ScanWhitelistedSNIs(ctx, net.JoinHostPort(req.Host, strconv.Itoa(port)), req.SNIs)
	} else if rep.IPv6TCP == "data" && rep.IPv6Port != 0 && req.HostV6 != "" {
		rep.NamesPort = rep.IPv6Port
		rep.Names = ScanWhitelistedSNIs(ctx, net.JoinHostPort(req.HostV6, strconv.Itoa(rep.IPv6Port)), req.SNIs)
	}
	return rep
}
