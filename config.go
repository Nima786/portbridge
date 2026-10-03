package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Mode decides which side opens the cross-border connection.
//
//	direct  - the edge dials the origin. Simple, and works wherever the edge is
//	          allowed to make outbound connections to the origin.
//	reverse - the origin dials the edge. Needed when the edge cannot reach the
//	          origin (for example its address is blocked outbound) but the origin
//	          can still reach the edge. The origin then needs no open ports.
type Mode string

// Role decides what the process does with traffic, and never changes with mode.
//
//	edge   - faces the users, holds the pool of ready spare connections, and
//	         signals the origin when a user turns up.
//	origin - sits next to the service being published, dials it on demand and
//	         confirms once connected.
type Role string

const (
	ModeDirect  Mode = "direct"
	ModeReverse Mode = "reverse"

	RoleEdge   Role = "edge"
	RoleOrigin Role = "origin"
)

// Config is one tunnel. It is read from a plain key=value file so that both the
// menu script and this program can handle it without extra tooling.
type Config struct {
	Name string
	Path string
	Mode Mode
	Role Role

	// TunnelAddr is the cross-border endpoint. On whichever side dials it is the
	// address to dial; on the side that accepts it is the address to bind.
	TunnelAddr string

	// UserListen is where end users connect. Edge only. Can be a single address
	// or a comma-separated list of addresses/ports.
	UserListen string

	// InboundAddr is the local service being published. Origin only. Can be a
	// single address or a comma-separated list of addresses/ports.
	InboundAddr string

	// ServerInboundPort is kept on the edge for multi-port target mapping.
	ServerInboundPort string

	// ForeignAgent is the alias of the linked foreign agent, kept for management.
	ForeignAgent string

	// Parsed addresses and mappings for multi-port operation.
	UserListens   []string
	InboundAddrs  []string
	listenToPort  map[string]uint16
	portToInbound map[uint16]string
	defaultTarget uint16

	// PeerIP is the other server's address. Used to lock the tunnel port down to
	// a single source, and to warn about obvious misconfiguration.
	PeerIP string

	// LocalIP is this server's own public address. The engine does not use it;
	// it is recorded so the menu can build a pairing code for the other side
	// without needing outbound web access every time.
	LocalIP string

	// Firewall says whether the tunnel port should be locked to PeerIP. Handled
	// entirely by the firewall helper; the engine only checks it is valid.
	Firewall string

	PoolSize    int
	MaxConn     int
	MaxPending  int
	SpareTTL    time.Duration
	ParkTimeout time.Duration
	Drain       time.Duration

	SecretFile string
	StatusFile string

	// Transport is what the link between the two servers looks like on the wire.
	// See transport.go for why this is worth having.
	Transport Transport

	// ServerName is the hostname the disguise claims to be, sent in the TLS
	// handshake. With a CDN it must be a real name pointed at the CDN; otherwise
	// it can be anything plausible.
	ServerName string

	// WSPath is the web address path used by the websocket disguise.
	WSPath string

	// CDN routes the link through a content delivery network, by dialling
	// ServerName instead of the other server's address. The other server's
	// address then never appears on the link, so it cannot simply be blocked.
	CDN bool

	// AltTarget is a second address to reach the other server, tried when the
	// first cannot be reached. Only the side that dials uses it. See route.go.
	AltTarget string

	// AltServerName is the hostname to claim while using that second route.
	//
	// It is separate from ServerName on purpose. The second route is a CDN, and
	// reaching it requires naming the real domain, because that is how a CDN
	// knows whose server to forward to. The first route goes straight to the
	// other server, where naming that same domain would be a slip: the domain's
	// own records point at the CDN, not at that address, so the name and the
	// destination would not agree and the pair of them together says more than
	// either alone.
	AltServerName string

	// CertFile and KeyFile hold the certificate the accepting side presents. They
	// are created automatically if missing.
	CertFile string
	KeyFile  string

	// Mux carries every session inside a few long-lived connections instead of
	// opening one per session. See mux.go for what that buys and what it costs.
	Mux bool

	// MuxLinks is how many of those long-lived connections to keep up. More than
	// one on purpose: everything sharing a single connection means one lost
	// packet stalls every session on it.
	MuxLinks int

	// KCP Forward Error Correction shards
	KCPDataShards   int
	KCPParityShards int

	secret []byte

	// TLS stealth & evasion settings
	TLSFragment      bool
	TLSFragmentSize  int
	TLSFragmentSleep time.Duration
	UTLS             bool
	UTLSProfile      string
	CleanIPs         []string

	fragmentSet bool
	utlsSet     bool

	// Disguise settings prepared once at startup and only read afterwards. They
	// are what makes a repeat connection cheap; see prepareTLS in transport.go
	// for why building them per connection was costing more than everything else
	// put together.
	tlsServer   *tls.Config
	tlsClients  map[string]*tls.Config
	utlsClients map[string]*utls.Config
	utlsCache   utls.ClientSessionCache
}

// effectiveServerName falls back to the peer address when no name was given, so
// a plain TLS link still works without any extra setup.
func (c *Config) effectiveServerName() string {
	if c.ServerName != "" {
		return c.ServerName
	}
	if host, _, err := net.SplitHostPort(c.TunnelAddr); err == nil && host != "" &&
		host != "0.0.0.0" && host != "::" {
		return host
	}
	if c.PeerIP != "" {
		return c.PeerIP
	}
	return "localhost"
}

// dialTarget is the address the dialling side actually connects to.
//
// Normally that is simply the other server. Only when routing through a CDN does
// it become the hostname, so the name resolves to the CDN's addresses and the
// other server's address never appears on the link, which is the point.
//
// This is deliberately tied to the CDN setting rather than to the hostname.
// Wanting a hostname for the disguise and wanting traffic routed through a CDN
// are separate intentions, and quietly changing the destination because a
// hostname was given would be a nasty surprise.
func (c *Config) dialTarget() string {
	if c.CDN && c.ServerName != "" {
		_, port, err := net.SplitHostPort(c.TunnelAddr)
		if err == nil && port != "" {
			return net.JoinHostPort(c.ServerName, port)
		}
	}
	return c.TunnelAddr
}

// withClaimedName returns this configuration with a different hostname claimed
// on the wire, leaving everything else alone.
//
// Used when a second route has to name itself differently from the first. The
// side that accepts does not care which name was used: it presents its
// certificate to whoever asks and checks the shared password, not the name.
func (c *Config) withClaimedName(name string) *Config {
	if name == "" || name == c.ServerName {
		return c
	}
	alt := *c
	alt.ServerName = name
	return &alt
}

func (c *Config) effectiveWSPath() string {
	if c.WSPath != "" {
		return c.WSPath
	}
	return defaultWSPath
}

// Dials reports whether this process opens the cross-border connection.
func (c *Config) Dials() bool {
	return (c.Mode == ModeDirect && c.Role == RoleEdge) ||
		(c.Mode == ModeReverse && c.Role == RoleOrigin)
}

func defaultConfig() *Config {
	return &Config{
		PoolSize:    25,
		MaxConn:     2000,
		MaxPending:  512,
		SpareTTL:    10 * time.Minute,
		ParkTimeout: 15 * time.Minute,
		Drain:       5 * time.Second,
		// Plain stays the default so that upgrading never silently changes how
		// an existing tunnel appears on the wire, which would break it until
		// both ends were updated together.
		Transport: TransportPlain,
		// Off for the same reason, and because sharing connections costs speed
		// on a lossy route. It is a choice, not an improvement.
		Mux:              false,
		MuxLinks:         4,
		KCPDataShards:    10,
		KCPParityShards:  3,
		TLSFragment:      false,
		TLSFragmentSize:  40,
		TLSFragmentSleep: 3 * time.Millisecond,
		UTLS:             false,
		UTLSProfile:      "chrome",
	}
}

// LoadConfig reads a key=value file. Blank lines and lines starting with # are
// ignored. Unknown keys are an error, because a silently ignored setting is
// worse than a refusal to start.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := defaultConfig()
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		key, val, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: expected key=value", path, line)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)

		if err := cfg.set(key, val); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if cfg.StatusFile == "" && cfg.Name != "" {
		cfg.StatusFile = "/run/portbridge/" + cfg.Name + ".json"
	}
	cfg.Path = path
	return cfg, nil
}

// ControlSocketPath returns the path to the Unix domain socket used for local IPC.
func (c *Config) ControlSocketPath() string {
	if c.StatusFile != "" {
		return filepath.Join(filepath.Dir(c.StatusFile), c.Name+".sock")
	}
	return "/run/portbridge/" + c.Name + ".sock"
}

func (c *Config) set(key, val string) error {
	dur := func(d *time.Duration) error {
		v, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		*d = v
		return nil
	}
	num := func(n *int) error {
		v, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		*n = v
		return nil
	}

	switch key {
	case "name":
		c.Name = val
	case "mode":
		c.Mode = Mode(strings.ToLower(val))
	case "role":
		c.Role = Role(strings.ToLower(val))
	case "tunnel_addr":
		c.TunnelAddr = val
	case "user_listen":
		c.UserListen = val
	case "inbound_addr":
		c.InboundAddr = val
	case "peer_ip":
		c.PeerIP = val
	case "local_ip":
		c.LocalIP = val
	case "transport":
		c.Transport = Transport(strings.ToLower(val))
	case "server_name":
		c.ServerName = val
	case "ws_path":
		if !strings.HasPrefix(val, "/") {
			return fmt.Errorf("ws_path must start with /")
		}
		c.WSPath = val
	case "cert_file":
		c.CertFile = val
	case "key_file":
		c.KeyFile = val
	case "cdn":
		switch strings.ToLower(val) {
		case "on", "yes", "true":
			c.CDN = true
		case "off", "no", "false":
			c.CDN = false
		default:
			return fmt.Errorf("cdn must be on or off, got %q", val)
		}
	case "alt_target":
		c.AltTarget = val
	case "alt_server_name":
		c.AltServerName = val
	case "mux":
		switch strings.ToLower(val) {
		case "on", "yes", "true":
			c.Mux = true
		case "off", "no", "false":
			c.Mux = false
		default:
			return fmt.Errorf("mux must be on or off, got %q", val)
		}
	case "mux_links":
		return num(&c.MuxLinks)
	case "server_inbound_port":
		c.ServerInboundPort = val
	case "foreign_agent":
		c.ForeignAgent = val
	case "firewall":
		// Read by the firewall helper, not by the engine. Accepted here so the
		// engine does not refuse a config that contains it.
		switch strings.ToLower(val) {
		case "on", "off":
			c.Firewall = strings.ToLower(val)
		default:
			return fmt.Errorf("firewall must be on or off, got %q", val)
		}
	case "secret_file":
		c.SecretFile = val
	case "status_file":
		c.StatusFile = val
	case "pool_size":
		return num(&c.PoolSize)
	case "max_conn":
		return num(&c.MaxConn)
	case "max_pending":
		return num(&c.MaxPending)
	case "spare_ttl":
		return dur(&c.SpareTTL)
	case "park_timeout":
		return dur(&c.ParkTimeout)
	case "kcp_data_shards":
		return num(&c.KCPDataShards)
	case "kcp_parity_shards":
		return num(&c.KCPParityShards)
	case "drain":
		return dur(&c.Drain)
	case "tls_fragment", "fragment":
		c.fragmentSet = true
		switch strings.ToLower(val) {
		case "on", "yes", "true":
			c.TLSFragment = true
		case "off", "no", "false":
			c.TLSFragment = false
		default:
			return fmt.Errorf("tls_fragment must be on or off, got %q", val)
		}
	case "tls_fragment_size", "fragment_size":
		c.fragmentSet = true
		return num(&c.TLSFragmentSize)
	case "tls_fragment_sleep", "fragment_sleep":
		c.fragmentSet = true
		return dur(&c.TLSFragmentSleep)
	case "utls":
		c.utlsSet = true
		switch strings.ToLower(val) {
		case "on", "yes", "true":
			c.UTLS = true
		case "off", "no", "false":
			c.UTLS = false
		default:
			return fmt.Errorf("utls must be on or off, got %q", val)
		}
	case "utls_profile":
		c.utlsSet = true
		c.UTLSProfile = strings.ToLower(val)
	case "clean_ips", "clean_ip":
		parts := strings.Split(val, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				c.CleanIPs = append(c.CleanIPs, p)
			}
		}
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

// Validate catches the mistakes that would otherwise show up as a tunnel that
// silently does nothing.
func (c *Config) Validate() error {
	if c.CDN {
		if !c.utlsSet {
			c.UTLS = true
		}
		if !c.fragmentSet {
			c.TLSFragment = true
		}
	}
	if c.TLSFragmentSize <= 0 {
		c.TLSFragmentSize = 40
	}
	if c.TLSFragmentSleep <= 0 {
		c.TLSFragmentSleep = 3 * time.Millisecond
	}
	if c.UTLSProfile == "" {
		c.UTLSProfile = "chrome"
	}

	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	for _, r := range c.Name {
		ok := r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("name may only contain letters, digits, dash and underscore")
		}
	}

	switch c.Mode {
	case ModeDirect, ModeReverse:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeDirect, ModeReverse, c.Mode)
	}
	switch c.Role {
	case RoleEdge, RoleOrigin:
	default:
		return fmt.Errorf("role must be %q or %q, got %q", RoleEdge, RoleOrigin, c.Role)
	}

	if c.TunnelAddr == "" {
		return fmt.Errorf("tunnel_addr is required")
	}
	if _, _, err := net.SplitHostPort(c.TunnelAddr); err != nil {
		return fmt.Errorf("tunnel_addr must be host:port: %w", err)
	}
	if c.Dials() {
		host, _, _ := net.SplitHostPort(c.TunnelAddr)
		if host == "" || host == "0.0.0.0" || host == "::" {
			return fmt.Errorf("tunnel_addr must name the other server, since this side dials out in %s mode", c.Mode)
		}
	}

	switch c.Role {
	case RoleEdge:
		if c.UserListen == "" {
			return fmt.Errorf("user_listen is required for the edge")
		}
		listens, err := parseAddressList(c.UserListen, "0.0.0.0")
		if err != nil || len(listens) == 0 {
			return fmt.Errorf("user_listen: %w", err)
		}
		c.UserListens = listens
		c.listenToPort = make(map[string]uint16, len(listens))

		var sinPorts []uint16
		if c.ServerInboundPort != "" {
			for _, sp := range strings.Split(c.ServerInboundPort, ",") {
				sp = strings.TrimSpace(sp)
				if sp == "" {
					continue
				}
				p, err := strconv.Atoi(sp)
				if err != nil || p < 1 || p > 65535 {
					return fmt.Errorf("invalid server_inbound_port %q", sp)
				}
				sinPorts = append(sinPorts, uint16(p))
			}
		}

		for i, u := range listens {
			if u == c.TunnelAddr {
				return fmt.Errorf("user_listen and tunnel_addr cannot be the same address")
			}
			_, pStr, _ := net.SplitHostPort(u)
			pNum, _ := strconv.Atoi(pStr)
			tp := uint16(pNum)
			if i < len(sinPorts) {
				tp = sinPorts[i]
			}
			c.listenToPort[u] = tp
			c.listenToPort[pStr] = tp
			c.listenToPort[":"+pStr] = tp
		}
		if len(listens) > 0 {
			c.defaultTarget = c.listenToPort[listens[0]]
		}

	case RoleOrigin:
		if c.InboundAddr == "" {
			return fmt.Errorf("inbound_addr is required for the origin")
		}
		inbounds, err := parseAddressList(c.InboundAddr, "127.0.0.1")
		if err != nil || len(inbounds) == 0 {
			return fmt.Errorf("inbound_addr: %w", err)
		}
		c.InboundAddrs = inbounds
		c.portToInbound = make(map[uint16]string, len(inbounds))
		for _, in := range inbounds {
			_, pStr, _ := net.SplitHostPort(in)
			pNum, _ := strconv.Atoi(pStr)
			c.portToInbound[uint16(pNum)] = in
		}
		if len(inbounds) > 0 {
			_, pStr, _ := net.SplitHostPort(inbounds[0])
			pNum, _ := strconv.Atoi(pStr)
			c.defaultTarget = uint16(pNum)
		}
	}

	if c.PoolSize < 0 {
		return fmt.Errorf("pool_size cannot be negative")
	}
	if c.MaxConn < 1 {
		return fmt.Errorf("max_conn must be at least 1")
	}
	if c.MaxPending < 1 {
		return fmt.Errorf("max_pending must be at least 1")
	}
	if c.SpareTTL <= 0 {
		return fmt.Errorf("spare_ttl must be positive")
	}
	if c.ParkTimeout <= c.SpareTTL {
		return fmt.Errorf("park_timeout (%s) must be longer than spare_ttl (%s), or spares are cut while still in use", c.ParkTimeout, c.SpareTTL)
	}
	if c.Drain < 0 {
		return fmt.Errorf("drain cannot be negative")
	}
	if c.SecretFile == "" {
		return fmt.Errorf("secret_file is required")
	}

	if !validTransport(c.Transport) {
		return fmt.Errorf("transport must be %q, %q, %q, %q, %q or %q, got %q",
			TransportPlain, TransportTLS, TransportWSS, TransportH2, TransportGRPC, TransportKCP, c.Transport)
	}
	if c.Transport != TransportPlain && c.Transport != TransportKCP {
		// Only the accepting side presents a certificate, and it is created on
		// demand, so a missing path is a configuration gap rather than a
		// missing file.
		if !c.Dials() && (c.CertFile == "" || c.KeyFile == "") {
			return fmt.Errorf("cert_file and key_file are required for the %s disguise on the side that accepts", c.Transport)
		}
	}
	if c.AltTarget != "" {
		host, port, err := net.SplitHostPort(c.AltTarget)
		if err != nil {
			return fmt.Errorf("alt_target must be host:port: %w", err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" || port == "" {
			return fmt.Errorf("alt_target must name the other server, got %q", c.AltTarget)
		}
		if !c.Dials() {
			return fmt.Errorf("alt_target is only used by the side that dials, and this side waits to be called")
		}
	}
	if c.AltServerName != "" {
		if c.AltTarget == "" {
			return fmt.Errorf("alt_server_name means nothing without alt_target")
		}
		if ip := net.ParseIP(c.AltServerName); ip != nil {
			return fmt.Errorf("alt_server_name must be a hostname, not the address %s", c.AltServerName)
		}
	}
	if c.Mux {
		if c.MuxLinks < 1 {
			return fmt.Errorf("mux_links must be at least 1")
		}
		if c.MuxLinks > 64 {
			return fmt.Errorf("mux_links of %d is far more than any link needs", c.MuxLinks)
		}
	}
	if c.CDN {
		if c.Transport != TransportWSS && c.Transport != TransportH2 && c.Transport != TransportGRPC {
			return fmt.Errorf("cdn needs transport %q, %q or %q, got %q",
				TransportWSS, TransportH2, TransportGRPC, c.Transport)
		}
		// It also routes by hostname, so an address cannot stand in for one.
		if c.ServerName == "" {
			return fmt.Errorf("server_name is required when using a cdn: it needs a hostname pointed at the cdn")
		}
		if ip := net.ParseIP(c.ServerName); ip != nil {
			return fmt.Errorf("server_name must be a hostname when using a cdn, not the address %s", c.ServerName)
		}
	}
	return nil
}

// LoadSecret reads the shared secret. It must be a file rather than a command
// line argument, because anything on the command line is visible to every local
// user in the process list.
func (c *Config) LoadSecret() error {
	b, err := os.ReadFile(c.SecretFile)
	if err != nil {
		return fmt.Errorf("reading secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 16 {
		return fmt.Errorf("the secret in %s must be at least 16 characters and identical on both servers", c.SecretFile)
	}
	c.secret = []byte(s)
	return nil
}

// Summary is the one-line description written to the log at startup.
func (c *Config) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tunnel %q: %s mode, acting as %s. ", c.Name, c.Mode, c.Role)
	if c.Dials() {
		fmt.Fprintf(&b, "Dialling out to %s", c.TunnelAddr)
		if c.AltTarget != "" {
			fmt.Fprintf(&b, ", falling back to %s if that cannot be reached", c.AltTarget)
			if c.AltServerName != "" && c.AltServerName != c.ServerName {
				fmt.Fprintf(&b, " and claiming to be %s when it does", c.AltServerName)
			}
		}
		b.WriteString(". ")
	} else {
		fmt.Fprintf(&b, "Accepting tunnel connections on %s. ", c.TunnelAddr)
	}
	if c.Role == RoleEdge {
		if len(c.UserListens) > 1 {
			fmt.Fprintf(&b, "Users connect to %s (%d ports). ", strings.Join(c.UserListens, ", "), len(c.UserListens))
		} else {
			fmt.Fprintf(&b, "Users connect to %s. ", c.UserListen)
		}
	} else {
		if len(c.InboundAddrs) > 1 {
			fmt.Fprintf(&b, "Publishing local services on %s. ", strings.Join(c.InboundAddrs, ", "))
		} else {
			fmt.Fprintf(&b, "Publishing local service %s. ", c.InboundAddr)
		}
	}
	fmt.Fprintf(&b, "Link is %s. ", describeTransport(c))
	if c.Mux {
		fmt.Fprintf(&b, "All sessions share %d long-lived connections, capacity %d, drain %s",
			c.MuxLinks, c.MaxConn, c.Drain)
	} else {
		fmt.Fprintf(&b, "Spares %d (life %s), capacity %d, drain %s",
			c.PoolSize, c.SpareTTL, c.MaxConn, c.Drain)
	}
	return b.String()
}

func parseAddressList(raw, defaultHost string) ([]string, error) {
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item == "" {
			continue
		}
		if _, err := strconv.Atoi(item); err == nil {
			item = net.JoinHostPort(defaultHost, item)
		} else if strings.HasPrefix(item, ":") {
			item = defaultHost + item
		}
		host, port, err := net.SplitHostPort(item)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", item, err)
		}
		pNum, err := strconv.Atoi(port)
		if err != nil || pNum < 1 || pNum > 65535 {
			return nil, fmt.Errorf("invalid port in %q", item)
		}
		if host == "" {
			host = defaultHost
		}
		result = append(result, net.JoinHostPort(host, port))
	}
	return result, nil
}

// TargetPortFor returns the target port for a given listen address or port.
func (c *Config) TargetPortFor(addr string) uint16 {
	if c.listenToPort != nil {
		if p, ok := c.listenToPort[addr]; ok {
			return p
		}
		if _, pStr, err := net.SplitHostPort(addr); err == nil {
			if p, ok := c.listenToPort[pStr]; ok {
				return p
			}
			if p, ok := c.listenToPort[":"+pStr]; ok {
				return p
			}
			if n, err := strconv.Atoi(pStr); err == nil && n > 0 && n <= 65535 {
				return uint16(n)
			}
		}
	}
	return c.defaultTarget
}

// InboundFor returns the dial target for a given destination port.
func (c *Config) InboundFor(port uint16) string {
	if port > 0 && c.portToInbound != nil {
		if addr, ok := c.portToInbound[port]; ok {
			return addr
		}
	}
	if len(c.InboundAddrs) > 0 {
		return c.InboundAddrs[0]
	}
	return c.InboundAddr
}
