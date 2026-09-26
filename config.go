package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
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
	Mode Mode
	Role Role

	// TunnelAddr is the cross-border endpoint. On whichever side dials it is the
	// address to dial; on the side that accepts it is the address to bind.
	TunnelAddr string

	// UserListen is where end users connect. Edge only.
	UserListen string

	// InboundAddr is the local service being published. Origin only.
	InboundAddr string

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

	// CertFile and KeyFile hold the certificate the accepting side presents. They
	// are created automatically if missing.
	CertFile string
	KeyFile  string

	secret []byte
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
	return cfg, nil
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
	case "server_inbound_port":
		// Recorded on the relay by the menu, purely so it can rebuild the code
		// for the server later. The engine does not use it.
		if _, err := strconv.Atoi(val); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
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
	case "drain":
		return dur(&c.Drain)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

// Validate catches the mistakes that would otherwise show up as a tunnel that
// silently does nothing.
func (c *Config) Validate() error {
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
		if _, _, err := net.SplitHostPort(c.UserListen); err != nil {
			return fmt.Errorf("user_listen must be host:port: %w", err)
		}
		if c.UserListen == c.TunnelAddr {
			return fmt.Errorf("user_listen and tunnel_addr cannot be the same address")
		}
	case RoleOrigin:
		if c.InboundAddr == "" {
			return fmt.Errorf("inbound_addr is required for the origin")
		}
		if _, _, err := net.SplitHostPort(c.InboundAddr); err != nil {
			return fmt.Errorf("inbound_addr must be host:port: %w", err)
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
		return fmt.Errorf("transport must be %q, %q or %q, got %q",
			TransportPlain, TransportTLS, TransportWSS, c.Transport)
	}
	if c.Transport != TransportPlain {
		// Only the accepting side presents a certificate, and it is created on
		// demand, so a missing path is a configuration gap rather than a
		// missing file.
		if !c.Dials() && (c.CertFile == "" || c.KeyFile == "") {
			return fmt.Errorf("cert_file and key_file are required for the %s disguise on the side that accepts", c.Transport)
		}
	}
	if c.CDN {
		// A CDN only carries a connection that arrives as a websocket over TLS.
		if c.Transport != TransportWSS {
			return fmt.Errorf("cdn needs transport %q, got %q", TransportWSS, c.Transport)
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
		fmt.Fprintf(&b, "Dialling out to %s. ", c.TunnelAddr)
	} else {
		fmt.Fprintf(&b, "Accepting tunnel connections on %s. ", c.TunnelAddr)
	}
	if c.Role == RoleEdge {
		fmt.Fprintf(&b, "Users connect to %s. ", c.UserListen)
	} else {
		fmt.Fprintf(&b, "Publishing local service %s. ", c.InboundAddr)
	}
	fmt.Fprintf(&b, "Link is %s. ", describeTransport(c))
	fmt.Fprintf(&b, "Spares %d (life %s), capacity %d, drain %s",
		c.PoolSize, c.SpareTTL, c.MaxConn, c.Drain)
	return b.String()
}
