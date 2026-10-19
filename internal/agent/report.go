package agent

// What the tunnels on this server look like, for the panel.
//
// Everything a person would want to see about a tunnel, and nothing secret: the
// password is never sent, only a short fingerprint of it (PairID) so the panel can
// tell which two halves on two servers belong to the same tunnel.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

// TunnelLive is the live part of a running tunnel's status file.
type TunnelLive struct {
	UptimeSeconds  int64  `json:"uptime_seconds"`
	ActiveSessions int64  `json:"active_sessions"`
	ActiveUsers    int    `json:"active_users"`
	ParkedSpares   int64  `json:"parked_spares"`
	PoolTarget     int    `json:"pool_target"`
	Links          int    `json:"links"`
	LinkTarget     int    `json:"link_target"`
	PathState      string `json:"path_state"`
	PathNote       string `json:"path_note"`
	RouteInUse     string `json:"route_in_use"`
	OnBackupRoute  bool   `json:"on_backup_route"`
	UpdatedAt      string `json:"updated_at"`
}

// TunnelInfo is one half of a tunnel, as this server has it.
type TunnelInfo struct {
	Name                  string      `json:"name"`
	Role                  string      `json:"role"`
	Mode                  string      `json:"mode"`
	Transport             string      `json:"transport"`
	Link                  string      `json:"link"`
	LinkPort              int         `json:"link_port"`
	PeerIP                string      `json:"peer_ip"`
	LocalIP               string      `json:"local_ip"`
	UserPorts             []int       `json:"user_ports,omitempty"`
	ServicePorts          []int       `json:"service_ports,omitempty"`
	Mux                   bool        `json:"mux"`
	MuxLinks              int         `json:"mux_links,omitempty"`
	PoolSize              int         `json:"pool_size,omitempty"`
	MaxConn               int         `json:"max_conn,omitempty"`
	SpareTTL              string      `json:"spare_ttl,omitempty"`
	Drain                 string      `json:"drain,omitempty"`
	Firewall              bool        `json:"firewall"`
	CDN                   bool        `json:"cdn"`
	ServerName            string      `json:"server_name,omitempty"`
	AltHost               string      `json:"alt_host,omitempty"`
	GRE                   bool        `json:"gre"`
	SIT                   bool        `json:"sit"`
	RealSite              bool        `json:"real_site"`
	SNISpoof              bool        `json:"sni_spoof"`
	SpoofSNI              string      `json:"spoof_sni,omitempty"`
	IPSpoof               bool        `json:"ip_spoof"`
	SpoofIP               string      `json:"spoof_ip,omitempty"`
	AntiFreeze            bool        `json:"anti_freeze"`
	ProxyProtocol         string      `json:"proxy_protocol"`
	WebsiteBridge         bool        `json:"website_bridge,omitempty"`
	WebsiteDomains        string      `json:"website_domains,omitempty"`
	OutboundProxy         bool        `json:"outbound_proxy,omitempty"`
	OutboundProxyPort     int         `json:"outbound_proxy_port,omitempty"`
	OutboundProxyMode     string      `json:"outbound_proxy_mode,omitempty"`
	OutboundIranDomains   string      `json:"outbound_iran_domains,omitempty"`
	OutboundBypassDomains string      `json:"outbound_bypass_domains,omitempty"`
	PairID                string      `json:"pair_id,omitempty"`
	Running               bool        `json:"running"`
	ServiceNote           string      `json:"service_note,omitempty"`
	Live                  *TunnelLive `json:"live,omitempty"`
	Problem               string      `json:"problem,omitempty"`
}

// Overview is everything the panel shows about one server.
type Overview struct {
	OK                bool         `json:"ok"`
	Version           string       `json:"version"`
	Hostname          string       `json:"hostname"`
	Arch              string       `json:"arch"`
	IPv4              []string     `json:"ipv4"`
	IPv6              []string     `json:"ipv6"`
	BBRActive         bool         `json:"bbr_active"`
	TunedByPB         bool         `json:"tuned_by_pb"`
	CongestionControl string       `json:"congestion_control,omitempty"`
	Tunnels           []TunnelInfo `json:"tunnels"`
}

// statusStaleAfter is how old a status file may be before the tunnel is taken to
// have stopped without cleaning up after itself. It is rewritten every 2 seconds.
const statusStaleAfter = 30 * time.Second

// PairID is a short fingerprint of a tunnel's password: the same on both of its
// halves and different for every other tunnel, but useless for finding the
// password itself.
func PairID(secret string) string {
	sum := sha256.Sum256([]byte("portbridge pair id\x00" + strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:6])
}

// portsOf turns "0.0.0.0:443, 127.0.0.1:8443" or "443, 8443" into port numbers.
func portsOf(items []string) []int {
	var out []int
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		p := it
		if _, port, err := net.SplitHostPort(it); err == nil {
			p = port
		}
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// tunnelInfo describes one settings file.
func tunnelInfo(path string, host agentHost) TunnelInfo {
	name := strings.TrimSuffix(filepath.Base(path), ".conf")
	ti := TunnelInfo{Name: name}
	cfg, err := engine.LoadConfig(path)
	if err != nil {
		ti.Problem = err.Error()
		return ti
	}
	verr := cfg.Validate()
	ti.Name = cfg.Name
	ti.Role = string(cfg.Role)
	ti.Mode = string(cfg.Mode)
	ti.Transport = string(cfg.Transport)
	ti.PeerIP = cfg.PeerIP
	ti.LocalIP = cfg.LocalIP
	ti.Mux = cfg.Mux
	ti.CDN = cfg.CDN
	ti.ServerName = cfg.ServerName
	ti.AltHost = cfg.AltServerName
	ti.GRE = cfg.GRE
	ti.SIT = cfg.SIT
	ti.RealSite = cfg.RealSite
	ti.SNISpoof = cfg.SNISpoof
	ti.SpoofSNI = cfg.SpoofSNI
	ti.IPSpoof = cfg.IPSpoof
	ti.SpoofIP = cfg.SpoofIP
	ti.AntiFreeze = cfg.AntiFreeze
	ti.WebsiteBridge = cfg.WebsiteBridge
	ti.WebsiteDomains = cfg.WebsiteDomains
	ti.OutboundProxy = cfg.OutboundProxy
	if cfg.OutboundProxy {
		ti.OutboundProxyPort = cfg.OutboundProxyPort
		ti.OutboundProxyMode = cfg.OutboundProxyMode
		ti.OutboundIranDomains = cfg.OutboundIranDomains
		ti.OutboundBypassDomains = cfg.OutboundBypassDomains
	}
	ti.MaxConn = cfg.MaxConn
	if cfg.SpareTTL > 0 {
		ti.SpareTTL = cfg.SpareTTL.String()
	}
	if cfg.Drain > 0 {
		ti.Drain = cfg.Drain.String()
	}
	ti.Firewall = cfg.Firewall != "off"
	ti.ProxyProtocol = "off"
	if cfg.ProxyProtocol != 0 {
		ti.ProxyProtocol = "v" + strconv.Itoa(cfg.ProxyProtocol)
	}
	ti.PoolSize = cfg.PoolSize
	if cfg.Mux {
		ti.MuxLinks = cfg.MuxLinks
	}
	if _, port, err := net.SplitHostPort(cfg.TunnelAddr); err == nil {
		ti.LinkPort, _ = strconv.Atoi(port)
	}
	if cfg.Role == engine.RoleEdge {
		ti.UserPorts = portsOf(cfg.UserListens)
		if len(ti.UserPorts) == 0 {
			ti.UserPorts = portsOf(strings.Split(cfg.UserListen, ","))
		}
		ti.ServicePorts = portsOf(strings.Split(cfg.ServerInboundPort, ","))
	} else {
		ti.ServicePorts = portsOf(cfg.InboundAddrs)
		if len(ti.ServicePorts) == 0 {
			ti.ServicePorts = portsOf(strings.Split(cfg.InboundAddr, ","))
		}
	}
	if verr == nil {
		ti.Link = engine.DescribeLink(cfg)
	} else {
		ti.Problem = verr.Error()
	}
	if b, err := os.ReadFile(cfg.SecretFile); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		ti.PairID = PairID(string(b))
	}

	ti.Running, ti.ServiceNote = host.Active(name)
	if b, err := os.ReadFile(cfg.StatusFile); err == nil {
		var live TunnelLive
		if json.Unmarshal(b, &live) == nil {
			if t, err := time.Parse(time.RFC3339, live.UpdatedAt); err == nil && time.Since(t) < statusStaleAfter {
				ti.Live = &live
			}
		}
	}
	return ti
}

// TunnelsReport describes every tunnel in a settings directory, sorted by name.
func TunnelsReport(confDir string) []TunnelInfo {
	host := hostFor(confDir)
	paths, _ := filepath.Glob(filepath.Join(confDir, "*.conf"))
	sort.Strings(paths)
	out := make([]TunnelInfo, 0, len(paths))
	for _, p := range paths {
		out = append(out, tunnelInfo(p, host))
	}
	return out
}

// LocalOverview is this server's overview, as the agent would report it.
func LocalOverview(confDir string) Overview {
	v4, v6 := localPublicAddresses()
	host, _ := os.Hostname()
	tune := readTuneStatus(confDir)
	return Overview{
		OK:                true,
		Version:           engine.Version,
		Hostname:          host,
		Arch:              runtime.GOARCH,
		IPv4:              v4,
		IPv6:              v6,
		BBRActive:         tune.BBRActive,
		TunedByPB:         tune.TunedByPB,
		CongestionControl: tune.CongestionControl,
		Tunnels:           TunnelsReport(confDir),
	}
}
