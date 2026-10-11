package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// buildOriginConf writes the settings of the foreign half of a tunnel from what a
// pairing code says. Used both to make a tunnel and to change one, so the two can
// never produce different files for the same code.
func buildOriginConf(p *PairingData, secretFile, certFile, keyFile string) string {
	// Format inbound ports (e.g. 100 -> 127.0.0.1:100, 100, 200 -> 127.0.0.1:100, 127.0.0.1:200)
	inboundParts := strings.Split(p.InboundPort, ",")
	var inbounds []string
	for _, ip := range inboundParts {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			inbounds = append(inbounds, "127.0.0.1:"+ip)
		}
	}
	inboundAddr := strings.Join(inbounds, ", ")
	if inboundAddr == "" {
		inboundAddr = "127.0.0.1:100"
	}

	var tunnelAddr string
	if p.Mode == "direct" {
		tunnelAddr = "0.0.0.0:" + p.TunnelPort
		// When the Iran server connects over IPv6 (its address in the code is an
		// IPv6 one), this side has to listen on IPv6. "[::]" takes both families.
		if ip := net.ParseIP(p.RelayIP); ip != nil && ip.To4() == nil {
			tunnelAddr = "[::]:" + p.TunnelPort
		}
	} else {
		tunnelAddr = net.JoinHostPort(p.RelayIP, p.TunnelPort)
	}
	peerIP := p.RelayIP

	firewall := "on"
	if p.CDN == "on" || p.AltHost != "" || p.Mode == "reverse" {
		firewall = "off"
	}

	// Over a private GRE link the two servers talk to each other's private
	// address, not the public one: this side listens on its own (direct mode) or
	// calls the Iran server's (reverse mode). The port is only reachable through
	// the link, so there is nothing for the firewall rule to guard.
	greOn := p.GRE == "on"
	if greOn {
		own, peer, err := greAddrs(p.ServerIP, p.RelayIP)
		if err == nil {
			if p.Mode == "direct" {
				tunnelAddr = net.JoinHostPort(own, p.TunnelPort)
			} else {
				tunnelAddr = net.JoinHostPort(peer, p.TunnelPort)
			}
			peerIP = peer
			firewall = "off"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# PortBridge tunnel %q, deployed by management agent\n", p.Name)
	fmt.Fprintf(&b, "name = %s\n", p.Name)
	fmt.Fprintf(&b, "mode = %s\n", p.Mode)
	fmt.Fprintf(&b, "role = origin\n")
	fmt.Fprintf(&b, "tunnel_addr = %s\n", tunnelAddr)
	fmt.Fprintf(&b, "inbound_addr = %s\n", inboundAddr)
	fmt.Fprintf(&b, "peer_ip = %s\n", peerIP)
	fmt.Fprintf(&b, "firewall = %s\n", firewall)
	if p.ServerIP != "" {
		fmt.Fprintf(&b, "local_ip = %s\n", p.ServerIP)
	}
	if greOn {
		fmt.Fprintf(&b, "\n# Carried over a private GRE link between the two servers.\n")
		fmt.Fprintf(&b, "gre = on\n")
		fmt.Fprintf(&b, "gre_local = %s\n", p.ServerIP)
		fmt.Fprintf(&b, "gre_remote = %s\n", p.RelayIP)
	}
	fmt.Fprintf(&b, "\ntransport = %s\n", p.Transport)
	if p.Transport == "plain" && p.HTTPHeader == "on" {
		fmt.Fprintf(&b, "http_header = on\n")
		if p.HTTPHost != "" {
			fmt.Fprintf(&b, "http_host = %s\n", p.HTTPHost)
		}
	}
	if p.Transport != "plain" && p.Transport != "kcp" {
		if p.ServerName != "" {
			fmt.Fprintf(&b, "server_name = %s\n", p.ServerName)
		}
		if p.WSPath != "" {
			fmt.Fprintf(&b, "ws_path = %s\n", p.WSPath)
		}
		fmt.Fprintf(&b, "cdn = %s\n", p.CDN)
		fmt.Fprintf(&b, "cert_file = %s\n", certFile)
		fmt.Fprintf(&b, "key_file = %s\n", keyFile)
		// Only the side that dials uses these, but they are harmless on the
		// other and keep a code made for a CDN tunnel whole.
		if p.UTLS != "" {
			fmt.Fprintf(&b, "utls = %s\n", p.UTLS)
		}
		if p.TLSFragment != "" {
			fmt.Fprintf(&b, "tls_fragment = %s\n", p.TLSFragment)
		}
		if p.ECH != "" {
			fmt.Fprintf(&b, "ech = %s\n", p.ECH)
		}
		if p.CleanIPs != "" && p.Mode == "reverse" {
			fmt.Fprintf(&b, "clean_ips = %s\n", p.CleanIPs)
		}
		if p.RealSite == "on" {
			fmt.Fprintf(&b, "real_site = on\n")
			if p.CoverSite != "" {
				fmt.Fprintf(&b, "cover_site = %s\n", p.CoverSite)
			}
		}
	}
	if p.AltHost != "" && p.Mode == "reverse" {
		fmt.Fprintf(&b, "alt_target = %s\n", net.JoinHostPort(p.AltHost, p.TunnelPort))
		fmt.Fprintf(&b, "alt_server_name = %s\n", p.AltHost)
	}
	fmt.Fprintf(&b, "\nmux = %s\n", p.Mux)
	if p.Mux == "on" {
		fmt.Fprintf(&b, "mux_links = %s\n", p.MuxLinks)
	}
	fmt.Fprintf(&b, "\npool_size = %s\n", p.Pool)
	fmt.Fprintf(&b, "max_conn = 2000\nmax_pending = 512\nspare_ttl = 10m\npark_timeout = 15m\ndrain = 5s\n")
	fmt.Fprintf(&b, "\nsecret_file = %s\n", secretFile)

	return b.String()
}

// ---------------------------------------------------------------------------
// Checking the ports a code asks for
// ---------------------------------------------------------------------------

// portsIn pulls the port numbers out of a setting that may list several
// addresses, such as "0.0.0.0:443, 0.0.0.0:8443" or "443".
func portsIn(list string) []int {
	var out []int
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if i := strings.LastIndex(item, ":"); i >= 0 {
			item = item[i+1:]
		}
		if n, ok := portOK(item); ok {
			out = append(out, n)
		}
	}
	return out
}

// claimedPort is a port another tunnel on this server already uses.
type claimedPort struct {
	port   int
	tunnel string
	what   string
}

// portsClaimedByOthers lists the ports the other tunnels on this server use for
// their link or for their users, so a new one cannot be given the same.
func portsClaimedByOthers(confDir, except string) []claimedPort {
	entries, _ := os.ReadDir(confDir)
	var out []claimedPort
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		if name == e.Name() || name == except {
			continue
		}
		cfg, err := LoadConfig(filepath.Join(confDir, e.Name()))
		if err != nil {
			continue
		}
		listensForLink := (cfg.Role == RoleOrigin && cfg.Mode == ModeDirect) ||
			(cfg.Role == RoleEdge && cfg.Mode == ModeReverse)
		if listensForLink {
			for _, p := range portsIn(cfg.TunnelAddr) {
				out = append(out, claimedPort{p, name, "the link between its servers"})
			}
		}
		if cfg.Role == RoleEdge {
			for _, p := range portsIn(cfg.UserListen) {
				out = append(out, claimedPort{p, name, "its users"})
			}
		}
	}
	return out
}

// checkPairingPorts decides whether this server can give a tunnel the ports its
// code asks for: the port the two servers use between themselves, and the ports
// of the service being published. Everything that is wrong is reported together,
// in words that say what to change. Things that are only worth knowing come back
// as notes.
//
// For a tunnel that already exists, its own current port is not counted against
// it, since the service holding it is this very tunnel.
func checkPairingPorts(p *PairingData, confDir string, host agentHost, _ string) ([]string, error) {
	var problems, notes []string

	tport, _ := portOK(p.TunnelPort)
	var inbound []int
	for _, s := range strings.Split(p.InboundPort, ",") {
		if n, ok := portOK(s); ok {
			inbound = append(inbound, n)
		}
	}
	if len(inbound) == 0 {
		inbound = []int{100}
	}

	// What this tunnel uses now, if it is being changed.
	currentLink := 0
	if cfg, err := LoadConfig(filepath.Join(confDir, p.Name+".conf")); err == nil {
		if ps := portsIn(cfg.TunnelAddr); len(ps) > 0 {
			currentLink = ps[0]
		}
	}

	others := portsClaimedByOthers(confDir, p.Name)

	if p.Mode == "direct" {
		for _, c := range others {
			if c.port == tport {
				problems = append(problems, fmt.Sprintf(
					"the port between the servers, %d, is already used by tunnel %q for %s on this server",
					tport, c.tunnel, c.what))
			}
		}
		if tport != currentLink {
			if err := host.PortFree(Transport(p.Transport), tport); err != nil {
				problems = append(problems, fmt.Sprintf(
					"the port between the servers, %d, is busy on this server: something else is using it", tport))
			}
		}
		for _, in := range inbound {
			if in == tport {
				problems = append(problems, fmt.Sprintf(
					"the service port and the port between the servers are both %d; they must be different", in))
			}
		}
	}

	for _, in := range inbound {
		for _, c := range others {
			if c.port == in {
				problems = append(problems, fmt.Sprintf(
					"the service port %d is used by tunnel %q for %s on this server, so it cannot also be your service",
					in, c.tunnel, c.what))
			}
		}
		if !host.Listening(in) {
			notes = append(notes, fmt.Sprintf(
				"nothing is answering on service port %d on this server yet; make sure the service (Xray) is running there", in))
		}
	}

	if len(problems) > 0 {
		return notes, fmt.Errorf("this server cannot use those ports:\n  - %s\nChange them and try again",
			strings.Join(problems, "\n  - "))
	}
	return notes, nil
}

// ---------------------------------------------------------------------------
// Changing a tunnel that already exists
// ---------------------------------------------------------------------------

// updatePairingData changes the ports and settings of a tunnel this server
// already has, from a fresh pairing code for it. It is all or nothing: the ports
// are checked first, and if the changed tunnel will not start, the old settings
// are put back and the tunnel is started on them again.
//
// The password in the code must be the tunnel's own. A code can name any tunnel,
// so without that check anyone holding the agent's token could rewrite a tunnel
// they know only the name of.
func updatePairingData(p *PairingData, confDir string, warns *[]string) error {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	if err := validatePairing(p); err != nil {
		return err
	}

	agentOpMu.Lock()
	defer agentOpMu.Unlock()

	host := hostFor(confDir)
	confFile := filepath.Join(confDir, p.Name+".conf")
	secretFile := filepath.Join(confDir, p.Name+".secret")
	certFile := filepath.Join(confDir, p.Name+".crt")
	keyFile := filepath.Join(confDir, p.Name+".key")

	oldConf, err := os.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("there is no tunnel named %q on this server to change", p.Name)
	}
	oldSecret, err := os.ReadFile(secretFile)
	if err != nil {
		return fmt.Errorf("the tunnel %q has no password file here", p.Name)
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(oldSecret))), []byte(p.Secret)) != 1 {
		return fmt.Errorf("the password in that code is not the one tunnel %q uses, so it was not changed", p.Name)
	}

	notes, err := checkPairingPorts(p, confDir, host, p.Name)
	if err != nil {
		return err
	}
	if warns != nil {
		*warns = append(*warns, notes...)
	}

	restore := func() {
		_ = writeFileAtomic(confFile, oldConf, 0o600)
		_ = host.FirewallApply(p.Name)
		_ = host.Restart(p.Name)
	}

	if err := writeFileAtomic(confFile, []byte(buildOriginConf(p, secretFile, certFile, keyFile)), 0o600); err != nil {
		_ = writeFileAtomic(confFile, oldConf, 0o600)
		return fmt.Errorf("writing config: %w", err)
	}
	cfg, err := LoadConfig(confFile)
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		err = cfg.LoadSecret()
	}
	if err != nil {
		_ = writeFileAtomic(confFile, oldConf, 0o600)
		return fmt.Errorf("validating config: %w", err)
	}

	// The firewall rule follows the port, then the service starts on it.
	if err := host.FirewallApply(p.Name); err != nil {
		if cfg.GRE {
			restore()
			return fmt.Errorf("this server could not make the private GRE link, so the old settings were put back: %w", err)
		}
		log.Printf("[%s] warning: %v", p.Name, err)
	}
	if err := host.Restart(p.Name); err != nil {
		if errors.Is(err, errNoSystemd) {
			log.Printf("[%s] %v", p.Name, err)
			return nil
		}
		restore()
		return fmt.Errorf("restarting on the new settings failed, the old ones were put back: %w", err)
	}
	if err := confirmRunning(host, p.Name); err != nil {
		restore()
		return fmt.Errorf("%w; the old settings were put back", err)
	}
	return nil
}
