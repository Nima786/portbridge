package agent

// "portbridge agent setup": switch the agent on in one step, without questions.
//
// The panel runs this over SSH when it adds a server. It keeps whatever the agent
// already has (its token, port and certificate), so a server already linked to
// an Iran server's menu stays linked, and only fills in what is missing. It
// prints what the panel needs to reach the agent, as JSON.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

const (
	defaultAgentConf = "/etc/portbridge/agent.conf"
	defaultAgentCert = "/etc/portbridge/agent.crt"
	defaultAgentKey  = "/etc/portbridge/agent.key"
	agentUnit        = "portbridge-agent.service"
)

// agentPortCandidates are tried in turn when the agent has no port yet. They are
// the ports Cloudflare forwards, so the agent can later sit behind it.
var agentPortCandidates = []int{2083, 2087, 2053, 8443, 2096}

// agentConfig is everything in agent.conf.
type agentConfig struct {
	Listen           string
	Token            string
	CertFile         string
	KeyFile          string
	PanelURL         string
	PanelFingerprint string
	// AllowUpdates is "on" when the panel may update PortBridge here.
	AllowUpdates string
}

func readAgentConfig(path string) (agentConfig, error) {
	var ac agentConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return ac, err
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "listen":
			ac.Listen = v
		case "token":
			ac.Token = v
		case "cert_file":
			ac.CertFile = v
		case "key_file":
			ac.KeyFile = v
		case "panel_url":
			ac.PanelURL = v
		case "panel_fingerprint":
			ac.PanelFingerprint = v
		case "allow_updates":
			ac.AllowUpdates = v
		}
	}
	return ac, nil
}

func writeAgentConfig(path string, ac agentConfig) error {
	// Every value is written as one "key = value" line. A line break inside one
	// would add a setting nobody asked for (allow_updates, a new token), so the
	// whole write is refused rather than risk it.
	for _, v := range []string{ac.Listen, ac.Token, ac.CertFile, ac.KeyFile,
		ac.PanelURL, ac.PanelFingerprint, ac.AllowUpdates} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("an agent setting contained a line break; nothing was written")
		}
	}
	var b strings.Builder
	b.WriteString("# PortBridge Management Agent configuration\n")
	fmt.Fprintf(&b, "listen = %s\ntoken = %s\n", ac.Listen, ac.Token)
	if ac.CertFile != "" {
		fmt.Fprintf(&b, "cert_file = %s\n", ac.CertFile)
	}
	if ac.KeyFile != "" {
		fmt.Fprintf(&b, "key_file = %s\n", ac.KeyFile)
	}
	if ac.PanelURL != "" {
		b.WriteString("\n# The panel this agent calls, for when the panel cannot reach it.\n")
		fmt.Fprintf(&b, "panel_url = %s\n", ac.PanelURL)
		if ac.PanelFingerprint != "" {
			fmt.Fprintf(&b, "panel_fingerprint = %s\n", ac.PanelFingerprint)
		}
	}
	if ac.AllowUpdates != "" {
		b.WriteString("\n# on = the web panel may update PortBridge on this server.\n")
		fmt.Fprintf(&b, "allow_updates = %s\n", ac.AllowUpdates)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(b.String()), 0o600)
}

func newAgentToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pba_" + hex.EncodeToString(b), nil
}

// AgentSetupResult is what "portbridge agent setup -json" prints.
type AgentSetupResult struct {
	OK          bool   `json:"ok"`
	Token       string `json:"token"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version"`
	CallsPanel  bool   `json:"calls_panel"`
	// AllowsUpdates says the panel may update PortBridge on this server.
	AllowsUpdates bool   `json:"allows_updates"`
	Error         string `json:"error,omitempty"`
}

// portFreeTCP reports whether nothing listens on the port.
func portFreeTCP(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func cmdAgentSetup(args []string) error {
	fs := flag.NewFlagSet("agent setup", flag.ExitOnError)
	confPath := fs.String("config", defaultAgentConf, "path to the agent's settings")
	port := fs.Int("port", 0, "port for the agent to listen on (default: keep its port, or pick a free one)")
	panelURL := fs.String("panel-url", "", "a panel for the agent to call (\"off\" stops calling one)")
	panelFP := fs.String("panel-fingerprint", "", "fingerprint of that panel's certificate, when it is self-made")
	allowUpdates := fs.String("allow-updates", "", "on lets the web panel update PortBridge here; off stops it (default: keep)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *allowUpdates {
	case "", "on", "off":
	default:
		return errors.New("-allow-updates must be on or off")
	}
	res, err := agentSetup(*confPath, *port, *panelURL, *panelFP, *allowUpdates)
	if *asJSON {
		if err != nil {
			res.Error = err.Error()
		}
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return err
	}
	if err != nil {
		return err
	}
	fmt.Printf("The agent is running on port %d (certificate fingerprint %s).\n", res.Port, res.Fingerprint)
	if res.CallsPanel {
		fmt.Println("It also calls the panel.")
	}
	return nil
}

func agentSetup(confPath string, port int, panelURL, panelFP, allowUpdates string) (AgentSetupResult, error) {
	res := AgentSetupResult{Version: engine.Version}
	if err := needRoot(); err != nil {
		return res, err
	}
	if !haveSystemd() {
		return res, errNoSystemd
	}
	ac, err := readAgentConfig(confPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, fmt.Errorf("reading %s: %w", confPath, err)
	}
	if ac.Token == "" {
		if ac.Token, err = newAgentToken(); err != nil {
			return res, fmt.Errorf("making the agent's token: %w", err)
		}
	}

	// The agent's own port counts as taken while it runs, so it is stopped
	// before ports are looked at, and started again at the end.
	_, _ = hostRun("systemctl", "stop", agentUnit)
	cur := 0
	if _, p, err := net.SplitHostPort(ac.Listen); err == nil {
		cur, _ = strconv.Atoi(p)
	}
	switch {
	case port > 0:
		if !portFreeTCP(port) {
			_, _ = hostRun("systemctl", "start", agentUnit)
			return res, fmt.Errorf("port %d is already used by something else on this server", port)
		}
	case cur > 0 && portFreeTCP(cur):
		port = cur
	default:
		for _, p := range agentPortCandidates {
			if portFreeTCP(p) {
				port = p
				break
			}
		}
		if port == 0 {
			_, _ = hostRun("systemctl", "start", agentUnit)
			return res, errors.New("none of the usual agent ports (2083, 2087, 2053, 8443, 2096) is free here; give one with -port")
		}
	}
	ac.Listen = "0.0.0.0:" + strconv.Itoa(port)

	switch panelURL {
	case "":
	case "off":
		ac.PanelURL, ac.PanelFingerprint = "", ""
	default:
		if err := validatePanelCallback(panelURL, panelFP); err != nil {
			_, _ = hostRun("systemctl", "start", agentUnit)
			return res, err
		}
		ac.PanelURL, ac.PanelFingerprint = panelURL, panelFP
	}
	if allowUpdates != "" {
		ac.AllowUpdates = allowUpdates
	}

	certFile, keyFile := ac.CertFile, ac.KeyFile
	if certFile == "" || keyFile == "" {
		certFile, keyFile = defaultAgentCert, defaultAgentKey
	}
	cert, err := engine.EnsureCert(certFile, keyFile, "portbridge-agent")
	if err != nil {
		return res, fmt.Errorf("preparing the agent's certificate: %w", err)
	}
	if err := writeAgentConfig(confPath, ac); err != nil {
		return res, fmt.Errorf("writing %s: %w", confPath, err)
	}

	_, _ = hostRun("systemctl", "daemon-reload")
	if out, err := hostRun("systemctl", "enable", agentUnit); err != nil {
		return res, fmt.Errorf("turning the agent on: %s: %w", out, err)
	}
	if out, err := hostRun("systemctl", "restart", agentUnit); err != nil {
		return res, fmt.Errorf("starting the agent: %s: %w", out, err)
	}
	// Up, and listening on the port it was given.
	deadline := time.Now().Add(8 * time.Second)
	for {
		if out, _ := hostRun("systemctl", "is-active", agentUnit); out == "active" && !portFreeTCP(port) {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := hostRun("journalctl", "-u", agentUnit, "-n", "8", "--no-pager", "-o", "cat")
			return res, fmt.Errorf("the agent did not start on port %d: %s", port, logs)
		}
		time.Sleep(300 * time.Millisecond)
	}

	res.OK = true
	res.Token = ac.Token
	res.Port = port
	res.Fingerprint = certFingerprint(cert)
	res.CallsPanel = ac.PanelURL != ""
	res.AllowsUpdates = ac.AllowUpdates == "on"
	return res, nil
}
