package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PairingData represents the decoded attributes from a PortBridge join code.
type PairingData struct {
	Version     string
	Name        string
	Mode        string
	TunnelPort  string
	RelayIP     string
	ServerIP    string
	InboundPort string
	Pool        string
	Transport   string
	ServerName  string
	WSPath      string
	CDN         string
	AltHost     string
	Mux         string
	MuxLinks    string
	Secret      string
}

// decodePairingCode parses a base64 encoded pairing code into structured data.
func decodePairingCode(code string) (*PairingData, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, errors.New("empty pairing code")
	}
	raw, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	kv := make(map[string]string)
	lines := strings.Split(string(raw), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) == 2 {
			kv[parts[0]] = parts[1]
		}
	}

	p := &PairingData{
		Version:     kv["v"],
		Name:        kv["name"],
		Mode:        kv["mode"],
		TunnelPort:  kv["tunnel_port"],
		RelayIP:     kv["relay_ip"],
		ServerIP:    kv["server_ip"],
		InboundPort: kv["inbound_port"],
		Pool:        kv["pool"],
		Transport:   kv["transport"],
		ServerName:  kv["server_name"],
		WSPath:      kv["ws_path"],
		CDN:         kv["cdn"],
		AltHost:     kv["alt_host"],
		Mux:         kv["mux"],
		MuxLinks:    kv["mux_links"],
		Secret:      kv["secret"],
	}

	if p.Name == "" || p.Mode == "" || p.TunnelPort == "" || p.Secret == "" {
		return nil, errors.New("pairing code missing required fields")
	}
	if p.Transport == "" {
		p.Transport = "plain"
	}
	if p.Pool == "" {
		p.Pool = "25"
	}
	if p.Mux == "" {
		p.Mux = "off"
	}
	if p.MuxLinks == "" {
		p.MuxLinks = "4"
	}
	if p.CDN == "" {
		p.CDN = "off"
	}

	return p, nil
}

// applyPairingData configures and starts a tunnel on the local server.
func applyPairingData(p *PairingData, confDir string) error {
	if confDir == "" {
		confDir = "/etc/portbridge/tunnels"
	}
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return fmt.Errorf("creating tunnels dir: %w", err)
	}

	confFile := filepath.Join(confDir, p.Name+".conf")
	secretFile := filepath.Join(confDir, p.Name+".secret")
	certFile := filepath.Join(confDir, p.Name+".crt")
	keyFile := filepath.Join(confDir, p.Name+".key")

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
	} else {
		tunnelAddr = p.RelayIP + ":" + p.TunnelPort
	}

	firewall := "on"
	if p.CDN == "on" || p.AltHost != "" || p.Mode == "reverse" {
		firewall = "off"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# PortBridge tunnel %q, deployed by management agent\n", p.Name)
	fmt.Fprintf(&b, "name = %s\n", p.Name)
	fmt.Fprintf(&b, "mode = %s\n", p.Mode)
	fmt.Fprintf(&b, "role = origin\n")
	fmt.Fprintf(&b, "tunnel_addr = %s\n", tunnelAddr)
	fmt.Fprintf(&b, "inbound_addr = %s\n", inboundAddr)
	fmt.Fprintf(&b, "peer_ip = %s\n", p.RelayIP)
	fmt.Fprintf(&b, "firewall = %s\n", firewall)
	if p.ServerIP != "" {
		fmt.Fprintf(&b, "local_ip = %s\n", p.ServerIP)
	}
	fmt.Fprintf(&b, "\ntransport = %s\n", p.Transport)
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
	}
	if p.AltHost != "" && p.Mode == "reverse" {
		fmt.Fprintf(&b, "alt_target = %s:%s\n", p.AltHost, p.TunnelPort)
		fmt.Fprintf(&b, "alt_server_name = %s\n", p.AltHost)
	}
	fmt.Fprintf(&b, "\nmux = %s\n", p.Mux)
	if p.Mux == "on" {
		fmt.Fprintf(&b, "mux_links = %s\n", p.MuxLinks)
	}
	fmt.Fprintf(&b, "\npool_size = %s\n", p.Pool)
	fmt.Fprintf(&b, "max_conn = 2000\nmax_pending = 512\nspare_ttl = 10m\npark_timeout = 15m\ndrain = 5s\n")
	fmt.Fprintf(&b, "\nsecret_file = %s\n", secretFile)

	if err := os.WriteFile(confFile, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.WriteFile(secretFile, []byte(p.Secret), 0o600); err != nil {
		return fmt.Errorf("writing secret: %w", err)
	}

	// Validate config syntax with loadConfig
	cfg, err := loadConfig(confFile)
	if err != nil {
		_ = os.Remove(confFile)
		_ = os.Remove(secretFile)
		return fmt.Errorf("validating config: %w", err)
	}

	// In reverse mode with TLS, ensure certificate is prepared
	if cfg.Transport != TransportPlain && cfg.Transport != TransportKCP && cfg.Mode == ModeReverse {
		if _, err := ensureCert(certFile, keyFile, cfg.effectiveServerName()); err != nil {
			log.Printf("[%s] warning: preparing cert: %v", p.Name, err)
		}
	}

	// Apply firewall rule if helper exists
	if _, err := os.Stat("/usr/local/bin/portbridge-firewall"); err == nil {
		_ = exec.Command("/usr/local/bin/portbridge-firewall", "apply", p.Name).Run()
	}

	// Enable and start systemd unit if systemd is active
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		_ = exec.Command("systemctl", "daemon-reload").Run()
		if out, err := exec.Command("systemctl", "enable", "--now", "portbridge@"+p.Name).CombinedOutput(); err != nil {
			return fmt.Errorf("starting systemd service: %s: %w", string(out), err)
		}
	}

	return nil
}

// deleteTunnel removes a tunnel config, secrets, firewall rules, and stops its service.
func deleteTunnel(name string, confDir string) error {
	if confDir == "" {
		confDir = "/etc/portbridge/tunnels"
	}
	name = filepath.Base(name)
	confFile := filepath.Join(confDir, name+".conf")
	secretFile := filepath.Join(confDir, name+".secret")
	certFile := filepath.Join(confDir, name+".crt")
	keyFile := filepath.Join(confDir, name+".key")
	runJSON := filepath.Join("/run/portbridge", name+".json")
	runSock := filepath.Join("/run/portbridge", name+".sock")

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		_ = exec.Command("systemctl", "disable", "--now", "portbridge@"+name).Run()
	}

	if _, err := os.Stat("/usr/local/bin/portbridge-firewall"); err == nil {
		_ = exec.Command("/usr/local/bin/portbridge-firewall", "remove", name).Run()
	}

	_ = os.Remove(confFile)
	_ = os.Remove(secretFile)
	_ = os.Remove(certFile)
	_ = os.Remove(keyFile)
	_ = os.Remove(runJSON)
	_ = os.Remove(runSock)

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	return nil
}

// parseAgentConfigFile reads listen address and token from a simple key=val config.
func parseAgentConfigFile(path string) (listen string, token string, certFile string, keyFile string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "listen":
			listen = v
		case "token":
			token = v
		case "cert_file":
			certFile = v
		case "key_file":
			keyFile = v
		}
	}
	return listen, token, certFile, keyFile, nil
}

func checkAgentAuth(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	authHeader := r.Header.Get("Authorization")
	var got string
	if strings.HasPrefix(authHeader, "Bearer ") {
		got = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		got = r.Header.Get("X-PortBridge-Token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// runAgentServer starts the HTTP/JSON management server.
func runAgentServer(listenAddr, token, certFile, keyFile, confDir string) error {
	if token == "" {
		return errors.New("agent token cannot be empty")
	}
	if listenAddr == "" {
		listenAddr = "0.0.0.0:2096"
	}

	mux := http.NewServeMux()

	// POST /api/tunnel/join
	mux.HandleFunc("/api/tunnel/join", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, `{"error":"reading body"}`, http.StatusBadRequest)
			return
		}

		var req struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Code == "" {
			http.Error(w, `{"error":"code required in json body"}`, http.StatusBadRequest)
			return
		}

		p, err := decodePairingCode(req.Code)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}

		if err := applyPairingData(p, confDir); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"name":    p.Name,
			"message": fmt.Sprintf("tunnel %q deployed and started successfully", p.Name),
		})
	})

	// POST /api/tunnel/delete
	mux.HandleFunc("/api/tunnel/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
		if err != nil {
			http.Error(w, `{"error":"reading body"}`, http.StatusBadRequest)
			return
		}

		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Name == "" {
			http.Error(w, `{"error":"name required in json body"}`, http.StatusBadRequest)
			return
		}

		if err := deleteTunnel(req.Name, confDir); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"name":    req.Name,
			"message": fmt.Sprintf("tunnel %q deleted successfully", req.Name),
		})
	})

	// GET /api/status
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !checkAgentAuth(r, token) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		entries, _ := os.ReadDir(confDir)
		var tunnels []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				tunnels = append(tunnels, strings.TrimSuffix(e.Name(), ".conf"))
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"version": version,
			"tunnels": tunnels,
		})
	})

	// Prepare TLS certificate
	if certFile == "" || keyFile == "" {
		certFile = "/etc/portbridge/agent.crt"
		keyFile = "/etc/portbridge/agent.key"
	}
	tlsCert, err := ensureCert(certFile, keyFile, "portbridge-agent")
	if err != nil {
		log.Printf("[agent] warning: generating cert failed: %v; running plain HTTP", err)
		server := &http.Server{Addr: listenAddr, Handler: mux}
		log.Printf("[agent] PortBridge management agent listening on http://%s", listenAddr)
		return server.ListenAndServe()
	}

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	log.Printf("[agent] PortBridge management agent listening on https://%s", listenAddr)
	return server.ListenAndServeTLS("", "")
}

// cmdAgent handles the "portbridge agent" command line.
func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	confPath := fs.String("config", "/etc/portbridge/agent.conf", "path to agent config file")
	listen := fs.String("listen", "", "listen address (e.g. 0.0.0.0:2096)")
	token := fs.String("token", "", "management authentication token")
	cert := fs.String("cert", "", "TLS certificate path")
	key := fs.String("key", "", "TLS private key path")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *confPath != "" {
		if cListen, cToken, cCert, cKey, err := parseAgentConfigFile(*confPath); err == nil {
			if *listen == "" {
				*listen = cListen
			}
			if *token == "" {
				*token = cToken
			}
			if *cert == "" {
				*cert = cCert
			}
			if *key == "" {
				*key = cKey
			}
		}
	}

	if *token == "" {
		return errors.New("agent requires -token or token set in config file")
	}
	if *listen == "" {
		*listen = "0.0.0.0:2096"
	}

	return runAgentServer(*listen, *token, *cert, *key, "/etc/portbridge/tunnels")
}

// cmdJoin handles the "portbridge join <code>" command line.
func cmdJoin(args []string) error {
	if len(args) < 1 {
		return errors.New("pairing code is required: portbridge join <code>")
	}
	code := args[0]
	p, err := decodePairingCode(code)
	if err != nil {
		return fmt.Errorf("parsing pairing code: %w", err)
	}

	if err := applyPairingData(p, "/etc/portbridge/tunnels"); err != nil {
		return err
	}
	fmt.Printf("Successfully joined and activated tunnel %q (role: origin, mode: %s)\n", p.Name, p.Mode)
	return nil
}
