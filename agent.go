package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

	// Added in version 6: the stealth settings of the dialling side. Without
	// them a code made for a CDN tunnel produced a foreign side that forgot the
	// browser hello, the split hello and the clean addresses.
	UTLS        string
	TLSFragment string
	CleanIPs    string

	// Added in version 7, and only sent when used: a plain link that opens with a
	// web header, and the name that header claims. See httpheader.go.
	HTTPHeader string
	HTTPHost   string
}

// pairingVersionMax is the newest code this build understands.
const pairingVersionMax = 7

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
		UTLS:        kv["utls"],
		TLSFragment: kv["tls_fragment"],
		CleanIPs:    kv["clean_ips"],
		HTTPHeader:  kv["http_header"],
		HTTPHost:    kv["http_host"],
	}

	if v, err := strconv.Atoi(p.Version); err == nil && v > pairingVersionMax {
		return nil, fmt.Errorf("this pairing code was made by a newer PortBridge (code version %d, this one understands up to %d); update this server first", v, pairingVersionMax)
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
//
// It is all or nothing. Every check that can be made before touching the machine
// is made first, and if anything fails after that, what was done is undone, so a
// refused code never leaves a half-made tunnel behind.
func applyPairingData(p *PairingData, confDir string) error {
	return applyPairingWarn(p, confDir, nil)
}

// applyPairingWarn is applyPairingData that also reports things worth knowing
// that did not stop the tunnel, such as a service that is not running yet.
func applyPairingWarn(p *PairingData, confDir string, warns *[]string) error {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	if err := validatePairing(p); err != nil {
		return err
	}

	agentOpMu.Lock()
	defer agentOpMu.Unlock()

	host := hostFor(confDir)

	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return fmt.Errorf("creating tunnels dir: %w", err)
	}

	confFile := filepath.Join(confDir, p.Name+".conf")
	secretFile := filepath.Join(confDir, p.Name+".secret")
	certFile := filepath.Join(confDir, p.Name+".crt")
	keyFile := filepath.Join(confDir, p.Name+".key")

	// Never replace a tunnel that is already here: that would swap its secret and
	// settings under a running service.
	for _, f := range []string{confFile, secretFile} {
		if _, err := os.Stat(f); err == nil {
			return fmt.Errorf("a tunnel named %q already exists on this server; delete it first or use another name", p.Name)
		}
	}

	// Both the port between the servers and the service ports are checked before
	// anything is written, and the reasons are given in full so they can be fixed.
	notes, err := checkPairingPorts(p, confDir, host, "")
	if err != nil {
		return err
	}
	if warns != nil {
		*warns = append(*warns, notes...)
	}

	confText := buildOriginConf(p, secretFile, certFile, keyFile)

	// From here on, failure undoes what was written.
	undo := func() {
		_ = os.Remove(confFile)
		_ = os.Remove(secretFile)
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
	}

	// The secret first, and never readable by anyone else.
	if err := writeFileAtomic(secretFile, []byte(p.Secret), 0o600); err != nil {
		undo()
		return fmt.Errorf("writing secret: %w", err)
	}
	if err := writeFileAtomic(confFile, []byte(confText), 0o600); err != nil {
		undo()
		return fmt.Errorf("writing config: %w", err)
	}

	// Everything the service itself will check at start, checked now: a tunnel
	// that passes here can start, and one that cannot is refused with the reason
	// instead of being enabled and left to fail in a loop.
	cfg, err := LoadConfig(confFile)
	if err != nil {
		undo()
		return fmt.Errorf("validating config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		undo()
		return fmt.Errorf("validating config: %w", err)
	}
	if err := cfg.LoadSecret(); err != nil {
		undo()
		return fmt.Errorf("validating secret: %w", err)
	}

	// In direct mode with TLS, origin is listening, so ensure certificate is prepared
	if cfg.Transport != TransportPlain && cfg.Transport != TransportKCP && cfg.Mode == ModeDirect {
		if _, err := ensureCert(certFile, keyFile, cfg.effectiveServerName()); err != nil {
			undo()
			return fmt.Errorf("preparing the certificate: %w", err)
		}
	}

	if err := host.FirewallApply(p.Name); err != nil {
		log.Printf("[%s] warning: %v", p.Name, err)
	}

	_ = host.Reload()
	if err := host.Enable(p.Name); err != nil {
		if errors.Is(err, errNoSystemd) {
			// The files are in place; only the starting is left to the owner.
			log.Printf("[%s] %v", p.Name, err)
			return nil
		}
		_ = host.Disable(p.Name)
		_ = host.FirewallRemove(p.Name)
		undo()
		_ = host.Reload()
		return err
	}
	if err := confirmRunning(host, p.Name); err != nil {
		_ = host.Disable(p.Name)
		_ = host.FirewallRemove(p.Name)
		undo()
		_ = host.Reload()
		return err
	}

	return nil
}

// writeFileAtomic writes to a temporary file and renames it into place, so a
// reader never sees half of it.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := os.Chmod(name, perm); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// deleteTunnel removes a tunnel config, secrets, firewall rules, and stops its service.
func deleteTunnel(name string, confDir string) error {
	if confDir == "" {
		confDir = defaultTunnelsDir
	}
	if err := validTunnelName(name); err != nil {
		return err
	}

	agentOpMu.Lock()
	defer agentOpMu.Unlock()

	host := hostFor(confDir)
	confFile := filepath.Join(confDir, name+".conf")
	secretFile := filepath.Join(confDir, name+".secret")
	certFile := filepath.Join(confDir, name+".crt")
	keyFile := filepath.Join(confDir, name+".key")

	// Stopped before anything is removed, so the service is not left running on
	// settings that have gone.
	if err := host.Disable(name); err != nil {
		log.Printf("[%s] stopping the service: %v", name, err)
	}
	if err := host.FirewallRemove(name); err != nil {
		log.Printf("[%s] removing firewall rules: %v", name, err)
	}

	_ = os.Remove(confFile)
	_ = os.Remove(secretFile)
	_ = os.Remove(certFile)
	_ = os.Remove(keyFile)
	host.RemoveRuntime(name)
	_ = host.Reload()
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

// ensureAgentConfigFile reads or creates a default agent config with a secure token.
func ensureAgentConfigFile(path string) (listen string, token string, certFile string, keyFile string, err error) {
	if _, err := os.Stat(path); err == nil {
		return parseAgentConfigFile(path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", "", fmt.Errorf("creating agent config directory: %w", err)
	}

	tokBytes := make([]byte, 24)
	if _, err := rand.Read(tokBytes); err != nil {
		return "", "", "", "", fmt.Errorf("generating agent token: %w", err)
	}
	genToken := "pba_" + hex.EncodeToString(tokBytes)
	defaultListen := "0.0.0.0:2083"

	content := fmt.Sprintf("# PortBridge Management Agent configuration\nlisten = %s\ntoken = %s\n", defaultListen, genToken)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", "", "", "", fmt.Errorf("writing agent config: %w", err)
	}
	log.Printf("[agent] generated new agent configuration at %s", path)
	return defaultListen, genToken, "", "", nil
}

// parseAgentClientConfigFile parses client config with url and token.
func parseAgentClientConfigFile(path string) (url string, token string, err error) {
	url, token, _, err = parseAgentClientProfile(path)
	return url, token, err
}

// parseAgentClientProfile is the same with the pinned certificate fingerprint,
// if the profile has one.
func parseAgentClientProfile(path string) (url string, token string, fingerprint string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
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
		case "url", "agent_url":
			url = v
		case "token", "agent_token":
			token = v
		case "fingerprint", "agent_fingerprint", "cert_fingerprint":
			fingerprint = v
		}
	}
	return url, token, fingerprint, nil
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
		listenAddr = "0.0.0.0:2083"
	}

	mux := http.NewServeMux()

	// POST /api/tunnel/join and /api/tunnel/update take the same pairing code. One
	// makes a tunnel that does not exist yet; the other changes the ports and
	// settings of one that does.
	codeHandler := func(update bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
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
			var warns []string
			verb := "deployed and started"
			if update {
				err = updatePairingData(p, confDir, &warns)
				verb = "updated and restarted"
			} else {
				err = applyPairingWarn(p, confDir, &warns)
			}
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":       true,
				"name":     p.Name,
				"message":  fmt.Sprintf("tunnel %q %s successfully", p.Name, verb),
				"warnings": warns,
			})
		}
	}
	mux.HandleFunc("/api/tunnel/join", codeHandler(false))
	mux.HandleFunc("/api/tunnel/update", codeHandler(true))

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
		// Never fall back to plain HTTP: the token that controls this server
		// would travel in the clear.
		return fmt.Errorf("preparing the agent's certificate: %w", err)
	}

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		// Without these a client that connects and says nothing holds a
		// connection open for ever.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute, // starting a service can take a while
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	log.Printf("[agent] PortBridge management agent listening on https://%s (certificate fingerprint %s)",
		listenAddr, certFingerprint(tlsCert))
	return server.ListenAndServeTLS("", "")
}

// certFingerprint is the SHA-256 of the leaf certificate, in the form a person
// can compare by eye: lower-case hex with colons.
func certFingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	return fingerprintOf(c.Certificate[0])
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// normalizeFingerprint lets a fingerprint be typed with or without colons, in
// any case.
func normalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// agentTrust says how the client decides whether to believe an agent's
// certificate.
//
// The agent's certificate is self-signed, so the usual check cannot work. The
// honest options are to pin the certificate it is known to have, or to say
// plainly that nothing is being checked. Skipping the check by default meant
// anyone on the path could stand in for the agent and collect the token that
// controls the server.
type agentTrust struct {
	Fingerprint string // pin: the certificate must have exactly this fingerprint
	Insecure    bool   // check nothing (asked for explicitly)
}

func makeAgentHTTPClient(trust agentTrust, agentURL string) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case trust.Fingerprint != "":
		want := normalizeFingerprint(trust.Fingerprint)
		// The certificate is checked by its fingerprint instead of by a
		// chain of trust, so the chain check is turned off and replaced.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the agent sent no certificate")
			}
			if got := normalizeFingerprint(fingerprintOf(raw[0])); got != want {
				return fmt.Errorf("the agent's certificate does not match the saved fingerprint (it is %s); "+
					"this could be the wrong server or someone in between", got)
			}
			return nil
		}
	case trust.Insecure:
		tc.InsecureSkipVerify = true
	}
	// With the chain of trust out of the picture the name sent is free to be
	// an ordinary one. See agentSNI.
	if tc.InsecureSkipVerify {
		tc.ServerName = agentSNI(agentURL)
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tc},
	}
}

// agentDisguiseName is the name sent in the secure handshake when the agent is
// addressed by a bare IP address.
//
// A handshake to an address carries no site name at all, which is itself unusual,
// and some networks reset exactly those. Measured on a real route out of Iran:
// the same request to the same agent was reset at once with no name and answered
// normally with an ordinary one. The agent presents one certificate whatever
// name it is asked for, and the fingerprint pin is what identifies it, so the
// name costs nothing.
const agentDisguiseName = "www.bing.com"

// agentSNI is the name to send for an agent at agentURL: its own name if it has
// one, since a CDN in front of it routes by that, and an ordinary one if it is
// reached by IP address.
func agentSNI(agentURL string) string {
	u, err := url.Parse(agentURL)
	if err != nil {
		return agentDisguiseName
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return agentDisguiseName
	}
	return host
}

// fetchAgentFingerprint connects to an agent without trusting it and reports the
// fingerprint of the certificate it presents, so a person can compare it with
// the one the agent printed and then pin it. Nothing secret is sent.
func fetchAgentFingerprint(agentURL string) (string, error) {
	u, err := url.Parse(agentURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a valid agent address", agentURL)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         agentSNI(agentURL),
	})
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", host, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("the agent presented no certificate")
	}
	return fingerprintOf(certs[0].Raw), nil
}

// refuseUnverified turns the certificate error from an agent we could not verify
// into advice someone can act on.
func explainAgentError(err error, trust agentTrust) error {
	if err == nil {
		return nil
	}
	if trust.Fingerprint == "" && !trust.Insecure && strings.Contains(err.Error(), "certificate") {
		return fmt.Errorf("%w\nThe agent uses a self-signed certificate. Pin it with -fingerprint <value> "+
			"(see it with -fetch-fingerprint and compare with what the agent printed when it started)", err)
	}
	return err
}

func agentClientStatus(agentURL, token string, trust agentTrust) error {
	agentURL = strings.TrimRight(agentURL, "/")
	req, err := http.NewRequest(http.MethodGet, agentURL+"/api/status", nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := makeAgentHTTPClient(trust, agentURL)
	resp, err := client.Do(req)
	if err != nil {
		return explainAgentError(fmt.Errorf("connecting to agent at %s: %w", agentURL, err), trust)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("agent returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var res struct {
		OK      bool     `json:"ok"`
		Version string   `json:"version"`
		Tunnels []string `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decoding agent response: %w", err)
	}
	fmt.Printf("Agent status: OK (version: %s, active tunnels: %d: %s)\n", res.Version, len(res.Tunnels), strings.Join(res.Tunnels, ", "))
	return nil
}

func agentClientDelete(agentURL, token, tunnelName string, trust agentTrust) error {
	agentURL = strings.TrimRight(agentURL, "/")
	payload, _ := json.Marshal(map[string]string{"name": tunnelName})
	req, err := http.NewRequest(http.MethodPost, agentURL+"/api/tunnel/delete", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := makeAgentHTTPClient(trust, agentURL)
	resp, err := client.Do(req)
	if err != nil {
		return explainAgentError(fmt.Errorf("connecting to agent at %s: %w", agentURL, err), trust)
	}
	defer resp.Body.Close()

	var res struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if resp.StatusCode != http.StatusOK || !res.OK {
		if res.Error != "" {
			return fmt.Errorf("remote delete failed: %s", res.Error)
		}
		return fmt.Errorf("remote delete failed with HTTP %d", resp.StatusCode)
	}
	fmt.Printf("Remote agent successfully deleted tunnel %q.\n", tunnelName)
	return nil
}

func agentClientJoin(agentURL, token, code string, trust agentTrust) error {
	return agentClientCode(agentURL, token, code, trust, false)
}

// agentClientUpdate asks the agent to change the ports and settings of a tunnel it
// already has, from a fresh pairing code for it.
func agentClientUpdate(agentURL, token, code string, trust agentTrust) error {
	return agentClientCode(agentURL, token, code, trust, true)
}

func agentClientCode(agentURL, token, code string, trust agentTrust, update bool) error {
	agentURL = strings.TrimRight(agentURL, "/")
	endpoint, what, done := "/api/tunnel/join", "join", "deployed and started"
	if update {
		endpoint, what, done = "/api/tunnel/update", "update", "updated and restarted"
	}
	payload, _ := json.Marshal(map[string]string{"code": code})
	req, err := http.NewRequest(http.MethodPost, agentURL+endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := makeAgentHTTPClient(trust, agentURL)
	resp, err := client.Do(req)
	if err != nil {
		return explainAgentError(fmt.Errorf("connecting to agent at %s: %w", agentURL, err), trust)
	}
	defer resp.Body.Close()

	var res struct {
		OK       bool     `json:"ok"`
		Name     string   `json:"name"`
		Error    string   `json:"error"`
		Message  string   `json:"message"`
		Warnings []string `json:"warnings"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if resp.StatusCode != http.StatusOK || !res.OK {
		if res.Error != "" {
			return fmt.Errorf("remote %s failed: %s", what, res.Error)
		}
		if resp.StatusCode == http.StatusNotFound && update {
			return errors.New("the agent on that server is too old to change a tunnel; update PortBridge there first")
		}
		return fmt.Errorf("remote %s failed with HTTP %d", what, resp.StatusCode)
	}
	for _, w := range res.Warnings {
		fmt.Printf("Note from the remote server: %s\n", w)
	}
	fmt.Printf("Remote agent successfully %s tunnel %q.\n", done, res.Name)
	return nil
}

// listSavedAgents prints all agent profiles found in /etc/portbridge/agents.
func listSavedAgents() error {
	agentsDir := "/etc/portbridge/agents"
	entries, err := os.ReadDir(agentsDir)
	var count int
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				alias := strings.TrimSuffix(e.Name(), ".conf")
				p := filepath.Join(agentsDir, e.Name())
				url, _, err := parseAgentClientConfigFile(p)
				if err == nil {
					fmt.Printf("- %s: %s\n", alias, url)
					count++
				}
			}
		}
	}
	if count == 0 {
		if url, _, err := parseAgentClientConfigFile("/etc/portbridge/agent-client.conf"); err == nil && url != "" {
			fmt.Printf("- default: %s\n", url)
			return nil
		}
		fmt.Println("No foreign agent profiles configured.")
	}
	return nil
}

// cmdAgent handles the "portbridge agent" command line.
func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	confPath := fs.String("config", "/etc/portbridge/agent.conf", "path to agent config file")
	listen := fs.String("listen", "", "listen address (e.g. 0.0.0.0:2083)")
	token := fs.String("token", "", "management authentication token")
	cert := fs.String("cert", "", "TLS certificate path")
	key := fs.String("key", "", "TLS private key path")
	showFP := fs.Bool("fingerprint", false, "print the SHA-256 fingerprint of the agent's certificate and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *confPath != "" {
		if cListen, cToken, cCert, cKey, err := ensureAgentConfigFile(*confPath); err == nil {
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

	if *showFP {
		certPath, keyPath := *cert, *key
		if certPath == "" || keyPath == "" {
			certPath, keyPath = "/etc/portbridge/agent.crt", "/etc/portbridge/agent.key"
		}
		c, err := ensureCert(certPath, keyPath, "portbridge-agent")
		if err != nil {
			return fmt.Errorf("preparing the agent's certificate: %w", err)
		}
		fmt.Println(certFingerprint(c))
		return nil
	}

	if *token == "" {
		return errors.New("agent requires -token or token set in config file")
	}
	if *listen == "" {
		*listen = "0.0.0.0:2083"
	}

	return runAgentServer(*listen, *token, *cert, *key, "/etc/portbridge/tunnels")
}

// cmdJoin handles pairing code application locally or against a remote agent.
func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	agentURL := fs.String("agent-url", "", "remote agent URL (e.g. https://foreign-ip:2083)")
	token := fs.String("token", "", "agent bearer token (visible in the process list; prefer -token-file or PORTBRIDGE_AGENT_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the agent bearer token from this file")
	codeFile := fs.String("code-file", "", "read the pairing code from this file (or - for standard input)")
	confPath := fs.String("agent-config", "", "path to client agent config file (e.g. /etc/portbridge/agent-client.conf)")
	agentAlias := fs.String("agent", "", "named agent profile from /etc/portbridge/agents/<alias>.conf")
	fingerprint := fs.String("fingerprint", "", "SHA-256 fingerprint the agent's certificate must have")
	insecure := fs.Bool("insecure", false, "do not check the agent's certificate at all (not recommended)")
	fetchFP := fs.Bool("fetch-fingerprint", false, "print the fingerprint of the agent's certificate and exit")
	isUpdate := fs.Bool("update", false, "change the ports and settings of a tunnel that already exists, from a new code")
	isDelete := fs.Bool("delete", false, "delete remote tunnel instead of joining")
	isStatus := fs.Bool("status", false, "check status/connectivity to remote agent")
	isListAgents := fs.Bool("list-agents", false, "list all saved foreign agent profiles")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *isListAgents {
		return listSavedAgents()
	}

	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("reading token file: %w", err)
		}
		*token = strings.TrimSpace(string(b))
	}
	if *token == "" {
		*token = strings.TrimSpace(os.Getenv("PORTBRIDGE_AGENT_TOKEN"))
	}

	profileFP := ""
	if *agentAlias != "" {
		namedPath := filepath.Join("/etc/portbridge/agents", *agentAlias+".conf")
		if _, err := os.Stat(namedPath); err != nil {
			namedPath = *agentAlias
		}
		cURL, cToken, cFP, err := parseAgentClientProfile(namedPath)
		if err != nil {
			return fmt.Errorf("reading agent profile %q: %w", *agentAlias, err)
		}
		if *agentURL == "" {
			*agentURL = cURL
		}
		if *token == "" {
			*token = cToken
		}
		profileFP = cFP
	}

	if *confPath == "" && *agentURL == "" {
		defaultClientConf := "/etc/portbridge/agent-client.conf"
		if _, err := os.Stat(defaultClientConf); err == nil {
			*confPath = defaultClientConf
		} else {
			entries, _ := os.ReadDir("/etc/portbridge/agents")
			var valid []string
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".conf") {
					valid = append(valid, filepath.Join("/etc/portbridge/agents", e.Name()))
				}
			}
			if len(valid) == 1 {
				*confPath = valid[0]
			}
		}
	}
	if *confPath != "" {
		if cURL, cToken, cFP, err := parseAgentClientProfile(*confPath); err == nil {
			if *agentURL == "" {
				*agentURL = cURL
			}
			if *token == "" {
				*token = cToken
			}
			if profileFP == "" {
				profileFP = cFP
			}
		}
	}
	if *fingerprint == "" {
		*fingerprint = profileFP
	}
	trust := agentTrust{Fingerprint: *fingerprint, Insecure: *insecure}
	if trust.Insecure && trust.Fingerprint == "" {
		fmt.Fprintln(os.Stderr, "warning: the agent's certificate is not being checked; anyone between here and there could read the token")
	}

	if *fetchFP {
		if *agentURL == "" {
			return errors.New("-agent-url, -agent, or agent config required for -fetch-fingerprint")
		}
		fp, err := fetchAgentFingerprint(*agentURL)
		if err != nil {
			return err
		}
		fmt.Println(fp)
		return nil
	}

	if *isStatus {
		if *agentURL == "" {
			return errors.New("-agent-url, -agent, or agent config required for -status")
		}
		return agentClientStatus(*agentURL, *token, trust)
	}

	if *isDelete {
		if *agentURL == "" {
			return errors.New("-agent-url, -agent, or agent config required for -delete")
		}
		remaining := fs.Args()
		if len(remaining) < 1 {
			return errors.New("tunnel name required: portbridge join -agent-url <url> -token <token> -delete <tunnel_name>")
		}
		name := remaining[0]
		return agentClientDelete(*agentURL, *token, name, trust)
	}

	var code string
	switch {
	case *codeFile == "-":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
		if err != nil {
			return fmt.Errorf("reading the pairing code: %w", err)
		}
		code = strings.TrimSpace(string(b))
	case *codeFile != "":
		b, err := os.ReadFile(*codeFile)
		if err != nil {
			return fmt.Errorf("reading the pairing code: %w", err)
		}
		code = strings.TrimSpace(string(b))
	default:
		remaining := fs.Args()
		if len(remaining) < 1 {
			return errors.New("pairing code is required: portbridge join [flags] <code>")
		}
		code = remaining[0]
	}

	if *agentURL != "" {
		if *isUpdate {
			return agentClientUpdate(*agentURL, *token, code, trust)
		}
		return agentClientJoin(*agentURL, *token, code, trust)
	}

	p, err := decodePairingCode(code)
	if err != nil {
		return fmt.Errorf("parsing pairing code: %w", err)
	}

	if *isUpdate {
		var warns []string
		if err := updatePairingData(p, defaultTunnelsDir, &warns); err != nil {
			return err
		}
		for _, w := range warns {
			fmt.Printf("Note: %s\n", w)
		}
		fmt.Printf("Updated and restarted tunnel %q.\n", p.Name)
		return nil
	}

	var joinWarns []string
	if err := applyPairingWarn(p, defaultTunnelsDir, &joinWarns); err != nil {
		return err
	}
	for _, w := range joinWarns {
		fmt.Printf("Note: %s\n", w)
	}
	fmt.Printf("Successfully joined and activated tunnel %q (role: origin, mode: %s)\n", p.Name, p.Mode)
	return nil
}
