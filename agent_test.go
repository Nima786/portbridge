package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecodePairingCode(t *testing.T) {
	// Generate a valid pairing payload
	payload := "v=5\nname=testtunnel\nmode=direct\ntunnel_port=443\nrelay_ip=94.184.46.135\nserver_ip=185.139.7.93\ninbound_port=100\npool=25\ntransport=wss\nserver_name=console.example.com\nws_path=/wspath\ncdn=on\nalt_host=\nmux=on\nmux_links=4\nsecret=0123456789abcdef0123456789abcdef\n"
	code := base64.StdEncoding.EncodeToString([]byte(payload))

	p, err := decodePairingCode(code)
	if err != nil {
		t.Fatalf("decodePairingCode failed: %v", err)
	}

	if p.Name != "testtunnel" {
		t.Errorf("expected name testtunnel, got %s", p.Name)
	}
	if p.Mode != "direct" {
		t.Errorf("expected mode direct, got %s", p.Mode)
	}
	if p.TunnelPort != "443" {
		t.Errorf("expected tunnel_port 443, got %s", p.TunnelPort)
	}
	if p.Transport != "wss" {
		t.Errorf("expected transport wss, got %s", p.Transport)
	}
	if p.Mux != "on" || p.MuxLinks != "4" {
		t.Errorf("expected mux on/4, got %s/%s", p.Mux, p.MuxLinks)
	}
	if p.Secret != "0123456789abcdef0123456789abcdef" {
		t.Errorf("expected secret, got %s", p.Secret)
	}
}

func TestApplyPairingData(t *testing.T) {
	tmpDir := t.TempDir()

	p := &PairingData{
		Version:     "5",
		Name:        "sample",
		Mode:        "direct",
		TunnelPort:  "8443",
		RelayIP:     "1.1.1.1",
		ServerIP:    "2.2.2.2",
		InboundPort: "8080, 9090",
		Pool:        "15",
		Transport:   "plain",
		Mux:         "off",
		Secret:      "0123456789abcdef0123456789abcdef",
	}

	if err := applyPairingData(p, tmpDir); err != nil {
		t.Fatalf("applyPairingData failed: %v", err)
	}

	confPath := filepath.Join(tmpDir, "sample.conf")
	cfg, err := LoadConfig(confPath)
	if err != nil {
		t.Fatalf("loadConfig failed on generated conf: %v", err)
	}

	if cfg.Name != "sample" {
		t.Errorf("expected name sample, got %s", cfg.Name)
	}
	if cfg.Role != RoleOrigin {
		t.Errorf("expected origin role on foreign side, got %s", cfg.Role)
	}
	if cfg.Mode != ModeDirect {
		t.Errorf("expected direct mode, got %s", cfg.Mode)
	}
	if cfg.TunnelAddr != "0.0.0.0:8443" {
		t.Errorf("expected 0.0.0.0:8443, got %s", cfg.TunnelAddr)
	}
	if cfg.InboundAddr != "127.0.0.1:8080, 127.0.0.1:9090" {
		t.Errorf("unexpected inbound_addr: %s", cfg.InboundAddr)
	}
}

func TestAgentServerAPI(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "agent.crt")
	keyFile := filepath.Join(tmpDir, "agent.key")

	token := "test_token_12345"
	listenAddr := "127.0.0.1:0"

	// Find free port
	l, err := (&net.ListenConfig{}).Listen(nil, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	listenAddr = l.Addr().String()
	_ = l.Close()

	go func() {
		_ = runAgentServer(listenAddr, token, certFile, keyFile, tmpDir)
	}()

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Poll until server is ready
	var ready bool
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		req, _ := http.NewRequest(http.MethodGet, "https://"+listenAddr+"/api/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("agent server did not start in time")
	}

	// 1. Unauthorized request
	unauthReq, _ := http.NewRequest(http.MethodGet, "https://"+listenAddr+"/api/status", nil)
	unauthResp, err := client.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauth request failed: %v", err)
	}
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", unauthResp.StatusCode)
	}
	unauthResp.Body.Close()

	// 2. Authorized status request
	statusReq, _ := http.NewRequest(http.MethodGet, "https://"+listenAddr+"/api/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+token)
	statusResp, err := client.Do(statusReq)
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	if statusResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", statusResp.StatusCode)
	}
	var statusData map[string]any
	body, _ := io.ReadAll(statusResp.Body)
	statusResp.Body.Close()
	if err := json.Unmarshal(body, &statusData); err != nil || statusData["ok"] != true {
		t.Errorf("unexpected status response: %s", string(body))
	}

	// 3. Test POST /api/tunnel/join
	pairingPayload := "v=5\nname=agttest\nmode=direct\ntunnel_port=9090\nrelay_ip=1.1.1.1\nserver_ip=2.2.2.2\ninbound_port=80\npool=10\ntransport=plain\nmux=off\nsecret=0123456789abcdef0123456789abcdef\n"
	pairingCode := base64.StdEncoding.EncodeToString([]byte(pairingPayload))

	joinBody, _ := json.Marshal(map[string]string{"code": pairingCode})
	joinReq, _ := http.NewRequest(http.MethodPost, "https://"+listenAddr+"/api/tunnel/join", bytes.NewReader(joinBody))
	joinReq.Header.Set("Authorization", "Bearer "+token)
	joinReq.Header.Set("Content-Type", "application/json")

	joinResp, err := client.Do(joinReq)
	if err != nil {
		t.Fatalf("join request failed: %v", err)
	}
	defer joinResp.Body.Close()
	joinOut, _ := io.ReadAll(joinResp.Body)
	if joinResp.StatusCode != http.StatusOK {
		t.Fatalf("join expected 200, got %d: %s", joinResp.StatusCode, string(joinOut))
	}

	// Verify tunnel files were created in tmpDir
	if _, err := os.Stat(filepath.Join(tmpDir, "agttest.conf")); err != nil {
		t.Errorf("agttest.conf not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "agttest.secret")); err != nil {
		t.Errorf("agttest.secret not found: %v", err)
	}

	// 4. Test POST /api/tunnel/delete
	delBody, _ := json.Marshal(map[string]string{"name": "agttest"})
	delReq, _ := http.NewRequest(http.MethodPost, "https://"+listenAddr+"/api/tunnel/delete", bytes.NewReader(delBody))
	delReq.Header.Set("Authorization", "Bearer "+token)
	delReq.Header.Set("Content-Type", "application/json")

	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Errorf("delete expected 200, got %d", delResp.StatusCode)
	}

	// Verify tunnel files were deleted
	if _, err := os.Stat(filepath.Join(tmpDir, "agttest.conf")); !os.IsNotExist(err) {
		t.Errorf("agttest.conf still exists after delete")
	}

	// 5. Test agent client helper functions directly against the running agent
	agentURL := "https://" + listenAddr
	if err := agentClientStatus(agentURL, token, true); err != nil {
		t.Errorf("agentClientStatus failed: %v", err)
	}

	if err := agentClientJoin(agentURL, token, pairingCode, true); err != nil {
		t.Errorf("agentClientJoin failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "agttest.conf")); err != nil {
		t.Errorf("agttest.conf not found after agentClientJoin: %v", err)
	}

	if err := agentClientDelete(agentURL, token, "agttest", true); err != nil {
		t.Errorf("agentClientDelete failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "agttest.conf")); !os.IsNotExist(err) {
		t.Errorf("agttest.conf still exists after agentClientDelete")
	}
}

func TestEnsureAgentConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "agent.conf")

	listen, token, cert, key, err := ensureAgentConfigFile(confPath)
	if err != nil {
		t.Fatalf("ensureAgentConfigFile failed: %v", err)
	}
	if listen != "0.0.0.0:2083" {
		t.Errorf("expected 0.0.0.0:2083, got %s", listen)
	}
	if token == "" || len(token) < 10 {
		t.Errorf("expected valid generated token, got %q", token)
	}
	if cert != "" || key != "" {
		t.Errorf("expected empty cert/key, got %s / %s", cert, key)
	}

	// Calling again should read the same file and return identical values
	listen2, token2, _, _, err := ensureAgentConfigFile(confPath)
	if err != nil {
		t.Fatalf("ensureAgentConfigFile second call failed: %v", err)
	}
	if listen2 != listen || token2 != token {
		t.Errorf("ensureAgentConfigFile returned different values on second call")
	}
}

func TestParseAgentClientConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	clientConfPath := filepath.Join(tmpDir, "agent-client.conf")
	content := "url = https://1.2.3.4:2083\ntoken = my_secret_token\n"
	if err := os.WriteFile(clientConfPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write client conf failed: %v", err)
	}

	url, token, err := parseAgentClientConfigFile(clientConfPath)
	if err != nil {
		t.Fatalf("parseAgentClientConfigFile failed: %v", err)
	}
	if url != "https://1.2.3.4:2083" {
		t.Errorf("expected url https://1.2.3.4:2083, got %s", url)
	}
	if token != "my_secret_token" {
		t.Errorf("expected token my_secret_token, got %s", token)
	}
}

func TestNamedAgentProfile(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "germany.conf")
	content := "alias = germany\nurl = https://185.139.7.93:2083\ntoken = pba_sampletoken123\nserver_ip = 185.139.7.93\nport = 2083\n"
	if err := os.WriteFile(profilePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write profile failed: %v", err)
	}

	url, token, err := parseAgentClientConfigFile(profilePath)
	if err != nil {
		t.Fatalf("parseAgentClientConfigFile on profile failed: %v", err)
	}
	if url != "https://185.139.7.93:2083" {
		t.Errorf("expected url https://185.139.7.93:2083, got %s", url)
	}
	if token != "pba_sampletoken123" {
		t.Errorf("expected token pba_sampletoken123, got %s", token)
	}
}
