package panel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

func startPinnedMockAgent(t *testing.T, token string) (*httptest.Server, string) {
	t.Helper()
	certDir := t.TempDir()
	cert, err := engine.EnsureCert(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), "portbridge-agent")
	if err != nil {
		t.Fatal(err)
	}
	fp := fingerprintOf(cert.Certificate[0])
	ts := httptest.NewUnstartedServer(agent.NewHandler(token, t.TempDir(), nil))
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, fp
}

func TestNetProxyBlocksPrivateAndLoopbackByDefault(t *testing.T) {
	agent.SetAllowLoopbackNetProxyForTest(false)
	const tok = "pba_ssrf_guard"
	ts, fp := startPinnedMockAgent(t, tok)
	client := agent.NewPinnedClient(fp, ts.URL, 5*time.Second)

	for _, blocked := range []string{"127.0.0.1:22", "10.0.0.1:22", "192.168.1.1:80", "100.64.0.1:443", "[::1]:22"} {
		raw, _ := json.Marshal(agent.NetProxyDialReq{Addr: blocked, TimeoutMs: 1000})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/net/dial", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("dial %s transport err: %v", blocked, err)
		}
		var rep agent.NetProxyDialReply
		_ = json.NewDecoder(resp.Body).Decode(&rep)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK || rep.OK || !strings.Contains(rep.Error, "refusing to dial") {
			t.Fatalf("expected SSRF block for %s, got HTTP %d %+v", blocked, resp.StatusCode, rep)
		}
	}
}

func TestFetchHostKeyAndSSHJumpViaOnlinePeer(t *testing.T) {
	agent.SetAllowLoopbackNetProxyForTest(true)
	t.Cleanup(func() { agent.SetAllowLoopbackNetProxyForTest(false) })

	p := newTestPanel(t)
	const jumpTok = "pba_jump_peer"
	jumpTS, jumpFP := startPinnedMockAgent(t, jumpTok)
	jumpSrv := addTestServer(t, p, Server{
		ID:          "jump1",
		Name:        "Germany-Jump",
		Group:       GroupForeign,
		Address:     "198.51.100.10",
		AgentURL:    jumpTS.URL,
		Fingerprint: jumpFP,
	}, jumpTok)
	p.fleet.refresh(jumpSrv)

	sshPort, realFP, attempts := fakeSSHServer(t)

	// Explicit jump through Germany-Jump fetches the real SSH fingerprint without logging in.
	gotFP, viaName, err := p.fetchHostKeyMultiPath(context.Background(), "127.0.0.1", sshPort, GroupForeign, jumpSrv.ID)
	if err != nil {
		t.Fatalf("fetchHostKeyMultiPath via jump failed: %v", err)
	}
	if gotFP != realFP || viaName != "Germany-Jump" {
		t.Fatalf("got fp=%q via=%q, want fp=%q via=Germany-Jump", gotFP, viaName, realFP)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("login attempted %d times during hostkey check over jump", n)
	}

	// End-to-end host-key mismatch over a jump server must STILL abort before sending credentials.
	j := &job{}
	_, err = p.addServer(j, addRequest{
		Group:     GroupForeign,
		Address:   "127.0.0.1",
		SSHPort:   sshPort,
		User:      "root",
		Password:  "topsecret",
		HostKey:   "SHA256:wrongFingerprintOnJump",
		ViaServer: jumpSrv.ID,
	})
	if err == nil || !strings.Contains(err.Error(), "confirmed") {
		t.Fatalf("expected host key mismatch rejection over jump, got: %v", err)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("credentials were offered %d times despite mismatched host key over jump", n)
	}
}

func TestStealthTLSAndPeerJumpAgentReachability(t *testing.T) {
	agent.SetAllowLoopbackNetProxyForTest(true)
	t.Cleanup(func() { agent.SetAllowLoopbackNetProxyForTest(false) })

	p := newTestPanel(t)
	const jumpTok = "pba_jump_agent"
	jumpTS, jumpFP := startPinnedMockAgent(t, jumpTok)
	jumpSrv := addTestServer(t, p, Server{
		ID:          "jump2",
		Name:        "Finland-Jump",
		Group:       GroupForeign,
		Address:     "198.51.100.20",
		AgentURL:    jumpTS.URL,
		Fingerprint: jumpFP,
	}, jumpTok)
	p.fleet.refresh(jumpSrv)

	const targetTok = "pba_target_agent"
	targetTS, targetFP := startPinnedMockAgent(t, targetTok)

	// 1. Stealth Chrome uTLS + fragmented ClientHello verifies pinned cert and fetches overview.
	stealthClient := agent.NewPinnedClientOpts(targetFP, targetTS.URL, 10*time.Second, nil, true)
	req, _ := http.NewRequest(http.MethodGet, targetTS.URL+"/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+targetTok)
	resp, err := stealthClient.Do(req)
	if err != nil {
		t.Fatalf("stealth TLS client failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stealth TLS status = %d, want 200", resp.StatusCode)
	}

	// Wrong fingerprint must still fail under Stealth uTLS.
	badStealth := agent.NewPinnedClientOpts("0000000000000000000000000000000000000000000000000000000000000000", targetTS.URL, 5*time.Second, nil, true)
	reqBad, _ := http.NewRequest(http.MethodGet, targetTS.URL+"/api/overview", nil)
	if _, err := badStealth.Do(reqBad); err == nil || !strings.Contains(err.Error(), "does not match the saved fingerprint") {
		t.Fatalf("expected fingerprint mismatch in stealth uTLS, got: %v", err)
	}

	// 2. End-to-end pinned TLS jumped through Finland-Jump reaches targetTS.
	sealedTok, err := p.store.seal(targetTok)
	if err != nil {
		t.Fatal(err)
	}
	targetSrv := Server{
		ID:          "target1",
		Name:        "Turkey-Hard",
		Group:       GroupForeign,
		Address:     "127.0.0.1",
		AgentURL:    targetTS.URL,
		Fingerprint: targetFP,
		TokenEnc:    sealedTok,
	}
	ov, viaName, err := p.tryJumpOverview(targetSrv, jumpSrv.ID)
	if err != nil {
		t.Fatalf("tryJumpOverview failed: %v", err)
	}
	if viaName != "Finland-Jump" || ov == nil {
		t.Fatalf("unexpected jump overview result: via=%q ov=%v", viaName, ov)
	}
}

func TestOneLineJoinTicketAndStealthHubRegister(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	p.cfg.PublicURL = ts.URL

	b := newBrowser(t, ts)
	st, loginBody, _ := b.do(http.MethodPost, "/api/login", map[string]string{
		"user":     "admin",
		"password": testPassword,
	}, map[string]string{"Origin": ts.URL})
	if st != http.StatusOK {
		t.Fatalf("login failed: %d %v", st, loginBody)
	}
	b.csrf, _ = loginBody["csrf"].(string)

	st, ticketBody, _ := b.do(http.MethodPost, "/api/join-tickets", map[string]string{
		"group": GroupForeign,
		"name":  "NL-JoinNode",
	}, map[string]string{"Origin": ts.URL})
	if st != http.StatusOK {
		t.Fatalf("create join ticket failed: %d %v", st, ticketBody)
	}
	ticketID, _ := ticketBody["ticket_id"].(string)
	cmdStr, _ := ticketBody["command"].(string)
	m := regexp.MustCompile(`-ticket '([^']+)'`).FindStringSubmatch(cmdStr)
	if ticketID == "" || len(m) != 2 {
		t.Fatalf("unexpected join ticket payload: %v", ticketBody)
	}
	secret := m[1]

	// Pair outbound using RegisterWithPanel (tests real TLS pinning against panel).
	const agentTok = "pba_joined_node_token"
	_, agentFP := startPinnedMockAgent(t, agentTok)
	rep, _, err := agent.RegisterWithPanel(context.Background(), ts.URL, p.ownFingerprint(), agent.HubRegisterRequest{
		Ticket:      secret,
		Token:       agentTok,
		Port:        4356,
		Fingerprint: agentFP,
		Hostname:    "nl-vps",
		IPv4:        []string{"203.0.113.77"},
		Version:     "v0.17.61",
	})
	if err != nil || !rep.OK || rep.Name != "NL-JoinNode" {
		t.Fatalf("RegisterWithPanel = %+v, err=%v", rep, err)
	}

	// Single-use enforcement: reusing the same ticket must fail.
	if _, _, err := agent.RegisterWithPanel(context.Background(), ts.URL, p.ownFingerprint(), agent.HubRegisterRequest{
		Ticket:      secret,
		Token:       agentTok,
		Port:        4356,
		Fingerprint: agentFP,
		IPv4:        []string{"203.0.113.78"},
	}); err == nil {
		t.Fatalf("expected reused join ticket to be rejected")
	}

	// Ticket status endpoint reports completion to the waiting UI.
	st, pollBody, _ := b.do(http.MethodGet, "/api/join-tickets/"+ticketID, nil, nil)
	if st != http.StatusOK || pollBody["done"] != true || pollBody["server_name"] != "NL-JoinNode" {
		t.Fatalf("unexpected ticket poll state: %d %v", st, pollBody)
	}

	servers := p.store.get().Servers
	if len(servers) != 1 || servers[0].Name != "NL-JoinNode" || !servers[0].CallsPanel {
		t.Fatalf("paired server not saved properly: %+v", servers)
	}
}
