package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordingHost stands in for the machine and remembers what it was asked to do.
type recordingHost struct {
	calls       []string
	enableErr   error
	activeAfter bool // what Active reports
	portErr     error
}

func (h *recordingHost) note(s string) { h.calls = append(h.calls, s) }

func (h *recordingHost) PortFree(Transport, int) error { h.note("port"); return h.portErr }
func (h *recordingHost) FirewallApply(n string) error  { h.note("fw+" + n); return nil }
func (h *recordingHost) FirewallRemove(n string) error { h.note("fw-" + n); return nil }
func (h *recordingHost) Reload() error                 { h.note("reload"); return nil }
func (h *recordingHost) Enable(n string) error         { h.note("enable " + n); return h.enableErr }
func (h *recordingHost) Disable(n string) error        { h.note("disable " + n); return nil }
func (h *recordingHost) Active(n string) (bool, string) {
	h.note("active " + n)
	return h.activeAfter, "crash looping"
}
func (h *recordingHost) RemoveRuntime(n string) { h.note("runtime- " + n) }

func (h *recordingHost) did(s string) bool {
	for _, c := range h.calls {
		if c == s {
			return true
		}
	}
	return false
}

func withHost(t *testing.T, h agentHost) {
	t.Helper()
	old, oldSettle := agentHostOverride, serviceStartSettle
	agentHostOverride, serviceStartSettle = h, time.Millisecond
	t.Cleanup(func() { agentHostOverride, serviceStartSettle = old, oldSettle })
}

func goodPairing(name string) *PairingData {
	return &PairingData{
		Version: "6", Name: name, Mode: "direct", TunnelPort: "8443", RelayIP: "1.1.1.1",
		ServerIP: "2.2.2.2", InboundPort: "8080", Pool: "10", Transport: "plain",
		Mux: "off", MuxLinks: "4", CDN: "off", Secret: "0123456789abcdef0123456789abcdef",
	}
}

// Running tests must never touch the real machine: only the real settings
// directory gets the real host.
func TestOnlyTheRealDirectoryGetsTheRealHost(t *testing.T) {
	if _, ok := hostFor(t.TempDir()).(noHost); !ok {
		t.Fatalf("a temporary directory was given the real host")
	}
	if _, ok := hostFor(defaultTunnelsDir).(systemHost); !ok {
		t.Fatalf("the real directory was not given the real host")
	}
}

func TestTunnelNamesAreChecked(t *testing.T) {
	bad := []string{"", "../x", "a/b", "a b", "a;b", strings.Repeat("a", 41), "x\ny", "..", "a.b"}
	for _, n := range bad {
		if err := validTunnelName(n); err == nil {
			t.Errorf("name %q was accepted", n)
		}
		if err := applyPairingData(goodPairing(n), t.TempDir()); err == nil {
			t.Errorf("a pairing with name %q was applied", n)
		}
		if err := deleteTunnel(n, t.TempDir()); err == nil {
			t.Errorf("deleting name %q was allowed", n)
		}
	}
	for _, n := range []string{"n", "my-tunnel_2", "A1"} {
		if err := validTunnelName(n); err != nil {
			t.Errorf("name %q was refused: %v", n, err)
		}
	}
}

func TestDeleteCannotEscapeTheDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "tunnels")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(parent, "victim.conf")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = deleteTunnel("../victim", dir)
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("a file outside the directory was removed")
	}
}

func TestExistingTunnelIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := applyPairingData(goodPairing("keep"), dir); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "keep.secret"))

	other := goodPairing("keep")
	other.Secret = "ffffffffffffffffffffffffffffffff"
	if err := applyPairingData(other, dir); err == nil {
		t.Fatalf("a second tunnel with the same name was accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "keep.secret"))
	if string(before) != string(after) {
		t.Fatalf("the existing secret was overwritten")
	}
}

func TestBadValuesAreRefusedBeforeAnythingIsWritten(t *testing.T) {
	cases := map[string]func(*PairingData){
		"port":        func(p *PairingData) { p.TunnelPort = "99999" },
		"mode":        func(p *PairingData) { p.Mode = "sideways" },
		"transport":   func(p *PairingData) { p.Transport = "carrier-pigeon" },
		"server name": func(p *PairingData) { p.Transport = "wss"; p.ServerName = "a b;c" },
		"ws path":     func(p *PairingData) { p.Transport = "wss"; p.WSPath = "no-slash" },
		"short key":   func(p *PairingData) { p.Secret = "short" },
		"spaced key":  func(p *PairingData) { p.Secret = "0123456789 abcdef0123" },
		"clean ip":    func(p *PairingData) { p.CleanIPs = "not-an-ip" },
		"mux":         func(p *PairingData) { p.Mux = "maybe" },
		"reverse ip":  func(p *PairingData) { p.Mode = "reverse"; p.RelayIP = "" },
	}
	for name, mutate := range cases {
		dir := t.TempDir()
		p := goodPairing("t")
		mutate(p)
		if err := applyPairingData(p, dir); err == nil {
			t.Errorf("%s: bad value accepted", name)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: files were left behind: %v", name, entries)
		}
	}
}

func TestFailureToStartUndoesEverything(t *testing.T) {
	h := &recordingHost{enableErr: errors.New("boom")}
	withHost(t, h)
	dir := t.TempDir()

	if err := applyPairingData(goodPairing("fails"), dir); err == nil {
		t.Fatalf("a service that could not start was reported as deployed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files were left behind: %v", entries)
	}
	if !h.did("disable fails") || !h.did("fw-fails") {
		t.Fatalf("the service and firewall were not cleaned up: %v", h.calls)
	}
}

func TestServiceThatCrashLoopsIsNotReportedAsStarted(t *testing.T) {
	h := &recordingHost{activeAfter: false}
	withHost(t, h)
	dir := t.TempDir()

	err := applyPairingData(goodPairing("loops"), dir)
	if err == nil || !strings.Contains(err.Error(), "did not stay running") {
		t.Fatalf("expected a did-not-stay-running error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "loops.conf")); !os.IsNotExist(statErr) {
		t.Fatalf("the settings of a tunnel that cannot run were kept")
	}
}

func TestSuccessfulDeployAndDeleteDriveTheHost(t *testing.T) {
	h := &recordingHost{activeAfter: true}
	withHost(t, h)
	dir := t.TempDir()

	if err := applyPairingData(goodPairing("fine"), dir); err != nil {
		t.Fatal(err)
	}
	if !h.did("enable fine") || !h.did("fw+fine") {
		t.Fatalf("host calls: %v", h.calls)
	}
	if err := deleteTunnel("fine", dir); err != nil {
		t.Fatal(err)
	}
	if !h.did("disable fine") || !h.did("fw-fine") {
		t.Fatalf("host calls after delete: %v", h.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "fine.conf")); !os.IsNotExist(err) {
		t.Fatalf("settings remain after delete")
	}
}

func TestBusyPortStopsDirectDeploy(t *testing.T) {
	h := &recordingHost{activeAfter: true, portErr: errors.New("port 8443 is already in use")}
	withHost(t, h)
	dir := t.TempDir()
	if err := applyPairingData(goodPairing("busy"), dir); err == nil {
		t.Fatalf("a busy port did not stop the deployment")
	}
	if h.did("enable busy") {
		t.Fatalf("the service was started on a busy port")
	}
}

func encodeCode(fields string) string {
	return base64.StdEncoding.EncodeToString([]byte(fields))
}

func TestNewerPairingCodeIsRefusedByName(t *testing.T) {
	_, err := decodePairingCode(encodeCode("v=9\nname=x\nmode=direct\ntunnel_port=1\nsecret=0123456789abcdef\n"))
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("got %v", err)
	}
}

func TestVersion6CarriesTheStealthSettings(t *testing.T) {
	code := encodeCode("v=6\nname=cdn\nmode=reverse\ntunnel_port=443\nrelay_ip=1.2.3.4\ninbound_port=80\n" +
		"transport=wss\nserver_name=front.example.org\nws_path=/t\ncdn=on\nutls=on\ntls_fragment=on\n" +
		"clean_ips=198.51.100.1,198.51.100.2\nsecret=0123456789abcdef0123456789abcdef\n")
	p, err := decodePairingCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if p.UTLS != "on" || p.TLSFragment != "on" || p.CleanIPs != "198.51.100.1,198.51.100.2" {
		t.Fatalf("stealth fields lost: %+v", p)
	}

	dir := t.TempDir()
	if err := applyPairingData(p, dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(filepath.Join(dir, "cdn.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UTLS || !cfg.TLSFragment || len(cfg.CleanIPs) != 2 {
		t.Fatalf("the settings file lost them: utls=%v frag=%v clean=%v", cfg.UTLS, cfg.TLSFragment, cfg.CleanIPs)
	}
}

func TestPinnedFingerprintRefusesTheWrongCertificate(t *testing.T) {
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen")
	}
	addr := l.Addr().String()
	_ = l.Close()
	go func() {
		_ = runAgentServer(addr, "tok", filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key"), dir)
	}()
	var fp string
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if fp, err = fetchAgentFingerprint("https://" + addr); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("agent never came up: %v", err)
	}

	wrong := strings.Repeat("00:", 31) + "00"
	if err := agentClientStatus("https://"+addr, "tok", agentTrust{Fingerprint: wrong}); err == nil {
		t.Fatalf("a certificate with the wrong fingerprint was accepted")
	}
	// No pin and no explicit opt-out: a self-signed certificate is refused, with
	// advice on what to do.
	err = agentClientStatus("https://"+addr, "tok", agentTrust{})
	if err == nil || !strings.Contains(err.Error(), "-fingerprint") {
		t.Fatalf("an unverified agent was not refused with advice: %v", err)
	}
	if err := agentClientStatus("https://"+addr, "tok", agentTrust{Fingerprint: strings.ToUpper(strings.ReplaceAll(fp, ":", ""))}); err != nil {
		t.Fatalf("the right fingerprint, written differently, was refused: %v", err)
	}
}

// An agent reached by IP address must be asked for by an ordinary name: on a real
// route out of Iran a handshake with no name was reset at once, while the same
// one carrying a name was answered. An agent with a real name keeps it, since a
// CDN in front of it routes by that.
func TestAgentHandshakeAlwaysCarriesAName(t *testing.T) {
	cases := map[string]string{
		"https://79.137.202.176:3333":    agentDisguiseName,
		"https://[2001:db8::1]:2083":     agentDisguiseName,
		"https://agent.example.org:2083": "agent.example.org",
		"https://agent.example.org":      "agent.example.org",
		"not a url \x7f":                 agentDisguiseName,
	}
	for in, want := range cases {
		if got := agentSNI(in); got != want {
			t.Errorf("agentSNI(%q) = %q, want %q", in, got, want)
		}
	}
}

// The name is actually sent, both when fetching the fingerprint and when calling
// the agent.
func TestAgentClientSendsAName(t *testing.T) {
	dir := t.TempDir()
	cert, err := ensureCert(filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key"), "portbridge-agent")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 4)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			seen <- h.ServerName
			return nil, nil
		},
	})
	if err != nil {
		t.Skip("cannot listen")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()

	url := "https://" + ln.Addr().String()
	if _, err := fetchAgentFingerprint(url); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != agentDisguiseName {
		t.Fatalf("fingerprint fetch sent the name %q", got)
	}

	_ = agentClientStatus(url, "tok", agentTrust{Fingerprint: certFingerprint(cert)})
	if got := <-seen; got != agentDisguiseName {
		t.Fatalf("agent call sent the name %q", got)
	}
}
