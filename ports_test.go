package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// portHost is a stand-in for the machine: it says which ports are taken and by
// whom, and never touches the real one.
type portHost struct {
	noHost
	taken map[int]string
}

func (h portHost) PortFree(_ Transport, p int) error {
	if _, ok := h.taken[p]; ok {
		return os.ErrExist
	}
	return nil
}

func (h portHost) ListenOwner(p int) string { return h.taken[p] }

func TestParsePortList(t *testing.T) {
	got, err := parsePortList("443, 2053,2083 443\t8443\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{443, 2053, 2083, 8443}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"", "  ", "0", "65536", "80,abc", "-1", "1.5"} {
		if _, err := parsePortList(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	var many []string
	for i := 1; i <= 65; i++ {
		many = append(many, strings.Repeat("1", 1)+string(rune('0'+i%10))+"0"+string(rune('0'+i/10)))
	}
	if _, err := parsePortList(strings.Join(many, ",")); err == nil {
		t.Errorf("65 ports at once were accepted")
	}
}

func writeTunnelClaiming(t *testing.T, dir, name, linkPort, usersPort string) {
	t.Helper()
	text := "name = " + name + "\nmode = direct\nrole = edge\ntunnel_addr = 1.2.3.4:" + linkPort +
		"\nuser_listen = " + usersPort + "\npeer_ip = 1.2.3.4\nsecret_file = /tmp/x\ntransport = plain\n"
	if err := os.WriteFile(filepath.Join(dir, name+".conf"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Busy ports say what has them; a port one of this server's own tunnels is set to
// use is reserved even while that tunnel is stopped; the rest are free.
func TestPortReport(t *testing.T) {
	dir := t.TempDir()
	// A direct edge dials out, so its link port is not listened on here, but its
	// users' port is.
	writeTunnelClaiming(t, dir, "mine", "9999", "2053")
	host := portHost{taken: map[int]string{443: "nginx", 8443: "x-ui"}}

	got := portReport(dir, []int{443, 2053, 2083, 8443, 9999}, host)
	byPort := map[int]portStatus{}
	for _, g := range got {
		byPort[g.Port] = g
	}
	check := func(port int, state, by string) {
		t.Helper()
		g := byPort[port]
		if g.State != state || !strings.Contains(g.By, by) {
			t.Errorf("port %d: got %q %q, want %q containing %q", port, g.State, g.By, state, by)
		}
	}
	check(443, "busy", "nginx")
	check(8443, "busy", "x-ui")
	check(2053, "reserved", "tunnel mine")
	check(2083, "free", "")
	check(9999, "free", "") // a dialling tunnel does not listen on its link port
	if len(got) != 5 {
		t.Errorf("got %d answers for 5 ports", len(got))
	}
}

func TestPortReportNamesATunnelThatIsRunning(t *testing.T) {
	dir := t.TempDir()
	writeTunnelClaiming(t, dir, "live", "9999", "2053")
	host := portHost{taken: map[int]string{2053: "portbridge"}}
	got := portReport(dir, []int{2053}, host)
	if got[0].State != "busy" || !strings.Contains(got[0].By, "PortBridge tunnel live") {
		t.Fatalf("got %+v", got[0])
	}
}

func TestPortLinesAreTabSeparated(t *testing.T) {
	out := portLines([]portStatus{{443, "busy", "nginx"}, {2083, "free", ""}})
	if out != "443\tbusy\tnginx\n2083\tfree\t\n" {
		t.Fatalf("got %q", out)
	}
}

func TestListenOwnerFromSS(t *testing.T) {
	line := `LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2918423,fd=7),("nginx",pid=2918422,fd=7))`
	if got := listenOwnerFromSS(line); got != "nginx" {
		t.Fatalf("got %q", got)
	}
	if got := listenOwnerFromSS("LISTEN 0 4096 *:2931 *:*"); got != "" {
		t.Fatalf("got %q for a line with no program", got)
	}
}

func TestPortsEndpoint(t *testing.T) {
	dir := t.TempDir()
	h := portsHandler("secret-token", dir)

	call := func(method, auth, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/ports", strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	if rec := call(http.MethodGet, "secret-token", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "", `{"ports":"443"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "wrong", `{"ports":"443"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "secret-token", `{"ports":"443,nope"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad list: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "secret-token", `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad body: %d", rec.Code)
	}

	rec := call(http.MethodPost, "secret-token", `{"ports":"443,2083"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("good request: %d %s", rec.Code, rec.Body)
	}
	var res struct {
		OK    bool         `json:"ok"`
		Ports []portStatus `json:"ports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || !res.OK || len(res.Ports) != 2 {
		t.Fatalf("bad answer: %v %s", err, rec.Body)
	}
	if res.Ports[0].Port != 443 || res.Ports[1].Port != 2083 {
		t.Fatalf("answers out of order: %+v", res.Ports)
	}
}

// The client prints what the agent says in the same form as the local command,
// and a server that has no such endpoint is named as too old.
func TestAgentClientPorts(t *testing.T) {
	good := httptest.NewTLSServer(portsHandler("tok", t.TempDir()))
	defer good.Close()

	out := captureStdout(t, func() {
		if err := agentClientPorts(good.URL, "tok", "443,2083", agentTrust{Insecure: true}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.HasPrefix(out, "443\t") || !strings.Contains(out, "\n2083\t") {
		t.Fatalf("got %q", out)
	}

	if err := agentClientPorts(good.URL, "wrong", "443", agentTrust{Insecure: true}); err == nil {
		t.Fatalf("a wrong token was accepted")
	}

	old := httptest.NewTLSServer(http.NotFoundHandler())
	defer old.Close()
	err := agentClientPorts(old.URL, "tok", "443", agentTrust{Insecure: true})
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("an agent without the endpoint should be called too old, got %v", err)
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		b := make([]byte, 0, 1024)
		buf := make([]byte, 1024)
		for {
			n, err := r.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}
