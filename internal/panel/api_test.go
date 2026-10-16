package panel

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

const testPassword = "correct horse battery"

func newTestPanel(t *testing.T) *Panel {
	t.Helper()
	dir := t.TempDir()
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.update(func(s *State) error { s.Admin = Admin{User: "admin", Hash: hash}; return nil }); err != nil {
		t.Fatal(err)
	}
	p := newPanel(dir, Config{Listen: "127.0.0.1:2096"}, st)
	p.tunnelsDir = t.TempDir()
	if err := p.loadSelfCert(); err != nil {
		t.Fatal(err)
	}
	return p
}

func startPanel(t *testing.T, p *Panel) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(p.routes())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{p.selfCert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// browser is a logged-in (or not) visitor to the panel.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func newBrowser(t *testing.T, ts *httptest.Server) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: ts.URL, c: &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}}
}

func (b *browser) do(method, path string, body any, hdr map[string]string) (int, map[string]any, http.Header) {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, b.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.csrf != "" && method != http.MethodGet {
		req.Header.Set(csrfHeader, b.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func (b *browser) login(user, pw string) int {
	b.t.Helper()
	code, out, _ := b.do(http.MethodPost, "/api/login", map[string]string{"user": user, "password": pw}, nil)
	if code == http.StatusOK {
		b.csrf, _ = out["csrf"].(string)
	}
	return code
}

func TestLoggingIn(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)

	if code, _, _ := b.do(http.MethodGet, "/api/me", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("not logged in, /api/me answered %d", code)
	}
	if code, _, _ := b.do(http.MethodGet, "/api/servers", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("not logged in, /api/servers answered %d", code)
	}
	if code := b.login("admin", "wrong password!"); code != http.StatusUnauthorized {
		t.Fatalf("a wrong password answered %d", code)
	}
	if code := b.login("nobody", testPassword); code != http.StatusUnauthorized {
		t.Fatalf("a wrong username answered %d", code)
	}

	code, out, hdr := b.do(http.MethodPost, "/api/login", map[string]string{"user": "admin", "password": testPassword}, nil)
	if code != http.StatusOK || out["csrf"] == "" {
		t.Fatalf("the right login answered %d %v", code, out)
	}
	b.csrf = out["csrf"].(string)
	cookie := hdr.Get("Set-Cookie")
	for _, want := range []string{cookieName + "=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("the session cookie lacks %q: %s", want, cookie)
		}
	}
	code, me, _ := b.do(http.MethodGet, "/api/me", nil, nil)
	if code != http.StatusOK || me["user"] != "admin" || me["csrf"] != b.csrf {
		t.Fatalf("/api/me after logging in: %d %v", code, me)
	}

	if code, _, _ := b.do(http.MethodPost, "/api/logout", nil, nil); code != http.StatusOK {
		t.Fatalf("logging out answered %d", code)
	}
	if code, _, _ := b.do(http.MethodGet, "/api/me", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("still logged in after logging out")
	}
}

func TestChangesNeedThePanelsOwnPage(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	if b.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}
	body := map[string]string{"group": GroupRelay}

	for name, hdr := range map[string]map[string]string{
		"no token":        {csrfHeader: ""},
		"wrong token":     {csrfHeader: "not-the-token"},
		"another site":    {"Origin": "https://evil.example"},
		"cross-site send": {"Sec-Fetch-Site": "cross-site"},
	} {
		if code, _, _ := b.do(http.MethodPatch, "/api/servers/this", body, hdr); code != http.StatusForbidden {
			t.Fatalf("%s: a change was let through (%d)", name, code)
		}
	}
	if p.store.get().ThisGroup != "" {
		t.Fatalf("a refused change was made")
	}
	code, _, _ := b.do(http.MethodPatch, "/api/servers/this", body, map[string]string{"Origin": ts.URL, "Sec-Fetch-Site": "same-origin"})
	if code != http.StatusOK || p.store.get().ThisGroup != GroupRelay {
		t.Fatalf("a proper change was refused (%d)", code)
	}

	// Only JSON is taken, which an ordinary form on another site cannot send.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", strings.NewReader("user=admin&password=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("a form login answered %d", resp.StatusCode)
	}
}

func TestGuessingIsStopped(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	last := 0
	for i := 0; i < lockAfter; i++ {
		last = b.login("admin", "guess number "+string(rune('a'+i)))
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong passwords the answer was %d, not a lock", lockAfter, last)
	}
	if code := b.login("admin", testPassword); code != http.StatusTooManyRequests {
		t.Fatalf("the right password got in while locked (%d)", code)
	}
}

func TestChangingTheLoginLogsEveryoneElseOut(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	a, other := newBrowser(t, ts), newBrowser(t, ts)
	if a.login("admin", testPassword) != http.StatusOK || other.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}

	if code, _, _ := a.do(http.MethodPost, "/api/account",
		map[string]string{"current_password": "not it at all", "new_user": "boss", "new_password": "a brand new password"}, nil); code != http.StatusForbidden {
		t.Fatalf("a wrong current password was accepted (%d)", code)
	}
	if code, _, _ := a.do(http.MethodPost, "/api/account",
		map[string]string{"current_password": testPassword, "new_user": "boss", "new_password": "short"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a short new password was accepted (%d)", code)
	}
	code, out, _ := a.do(http.MethodPost, "/api/account",
		map[string]string{"current_password": testPassword, "new_user": "boss", "new_password": "a brand new password"}, nil)
	if code != http.StatusOK {
		t.Fatalf("changing the login failed: %d %v", code, out)
	}
	a.csrf = out["csrf"].(string)

	if code, _, _ := other.do(http.MethodGet, "/api/me", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("another browser stayed logged in after the change")
	}
	if code, me, _ := a.do(http.MethodGet, "/api/me", nil, nil); code != http.StatusOK || me["user"] != "boss" {
		t.Fatalf("the browser that made the change was logged out: %d %v", code, me)
	}
	fresh := newBrowser(t, ts)
	if fresh.login("admin", testPassword) == http.StatusOK {
		t.Fatalf("the old login still works")
	}
	if fresh.login("boss", "a brand new password") != http.StatusOK {
		t.Fatalf("the new login does not work")
	}
}

func TestServersCanBeRenamedMovedAndRemoved(t *testing.T) {
	p := newTestPanel(t)
	_ = p.store.update(func(s *State) error {
		s.Servers = append(s.Servers, Server{ID: "s1", Name: "one", Group: GroupForeign, Address: "203.0.113.1"})
		return nil
	})
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	if b.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}

	if code, _, _ := b.do(http.MethodPatch, "/api/servers/s1", map[string]string{"name": "Aeza", "group": GroupRelay}, nil); code != http.StatusOK {
		t.Fatalf("renaming answered %d", code)
	}
	if s := p.store.get().Servers[0]; s.Name != "Aeza" || s.Group != GroupRelay {
		t.Fatalf("not renamed and moved: %+v", s)
	}
	if code, _, _ := b.do(http.MethodPatch, "/api/servers/s1", map[string]string{"group": "elsewhere"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a made-up group was accepted (%d)", code)
	}
	if code, _, _ := b.do(http.MethodPatch, "/api/servers/nope", map[string]string{"name": "x"}, nil); code != http.StatusNotFound {
		t.Fatalf("renaming a server that is not there answered %d", code)
	}
	code, list, _ := b.do(http.MethodGet, "/api/servers", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("listing answered %d", code)
	}
	servers := list["servers"].([]any)
	if len(servers) != 2 || servers[0].(map[string]any)["this"] != true {
		t.Fatalf("the list should be this server first, then one more: %v", servers)
	}

	if code, _, _ := b.do(http.MethodDelete, "/api/servers/this", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("the panel's own server could be removed (%d)", code)
	}
	if code, _, _ := b.do(http.MethodDelete, "/api/servers/s1", nil, nil); code != http.StatusOK {
		t.Fatalf("removing answered %d", code)
	}
	if len(p.store.get().Servers) != 0 {
		t.Fatalf("the server is still there")
	}
}

func TestAddingRefusesWhatCannotWork(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	if b.login("admin", testPassword) != http.StatusOK {
		t.Fatal("could not log in")
	}
	for name, req := range map[string]map[string]any{
		"no group":    {"address": "203.0.113.1", "password": "x"},
		"no address":  {"group": "relay", "password": "x"},
		"no login":    {"group": "relay", "address": "203.0.113.1"},
		"bad port":    {"group": "relay", "address": "203.0.113.1", "password": "x", "ssh_port": 70000},
		"odd address": {"group": "relay", "address": "root@203.0.113.1", "password": "x"},
	} {
		if code, out, _ := b.do(http.MethodPost, "/api/servers", req, nil); code != http.StatusBadRequest || out["error"] == "" {
			t.Fatalf("%s: answered %d %v", name, code, out)
		}
	}
	if code, _, _ := b.do(http.MethodPost, "/api/servers", map[string]any{"group": "relay", "surprise": 1}, nil); code != http.StatusBadRequest {
		t.Fatalf("an unknown field was accepted (%d)", code)
	}
}

func TestThePageIsServedSafely(t *testing.T) {
	p := newTestPanel(t)
	ts := startPanel(t, p)
	b := newBrowser(t, ts)
	for path, ctype := range map[string]string{
		"/": "text/html", "/app.js": "text/javascript", "/app.css": "text/css", "/icon.svg": "image/svg+xml",
	} {
		resp, err := b.c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), ctype) || len(body) == 0 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s: weak content policy %q", path, csp)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: missing protective headers", path)
		}
	}
	// The page has no script of its own inline, which the policy would block.
	resp, _ := b.c.Get(ts.URL + "/")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(page), "<script>") || strings.Contains(string(page), " onclick=") {
		t.Fatalf("the page has inline script")
	}
	for _, path := range []string{"/nope", "/web/app.js", "/../panel.go"} {
		resp, err := b.c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s answered %d", path, resp.StatusCode)
		}
	}
}
