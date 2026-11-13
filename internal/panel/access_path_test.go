package panel

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeBasePath(t *testing.T) {
	valid := map[string]string{
		"":            "",
		"/":           "",
		"off":         "",
		"OFF":         "",
		"none":        "",
		"k9x4m2":      "/k9x4m2",
		"/k9x4m2/":    "/k9x4m2",
		"my_panel-01": "/my_panel-01",
		"sec/sub2":    "/sec/sub2",
	}
	for in, want := range valid {
		got, err := normalizeBasePath(in)
		if err != nil || got != want {
			t.Fatalf("normalizeBasePath(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}

	rnd, err := normalizeBasePath("random")
	if err != nil || !strings.HasPrefix(rnd, "/") || len(rnd) != 11 {
		t.Fatalf("normalizeBasePath(\"random\") = (%q, %v)", rnd, err)
	}

	invalid := []string{
		"api", "/api", "API/v1", "hub", "/hub/poll",
		"app.js", "app.css", "icon.svg", "index.html", ".well-known",
		"../secret", "a//b", "has space", "bad$char",
		"a/b/c/d",
		strings.Repeat("x", 65),
	}
	for _, in := range invalid {
		if got, err := normalizeBasePath(in); err == nil {
			t.Fatalf("normalizeBasePath(%q) unexpectedly succeeded with %q", in, got)
		}
	}
}

func TestAddressesForIncludesSecretPath(t *testing.T) {
	cfg := Config{
		Listen:    ":2096",
		Domain:    "panel.example.com",
		BasePath:  "/k9x4m2",
		PublicURL: "https://203.0.113.5:2096",
	}
	got := addressesFor(cfg)
	if len(got) != 2 || got[0] != "https://panel.example.com:2096/k9x4m2/" || got[1] != "https://203.0.113.5:2096/k9x4m2/" {
		t.Fatalf("addressesFor with BasePath = %v", got)
	}
	// Agent callback URLs must stay at root (never include BasePath) so /hub/poll works.
	if pub := publicURLFor(cfg); pub != "https://203.0.113.5:2096" {
		t.Fatalf("publicURLFor = %q, want root URL without BasePath", pub)
	}
}

func TestLivePanelDomainAndSecretPathUpdate(t *testing.T) {
	p := newTestPanel(t)
	if err := writeConfig(p.dir, p.getConfig()); err != nil {
		t.Fatal(err)
	}
	ts := startPanel(t, p)
	b := newBrowser(t, ts)

	if code := b.login("admin", testPassword); code != http.StatusOK {
		t.Fatalf("initial login at / failed: %d", code)
	}

	// Verify GET /api/panel initially shows empty domain and base_path.
	code, info, _ := b.do(http.MethodGet, "/api/panel", nil, nil)
	if code != http.StatusOK || info["domain"] != "" || info["base_path"] != "" {
		t.Fatalf("initial /api/panel = %d %v", code, info)
	}

	// Reject invalid domain or reserved base_path.
	code, _, _ = b.do(http.MethodPost, "/api/panel/access", map[string]any{
		"domain":    "not_a_domain",
		"base_path": "k9x4m2",
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid domain, got %d", code)
	}
	code, _, _ = b.do(http.MethodPost, "/api/panel/access", map[string]any{
		"domain":    "cp.example.com",
		"base_path": "api",
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reserved base_path 'api', got %d", code)
	}

	// Live update: set domain, email, and secret path /k9x4m2!
	code, updated, _ := b.do(http.MethodPost, "/api/panel/access", map[string]any{
		"domain":     "cp.example.com",
		"email":      "ops@example.com",
		"base_path":  "k9x4m2",
		"retry_cert": true,
	}, nil)
	if code != http.StatusOK || updated["domain"] != "cp.example.com" || updated["base_path"] != "/k9x4m2" {
		t.Fatalf("POST /api/panel/access = %d %v", code, updated)
	}

	// Verify persisted to panel.conf on disk.
	savedCfg, err := readConfig(p.dir)
	if err != nil {
		t.Fatalf("readConfig after update: %v", err)
	}
	if savedCfg.Domain != "cp.example.com" || savedCfg.Email != "ops@example.com" || savedCfg.BasePath != "/k9x4m2" {
		t.Fatalf("persisted panel.conf mismatch: %+v", savedCfg)
	}

	// Verify p.certs was dynamically initialized for cp.example.com without restart.
	if c := p.activeCerts(); c == nil || c.domain != "cp.example.com" {
		t.Fatalf("expected activeCerts for cp.example.com, got %+v", c)
	}

	// Root paths (/, /app.js, /api/me) must now return plain 404 Not Found with no PortBridge CSP header!
	rawClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	for _, probePath := range []string{"/", "/app.js", "/api/me", "/api/login", "/k9x4m2extra"} {
		resp, err := rawClient.Get(ts.URL + probePath)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("scanner probe %s got %d, want 404", probePath, resp.StatusCode)
		}
		if resp.Header.Get("Content-Security-Policy") != "" {
			t.Fatalf("scanner probe %s leaked CSP header: %q", probePath, resp.Header.Get("Content-Security-Policy"))
		}
		if strings.Contains(strings.ToLower(string(body)), "portbridge") {
			t.Fatalf("scanner probe %s leaked 'portbridge' in 404 body", probePath)
		}
	}

	// Exact /k9x4m2 (without trailing slash) redirects to /k9x4m2/.
	redirResp, err := rawClient.Get(ts.URL + "/k9x4m2")
	if err != nil {
		t.Fatal(err)
	}
	redirResp.Body.Close()
	if redirResp.StatusCode != http.StatusTemporaryRedirect || redirResp.Header.Get("Location") != "/k9x4m2/" {
		t.Fatalf("GET /k9x4m2 = %d Location=%q, want 307 /k9x4m2/", redirResp.StatusCode, redirResp.Header.Get("Location"))
	}

	// Opening /k9x4m2/ and /k9x4m2/app.js serves the real panel HTML and JS!
	pageResp, err := rawClient.Get(ts.URL + "/k9x4m2/")
	if err != nil {
		t.Fatal(err)
	}
	pageHTML, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	if pageResp.StatusCode != http.StatusOK || !strings.Contains(string(pageHTML), "<title>PortBridge</title>") {
		t.Fatalf("GET /k9x4m2/ = %d", pageResp.StatusCode)
	}
	jsResp, err := rawClient.Get(ts.URL + "/k9x4m2/app.js")
	if err != nil {
		t.Fatal(err)
	}
	jsResp.Body.Close()
	if jsResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /k9x4m2/app.js = %d", jsResp.StatusCode)
	}

	// Existing admin session cookie (__Host-pb_session, Path=/) STILL authenticates seamlessly under /k9x4m2/api/...!
	code, meOut, _ := b.do(http.MethodGet, "/k9x4m2/api/me", nil, nil)
	if code != http.StatusOK || meOut["user"] != "admin" {
		t.Fatalf("authenticated GET /k9x4m2/api/me after live path change = %d %v", code, meOut)
	}

	//Meanwhile, remote callback agents hitting root /hub/poll STILL reach the hub (401 without agent token, NOT 404)!
	hubResp, err := rawClient.Get(ts.URL + "/hub/poll")
	if err != nil {
		t.Fatal(err)
	}
	hubResp.Body.Close()
	if hubResp.StatusCode == http.StatusNotFound {
		t.Fatalf("/hub/poll returned 404 when BasePath was enabled — callback agents would disconnect!")
	}

	// Now clear both domain and base_path ("off") from under /k9x4m2/api/panel/access and confirm / works again!
	code, cleared, _ := b.do(http.MethodPost, "/k9x4m2/api/panel/access", map[string]any{
		"domain":    "off",
		"email":     "off",
		"base_path": "off",
	}, nil)
	if code != http.StatusOK || cleared["domain"] != "" || cleared["base_path"] != "" {
		t.Fatalf("clearing domain & base_path = %d %v", code, cleared)
	}
	if p.activeCerts() != nil {
		t.Fatalf("expected activeCerts to be nil after clearing domain")
	}
	if code, _, _ := b.do(http.MethodGet, "/api/me", nil, nil); code != http.StatusOK {
		t.Fatalf("root /api/me after clearing base_path = %d, want 200", code)
	}
}
