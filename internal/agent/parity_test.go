package agent

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/engine"
)

// The menu writes settings files and pairing codes in shell, the engine reads
// them in Go, and nothing but convention kept the two in agreement. A setting
// the menu wrote under a name the engine did not know would stop a tunnel from
// starting; a field the menu put in a code and the engine ignored would be
// silently lost. These tests read the menu's own text and hold both to account.

func readMenu(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../scripts/portbridge-menu")
	if err != nil {
		t.Skipf("menu not available: %v", err)
	}
	return string(b)
}

// Every setting name the menu writes must be one the engine accepts.
func TestMenuOnlyWritesSettingsTheEngineKnows(t *testing.T) {
	menu := readMenu(t)

	keys := map[string]bool{}
	// printf 'key = %s\n' ... inside the settings writer
	for _, m := range regexp.MustCompile(`printf '(?:\\n)?([a-z_]+) = `).FindAllStringSubmatch(menu, -1) {
		keys[m[1]] = true
	}
	// write_conf "$name" key value
	for _, m := range regexp.MustCompile(`write_conf "\$[a-z_]+" ([a-z_]+) `).FindAllStringSubmatch(menu, -1) {
		keys[m[1]] = true
	}
	if len(keys) < 15 {
		t.Fatalf("only found %d settings in the menu; the pattern no longer matches it", len(keys))
	}

	// Settings the menu reads or writes for its own purposes, which the engine
	// is told about through other means or does not need.
	menuOnly := map[string]bool{"foreign_agent": false}

	for k := range keys {
		cfg := engine.DefaultConfig()
		err := cfg.Set(k, "1")
		if err != nil && strings.Contains(err.Error(), "unknown setting") {
			if _, ok := menuOnly[k]; ok {
				continue
			}
			t.Errorf("the menu writes %q, which the engine does not know", k)
		}
	}
}

// menuFunction returns one shell function from the menu, from its first line to
// the closing brace at the start of a line.
func menuFunction(t *testing.T, menu, name string) string {
	t.Helper()
	start := strings.Index(menu, "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("could not find %s in the menu", name)
	}
	body := menu[start+1:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatalf("could not find the end of %s in the menu", name)
	}
	return body[:end+3]
}

// menuCodeKeys lists the lines the menu can put in a pairing code: those every
// code has, from the one format string, and the optional ones, from the blocks
// that add them.
func menuCodeKeys(t *testing.T, menu string) (always, optional []string) {
	t.Helper()
	fn := menuFunction(t, menu, "make_pairing_code")
	m := regexp.MustCompile(`printf 'v=%s\\n([^']*)'`).FindStringSubmatch(fn)
	if m == nil {
		t.Fatalf("could not find the code format in make_pairing_code")
	}
	always = []string{"v"}
	slot := false
	for _, part := range strings.Split(m[1], `\n`) {
		// The optional lines go in at a bare %s, just before the password.
		if rest, ok := strings.CutPrefix(part, "%s"); ok {
			slot, part = true, rest
		}
		if k, _, ok := strings.Cut(part, "="); ok && k != "" {
			always = append(always, k)
		}
	}
	if !slot {
		t.Fatalf("the code format in make_pairing_code has no place for the optional lines")
	}
	key := regexp.MustCompile(`"([a-z_]+)=`)
	for _, line := range strings.Split(fn, "\n") {
		if !strings.Contains(line, "extra+=") {
			continue
		}
		for _, k := range key.FindAllStringSubmatch(line, -1) {
			optional = append(optional, k[1])
		}
	}
	if len(optional) == 0 {
		t.Fatalf("found no optional lines in make_pairing_code; the pattern no longer matches it")
	}
	return always, optional
}

// The lines of a pairing code: what the menu writes, what its own "Join a
// tunnel" reads, and what the engine reads must all be the same list, so that
// nothing put in a code is lost on the other side.
func TestPairingCodeFieldsMatch(t *testing.T) {
	menu := readMenu(t)
	always, optional := menuCodeKeys(t, menu)

	// Every code has these, in this order. Changing them changes every code.
	wantAlways := []string{
		"v", "name", "mode", "tunnel_port", "relay_ip", "server_ip", "inbound_port", "pool",
		"transport", "server_name", "ws_path", "cdn", "alt_host", "mux", "mux_links",
		"utls", "tls_fragment", "clean_ips", "secret",
	}
	if strings.Join(always, ",") != strings.Join(wantAlways, ",") {
		t.Fatalf("every code carries %v\nexpected %v", always, wantAlways)
	}
	wantOptional := []string{"http_header", "http_host", "gre", "real_site", "cover_site", "proxy_protocol"}
	if strings.Join(optional, ",") != strings.Join(wantOptional, ",") {
		t.Fatalf("the optional lines are %v\nexpected %v", optional, wantOptional)
	}
	written := map[string]bool{}
	for _, k := range append(append([]string{}, always...), optional...) {
		written[k] = true
	}

	engineSrc, err := os.ReadFile("agent.go")
	if err != nil {
		t.Fatal(err)
	}
	engine := map[string]bool{}
	for _, m := range regexp.MustCompile(`kv\["([a-z_]+)"\]`).FindAllStringSubmatch(string(engineSrc), -1) {
		engine[m[1]] = true
	}
	join := map[string]bool{}
	for _, m := range regexp.MustCompile(`\$\(get ([a-z_]+)\)`).FindAllStringSubmatch(menuFunction(t, menu, "join_tunnel"), -1) {
		join[m[1]] = true
	}

	// Lines the engine understands that the menu never writes, and why.
	engineOnly := map[string]string{
		"ech":         "the engine turns it on by itself for a CDN route; nothing in the menu sets it",
		"sni_spoof":   "configured from the web panel and engine",
		"spoof_sni":   "configured from the web panel and engine",
		"ip_spoof":    "configured from the web panel and engine",
		"spoof_ip":    "configured from the web panel and engine",
		"sit":         "configured from the web panel and engine",
		"anti_freeze": "configured from the web panel and engine",
	}

	for k := range written {
		if !engine[k] {
			t.Errorf("the menu writes %q into codes, but the engine never reads it", k)
		}
		if !join[k] {
			t.Errorf(`the menu writes %q into codes, but "Join a tunnel" never reads it`, k)
		}
	}
	for k := range engine {
		if _, ok := engineOnly[k]; !written[k] && !ok {
			t.Errorf("the engine reads %q from codes, but the menu never writes it", k)
		}
	}
	for k := range join {
		if !written[k] {
			t.Errorf(`"Join a tunnel" reads %q from codes, but the menu never writes it`, k)
		}
	}
}

// Every kind of code the menu makes must also be accepted when it is pasted into
// "Join a tunnel" on the other server, and by the engine. Version 9 was once made
// by the menu and refused by its own join, which only the agent's automatic setup
// hid: the agent reads codes in the engine, and the engine already knew 9.
func TestMenuAcceptsEveryCodeItMakes(t *testing.T) {
	menu := readMenu(t)

	m := regexp.MustCompile(`(?m)^PAIRING_VERSION_MAX=(\d+)$`).FindStringSubmatch(menu)
	if m == nil {
		t.Fatalf("could not find PAIRING_VERSION_MAX in the menu")
	}
	menuMax, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("PAIRING_VERSION_MAX is not a number: %q", m[1])
	}
	if menuMax != pairingVersionMax {
		t.Fatalf("the menu accepts codes up to version %d, the engine up to %d", menuMax, pairingVersionMax)
	}

	// Every version make_pairing_code can give a code: where it starts, and each
	// one an optional setting raises it to.
	newest := 0
	fn := menuFunction(t, menu, "make_pairing_code")
	for _, w := range regexp.MustCompile(`\bv=(\d+)\b`).FindAllStringSubmatch(fn, -1) {
		v, _ := strconv.Atoi(w[1])
		if v > menuMax {
			t.Errorf("the menu makes version %d codes but its join accepts only up to %d", v, menuMax)
		}
		if v > newest {
			newest = v
		}
	}
	if newest == 0 {
		t.Fatalf("found no versions in make_pairing_code; the pattern no longer matches it")
	}
	if newest != menuMax {
		t.Errorf("the newest code the menu makes is version %d, but PAIRING_VERSION_MAX says %d", newest, menuMax)
	}

	// The join must compare against that one number rather than keep a list of
	// its own, which is how version 9 was left out.
	if !strings.Contains(menu, `-gt "$PAIRING_VERSION_MAX"`) {
		t.Errorf(`"Join a tunnel" no longer checks codes against PAIRING_VERSION_MAX`)
	}
}

// menuShell finds a shell that can run the menu's own functions, or skips. A
// bash that cannot even run "printf | base64" (Windows has a bash.exe that only
// starts WSL) counts as none.
func menuShell(t *testing.T) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}
	out, err := exec.Command(bash, "-c", "printf ok | base64 | tr -d '\\n'").Output()
	if err != nil || string(out) != "b2s=" {
		t.Skip("bash here cannot run the menu's functions")
	}
	return bash
}

// runMakePairingCode runs the menu's own make_pairing_code with these arguments
// and returns the code it makes, decoded.
func runMakePairingCode(t *testing.T, bash, fn string, args []string) string {
	t.Helper()
	cmd := exec.Command(bash, append([]string{"-c", fn + "\nmake_pairing_code \"$@\"\n", "make_pairing_code"}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("make_pairing_code %v: %v", args, err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		t.Fatalf("make_pairing_code made something that is not base64: %q", out)
	}
	return string(raw)
}

// The codes the menu makes, run for real: a tunnel with any one setting gets
// exactly the code it always did, settings can travel together in one code,
// and the engine reads back every one of them.
func TestMenuCodesAreUnchangedAndCombine(t *testing.T) {
	bash := menuShell(t)
	fn := menuFunction(t, readMenu(t), "make_pairing_code")

	const secret = "0123456789abcdef0123456789abcdef"
	// The arguments get_tunnel_pairing_code passes, in its order. The real-address
	// setting is optional at the end, as it is for a menu that predates it.
	args := func(transport, header, headerHost, gre, realSite, coverSite string, proxy ...string) []string {
		return append([]string{"t1", "direct", "443", "1.2.3.4", "5.6.7.8", "80", "25", secret,
			transport, "www.bing.com", "", "off", "off", "4", "", "", "", "",
			header, headerHost, gre, realSite, coverSite}, proxy...)
	}
	code := func(v int, transport, extra string) string {
		return fmt.Sprintf("v=%d\nname=t1\nmode=direct\ntunnel_port=443\nrelay_ip=1.2.3.4\nserver_ip=5.6.7.8\n"+
			"inbound_port=80\npool=25\ntransport=%s\nserver_name=www.bing.com\nws_path=\ncdn=off\nalt_host=\n"+
			"mux=off\nmux_links=4\nutls=\ntls_fragment=\nclean_ips=\n%ssecret=%s\n", v, transport, extra, secret)
	}

	cases := []struct {
		name string
		args []string
		want string
	}{
		// Each of these is the code the menu has always made for such a tunnel.
		{"nothing optional", args("plain", "", "", "", "", ""), code(6, "plain", "")},
		{"settings off", args("tls", "off", "", "off", "off", ""), code(6, "tls", "")},
		{"web header", args("plain", "on", "", "", "", ""), code(7, "plain", "http_header=on\nhttp_host=www.bing.com\n")},
		{"web header, own name", args("plain", "on", "cdn.example.org", "", "", ""), code(7, "plain", "http_header=on\nhttp_host=cdn.example.org\n")},
		{"GRE", args("plain", "", "", "on", "", ""), code(8, "plain", "gre=on\n")},
		{"real website", args("tls", "", "", "", "on", ""), code(9, "tls", "real_site=on\n")},
		// A cover site is carried with the real website, and only with it.
		{"real website, own cover site", args("tls", "", "", "", "on", "www.example.org:8443"), code(9, "tls", "real_site=on\ncover_site=www.example.org:8443\n")},
		{"cover site without real website", args("tls", "", "", "", "", "www.example.org"), code(6, "tls", "")},
		// Together: every line is there, and the version is the highest of them.
		{"web header with GRE", args("plain", "on", "", "on", "", ""), code(8, "plain", "http_header=on\nhttp_host=www.bing.com\ngre=on\n")},
		// Users' real addresses: version 10, and only when it is on.
		{"real address off", args("tls", "", "", "", "on", "", "off"), code(9, "tls", "real_site=on\n")},
		{"real address", args("plain", "", "", "", "", "", "v1"), code(10, "plain", "proxy_protocol=v1\n")},
		{"real address, version 2", args("plain", "", "", "", "", "", "v2"), code(10, "plain", "proxy_protocol=v2\n")},
		{"real address with the real website", args("tls", "", "", "", "on", "", "v1"), code(10, "tls", "real_site=on\nproxy_protocol=v1\n")},
		{"real address with the web header and GRE", args("plain", "on", "", "on", "", "", "v1"),
			code(10, "plain", "http_header=on\nhttp_host=www.bing.com\ngre=on\nproxy_protocol=v1\n")},
		{"real address, nonsense", args("plain", "", "", "", "", "", "on"), code(6, "plain", "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runMakePairingCode(t, bash, fn, tc.args)
			if got != tc.want {
				t.Fatalf("the menu made\n%s\nexpected\n%s", got, tc.want)
			}
			p, err := decodePairingCode(base64.StdEncoding.EncodeToString([]byte(got)))
			if err != nil {
				t.Fatalf("the engine refused the code: %v", err)
			}
			for k, v := range map[string]string{
				"http_header": p.HTTPHeader, "http_host": p.HTTPHost, "gre": p.GRE,
				"real_site": p.RealSite, "cover_site": p.CoverSite, "proxy_protocol": p.ProxyProtocol,
			} {
				if line := k + "=" + v + "\n"; v != "" && !strings.Contains(got, line) {
					t.Errorf("the engine read %s=%q, which is not in the code", k, v)
				} else if v == "" && strings.Contains(got, "\n"+k+"=") {
					t.Errorf("the engine lost %s from the code", k)
				}
			}
		})
	}

	// A combined code is not only read but accepted, and both settings reach the
	// foreign server's settings file.
	p, err := decodePairingCode(base64.StdEncoding.EncodeToString([]byte(
		runMakePairingCode(t, bash, fn, args("plain", "on", "", "on", "", "")))))
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePairing(p); err != nil {
		t.Fatalf("the engine refused a code with the web header and GRE together: %v", err)
	}
	conf := buildOriginConf(p, "/tmp/t1.secret", "/tmp/t1.crt", "/tmp/t1.key")
	for _, line := range []string{"http_header = on\n", "gre = on\n"} {
		if !strings.Contains(conf, line) {
			t.Errorf("the foreign settings lost %q:\n%s", strings.TrimSpace(line), conf)
		}
	}
}

// The settings in a code go into a settings file on the other server, so the
// engine refuses anything that is not what they are allowed to be.
func TestPairingRefusesBadRealSiteSettings(t *testing.T) {
	cases := map[string]struct {
		realSite, coverSite string
		ok                  bool
	}{
		"real site on":                {"on", "", true},
		"cover site name":             {"on", "www.example.org", true},
		"cover site name and port":    {"on", "www.example.org:8443", true},
		"cover site address and port": {"on", "[2001:db8::1]:443", true},
		"real site says maybe":        {"maybe", "", false},
		"cover site with a space":     {"on", "www.example.org extra", false},
		"cover site with a bad port":  {"on", "www.example.org:99999", false},
		"cover site with a path":      {"on", "www.example.org/x", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := goodPairing("rs")
			p.Transport, p.ServerName, p.RealSite, p.CoverSite = "tls", "www.bing.com", tc.realSite, tc.coverSite
			err := validatePairing(p)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("accepted real_site=%q cover_site=%q", tc.realSite, tc.coverSite)
			}
		})
	}
}
