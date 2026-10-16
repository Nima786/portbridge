package agent

// The Iran half the panel makes must be the one the menu makes. These run the
// menu's own write_tunnel and get_tunnel_pairing_code on the same answers and
// compare, line for line.

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/engine"
)

const testSecret = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="

// edgeCases are tunnels of every kind the menu's "Create a tunnel" can make.
func edgeCases() map[string]EdgeSpec {
	base := func(mode, transport string) EdgeSpec {
		return EdgeSpec{Name: "t1", Mode: mode, Transport: transport, PeerIP: "5.6.7.8", LocalIP: "1.2.3.4",
			LinkPort: 443, UserPorts: "29311", ServicePorts: "39001"}
	}
	m := map[string]EdgeSpec{}
	m["direct plain"] = base("direct", "plain")
	s := base("reverse", "plain")
	s.HTTPHeader, s.HTTPHost = "on", "cdn.example.org"
	m["reverse plain, web header"] = s
	s = base("direct", "tls")
	s.ServerName, s.UTLS, s.TLSFragment = "www.bing.com", "on", "on"
	m["direct website, stealth"] = s
	s = base("reverse", "tls")
	s.ServerName, s.RealSite = "www.bing.com", "on"
	m["reverse website, real site"] = s
	s = base("direct", "wss")
	s.ServerName, s.CDN, s.WSPath, s.CleanIPs = "link.example.com", "on", "/abcDEF1234", "104.16.12.34,172.67.45.67"
	m["direct through a CDN, clean addresses"] = s
	s = base("direct", "wss")
	s.ServerName, s.AltHost, s.WSPath = "www.bing.com", "link.example.com", "/abcDEF1234"
	m["direct website with CDN backup"] = s
	s = base("direct", "grpc")
	s.ServerName, s.CDN, s.CleanIPs = "grpc.example.com", "on", "104.16.12.34"
	m["direct gRPC through a CDN"] = s
	s = base("reverse", "kcp")
	s.Mux, s.MuxLinks = "on", 6
	m["reverse KCP, shared links"] = s
	s = base("direct", "plain")
	s.GRE = "on"
	m["direct over GRE"] = s
	s = base("reverse", "plain")
	s.GRE = "on"
	m["reverse over GRE"] = s
	s = base("reverse", "tls")
	s.ServerName, s.IPv6, s.PeerIP, s.LocalIP = "www.bing.com", true, "2a01:e5c0:585a::2", "2a14:ec00:4:5:216:3eff:fe92:3c2"
	m["reverse website over IPv6"] = s
	s = base("direct", "plain")
	s.IPv6, s.PeerIP, s.LocalIP = true, "2a01:e5c0:585a::2", "2a14:ec00:4:5:216:3eff:fe92:3c2"
	m["direct plain over IPv6"] = s
	s = base("direct", "tls")
	s.ServerName, s.ProxyProtocol, s.UserPorts, s.ServicePorts = "www.bing.com", "v2", "443, 8443", "2083,2087"
	m["several ports, real address"] = s
	return m
}

// menuFunc is menuFunction, also for the menu's one-line helpers, such as
// "conf_of()   { printf ...; }".
func menuFunc(t *testing.T, menu, name string) string {
	t.Helper()
	for _, sep := range []string{"() {\n", "()"} {
		i := strings.Index(menu, "\n"+name+sep)
		if i < 0 {
			continue
		}
		if sep == "() {\n" {
			return menuFunction(t, menu, name)
		}
		line := menu[i+1:]
		if j := strings.Index(line, "\n"); j >= 0 {
			line = line[:j]
		}
		if strings.HasSuffix(strings.TrimSpace(line), "}") {
			return line + "\n"
		}
	}
	t.Fatalf("could not find %s in the menu", name)
	return ""
}

// runWriteTunnel runs the menu's own write_tunnel with the answers create_tunnel
// would have given it, in dir, and returns the settings file it wrote.
func runWriteTunnel(t *testing.T, bash, menu, dir string, s EdgeSpec, l edgeLayout) string {
	t.Helper()
	var fns strings.Builder
	for _, f := range []string{"conf_of", "secret_of", "cdn_involved", "write_tunnel"} {
		fns.WriteString(menuFunc(t, menu, f))
	}
	onOff := func(v string) string {
		if v == "" {
			return "off"
		}
		return v
	}
	proxy := s.ProxyProtocol
	if proxy == "" {
		proxy = "off"
	}
	env := map[string]string{
		"CONF_DIR": "tunnels", "DG_TRANSPORT": s.Transport, "DG_SERVERNAME": s.ServerName, "DG_WSPATH": s.WSPath,
		"DG_CDN": onOff(s.CDN), "DG_ALTHOST": s.AltHost, "DG_CLEAN_IPS": s.CleanIPs, "DG_UTLS": onOff(s.UTLS),
		"DG_FRAGMENT": onOff(s.TLSFragment), "DG_HTTPHEADER": onOff(s.HTTPHeader), "DG_HTTPHOST": s.HTTPHost,
		"DG_REAL_SITE": onOff(s.RealSite), "DG_COVER_SITE": s.CoverSite, "DG_GRE": onOff(s.GRE),
		"DG_GRE_LOCAL": l.greLocal, "DG_GRE_REMOTE": l.greRemote, "DG_PROXY": proxy,
		"MX_MUX": onOff(s.Mux), "MX_LINKS": strconv.Itoa(s.MuxLinks),
	}
	script := fns.String() + "\nwrite_tunnel \"$@\"\n"
	args := []string{"-c", script, "write_tunnel", s.Name, s.Mode, "edge", l.tunnelAddr, s.UserPorts, "",
		l.peerConf, s.LocalIP, strconv.Itoa(s.Pool), testSecret, s.ServicePorts}
	cmd := exec.Command(bash, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write_tunnel: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "tunnels", s.Name+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withoutFirstLine drops the line saying who wrote the file and when.
func withoutFirstLine(s string) string {
	_, rest, _ := strings.Cut(s, "\n")
	return rest
}

func TestPanelWritesTheIranHalfExactlyAsTheMenuDoes(t *testing.T) {
	bash := menuShell(t)
	menu := readMenu(t)
	for name, spec := range edgeCases() {
		t.Run(name, func(t *testing.T) {
			s := spec
			s.normalise()
			if err := s.check(); err != nil {
				t.Fatalf("a tunnel the menu can make was refused: %v", err)
			}
			l, err := s.layout()
			if err != nil {
				t.Fatal(err)
			}
			want := runWriteTunnel(t, bash, menu, t.TempDir(), s, l)
			got := buildEdgeConf(&s, l, "tunnels", time.Now())
			if withoutFirstLine(got) != withoutFirstLine(want) {
				t.Fatalf("the panel wrote\n%s\nthe menu wrote\n%s", got, want)
			}
		})
	}
}

func TestPanelMakesTheMenusCode(t *testing.T) {
	bash := menuShell(t)
	menu := readMenu(t)
	var fns strings.Builder
	for _, f := range []string{"conf_of", "secret_of", "read_conf", "other_public_ip", "make_pairing_code", "get_tunnel_pairing_code"} {
		fns.WriteString(menuFunc(t, menu, f))
	}
	for name, spec := range edgeCases() {
		t.Run(name, func(t *testing.T) {
			s := spec
			s.normalise()
			l, err := s.layout()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			tunnels := filepath.Join(dir, "tunnels")
			_ = os.MkdirAll(tunnels, 0o700)
			_ = os.WriteFile(filepath.Join(tunnels, s.Name+".conf"), []byte(buildEdgeConf(&s, l, "tunnels", time.Now())), 0o600)
			_ = os.WriteFile(filepath.Join(tunnels, s.Name+".secret"), []byte(testSecret+"\n"), 0o600)

			got, err := edgePairingCode(tunnels, s.Name)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bash, "-c", fns.String()+"\nget_tunnel_pairing_code \"$1\"\n", "x", s.Name)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "CONF_DIR=tunnels")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("get_tunnel_pairing_code: %v", err)
			}
			if got != string(out) {
				a, _ := base64.StdEncoding.DecodeString(got)
				b, _ := base64.StdEncoding.DecodeString(string(out))
				t.Fatalf("the panel's code\n%s\nthe menu's code\n%s", a, b)
			}
		})
	}
}

// Made by the panel, read by the foreign server's agent: both halves of the same
// tunnel, with the same password, and settings the engine accepts.
func TestTheTwoHalvesMadeFromThePanelMatch(t *testing.T) {
	old := hasLocalAddress
	hasLocalAddress = func(string) bool { return true }
	t.Cleanup(func() { hasLocalAddress = old })
	for name, spec := range edgeCases() {
		t.Run(name, func(t *testing.T) {
			relay, foreign := t.TempDir(), t.TempDir()
			res, err := CreateEdge(spec, relay)
			if err != nil || !res.OK || res.Code == "" {
				t.Fatalf("the Iran half was not made: %v %+v", err, res)
			}
			cfg, err := engine.LoadConfig(filepath.Join(relay, spec.Name+".conf"))
			if err != nil || cfg.Validate() != nil {
				t.Fatalf("the engine refuses the Iran half: %v %v", err, cfg.Validate())
			}
			p, err := decodePairingCode(res.Code)
			if err != nil {
				t.Fatal(err)
			}
			if err := applyPairingData(p, foreign); err != nil {
				t.Fatalf("the foreign half was refused: %v", err)
			}
			a, b := TunnelsReport(relay), TunnelsReport(foreign)
			if len(a) != 1 || len(b) != 1 || a[0].PairID == "" || a[0].PairID != b[0].PairID {
				t.Fatalf("the halves do not share a password: %+v %+v", a, b)
			}
			if a[0].Role != "edge" || b[0].Role != "origin" || a[0].Mode != b[0].Mode || a[0].Transport != b[0].Transport {
				t.Fatalf("the halves disagree: %+v %+v", a[0], b[0])
			}
			if a[0].LinkPort != b[0].LinkPort {
				t.Fatalf("the halves use different link ports: %d %d", a[0].LinkPort, b[0].LinkPort)
			}
		})
	}
}

func TestCreatingTheIranHalfRefusesWhatCannotWork(t *testing.T) {
	ok := func() EdgeSpec {
		return EdgeSpec{Name: "t1", Mode: "direct", Transport: "plain", PeerIP: "5.6.7.8", LocalIP: "1.2.3.4",
			LinkPort: 443, UserPorts: "443", ServicePorts: "8080"}
	}
	for name, change := range map[string]func(*EdgeSpec){
		"bad name":                        func(s *EdgeSpec) { s.Name = "../x" },
		"bad mode":                        func(s *EdgeSpec) { s.Mode = "sideways" },
		"unknown link":                    func(s *EdgeSpec) { s.Transport = "carrier-pigeon" },
		"no foreign address":              func(s *EdgeSpec) { s.PeerIP = "" },
		"port out of range":               func(s *EdgeSpec) { s.LinkPort = 70000 },
		"ports do not pair":               func(s *EdgeSpec) { s.UserPorts = "443, 8443" },
		"a user port that is not one":     func(s *EdgeSpec) { s.UserPorts = "443x" },
		"link port on the service":        func(s *EdgeSpec) { s.ServicePorts = "443" },
		"CDN without a domain":            func(s *EdgeSpec) { s.Transport, s.CDN = "wss", "on" },
		"CDN backup in reverse":           func(s *EdgeSpec) { s.Mode, s.Transport, s.AltHost = "reverse", "wss", "x.example.com" },
		"web header on a website link":    func(s *EdgeSpec) { s.Transport, s.HTTPHeader = "tls", "on" },
		"real site on a plain link":       func(s *EdgeSpec) { s.RealSite = "on" },
		"IPv6 with IPv4 addresses":        func(s *EdgeSpec) { s.IPv6 = true },
		"too many shared connections":     func(s *EdgeSpec) { s.Mux, s.MuxLinks = "on", 40 },
		"real address nonsense":           func(s *EdgeSpec) { s.ProxyProtocol = "yes" },
		"a server name that is not one":   func(s *EdgeSpec) { s.Transport, s.ServerName = "tls", "bad name!" },
		"clean addresses that are not IP": func(s *EdgeSpec) { s.Transport, s.CDN, s.ServerName, s.CleanIPs = "wss", "on", "x.example.com", "nope" },
	} {
		t.Run(name, func(t *testing.T) {
			s := ok()
			change(&s)
			dir := t.TempDir()
			if _, err := CreateEdge(s, dir); err == nil {
				t.Fatalf("it was accepted")
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("a refused tunnel left files behind: %v", entries)
			}
		})
	}

	// The same name twice, and a users' port another tunnel already has.
	dir := t.TempDir()
	if _, err := CreateEdge(ok(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateEdge(ok(), dir); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a second tunnel of the same name: %v", err)
	}
	other := ok()
	other.Name = "t2"
	other.LinkPort = 8443
	if _, err := CreateEdge(other, dir); err == nil || !strings.Contains(err.Error(), "users' port 443") {
		t.Fatalf("a users' port another tunnel has: %v", err)
	}
}

func TestRealSiteFallsBackToASiteThisServerCanReach(t *testing.T) {
	old := reachable
	reachable = func(h string) bool { return h == "www.wikipedia.org" }
	t.Cleanup(func() { reachable = old })
	s := EdgeSpec{Name: "t1", Mode: "reverse", Transport: "tls", ServerName: "blocked.example.com", RealSite: "on",
		PeerIP: "5.6.7.8", LocalIP: "1.2.3.4", LinkPort: 443, UserPorts: "29311", ServicePorts: "39001"}
	res, err := CreateEdge(s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := decodePairingCode(res.Code)
	if p.ServerName != "www.wikipedia.org" || len(res.Warnings) == 0 {
		t.Fatalf("the unreachable site was kept: %q %v", p.ServerName, res.Warnings)
	}
	if p.UTLS != "on" {
		t.Fatalf("the real website goes with a browser's hello, as in the menu")
	}
}
