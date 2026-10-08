package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The two servers never talk about which private address each gets; both work it
// out from the two public ones. These values were produced by the helper script
// itself, so Go and shell are held to the same answers.
var greVectors = []struct {
	a, b        string
	iface, aOwn string
	aPeer       string
}{
	{"87.236.208.145", "79.137.202.176", "pbgc848d733", "10.99.92.206", "10.99.92.205"},
	{"79.137.202.176", "87.236.208.145", "pbgc848d733", "10.99.92.205", "10.99.92.206"},
	{"1.1.1.1", "2.2.2.2", "pbgce79c9f1", "10.99.39.197", "10.99.39.198"},
	{"94.184.46.135", "185.139.7.93", "pbgd54431cd", "10.99.199.53", "10.99.199.54"},
	{"10.0.0.9", "10.0.0.10", "pbg518969f6", "10.99.167.217", "10.99.167.218"},
	{"255.255.255.254", "0.0.0.1", "pbge1bf9e01", "10.99.120.6", "10.99.120.5"},
}

func TestGREAddresses(t *testing.T) {
	for _, v := range greVectors {
		iface, _, _, err := greLink(v.a, v.b)
		if err != nil {
			t.Fatalf("%s/%s: %v", v.a, v.b, err)
		}
		own, peer, err := greAddrs(v.a, v.b)
		if err != nil {
			t.Fatalf("%s/%s: %v", v.a, v.b, err)
		}
		if iface != v.iface || own != v.aOwn || peer != v.aPeer {
			t.Errorf("%s -> %s: got %s %s %s, want %s %s %s", v.a, v.b, iface, own, peer, v.iface, v.aOwn, v.aPeer)
		}
		if len(iface) > 15 {
			t.Errorf("interface name %q is longer than Linux allows", iface)
		}
	}
}

// Whichever side asks, the two servers get opposite halves of the same block.
func TestGREAddressesAreMirrored(t *testing.T) {
	ownA, peerA, _ := greAddrs("3.3.3.3", "4.4.4.4")
	ownB, peerB, _ := greAddrs("4.4.4.4", "3.3.3.3")
	if ownA != peerB || peerA != ownB || ownA == peerA {
		t.Fatalf("not mirrored: %s %s vs %s %s", ownA, peerA, ownB, peerB)
	}
}

func TestGRERefusesBadAddresses(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.1.1.1", "1.1.1.1"},   // the same server twice
		{"01.1.1.1", "2.2.2.2"},  // leading zero: read differently by different tools
		{"1.1.1.256", "2.2.2.2"}, // not an address
		{"::1", "2.2.2.2"},       // IPv6
		{"", "2.2.2.2"},
		{"example.com", "2.2.2.2"},
	} {
		if _, _, err := greAddrs(pair[0], pair[1]); err == nil {
			t.Errorf("%q and %q were accepted", pair[0], pair[1])
		}
	}
}

// The shell helper and the engine must give the same answer for any pair, since
// the Iran server's menu asks the helper and the foreign server's agent asks Go.
// Skipped where bash or sha256sum is not at hand.
func TestGREHelperAgreesWithEngine(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("no sha256sum on this machine")
	}
	helper, _ := filepath.Abs("scripts/portbridge-firewall")
	if _, err := os.Stat(helper); err != nil {
		t.Skip("helper script not available")
	}
	for _, v := range greVectors {
		out, err := exec.Command(bash, helper, "gre-addr", v.a, v.b).CombinedOutput()
		if err != nil {
			t.Fatalf("helper for %s/%s: %v: %s", v.a, v.b, err, out)
		}
		iface, own, peer, err := func() (string, string, string, error) {
			i, _, _, e := greLink(v.a, v.b)
			o, p, e2 := greAddrs(v.a, v.b)
			if e == nil {
				e = e2
			}
			return i, o, p, e
		}()
		if err != nil {
			t.Fatal(err)
		}
		want := iface + " " + own + " " + peer
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s/%s: helper says %q, engine says %q", v.a, v.b, got, want)
		}
	}
}

func greCode(mode string) string {
	return encodeCode("v=8\nname=greone\nmode=" + mode + "\ntunnel_port=9443\nrelay_ip=87.236.208.145\nserver_ip=79.137.202.176\n" +
		"inbound_port=8080\npool=10\ntransport=plain\nmux=on\nmux_links=4\ngre=on\n" +
		"secret=0123456789abcdef0123456789abcdef\n")
}

// A version 8 code makes the foreign half listen on (direct) or call (reverse)
// the right private address, and the result is a tunnel the engine accepts.
func TestPairingCodeBuildsTheForeignHalfOfAGRETunnel(t *testing.T) {
	// Foreign is 79.137.202.176 (the smaller address), Iran is 87.236.208.145.
	ownForeign, ownIran := "10.99.92.205", "10.99.92.206"

	for _, tc := range []struct{ mode, wantAddr string }{
		{"direct", ownForeign + ":9443"}, // accepts on its own private address
		{"reverse", ownIran + ":9443"},   // calls the Iran server's
	} {
		t.Run(tc.mode, func(t *testing.T) {
			p, err := decodePairingCode(greCode(tc.mode))
			if err != nil {
				t.Fatal(err)
			}
			if p.GRE != "on" {
				t.Fatalf("the code lost gre: %q", p.GRE)
			}
			dir := t.TempDir()
			if err := applyPairingData(p, dir); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(filepath.Join(dir, "greone.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("the engine refused the settings it was given: %v", err)
			}
			if !cfg.GRE || cfg.GRELocal != "79.137.202.176" || cfg.GRERemote != "87.236.208.145" {
				t.Fatalf("gre settings wrong: %v %q %q", cfg.GRE, cfg.GRELocal, cfg.GRERemote)
			}
			if cfg.TunnelAddr != tc.wantAddr {
				t.Fatalf("tunnel_addr = %q, want %q", cfg.TunnelAddr, tc.wantAddr)
			}
			if cfg.PeerIP != ownIran {
				t.Fatalf("peer_ip = %q, want the Iran server's private address %q", cfg.PeerIP, ownIran)
			}
			if cfg.Firewall != "off" {
				t.Fatalf("the port is only reachable over the link, so the firewall should be off, got %q", cfg.Firewall)
			}
			if !strings.Contains(cfg.Summary(), "GRE") {
				t.Fatalf("the check output does not say the link is GRE: %q", cfg.Summary())
			}
		})
	}
}

// Anything that would make a GRE tunnel that cannot work is refused up front.
func TestPairingRefusesAGRETunnelThatCannotWork(t *testing.T) {
	cases := map[string]func(p *PairingData){
		"no foreign address": func(p *PairingData) { p.ServerIP = "" },
		"IPv6 address":       func(p *PairingData) { p.ServerIP = "2001:db8::1" },
		"same address twice": func(p *PairingData) { p.ServerIP = p.RelayIP },
		"with a CDN":         func(p *PairingData) { p.CDN = "on" },
		"with a backup host": func(p *PairingData) { p.AltHost = "backup.example.com" },
		"on a website link":  func(p *PairingData) { p.Transport = "wss" },
		"gre says maybe":     func(p *PairingData) { p.GRE = "maybe" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := decodePairingCode(greCode("direct"))
			if err != nil {
				t.Fatal(err)
			}
			change(p)
			if err := applyPairingData(p, t.TempDir()); err == nil {
				t.Fatalf("accepted a GRE tunnel with %s", name)
			}
		})
	}
}

// A tunnel that does not use GRE is written exactly as before.
func TestPlainPairingIsUnchangedByGRE(t *testing.T) {
	p := goodPairing("nolink")
	p.TunnelPort, p.InboundPort = "9443", "9090"
	dir := t.TempDir()
	if err := applyPairingData(p, dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "nolink.conf"))
	if strings.Contains(string(b), "gre") {
		t.Fatalf("a tunnel without GRE mentions it:\n%s", b)
	}
}

func greConf(mode, role, tunnelAddr string) string {
	conf := "name = g\nmode = " + mode + "\nrole = " + role + "\ntunnel_addr = " + tunnelAddr + "\n" +
		"peer_ip = 10.99.92.205\ntransport = plain\nsecret_file = /tmp/g.secret\ngre = on\ngre_local = 87.236.208.145\ngre_remote = 79.137.202.176\n"
	if role == "edge" {
		conf += "user_listen = 127.0.0.1:18080\n"
	} else {
		conf += "inbound_addr = 127.0.0.1:18081\n"
	}
	return conf
}

func loadGREConf(t *testing.T, text string) error {
	t.Helper()
	f := filepath.Join(t.TempDir(), "g.conf")
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(f)
	if err != nil {
		return err
	}
	return cfg.Validate()
}

// On the Iran server (87.236.208.145, private .206) each of the four ways a
// tunnel can be set up names the right address, and only that one is accepted.
func TestGREConfigNamesTheRightPrivateAddress(t *testing.T) {
	const iran, foreign = "10.99.92.206", "10.99.92.205"
	good := []struct{ mode, role, addr string }{
		{"direct", "edge", foreign + ":9443"},    // Iran dials the foreign server
		{"reverse", "edge", iran + ":9443"},      // Iran waits on its own address
		{"direct", "origin", iran + ":9443"},     // (this machine playing origin) waits on its own
		{"reverse", "origin", foreign + ":9443"}, // and dials the other's
	}
	for _, g := range good {
		if err := loadGREConf(t, greConf(g.mode, g.role, g.addr)); err != nil {
			t.Errorf("%s/%s with %s was refused: %v", g.mode, g.role, g.addr, err)
		}
		// The public address, the other side's private one, a made-up one and a
		// wildcard are all refused: it has to be exactly the address the link gives.
		for _, wrong := range []string{"79.137.202.176:9443", "0.0.0.0:9443", "10.99.0.1:9443", iran + ":9443", foreign + ":9443"} {
			if wrong == g.addr {
				continue
			}
			if err := loadGREConf(t, greConf(g.mode, g.role, wrong)); err == nil {
				t.Errorf("%s/%s accepted %s", g.mode, g.role, wrong)
			}
		}
	}
}

func TestGREConfigRefusals(t *testing.T) {
	base := greConf("direct", "edge", "10.99.92.205:9443")
	for name, text := range map[string]string{
		"missing local":  strings.Replace(base, "gre_local = 87.236.208.145\n", "", 1),
		"missing remote": strings.Replace(base, "gre_remote = 79.137.202.176\n", "", 1),
		"on a website":   strings.Replace(base, "transport = plain", "transport = wss\nserver_name = a.example.com", 1),
		"with a CDN":     base + "cdn = on\n",
		"gre says maybe": strings.Replace(base, "gre = on", "gre = maybe", 1),
	} {
		if err := loadGREConf(t, text); err == nil {
			t.Errorf("accepted a GRE config %s", name)
		}
	}
	if err := loadGREConf(t, base); err != nil {
		t.Fatalf("the good one was refused: %v", err)
	}
}
