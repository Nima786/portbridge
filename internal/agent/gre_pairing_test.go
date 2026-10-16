package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nima786/portbridge/internal/engine"
)

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
			cfg, err := engine.LoadConfig(filepath.Join(dir, "greone.conf"))
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
