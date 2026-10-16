package agent

import (
	"path/filepath"
	"testing"

	"github.com/Nima786/portbridge/internal/engine"
)

// A version 7 code brings the web header to the foreign half, and a plain code
// does not grow one.
func TestPairingCodeCarriesTheWebHeader(t *testing.T) {
	code := encodeCode("v=7\nname=hdr\nmode=direct\ntunnel_port=8443\nrelay_ip=1.1.1.1\nserver_ip=2.2.2.2\n" +
		"inbound_port=8080\npool=10\ntransport=plain\nhttp_header=on\nhttp_host=files.example.org\n" +
		"secret=0123456789abcdef0123456789abcdef\n")
	p, err := decodePairingCode(code)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := applyPairingData(p, dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := engine.LoadConfig(filepath.Join(dir, "hdr.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HTTPHeader || cfg.HTTPHost != "files.example.org" {
		t.Fatalf("the foreign half lost the web header: %v %q", cfg.HTTPHeader, cfg.HTTPHost)
	}

	plain := goodPairing("nohdr")
	plain.TunnelPort, plain.InboundPort = "9443", "9090"
	if err := applyPairingData(plain, dir); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := engine.LoadConfig(filepath.Join(dir, "nohdr.conf"))
	if cfg2.HTTPHeader {
		t.Fatalf("a plain code grew a web header")
	}

	bad := goodPairing("badhdr")
	bad.Transport = "wss"
	bad.HTTPHeader = "on"
	if err := applyPairingData(bad, t.TempDir()); err == nil {
		t.Fatalf("a web header on a website link was accepted")
	}
}
