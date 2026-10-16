package agent

import (
	"path/filepath"
	"testing"

	"github.com/Nima786/portbridge/internal/engine"
	"github.com/Nima786/portbridge/internal/proxyproto"
)

// A code carries the setting to the foreign server, a later code can turn it
// off again there, and anything but off, v1 or v2 is refused.
func TestPairingCarriesTheRealAddressSetting(t *testing.T) {
	dir := t.TempDir()
	read := func() *engine.Config {
		t.Helper()
		cfg, err := engine.LoadConfig(filepath.Join(dir, "pp.conf"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	p := goodPairing("pp")
	p.Version, p.ProxyProtocol = "10", "v1"
	if err := applyPairingData(p, dir); err != nil {
		t.Fatal(err)
	}
	if cfg := read(); cfg.ProxyProtocol != proxyproto.V1 {
		t.Fatalf("the foreign half has proxy_protocol %d, want v1", cfg.ProxyProtocol)
	}

	for _, change := range []struct {
		to   string
		want int
	}{{"v2", proxyproto.V2}, {"", proxyproto.Off}} {
		p := goodPairing("pp")
		p.Version, p.ProxyProtocol = "10", change.to
		if err := updatePairingData(p, dir, nil); err != nil {
			t.Fatalf("changing it to %q: %v", change.to, err)
		}
		if cfg := read(); cfg.ProxyProtocol != change.want {
			t.Fatalf("after changing it to %q the foreign half has %d", change.to, cfg.ProxyProtocol)
		}
	}

	bad := goodPairing("pp2")
	bad.ProxyProtocol = "on"
	if err := validatePairing(bad); err == nil {
		t.Fatalf("a code with proxy_protocol=on was accepted")
	}
}
