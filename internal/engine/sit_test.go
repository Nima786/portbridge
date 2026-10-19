package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSITAddressesAreMirrored(t *testing.T) {
	pairs := [][2]string{
		{"88.218.16.186", "79.137.202.176"},
		{"1.1.1.1", "2.2.2.2"},
		{"94.184.46.135", "185.139.7.93"},
	}
	for _, p := range pairs {
		ifA, _, _, err := sitLink(p[0], p[1])
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
		ifB, _, _, err := sitLink(p[1], p[0])
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
		if ifA != ifB || !strings.HasPrefix(ifA, "pbs") || len(ifA) > 15 {
			t.Fatalf("bad sit iface: %q vs %q", ifA, ifB)
		}
		ownA, peerA, err := SITAddrs(p[0], p[1])
		if err != nil {
			t.Fatal(err)
		}
		ownB, peerB, err := SITAddrs(p[1], p[0])
		if err != nil {
			t.Fatal(err)
		}
		if ownA != peerB || peerA != ownB || ownA == peerA {
			t.Fatalf("not mirrored: %s %s vs %s %s", ownA, peerA, ownB, peerB)
		}
	}
}

func TestSITHelperAgreesWithEngine(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("no sha256sum on this machine")
	}
	helper, _ := filepath.Abs("../../scripts/portbridge-firewall")
	if _, err := os.Stat(helper); err != nil {
		t.Skip("helper script not available")
	}
	for _, pair := range [][2]string{
		{"88.218.16.186", "79.137.202.176"},
		{"79.137.202.176", "88.218.16.186"},
		{"1.1.1.1", "2.2.2.2"},
	} {
		out, err := exec.Command(bash, helper, "sit-addr", pair[0], pair[1]).CombinedOutput()
		if err != nil {
			t.Fatalf("helper for %v: %v: %s", pair, err, out)
		}
		iface, _, _, err := sitLink(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		own, peer, err := SITAddrs(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		want := iface + " " + own + " " + peer
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%v: helper says %q, engine says %q", pair, got, want)
		}
	}
}
