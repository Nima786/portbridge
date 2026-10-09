package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The firewall helper has to lock a tunnel's port to a peer that connects over
// IPv6, which it could not do before: it handed the address to the IPv4 tool.

func (r *greRig) listeningTunnel(name, mode, role, tunnelAddr, peer string) {
	r.t.Helper()
	text := "name = " + name + "\nmode = " + mode + "\nrole = " + role + "\ntunnel_addr = " + tunnelAddr + "\n" +
		"peer_ip = " + peer + "\nfirewall = on\ntransport = plain\n"
	if role == "origin" {
		text += "inbound_addr = 127.0.0.1:8080\n"
	} else {
		text += "user_listen = 127.0.0.1:18080\n"
	}
	if err := os.WriteFile(filepath.Join(r.conf, name+".conf"), []byte(text), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func TestFirewallLocksThePortToAnIPv6Peer(t *testing.T) {
	r := newGRERig(t)
	r.listeningTunnel("six", "direct", "origin", "[::]:9443", "2a00:15c9:0:4::3c1")

	out, code := r.run("apply", "six")
	if code != 0 || !strings.Contains(out, "restricted to 2a00:15c9:0:4::3c1") {
		t.Fatalf("apply (%d): %s", code, out)
	}
	v6, v4 := r.rulesIn("rules6"), r.rulesIn("rules")
	// IPv6: the peer and localhost in, everyone else out.
	mustContain(t, v6,
		`-s 2a00:15c9:0:4::3c1 -p tcp --dport 9443 -m comment --comment "portbridge:six" -j ACCEPT`,
		`-s ::1 -p tcp --dport 9443 -m comment --comment "portbridge:six" -j ACCEPT`,
		`-p tcp --dport 9443 -m comment --comment "portbridge:six" -j DROP`)
	// IPv4: the same port is shut, except to the machine itself; the IPv6 address
	// is never handed to the IPv4 tool.
	mustContain(t, v4,
		`-p tcp --dport 9443 -m comment --comment "portbridge:six" -j DROP`,
		`-s 127.0.0.1 -p tcp --dport 9443 -m comment --comment "portbridge:six" -j ACCEPT`)
	mustNotContain(t, v4, "2a00:15c9")

	// Applied again, nothing is doubled.
	if _, code := r.run("apply", "six"); code != 0 {
		t.Fatalf("second apply failed")
	}
	if n := strings.Count(r.rulesIn("rules6"), "portbridge:six"); n != 3 {
		t.Fatalf("expected 3 IPv6 rules, got %d:\n%s", n, r.rulesIn("rules6"))
	}

	// Deleting the tunnel clears both families.
	if out, code := r.run("remove", "six"); code != 0 {
		t.Fatalf("remove (%d): %s", code, out)
	}
	mustNotContain(t, r.rulesIn("rules6"), "portbridge:six")
	mustNotContain(t, r.rulesIn("rules"), "portbridge:six")
}

// An IPv4 peer is locked as before, with IPv6 shut on the port.
func TestFirewallStillLocksAnIPv4Peer(t *testing.T) {
	r := newGRERig(t)
	r.listeningTunnel("four", "direct", "origin", "0.0.0.0:9443", "94.184.46.135")
	if out, code := r.run("apply", "four"); code != 0 {
		t.Fatalf("apply (%d): %s", code, out)
	}
	mustContain(t, r.rulesIn("rules"),
		`-s 94.184.46.135 -p tcp --dport 9443 -m comment --comment "portbridge:four" -j ACCEPT`,
		`-p tcp --dport 9443 -m comment --comment "portbridge:four" -j DROP`)
	v6 := r.rulesIn("rules6")
	mustContain(t, v6, `-p tcp --dport 9443 -m comment --comment "portbridge:four" -j DROP`)
	mustNotContain(t, v6, "-j ACCEPT")
}

// The side that waits in reverse mode is the Iran server: same lock.
func TestFirewallLocksAReverseEdgeToAnIPv6Peer(t *testing.T) {
	r := newGRERig(t)
	r.listeningTunnel("rev", "reverse", "edge", "[::]:9443", "2a01:e5c0:585a::2")
	if out, code := r.run("apply", "rev"); code != 0 {
		t.Fatalf("apply (%d): %s", code, out)
	}
	mustContain(t, r.rulesIn("rules6"), `-s 2a01:e5c0:585a::2 -p tcp --dport 9443`)
}

// A side that dials out has no rule to make, whichever family it uses.
func TestFirewallLeavesADialingIPv6TunnelAlone(t *testing.T) {
	r := newGRERig(t)
	r.listeningTunnel("out", "direct", "edge", "[2a01:e5c0:585a::2]:9443", "2a01:e5c0:585a::2")
	if out, code := r.run("apply", "out"); code != 0 || !strings.Contains(out, "dials out") {
		t.Fatalf("apply (%d): %s", code, out)
	}
	mustNotContain(t, r.rulesIn("rules6")+r.rulesIn("rules"), "portbridge:out")
}
