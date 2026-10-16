package engine

import (
	"net"
	"testing"
)

// The tunnel connects from its own IPv6 address, so the other side's firewall,
// which lets in only that one, never meets another.
func TestSourceForOnlyAppliesToIPv6ToIPv6(t *testing.T) {
	cfg := &Config{LocalIP: "2a00:15c9:0:4::3c1"}
	if a := cfg.sourceFor("[2a01:e5c0:585a::2]:18443"); a == nil || a.(*net.TCPAddr).IP.String() != "2a00:15c9:0:4::3c1" {
		t.Fatalf("an IPv6 target did not get the IPv6 source: %v", a)
	}
	if a := cfg.sourceFor("79.137.202.176:18443"); a != nil {
		t.Fatalf("an IPv4 target got a source: %v", a)
	}
	if a := cfg.sourceFor("example.com:443"); a != nil {
		t.Fatalf("a name got a source: %v", a)
	}
	if a := (&Config{LocalIP: "87.236.208.145"}).sourceFor("[2001:db8::1]:1"); a != nil {
		t.Fatalf("an IPv4 local address was used for an IPv6 target: %v", a)
	}
	if a := (&Config{}).sourceFor("[2001:db8::1]:1"); a != nil {
		t.Fatalf("no local address should mean no source: %v", a)
	}
	if a := (&Config{LocalIP: "not-an-ip"}).sourceFor("[2001:db8::1]:1"); a != nil {
		t.Fatalf("nonsense should mean no source: %v", a)
	}
}
