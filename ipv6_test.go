package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func ipnet(s string) net.Addr {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

func TestPublicAddressesKeepsOnlyReachableOnes(t *testing.T) {
	v4, v6 := publicAddresses([]net.Addr{
		ipnet("127.0.0.1/8"),                    // loopback
		ipnet("10.0.0.5/24"),                    // private
		ipnet("192.168.1.5/24"),                 // private
		ipnet("172.20.0.1/16"),                  // private
		ipnet("100.64.3.4/10"),                  // carrier-grade NAT
		ipnet("169.254.1.1/16"),                 // link-local
		ipnet("87.236.208.145/24"),              // public
		ipnet("::1/128"),                        // loopback
		ipnet("fe80::1/64"),                     // link-local
		ipnet("fd12:3456:789a::1/64"),           // unique-local
		ipnet("2a00:15c9:0:4::3c1/128"),         // public
		ipnet("2a01:e5c0:585a::2/48"),           // public
		&net.IPAddr{IP: net.ParseIP("8.8.4.4")}, // a bare address is read too
	})
	if strings.Join(v4, ",") != "87.236.208.145,8.8.4.4" {
		t.Errorf("IPv4: %v", v4)
	}
	if strings.Join(v6, ",") != "2a00:15c9:0:4::3c1,2a01:e5c0:585a::2" {
		t.Errorf("IPv6: %v", v6)
	}
}

func TestAddressLines(t *testing.T) {
	got := addressLines([]string{"1.2.3.4"}, []string{"2001:db8::1", "2001:db8::2"})
	if got != "ipv4 1.2.3.4\nipv6 2001:db8::1\nipv6 2001:db8::2\n" {
		t.Fatalf("got %q", got)
	}
	if addressLines(nil, nil) != "" {
		t.Fatalf("nothing should print nothing")
	}
}

func TestAddressesEndpointAndClient(t *testing.T) {
	srv := httptest.NewTLSServer(addressesHandler("tok"))
	defer srv.Close()

	// The endpoint refuses a wrong token.
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong token got %d", resp.StatusCode)
	}

	// And with the right one it answers in the form the client prints.
	req, _ = http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res struct {
		OK   bool     `json:"ok"`
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || !res.OK {
		t.Fatalf("bad answer: %v %+v", err, res)
	}

	out := captureStdout(t, func() {
		if err := agentClientAddresses(srv.URL, "tok", agentTrust{Insecure: true}); err != nil {
			t.Fatal(err)
		}
	})
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" && !strings.HasPrefix(line, "ipv4 ") && !strings.HasPrefix(line, "ipv6 ") {
			t.Errorf("unexpected line %q", line)
		}
	}

	if err := agentClientAddresses(srv.URL, "wrong", agentTrust{Insecure: true}); err == nil {
		t.Fatalf("a wrong token was accepted")
	}
	old := httptest.NewTLSServer(http.NotFoundHandler())
	defer old.Close()
	if err := agentClientAddresses(old.URL, "tok", agentTrust{Insecure: true}); err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("an agent without the endpoint should be called too old, got %v", err)
	}
}

// When the Iran server's address in the code is IPv6, the foreign half listens on
// IPv6 (direct) or calls that address in brackets (reverse), and the result is a
// tunnel the engine accepts.
func TestPairingOverIPv6BuildsAWorkingForeignHalf(t *testing.T) {
	for _, tc := range []struct{ mode, wantAddr string }{
		{"direct", "[::]:9443"},
		{"reverse", "[2a00:15c9:0:4::3c1]:9443"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			p, err := decodePairingCode(encodeCode("v=6\nname=six\nmode=" + tc.mode + "\ntunnel_port=9443\n" +
				"relay_ip=2a00:15c9:0:4::3c1\nserver_ip=2a01:e5c0:585a::2\ninbound_port=8080\npool=10\ntransport=plain\n" +
				"mux=on\nmux_links=4\nsecret=0123456789abcdef0123456789abcdef\n"))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := applyPairingData(p, dir); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(filepath.Join(dir, "six.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("the engine refused the settings: %v", err)
			}
			if cfg.TunnelAddr != tc.wantAddr {
				t.Fatalf("tunnel_addr = %q, want %q", cfg.TunnelAddr, tc.wantAddr)
			}
			if cfg.PeerIP != "2a00:15c9:0:4::3c1" || cfg.LocalIP != "2a01:e5c0:585a::2" {
				t.Fatalf("peer %q local %q", cfg.PeerIP, cfg.LocalIP)
			}
		})
	}
}

// IPv4 tunnels are written as before.
func TestPairingOverIPv4IsUnchangedByIPv6(t *testing.T) {
	p := goodPairing("fourlegs")
	p.TunnelPort, p.InboundPort = "9443", "9090"
	dir := t.TempDir()
	if err := applyPairingData(p, dir); err != nil {
		t.Fatal(err)
	}
	cfg, _ := LoadConfig(filepath.Join(dir, "fourlegs.conf"))
	if cfg.TunnelAddr != "0.0.0.0:9443" {
		t.Fatalf("tunnel_addr = %q", cfg.TunnelAddr)
	}
}

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
