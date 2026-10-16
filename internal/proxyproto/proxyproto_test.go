package proxyproto

import (
	"bytes"
	"net"
	"testing"
)

func tcpAddr(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestProxyHeaderFormats(t *testing.T) {
	v4 := &Addrs{Src: tcpAddr(t, "203.0.113.7:51234"), Dst: tcpAddr(t, "198.51.100.1:443")}
	v6 := &Addrs{Src: tcpAddr(t, "[2001:db8::7]:51234"), Dst: tcpAddr(t, "[2001:db8::1]:443")}
	// An IPv4 user reaching a listener that also takes IPv6 shows up in IPv6
	// form on that side; both must still go out as IPv4.
	mapped := &Addrs{Src: tcpAddr(t, "[::ffff:203.0.113.7]:51234"), Dst: tcpAddr(t, "198.51.100.1:443")}

	sig := string(V2Signature)
	cases := []struct {
		name    string
		version int
		a       *Addrs
		want    string
	}{
		{"v1 IPv4", V1, v4, "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"},
		{"v1 IPv6", V1, v6, "PROXY TCP6 2001:db8::7 2001:db8::1 51234 443\r\n"},
		{"v1 IPv4 seen as IPv6", V1, mapped, "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"},
		{"v1 unknown", V1, nil, "PROXY UNKNOWN\r\n"},
		{"v1 empty", V1, &Addrs{}, "PROXY UNKNOWN\r\n"},
		{"v2 IPv4", V2, v4, sig + "\x21\x11\x00\x0c" +
			"\xcb\x00\x71\x07" + "\xc6\x33\x64\x01" + "\xc8\x22" + "\x01\xbb"},
		{"v2 IPv6", V2, v6, sig + "\x21\x21\x00\x24" +
			"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07" +
			"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" +
			"\xc8\x22" + "\x01\xbb"},
		{"v2 unknown", V2, nil, sig + "\x20\x00\x00\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(Header(tc.version, tc.a)); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestUserAddrsCrossTheTunnelIntact(t *testing.T) {
	for _, s := range [][2]string{
		{"203.0.113.7:51234", "198.51.100.1:443"},
		{"[2001:db8::7]:1", "[2001:db8::1]:65535"},
		{"[::ffff:203.0.113.7]:51234", "198.51.100.1:443"},
	} {
		in := &Addrs{Src: tcpAddr(t, s[0]), Dst: tcpAddr(t, s[1])}
		out, err := ReadAddrs(bytes.NewReader(in.AppendTo(nil)))
		if err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		if string(Header(V1, out)) != string(Header(V1, in)) {
			t.Fatalf("%v: went in as %s came out as %s", s, Header(1, in), Header(1, out))
		}
	}
	// Not known goes across as not known.
	out, err := ReadAddrs(bytes.NewReader((&Addrs{}).AppendTo(nil)))
	if err != nil || out.family() != 0 {
		t.Fatalf("an unknown address came out as %+v, %v", out, err)
	}
	// Anything else is refused rather than guessed at.
	if _, err := ReadAddrs(bytes.NewReader([]byte{5, 1, 2, 3})); err == nil {
		t.Fatalf("accepted an address family that does not exist")
	}
}
