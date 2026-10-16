package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/proxyproto"
)

// ---------------------------------------------------------------------------
// The header and the message, byte for byte
// ---------------------------------------------------------------------------

func tcpAddr(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// With the setting off, the edge opens a session with exactly the bytes it always
// has; only with it on is the new message sent.
func TestActivationIsUnchangedWithoutRealAddress(t *testing.T) {
	from := &proxyproto.Addrs{Src: tcpAddr(t, "203.0.113.7:51234"), Dst: tcpAddr(t, "198.51.100.1:443")}
	head := []byte("hello")
	cases := []struct {
		name string
		port uint16
		from *proxyproto.Addrs
		want []byte
	}{
		{"one service", 0, nil, append([]byte{msgActivate}, head...)},
		{"several services", 8443, nil, append([]byte{msgActivatePort, 0x20, 0xfb}, head...)},
		{"real address", 8443, from, append(from.AppendTo([]byte{msgActivateFrom, 0x20, 0xfb}), head...)},
		{"real address, one service", 0, from, append(from.AppendTo([]byte{msgActivateFrom, 0, 0}), head...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edgeSide, originSide := net.Pipe()
			defer edgeSide.Close()
			defer originSide.Close()
			got := make(chan []byte, 1)
			go func() {
				buf := make([]byte, len(tc.want))
				_, _ = io.ReadFull(originSide, buf)
				got <- buf
				_, _ = originSide.Write([]byte{msgAck})
			}()
			if err := activate(edgeSide, head, tc.port, tc.from); err != nil {
				t.Fatal(err)
			}
			if b := <-got; !bytes.Equal(b, tc.want) {
				t.Fatalf("sent %x\nwant %x", b, tc.want)
			}
		})
	}
}

func TestProxyProtocolSetting(t *testing.T) {
	for val, want := range map[string]int{"off": 0, "v1": 1, "V2": 2, "no": 0} {
		cfg := DefaultConfig()
		if err := cfg.Set("proxy_protocol", val); err != nil || cfg.ProxyProtocol != want {
			t.Errorf("proxy_protocol = %s gave %d, %v", val, cfg.ProxyProtocol, err)
		}
	}
	for _, val := range []string{"on", "v3", "yes please"} {
		cfg := DefaultConfig()
		if err := cfg.Set("proxy_protocol", val); err == nil {
			t.Errorf("proxy_protocol = %s was accepted", val)
		}
	}
}

// ---------------------------------------------------------------------------
// A service that reads the header, and a tunnel to put in front of it
// ---------------------------------------------------------------------------

// seen is what a service learnt at the start of one connection.
type seen struct {
	kind string // "none", "v1" or "v2"
	src  string // the user's address, or "" when the header said it is unknown
	dst  string
	raw  []byte // with kind "none", the first bytes as they came
}

// ppService reads a PROXY header if one comes, the way a real service set up for
// it would, and then echoes the rest in uppercase like startService.
type ppService struct {
	addr string
	ln   net.Listener
	mu   sync.Mutex
	got  []seen
	wg   sync.WaitGroup
}

func startPPService(t *testing.T) *ppService {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &ppService{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				r := bufio.NewReader(c)
				s.record(readPPHeader(r))
				buf := make([]byte, 8192)
				for {
					n, err := r.Read(buf)
					if n > 0 {
						if _, werr := c.Write(bytes.ToUpper(buf[:n])); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func (s *ppService) record(x seen) {
	s.mu.Lock()
	s.got = append(s.got, x)
	s.mu.Unlock()
}

func (s *ppService) last(t *testing.T) seen {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) == 0 {
		t.Fatalf("the service saw no connection")
	}
	return s.got[len(s.got)-1]
}

// readPPHeader parses either version, or notes that there was none. Every test
// payload is longer than the version 2 signature, so peeking that far is safe.
func readPPHeader(r *bufio.Reader) seen {
	if b, _ := r.Peek(6); string(b) == "PROXY " {
		line, _ := r.ReadString('\n')
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 6 {
			return seen{kind: "v1", src: net.JoinHostPort(f[2], f[4]), dst: net.JoinHostPort(f[3], f[5])}
		}
		return seen{kind: "v1"}
	}
	if b, _ := r.Peek(12); bytes.Equal(b, proxyproto.V2Signature) {
		hdr := make([]byte, 16)
		_, _ = io.ReadFull(r, hdr)
		body := make([]byte, binary.BigEndian.Uint16(hdr[14:]))
		_, _ = io.ReadFull(r, body)
		n := 0
		switch hdr[13] {
		case 0x11:
			n = 4
		case 0x21:
			n = 16
		}
		if hdr[12]&0x0f != 1 || n == 0 {
			return seen{kind: "v2"}
		}
		port := func(b []byte) string { return fmt.Sprint(binary.BigEndian.Uint16(b)) }
		return seen{kind: "v2",
			src: net.JoinHostPort(net.IP(body[:n]).String(), port(body[2*n:])),
			dst: net.JoinHostPort(net.IP(body[n:2*n]).String(), port(body[2*n+2:]))}
	}
	b, _ := r.Peek(r.Buffered())
	return seen{kind: "none", raw: append([]byte{}, b...)}
}

type ppTunnelOpts struct {
	mode             Mode
	transport        Transport
	mux              bool
	edgePP, originPP int
	services         []string
}

// startPPTunnel brings up both halves with the given real-address settings and
// returns the address users connect to for each service, in order.
func startPPTunnel(t *testing.T, o ppTunnelOpts) []string {
	t.Helper()
	tunnelAddr := freeAddr(t)
	var userAddrs, servicePorts []string
	for _, s := range o.services {
		userAddrs = append(userAddrs, freeAddr(t))
		_, p, _ := net.SplitHostPort(s)
		servicePorts = append(servicePorts, p)
	}
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := certPaths(t)

	mk := func(role Role) *Config {
		cfg := DefaultConfig()
		cfg.Name = "pp" + string(role)
		cfg.Mode = o.mode
		cfg.Role = role
		cfg.Transport = o.transport
		cfg.ServerName = "www.example.com"
		cfg.CertFile, cfg.KeyFile = certFile, keyFile
		cfg.Mux = o.mux
		cfg.MuxLinks = 2
		cfg.PoolSize = 3
		cfg.MaxConn = 100
		cfg.MaxPending = 64
		cfg.SpareTTL = 10 * time.Minute
		cfg.ParkTimeout = 15 * time.Minute
		cfg.Drain = time.Second
		cfg.SecretFile = secretPath
		cfg.StatusFile = ""
		cfg.TunnelAddr = tunnelAddr
		if role == RoleEdge {
			cfg.UserListen = strings.Join(userAddrs, ", ")
			if len(o.services) > 1 {
				cfg.ServerInboundPort = strings.Join(servicePorts, ", ")
			}
			cfg.ProxyProtocol = o.edgePP
		} else {
			cfg.InboundAddr = strings.Join(o.services, ", ")
			cfg.ProxyProtocol = o.originPP
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config %s/%s: %v", o.mode, role, err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	edgeCfg, originCfg := mk(RoleEdge), mk(RoleOrigin)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	start := func(run func(context.Context, *Config, *status) error, cfg *Config) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run(ctx, cfg, newStatus(cfg)); err != nil {
				t.Logf("%s exited: %v", cfg.Role, err)
			}
		}()
	}
	if o.mode == ModeDirect {
		start(runOrigin, originCfg)
		time.Sleep(200 * time.Millisecond)
		start(runEdge, edgeCfg)
	} else {
		start(runEdge, edgeCfg)
		time.Sleep(200 * time.Millisecond)
		start(runOrigin, originCfg)
	}
	time.Sleep(1200 * time.Millisecond)
	t.Cleanup(func() { cancel(); wg.Wait() })
	return userAddrs
}

// visit connects as a user, sends payload, checks the echo, and returns the
// address the user connected from.
func visit(t *testing.T, userAddr, payload string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", userAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("no reply through the tunnel: %v", err)
	}
	if string(buf) != strings.ToUpper(payload) {
		t.Fatalf("got %q back, want %q: the header leaked into the user's data, or the data was changed",
			buf, strings.ToUpper(payload))
	}
	return c.LocalAddr().String()
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

// The service learns the address the user really connected from, and the one
// they reached, over every kind of link, in both directions, shared or not.
func TestRealAddressReachesTheService(t *testing.T) {
	type combo struct {
		tr      Transport
		mux     bool
		version int
	}
	var combos []combo
	for _, tr := range []Transport{TransportPlain, TransportTLS, TransportWSS, TransportH2, TransportKCP} {
		combos = append(combos, combo{tr, false, proxyproto.V1})
	}
	combos = append(combos,
		combo{TransportPlain, true, proxyproto.V1},
		combo{TransportTLS, true, proxyproto.V1},
		combo{TransportPlain, false, proxyproto.V2},
		combo{TransportTLS, true, proxyproto.V2},
	)
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		for _, c := range combos {
			name := fmt.Sprintf("%s/%s/mux=%v/%s", mode, c.tr, c.mux, proxyproto.SettingName(c.version))
			t.Run(name, func(t *testing.T) {
				svc := startPPService(t)
				users := startPPTunnel(t, ppTunnelOpts{mode: mode, transport: c.tr, mux: c.mux,
					edgePP: c.version, originPP: c.version, services: []string{svc.addr}})
				for i := 0; i < 2; i++ {
					from := visit(t, users[0], fmt.Sprintf("hello-real-address-%d", i))
					got := svc.last(t)
					want := proxyproto.SettingName(c.version)
					if got.kind != want || got.src != from || got.dst != users[0] {
						t.Fatalf("the service saw %+v\nwant a %s header from %s to %s", got, want, from, users[0])
					}
				}
			})
		}
	}
}

// With several services behind one tunnel, each user still reaches the right
// one, and each service is told who it is.
func TestRealAddressWithSeveralServices(t *testing.T) {
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mux=%v", mode, mux), func(t *testing.T) {
				one, two := startPPService(t), startPPService(t)
				users := startPPTunnel(t, ppTunnelOpts{mode: mode, transport: TransportPlain, mux: mux,
					edgePP: proxyproto.V1, originPP: proxyproto.V1, services: []string{one.addr, two.addr}})
				for i, svc := range []*ppService{one, two} {
					from := visit(t, users[i], fmt.Sprintf("to-service-number-%d", i+1))
					if got := svc.last(t); got.src != from || got.dst != users[i] {
						t.Fatalf("service %d saw %+v; want from %s to %s", i+1, got, from, users[i])
					}
				}
			})
		}
	}
}

// When only one server has it on, the tunnel keeps working and the log says
// which to change. With it off on both, the service gets the user's bytes and
// nothing else, as it always has.
func TestRealAddressSettingsDisagreeing(t *testing.T) {
	cases := []struct {
		name             string
		edgePP, originPP int
		wantKind         string
		wantSrc          string
		wantLog          string
	}{
		{"off on both", proxyproto.Off, proxyproto.Off, "none", "", ""},
		{"on at the edge only", proxyproto.V1, proxyproto.Off, "none", "",
			"is sending users' real addresses, but proxy_protocol is off here"},
		{"on at the origin only", proxyproto.Off, proxyproto.V1, "v1", "",
			"proxy_protocol is on here, but the other server is not sending"},
		{"on at the origin only, v2", proxyproto.Off, proxyproto.V2, "v2", "",
			"proxy_protocol is on here, but the other server is not sending"},
	}
	for _, mode := range []Mode{ModeDirect, ModeReverse} {
		for _, tc := range cases {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				logs := captureLog(t)
				svc := startPPService(t)
				users := startPPTunnel(t, ppTunnelOpts{mode: mode, transport: TransportPlain,
					edgePP: tc.edgePP, originPP: tc.originPP, services: []string{svc.addr}})
				const payload = "only-the-users-own-bytes"
				visit(t, users[0], payload)
				got := svc.last(t)
				if got.kind != tc.wantKind || got.src != tc.wantSrc {
					t.Fatalf("the service saw %+v; want kind %q, source %q", got, tc.wantKind, tc.wantSrc)
				}
				if tc.wantKind == "none" && string(got.raw) != payload {
					t.Fatalf("the service's first bytes were %q, want exactly %q", got.raw, payload)
				}
				if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
					t.Fatalf("the log does not say %q:\n%s", tc.wantLog, logs.String())
				}
				if tc.wantLog == "" && strings.Contains(logs.String(), "proxy_protocol") {
					t.Fatalf("the log mentions proxy_protocol with the setting off on both:\n%s", logs.String())
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

func TestSummarySaysUsersAddressesArePassedOn(t *testing.T) {
	for role, want := range map[Role]string{
		RoleEdge:   "real address is sent to the other server",
		RoleOrigin: "told each user's real address (PROXY protocol v2)",
	} {
		cfg := DefaultConfig()
		cfg.Role = role
		cfg.ProxyProtocol = proxyproto.V2
		if s := cfg.Summary(); !strings.Contains(s, want) {
			t.Errorf("%s summary does not say %q: %s", role, want, s)
		}
		cfg.ProxyProtocol = proxyproto.Off
		if s := cfg.Summary(); strings.Contains(s, "real address") {
			t.Errorf("%s summary mentions real addresses with it off: %s", role, s)
		}
	}
}
