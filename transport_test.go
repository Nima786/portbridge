package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// certPaths gives a tunnel somewhere to keep its generated certificate.
func certPaths(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
}

// startTunnelT is startTunnel with a transport and hostname applied to both ends.
func startTunnelT(t *testing.T, mode Mode, tr Transport, serverName, serviceAddr string, poolSize int) *tunnel {
	t.Helper()

	tunnelAddr := freeAddr(t)
	userAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)
	certFile, keyFile := certPaths(t)

	mk := func(role Role) *Config {
		cfg := defaultConfig()
		cfg.Name = "tr" + string(role)
		cfg.Mode = mode
		cfg.Role = role
		cfg.TunnelAddr = tunnelAddr
		cfg.PoolSize = poolSize
		cfg.MaxConn = 100
		cfg.MaxPending = 64
		cfg.Drain = 2 * time.Second
		cfg.SecretFile = secretPath
		cfg.StatusFile = ""
		cfg.Transport = tr
		cfg.ServerName = serverName
		cfg.CertFile = certFile
		cfg.KeyFile = keyFile
		if role == RoleEdge {
			cfg.UserListen = userAddr
		} else {
			cfg.InboundAddr = serviceAddr
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config %s/%s/%s: %v", mode, tr, role, err)
		}
		if err := cfg.LoadSecret(); err != nil {
			t.Fatalf("secret: %v", err)
		}
		return cfg
	}

	edgeCfg, originCfg := mk(RoleEdge), mk(RoleOrigin)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	startEdge := func() {
		go func() {
			defer wg.Done()
			if err := runEdge(ctx, edgeCfg, newStatus(edgeCfg)); err != nil {
				t.Logf("edge exited: %v", err)
			}
		}()
	}
	startOrigin := func() {
		go func() {
			defer wg.Done()
			if err := runOrigin(ctx, originCfg, newStatus(originCfg)); err != nil {
				t.Logf("origin exited: %v", err)
			}
		}()
	}
	if mode == ModeDirect {
		startOrigin()
		time.Sleep(200 * time.Millisecond)
		startEdge()
	} else {
		startEdge()
		time.Sleep(200 * time.Millisecond)
		startOrigin()
	}
	time.Sleep(900 * time.Millisecond)

	return &tunnel{userAddr: userAddr, stop: func() { cancel(); wg.Wait() }}
}

// Traffic must flow over every disguise, in both modes.
func TestTrafficFlowsOverEveryTransport(t *testing.T) {
	for _, tr := range []Transport{TransportPlain, TransportTLS, TransportWSS, TransportH2, TransportGRPC} {
		for _, mode := range []Mode{ModeDirect, ModeReverse} {
			t.Run(string(tr)+"/"+string(mode), func(t *testing.T) {
				svc := startService(t)
				defer svc.stop()

				tun := startTunnelT(t, mode, tr, "www.example.com", svc.addr, 3)
				defer tun.stop()

				if n := svc.connections(); n != 0 {
					t.Fatalf("service saw %d connections before any user", n)
				}
				got, err := roundTrip(t, tun.userAddr, "hello-disguise", 15*time.Second)
				if err != nil {
					t.Fatalf("round trip failed: %v", err)
				}
				if got != "HELLO-DISGUISE" {
					t.Fatalf("got %q", got)
				}
			})
		}
	}
}

// Larger transfers must survive the framing, not just short messages.
func TestLargeTransferOverEveryTransport(t *testing.T) {
	payload := bytes.Repeat([]byte("PortBridge"), 120_000) // 1.2 MB

	for _, tr := range []Transport{TransportTLS, TransportWSS, TransportH2, TransportGRPC} {
		t.Run(string(tr), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						_, _ = io.Copy(io.Discard, c)
						_, _ = c.Write(payload)
					}(c)
				}
			}()

			tun := startTunnelT(t, ModeDirect, tr, "cdn.example.com", ln.Addr().String(), 2)
			defer tun.stop()

			c, err := net.DialTimeout("tcp", tun.userAddr, 10*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			if _, err := c.Write([]byte("go")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload came back wrong: %d bytes of %d", len(got), len(payload))
			}
		})
	}
}

// The whole point of the TLS disguise: an onlooker must see an ordinary HTTPS
// handshake, with a certificate and a server name, not unexplained random bytes.
func TestLinkLooksLikeHTTPS(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	// Watch the first bytes the edge sends by putting a listener in the middle.
	tunnelAddr := freeAddr(t)
	secretPath := writeSecret(t, testSecret)
	certFile, keyFile := certPaths(t)

	cfg := defaultConfig()
	cfg.Name = "peek"
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.TunnelAddr = tunnelAddr
	cfg.UserListen = freeAddr(t)
	cfg.PoolSize = 1
	cfg.SecretFile = secretPath
	cfg.StatusFile = ""
	cfg.Transport = TransportTLS
	cfg.ServerName = "www.wikipedia.org"
	cfg.CertFile, cfg.KeyFile = certFile, keyFile
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := cfg.LoadSecret(); err != nil {
		t.Fatalf("secret: %v", err)
	}

	ln, err := net.Listen("tcp", tunnelAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	seen := make(chan []byte, 1)
	sniSeen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		head := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _ := c.Read(head)
		seen <- head[:n]

		// Complete the handshake far enough to read the requested hostname.
		cert, err := ensureCert(certFile, keyFile, "www.wikipedia.org")
		if err != nil {
			return
		}
		replay := &prefixConn{Conn: c, pre: head[:n]}
		ts := tls.Server(replay, &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				sniSeen <- h.ServerName
				return nil, nil
			},
		})
		_ = ts.Handshake()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runEdge(ctx, cfg, newStatus(cfg)) }()

	var head []byte
	select {
	case head = <-seen:
	case <-time.After(10 * time.Second):
		t.Fatal("the edge never connected")
	}

	if len(head) < 6 {
		t.Fatalf("only %d bytes sent", len(head))
	}
	// A TLS record: handshake type 0x16, version 0x03 0x01, then a ClientHello.
	if head[0] != 0x16 || head[1] != 0x03 {
		t.Fatalf("first bytes are not a TLS handshake: % x", head[:6])
	}
	if head[5] != 0x01 {
		t.Fatalf("not a ClientHello: % x", head[:6])
	}
	if !bytes.Contains(head, []byte("www.wikipedia.org")) {
		t.Fatal("the chosen hostname was not sent, so the disguise is incomplete")
	}
	select {
	case got := <-sniSeen:
		if got != "www.wikipedia.org" {
			t.Fatalf("server saw hostname %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handshake never reached the hostname")
	}
}

// prefixConn replays bytes already read, so the handshake can be inspected and
// then completed.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// With the CDN disguise the link must begin with a real HTTP upgrade request,
// because that is what a CDN needs in order to forward it.
func TestCDNLinkSendsHTTPUpgrade(t *testing.T) {
	svc := startService(t)
	defer svc.stop()

	tunnelAddr := freeAddr(t)
	certFile, keyFile := certPaths(t)

	cfg := defaultConfig()
	cfg.Name = "wspeek"
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.TunnelAddr = tunnelAddr
	cfg.UserListen = freeAddr(t)
	cfg.PoolSize = 1
	cfg.SecretFile = writeSecret(t, testSecret)
	cfg.StatusFile = ""
	cfg.Transport = TransportWSS
	cfg.ServerName = "cdn.example.com"
	cfg.WSPath = "/live/stream"
	cfg.CertFile, cfg.KeyFile = certFile, keyFile
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := cfg.LoadSecret(); err != nil {
		t.Fatalf("secret: %v", err)
	}

	cert, err := ensureCert(certFile, keyFile, "cdn.example.com")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	ln, err := tls.Listen("tcp", tunnelAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		var sb strings.Builder
		for i := 0; i < 12; i++ {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			sb.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		got <- sb.String()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runEdge(ctx, cfg, newStatus(cfg)) }()

	select {
	case req := <-got:
		for _, want := range []string{
			"GET /live/stream HTTP/1.1",
			"Host: cdn.example.com",
			"Upgrade: websocket",
			"Sec-WebSocket-Key:",
		} {
			if !strings.Contains(req, want) {
				t.Fatalf("upgrade request missing %q:\n%s", want, req)
			}
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no upgrade request arrived")
	}
}

// Anything that is not a valid upgrade must look like an unremarkable web
// server, so that probing the port gives nothing away.
func TestProbingTheCDNPortLooksLikeAWebServer(t *testing.T) {
	cfg := defaultConfig()
	cfg.Transport = TransportWSS
	cfg.WSPath = "/live/stream"

	for _, probe := range []string{
		"GET / HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n",                    // wrong path
		"GET /live/stream HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n",         // right path, no upgrade
		"POST /live/stream HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", // wrong method
	} {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() {
			_, err := wsAccept(server, cfg)
			done <- err
			_ = server.Close()
		}()

		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(client, probe); err != nil {
			t.Fatalf("write probe: %v", err)
		}
		body, _ := io.ReadAll(client)
		_ = client.Close()

		if err := <-done; err == nil {
			t.Fatalf("a probe was accepted as a tunnel connection: %q", probe)
		}
		got := string(body)
		for _, want := range []string{"404 Not Found", "nginx"} {
			if !strings.Contains(got, want) {
				t.Fatalf("probe reply does not look like a web server (missing %q):\n%s", want, got)
			}
		}
		if strings.Contains(strings.ToLower(got), "portbridge") ||
			strings.Contains(strings.ToLower(got), "tunnel") {
			t.Fatalf("probe reply gives the tunnel away:\n%s", got)
		}
	}
}

func TestTransportSettingsValidation(t *testing.T) {
	base := func() *Config {
		c := defaultConfig()
		c.Name = "ok"
		c.Mode = ModeDirect
		c.Role = RoleOrigin
		c.TunnelAddr = "0.0.0.0:443"
		c.InboundAddr = "127.0.0.1:26963"
		c.SecretFile = "/tmp/s"
		return c
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("plain config rejected: %v", err)
	}

	c := base()
	c.Transport = "sideways"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "transport must be") {
		t.Fatalf("bad transport gave %v", err)
	}

	// The accepting side needs somewhere to keep its certificate.
	c = base()
	c.Transport = TransportTLS
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cert_file") {
		t.Fatalf("missing cert paths gave %v", err)
	}
	c.CertFile, c.KeyFile = "/tmp/c.pem", "/tmp/k.pem"
	if err := c.Validate(); err != nil {
		t.Fatalf("tls config with cert paths rejected: %v", err)
	}

	// A hostname on its own must not change where we connect. Wanting a name for
	// the disguise is a different thing from wanting a CDN in the path.
	c = base()
	c.Role = RoleEdge
	c.UserListen = "0.0.0.0:26963"
	c.TunnelAddr = "198.51.100.10:443"
	c.Transport = TransportWSS
	c.ServerName = "www.example.com"
	if err := c.Validate(); err != nil {
		t.Fatalf("websocket disguise with a hostname rejected: %v", err)
	}
	if got := c.dialTarget(); got != "198.51.100.10:443" {
		t.Fatalf("a hostname alone changed the destination to %q", got)
	}

	// Turning the CDN on is what redirects the connection to the hostname, so
	// the other server's address never appears on the link.
	c.CDN = true
	if err := c.Validate(); err != nil {
		t.Fatalf("cdn with a hostname rejected: %v", err)
	}
	if got := c.dialTarget(); got != "www.example.com:443" {
		t.Fatalf("with a cdn the destination is %q, so the address is still exposed", got)
	}

	// A CDN needs a hostname, and only carries a websocket over TLS.
	c.ServerName = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server_name is required") {
		t.Fatalf("cdn without a hostname gave %v", err)
	}
	c.ServerName = "198.51.100.10"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "must be a hostname") {
		t.Fatalf("cdn with an address as the hostname gave %v", err)
	}
	c.ServerName = "www.example.com"
	c.Transport = TransportTLS
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cdn needs transport") {
		t.Fatalf("cdn without the websocket disguise gave %v", err)
	}
}

func TestCertificateIsCreatedThenReused(t *testing.T) {
	certFile, keyFile := certPaths(t)

	c1, err := ensureCert(certFile, keyFile, "example.org")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if !fileExists(certFile) || !fileExists(keyFile) {
		t.Fatal("certificate files were not written")
	}
	// Only meaningful where the operating system enforces file permissions.
	// Windows does not, so the check would fail there for no good reason.
	if runtime.GOOS == "linux" {
		st, err := os.Stat(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		if mode := st.Mode().Perm(); mode != 0o600 {
			t.Fatalf("private key is readable by others: %v", mode)
		}
	}

	c2, err := ensureCert(certFile, keyFile, "example.org")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(c1.Certificate[0], c2.Certificate[0]) {
		t.Fatal("a second call made a new certificate instead of reusing the first")
	}

	leaf, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if leaf.Subject.CommonName != "example.org" {
		t.Fatalf("wrong name: %q", leaf.Subject.CommonName)
	}
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life < 300*24*time.Hour {
		t.Fatalf("certificate life is only %v, which would look unusual", life)
	}
}

func TestWrongSecretRefusedOverEveryTransport(t *testing.T) {
	for _, tr := range []Transport{TransportTLS, TransportWSS} {
		t.Run(string(tr), func(t *testing.T) {
			svc := startService(t)
			defer svc.stop()

			tunnelAddr := freeAddr(t)
			userAddr := freeAddr(t)
			certFile, keyFile := certPaths(t)

			mk := func(role Role, secret string) *Config {
				cfg := defaultConfig()
				cfg.Name = "ws" + string(role)
				cfg.Mode = ModeDirect
				cfg.Role = role
				cfg.TunnelAddr = tunnelAddr
				cfg.PoolSize = 2
				cfg.Drain = time.Second
				cfg.SecretFile = writeSecret(t, secret)
				cfg.StatusFile = ""
				cfg.Transport = tr
				cfg.ServerName = "www.example.com"
				cfg.CertFile, cfg.KeyFile = certFile, keyFile
				if role == RoleEdge {
					cfg.UserListen = userAddr
				} else {
					cfg.InboundAddr = svc.addr
				}
				if err := cfg.Validate(); err != nil {
					t.Fatalf("validate: %v", err)
				}
				if err := cfg.LoadSecret(); err != nil {
					t.Fatalf("secret: %v", err)
				}
				return cfg
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			oc := mk(RoleOrigin, testSecret)
			go func() { _ = runOrigin(ctx, oc, newStatus(oc)) }()
			time.Sleep(200 * time.Millisecond)
			ec := mk(RoleEdge, "a-totally-different-secret")
			go func() { _ = runEdge(ctx, ec, newStatus(ec)) }()
			time.Sleep(800 * time.Millisecond)

			if _, err := roundTrip(t, userAddr, "nope", 8*time.Second); err == nil {
				t.Fatal("traffic passed with mismatched secrets")
			}
			if n := svc.connections(); n != 0 {
				t.Fatalf("service saw %d connections despite a wrong secret", n)
			}
		})
	}
}

func TestSummaryNamesTheDisguise(t *testing.T) {
	mk := func(tr Transport, cdn bool) string {
		c := defaultConfig()
		c.Name = "x"
		c.Mode = ModeDirect
		c.Role = RoleEdge
		c.TunnelAddr = "198.51.100.1:443"
		c.UserListen = "0.0.0.0:26963"
		c.Transport = tr
		c.ServerName = "www.example.com"
		c.CDN = cdn
		return c.Summary()
	}

	for _, tc := range []struct {
		tr   Transport
		cdn  bool
		want string
	}{
		{TransportPlain, false, "plain, no disguise"},
		{TransportTLS, false, "disguised as an HTTPS site"},
		{TransportWSS, false, "websocket over HTTPS"},
		{TransportWSS, true, "routed through a CDN"},
		{TransportH2, false, "disguised as HTTP/2"},
		{TransportGRPC, false, "disguised as gRPC over HTTP/2"},
	} {
		if got := mk(tc.tr, tc.cdn); !strings.Contains(got, tc.want) {
			t.Errorf("%s (cdn=%v) summary missing %q: %s", tc.tr, tc.cdn, tc.want, got)
		}
	}
	// Without a CDN the summary must not claim one.
	if got := mk(TransportWSS, false); strings.Contains(got, "CDN") {
		t.Errorf("summary mentions a CDN when none is configured: %s", got)
	}
}

// Repeat connections on a disguised link must resume the previous session
// instead of negotiating from scratch.
//
// This is the single most expensive thing either server does: measured on a real
// machine, setting up the disguise accounted for more than half of all processor
// time on a disguised tunnel, because one connection is spent per user and a full
// negotiation was paid to replace it. Resumption only works if both ends keep
// their settings between connections, which is exactly what is easy to undo by
// accident, and nothing else in the program would notice if it broke.
func TestDisguisedLinkResumesInsteadOfRenegotiating(t *testing.T) {
	for _, tr := range []Transport{TransportTLS, TransportWSS, TransportH2, TransportGRPC} {
		t.Run(string(tr), func(t *testing.T) {
			certFile, keyFile := certPaths(t)
			cert, err := ensureCert(certFile, keyFile, "www.example.com")
			if err != nil {
				t.Fatalf("cert: %v", err)
			}

			// Both sides, prepared the way a running tunnel prepares them.
			accepting := defaultConfig()
			accepting.Transport = tr
			accepting.ServerName = "www.example.com"
			accepting.WSPath = "/tunnel"
			accepting.Mode = ModeDirect
			accepting.Role = RoleOrigin // accepts in direct mode
			accepting.prepareTLS(&cert)

			dialling := defaultConfig()
			dialling.Transport = tr
			dialling.ServerName = "www.example.com"
			dialling.WSPath = "/tunnel"
			dialling.Mode = ModeDirect
			dialling.Role = RoleEdge // dials in direct mode
			dialling.TunnelAddr = "127.0.0.1:1"
			dialling.prepareTLS(nil)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			go func() {
				for {
					raw, err := ln.Accept()
					if err != nil {
						return
					}
					go func(raw net.Conn) {
						c, err := wrapAccept(raw, accepting, &cert)
						if err != nil {
							_ = raw.Close()
							return
						}
						// One byte back, as the real handshake does. It matters:
						// the resumable session is offered by the accepting side
						// after the negotiation finishes, so the dialling side
						// only learns of it when it next reads. In the running
						// tunnel that read is the one waiting to be told a user
						// has arrived.
						_, _ = c.Write([]byte{msgAck})
						time.Sleep(150 * time.Millisecond)
						_ = c.Close()
					}(raw)
				}
			}()

			resumed := 0
			const attempts = 4
			for i := 0; i < attempts; i++ {
				raw, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				c, err := wrapDial(raw, dialling)
				if err != nil {
					t.Fatalf("connection %d failed: %v", i, err)
				}
				var one [1]byte
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, one[:]); err != nil {
					t.Fatalf("connection %d never heard back: %v", i, err)
				}
				_ = c.SetReadDeadline(time.Time{})

				// The disguise wraps the secured connection, so reach
				// through it for the one underneath.
				under := c
				if ws, ok := c.(*wsConn); ok {
					under = ws.Conn
				}
				if h2, ok := c.(*h2Conn); ok {
					under = h2.Conn
				}
				tc, ok := under.(*tls.Conn)
				if !ok {
					t.Fatalf("connection %d is not a secured connection: %T", i, under)
				}
				st := tc.ConnectionState()
				if st.DidResume {
					resumed++
				}
				_ = c.Close()
				time.Sleep(150 * time.Millisecond)
			}

			if resumed == 0 {
				t.Fatalf("none of %d repeat connections resumed, so every user pays for a full negotiation", attempts)
			}
		})
	}
}
