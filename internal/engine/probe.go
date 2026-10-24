package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CDNHTTPSPorts lists the HTTPS ports supported by Cloudflare's proxy.
// Picking one of these for the probe listener allows the exact same port to
// serve both direct transport probes and Cloudflare CDN probes.
var CDNHTTPSPorts = []int{2053, 2083, 2087, 2096, 8443, 443}

// ProbeCandidateSpec describes one tunnel configuration to benchmark.
type ProbeCandidateSpec struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Mode       string `json:"mode"`       // "direct" or "reverse"
	Link       string `json:"link"`       // panel/CLI link key: "website", "sni-spoof", "split", "website-cdn-backup", "cdn", "grpc", "grpc-cdn", "kcp", "ip-spoof", "faketcp", "icmp", "plain"
	Transport  string `json:"transport"`  // engine transport: "tls", "wss", "grpc", "kcp", "icmp", "faketcp", "plain"
	Stealth    bool   `json:"stealth"`    // uTLS browser fingerprint + ClientHello fragmentation
	WebHeader  bool   `json:"web_header"` // HTTP header obfuscation on plain TCP
	SNISpoof   bool   `json:"sni_spoof,omitempty"`
	SpoofSNI   string `json:"spoof_sni,omitempty"`
	IPSpoof    bool   `json:"ip_spoof,omitempty"`
	SpoofIP    string `json:"spoof_ip,omitempty"`
	AntiFreeze bool   `json:"anti_freeze,omitempty"`
	CDN        bool   `json:"cdn"`
	IPv6       bool   `json:"ipv6"`
	Shared     bool   `json:"shared"` // recommended pooling mode (mux vs pool)
	Gaming     bool   `json:"gaming,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Domain     string `json:"domain,omitempty"`
	TargetAddr string `json:"target_addr"` // host:port to dial
	Port       int    `json:"port"`
}

// ProbeCandidateResult holds the measured metrics and computed score for one candidate.
type ProbeCandidateResult struct {
	ProbeCandidateSpec
	Status      string  `json:"status"` // "ok", "throttled", "degraded", "blocked"
	Error       string  `json:"error,omitempty"`
	Attempts    int     `json:"attempts"`
	Successes   int     `json:"successes"`
	HandshakeMS float64 `json:"handshake_ms"`
	RTTMS       float64 `json:"rtt_ms"`
	JitterMS    float64 `json:"jitter_ms"`
	DownMbps    float64 `json:"down_mbps"`
	UpMbps      float64 `json:"up_mbps"`
	AvgMbps     float64 `json:"avg_mbps"`
	Score       int     `json:"score"`
	Summary     string  `json:"summary"`
	Hybrid      bool    `json:"hybrid,omitempty"`
	// Retested is set when the result was checked a second time at the end
	// of the run (see ProbeRetestIDs).
	Retested bool `json:"retested,omitempty"`
}

// ProbeBenchmarkReport is the full ranked benchmark output.
type ProbeBenchmarkReport struct {
	Recommended *ProbeCandidateResult  `json:"recommended,omitempty"`
	Results     []ProbeCandidateResult `json:"results"`
	TestedAt    time.Time              `json:"tested_at"`
	Notes       []string               `json:"notes,omitempty"`
}

// ProbeListener accepts multi-transport probe connections on one TCP port,
// one UDP (KCP) port, and optional raw ICMP / FakeTCP listeners with the same port number.
type ProbeListener struct {
	Port   int
	Secret []byte

	tcpLn     net.Listener
	kcpLn     net.Listener
	kcp6Ln    net.Listener // IPv6-only UDP; nil when bound to one address
	icmpLn    net.Listener
	fakeTCPLn net.Listener
	splitMgr  *splitSessionManager
	cert      tls.Certificate
	closed    chan struct{}
	once      sync.Once
}

type peekedConn struct {
	net.Conn
	peeked []byte
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if len(p.peeked) > 0 {
		n := copy(b, p.peeked)
		p.peeked = p.peeked[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func makeEphemeralCert(cn string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	if cn == "" {
		cn = "www.bing.com"
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn, "www.bing.com", "www.google.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

// StartProbeListener binds a free TCP+UDP port (preferring preferredPort and
// Cloudflare HTTPS ports) and serves probe connections until Close() or ttl.
func StartProbeListener(bindHost string, preferredPort int, secret []byte, ttl time.Duration) (*ProbeListener, error) {
	return StartProbeListenerAvoiding(bindHost, preferredPort, nil, secret, ttl)
}

// StartProbeListenerAvoiding is StartProbeListener that never takes one of the
// avoid ports. A port nothing listens on can still belong to something: a
// stopped tunnel owns its port, and a benchmark that tested on it would
// recommend a port the new tunnel then cannot have.
func StartProbeListenerAvoiding(bindHost string, preferredPort int, avoid map[int]bool, secret []byte, ttl time.Duration) (*ProbeListener, error) {
	if len(secret) < 16 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	cert, err := makeEphemeralCert("www.bing.com")
	if err != nil {
		return nil, err
	}

	var candidates []int
	if preferredPort > 0 && !avoid[preferredPort] {
		candidates = append(candidates, preferredPort)
	}
	// Then the other HTTPS-looking ports a tunnel's bridge is usually given
	// (the ones Auto-Heal picks from too), before any random one.
	for _, p := range append(append([]int(nil), CDNHTTPSPorts...), 4433, 7443, 9443) {
		if p != preferredPort && !avoid[p] {
			candidates = append(candidates, p)
		}
	}
	// OS-assigned fallback, tried a few times in case it hands out a port
	// that is to be avoided.
	candidates = append(candidates, 0, 0, 0)

	kcpCfg := &Config{
		Transport:       TransportKCP,
		secret:          secret,
		KCPDataShards:   10,
		KCPParityShards: 3,
		IPSpoof:         true,
		allowPlainKCP:   true,
	}
	probeKCPDefaults(kcpCfg)

	listenHost := bindHost
	if listenHost == "0.0.0.0" {
		listenHost = ""
	}

	var tcpLn net.Listener
	var kcpLn net.Listener
	var chosenPort int

	for _, port := range candidates {
		addr := net.JoinHostPort(listenHost, strconv.Itoa(port))
		tln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		actualPort := tln.Addr().(*net.TCPAddr).Port
		if avoid[actualPort] {
			_ = tln.Close()
			continue
		}
		uaddr := net.JoinHostPort(listenHost, strconv.Itoa(actualPort))
		uln, err := kcpListen(uaddr, kcpCfg)
		if err != nil {
			_ = tln.Close()
			continue
		}
		tcpLn = tln
		kcpLn = uln
		chosenPort = actualPort
		break
	}
	if tcpLn == nil {
		return nil, errors.New("could not find a free TCP+UDP port for the probe listener")
	}

	rawAddr := net.JoinHostPort(listenHost, strconv.Itoa(chosenPort))
	icmpCfg := &Config{
		Transport:       TransportICMP,
		secret:          secret,
		KCPDataShards:   10,
		KCPParityShards: 3,
	}
	probeKCPDefaults(icmpCfg)
	icmpLn, _ := kcpListen(rawAddr, icmpCfg)
	fakeCfg := &Config{
		Transport:       TransportFakeTCP,
		secret:          secret,
		KCPDataShards:   10,
		KCPParityShards: 3,
	}
	probeKCPDefaults(fakeCfg)
	fakeTCPLn, _ := kcpListen(rawAddr, fakeCfg)

	// The KCP listener above takes IPv4 only (it also has to accept the
	// spoofed-source candidates), so KCP over IPv6 gets its own IPv6-only
	// UDP socket on the same port. Without it the IPv6 KCP candidate always
	// timed out, though a real KCP tunnel over IPv6 works.
	var kcp6Ln net.Listener
	if listenHost == "" {
		if u6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: chosenPort}); err == nil {
			kcp6Cfg := &Config{
				Transport:       TransportKCP,
				secret:          secret,
				KCPDataShards:   10,
				KCPParityShards: 3,
				allowPlainKCP:   true,
			}
			probeKCPDefaults(kcp6Cfg)
			if ln6, err := kcpServePacketConn(u6, kcp6Cfg); err == nil {
				kcp6Ln = ln6
			} else {
				_ = u6.Close()
			}
		}
	}

	pl := &ProbeListener{
		Port:      chosenPort,
		Secret:    secret,
		tcpLn:     tcpLn,
		kcpLn:     kcpLn,
		kcp6Ln:    kcp6Ln,
		icmpLn:    icmpLn,
		fakeTCPLn: fakeTCPLn,
		splitMgr:  newSplitSessionManager(),
		cert:      cert,
		closed:    make(chan struct{}),
	}

	go pl.serveTCP()
	go pl.servePacketLn(pl.kcpLn)
	if pl.kcp6Ln != nil {
		go pl.servePacketLn(pl.kcp6Ln)
	}
	if pl.icmpLn != nil {
		go pl.servePacketLn(pl.icmpLn)
	}
	if pl.fakeTCPLn != nil {
		go pl.servePacketLn(pl.fakeTCPLn)
	}
	time.AfterFunc(ttl, func() { pl.Close() })

	return pl, nil
}

// Close stops all probe listeners.
func (pl *ProbeListener) Close() {
	pl.once.Do(func() {
		close(pl.closed)
		if pl.tcpLn != nil {
			_ = pl.tcpLn.Close()
		}
		if pl.kcpLn != nil {
			_ = pl.kcpLn.Close()
		}
		if pl.kcp6Ln != nil {
			_ = pl.kcp6Ln.Close()
		}
		if pl.icmpLn != nil {
			_ = pl.icmpLn.Close()
		}
		if pl.fakeTCPLn != nil {
			_ = pl.fakeTCPLn.Close()
		}
	})
}

func (pl *ProbeListener) serveTCP() {
	for {
		raw, err := pl.tcpLn.Accept()
		if err != nil {
			select {
			case <-pl.closed:
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// A listener that keeps failing (out of file descriptors,
				// say) must not turn this loop into a busy spin.
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		go pl.handleTCPConn(raw)
	}
}

func (pl *ProbeListener) handleTCPConn(raw net.Conn) {
	tuneSocket(raw)
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))

	var first [1]byte
	if _, err := io.ReadFull(raw, first[:]); err != nil {
		_ = raw.Close()
		return
	}
	pconn := &peekedConn{Conn: raw, peeked: []byte{first[0]}}

	switch first[0] {
	case 0x16: // TLS Handshake record
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{pl.cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		}
		ts := tls.Server(pconn, tlsCfg)
		if err := ts.Handshake(); err != nil {
			_ = raw.Close()
			return
		}
		_ = ts.SetDeadline(time.Now().Add(15 * time.Second))
		var innerFirst [1]byte
		if _, err := io.ReadFull(ts, innerFirst[:]); err != nil {
			_ = ts.Close()
			return
		}
		innerConn := &peekedConn{Conn: ts, peeked: []byte{innerFirst[0]}}

		switch innerFirst[0] {
		case 'G': // WebSocket HTTP/1.1 Upgrade ("GET /tunnel ...")
			wsCfg := &Config{
				Transport: TransportWSS,
				WSPath:    defaultWSPath,
				secret:    pl.Secret,
			}
			wsConn, err := wsAccept(innerConn, wsCfg, nil)
			if err != nil {
				_ = ts.Close()
				return
			}
			if _, err := recvAuthPurpose(wsConn, pl.Secret, nil); err != nil {
				_ = wsConn.Close()
				return
			}
			runSpeedtestServer(wsConn)

		case 'P': // HTTP/2 / gRPC client preface ("PRI * HTTP/2.0...")
			h2Cfg := &Config{
				Transport: TransportGRPC,
				WSPath:    defaultWSPath,
				secret:    pl.Secret,
			}
			h2Conn, err := h2Accept(innerConn, h2Cfg)
			if err != nil {
				_ = ts.Close()
				return
			}
			if _, err := recvAuthPurpose(h2Conn, pl.Secret, nil); err != nil {
				_ = h2Conn.Close()
				return
			}
			runSpeedtestServer(h2Conn)

		case 'S': // Possible Anti-Freeze Split-Stream ("SPLIT1...") or random auth nonce starting with 'S'
			var rest [5]byte
			if _, err := io.ReadFull(ts, rest[:]); err != nil {
				_ = ts.Close()
				return
			}
			six := append([]byte{'S'}, rest[:]...)
			fullPeek := &peekedConn{Conn: ts, peeked: six}
			if string(six) == splitMagic {
				sc, isInitial, err := pl.splitMgr.AcceptLeg(fullPeek, pl.Secret)
				if err != nil || !isInitial {
					return
				}
				if _, err := recvAuthPurpose(sc, pl.Secret, nil); err != nil {
					_ = sc.Close()
					return
				}
				runSpeedtestServer(sc)
				return
			}
			if _, err := recvAuthPurpose(fullPeek, pl.Secret, nil); err != nil {
				_ = ts.Close()
				return
			}
			runSpeedtestServer(fullPeek)

		default: // Raw Fake TLS (TransportTLS)
			if _, err := recvAuthPurpose(innerConn, pl.Secret, nil); err != nil {
				_ = ts.Close()
				return
			}
			runSpeedtestServer(innerConn)
		}

	case 'G': // Plain TCP with HTTP Header obfuscation ("GET / ...")
		if err := httpHeaderAccept(pconn); err != nil {
			_ = raw.Close()
			return
		}
		if _, err := recvAuthPurpose(pconn, pl.Secret, nil); err != nil {
			_ = raw.Close()
			return
		}
		runSpeedtestServer(pconn)

	default: // Plain TCP (no header)
		if _, err := recvAuthPurpose(pconn, pl.Secret, nil); err != nil {
			_ = raw.Close()
			return
		}
		runSpeedtestServer(pconn)
	}
}

func (pl *ProbeListener) servePacketLn(ln net.Listener) {
	if ln == nil {
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-pl.closed:
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		go func(conn net.Conn) {
			if _, err := recvAuthPurpose(conn, pl.Secret, nil); err != nil {
				_ = conn.Close()
				return
			}
			runSpeedtestServer(conn)
		}(c)
	}
}

// BuildProbeCandidates constructs the list of transport candidates for a given
// mode ("direct" or "reverse"), target IPv4, optional IPv6, port, and optional
// Cloudflare CDN domain.
func BuildProbeCandidates(mode, ipv4, ipv6 string, port int, cdnDomain string) []ProbeCandidateSpec {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "reverse" {
		mode = "direct"
	}
	dirLabel := "Direct"
	if mode == "reverse" {
		dirLabel = "Reverse"
	}
	v4Label := dirLabel + " (IPv4)"

	var specs []ProbeCandidateSpec
	if ipv4 != "" && port > 0 {
		addr4 := net.JoinHostPort(ipv4, strconv.Itoa(port))
		specs = append(specs,
			ProbeCandidateSpec{
				ID:         mode + "-tls-stealth",
				Label:      v4Label + " · Fake TLS + Stealth (uTLS + Frag)",
				Mode:       mode,
				Link:       "website",
				Transport:  string(TransportTLS),
				Stealth:    true,
				Shared:     false,
				ServerName: "www.bing.com",
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-split",
				Label:      v4Label + " · Split-Stream TLS (Anti-Freeze Rotation)",
				Mode:       mode,
				Link:       "split",
				Transport:  string(TransportTLS),
				Stealth:    true,
				SNISpoof:   true,
				SpoofSNI:   DefaultSpoofSNI,
				AntiFreeze: true,
				Shared:     true,
				ServerName: DefaultSpoofSNI,
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-sni-spoof",
				Label:      v4Label + " · Decoy Whitelisted SNI (" + DefaultSpoofSNI + ")",
				Mode:       mode,
				Link:       "sni-spoof",
				Transport:  string(TransportTLS),
				Stealth:    true,
				SNISpoof:   true,
				SpoofSNI:   DefaultSpoofSNI,
				Shared:     false,
				ServerName: DefaultSpoofSNI,
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-tls",
				Label:      v4Label + " · Fake TLS Website (SNI)",
				Mode:       mode,
				Link:       "website",
				Transport:  string(TransportTLS),
				Stealth:    false,
				Shared:     false,
				ServerName: "www.bing.com",
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-grpc",
				Label:      v4Label + " · gRPC Stream (HTTP/2)",
				Mode:       mode,
				Link:       "grpc",
				Transport:  string(TransportGRPC),
				Stealth:    false,
				Shared:     true,
				ServerName: "www.google.com",
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-kcp",
				Label:      v4Label + " · KCP over UDP (FEC)",
				Mode:       mode,
				Link:       "kcp",
				Transport:  string(TransportKCP),
				Stealth:    false,
				Shared:     true,
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-ip-spoof",
				Label:      v4Label + " · Source IP + SNI Spoof (" + DefaultSpoofIP + ")",
				Mode:       mode,
				Link:       "ip-spoof",
				Transport:  string(TransportKCP),
				SNISpoof:   true,
				SpoofSNI:   DefaultSpoofSNI,
				IPSpoof:    true,
				SpoofIP:    DefaultSpoofIP,
				Shared:     true,
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-faketcp",
				Label:      v4Label + " · Raw FakeTCP · Paqet-Style (KCP+FEC)",
				Mode:       mode,
				Link:       "faketcp",
				Transport:  string(TransportFakeTCP),
				Shared:     true,
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-icmp",
				Label:      v4Label + " · ICMP Ping Tunnel (KCP+FEC)",
				Mode:       mode,
				Link:       "icmp",
				Transport:  string(TransportICMP),
				Shared:     true,
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-http-tcp",
				Label:      v4Label + " · TCP + HTTP Header",
				Mode:       mode,
				Link:       "plain",
				Transport:  string(TransportPlain),
				WebHeader:  true,
				Shared:     false,
				ServerName: "www.bing.com",
				TargetAddr: addr4,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-plain",
				Label:      v4Label + " · Plain TCP (Raw)",
				Mode:       mode,
				Link:       "plain",
				Transport:  string(TransportPlain),
				WebHeader:  false,
				Shared:     false,
				TargetAddr: addr4,
				Port:       port,
			},
		)
	}

	if ipv6 != "" && port > 0 {
		addr6 := net.JoinHostPort(ipv6, strconv.Itoa(port))
		specs = append(specs,
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-tls-stealth",
				Label:      dirLabel + " (IPv6) · Fake TLS + Stealth (uTLS + Frag)",
				Mode:       mode,
				Link:       "website",
				Transport:  string(TransportTLS),
				Stealth:    true,
				IPv6:       true,
				Shared:     false,
				ServerName: "www.bing.com",
				TargetAddr: addr6,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-sni-spoof",
				Label:      dirLabel + " (IPv6) · Decoy Whitelisted SNI (" + DefaultSpoofSNI + ")",
				Mode:       mode,
				Link:       "sni-spoof",
				Transport:  string(TransportTLS),
				Stealth:    true,
				SNISpoof:   true,
				SpoofSNI:   DefaultSpoofSNI,
				IPv6:       true,
				Shared:     false,
				ServerName: DefaultSpoofSNI,
				TargetAddr: addr6,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-tls",
				Label:      dirLabel + " (IPv6) · Fake TLS Website (SNI)",
				Mode:       mode,
				Link:       "website",
				Transport:  string(TransportTLS),
				Stealth:    false,
				IPv6:       true,
				Shared:     false,
				ServerName: "www.bing.com",
				TargetAddr: addr6,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-plain",
				Label:      dirLabel + " (IPv6) · Plain TCP (Raw)",
				Mode:       mode,
				Link:       "plain",
				Transport:  string(TransportPlain),
				Stealth:    false,
				IPv6:       true,
				Shared:     false,
				TargetAddr: addr6,
				Port:       port,
			},
			// The IPv6 route is often shorter than the IPv4 one, so KCP is
			// tried on it too: a tunnel can run KCP over IPv6, and the
			// lowest-ping gaming route may be exactly that pair.
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-kcp",
				Label:      dirLabel + " (IPv6) · KCP over UDP (FEC)",
				Mode:       mode,
				Link:       "kcp",
				Transport:  string(TransportKCP),
				Stealth:    false,
				IPv6:       true,
				Shared:     true,
				TargetAddr: addr6,
				Port:       port,
			},
			// The other stream links a tunnel can run over IPv6. Where IPv4
			// between two servers is blocked and IPv6 is not, these were
			// never offered. ICMP and FakeTCP are not here: they work over
			// IPv4 only, in a real tunnel as much as in this test.
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-grpc",
				Label:      dirLabel + " (IPv6) · gRPC Stream (HTTP/2)",
				Mode:       mode,
				Link:       "grpc",
				Transport:  string(TransportGRPC),
				Stealth:    false,
				IPv6:       true,
				Shared:     true,
				ServerName: "www.google.com",
				TargetAddr: addr6,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-split",
				Label:      dirLabel + " (IPv6) · Split-Stream TLS (Anti-Freeze Rotation)",
				Mode:       mode,
				Link:       "split",
				Transport:  string(TransportTLS),
				Stealth:    true,
				SNISpoof:   true,
				SpoofSNI:   DefaultSpoofSNI,
				AntiFreeze: true,
				IPv6:       true,
				Shared:     true,
				ServerName: DefaultSpoofSNI,
				TargetAddr: addr6,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         mode + "-ipv6-http-tcp",
				Label:      dirLabel + " (IPv6) · TCP + HTTP Header",
				Mode:       mode,
				Link:       "plain",
				Transport:  string(TransportPlain),
				WebHeader:  true,
				IPv6:       true,
				Shared:     false,
				ServerName: "www.bing.com",
				TargetAddr: addr6,
				Port:       port,
			},
		)
	}

	cdnDomain = strings.TrimSpace(cdnDomain)
	if mode == "direct" && cdnDomain != "" && port > 0 {
		cdnAddr := net.JoinHostPort(cdnDomain, strconv.Itoa(port))
		specs = append(specs,
			ProbeCandidateSpec{
				ID:         "direct-cdn-ws",
				Label:      "Direct · Cloudflare CDN (WebSocket)",
				Mode:       "direct",
				Link:       "cdn",
				Transport:  string(TransportWSS),
				CDN:        true,
				Stealth:    true,
				Shared:     true,
				ServerName: cdnDomain,
				Domain:     cdnDomain,
				TargetAddr: cdnAddr,
				Port:       port,
			},
			ProbeCandidateSpec{
				ID:         "direct-cdn-grpc",
				Label:      "Direct · Cloudflare CDN (gRPC)",
				Mode:       "direct",
				Link:       "grpc-cdn",
				Transport:  string(TransportGRPC),
				CDN:        true,
				Stealth:    true,
				Shared:     true,
				ServerName: cdnDomain,
				Domain:     cdnDomain,
				TargetAddr: cdnAddr,
				Port:       port,
			},
		)
	}

	return specs
}

// RunProbeDialer benchmarks each candidate spec in order against the remote
// ProbeListener using the shared ephemeral secret.
func RunProbeDialer(ctx context.Context, specs []ProbeCandidateSpec, secret []byte, burstBytes int) []ProbeCandidateResult {
	if burstBytes <= 0 {
		burstBytes = 256 * 1024 // 256 KB down + 256 KB up per main test (~512 KB sustained burst)
	}
	results := make([]ProbeCandidateResult, 0, len(specs))
	deadTCP := map[string]int{}

	for _, spec := range specs {
		if ctx.Err() != nil {
			break
		}
		isTCPDirect := !spec.CDN && !Transport(spec.Transport).IsPacketBased() && spec.TargetAddr != ""
		if isTCPDirect && deadTCP[spec.TargetAddr] >= 2 {
			results = append(results, ProbeCandidateResult{
				ProbeCandidateSpec: spec,
				Status:             "blocked",
				Attempts:           1,
				Error:              "TCP port unreachable (connection timed out)",
				Summary:            "Blocked / Unreachable — TCP port unreachable",
			})
			continue
		}
		res := probeOneSpec(ctx, spec, secret, burstBytes)
		if isTCPDirect && res.Successes == 0 && (res.Error == "TCP port unreachable (connection timed out)" || res.Error == "connection refused") {
			deadTCP[spec.TargetAddr]++
		}
		results = append(results, res)
	}

	// The results that look like a bad moment rather than the link are
	// tested once more (see ProbeRetestIDs). A run of one candidate has
	// nothing to compare with; the panel re-tests those itself.
	if len(specs) > 1 && ctx.Err() == nil {
		var retests []ProbeCandidateResult
		for _, id := range ProbeRetestIDs(results) {
			if ctx.Err() != nil {
				break
			}
			for _, spec := range specs {
				if spec.ID == id {
					retests = append(retests, probeOneSpec(ctx, spec, secret, burstBytes))
					break
				}
			}
		}
		results = MergeProbeRetests(results, retests)
	}
	return results
}

func probeOneSpec(parentCtx context.Context, spec ProbeCandidateSpec, secret []byte, burstBytes int) ProbeCandidateResult {
	res := ProbeCandidateResult{
		ProbeCandidateSpec: spec,
		Status:             "blocked",
		Attempts:           2,
	}

	cfg := &Config{
		Name:            "probe-" + spec.ID,
		Mode:            ModeDirect,
		Role:            RoleEdge,
		TunnelAddr:      spec.TargetAddr,
		Transport:       Transport(spec.Transport),
		ServerName:      spec.ServerName,
		CDN:             spec.CDN,
		HTTPHeader:      spec.WebHeader,
		HTTPHost:        spec.ServerName,
		SNISpoof:        spec.SNISpoof,
		SpoofSNI:        spec.SpoofSNI,
		IPSpoof:         spec.IPSpoof,
		SpoofIP:         spec.SpoofIP,
		AntiFreeze:      spec.AntiFreeze,
		UTLS:            false,
		TLSFragment:     false,
		ECH:             false,
		utlsSet:         true,
		fragmentSet:     true,
		echSet:          true,
		KCPDataShards:   10,
		KCPParityShards: 3,
		secret:          secret,
	}
	probeKCPDefaults(cfg)
	if spec.Stealth {
		cfg.UTLS = true
		cfg.UTLSProfile = "chrome"
		cfg.TLSFragment = true
		cfg.TLSFragmentSize = 40
		cfg.TLSFragmentSleep = 3 * time.Millisecond
	}
	cfg.prepareTLS(nil)

	routes := newRouter(cfg)

	pings1 := 3
	burst1 := uint32(burstBytes)
	pings2 := 2
	burst2 := uint32(32 * 1024)
	if spec.Gaming {
		pings1 = 12
		if burst1 == 0 || burst1 > 64*1024 {
			burst1 = 64 * 1024
		}
		pings2 = 8
	}

	// Attempt 1: Full handshake + ping samples + download/upload burst
	hs1, rtts1, dlMbps, ulMbps, partial1, err1 := runSingleProbeAttempt(parentCtx, cfg, routes, secret, pings1, burst1)
	if err1 != nil {
		res.Error = simplifyProbeErr(err1)
		res.Summary = "Blocked / Unreachable — " + res.Error
		return res
	}
	res.Successes++

	var partial2 string
	var rtts2 []float64
	if partial1 != "" {
		// Handshake and initial ping succeeded, but the transfer stopped
		// moving (or barely moved). Skip Attempt 2 to save time.
		res.Attempts = 1
		res.HandshakeMS = round2(hs1)
		res.Error = partial1
	} else {
		// Attempt 2: Repeat connection check + pings + 32 KB burst to confirm stability & jitter
		hs2, r2, dl2, ul2, p2, err2 := runSingleProbeAttempt(parentCtx, cfg, routes, secret, pings2, burst2)
		partial2 = p2
		if err2 == nil {
			res.Successes++
			rtts2 = r2
			res.HandshakeMS = round2((hs1 + hs2) / 2.0)
			if partial2 != "" {
				res.Error = partial2
			}
			// The first attempt's transfer is the measurement; the second only
			// stands in for a direction the first could not time.
			if dlMbps == 0 {
				dlMbps = dl2
			}
			if ulMbps == 0 {
				ulMbps = ul2
			}
		} else {
			res.HandshakeMS = round2(hs1)
			res.Error = simplifyProbeErr(err2)
		}
	}

	rttMS, jitterMS := probeRTTStatsAttempts(rtts1, rtts2)
	res.RTTMS = round2(rttMS)
	res.JitterMS = round2(jitterMS)

	// In Reverse mode, the Foreign server is the probe dialer and the Relay
	// (Iran) server is the listener. Phase 0x02 (Listener -> Dialer) therefore
	// measures Relay -> Foreign (User Upload), and Phase 0x03 (Dialer -> Listener)
	// measures Foreign -> Relay (User Download). Swap them so DownMbps is always
	// User Download (Foreign -> Relay) and UpMbps is always User Upload.
	if spec.Mode == "reverse" {
		dlMbps, ulMbps = ulMbps, dlMbps
	}

	res.DownMbps = round1(dlMbps)
	res.UpMbps = round1(ulMbps)
	res.AvgMbps = round1((dlMbps + ulMbps) / 2.0)

	switch {
	case partial1 != "" || partial2 != "":
		res.Status = "throttled"
		why := partial1
		if why == "" {
			why = partial2
		}
		if why == probeTooSlowMsg {
			res.Summary = fmt.Sprintf("Throttled — connected (%.0f ms ping), but data barely moves", res.RTTMS)
		} else if res.AvgMbps > 0 {
			res.Summary = fmt.Sprintf("Throttled — data stopped mid-stream (%.1f Mbps before it stopped, %.0f ms ping)", res.AvgMbps, res.RTTMS)
		} else {
			res.Summary = fmt.Sprintf("Throttled — connected (%.0f ms ping), then data stopped mid-stream", res.RTTMS)
		}
	case res.Successes < res.Attempts:
		res.Status = "degraded"
		res.Summary = fmt.Sprintf("Unstable (%d/%d connections succeeded, %.1f Mbps, %.0f ms)", res.Successes, res.Attempts, res.AvgMbps, res.RTTMS)
	default:
		res.Status = "ok"
		if spec.Gaming {
			res.Summary = GamingSummary(res.RTTMS, res.JitterMS)
		} else {
			res.Summary = fmt.Sprintf("Healthy — %.1f Mbps avg (↓%.1f / ↑%.1f Mbps), %.0f ms ping", res.AvgMbps, res.DownMbps, res.UpMbps, res.RTTMS)
		}
	}
	return res
}

// How long one attempt is planned to take, and the most it may take while
// data is still moving. The plan sizes the transfers; the cap is only reached
// by a link that is slow but working, which used to run out of the planned
// time and be reported as frozen by DPI though its data was still flowing.
const (
	probeSoftBudget      = 6500 * time.Millisecond
	probeSoftBudgetSplit = 10000 * time.Millisecond
	probeHardCap         = 16 * time.Second
	probeHardCapSplit    = 22 * time.Second
	probeMinMeasure      = 32 * 1024
	// probeHandshakeCap bounds connecting and the secure handshake, which
	// used to be bounded by the whole planned attempt.
	probeHandshakeCap = 6 * time.Second
)

// probeStallWindow is how long a transfer may go without moving a byte before
// it counts as frozen. A variable so a test can shorten it.
var probeStallWindow = 3 * time.Second

// Why an attempt's transfer was cut off, in the words the results show.
const (
	probeFrozenMsg  = "connected, then data stopped mid-stream (frozen by the network or a DPI filter)"
	probeTooSlowMsg = "connected, but data barely moves (far too slow to use)"
)

// probeSizeFor sizes a timed transfer from the speed just seen, so it fits in
// the planned time that is left: as it was for a fast link, smaller for a slow
// one. rate is in bytes per second; 0 means not known yet.
func probeSizeFor(rate float64, def uint32, soft time.Time) uint32 {
	if rate <= 0 {
		return def
	}
	left := time.Until(soft).Seconds()
	if left < 1 {
		left = 1
	}
	size := rate * left / 4
	if size < probeMinMeasure {
		size = probeMinMeasure
	}
	if size >= float64(def) {
		return def
	}
	return uint32(size)
}

// runSingleProbeAttempt opens one connection and runs the ping and transfer
// checks over it. partial says why a transfer was cut off ("" when none was).
func runSingleProbeAttempt(parentCtx context.Context, cfg *Config, routes *router, secret []byte, pings int, burstBytes uint32) (hsMS float64, rtts []float64, dlMbps, ulMbps float64, partial string, err error) {
	soft, hardCap := probeSoftBudget, probeHardCap
	if cfg.AntiFreeze {
		soft, hardCap = probeSoftBudgetSplit, probeHardCapSplit
		// A light check (the second attempt, or Gaming) stays light.
		if burstBytes < 192*1024 && burstBytes > 32*1024 {
			burstBytes = 32 * 1024
		}
	}
	ctx, cancel := context.WithTimeout(parentCtx, hardCap)
	defer cancel()

	t0 := time.Now()
	softDeadline := t0.Add(soft)
	hardDeadline, _ := ctx.Deadline()
	raw, claim, err := routes.dial(2200 * time.Millisecond)
	if err != nil {
		return 0, nil, 0, 0, "", fmt.Errorf("tcp dial: %w", err)
	}
	defer raw.Close()
	tuneSocket(raw)

	// Ensure that if ctx expires, raw is immediately interrupted even if wrapDialTLSOnce
	// sets a longer internal deadline during the TLS handshake.
	stop := context.AfterFunc(ctx, func() {
		_ = raw.SetDeadline(time.Now())
	})
	defer stop()

	_ = raw.SetDeadline(time.Now().Add(2500 * time.Millisecond))

	// The handshake gets no more time than it always had: only moving data
	// earns the longer cap. Some handshakes set their own, longer deadlines,
	// so this one cuts the connection itself if it is not done in time.
	var hsMu sync.Mutex
	hsDone := false
	hsTimer := time.AfterFunc(probeHandshakeCap, func() {
		hsMu.Lock()
		defer hsMu.Unlock()
		if !hsDone {
			_ = raw.SetDeadline(time.Now())
		}
	})
	defer hsTimer.Stop()

	c, err := wrapDialPurpose(raw, cfg.withClaimedName(claim), authPurposeSpeedtest)
	if err != nil {
		return 0, nil, 0, 0, "", fmt.Errorf("handshake: %w", err)
	}
	defer c.Close()

	if err := sendAuthPurpose(c, secret, authPurposeSpeedtest); err != nil {
		return 0, nil, 0, 0, "", fmt.Errorf("auth: %w", err)
	}
	hsMu.Lock()
	hsDone = true
	hsMu.Unlock()
	hsMS = float64(time.Since(t0)) / float64(time.Millisecond)

	// Ping samples (use 2.0s deadline on first ping so dead UDP/KCP or DPI-dropped streams fail fast).
	// Once at least two samples are in and too little of the planned time is
	// left for the transfer check, it stops pinging rather than letting a slow
	// but healthy link (many pings on a high-latency path in Gaming mode) eat
	// the time the transfers need.
	for i := 0; i < pings; i++ {
		if len(rtts) >= 2 && time.Until(softDeadline) < probePingReserve {
			break
		}
		pingDeadline := time.Now().Add(2000 * time.Millisecond)
		if hardDeadline.Before(pingDeadline) {
			pingDeadline = hardDeadline
		}
		_ = c.SetDeadline(pingDeadline)
		pStart := time.Now()
		var req [9]byte
		req[0] = 0x01
		binary.BigEndian.PutUint64(req[1:], uint64(pStart.UnixNano()))
		if _, err := c.Write(req[:]); err != nil {
			if len(rtts) > 0 {
				return hsMS, rtts, 0, 0, probeFrozenMsg, nil
			}
			return hsMS, rtts, 0, 0, "", fmt.Errorf("ping write: %w", err)
		}
		var echo [8]byte
		if _, err := io.ReadFull(c, echo[:]); err != nil {
			if len(rtts) > 0 {
				return hsMS, rtts, 0, 0, probeFrozenMsg, nil
			}
			return hsMS, rtts, 0, 0, "", fmt.Errorf("ping read: %w", err)
		}
		rtts = append(rtts, float64(time.Since(pStart))/float64(time.Millisecond))
	}

	// Every step of a transfer gets probeStallWindow to move something, up
	// to the attempt's cap. Frozen is "nothing moved for that long", not "did
	// not finish in the planned time".
	stallDeadline := func() time.Time {
		d := time.Now().Add(probeStallWindow)
		if d.After(hardDeadline) {
			d = hardDeadline
		}
		return d
	}
	// cutOff says why a transfer that did not finish was cut off.
	cutOff := func() string {
		if time.Until(hardDeadline) <= 100*time.Millisecond {
			return probeTooSlowMsg
		}
		return probeFrozenMsg
	}

	minRTTSec := 0.0
	if len(rtts) > 0 {
		minRTT := rtts[0]
		for _, r := range rtts[1:] {
			if r < minRTT {
				minRTT = r
			}
		}
		minRTTSec = minRTT / 1000.0
	}

	readBuf := make([]byte, 32*1024)

	// Helper to run one 0x02 (Listener -> Dialer) transfer of sz bytes.
	runPhase02 := func(sz uint32) (int64, float64, error) {
		var hdr [5]byte
		hdr[0] = 0x02
		binary.BigEndian.PutUint32(hdr[1:], sz)
		reqStart := time.Now()
		_ = c.SetDeadline(stallDeadline())
		if _, err := c.Write(hdr[:]); err != nil {
			return 0, 0, err
		}
		var ackByte [1]byte
		if _, err := io.ReadFull(c, ackByte[:]); err != nil {
			return 0, 0, err
		}
		readStart := time.Now()
		var n int64
		var rerr error
		for n < int64(sz) {
			want := int64(len(readBuf))
			if rem := int64(sz) - n; rem < want {
				want = rem
			}
			_ = c.SetReadDeadline(stallDeadline())
			k, err := c.Read(readBuf[:want])
			n += int64(k)
			if err != nil {
				rerr = err
				break
			}
		}
		dur := time.Since(readStart).Seconds()
		if minRTTSec > 0 {
			totalSec := time.Since(reqStart).Seconds()
			netDur := totalSec - minRTTSec
			if netDur < totalSec*0.5 {
				netDur = totalSec * 0.5
			}
			if netDur > dur {
				dur = netDur
			}
		}
		return n, dur, rerr
	}

	payload := make([]byte, 32*1024)
	_, _ = rand.Read(payload[:128])
	for i := 128; i < len(payload); i++ {
		payload[i] = payload[i%128] ^ byte(i)
	}

	// Helper to run one 0x03 (Dialer -> Listener) transfer of sz bytes.
	runPhase03 := func(sz uint32) (int64, float64, error) {
		var hdr [5]byte
		hdr[0] = 0x03
		binary.BigEndian.PutUint32(hdr[1:], sz)
		_ = c.SetDeadline(stallDeadline())
		if _, err := c.Write(hdr[:]); err != nil {
			return 0, 0, err
		}
		var ackByte [1]byte
		if _, err := io.ReadFull(c, ackByte[:]); err != nil {
			return 0, 0, err
		}
		writeStart := time.Now()
		var sent int64
		var werr error
		for sent < int64(sz) {
			chunk := int64(len(payload))
			if rem := int64(sz) - sent; rem < chunk {
				chunk = rem
			}
			_ = c.SetWriteDeadline(stallDeadline())
			n, err := c.Write(payload[:chunk])
			if n > 0 {
				sent += int64(n)
			}
			if err != nil {
				werr = err
				break
			}
		}
		if werr == nil {
			// What was written may still sit in buffers on the way, and
			// nothing says how it is moving, so the completion is waited for
			// up to the attempt's cap.
			_ = c.SetReadDeadline(hardDeadline)
			if _, err := io.ReadFull(c, ackByte[:]); err != nil {
				werr = err
			}
		}
		dur := time.Since(writeStart).Seconds()
		if minRTTSec > 0 && dur > minRTTSec {
			// Subtract one-way propagation of the final 1-byte completion ACK
			adj := dur - minRTTSec*0.5
			if adj < dur*0.65 {
				adj = dur * 0.65
			}
			dur = adj
		}
		return sent, dur, werr
	}

	// The planned time left bounds how long a longer measurement may run,
	// so it is what measureTransfer is given; the cap is never planned for.
	softCtx, softCancel := context.WithDeadline(ctx, softDeadline)
	defer softCancel()

	// Phase 0x02 (Listener -> Dialer):
	// When burstBytes >= 192 KB, first send a warm-up command so TCP exits Slow Start
	// (and any packet token-bucket burst is primed) before timing the steady-state burst.
	// Split rotation is warmed up too, with less, so its connection ramp is
	// past before the timing starts. Each timed size after a warm-up is fitted
	// to the speed the warm-up showed.
	full := burstBytes >= 192*1024
	measure02 := burstBytes
	if full {
		warmup02 := uint32(128 * 1024)
		switch {
		case cfg.AntiFreeze:
			warmup02, measure02 = 64*1024, 128*1024
		case cfg.Transport == TransportICMP:
			warmup02, measure02 = 512*1024, 512*1024
		case !cfg.Transport.IsPacketBased():
			measure02 = 384 * 1024
		}
		wn, wd, werr := runPhase02(warmup02)
		if werr != nil || wn < int64(warmup02) {
			return hsMS, rtts, 0, 0, cutOff(), nil
		}
		if wd > 0 {
			measure02 = probeSizeFor(float64(wn)/wd, measure02, softDeadline)
		}
	}
	longer := cfg.Transport != TransportICMP && full
	dlRead, dlDur, dlOK, dlErr := measureTransfer(softCtx, runPhase02, measure02, longer)
	if dlErr != nil || !dlOK {
		return hsMS, rtts, 0, 0, cutOff(), nil
	}
	dlRate := 0.0
	if dlDur > 0 && dlRead > 0 {
		dlRate = float64(dlRead) / dlDur
		dlMbps = dlRate * 8 / 1_000_000
	}

	// Phase 0x03 (Dialer -> Listener):
	// Warm up the Dialer -> Listener direction first (critical for Reverse mode where
	// Dialer -> Listener is User Download Foreign -> Relay, and where transit routers
	// often apply a ~768 KB token-bucket burst allowance to ICMP Echo Requests before
	// enforcing their sustained ICMP rate limit). Its sizes start from the
	// download speed until the upload's own warm-up has shown its speed.
	measure03 := burstBytes
	if full {
		warmup03 := uint32(128 * 1024)
		switch {
		case cfg.AntiFreeze:
			warmup03, measure03 = 64*1024, 128*1024
		case cfg.Transport == TransportICMP:
			warmup03, measure03 = 768*1024, 512*1024
		case !cfg.Transport.IsPacketBased():
			measure03 = 384 * 1024
		}
		warmup03 = probeSizeFor(dlRate, warmup03, softDeadline)
		wn, wd, werr := runPhase03(warmup03)
		if werr != nil || wn < int64(warmup03) {
			return hsMS, rtts, dlMbps, 0, cutOff(), nil
		}
		if wd > 0 {
			measure03 = probeSizeFor(float64(wn)/wd, measure03, softDeadline)
		}
	}
	ulSent, ulDur, ulOK, ulErr := measureTransfer(softCtx, runPhase03, measure03, longer)
	if ulErr != nil || !ulOK {
		return hsMS, rtts, dlMbps, 0, cutOff(), nil
	}
	if ulDur > 0 && ulSent > 0 {
		ulMbps = (float64(ulSent) * 8 / 1_000_000) / ulDur
	}

	_ = c.SetWriteDeadline(stallDeadline())
	_, _ = c.Write([]byte{0x04})
	return hsMS, rtts, dlMbps, ulMbps, "", nil
}

// probeKCPDefaults gives a probe's settings the KCP tuning a real tunnel has.
// Left at zero, the ICMP and FakeTCP links fell back to a window of 256 packets
// (a safe floor for a hand-written settings file), which on a 100 ms link holds
// them to about 22 Mbit/s however fast the link is, while the same links in a
// real tunnel use the usual window and run three to five times faster. The
// benchmark then told people those links were far slower than they are.
func probeKCPDefaults(c *Config) {
	d := DefaultConfig()
	c.KCPWindow, c.KCPMTU, c.KCPInterval, c.KCPResend = d.KCPWindow, d.KCPMTU, d.KCPInterval, d.KCPResend
}

// What a probe's timed transfers are made to show. A few hundred KB is over in
// less than one round trip on a fast link, so what it times is the start-up of
// the connection (TCP's slow start, KCP's ramp-up), not the speed the link
// holds. Real tunnels measured two to four times faster than the probe said.
const (
	probeLongEnough  = 500 * time.Millisecond  // a transfer this long already shows the sustained speed
	probeTargetTime  = 1000 * time.Millisecond // how long the longer transfer is meant to take
	probeMaxMeasure  = 24 << 20                // never more than this in one timed transfer
	probeBudgetShare = 3                       // a longer transfer may use up to a third of what is left
)

// measureTransfer times a transfer of first bytes. If that was over too soon to
// mean much, a longer one, sized from the speed just seen, is timed and used
// instead, and again, up to three times: the speed seen while a connection is
// still speeding up understates the next, so each step is sized from the last
// until one runs long enough to show what the link holds. Every size is held to
// what the attempt's remaining time allows. ok is false when a transfer did not
// complete.
func measureTransfer(ctx context.Context, run func(uint32) (int64, float64, error), first uint32, allowLonger bool) (n int64, dur float64, ok bool, err error) {
	n, dur, err = run(first)
	if err != nil || n < int64(first) {
		return n, dur, false, err
	}
	for step := 0; step < 3 && allowLonger && dur > 0 && dur < probeLongEnough.Seconds(); step++ {
		rate := float64(n) / dur // bytes per second
		size := math.Max(rate*probeTargetTime.Seconds(), float64(n)*2)
		if dl, has := ctx.Deadline(); has {
			left := time.Until(dl).Seconds()
			if left <= 0 {
				break // the planned time is used up; keep what was measured
			}
			size = math.Min(size, rate*left/probeBudgetShare)
		}
		size = math.Min(size, probeMaxMeasure)
		if size < float64(n)*1.5 {
			break // nothing to gain from a barely longer one
		}
		want := uint32(size)
		n2, dur2, err2 := run(want)
		if err2 != nil || n2 < int64(want) {
			return n2, dur2, false, err2
		}
		n, dur = n2, dur2
	}
	return n, dur, true, nil
}

// probeRTTStats gives the round trip time and its jitter from the ping samples.
// The middle sample is used rather than the average: the first ping on a new
// KCP or spoofed link carries the cost of setting the link up (hundreds of
// milliseconds that real traffic never sees again) and must not drag it up.
func probeRTTStats(rtts []float64) (rtt, jitter float64) {
	if len(rtts) == 0 {
		return 0, 0
	}
	sorted := append([]float64(nil), rtts...)
	sort.Float64s(sorted)
	if n := len(sorted); n%2 == 1 {
		rtt = sorted[n/2]
	} else {
		rtt = (sorted[n/2-1] + sorted[n/2]) / 2
	}
	// The first sample is left out of the jitter when there are enough others.
	steady := rtts
	if len(rtts) >= 4 {
		steady = rtts[1:]
	}
	if len(steady) > 1 {
		var sum float64
		for i := 1; i < len(steady); i++ {
			sum += math.Abs(steady[i] - steady[i-1])
		}
		jitter = sum / float64(len(steady)-1)
	}
	return rtt, jitter
}

// probePingReserve is the time an attempt keeps back from its ping samples
// for the transfer check that follows them.
const probePingReserve = 2500 * time.Millisecond

// probeRTTStatsAttempts gives the round trip time and jitter from the ping
// samples of several attempts, each on its own fresh connection. Every
// attempt's first ping pays for setting its link up (hundreds of milliseconds
// on KCP, FakeTCP and ICMP), so it is left out of each attempt, not only the
// first one; and jitter is the change between consecutive pings within one
// connection, never the jump from the last ping of one attempt to the set-up
// ping of the next, which no game ever sees. Run together, those two inflated
// a healthy KCP link's jitter to tens of milliseconds.
func probeRTTStatsAttempts(attempts ...[]float64) (rtt, jitter float64) {
	var all, steady []float64
	var diffSum float64
	var diffs int
	for _, a := range attempts {
		all = append(all, a...)
		s := a
		if len(a) >= 2 {
			s = a[1:]
		}
		steady = append(steady, s...)
		for i := 1; i < len(s); i++ {
			diffSum += math.Abs(s[i] - s[i-1])
			diffs++
		}
	}
	if len(all) == 0 {
		return 0, 0
	}
	base := steady
	if len(base) < 3 {
		base = all
	}
	sorted := append([]float64(nil), base...)
	sort.Float64s(sorted)
	if n := len(sorted); n%2 == 1 {
		rtt = sorted[n/2]
	} else {
		rtt = (sorted[n/2-1] + sorted[n/2]) / 2
	}
	if diffs == 0 {
		// Too few samples once the set-up pings are left out: fall back to
		// every change within each attempt.
		for _, a := range attempts {
			for i := 1; i < len(a); i++ {
				diffSum += math.Abs(a[i] - a[i-1])
				diffs++
			}
		}
	}
	if diffs > 0 {
		jitter = diffSum / float64(diffs)
	}
	return rtt, jitter
}

func effectiveProbeMbps(r *ProbeCandidateResult) float64 {
	if r.DownMbps > 0 && r.UpMbps > 0 {
		minDir := math.Min(r.DownMbps, r.UpMbps)
		return 0.45*minDir + 0.35*r.DownMbps + 0.20*r.UpMbps
	}
	return r.AvgMbps
}

// FinalizeProbeReport scores and ranks all candidate results and synthesizes a
// hybrid Fake TLS + CDN Auto-Fallback recommendation if both Direct Fake TLS
// and Cloudflare CDN succeeded.
func FinalizeProbeReport(results []ProbeCandidateResult, cdnDomain string) *ProbeBenchmarkReport {
	var maxMbps float64
	for i := range results {
		if results[i].Status == "ok" {
			if eff := effectiveProbeMbps(&results[i]); eff > maxMbps {
				maxMbps = eff
			}
		}
	}
	if maxMbps < 5 {
		maxMbps = 5
	}

	var isGaming bool
	for i := range results {
		if results[i].Gaming {
			isGaming = true
		}
		results[i].Score = scoreCandidate(&results[i], maxMbps)
	}

	// Check if Direct Fake TLS AND Cloudflare CDN WebSocket both worked well;
	// if so, synthesize the Fake TLS + CDN Auto-Fallback hybrid recommendation
	// (skipped in Gaming mode where lowest ping & jitter without CDN hops wins).
	var bestDirectTLS *ProbeCandidateResult
	var bestCDNWS *ProbeCandidateResult
	if !isGaming {
		for i := range results {
			r := &results[i]
			if r.Status != "ok" {
				continue
			}
			if r.Mode == "direct" && (r.Link == "website" || r.Link == "sni-spoof") && !r.IPv6 {
				if bestDirectTLS == nil || r.Score > bestDirectTLS.Score {
					bestDirectTLS = r
				}
			}
			if r.Mode == "direct" && r.Link == "cdn" {
				bestCDNWS = r
			}
		}
	}

	if bestDirectTLS != nil && bestCDNWS != nil && bestDirectTLS.Score >= 60 && bestCDNWS.Score >= 45 {
		hybridScore := bestDirectTLS.Score + 4
		if bestCDNWS.Score+4 > hybridScore {
			hybridScore = bestCDNWS.Score + 4
		}
		if hybridScore > 99 {
			hybridScore = 99
		}
		dom := bestCDNWS.Domain
		if dom == "" {
			dom = cdnDomain
		}
		hybrid := ProbeCandidateResult{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:         "direct-website-cdn-backup",
				Label:      "Direct · Fake TLS + CDN Auto-Fallback (Hybrid)",
				Mode:       "direct",
				Link:       "website-cdn-backup",
				Transport:  string(TransportTLS),
				Stealth:    bestDirectTLS.Stealth,
				Shared:     true,
				ServerName: bestDirectTLS.ServerName,
				Domain:     dom,
				TargetAddr: bestDirectTLS.TargetAddr,
				Port:       bestDirectTLS.Port,
			},
			Status:      "ok",
			Attempts:    bestDirectTLS.Attempts + bestCDNWS.Attempts,
			Successes:   bestDirectTLS.Successes + bestCDNWS.Successes,
			HandshakeMS: bestDirectTLS.HandshakeMS,
			RTTMS:       bestDirectTLS.RTTMS,
			JitterMS:    bestDirectTLS.JitterMS,
			DownMbps:    bestDirectTLS.DownMbps,
			UpMbps:      bestDirectTLS.UpMbps,
			AvgMbps:     bestDirectTLS.AvgMbps,
			Score:       hybridScore,
			Hybrid:      true,
			Summary: fmt.Sprintf("Best of both: %.1f Mbps Direct Fake TLS speed + automatic failover to CDN (%s) if blocked",
				bestDirectTLS.AvgMbps, dom),
		}
		results = append(results, hybrid)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if isGaming {
			latI := results[i].RTTMS + results[i].JitterMS*2.0
			latJ := results[j].RTTMS + results[j].JitterMS*2.0
			if latI != latJ {
				return latI < latJ
			}
		}
		return effectiveProbeMbps(&results[i]) > effectiveProbeMbps(&results[j])
	})

	rep := &ProbeBenchmarkReport{
		Results:  results,
		TestedAt: time.Now().UTC(),
	}
	for i := range rep.Results {
		if rep.Results[i].Status == "ok" || rep.Results[i].Status == "degraded" {
			picked := rep.Results[i]
			rep.Recommended = &picked
			break
		}
	}
	return rep
}

func scoreCandidate(r *ProbeCandidateResult, maxMbps float64) int {
	if r.Successes == 0 || r.Status == "blocked" {
		return 0
	}
	// A candidate where the handshake succeeded but the transfer froze
	// mid-stream ("throttled") is blocked by a DPI byte-cap filter and cannot
	// carry real user traffic. Cap its score well below any working candidate.
	if r.Status == "throttled" {
		rttBonus := int(math.Round(8.0 * clamp01(1.0-(r.RTTMS-15.0)/385.0)))
		score := 10 + rttBonus
		if score > 20 {
			score = 20
		}
		return score
	}
	if r.Gaming {
		return scoreGamingCandidate(r)
	}

	// 1. Reliability (0..45)
	rel := 45.0 * (float64(r.Successes) / float64(maxInt(1, r.Attempts)))

	// 2. Latency & Jitter (0..25)
	rttScore := 18.0 * clamp01(1.0-(r.RTTMS-15.0)/385.0)
	jitScore := 7.0 * clamp01(1.0-r.JitterMS/80.0)

	// 3. Throughput (0..20): weights both Download and Upload (plus bidirectional floor)
	effMbps := effectiveProbeMbps(r)
	relSpeed := 12.0 * clamp01(effMbps/maxMbps)
	absSpeed := 8.0 * clamp01(effMbps/40.0)
	tpScore := relSpeed + absSpeed

	// 4. DPI Resistance & Transport Efficiency Bonus (0..10)
	var dpiBonus float64
	switch {
	case (r.Link == "website" && r.Stealth) || r.Link == "sni-spoof" || r.Link == "split":
		dpiBonus = 10.0
	case r.Link == "website" || r.Link == "grpc":
		dpiBonus = 9.0
	case r.Link == "cdn" || r.Link == "grpc-cdn":
		dpiBonus = 8.5
	case r.Link == "faketcp" || r.Link == "ip-spoof":
		dpiBonus = 7.0
	case r.Link == "kcp":
		dpiBonus = 6.5
	case r.Link == "icmp":
		dpiBonus = 6.0
	case r.WebHeader:
		dpiBonus = 3.0
	default:
		dpiBonus = 0.0
	}

	total := int(math.Round(rel + rttScore + jitScore + tpScore + dpiBonus))
	if total > 98 {
		total = 98
	}
	if total < 1 {
		total = 1
	}
	return total
}

// GamingSummary is the one-line verdict for a healthy Gaming benchmark
// result. It leaves out Mbps on purpose: the 64 KB check only shows the link
// does not freeze, and its speed says nothing about what the link carries.
func GamingSummary(rttMS, jitterMS float64) string {
	return fmt.Sprintf("Gaming Ready — %.0f ms ping, ±%.1f ms jitter, no freeze on the 64 KB check", rttMS, jitterMS)
}

func scoreGamingCandidate(r *ProbeCandidateResult) int {
	// 1. Reliability / Zero Packet Drop (0..35)
	rel := 35.0 * (float64(r.Successes) / float64(maxInt(1, r.Attempts)))

	// 2. Lowest Ping / RTT (0..35): 10 ms = 35 pts, 50 ms = 27.6 pts, 100 ms = 18.4 pts, >= 200 ms = 0 pts.
	// Every 10 ms of ping is worth ~1.8 pts, more than the transport bonus
	// gap between any two working links, so a clearly shorter route wins.
	rttScore := 35.0 * clamp01(1.0-(r.RTTMS-10.0)/190.0)

	// 3. Lowest Jitter / Tick Stability (0..22): 0 ms = 22 pts, 3 ms = 19.8 pts, 10 ms = 14.7 pts, >= 30 ms = 0 pts
	jitScore := 22.0 * clamp01(1.0-r.JitterMS/30.0)

	// 4. Gaming Transport Mechanics Bonus (0..8):
	// Rewards transports that eliminate TCP head-of-line blocking (KCP/FEC over UDP or Raw TCP)
	// or have zero framing/encryption overhead (Plain TCP with Dedicated Pool).
	var gamingBonus float64
	switch {
	case r.Link == "kcp" || r.Link == "ip-spoof" || r.Link == "faketcp":
		gamingBonus = 8.0
	case r.Link == "plain" && !r.WebHeader:
		gamingBonus = 7.0
	case r.Link == "plain" && r.WebHeader:
		gamingBonus = 6.5
	case r.Link == "website" && !r.Stealth:
		gamingBonus = 6.0
	case (r.Link == "website" && r.Stealth) || r.Link == "sni-spoof":
		gamingBonus = 4.5
	case r.Link == "icmp":
		gamingBonus = 4.0
	case r.Link == "grpc":
		gamingBonus = 3.0
	case r.Link == "split":
		gamingBonus = 1.5
	case r.Link == "cdn" || r.Link == "grpc-cdn":
		gamingBonus = 1.0
	default:
		gamingBonus = 3.0
	}

	// No points for the Mbps of the 64 KB check: so small a transfer ends
	// while TCP is still in slow start (a few round trips at a small window),
	// while KCP sends it all at once, so it reads 3 Mbps on a TCP link that
	// carries gigabits and ~10 Mbps on KCP. Scoring it handed KCP points over
	// a TCP route with a clearly lower ping. The check only has to complete,
	// which every "ok" result already has (a frozen one is "throttled").
	total := int(math.Round(rel + rttScore + jitScore + gamingBonus))
	if total > 99 {
		total = 99
	}
	if total < 1 {
		total = 1
	}
	return total
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func simplifyProbeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "connection reset"):
		return "connection reset by firewall (RST)"
	case strings.Contains(s, "did not agree to HTTP/2"):
		return "HTTP/2 (gRPC) not enabled on CDN/peer"
	case strings.HasPrefix(s, "tcp dial:") && (strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded")):
		return "TCP port unreachable (connection timed out)"
	case strings.HasPrefix(s, "handshake:") && (strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded")):
		return "TLS/stream handshake blocked by DPI"
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded"):
		return "connection timed out (dropped by firewall)"
	default:
		return s
	}
}

// ---------------------------------------------------------------------------
// CLI command: portbridge probe
// ---------------------------------------------------------------------------

type probeCodePayload struct {
	IPv4   string `json:"v4"`
	IPv6   string `json:"v6,omitempty"`
	Port   int    `json:"p"`
	Secret string `json:"s"`
}

// EncodeProbeCode packages a listener's address, port, and secret into a
// one-line PBPROBE1:... token for CLI users.
func EncodeProbeCode(ipv4, ipv6 string, port int, secret []byte) string {
	b, _ := json.Marshal(probeCodePayload{
		IPv4:   ipv4,
		IPv6:   ipv6,
		Port:   port,
		Secret: base64.RawURLEncoding.EncodeToString(secret),
	})
	return "PBPROBE1:" + base64.RawURLEncoding.EncodeToString(b)
}

// DecodeProbeCode unpacks a PBPROBE1:... token.
func DecodeProbeCode(code string) (ipv4, ipv6 string, port int, secret []byte, err error) {
	code = strings.TrimSpace(code)
	rawB64, ok := strings.CutPrefix(code, "PBPROBE1:")
	if !ok {
		return "", "", 0, nil, errors.New("probe code must start with PBPROBE1:")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rawB64)
	if err != nil {
		return "", "", 0, nil, errors.New("probe code is corrupted")
	}
	var p probeCodePayload
	if err := json.Unmarshal(raw, &p); err != nil || p.Port <= 0 || p.Secret == "" {
		return "", "", 0, nil, errors.New("probe code is incomplete")
	}
	sec, err := base64.RawURLEncoding.DecodeString(p.Secret)
	if err != nil || len(sec) < 16 {
		return "", "", 0, nil, errors.New("probe code secret is invalid")
	}
	return p.IPv4, p.IPv6, p.Port, sec, nil
}

// FormatProbeReport renders a human-readable CLI summary of a ProbeBenchmarkReport.
func FormatProbeReport(rep *ProbeBenchmarkReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "\n================ PortBridge Route & Transport Benchmark ================")
	fmt.Fprintf(&b, " %-42s  %-9s  %-8s  %-8s  %-10s  %s\n", "TRANSPORT MODE", "STATUS", "PING", "JITTER", "SPEED", "SCORE")
	fmt.Fprintln(&b, " ---------------------------------------------------------------------------------")
	for _, r := range rep.Results {
		st := strings.ToUpper(r.Status)
		ping := "—"
		jit := "—"
		speed := "—"
		if r.Successes > 0 {
			ping = fmt.Sprintf("%.0f ms", r.RTTMS)
			jit = fmt.Sprintf("±%.1f", r.JitterMS)
			speed = fmt.Sprintf("%.1f Mbps", r.AvgMbps)
			if r.Gaming {
				// The 64 KB check's speed is not the link's speed.
				speed = "check ok"
				if r.Status == "throttled" {
					speed = "froze"
				}
			}
		}
		fmt.Fprintf(&b, " %-42s  %-9s  %-8s  %-8s  %-10s  %3d/100\n",
			r.Label, st, ping, jit, speed, r.Score)
	}
	fmt.Fprintln(&b, "==================================================================================")
	for _, r := range rep.Results {
		if r.Status != "ok" && r.Error != "" {
			fmt.Fprintf(&b, " ✖ %s: %s\n", r.Label, r.Error)
		}
	}
	if rep.Recommended != nil {
		rec := rep.Recommended
		if rec.Gaming {
			fmt.Fprintf(&b, "\n★ Best for Gaming (%d/100):\n", rec.Score)
		} else {
			fmt.Fprintf(&b, "\n★ Recommended Configuration (%d/100):\n", rec.Score)
		}
		fmt.Fprintf(&b, "  • Mode:      %s\n", rec.Mode)
		fmt.Fprintf(&b, "  • Transport: %s (%s)\n", rec.Label, rec.Link)
		if rec.Domain != "" {
			fmt.Fprintf(&b, "  • CDN Host:  %s (Port %d)\n", rec.Domain, rec.Port)
		}
		fmt.Fprintf(&b, "  • Summary:   %s\n", rec.Summary)
	} else {
		fmt.Fprintln(&b, "\n✖ All tested transport modes failed or were blocked between these two servers.")
	}
	return b.String()
}

// CmdProbe implements `portbridge probe ...` for CLI users.
func CmdProbe(args []string) {
	if len(args) > 0 && args[0] == "listen" {
		fs := flag.NewFlagSet("probe listen", flag.ExitOnError)
		port := fs.Int("port", 0, "Preferred port to listen on (default: free Cloudflare HTTPS port)")
		ip4 := fs.String("ip4", "", "Public IPv4 address of this server")
		ip6 := fs.String("ip6", "", "Public IPv6 address of this server")
		duration := fs.Duration("duration", 3*time.Minute, "How long to keep the benchmark listener open")
		_ = fs.Parse(args[1:])

		if *ip4 == "" {
			*ip4, *ip6 = detectLocalPublicIPs()
		}
		if *ip4 == "" && *ip6 == "" {
			fmt.Fprintln(os.Stderr, "probe listen: could not detect public IP; pass -ip4 <your-server-ip>")
			os.Exit(1)
		}

		pl, err := StartProbeListener("0.0.0.0", *port, nil, *duration)
		if err != nil {
			fmt.Fprintf(os.Stderr, "probe listen: %v\n", err)
			os.Exit(1)
		}
		defer pl.Close()

		code := EncodeProbeCode(*ip4, *ip6, pl.Port, pl.Secret)
		fmt.Printf("\n📡 PortBridge Benchmark Listener Ready on port %d (open for %s)\n", pl.Port, duration.Round(time.Second))
		fmt.Println("Run this command on your other server to benchmark all tunnel modes:")
		fmt.Printf("\n  portbridge probe %s\n\n", code)
		fmt.Println("Or to also benchmark a Cloudflare CDN subdomain pointed at this server:")
		fmt.Printf("\n  portbridge probe -cdn sub.yourdomain.com %s\n\n", code)
		fmt.Println("Waiting for benchmark connections (press Ctrl+C to stop)...")
		<-pl.closed
		return
	}

	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cdn := fs.String("cdn", "", "Optional Cloudflare/CDN subdomain pointed at the listener server")
	mode := fs.String("mode", "direct", "Direction label for the report (direct or reverse)")
	gaming := fs.Bool("gaming", false, "Rank for gaming: lowest ping and jitter, with a light 64 KB transfer check instead of a bulk speed test")
	var codeArg string
	var flagArgs []string
	for _, a := range args {
		if strings.HasPrefix(a, "PBPROBE1:") && codeArg == "" {
			codeArg = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	_ = fs.Parse(flagArgs)
	if codeArg == "" && fs.NArg() > 0 {
		codeArg = fs.Arg(0)
	}
	if codeArg == "" {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  1. On Server A: portbridge probe listen")
		fmt.Fprintln(os.Stderr, "  2. On Server B: portbridge probe [-gaming] [-cdn sub.domain.com] <PBPROBE1:...>")
		os.Exit(2)
	}

	ipv4, ipv6, port, secret, err := DecodeProbeCode(codeArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}

	specs := BuildProbeCandidates(*mode, ipv4, ipv6, port, *cdn)
	burst := 384 * 1024
	if *gaming {
		burst = 64 * 1024
		for i := range specs {
			specs[i].Gaming = true
		}
		fmt.Printf("🎮 Gaming benchmark: %d transport modes against %s:%d (lowest ping & jitter)...\n", len(specs), ipv4, port)
	} else {
		fmt.Printf("🔍 Benchmarking %d transport modes against %s:%d...\n", len(specs), ipv4, port)
	}
	results := RunProbeDialer(context.Background(), specs, secret, burst)
	rep := FinalizeProbeReport(results, *cdn)
	fmt.Print(FormatProbeReport(rep))
}

func detectLocalPublicIPs() (v4, v6 string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsPrivate() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				if v4 == "" {
					v4 = ip4.String()
				}
			} else if v6 == "" {
				v6 = ipNet.IP.String()
			}
		}
	}
	return v4, v6
}

// Ensure bytes is referenced if needed.
var _ = bytes.Compare
