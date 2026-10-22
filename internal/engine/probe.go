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
	if preferredPort > 0 {
		candidates = append(candidates, preferredPort)
	}
	for _, p := range CDNHTTPSPorts {
		if p != preferredPort {
			candidates = append(candidates, p)
		}
	}
	candidates = append(candidates, 0) // OS-assigned fallback

	kcpCfg := &Config{
		Transport:       TransportKCP,
		secret:          secret,
		KCPDataShards:   10,
		KCPParityShards: 3,
		IPSpoof:         true,
		allowPlainKCP:   true,
	}

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
	icmpLn, _ := kcpListen(rawAddr, &Config{
		Transport:       TransportICMP,
		secret:          secret,
		KCPDataShards:   10,
		KCPParityShards: 3,
	})
	fakeTCPLn, _ := kcpListen(rawAddr, &Config{
		Transport:       TransportFakeTCP,
		secret:          secret,
		KCPDataShards:   10,
		KCPParityShards: 3,
	})

	pl := &ProbeListener{
		Port:      chosenPort,
		Secret:    secret,
		tcpLn:     tcpLn,
		kcpLn:     kcpLn,
		icmpLn:    icmpLn,
		fakeTCPLn: fakeTCPLn,
		splitMgr:  newSplitSessionManager(),
		cert:      cert,
		closed:    make(chan struct{}),
	}

	go pl.serveTCP()
	go pl.servePacketLn(pl.kcpLn)
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
	if spec.Stealth {
		cfg.UTLS = true
		cfg.UTLSProfile = "chrome"
		cfg.TLSFragment = true
		cfg.TLSFragmentSize = 40
		cfg.TLSFragmentSleep = 3 * time.Millisecond
	}
	cfg.prepareTLS(nil)

	routes := newRouter(cfg)

	// Attempt 1: Full handshake + 1 ping sample + sustained download/upload burst
	hs1, rtts, dlMbps, ulMbps, partial1, err1 := runSingleProbeAttempt(parentCtx, cfg, routes, secret, 3, uint32(burstBytes))
	if err1 != nil {
		res.Error = simplifyProbeErr(err1)
		res.Summary = "Blocked / Unreachable — " + res.Error
		return res
	}
	res.Successes++

	var partial2 bool
	if partial1 {
		// Handshake and initial ping succeeded, but the sustained burst was cut off
		// mid-stream by a DPI packet-count filter. Skip Attempt 2 to save time.
		res.Attempts = 1
		res.HandshakeMS = round2(hs1)
		res.Error = "connected, then frozen mid-stream by ISP/DPI filter"
	} else {
		// Attempt 2: Repeat connection check + 2 pings + 32 KB burst to confirm stability & jitter
		hs2, rtts2, _, _, p2, err2 := runSingleProbeAttempt(parentCtx, cfg, routes, secret, 2, 32*1024)
		partial2 = p2
		if err2 == nil {
			res.Successes++
			rtts = append(rtts, rtts2...)
			res.HandshakeMS = round2((hs1 + hs2) / 2.0)
			if partial2 {
				res.Error = "connected, then frozen mid-stream by ISP/DPI filter"
			}
		} else {
			res.HandshakeMS = round2(hs1)
			res.Error = simplifyProbeErr(err2)
		}
	}

	rttMS, jitterMS := probeRTTStats(rtts)
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
	case partial1 || partial2:
		res.Status = "throttled"
		if res.AvgMbps > 0 {
			res.Summary = fmt.Sprintf("Throttled — DPI freeze mid-stream (%.1f Mbps, %.0f ms ping)", res.AvgMbps, res.RTTMS)
		} else {
			res.Summary = fmt.Sprintf("Throttled — connected (%.0f ms ping), then frozen mid-stream by DPI filter", res.RTTMS)
		}
	case res.Successes < res.Attempts:
		res.Status = "degraded"
		res.Summary = fmt.Sprintf("Unstable (%d/%d connections succeeded, %.1f Mbps, %.0f ms)", res.Successes, res.Attempts, res.AvgMbps, res.RTTMS)
	default:
		res.Status = "ok"
		res.Summary = fmt.Sprintf("Healthy — %.1f Mbps avg (↓%.1f / ↑%.1f Mbps), %.0f ms ping", res.AvgMbps, res.DownMbps, res.UpMbps, res.RTTMS)
	}
	return res
}

func runSingleProbeAttempt(parentCtx context.Context, cfg *Config, routes *router, secret []byte, pings int, burstBytes uint32) (hsMS float64, rtts []float64, dlMbps, ulMbps float64, partial bool, err error) {
	attemptTimeout := 6500 * time.Millisecond
	if cfg.AntiFreeze {
		attemptTimeout = 10000 * time.Millisecond
		if burstBytes > 32*1024 {
			burstBytes = 32 * 1024
		}
	}
	ctx, cancel := context.WithTimeout(parentCtx, attemptTimeout)
	defer cancel()

	t0 := time.Now()
	raw, claim, err := routes.dial(2200 * time.Millisecond)
	if err != nil {
		return 0, nil, 0, 0, false, fmt.Errorf("tcp dial: %w", err)
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

	c, err := wrapDialPurpose(raw, cfg.withClaimedName(claim), authPurposeSpeedtest)
	if err != nil {
		return 0, nil, 0, 0, false, fmt.Errorf("handshake: %w", err)
	}
	defer c.Close()

	if err := sendAuthPurpose(c, secret, authPurposeSpeedtest); err != nil {
		return 0, nil, 0, 0, false, fmt.Errorf("auth: %w", err)
	}
	hsMS = float64(time.Since(t0)) / float64(time.Millisecond)

	// Ping samples (use 2.0s deadline on first ping so dead UDP/KCP or DPI-dropped streams fail fast)
	for i := 0; i < pings; i++ {
		_ = c.SetDeadline(time.Now().Add(2000 * time.Millisecond))
		pStart := time.Now()
		var req [9]byte
		req[0] = 0x01
		binary.BigEndian.PutUint64(req[1:], uint64(pStart.UnixNano()))
		if _, err := c.Write(req[:]); err != nil {
			if len(rtts) > 0 {
				return hsMS, rtts, 0, 0, true, nil
			}
			return hsMS, rtts, 0, 0, false, fmt.Errorf("ping write: %w", err)
		}
		var echo [8]byte
		if _, err := io.ReadFull(c, echo[:]); err != nil {
			if len(rtts) > 0 {
				return hsMS, rtts, 0, 0, true, nil
			}
			return hsMS, rtts, 0, 0, false, fmt.Errorf("ping read: %w", err)
		}
		rtts = append(rtts, float64(time.Since(pStart))/float64(time.Millisecond))
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
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

	// Helper to run one 0x02 (Listener -> Dialer) transfer of sz bytes.
	runPhase02 := func(sz uint32) (int64, float64, error) {
		var hdr [5]byte
		hdr[0] = 0x02
		binary.BigEndian.PutUint32(hdr[1:], sz)
		reqStart := time.Now()
		if _, err := c.Write(hdr[:]); err != nil {
			return 0, 0, err
		}
		var ackByte [1]byte
		if _, err := io.ReadFull(c, ackByte[:]); err != nil {
			return 0, 0, err
		}
		readStart := time.Now()
		n, rerr := io.CopyN(io.Discard, c, int64(sz))
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

	// Phase 0x02 (Listener -> Dialer):
	// When burstBytes >= 192 KB, first send a warm-up command so TCP exits Slow Start
	// (and any packet token-bucket burst is primed) before timing the steady-state burst.
	measure02 := burstBytes
	if !cfg.AntiFreeze && burstBytes >= 192*1024 {
		warmup02 := uint32(128 * 1024)
		if cfg.Transport == TransportICMP {
			warmup02 = 512 * 1024
		}
		if wn, _, werr := runPhase02(warmup02); werr != nil || wn < int64(warmup02) {
			return hsMS, rtts, 0, 0, true, nil
		}
		if !cfg.Transport.IsPacketBased() {
			measure02 = 384 * 1024
		} else if cfg.Transport == TransportICMP {
			measure02 = 512 * 1024
		}
	}
	// The time left to spend on this attempt bounds how long a longer
	// measurement may run, so a slow but working link is never mistaken for a
	// frozen one just because it was asked for too much.
	longer := !cfg.AntiFreeze && cfg.Transport != TransportICMP && burstBytes >= 192*1024
	dlRead, dlDur, dlOK, dlErr := measureTransfer(ctx, runPhase02, measure02, longer)
	if dlErr != nil || !dlOK {
		return hsMS, rtts, 0, 0, true, nil
	}
	if dlDur > 0 && dlRead > 0 {
		dlMbps = (float64(dlRead) * 8 / 1_000_000) / dlDur
	}

	// Phase 0x03 (Dialer -> Listener):
	// Warm up the Dialer -> Listener direction first (critical for Reverse mode where
	// Dialer -> Listener is User Download Foreign -> Relay, and where transit routers
	// often apply a ~768 KB token-bucket burst allowance to ICMP Echo Requests before
	// enforcing their sustained ICMP rate limit).
	measure03 := burstBytes
	if !cfg.AntiFreeze && burstBytes >= 192*1024 {
		warmup03 := uint32(128 * 1024)
		if cfg.Transport == TransportICMP {
			warmup03 = 768 * 1024
			measure03 = 512 * 1024
		} else if !cfg.Transport.IsPacketBased() {
			measure03 = 384 * 1024
		}
		if wn, _, werr := runPhase03(warmup03); werr != nil || wn < int64(warmup03) {
			return hsMS, rtts, dlMbps, 0, true, nil
		}
	}
	ulSent, ulDur, ulOK, ulErr := measureTransfer(ctx, runPhase03, measure03, longer)
	if ulErr != nil || !ulOK {
		return hsMS, rtts, dlMbps, 0, true, nil
	}
	if ulDur > 0 && ulSent > 0 {
		ulMbps = (float64(ulSent) * 8 / 1_000_000) / ulDur
	}

	_, _ = c.Write([]byte{0x04})
	return hsMS, rtts, dlMbps, ulMbps, false, nil
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
			if left := time.Until(dl).Seconds(); left > 0 {
				size = math.Min(size, rate*left/probeBudgetShare)
			}
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

	for i := range results {
		results[i].Score = scoreCandidate(&results[i], maxMbps)
	}

	// Check if Direct Fake TLS AND Cloudflare CDN WebSocket both worked well;
	// if so, synthesize the Fake TLS + CDN Auto-Fallback hybrid recommendation.
	var bestDirectTLS *ProbeCandidateResult
	var bestCDNWS *ProbeCandidateResult
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
	fmt.Fprintf(&b, " %-42s  %-9s  %-8s  %-10s  %s\n", "TRANSPORT MODE", "STATUS", "PING", "SPEED", "SCORE")
	fmt.Fprintln(&b, " -----------------------------------------------------------------------")
	for _, r := range rep.Results {
		st := strings.ToUpper(r.Status)
		ping := "—"
		speed := "—"
		if r.Successes > 0 {
			ping = fmt.Sprintf("%.0f ms", r.RTTMS)
			speed = fmt.Sprintf("%.1f Mbps", r.AvgMbps)
		}
		fmt.Fprintf(&b, " %-42s  %-9s  %-8s  %-10s  %3d/100\n",
			r.Label, st, ping, speed, r.Score)
	}
	fmt.Fprintln(&b, "========================================================================")
	if rep.Recommended != nil {
		rec := rep.Recommended
		fmt.Fprintf(&b, "\n★ Recommended Configuration (%d/100):\n", rec.Score)
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
		fmt.Fprintln(os.Stderr, "  2. On Server B: portbridge probe [-cdn sub.domain.com] <PBPROBE1:...>")
		os.Exit(2)
	}

	ipv4, ipv6, port, secret, err := DecodeProbeCode(codeArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}

	specs := BuildProbeCandidates(*mode, ipv4, ipv6, port, *cdn)
	fmt.Printf("🔍 Benchmarking %d transport modes against %s:%d...\n", len(specs), ipv4, port)
	results := RunProbeDialer(context.Background(), specs, secret, 384*1024)
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
