package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultCloudflareSubnets is a curated set of 44 distinct /24 slices spread
// across Cloudflare's published anycast announcements (104.16.0.0/13,
// 104.24.0.0/14, 172.64.0.0/13, 162.158.0.0/15, 198.41.128.0/17,
// 188.114.96.0/20, 190.93.240.0/20, 197.234.240.0/22, 108.162.192.0/18,
// 141.101.64.0/18, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, and
// 173.245.48.0/20). Sampling one host IP per /24 tests genuinely independent
// routing prefixes on Iranian datacenter ISPs while avoiding Cloudflare's
// .0/.1/.255 edge reservations and non-Free-plan ranges.
var DefaultCloudflareSubnets = []string{
	"104.16.12.0/24",
	"104.16.132.0/24",
	"104.17.24.0/24",
	"104.17.175.0/24",
	"104.18.6.0/24",
	"104.18.38.0/24",
	"104.19.144.0/24",
	"104.19.210.0/24",
	"104.20.18.0/24",
	"104.21.11.0/24",
	"104.21.64.0/24",
	"104.22.14.0/24",
	"104.24.42.0/24",
	"104.25.118.0/24",
	"104.26.8.0/24",
	"104.27.32.0/24",
	"172.64.86.0/24",
	"172.64.148.0/24",
	"172.66.40.0/24",
	"172.67.18.0/24",
	"172.67.74.0/24",
	"172.67.156.0/24",
	"172.67.212.0/24",
	"162.159.36.0/24",
	"162.159.128.0/24",
	"162.159.152.0/24",
	"162.159.200.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
	"198.41.192.0/24",
	"198.41.200.0/24",
	"198.41.209.0/24",
	"198.41.214.0/24",
	"108.162.194.0/24",
	"108.162.226.0/24",
	"141.101.76.0/24",
	"141.101.90.0/24",
	"190.93.242.0/24",
	"197.234.241.0/24",
	"173.245.58.0/24",
	"103.21.245.0/24",
	"103.22.201.0/24",
}

// CFScanRequest configures an end-to-end Cloudflare Clean-IP scan executed from
// the Iran Relay server through Cloudflare Edge into the Foreign server's
// PortBridge listener (either a live Origin tunnel or a temporary ProbeListener).
type CFScanRequest struct {
	Domain      string   `json:"domain"`
	Port        int      `json:"port"`
	Transport   string   `json:"transport,omitempty"` // "wss" (default), "xhttp", "grpc", or "h3"
	WSPath      string   `json:"ws_path,omitempty"`
	Secret      []byte   `json:"-"`
	Candidates  []string `json:"candidates,omitempty"` // optional custom IPs or CIDRs
	MaxSelect   int      `json:"max_select,omitempty"` // default 5
	Stage2Limit int      `json:"stage2_limit,omitempty"`
}

// CFScanResult holds the Stage 1 and Stage 2 end-to-end measurements for one IP.
type CFScanResult struct {
	IP          string  `json:"ip"`
	Subnet      string  `json:"subnet"`
	Status      string  `json:"status"` // "ok", "throttled", "stage1_ok", "blocked"
	Selected    bool    `json:"selected,omitempty"`
	HandshakeMS float64 `json:"handshake_ms,omitempty"`
	RTTMS       float64 `json:"rtt_ms,omitempty"`
	JitterMS    float64 `json:"jitter_ms,omitempty"`
	DownMbps    float64 `json:"down_mbps,omitempty"`
	UpMbps      float64 `json:"up_mbps,omitempty"`
	AvgMbps     float64 `json:"avg_mbps,omitempty"`
	Score       int     `json:"score,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// CFScanReport summarizes a complete Cloudflare Clean-IP scan.
type CFScanReport struct {
	Domain        string         `json:"domain"`
	Port          int            `json:"port"`
	Transport     string         `json:"transport"`
	ScannedCount  int            `json:"scanned_count"`
	PassedStage1  int            `json:"passed_stage1"`
	VerifiedCount int            `json:"verified_count"`
	Recommended   []string       `json:"recommended"`
	Results       []CFScanResult `json:"results"`
	Notes         []string       `json:"notes,omitempty"`
	TestedAt      time.Time      `json:"tested_at"`
}

func randomByteRange(lo, hi int) byte {
	if hi <= lo {
		return byte(lo)
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	n := int(binary.BigEndian.Uint16(b[:]))
	return byte(lo + (n % (hi - lo + 1)))
}

func sampleIPFromCIDR(cidr string) (string, bool) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipNet == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		// IPv6 CIDR: randomize the last 16 bits while keeping ::2..::fffe.
		v16 := make(net.IP, net.IPv6len)
		copy(v16, ipNet.IP.To16())
		if len(v16) != net.IPv6len {
			return "", false
		}
		v16[14] = randomByteRange(0, 255)
		v16[15] = randomByteRange(2, 254)
		return v16.String(), true
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 8 || ones > 30 {
		if ones == 32 {
			return v4.String(), true
		}
		return "", false
	}
	base := binary.BigEndian.Uint32(v4) & binary.BigEndian.Uint32(ipNet.Mask)
	span := uint32(1) << uint32(32-ones)
	var rbuf [4]byte
	_, _ = rand.Read(rbuf[:])
	// Avoid .0, .1, and .255 inside any /24 slice.
	offset := uint32(2)
	if span > 4 {
		offset = 2 + (binary.BigEndian.Uint32(rbuf[:]) % (span - 3))
	}
	cand := base | offset
	lastOctet := byte(cand & 0xff)
	if lastOctet == 0 || lastOctet == 1 || lastOctet == 255 {
		cand = (cand & 0xffffff00) | uint32(randomByteRange(2, 253))
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], cand)
	return net.IPv4(out[0], out[1], out[2], out[3]).String(), true
}

func subnet24Key(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

func subnet16Key(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.0.0/16", v4[0], v4[1])
	}
	return ip.Mask(net.CIDRMask(32, 128)).String() + "/32"
}

// expandCFScanCandidates expands custom IPs/CIDRs (or samples DefaultCloudflareSubnets
// when empty), returning deduplicated concrete IP strings.
func expandCFScanCandidates(raw []string) []string {
	src := raw
	if len(src) == 0 {
		src = DefaultCloudflareSubnets
	}
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		ip = strings.Trim(strings.TrimSpace(ip), "[]")
		if h, _, err := net.SplitHostPort(ip); err == nil && h != "" {
			ip = h
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return
		}
		canon := parsed.String()
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	for _, item := range src {
		for _, tok := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
		}) {
			if strings.Contains(tok, "/") {
				if sampled, ok := sampleIPFromCIDR(tok); ok {
					add(sampled)
				}
				continue
			}
			add(tok)
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func normaliseCDNTransport(tr string) Transport {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "xhttp":
		return TransportXHTTP
	case "grpc":
		return TransportGRPC
	case "h3":
		return TransportH3
	default:
		return TransportWSS
	}
}

func buildSingleIPProbeConfig(ip string, port int, domain string, tr Transport, wsPath string, secret []byte) (*Config, *router) {
	cfg := DefaultConfig()
	cfg.Name = "cf-clean-scan"
	cfg.Mode = ModeDirect
	cfg.Role = RoleEdge
	cfg.Transport = tr
	cfg.CDN = true
	cfg.ServerName = domain
	cfg.WSPath = wsPath
	cfg.ECH = false
	cfg.echSet = true
	cfg.utlsSet = true
	cfg.fragmentSet = true
	cfg.secret = secret
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	cfg.TunnelAddr = addr
	if tr != TransportH3 {
		cfg.UTLS = true
		cfg.UTLSProfile = "chrome"
		cfg.TLSFragment = true
		cfg.TLSFragmentSize = 40
		cfg.TLSFragmentSleep = 3 * time.Millisecond
	} else {
		cfg.UTLS = false
		cfg.TLSFragment = false
	}
	cfg.prepareTLS(nil)
	r := &router{
		cfg: cfg,
		targets: []route{{
			addr:  addr,
			name:  domain,
			cdn:   true,
			clean: true,
		}},
		badUntil:  make([]time.Time, 1),
		badCount:  make([]int, 1),
		hsFails:   make([]int, 1),
		lastTrial: make([]time.Time, 1),
		log:       newThrottled(),
	}
	return cfg, r
}

func conciseCFScanError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case isTimeout(err) || strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "i/o timeout"):
		return "timed out"
	case strings.Contains(lower, "connection reset") || strings.Contains(lower, "forcibly closed") || strings.Contains(lower, "eof"):
		return "connection reset / DPI drop"
	case strings.Contains(lower, "403") || strings.Contains(lower, "530") || strings.Contains(lower, "522") || strings.Contains(lower, "521") || strings.Contains(lower, "520") || strings.Contains(lower, "400") || strings.Contains(lower, "bad status"):
		return "Cloudflare edge rejected route (" + extractHTTPCode(msg) + ")"
	case strings.Contains(lower, "refused"):
		return "connection refused"
	case strings.Contains(lower, "wrong or missing secret"):
		return "reached wrong origin (check Cloudflare DNS target)"
	default:
		if len(msg) > 72 {
			return msg[:72] + "…"
		}
		return msg
	}
}

func extractHTTPCode(s string) string {
	for _, code := range []string{"400", "403", "404", "502", "503", "520", "521", "522", "523", "524", "525", "526", "530"} {
		if strings.Contains(s, code) {
			return "HTTP " + code
		}
	}
	return "HTTP error"
}

// runCFStage1 performs a fast end-to-end handshake + HMAC Origin authentication +
// 2 rapid RTT pings through a single candidate Cloudflare IP.
func runCFStage1(parent context.Context, ip string, port int, domain string, tr Transport, wsPath string, secret []byte) (hsMS, rttMS float64, err error) {
	ctx, cancel := context.WithTimeout(parent, 8500*time.Millisecond)
	defer cancel()

	cfg, routes := buildSingleIPProbeConfig(ip, port, domain, tr, wsPath, secret)
	t0 := time.Now()
	raw, claim, err := routes.dial(2500 * time.Millisecond)
	if err != nil {
		return 0, 0, err
	}
	defer raw.Close()
	if tr != TransportH3 {
		tuneSocket(raw)
	}

	stop := context.AfterFunc(ctx, func() {
		_ = raw.SetDeadline(time.Now())
	})
	defer stop()

	_ = raw.SetDeadline(time.Now().Add(5500 * time.Millisecond))
	c, err := wrapDialPurpose(raw, cfg.withClaimedName(claim), authPurposeSpeedtest)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()

	if err := sendAuthPurpose(c, secret, authPurposeSpeedtest); err != nil {
		return 0, 0, err
	}
	hsMS = math.Round(float64(time.Since(t0))/float64(time.Millisecond)*10) / 10

	var rtts []float64
	for i := 0; i < 2; i++ {
		_ = c.SetDeadline(time.Now().Add(2000 * time.Millisecond))
		pStart := time.Now()
		var req [9]byte
		req[0] = 0x01
		binary.BigEndian.PutUint64(req[1:], uint64(pStart.UnixNano()))
		if _, err := c.Write(req[:]); err != nil {
			return hsMS, 0, err
		}
		var echo [8]byte
		if _, err := io.ReadFull(c, echo[:]); err != nil {
			return hsMS, 0, err
		}
		rtts = append(rtts, float64(time.Since(pStart))/float64(time.Millisecond))
	}
	_ = c.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
	_, _ = c.Write([]byte{0x04})

	rtt, _ := probeRTTStats(rtts)
	return hsMS, math.Round(rtt*10) / 10, nil
}

func scoreCFCandidate(rttMS, jitterMS, downMbps, upMbps float64) int {
	avgMbps := (downMbps*0.65 + upMbps*0.35)
	// Throughput up to 62 pts (saturates smoothly around ~60 Mbps over CDN).
	tpPts := 62.0 * (1.0 - math.Exp(-avgMbps/22.0))
	// Latency up to 28 pts (<= 60ms = 28, 150ms = ~20, 300ms = ~10, >= 500ms = 2).
	latPts := 28.0 - math.Max(0, rttMS-50.0)*0.06
	if latPts < 2 {
		latPts = 2
	}
	if latPts > 28 {
		latPts = 28
	}
	// Jitter stability up to 10 pts.
	jitPts := 10.0 - jitterMS*0.25
	if jitPts < 0 {
		jitPts = 0
	}
	score := int(math.Round(tpPts + latPts + jitPts))
	if score < 5 {
		score = 5
	}
	if score > 100 {
		score = 100
	}
	return score
}

// ScanCloudflareCleanIPs runs the 3-stage Cloudflare Clean-IP scan from the
// calling machine (the Iran Relay):
//  1. Parallel Stage-1 real CDN transport handshake + Origin HMAC auth + RTT filter.
//  2. Stage-2 sustained download + upload anti-freeze transfer test on top subnet-diverse finalists.
//  3. Subnet-diverse selection (/16 then /24) of the cleanest verified edge IPs.
func ScanCloudflareCleanIPs(ctx context.Context, req CFScanRequest) (*CFScanReport, error) {
	domain := strings.TrimSpace(req.Domain)
	if domain == "" || !HostnameRe.MatchString(domain) {
		return nil, errors.New("enter a valid Cloudflare-proxied domain name first")
	}
	if len(req.Secret) == 0 {
		return nil, errors.New("missing authentication secret for end-to-end Clean-IP verification")
	}
	port := req.Port
	if port <= 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	maxSelect := req.MaxSelect
	if maxSelect <= 0 {
		maxSelect = 5
	}
	if maxSelect > 12 {
		maxSelect = 12
	}
	stage2Limit := req.Stage2Limit
	if stage2Limit <= 0 {
		stage2Limit = max(8, maxSelect+3)
	}
	tr := normaliseCDNTransport(req.Transport)
	wsPath := strings.TrimSpace(req.WSPath)

	candidates := expandCFScanCandidates(req.Candidates)
	if len(candidates) == 0 {
		return nil, errors.New("no valid candidate Cloudflare IPs to test")
	}

	results := make([]CFScanResult, len(candidates))
	var wg1 sync.WaitGroup
	sem1 := make(chan struct{}, 16)
	for i, ip := range candidates {
		wg1.Add(1)
		go func(idx int, candIP string) {
			defer wg1.Done()
			r := CFScanResult{
				IP:     candIP,
				Subnet: subnet24Key(candIP),
				Status: "blocked",
			}
			select {
			case sem1 <- struct{}{}:
				defer func() { <-sem1 }()
			case <-ctx.Done():
				r.Error = "scan cancelled"
				results[idx] = r
				return
			}
			hs, rtt, err := runCFStage1(ctx, candIP, port, domain, tr, wsPath, req.Secret)
			if err != nil {
				r.Error = conciseCFScanError(err)
				results[idx] = r
				return
			}
			r.Status = "stage1_ok"
			r.HandshakeMS = hs
			r.RTTMS = rtt
			results[idx] = r
		}(i, ip)
	}
	wg1.Wait()

	// Collect Stage 1 survivors and rank by fast RTT + handshake.
	var passedIdx []int
	for i := range results {
		if results[i].Status == "stage1_ok" {
			passedIdx = append(passedIdx, i)
		}
	}
	sort.Slice(passedIdx, func(a, b int) bool {
		ra, rb := results[passedIdx[a]], results[passedIdx[b]]
		wa := ra.RTTMS + 0.35*ra.HandshakeMS
		wb := rb.RTTMS + 0.35*rb.HandshakeMS
		return wa < wb
	})

	// Pick up to stage2Limit subnet-diverse finalists for full anti-freeze transfer testing.
	var finalists []int
	used24 := map[string]bool{}
	for _, idx := range passedIdx {
		if len(finalists) >= stage2Limit {
			break
		}
		sub := results[idx].Subnet
		if !used24[sub] {
			used24[sub] = true
			finalists = append(finalists, idx)
		}
	}
	for _, idx := range passedIdx {
		if len(finalists) >= stage2Limit {
			break
		}
		already := false
		for _, f := range finalists {
			if f == idx {
				already = true
				break
			}
		}
		if !already {
			finalists = append(finalists, idx)
		}
	}

	// Stage 2: Sustained bidirectional throughput & anti-freeze check (256 KB+ each way).
	var wg2 sync.WaitGroup
	sem2 := make(chan struct{}, 4)
	for _, idx := range finalists {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			select {
			case sem2 <- struct{}{}:
				defer func() { <-sem2 }()
			case <-ctx.Done():
				return
			}
			candIP := results[i].IP
			cfg, routes := buildSingleIPProbeConfig(candIP, port, domain, tr, wsPath, req.Secret)
			hsMS, rtts, dlMbps, ulMbps, partial, err := runSingleProbeAttempt(ctx, cfg, routes, req.Secret, 4, 256*1024)
			if err != nil {
				results[i].Status = "blocked"
				results[i].Error = conciseCFScanError(err)
				return
			}
			rtt, jitter := probeRTTStats(rtts)
			if rtt > 0 {
				results[i].RTTMS = math.Round(rtt*10) / 10
			}
			results[i].JitterMS = math.Round(jitter*10) / 10
			if hsMS > 0 {
				results[i].HandshakeMS = math.Round(hsMS*10) / 10
			}
			results[i].DownMbps = math.Round(dlMbps*10) / 10
			results[i].UpMbps = math.Round(ulMbps*10) / 10
			results[i].AvgMbps = math.Round(((dlMbps+ulMbps)/2)*10) / 10
			if partial != "" {
				results[i].Status = "throttled"
				results[i].Error = partial
				return
			}
			results[i].Status = "ok"
			results[i].Score = scoreCFCandidate(results[i].RTTMS, results[i].JitterMS, dlMbps, ulMbps)
		}(idx)
	}
	wg2.Wait()

	// Sort Results so verified "ok" IPs come first (highest score), then stage1_ok,
	// then throttled, then blocked.
	rankOf := func(st string) int {
		switch st {
		case "ok":
			return 0
		case "stage1_ok":
			return 1
		case "throttled":
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := rankOf(results[i].Status), rankOf(results[j].Status)
		if ri != rj {
			return ri < rj
		}
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].RTTMS > 0 && results[j].RTTMS > 0 && results[i].RTTMS != results[j].RTTMS {
			return results[i].RTTMS < results[j].RTTMS
		}
		return results[i].IP < results[j].IP
	})

	// Stage 3: Select up to maxSelect verified Clean IPs with maximum subnet diversity:
	// Pass 1 = unique /16, Pass 2 = unique /24, Pass 3 = remaining verified "ok" IPs.
	var verifiedIdx []int
	for i := range results {
		if results[i].Status == "ok" {
			verifiedIdx = append(verifiedIdx, i)
		}
	}

	var recommended []string
	picked := map[int]bool{}
	seen16 := map[string]bool{}
	seen24 := map[string]bool{}

	for _, i := range verifiedIdx {
		if len(recommended) >= maxSelect {
			break
		}
		k16 := subnet16Key(results[i].IP)
		k24 := results[i].Subnet
		if !seen16[k16] {
			seen16[k16] = true
			seen24[k24] = true
			picked[i] = true
			results[i].Selected = true
			recommended = append(recommended, results[i].IP)
		}
	}
	for _, i := range verifiedIdx {
		if len(recommended) >= maxSelect {
			break
		}
		if picked[i] {
			continue
		}
		k24 := results[i].Subnet
		if !seen24[k24] {
			seen24[k24] = true
			picked[i] = true
			results[i].Selected = true
			recommended = append(recommended, results[i].IP)
		}
	}
	for _, i := range verifiedIdx {
		if len(recommended) >= maxSelect {
			break
		}
		if picked[i] {
			continue
		}
		picked[i] = true
		results[i].Selected = true
		recommended = append(recommended, results[i].IP)
	}

	rep := &CFScanReport{
		Domain:        domain,
		Port:          port,
		Transport:     string(tr),
		ScannedCount:  len(candidates),
		PassedStage1:  len(passedIdx),
		VerifiedCount: len(verifiedIdx),
		Recommended:   recommended,
		Results:       results,
		TestedAt:      time.Now().UTC(),
	}

	if len(recommended) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"Verified %d clean Cloudflare edge %s end-to-end through %s:%d (%s) with sustained upload & download transfer.",
			len(verifiedIdx),
			pluralWord(len(verifiedIdx), "IP", "IPs"),
			domain, port, strings.ToUpper(string(tr)),
		))
	} else if len(passedIdx) > 0 {
		rep.Notes = append(rep.Notes,
			"Handshakes reached the Foreign server via Cloudflare, but sustained data transfers were throttled or frozen mid-stream. Try switching CDN transport (e.g. SplitHTTP/XHTTP via CDN or QUIC/HTTP/3 via CDN) or port 2053/2083/8443.")
	} else {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"No Cloudflare edge IPs completed an authenticated handshake to %s:%d. Verify that (1) %s points to your Foreign server IP in Cloudflare DNS with Orange Cloud (Proxy) ON, (2) Cloudflare SSL/TLS mode is set to Full (not Flexible), and (3) port %d is one of Cloudflare's HTTPS ports (443, 2053, 2083, 2087, 2096, 8443).",
			domain, port, domain, port,
		))
	}
	return rep, nil
}

func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// SecretBytes returns a copy of the loaded tunnel secret after LoadSecret().
func (c *Config) SecretBytes() []byte {
	return append([]byte(nil), c.secret...)
}
