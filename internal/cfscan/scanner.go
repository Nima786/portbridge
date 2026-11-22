package cfscan

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultSpeedHost     = "speed.cloudflare.com"
	DefaultDownloadBytes = 2 * 1024 * 1024 // 2 MB sustained download test
	DefaultUploadBytes   = 512 * 1024      // 512 KB sustained upload test
)

// DefaultSubnets holds 64 distinct /24 slices distributed across all 14 of
// Cloudflare's published IPv4 anycast ranges (104.16-27, 172.64-67, 162.158-159,
// 188.114, 198.41, 108.162, 141.101, 190.93, 197.234, 173.245, 103.21/22/31).
var DefaultSubnets = []string{
	"104.16.12.0/24", "104.16.64.0/24", "104.16.132.0/24", "104.16.210.0/24",
	"104.17.24.0/24", "104.17.96.0/24", "104.17.175.0/24", "104.17.228.0/24",
	"104.18.6.0/24", "104.18.38.0/24", "104.18.114.0/24", "104.18.196.0/24",
	"104.19.44.0/24", "104.19.144.0/24", "104.19.210.0/24",
	"104.20.18.0/24", "104.20.88.0/24", "104.20.164.0/24",
	"104.21.11.0/24", "104.21.64.0/24", "104.21.148.0/24",
	"104.22.14.0/24", "104.22.72.0/24",
	"104.24.42.0/24", "104.24.118.0/24",
	"104.25.56.0/24", "104.25.118.0/24",
	"104.26.8.0/24", "104.26.14.0/24",
	"104.27.32.0/24", "104.27.142.0/24",
	"172.64.32.0/24", "172.64.86.0/24", "172.64.148.0/24", "172.64.204.0/24",
	"172.65.36.0/24", "172.65.112.0/24",
	"172.66.40.0/24", "172.66.44.0/24",
	"172.67.18.0/24", "172.67.74.0/24", "172.67.156.0/24", "172.67.212.0/24",
	"162.158.18.0/24", "162.158.112.0/24",
	"162.159.36.0/24", "162.159.128.0/24", "162.159.152.0/24", "162.159.200.0/24",
	"188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
	"198.41.192.0/24", "198.41.200.0/24", "198.41.209.0/24", "198.41.214.0/24",
	"108.162.194.0/24", "108.162.226.0/24",
	"141.101.76.0/24", "141.101.90.0/24",
	"190.93.242.0/24", "197.234.241.0/24", "173.245.58.0/24",
	"103.21.245.0/24", "103.22.201.0/24", "103.31.4.0/24",
}

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// ISPInfo describes the user's current local network/ISP detected directly from
// the device running the scanner.
type ISPInfo struct {
	IP       string `json:"ip"`
	ISP      string `json:"isp"`
	ASN      string `json:"asn,omitempty"`
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	Colo     string `json:"colo,omitempty"`
	Detected bool   `json:"detected"`
	Error    string `json:"error,omitempty"`
}

// Request configures a local ISP Cloudflare Clean-IP scan.
type Request struct {
	Domain        string            `json:"domain,omitempty"`          // optional custom CF-proxied domain; default speed.cloudflare.com
	Port          int               `json:"port,omitempty"`            // default 443
	Count         int               `json:"count,omitempty"`           // number of IPs to sample (default 64, max 320)
	MaxSelect     int               `json:"max_select,omitempty"`      // number of top diverse winners (default 5, max 20)
	Stage2Limit   int               `json:"stage2_limit,omitempty"`    // how many Stage 1 survivors get full speed tests (default 12)
	Workers       int               `json:"workers,omitempty"`         // Stage 1 concurrency (default 20)
	Fragment      bool              `json:"fragment,omitempty"`        // fragment TLS ClientHello into 40B chunks
	CustomRanges  []string          `json:"custom_ranges,omitempty"`   // optional user IPs / CIDRs
	DownloadBytes int               `json:"download_bytes,omitempty"`  // default 2 MB
	UploadBytes   int               `json:"upload_bytes,omitempty"`    // default 512 KB
	SkipSpeedTest bool              `json:"skip_speed_test,omitempty"` // optional fast latency-only scan
	SpeedHost     string            `json:"-"`                         // test override for speed.cloudflare.com
	SpeedPort     int               `json:"-"`                         // test override for speed port (default 443)
	TLSConfigHook func(*tls.Config) // optional hook for unit tests (e.g. custom test CA)
}

// Result holds real TLS, latency, packet-loss, and throughput measurements for one IP.
type Result struct {
	IP          string  `json:"ip"`
	Subnet      string  `json:"subnet"`
	Colo        string  `json:"colo,omitempty"`
	Status      string  `json:"status"` // "ok", "throttled", "stage1_ok", "blocked"
	Selected    bool    `json:"selected,omitempty"`
	HandshakeMS float64 `json:"handshake_ms,omitempty"`
	RTTMS       float64 `json:"rtt_ms,omitempty"`
	JitterMS    float64 `json:"jitter_ms,omitempty"`
	LossPct     int     `json:"loss_pct,omitempty"`
	DownMbps    float64 `json:"down_mbps,omitempty"`
	UpMbps      float64 `json:"up_mbps,omitempty"`
	AvgMbps     float64 `json:"avg_mbps,omitempty"`
	Score       int     `json:"score,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// Progress is emitted live while a scan is running.
type Progress struct {
	Phase         string   `json:"phase"` // "stage1", "stage2", "done", "cancelled"
	Message       string   `json:"message"`
	Done          int      `json:"done"`
	Total         int      `json:"total"`
	Percent       int      `json:"percent"`
	PassedStage1  int      `json:"passed_stage1"`
	VerifiedCount int      `json:"verified_count"`
	CurrentIP     string   `json:"current_ip,omitempty"`
	Results       []Result `json:"results,omitempty"`
}

// Report is the completed scan summary.
type Report struct {
	Domain        string    `json:"domain"`
	Port          int       `json:"port"`
	Fragment      bool      `json:"fragment"`
	ISP           ISPInfo   `json:"isp"`
	ScannedCount  int       `json:"scanned_count"`
	PassedStage1  int       `json:"passed_stage1"`
	VerifiedCount int       `json:"verified_count"`
	Recommended   []string  `json:"recommended"`
	Results       []Result  `json:"results"`
	Notes         []string  `json:"notes,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
	TestedAt      time.Time `json:"tested_at"`
}

// Overridable ISP detection URLs for offline testing.
var (
	ipAPIURL  = "http://ip-api.com/json/?fields=status,query,isp,as,country,city"
	cfMetaURL = "https://speed.cloudflare.com/meta"
)

// DetectISP discovers the user's current public IP and ISP directly from this device.
func DetectISP(ctx context.Context) ISPInfo {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type res struct {
		info ISPInfo
		prio int
	}
	ch := make(chan res, 2)

	// 1. ip-api.com over plain HTTP works even when Cloudflare's default Anycast IP is blocked.
	go func() {
		client := &http.Client{Timeout: 4500 * time.Millisecond}
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, ipAPIURL, nil)
		if err != nil {
			ch <- res{}
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			ch <- res{}
			return
		}
		defer resp.Body.Close()
		var body struct {
			Status  string `json:"status"`
			Query   string `json:"query"`
			ISP     string `json:"isp"`
			AS      string `json:"as"`
			Country string `json:"country"`
			City    string `json:"city"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&body); err != nil || body.Query == "" {
			ch <- res{}
			return
		}
		ch <- res{
			prio: 2,
			info: ISPInfo{
				IP:       body.Query,
				ISP:      strings.TrimSpace(body.ISP),
				ASN:      strings.TrimSpace(body.AS),
				Country:  strings.TrimSpace(body.Country),
				City:     strings.TrimSpace(body.City),
				Detected: true,
			},
		}
	}()

	// 2. speed.cloudflare.com/meta gives exact Cloudflare edge Colo + ASN + Client IP.
	go func() {
		client := &http.Client{Timeout: 4500 * time.Millisecond}
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, cfMetaURL, nil)
		if err != nil {
			ch <- res{}
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			ch <- res{}
			return
		}
		defer resp.Body.Close()
		var body struct {
			ClientIP       string `json:"clientIp"`
			ASN            int    `json:"asn"`
			ASOrganization string `json:"asOrganization"`
			Country        string `json:"country"`
			City           string `json:"city"`
			Colo           string `json:"colo"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&body); err != nil || body.ClientIP == "" {
			ch <- res{}
			return
		}
		asnStr := ""
		if body.ASN > 0 {
			asnStr = fmt.Sprintf("AS%d", body.ASN)
		}
		ch <- res{
			prio: 1,
			info: ISPInfo{
				IP:       body.ClientIP,
				ISP:      strings.TrimSpace(body.ASOrganization),
				ASN:      asnStr,
				Country:  strings.TrimSpace(body.Country),
				City:     strings.TrimSpace(body.City),
				Colo:     strings.TrimSpace(body.Colo),
				Detected: true,
			},
		}
	}()

	var best ISPInfo
	bestPrio := 0
	for i := 0; i < 2; i++ {
		r := <-ch
		if !r.info.Detected {
			continue
		}
		if r.prio > bestPrio {
			colo := best.Colo
			best = r.info
			if best.Colo == "" {
				best.Colo = colo
			}
			bestPrio = r.prio
		} else if best.Colo == "" && r.info.Colo != "" {
			best.Colo = r.info.Colo
		}
	}
	if !best.Detected {
		best.Error = "Could not detect public ISP automatically (scan still works)"
	}
	return best
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

// ExpandCandidates turns custom IPs/CIDRs (or DefaultSubnets when empty) into
// up to targetCount deduplicated concrete IP addresses spread across subnets.
func ExpandCandidates(customRaw []string, targetCount int) []string {
	if targetCount <= 0 {
		targetCount = 64
	}
	if targetCount > 320 {
		targetCount = 320
	}
	var tokens []string
	for _, raw := range customRaw {
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
		}) {
			if tok != "" {
				tokens = append(tokens, tok)
			}
		}
	}
	useCustom := len(tokens) > 0
	if !useCustom {
		tokens = DefaultSubnets
	}

	var out []string
	seen := map[string]bool{}
	add := func(ip string) bool {
		ip = strings.Trim(strings.TrimSpace(ip), "[]")
		if h, _, err := net.SplitHostPort(ip); err == nil && h != "" {
			ip = h
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return false
		}
		canon := parsed.String()
		if seen[canon] {
			return false
		}
		seen[canon] = true
		out = append(out, canon)
		return true
	}

	var cidrs []string
	for _, tok := range tokens {
		if strings.Contains(tok, "/") {
			cidrs = append(cidrs, tok)
			if sampled, ok := sampleIPFromCIDR(tok); ok {
				add(sampled)
				if len(out) >= targetCount {
					return out
				}
			}
		} else {
			add(tok)
			if len(out) >= targetCount {
				return out
			}
		}
	}

	// If more samples were requested than distinct CIDRs (e.g. Deep 160-IP scan),
	// keep drawing fresh random hosts across all CIDRs in round-robin passes.
	if len(cidrs) > 0 && len(out) < targetCount {
		maxRounds := 12
		for round := 0; round < maxRounds && len(out) < targetCount; round++ {
			addedAny := false
			for _, c := range cidrs {
				if len(out) >= targetCount {
					break
				}
				if sampled, ok := sampleIPFromCIDR(c); ok && add(sampled) {
					addedAny = true
				}
			}
			if !addedAny {
				break
			}
		}
	}
	return out
}

// fragConn fragments only the initial TLS ClientHello write into small chunks
// with short pacing delays to test DPI ClientHello fragmentation behavior.
type fragConn struct {
	net.Conn
	done bool
}

func (f *fragConn) Write(p []byte) (int, error) {
	if f.done || len(p) <= 40 || len(p) < 5 || p[0] != 0x16 {
		return f.Conn.Write(p)
	}
	f.done = true
	const chunk = 40
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		w, err := f.Conn.Write(p[:n])
		total += w
		if err != nil {
			return total, err
		}
		p = p[n:]
		if len(p) > 0 {
			time.Sleep(3 * time.Millisecond)
		}
	}
	return total, nil
}

func dialPinnedTLS(ctx context.Context, ip string, port int, sni string, fragment bool, hook func(*tls.Config)) (*tls.Conn, float64, error) {
	t0 := time.Now()
	d := &net.Dialer{Timeout: 2400 * time.Millisecond}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, 0, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	var base net.Conn = raw
	if fragment {
		base = &fragConn{Conn: raw}
	}
	tlsCfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if hook != nil {
		hook(tlsCfg)
	}
	conn := tls.Client(base, tlsCfg)
	hsDeadline := time.Now().Add(3200 * time.Millisecond)
	if dl, ok := ctx.Deadline(); ok && dl.Before(hsDeadline) {
		hsDeadline = dl
	}
	_ = conn.SetDeadline(hsDeadline)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	_ = conn.SetDeadline(time.Time{})
	hsMS := math.Round(float64(time.Since(t0))/float64(time.Millisecond)*10) / 10
	return conn, hsMS, nil
}

func probeTraceOnce(conn net.Conn, br *bufio.Reader, host string) (rttMS float64, colo string, err error) {
	_ = conn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	t0 := time.Now()
	reqStr := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n", host)
	if _, err := io.WriteString(conn, reqStr); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, "", err
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()
	if rerr != nil {
		return 0, "", rerr
	}
	rttMS = float64(time.Since(t0)) / float64(time.Millisecond)
	if resp.StatusCode == http.StatusOK {
		for _, line := range strings.Split(string(body), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == "colo" {
				colo = strings.TrimSpace(v)
				break
			}
		}
		if colo != "" || strings.Contains(string(body), "fl=") || strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") {
			return rttMS, colo, nil
		}
	}
	// Custom domain with WAF blocking /cdn-cgi/trace still returns cf-ray / cloudflare Server header.
	if ray := resp.Header.Get("Cf-Ray"); ray != "" {
		if idx := strings.LastIndex(ray, "-"); idx >= 0 && idx+1 < len(ray) {
			colo = ray[idx+1:]
		}
		return rttMS, colo, nil
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") {
		return rttMS, colo, nil
	}
	return rttMS, "", fmt.Errorf("HTTP %d (not Cloudflare edge)", resp.StatusCode)
}

func rttStats(samples []float64) (median, jitter float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	median = cp[len(cp)/2]
	if len(cp) == 1 {
		return median, 0
	}
	var sum float64
	for _, s := range cp {
		sum += s
	}
	mean := sum / float64(len(cp))
	var sq float64
	for _, s := range cp {
		d := s - mean
		sq += d * d
	}
	jitter = math.Sqrt(sq / float64(len(cp)))
	return median, jitter
}

func conciseError(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded"):
		return "timed out"
	case strings.Contains(lower, "reset") || strings.Contains(lower, "forcibly closed") || strings.Contains(lower, "eof"):
		return "connection reset / DPI drop"
	case strings.Contains(lower, "refused"):
		return "connection refused"
	case strings.Contains(lower, "certificate") || strings.Contains(lower, "handshake"):
		return "TLS handshake failed"
	case strings.Contains(lower, "no route") || strings.Contains(lower, "unreachable"):
		return "network unreachable"
	default:
		msg := err.Error()
		if len(msg) > 68 {
			return msg[:68] + "…"
		}
		return msg
	}
}

func runStage1(ctx context.Context, ip string, port int, domain string, fragment bool, hook func(*tls.Config)) Result {
	r := Result{
		IP:     ip,
		Subnet: subnet24Key(ip),
		Status: "blocked",
	}
	pctx, cancel := context.WithTimeout(ctx, 7500*time.Millisecond)
	defer cancel()

	conn, hsMS, err := dialPinnedTLS(pctx, ip, port, domain, fragment, hook)
	if err != nil {
		r.Error = conciseError(err)
		return r
	}
	defer conn.Close()

	stop := context.AfterFunc(pctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	br := bufio.NewReaderSize(conn, 16*1024)
	const probes = 3
	var rtts []float64
	var lastErr error
	for i := 0; i < probes; i++ {
		rtt, colo, perr := probeTraceOnce(conn, br, domain)
		if perr != nil {
			lastErr = perr
			continue
		}
		if r.Colo == "" && colo != "" {
			r.Colo = colo
		}
		rtts = append(rtts, rtt)
	}
	if len(rtts) == 0 {
		r.Error = conciseError(lastErr)
		return r
	}
	med, jit := rttStats(rtts)
	r.Status = "stage1_ok"
	r.HandshakeMS = hsMS
	r.RTTMS = math.Round(med*10) / 10
	r.JitterMS = math.Round(jit*10) / 10
	r.LossPct = ((probes - len(rtts)) * 100) / probes
	return r
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func runStage2Speed(ctx context.Context, ip string, speedPort int, speedHost string, dlBytes, ulBytes int, fragment bool, hook func(*tls.Config)) (downMbps, upMbps float64, partial string, err error) {
	// Download test: real sustained HTTPS download directly over candidate IP.
	dlCtx, dlCancel := context.WithTimeout(ctx, 6500*time.Millisecond)
	defer dlCancel()

	dlConn, _, err := dialPinnedTLS(dlCtx, ip, speedPort, speedHost, fragment, hook)
	if err != nil {
		return 0, 0, "", err
	}
	dlStop := context.AfterFunc(dlCtx, func() { _ = dlConn.SetDeadline(time.Now()) })
	_ = dlConn.SetDeadline(time.Now().Add(5500 * time.Millisecond))

	dlReq := fmt.Sprintf("GET /__down?bytes=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", dlBytes, speedHost)
	if _, err := io.WriteString(dlConn, dlReq); err != nil {
		dlStop()
		_ = dlConn.Close()
		return 0, 0, "", err
	}
	br := bufio.NewReaderSize(dlConn, 64*1024)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		dlStop()
		_ = dlConn.Close()
		return 0, 0, "", err
	}
	tStart := time.Now()
	gotBytes, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(dlBytes)+4096))
	dlDur := time.Since(tStart)
	_ = resp.Body.Close()
	dlStop()
	_ = dlConn.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", fmt.Errorf("speed endpoint returned HTTP %d", resp.StatusCode)
	}
	if dlDur > 0 && gotBytes > 0 {
		downMbps = (float64(gotBytes) * 8.0) / dlDur.Seconds() / 1_000_000.0
	}
	if readErr != nil && gotBytes < int64(dlBytes)/4 {
		return downMbps, 0, "download stalled mid-transfer", nil
	}
	if gotBytes < int64(dlBytes)/2 {
		return downMbps, 0, "download truncated / throttled", nil
	}

	// Upload test: real sustained HTTPS POST upload over candidate IP.
	if ulBytes > 0 {
		ulCtx, ulCancel := context.WithTimeout(ctx, 5500*time.Millisecond)
		defer ulCancel()
		ulConn, _, uerr := dialPinnedTLS(ulCtx, ip, speedPort, speedHost, fragment, hook)
		if uerr == nil {
			ulStop := context.AfterFunc(ulCtx, func() { _ = ulConn.SetDeadline(time.Now()) })
			_ = ulConn.SetDeadline(time.Now().Add(4500 * time.Millisecond))
			hdr := fmt.Sprintf("POST /__up HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", speedHost, ulBytes)
			uStart := time.Now()
			if _, werr := io.WriteString(ulConn, hdr); werr == nil {
				sent, serr := io.CopyN(ulConn, zeroReader{}, int64(ulBytes))
				if serr == nil && sent == int64(ulBytes) {
					ubr := bufio.NewReaderSize(ulConn, 8192)
					if uresp, rerr := http.ReadResponse(ubr, &http.Request{Method: http.MethodPost}); rerr == nil {
						_, _ = io.Copy(io.Discard, io.LimitReader(uresp.Body, 4096))
						_ = uresp.Body.Close()
						uDur := time.Since(uStart)
						if uDur > 0 && uresp.StatusCode < 400 {
							upMbps = (float64(sent) * 8.0) / uDur.Seconds() / 1_000_000.0
						}
					}
				}
			}
			ulStop()
			_ = ulConn.Close()
		}
	}

	if downMbps < 0.8 {
		return downMbps, upMbps, "severely throttled (< 0.8 Mbps)", nil
	}
	return downMbps, upMbps, "", nil
}

func scoreResult(rttMS, jitterMS float64, lossPct int, downMbps, upMbps float64) int {
	avgMbps := downMbps
	if upMbps > 0 {
		avgMbps = downMbps*0.7 + upMbps*0.3
	}
	// Up to 58 pts for real sustained throughput (smooth saturation around 50+ Mbps).
	tpPts := 58.0 * (1.0 - math.Exp(-avgMbps/18.0))
	// Up to 28 pts for low ping (<= 60ms = 28, 150ms = ~22, 300ms = ~12, >= 500ms = 2).
	latPts := 28.0 - math.Max(0, rttMS-55.0)*0.06
	if latPts < 2 {
		latPts = 2
	}
	if latPts > 28 {
		latPts = 28
	}
	// Up to 14 pts for stability (jitter + zero loss).
	stabPts := 14.0 - jitterMS*0.25 - float64(lossPct)*0.3
	if stabPts < 0 {
		stabPts = 0
	}
	score := int(math.Round(tpPts + latPts + stabPts))
	if score < 5 {
		score = 5
	}
	if score > 100 {
		score = 100
	}
	return score
}

func sortResults(results []Result) {
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
		if results[i].DownMbps != results[j].DownMbps {
			return results[i].DownMbps > results[j].DownMbps
		}
		if results[i].RTTMS > 0 && results[j].RTTMS > 0 && results[i].RTTMS != results[j].RTTMS {
			return results[i].RTTMS < results[j].RTTMS
		}
		return results[i].IP < results[j].IP
	})
}

// Run executes the 2-stage real ISP Cloudflare Clean IP scan directly from the
// local device, calling onProgress (if non-nil) as each IP completes.
func Run(ctx context.Context, req Request, onProgress func(Progress)) (*Report, error) {
	started := time.Now()
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = DefaultSpeedHost
	} else if !hostRe.MatchString(domain) {
		return nil, errors.New("enter a valid Cloudflare domain name (e.g. cdn.yourdomain.com) or leave empty for default")
	}
	port := req.Port
	if port <= 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("port must be between 1 and 65535")
	}
	count := req.Count
	if count <= 0 {
		count = 64
	}
	if count > 320 {
		count = 320
	}
	maxSelect := req.MaxSelect
	if maxSelect <= 0 {
		maxSelect = 5
	}
	if maxSelect > 20 {
		maxSelect = 20
	}
	stage2Limit := req.Stage2Limit
	if stage2Limit <= 0 {
		stage2Limit = max(12, maxSelect+4)
	}
	if stage2Limit > 24 {
		stage2Limit = 24
	}
	workers := req.Workers
	if workers <= 0 {
		workers = 20
	}
	if workers > 40 {
		workers = 40
	}
	dlBytes := req.DownloadBytes
	if dlBytes <= 0 {
		dlBytes = DefaultDownloadBytes
	}
	ulBytes := req.UploadBytes
	if ulBytes < 0 {
		ulBytes = 0
	} else if ulBytes == 0 && !req.SkipSpeedTest {
		ulBytes = DefaultUploadBytes
	}
	speedHost := strings.TrimSpace(req.SpeedHost)
	if speedHost == "" {
		speedHost = DefaultSpeedHost
	}
	speedPort := req.SpeedPort
	if speedPort <= 0 {
		speedPort = 443
	}

	candidates := ExpandCandidates(req.CustomRanges, count)
	if len(candidates) == 0 {
		return nil, errors.New("no valid candidate IP addresses or CIDR ranges to scan")
	}

	emit := func(p Progress) {
		if onProgress != nil {
			onProgress(p)
		}
	}

	// Kick off ISP detection concurrently while Stage 1 probes run.
	ispCh := make(chan ISPInfo, 1)
	go func() {
		ispCh <- DetectISP(ctx)
	}()

	results := make([]Result, len(candidates))
	var s1Done atomic.Int32
	var s1Passed atomic.Int32
	var mu sync.Mutex

	emit(Progress{
		Phase:   "stage1",
		Message: fmt.Sprintf("Stage 1: Testing real TLS + SNI (%s:%d) across %d Cloudflare IPs…", domain, port, len(candidates)),
		Done:    0,
		Total:   len(candidates),
		Percent: 2,
	})

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, ip := range candidates {
		wg.Add(1)
		go func(idx int, candIP string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results[idx] = Result{IP: candIP, Subnet: subnet24Key(candIP), Status: "blocked", Error: "cancelled"}
				mu.Unlock()
				return
			}
			r := runStage1(ctx, candIP, port, domain, req.Fragment, req.TLSConfigHook)
			doneN := int(s1Done.Add(1))
			if r.Status == "stage1_ok" {
				s1Passed.Add(1)
			}
			mu.Lock()
			results[idx] = r
			snap := make([]Result, 0, doneN)
			for _, x := range results {
				if x.IP != "" {
					snap = append(snap, x)
				}
			}
			mu.Unlock()
			sortResults(snap)
			pct := 4 + (doneN*56)/len(candidates)
			if req.SkipSpeedTest {
				pct = 4 + (doneN*94)/len(candidates)
			}
			emit(Progress{
				Phase:        "stage1",
				Message:      fmt.Sprintf("Stage 1: Real TLS + SNI (%d / %d tested · %d reachable)", doneN, len(candidates), s1Passed.Load()),
				Done:         doneN,
				Total:        len(candidates),
				Percent:      pct,
				PassedStage1: int(s1Passed.Load()),
				CurrentIP:    candIP,
				Results:      snap,
			})
		}(i, ip)
	}
	wg.Wait()

	var passedIdx []int
	for i := range results {
		if results[i].Status == "stage1_ok" {
			passedIdx = append(passedIdx, i)
		}
	}
	sort.Slice(passedIdx, func(a, b int) bool {
		ra, rb := results[passedIdx[a]], results[passedIdx[b]]
		if ra.LossPct != rb.LossPct {
			return ra.LossPct < rb.LossPct
		}
		return (ra.RTTMS + 0.3*ra.HandshakeMS) < (rb.RTTMS + 0.3*rb.HandshakeMS)
	})

	// Pick subnet-diverse finalists for Stage 2 sustained throughput tests.
	var finalists []int
	used24 := map[string]bool{}
	for _, idx := range passedIdx {
		if len(finalists) >= stage2Limit {
			break
		}
		if !used24[results[idx].Subnet] {
			used24[results[idx].Subnet] = true
			finalists = append(finalists, idx)
		}
	}
	for _, idx := range passedIdx {
		if len(finalists) >= stage2Limit {
			break
		}
		exists := false
		for _, f := range finalists {
			if f == idx {
				exists = true
				break
			}
		}
		if !exists {
			finalists = append(finalists, idx)
		}
	}

	verifiedCount := 0
	if req.SkipSpeedTest {
		for _, idx := range passedIdx {
			results[idx].Status = "ok"
			results[idx].Score = scoreResult(results[idx].RTTMS, results[idx].JitterMS, results[idx].LossPct, 25, 10)
			verifiedCount++
		}
	} else if len(finalists) > 0 && ctx.Err() == nil {
		// Run Stage 2 sequentially (1 finalist at a time) so each IP gets 100%
		// of the user's real home/mobile ISP bandwidth without self-contention.
		for step, idx := range finalists {
			if ctx.Err() != nil {
				break
			}
			candIP := results[idx].IP
			pct := 60 + (step*36)/len(finalists)
			emit(Progress{
				Phase:         "stage2",
				Message:       fmt.Sprintf("Stage 2: Speed testing %s (%d / %d finalists)…", candIP, step+1, len(finalists)),
				Done:          step,
				Total:         len(finalists),
				Percent:       pct,
				PassedStage1:  len(passedIdx),
				VerifiedCount: verifiedCount,
				CurrentIP:     candIP,
			})

			dlMbps, ulMbps, partial, err := runStage2Speed(ctx, candIP, speedPort, speedHost, dlBytes, ulBytes, req.Fragment, req.TLSConfigHook)
			if err != nil {
				results[idx].Status = "throttled"
				results[idx].Error = conciseError(err)
			} else {
				results[idx].DownMbps = math.Round(dlMbps*10) / 10
				results[idx].UpMbps = math.Round(ulMbps*10) / 10
				avg := dlMbps
				if ulMbps > 0 {
					avg = (dlMbps + ulMbps) / 2
				}
				results[idx].AvgMbps = math.Round(avg*10) / 10
				if partial != "" {
					results[idx].Status = "throttled"
					results[idx].Error = partial
				} else {
					results[idx].Status = "ok"
					results[idx].Score = scoreResult(results[idx].RTTMS, results[idx].JitterMS, results[idx].LossPct, dlMbps, ulMbps)
					verifiedCount++
				}
			}

			snap := append([]Result(nil), results...)
			sortResults(snap)
			emit(Progress{
				Phase:         "stage2",
				Message:       fmt.Sprintf("Stage 2: Speed tested %d / %d (%d clean verified)", step+1, len(finalists), verifiedCount),
				Done:          step + 1,
				Total:         len(finalists),
				Percent:       60 + ((step+1)*36)/len(finalists),
				PassedStage1:  len(passedIdx),
				VerifiedCount: verifiedCount,
				CurrentIP:     candIP,
				Results:       snap,
			})
		}
	}

	sortResults(results)

	// Stage 3: Select up to maxSelect verified IPs maximizing /16 then /24 diversity.
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
		if !seen16[k16] {
			seen16[k16] = true
			seen24[results[i].Subnet] = true
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
		if !seen24[results[i].Subnet] {
			seen24[results[i].Subnet] = true
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

	var isp ISPInfo
	select {
	case isp = <-ispCh:
	default:
	}

	rep := &Report{
		Domain:        domain,
		Port:          port,
		Fragment:      req.Fragment,
		ISP:           isp,
		ScannedCount:  len(candidates),
		PassedStage1:  len(passedIdx),
		VerifiedCount: len(verifiedIdx),
		Recommended:   recommended,
		Results:       results,
		DurationMS:    time.Since(started).Milliseconds(),
		TestedAt:      time.Now().UTC(),
	}

	if len(recommended) > 0 {
		ispLabel := "your current ISP"
		if isp.ISP != "" {
			ispLabel = isp.ISP
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"Found %d verified clean Cloudflare IPs on %s with real TLS (%s:%d) and sustained download/upload throughput.",
			len(verifiedIdx), ispLabel, domain, port,
		))
	} else if len(passedIdx) > 0 {
		rep.Notes = append(rep.Notes,
			"Cloudflare TLS handshakes succeeded on your ISP, but sustained downloads were throttled or cut mid-stream. Try enabling TLS ClientHello Fragmentation or scanning a deeper range.")
	} else {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"No tested Cloudflare IPs completed a TLS handshake to %s:%d. Make sure your VPN is disconnected, try enabling TLS ClientHello Fragmentation, or try port 2053 / 2083 / 8443.",
			domain, port,
		))
	}

	phase := "done"
	if ctx.Err() != nil {
		phase = "cancelled"
	}
	emit(Progress{
		Phase:         phase,
		Message:       fmt.Sprintf("Finished: %d clean IPs verified across %d tested.", len(verifiedIdx), len(candidates)),
		Done:          len(candidates),
		Total:         len(candidates),
		Percent:       100,
		PassedStage1:  len(passedIdx),
		VerifiedCount: len(verifiedIdx),
		Results:       results,
	})

	return rep, nil
}
