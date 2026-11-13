package engine

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	clientEntryIdleTTL = 10 * time.Minute
	clientGuardMaxMap  = 8192
	clientGuardGCStep  = 60 * time.Second
)

// ClientSnapshot describes one client IP observed on an Edge tunnel's user ports.
type ClientSnapshot struct {
	IP          string `json:"ip"`
	Active      int    `json:"active"`
	TotalConns  int64  `json:"total_conns"`
	Rejected    int64  `json:"rejected"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	Blocked     bool   `json:"blocked,omitempty"`
	LastSeenSec int64  `json:"last_seen_sec"`
}

type clientEntry struct {
	ip         string
	active     int
	totalConns int64
	rejected   int64
	bytesUp    int64 // atomic
	bytesDown  int64 // atomic
	tokens     float64
	lastRefill time.Time
	lastSeenNS int64
	closers    map[uint64]func()
}

type clientGuard struct {
	mu            sync.Mutex
	maxPerIP      int
	maxRatePerIP  int
	blockedExact  map[string]bool
	blockedNets   []*net.IPNet
	entries       map[string]*clientEntry
	nextHandle    uint64
	lastGCNano    int64
	totalRejected atomic.Int64
}

// CheckBlockedIPOrCIDR validates and normalises one client IP address or CIDR
// subnet (e.g. "203.0.113.9" or "203.0.113.0/24") for blocked_ips.
func CheckBlockedIPOrCIDR(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty IP or subnet")
	}
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil || ipNet == nil {
			return "", fmt.Errorf("%q is not a valid CIDR subnet", raw)
		}
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && ones < 8 {
			return "", fmt.Errorf("IPv4 block %q is too broad (use /8 to /32)", raw)
		}
		if bits == 128 && ones < 32 {
			return "", fmt.Errorf("IPv6 block %q is too broad (use /32 to /128)", raw)
		}
		return ipNet.String(), nil
	}
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return "", fmt.Errorf("%q is not a valid IP address or CIDR", raw)
	}
	if ip.IsUnspecified() {
		return "", fmt.Errorf("unspecified address %q cannot be blocked", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), nil
	}
	return ip.String(), nil
}

// ParseBlockedIPList parses a comma/space-separated list of blocked IPs or CIDRs,
// deduplicating while preserving order.
func ParseBlockedIPList(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	seen := make(map[string]bool, len(fields))
	var out []string
	for _, f := range fields {
		norm, err := CheckBlockedIPOrCIDR(f)
		if err != nil {
			return nil, err
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

func newClientGuard(cfg *Config) *clientGuard {
	g := &clientGuard{
		entries:    make(map[string]*clientEntry),
		lastGCNano: time.Now().UnixNano(),
	}
	if cfg != nil {
		g.updateRules(cfg.MaxConnPerIP, cfg.MaxRatePerIP, cfg.BlockedIPs)
	}
	return g
}

func compileBlockedRules(list []string) (map[string]bool, []*net.IPNet) {
	exact := make(map[string]bool)
	var nets []*net.IPNet
	for _, item := range list {
		norm, err := CheckBlockedIPOrCIDR(item)
		if err != nil {
			continue
		}
		if strings.Contains(norm, "/") {
			if _, ipNet, err := net.ParseCIDR(norm); err == nil && ipNet != nil {
				nets = append(nets, ipNet)
			}
		} else {
			exact[norm] = true
		}
	}
	return exact, nets
}

func (g *clientGuard) isBlockedLocked(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	if g.blockedExact[ipStr] {
		return true
	}
	if len(g.blockedNets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range g.blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *clientGuard) isBlocked(ipStr string) bool {
	if g == nil || ipStr == "" {
		return false
	}
	g.mu.Lock()
	blocked := g.isBlockedLocked(ipStr)
	g.mu.Unlock()
	return blocked
}

// updateRules hot-swaps per-IP limits and blocked IPs/subnets without restarting
// the tunnel, and immediately terminates all open sessions belonging to any IP
// now matched by the blocklist.
func (g *clientGuard) updateRules(maxPerIP, maxRatePerIP int, blocked []string) int {
	if g == nil {
		return 0
	}
	exact, nets := compileBlockedRules(blocked)
	var toKill []func()

	g.mu.Lock()
	g.maxPerIP = maxPerIP
	g.maxRatePerIP = maxRatePerIP
	g.blockedExact = exact
	g.blockedNets = nets

	for ip, ce := range g.entries {
		if g.isBlockedLocked(ip) && len(ce.closers) > 0 {
			for k, fn := range ce.closers {
				if fn != nil {
					toKill = append(toKill, fn)
				}
				delete(ce.closers, k)
			}
		}
	}
	g.mu.Unlock()

	for _, fn := range toKill {
		fn()
	}
	return len(toKill)
}

func burstForRate(rate int) float64 {
	b := rate * 2
	if b < 20 {
		b = 20
	}
	return float64(b)
}

func (g *clientGuard) entryForLocked(ip string, now time.Time) *clientEntry {
	ce := g.entries[ip]
	if ce != nil {
		return ce
	}
	if len(g.entries) >= clientGuardMaxMap {
		g.gcLocked(now.UnixNano(), true)
	}
	initTokens := 20.0
	if g.maxRatePerIP > 0 {
		initTokens = burstForRate(g.maxRatePerIP)
	}
	ce = &clientEntry{
		ip:         ip,
		tokens:     initTokens,
		lastRefill: now,
		lastSeenNS: now.UnixNano(),
	}
	g.entries[ip] = ce
	return ce
}

// acquire checks per-IP blocklists, max concurrent sessions, and connection rate
// limits for addr before admitting a new TCP or UDP user session.
func (g *clientGuard) acquire(addr net.Addr, closer func()) (string, *clientEntry, uint64, string, bool) {
	ip := normalizeClientIP(addr)
	if g == nil || ip == "" {
		return ip, nil, 0, "", true
	}

	now := time.Now()
	nowNS := now.UnixNano()

	g.mu.Lock()
	defer g.mu.Unlock()

	if nowNS-g.lastGCNano > int64(clientGuardGCStep) {
		g.gcLocked(nowNS, false)
	}

	ce := g.entryForLocked(ip, now)
	ce.lastSeenNS = nowNS

	if g.isBlockedLocked(ip) {
		ce.rejected++
		g.totalRejected.Add(1)
		return ip, ce, 0, "blocked_ip", false
	}
	if g.maxPerIP > 0 && ce.active >= g.maxPerIP {
		ce.rejected++
		g.totalRejected.Add(1)
		return ip, ce, 0, "max_per_ip", false
	}
	if g.maxRatePerIP > 0 {
		burst := burstForRate(g.maxRatePerIP)
		if ce.lastRefill.IsZero() {
			ce.tokens = burst
			ce.lastRefill = now
		} else if dt := now.Sub(ce.lastRefill).Seconds(); dt > 0 {
			ce.tokens += dt * float64(g.maxRatePerIP)
			if ce.tokens > burst {
				ce.tokens = burst
			}
			ce.lastRefill = now
		}
		if ce.tokens < 1.0 {
			ce.rejected++
			g.totalRejected.Add(1)
			return ip, ce, 0, "rate_per_ip", false
		}
		ce.tokens -= 1.0
	}

	ce.active++
	ce.totalConns++
	var handle uint64
	if closer != nil {
		g.nextHandle++
		handle = g.nextHandle
		if ce.closers == nil {
			ce.closers = make(map[uint64]func())
		}
		ce.closers[handle] = closer
	}
	return ip, ce, handle, "", true
}

func (g *clientGuard) release(ip string, handle uint64) {
	if g == nil || ip == "" {
		return
	}
	nowNS := time.Now().UnixNano()
	g.mu.Lock()
	if ce := g.entries[ip]; ce != nil {
		if ce.active > 0 {
			ce.active--
		}
		ce.lastSeenNS = nowNS
		if handle != 0 && ce.closers != nil {
			delete(ce.closers, handle)
		}
	}
	g.mu.Unlock()
}

func (g *clientGuard) gcLocked(nowNS int64, aggressive bool) {
	g.lastGCNano = nowNS
	cutoff := nowNS - int64(clientEntryIdleTTL)
	for ip, ce := range g.entries {
		if ce.active == 0 && ce.lastSeenNS < cutoff {
			delete(g.entries, ip)
		}
	}
	if !aggressive || len(g.entries) < clientGuardMaxMap {
		return
	}
	// Evict oldest inactive entries when flooded by random spoofed scanner IPs.
	type idleItem struct {
		ip   string
		seen int64
	}
	idle := make([]idleItem, 0, len(g.entries)/2)
	for ip, ce := range g.entries {
		if ce.active == 0 {
			idle = append(idle, idleItem{ip: ip, seen: ce.lastSeenNS})
		}
	}
	sort.Slice(idle, func(i, j int) bool { return idle[i].seen < idle[j].seen })
	dropTarget := len(g.entries) - (clientGuardMaxMap * 3 / 4)
	for i := 0; i < len(idle) && i < dropTarget; i++ {
		delete(g.entries, idle[i].ip)
	}
}

func (g *clientGuard) uniqueActiveCount() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	n := 0
	for _, ce := range g.entries {
		if ce.active > 0 {
			n++
		}
	}
	g.mu.Unlock()
	return n
}

func (g *clientGuard) snapshot(maxTop int) (uniqueActive int, abuseDrops int64, top []ClientSnapshot) {
	if g == nil {
		return 0, 0, nil
	}
	if maxTop <= 0 {
		maxTop = 25
	}
	nowNS := time.Now().UnixNano()

	g.mu.Lock()
	all := make([]ClientSnapshot, 0, len(g.entries))
	for ip, ce := range g.entries {
		if ce.active > 0 {
			uniqueActive++
		}
		ageSec := (nowNS - ce.lastSeenNS) / int64(time.Second)
		if ageSec < 0 {
			ageSec = 0
		}
		if ce.active == 0 && ce.rejected == 0 && ageSec > int64(clientEntryIdleTTL/time.Second) {
			continue
		}
		all = append(all, ClientSnapshot{
			IP:          ip,
			Active:      ce.active,
			TotalConns:  ce.totalConns,
			Rejected:    ce.rejected,
			BytesUp:     atomic.LoadInt64(&ce.bytesUp),
			BytesDown:   atomic.LoadInt64(&ce.bytesDown),
			Blocked:     g.isBlockedLocked(ip),
			LastSeenSec: ageSec,
		})
	}
	g.mu.Unlock()

	sort.Slice(all, func(i, j int) bool {
		if all[i].Active != all[j].Active {
			return all[i].Active > all[j].Active
		}
		if all[i].Rejected != all[j].Rejected {
			return all[i].Rejected > all[j].Rejected
		}
		bi := all[i].BytesUp + all[i].BytesDown
		bj := all[j].BytesUp + all[j].BytesDown
		if bi != bj {
			return bi > bj
		}
		if all[i].TotalConns != all[j].TotalConns {
			return all[i].TotalConns > all[j].TotalConns
		}
		return all[i].IP < all[j].IP
	})
	if len(all) > maxTop {
		all = all[:maxTop]
	}
	return uniqueActive, g.totalRejected.Load(), all
}

// ReloadGuardControl asks a running Edge tunnel over its Unix control socket to
// reload max_per_ip, rate_per_ip, and blocked_ips in-place without dropping
// legitimate user sessions.
func ReloadGuardControl(sockPath string) error {
	if strings.TrimSpace(sockPath) == "" {
		return fmt.Errorf("empty control socket path")
	}
	c, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("reload-guard\n")); err != nil {
		return err
	}
	var buf [128]byte
	n, err := c.Read(buf[:])
	if err != nil {
		return err
	}
	resp := strings.TrimSpace(string(buf[:n]))
	if resp != "ok" {
		return fmt.Errorf("reload-guard failed: %s", resp)
	}
	return nil
}
