package panel

// Auto-Heal & Smart Failover for tunnels.
//
// When Auto-Heal is enabled on a tunnel, the panel watches its live path state
// and link count in the background. If a running tunnel becomes blocked or loses
// all inter-server links for consecutive checks, the panel benchmarks all
// available transport/direction/IP-family candidates between the two servers
// (including Reverse, IPv6, and Cloudflare CDN if configured) and hot-swaps both
// halves of the tunnel to the highest-scoring working candidate while keeping
// the tunnel's name, secret, user ports, service ports, and PROXY protocol.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

const (
	autoHealInterval  = 20 * time.Second
	autoHealCooldown  = 2 * time.Minute
	autoHealThreshold = 2 // consecutive unhealthy checks (~40s) before probing & switching

	// After a failed attempt the next one waits twice as long as the last, so a
	// path that is down does not have the whole benchmark and two servers' worth
	// of config changes repeated every 20 seconds.
	autoHealBackoffBase = 2 * time.Minute
	autoHealBackoffMax  = 30 * time.Minute

	// How many tunnels may be healed at the same time. A wide outage makes many
	// tunnels unhealthy at once; healing them all together would benchmark and
	// reconfigure every server at the same moment.
	autoHealMaxParallel = 2
)

type tunnelHealRuntime struct {
	state     string
	failCount int
	lastCheck time.Time
	lastHeal  time.Time
	lastNote  string
	running   bool

	// failures counts failed heals in a row; nextTry is the earliest the next
	// automatic attempt may start.
	failures int
	nextTry  time.Time
}

type autoHealer struct {
	p  *Panel
	mu sync.Mutex
	rt map[string]*tunnelHealRuntime

	// slots bounds the heals running at once; serverMu keeps two heals from
	// working on the same server at the same time.
	slots    chan struct{}
	serverMu map[string]*sync.Mutex
}

func newAutoHealer(p *Panel) *autoHealer {
	return &autoHealer{
		p:        p,
		rt:       map[string]*tunnelHealRuntime{},
		slots:    make(chan struct{}, autoHealMaxParallel),
		serverMu: map[string]*sync.Mutex{},
	}
}

func (ah *autoHealer) runtimeOf(key string) *tunnelHealRuntime {
	r := ah.rt[key]
	if r == nil {
		r = &tunnelHealRuntime{state: "monitoring"}
		ah.rt[key] = r
	}
	return r
}

// healBackoff is how long to wait after the given number of failed heals in a
// row: 2 minutes, then 4, 8, 16, and never more than 30.
func healBackoff(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	d := autoHealBackoffBase
	for i := 1; i < failures && d < autoHealBackoffMax; i++ {
		d *= 2
	}
	if d > autoHealBackoffMax {
		d = autoHealBackoffMax
	}
	return d
}

// lockServers takes a lock on each server, always in the same order so two heals
// can never wait on each other, and returns the function that lets go.
func (ah *autoHealer) lockServers(ids ...string) func() {
	uniq := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !slices.Contains(uniq, id) {
			uniq = append(uniq, id)
		}
	}
	slices.Sort(uniq)
	locks := make([]*sync.Mutex, 0, len(uniq))
	ah.mu.Lock()
	for _, id := range uniq {
		m := ah.serverMu[id]
		if m == nil {
			m = &sync.Mutex{}
			ah.serverMu[id] = m
		}
		locks = append(locks, m)
	}
	ah.mu.Unlock()
	for _, m := range locks {
		m.Lock()
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Unlock()
		}
	}
}

// Auto-Heal settings are kept per tunnel, and a tunnel name is only unique on one
// server: two different pairs of servers can each have a tunnel called "main".
// The settings are therefore kept under "<relay server id>/<name>". Settings from
// before that were kept under the bare name; they still count while only one
// tunnel has that name, and are moved to the new key as soon as they can be.

// healKeyFor is where a tunnel's Auto-Heal settings are kept.
func healKeyFor(edgeID, name string) string {
	if edgeID == "" {
		return name
	}
	return edgeID + "/" + name
}

func edgeIDOf(tv tunnelView) string {
	if tv.Edge == nil {
		return ""
	}
	return tv.Edge.ServerID
}

// healableNameCounts says how many tunnels, with both halves in the panel, carry
// each name. Only those can be healed, so only those can be confused.
func healableNameCounts(tunnels []tunnelView) map[string]int {
	counts := map[string]int{}
	for _, tv := range tunnels {
		if tv.Edge != nil && tv.Origin != nil {
			counts[tv.Name]++
		}
	}
	return counts
}

// resolveHealConfig finds a tunnel's settings: under its own key, or else under
// the bare name from before, when that name belongs to just this one tunnel.
func resolveHealConfig(st State, edgeID, name string, counts map[string]int) (AutoHealConfig, bool) {
	if c, ok := st.AutoHeal[healKeyFor(edgeID, name)]; ok {
		return c, true
	}
	if c, ok := st.AutoHeal[name]; ok && counts[name] <= 1 {
		return c, true
	}
	return AutoHealConfig{}, false
}

// moveLegacyHealKey gives a tunnel's old bare-name settings its own key, when the
// name is not shared with another tunnel. Called inside a store update.
func moveLegacyHealKey(st *State, edgeID, name string, counts map[string]int) {
	ck := healKeyFor(edgeID, name)
	if ck == name || st.AutoHeal == nil || counts[name] > 1 {
		return
	}
	if _, has := st.AutoHeal[ck]; has {
		return
	}
	if c, ok := st.AutoHeal[name]; ok {
		st.AutoHeal[ck] = c
		delete(st.AutoHeal, name)
	}
}

// migrateLegacyKeys moves every tunnel's old bare-name settings to its own key.
func (ah *autoHealer) migrateLegacyKeys(tunnels []tunnelView) {
	st := ah.p.store.get()
	if len(st.AutoHeal) == 0 {
		return
	}
	counts := healableNameCounts(tunnels)
	need := false
	for _, tv := range tunnels {
		if tv.Edge == nil || tv.Origin == nil {
			continue
		}
		if _, ok := st.AutoHeal[tv.Name]; ok && counts[tv.Name] <= 1 && healKeyFor(edgeIDOf(tv), tv.Name) != tv.Name {
			need = true
			break
		}
	}
	if !need {
		return
	}
	_ = ah.p.store.update(func(s *State) error {
		for _, tv := range tunnels {
			if tv.Edge != nil && tv.Origin != nil {
				moveLegacyHealKey(s, edgeIDOf(tv), tv.Name, counts)
			}
		}
		return nil
	})
}

// forget drops a deleted tunnel's Auto-Heal settings and live state.
func (ah *autoHealer) forget(edgeID, name string) {
	counts := healableNameCounts(pairTunnels(ah.p.fleet.views()))
	_ = ah.p.store.update(func(st *State) error {
		delete(st.AutoHeal, healKeyFor(edgeID, name))
		// The old bare-name entry is this tunnel's only if no other tunnel
		// still has the name.
		if counts[name] == 0 {
			delete(st.AutoHeal, name)
		}
		return nil
	})
	ah.mu.Lock()
	delete(ah.rt, healKeyFor(edgeID, name))
	ah.mu.Unlock()
}

// extractTunnelCDNDomain returns the CDN domain configured on a tunnel (either
// as its primary CDN domain or its hybrid CDN backup domain).
func extractTunnelCDNDomain(ti agent.TunnelInfo) string {
	if ti.CDN && ti.ServerName != "" && engine.HostnameRe.MatchString(ti.ServerName) {
		return ti.ServerName
	}
	if ti.AltHost != "" && engine.HostnameRe.MatchString(ti.AltHost) {
		return ti.AltHost
	}
	if ti.CDN {
		// Fallback extraction from human-readable Link description, e.g. "(sub.domain.com)"
		if i := strings.IndexByte(ti.Link, '('); i >= 0 {
			if j := strings.IndexByte(ti.Link[i+1:], ')'); j >= 0 {
				cand := strings.TrimSpace(ti.Link[i+1 : i+1+j])
				if strings.Contains(cand, ".") && engine.HostnameRe.MatchString(cand) {
					return cand
				}
			}
		}
	}
	return ""
}

// attachViews populates AutoHeal on each tunnelView for the UI.
func (ah *autoHealer) attachViews(tunnels []tunnelView) {
	st := ah.p.store.get()
	counts := healableNameCounts(tunnels)
	ah.mu.Lock()
	defer ah.mu.Unlock()
	for i := range tunnels {
		name := tunnels[i].Name
		edgeID := edgeIDOf(tunnels[i])
		cfg, _ := resolveHealConfig(st, edgeID, name, counts)
		if cfg.CDNDomain == "" && tunnels[i].Edge != nil {
			if dom := extractTunnelCDNDomain(tunnels[i].Edge.Info); dom != "" {
				cfg.CDNDomain = dom
			}
		}
		if r := ah.rt[healKeyFor(edgeID, name)]; r != nil {
			cfg.State = r.state
			cfg.FailCount = r.failCount
			if !r.lastCheck.IsZero() {
				cfg.LastCheck = r.lastCheck.UTC().Format(time.RFC3339)
			}
			if !r.lastHeal.IsZero() {
				cfg.LastHeal = r.lastHeal.UTC().Format(time.RFC3339)
			}
			if r.lastNote != "" {
				cfg.LastNote = r.lastNote
			}
		} else if cfg.Enabled && cfg.State == "" {
			cfg.State = "monitoring"
		}
		if len(cfg.History) > 0 && cfg.LastHeal == "" {
			cfg.LastHeal = cfg.History[0].At
		}
		c := cfg
		tunnels[i].AutoHeal = &c
	}
}

// setConfig enables/disables Auto-Heal or updates its optional CDN failover domain.
// edgeID says which relay server's tunnel is meant; when empty, the name alone
// must pick out exactly one tunnel.
func (ah *autoHealer) setConfig(edgeID, name string, enabled bool, cdnDomain string) error {
	cdnDomain = strings.TrimSpace(cdnDomain)
	if cdnDomain != "" && !engine.HostnameRe.MatchString(cdnDomain) {
		return fmt.Errorf("%q is not a valid domain name", cdnDomain)
	}
	tunnels := pairTunnels(ah.p.fleet.views())
	counts := healableNameCounts(tunnels)
	if edgeID == "" {
		var found []string
		for _, tv := range tunnels {
			if tv.Name == name && tv.Edge != nil && tv.Origin != nil {
				found = append(found, tv.Edge.ServerID)
			}
		}
		switch len(found) {
		case 1:
			edgeID = found[0]
		case 0:
		default:
			return fmt.Errorf("more than one tunnel is called %q; open Auto-Heal from the tunnel's own card", name)
		}
	}
	key := healKeyFor(edgeID, name)
	if cdnDomain == "" {
		for _, tv := range tunnels {
			if tv.Name == name && edgeIDOf(tv) == edgeID && tv.Edge != nil {
				if dom := extractTunnelCDNDomain(tv.Edge.Info); dom != "" {
					cdnDomain = dom
				}
				break
			}
		}
	}
	err := ah.p.store.update(func(st *State) error {
		if st.AutoHeal == nil {
			st.AutoHeal = map[string]AutoHealConfig{}
		}
		moveLegacyHealKey(st, edgeID, name, counts)
		c := st.AutoHeal[key]
		c.Enabled = enabled
		if cdnDomain != "" || !enabled {
			c.CDNDomain = cdnDomain
		}
		if enabled && c.State == "" {
			c.State = "monitoring"
		}
		st.AutoHeal[key] = c
		return nil
	})
	if err != nil {
		return err
	}
	ah.mu.Lock()
	r := ah.runtimeOf(key)
	if enabled {
		if !r.running {
			r.state = "monitoring"
		}
	} else {
		r.failCount = 0
		r.failures = 0
		r.nextTry = time.Time{}
		r.state = ""
		r.lastNote = ""
	}
	ah.mu.Unlock()
	return nil
}

// run periodically inspects tunnels that have Auto-Heal enabled.
func (ah *autoHealer) run(ctx context.Context) {
	tick := time.NewTicker(autoHealInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			ah.checkAll(ctx)
		}
	}
}

func (ah *autoHealer) checkAll(ctx context.Context) {
	if len(ah.p.store.get().AutoHeal) == 0 {
		return
	}
	tunnels := pairTunnels(ah.p.fleet.views())
	ah.migrateLegacyKeys(tunnels)
	st := ah.p.store.get()
	counts := healableNameCounts(tunnels)
	for _, tv := range tunnels {
		cfg, ok := resolveHealConfig(st, edgeIDOf(tv), tv.Name, counts)
		if !ok || !cfg.Enabled {
			continue
		}
		key := healKeyFor(edgeIDOf(tv), tv.Name)
		if cfg.CDNDomain == "" && tv.Edge != nil {
			if dom := extractTunnelCDNDomain(tv.Edge.Info); dom != "" {
				cfg.CDNDomain = dom
				_ = ah.p.store.update(func(s *State) error {
					c, has := s.AutoHeal[key]
					if has && c.CDNDomain == "" {
						c.CDNDomain = dom
						s.AutoHeal[key] = c
					}
					return nil
				})
			}
		}
		ah.evaluateTunnel(ctx, tv, key, cfg)
	}
}

func tunnelUnhealthyReason(tv tunnelView) (bool, string) {
	if tv.Edge == nil || tv.Origin == nil || tv.Stale {
		return false, ""
	}
	ei := tv.Edge.Info
	oi := tv.Origin.Info
	// Do not auto-heal tunnels that were intentionally stopped.
	if !ei.Running || !oi.Running {
		return false, ""
	}
	el := ei.Live
	ol := oi.Live
	if el == nil {
		return false, ""
	}
	// Give newly started or recently restarted tunnels time to establish links.
	if el.UptimeSeconds < 25 {
		return false, ""
	}
	if el.PathState == "blocked" {
		note := strings.TrimSpace(el.PathNote)
		if note == "" {
			note = "relay path reported blocked"
		}
		return true, note
	}
	if ol != nil && ol.UptimeSeconds >= 25 && ol.PathState == "blocked" {
		note := strings.TrimSpace(ol.PathNote)
		if note == "" {
			note = "foreign path reported blocked"
		}
		return true, note
	}
	if ei.Mux {
		if el.Links == 0 && el.UptimeSeconds >= 30 {
			return true, "0 shared Mux links open between Relay and Foreign"
		}
	} else {
		if el.ParkedSpares == 0 && el.ActiveSessions == 0 && el.UptimeSeconds >= 30 {
			return true, "0 spare or active connections open between Relay and Foreign"
		}
	}
	return false, ""
}

func (ah *autoHealer) evaluateTunnel(ctx context.Context, tv tunnelView, key string, cfg AutoHealConfig) {
	unhealthy, reason := tunnelUnhealthyReason(tv)
	now := time.Now()

	ah.mu.Lock()
	r := ah.runtimeOf(key)
	r.lastCheck = now
	if r.running {
		ah.mu.Unlock()
		return
	}
	if !unhealthy {
		r.failCount = 0
		// The path works again, whether by a heal or by itself: start the
		// back-off over.
		r.failures = 0
		r.nextTry = time.Time{}
		if !r.lastHeal.IsZero() && now.Sub(r.lastHeal) < autoHealCooldown {
			r.state = "cooldown"
		} else {
			r.state = "monitoring"
			r.lastNote = "Tunnel link is healthy"
		}
		ah.mu.Unlock()
		return
	}

	r.failCount++
	r.lastNote = fmt.Sprintf("Unhealthy (%d/%d): %s", r.failCount, autoHealThreshold, reason)
	if r.failCount < autoHealThreshold {
		r.state = "monitoring"
		ah.mu.Unlock()
		return
	}
	if !r.lastHeal.IsZero() && now.Sub(r.lastHeal) < autoHealCooldown {
		r.state = "cooldown"
		r.lastNote = fmt.Sprintf("Waiting cooldown before next auto-heal (%s)", reason)
		ah.mu.Unlock()
		return
	}

	// A heal that just failed is not repeated straight away.
	if now.Before(r.nextTry) {
		r.state = "backoff"
		r.lastNote = fmt.Sprintf("The last attempt failed; trying again in %s (%s)",
			r.nextTry.Sub(now).Round(time.Second), reason)
		ah.mu.Unlock()
		return
	}
	// Only a few tunnels are healed at a time; the rest wait for the next check.
	select {
	case ah.slots <- struct{}{}:
	default:
		r.state = "queued"
		r.lastNote = fmt.Sprintf("Waiting for other tunnels being healed to finish (%s)", reason)
		ah.mu.Unlock()
		return
	}

	r.running = true
	r.state = "probing"
	r.lastNote = "Benchmarking alternative tunnel modes..."
	ah.mu.Unlock()

	go func() {
		defer func() { <-ah.slots }()
		hctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		_ = ah.healTunnel(hctx, nil, key, tv.Name, tv.Edge.ServerID, tv.Origin.ServerID, cfg.CDNDomain, reason, false)
	}()
}

// startManualHeal launches an immediate Smart Failover benchmark + mode switch job.
func (ah *autoHealer) startManualHeal(name, edgeID, originID, cdnDomain string) (string, error) {
	if err := ah.p.knownTarget(tunnelTarget{Name: name, Edge: edgeID, Origin: originID}); err != nil {
		return "", err
	}
	if edgeID == "" || originID == "" {
		return "", errors.New("both the Relay (Iran) and Foreign servers must be in the panel to switch tunnel modes")
	}
	cdnDomain = strings.TrimSpace(cdnDomain)
	tunnels := pairTunnels(ah.p.fleet.views())
	ah.migrateLegacyKeys(tunnels)
	key := healKeyFor(edgeID, name)
	if cdnDomain == "" {
		cfg, _ := resolveHealConfig(ah.p.store.get(), edgeID, name, healableNameCounts(tunnels))
		cdnDomain = cfg.CDNDomain
	}
	ah.mu.Lock()
	r := ah.runtimeOf(key)
	if r.running {
		ah.mu.Unlock()
		return "", errors.New("Auto-Heal is already running for this tunnel")
	}
	r.running = true
	r.state = "probing"
	r.lastNote = "Manual Smart Failover started..."
	ah.mu.Unlock()

	return ah.p.startJob(func(j *job) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		err := ah.healTunnel(ctx, j, key, name, edgeID, originID, cdnDomain, "manual trigger", true)
		return "", err
	}), nil
}

func describeTunnelInfo(ti agent.TunnelInfo) string {
	dir := strings.ToUpper(ti.Mode)
	if dir == "" {
		dir = "DIRECT"
	}
	tr := strings.ToUpper(ti.Transport)
	linkLower := strings.ToLower(ti.Link)
	if ti.SIT {
		tr += " (6in4)"
	} else if ti.CDN {
		tr += " (CDN)"
	} else if ti.AntiFreeze {
		tr += " (Split-Stream)"
	} else if strings.Contains(linkLower, "website header") {
		tr += " (HTTP)"
	} else if strings.Contains(linkLower, "fragmented") || strings.Contains(linkLower, "browser tls") {
		tr += " (Stealth)"
	}
	fam := "IPv4"
	if strings.Contains(ti.PeerIP, ":") || strings.Contains(ti.LocalIP, ":") {
		fam = "IPv6"
	}
	return fmt.Sprintf("%s · %s · %s", dir, tr, fam)
}

func sameCandidateAsCurrent(c engine.ProbeCandidateResult, ti agent.TunnelInfo) bool {
	if ti.CDN && !slices.Contains(engine.CDNHTTPSPorts, ti.LinkPort) {
		// If a CDN tunnel was set to a non-Cloudflare port, switching to a valid
		// Cloudflare HTTPS port on CDN fixes the port and should not be penalized.
		return false
	}
	curIPv6 := strings.Contains(ti.PeerIP, ":") || strings.Contains(ti.LocalIP, ":")
	curHTTP := strings.Contains(strings.ToLower(ti.Link), "website header")
	return strings.EqualFold(c.Mode, ti.Mode) &&
		strings.EqualFold(c.Transport, ti.Transport) &&
		c.IPv6 == curIPv6 &&
		c.CDN == ti.CDN &&
		c.AntiFreeze == ti.AntiFreeze &&
		c.WebHeader == curHTTP
}

func (ah *autoHealer) pickBestCandidate(rep *engine.ProbeBenchmarkReport, cur agent.TunnelInfo, force bool) (engine.ProbeCandidateResult, bool) {
	if rep == nil {
		return engine.ProbeCandidateResult{}, false
	}
	var working []engine.ProbeCandidateResult
	var different []engine.ProbeCandidateResult
	for _, c := range rep.Results {
		// Only select candidates where end-to-end data transfer actually succeeded
		// ("ok" or "degraded"). Never select "throttled" candidates, which are
		// connections where the handshake opened but data froze mid-stream due to
		// an ISP/DPI byte-cap filter.
		if c.Status != "ok" && c.Status != "degraded" {
			continue
		}
		if c.Hybrid {
			continue
		}
		working = append(working, c)
		if !sameCandidateAsCurrent(c, cur) {
			different = append(different, c)
		}
	}
	// When healing an unhealthy tunnel (or if scores are close), prefer a different
	// mode/transport/IP-family than the one that just got blocked.
	if len(different) > 0 {
		if !force || len(working) == 0 || different[0].Score >= working[0].Score-5 {
			return different[0], true
		}
	}
	if len(working) > 0 {
		return working[0], true
	}
	return engine.ProbeCandidateResult{}, false
}

// chooseFailoverLinkPort picks a bridge port that is free on whichever server
// will listen for the new tunnel mode (Foreign for direct, Relay for reverse).
func (ah *autoHealer) chooseFailoverLinkPort(ctx context.Context, relayID, foreignID string, cur agent.TunnelInfo, best engine.ProbeCandidateResult) int {
	var candidates []int
	if best.CDN {
		// Cloudflare CDN only forwards its supported HTTPS ports.
		if best.Port > 0 && slices.Contains(engine.CDNHTTPSPorts, best.Port) {
			candidates = append(candidates, best.Port)
		}
		if cur.LinkPort > 0 && slices.Contains(engine.CDNHTTPSPorts, cur.LinkPort) {
			candidates = append(candidates, cur.LinkPort)
		}
		candidates = append(candidates, engine.CDNHTTPSPorts...)
	} else {
		stdPorts := []int{2053, 2083, 2087, 2096, 8443, 443, 4433, 7443, 9443}
		if best.Port > 0 && slices.Contains(stdPorts, best.Port) {
			candidates = append(candidates, best.Port)
		}
		if cur.LinkPort > 0 && cur.Mode == best.Mode {
			candidates = append(candidates, cur.LinkPort)
		}
		candidates = append(candidates, stdPorts...)
		if cur.LinkPort > 0 {
			candidates = append(candidates, cur.LinkPort)
		}
	}

	avoid := map[int]bool{}
	for _, p := range cur.UserPorts {
		avoid[p] = true
	}
	for _, p := range cur.ServicePorts {
		avoid[p] = true
	}

	var ask []int
	seen := map[int]bool{}
	for _, p := range candidates {
		if p > 0 && !avoid[p] && !seen[p] {
			seen[p] = true
			ask = append(ask, p)
		}
	}
	if len(ask) == 0 {
		if best.CDN {
			return 2083
		}
		return 8443
	}

	listenServerID := foreignID
	if best.Mode == "reverse" {
		listenServerID = relayID
	}
	st, err := ah.p.portsThere(ctx, listenServerID, ask)
	if err != nil {
		return ask[0]
	}
	ownLabel := "PortBridge tunnel " + cur.Name
	for _, p := range ask {
		ps, ok := st[p]
		if !ok || ps.State == "free" || ps.By == ownLabel {
			return p
		}
	}
	return ask[0]
}

func (ah *autoHealer) healTunnel(ctx context.Context, j *job, key, name, relayID, foreignID, cdnDomain, reason string, force bool) (retErr error) {
	say := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if j != nil {
			j.say("%s", msg)
		}
		logf("[auto-heal %s] %s", name, msg)
	}

	var ev AutoHealEvent
	ev.At = time.Now().UTC().Format(time.RFC3339)
	ev.Reason = reason

	defer func() {
		var note string
		ah.mu.Lock()
		r := ah.runtimeOf(key)
		r.running = false
		r.lastCheck = time.Now()
		if retErr != nil {
			r.state = "error"
			r.lastNote = retErr.Error()
			ev.Success = false
			ev.Error = retErr.Error()
			// Each failure in a row doubles the wait before the next
			// automatic attempt.
			r.failures++
			r.nextTry = time.Now().Add(healBackoff(r.failures))
		} else {
			r.failCount = 0
			r.failures = 0
			r.nextTry = time.Time{}
			r.state = "monitoring"
			if ev.ToDesc == "" {
				// It came back by itself before anything was changed.
				r.lastNote = "Tunnel link is healthy"
			} else {
				r.lastHeal = time.Now()
				r.lastNote = fmt.Sprintf("Switched to %s (Score %d/100)", ev.ToDesc, ev.Score)
			}
			ev.Success = true
		}
		note = r.lastNote
		ah.mu.Unlock()

		if ev.FromDesc != "" || ev.Error != "" {
			_ = ah.p.store.update(func(st *State) error {
				if st.AutoHeal == nil {
					st.AutoHeal = map[string]AutoHealConfig{}
				}
				c := st.AutoHeal[key]
				c.LastHeal = ev.At
				c.LastNote = note
				c.History = append([]AutoHealEvent{ev}, c.History...)
				if len(c.History) > 20 {
					c.History = c.History[:20]
				}
				st.AutoHeal[key] = c
				return nil
			})
		}
	}()

	// Only one heal at a time may be working on a given server.
	defer ah.lockServers(relayID, foreignID)()

	// Refresh both servers first so we have fresh tunnel info and addresses.
	ah.p.refreshOne(relayID)
	ah.p.refreshOne(foreignID)

	var tv *tunnelView
	for _, item := range pairTunnels(ah.p.fleet.views()) {
		// The relay is part of the match: another pair of servers may have a
		// tunnel with the same name.
		if item.Name == name && edgeIDOf(item) == relayID {
			copyItem := item
			tv = &copyItem
			break
		}
	}
	if tv == nil || tv.Edge == nil || tv.Origin == nil {
		return fmt.Errorf("tunnel %q could not be found on both Relay and Foreign servers", name)
	}
	curInfo := tv.Edge.Info
	ev.FromDesc = describeTunnelInfo(curInfo)
	if cdnDomain == "" {
		if dom := extractTunnelCDNDomain(curInfo); dom != "" {
			cdnDomain = dom
			_ = ah.p.store.update(func(st *State) error {
				if st.AutoHeal == nil {
					st.AutoHeal = map[string]AutoHealConfig{}
				}
				c := st.AutoHeal[key]
				if c.CDNDomain == "" {
					c.CDNDomain = dom
					st.AutoHeal[key] = c
				}
				return nil
			})
		}
	}

	if !force {
		if unhealthy, _ := tunnelUnhealthyReason(*tv); !unhealthy {
			say("Tunnel %q recovered on its own before failover started.", name)
			ev.FromDesc = "" // do not record a spurious event
			return nil
		}
	}

	say("Tunnel %q (%s) triggered Smart Failover (%s). Benchmarking all available paths...", name, ev.FromDesc, reason)
	rep, err := ah.p.probeBetweenServers(ctx, relayID, foreignID, cdnDomain)
	if err != nil {
		return fmt.Errorf("could not benchmark paths between servers: %s", plainAgentError(err))
	}

	best, ok := ah.pickBestCandidate(rep, curInfo, force)
	if !ok {
		return errors.New("all tested tunnel modes (Direct, Reverse, IPv4, IPv6, CDN) failed or were blocked between these servers")
	}
	say("Best working path found: %s (%s, score %d/100).", best.Label, best.Summary, best.Score)

	ah.mu.Lock()
	if r := ah.rt[key]; r != nil {
		r.state = "switching"
		r.lastNote = fmt.Sprintf("Switching to %s...", best.Label)
	}
	ah.mu.Unlock()

	rv, rok := ah.p.viewOf(relayID)
	fv, fok := ah.p.viewOf(foreignID)
	if !rok || !fok {
		return errors.New("one of the tunnel's servers is no longer in the panel")
	}
	rv4, rv6 := addressesOf(rv)
	fv4, fv6 := addressesOf(fv)

	localIP, peerIP := rv4, fv4
	if best.IPv6 {
		if rv6 == "" || fv6 == "" {
			return errors.New("selected IPv6 candidate, but one of the servers has no public IPv6 address")
		}
		localIP, peerIP = rv6, fv6
	} else {
		// Preserve custom IPv4 local/peer address if already IPv4.
		if ip := net.ParseIP(curInfo.LocalIP); ip != nil && ip.To4() != nil {
			localIP = curInfo.LocalIP
		}
		if ip := net.ParseIP(curInfo.PeerIP); ip != nil && ip.To4() != nil {
			peerIP = curInfo.PeerIP
		}
	}

	linkPort := ah.chooseFailoverLinkPort(ctx, relayID, foreignID, curInfo, best)
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	muxMode := "on"
	if !best.Shared && !curInfo.Mux && !engine.IsKCPFamily(engine.Transport(best.Transport)) {
		muxMode = "off"
	}
	muxLinks := max(1, curInfo.MuxLinks)
	if best.Transport == "icmp" || best.Transport == "faketcp" || best.IPSpoof {
		if curInfo.MuxLinks <= 0 || curInfo.MuxLinks == 4 {
			muxLinks = 2
		}
	}
	ipv6Flag := best.IPv6
	serverName := best.ServerName
	if best.CDN {
		if best.Domain != "" {
			serverName = best.Domain
		} else if cdnDomain != "" {
			serverName = cdnDomain
		}
	}
	if serverName == "" && (best.Transport == "tls" || best.Transport == "wss" || best.Transport == "grpc") {
		serverName = "www.bing.com"
	}
	httpHost := ""
	if best.WebHeader {
		httpHost = "www.bing.com"
	}
	realSite := !best.CDN && (best.Transport == "tls" || best.Transport == "grpc")

	// A CDN backup route the owner set up is kept where it can still work: on a
	// direct website-style link. It cannot be combined with showing the real
	// website to strangers (the CDN's own connection carries no proof), so that
	// is left off for the tunnel that keeps the backup.
	altHost := ""
	switch best.Transport {
	case "tls", "wss", "h2", "grpc":
		// (IPv6 between the servers cannot be combined with a CDN route.)
		if curInfo.AltHost != "" && !best.CDN && !best.IPv6 && best.Mode == "direct" {
			altHost = curInfo.AltHost
			realSite = false
		}
	}

	spec := agent.EditSpec{
		Name:       name,
		Mode:       best.Mode,
		Transport:  best.Transport,
		LinkPort:   linkPort,
		PeerIP:     peerIP,
		LocalIP:    localIP,
		IPv6:       &ipv6Flag,
		ServerName: serverName,
		CDN:        onOff(best.CDN),
		AltHost:    altHost,
		CleanIPs:   "",
		// The tunnel's own clean addresses are kept when it stays on a CDN link.
		KeepCleanIPs: best.CDN,
		UTLS:         onOff(best.Stealth),
		TLSFragment:  onOff(best.Stealth),
		HTTPHeader:   onOff(best.WebHeader),
		HTTPHost:     httpHost,
		RealSite:     onOff(realSite),
		SNISpoof:     onOff(best.SNISpoof),
		SpoofSNI:     best.SpoofSNI,
		IPSpoof:      onOff(best.IPSpoof),
		SpoofIP:      best.SpoofIP,
		GRE:          "off",
		SIT:          "off",
		AntiFreeze:   onOff(best.AntiFreeze),
		Mux:          muxMode,
		MuxLinks:     muxLinks,
		Pool:         curInfo.PoolSize,
	}

	ev.Candidate = best.ID
	ev.Score = best.Score
	ev.ToDesc = describeCandidate(best)

	relayName := ah.p.serverName(relayID)
	foreignName := ah.p.serverName(foreignID)

	if err := switchBothHalves(ctx, ah.p.callJSON, say, name, relayID, foreignID, relayName, foreignName, ev.ToDesc, linkPort, spec); err != nil {
		return err
	}

	say("Tunnel %q switched from [%s] to [%s] (Score %d/100) and is now running on both servers!", name, ev.FromDesc, ev.ToDesc, best.Score)
	ah.p.refreshOne(relayID)
	ah.p.refreshOne(foreignID)
	return nil
}

func describeCandidate(c engine.ProbeCandidateResult) string {
	dir := strings.ToUpper(c.Mode)
	tr := strings.ToUpper(c.Transport)
	if c.CDN {
		tr += " (CDN)"
	} else if c.IPSpoof {
		tr += " (IP Spoof)"
	} else if c.AntiFreeze {
		tr += " (Split-Stream)"
	} else if c.SNISpoof {
		tr += " (SNI Spoof)"
	} else if c.WebHeader {
		tr += " (HTTP)"
	} else if c.Stealth {
		tr += " (Stealth)"
	}
	fam := "IPv4"
	if c.IPv6 {
		fam = "IPv6"
	}
	return fmt.Sprintf("%s · %s · %s", dir, tr, fam)
}

func init() {
	// Ensure slices package is referenced.
	_ = slices.Equal[[]string]
}
