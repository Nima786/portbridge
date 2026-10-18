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
)

type tunnelHealRuntime struct {
	state     string
	failCount int
	lastCheck time.Time
	lastHeal  time.Time
	lastNote  string
	running   bool
}

type autoHealer struct {
	p  *Panel
	mu sync.Mutex
	rt map[string]*tunnelHealRuntime
}

func newAutoHealer(p *Panel) *autoHealer {
	return &autoHealer{
		p:  p,
		rt: map[string]*tunnelHealRuntime{},
	}
}

func (ah *autoHealer) runtimeOf(name string) *tunnelHealRuntime {
	r := ah.rt[name]
	if r == nil {
		r = &tunnelHealRuntime{state: "monitoring"}
		ah.rt[name] = r
	}
	return r
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
	ah.mu.Lock()
	defer ah.mu.Unlock()
	for i := range tunnels {
		name := tunnels[i].Name
		cfg := st.AutoHeal[name]
		if cfg.CDNDomain == "" && tunnels[i].Edge != nil {
			if dom := extractTunnelCDNDomain(tunnels[i].Edge.Info); dom != "" {
				cfg.CDNDomain = dom
			}
		}
		if r := ah.rt[name]; r != nil {
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
func (ah *autoHealer) setConfig(name string, enabled bool, cdnDomain string) error {
	cdnDomain = strings.TrimSpace(cdnDomain)
	if cdnDomain != "" && !engine.HostnameRe.MatchString(cdnDomain) {
		return fmt.Errorf("%q is not a valid domain name", cdnDomain)
	}
	if cdnDomain == "" {
		for _, tv := range pairTunnels(ah.p.fleet.views()) {
			if tv.Name == name && tv.Edge != nil {
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
		c := st.AutoHeal[name]
		c.Enabled = enabled
		if cdnDomain != "" || !enabled {
			c.CDNDomain = cdnDomain
		}
		if enabled && c.State == "" {
			c.State = "monitoring"
		}
		st.AutoHeal[name] = c
		return nil
	})
	if err != nil {
		return err
	}
	ah.mu.Lock()
	r := ah.runtimeOf(name)
	if enabled {
		if !r.running {
			r.state = "monitoring"
		}
	} else {
		r.failCount = 0
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
	st := ah.p.store.get()
	if len(st.AutoHeal) == 0 {
		return
	}
	tunnels := pairTunnels(ah.p.fleet.views())
	for _, tv := range tunnels {
		cfg, ok := st.AutoHeal[tv.Name]
		if !ok || !cfg.Enabled {
			continue
		}
		if cfg.CDNDomain == "" && tv.Edge != nil {
			if dom := extractTunnelCDNDomain(tv.Edge.Info); dom != "" {
				cfg.CDNDomain = dom
				_ = ah.p.store.update(func(s *State) error {
					c := s.AutoHeal[tv.Name]
					if c.CDNDomain == "" {
						c.CDNDomain = dom
						s.AutoHeal[tv.Name] = c
					}
					return nil
				})
			}
		}
		ah.evaluateTunnel(ctx, tv, cfg)
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

func (ah *autoHealer) evaluateTunnel(ctx context.Context, tv tunnelView, cfg AutoHealConfig) {
	unhealthy, reason := tunnelUnhealthyReason(tv)
	now := time.Now()

	ah.mu.Lock()
	r := ah.runtimeOf(tv.Name)
	r.lastCheck = now
	if r.running {
		ah.mu.Unlock()
		return
	}
	if !unhealthy {
		r.failCount = 0
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

	r.running = true
	r.state = "probing"
	r.lastNote = "Benchmarking alternative tunnel modes..."
	ah.mu.Unlock()

	go func() {
		hctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		_ = ah.healTunnel(hctx, nil, tv.Name, tv.Edge.ServerID, tv.Origin.ServerID, cfg.CDNDomain, reason, false)
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
	if cdnDomain == "" {
		st := ah.p.store.get()
		cdnDomain = st.AutoHeal[name].CDNDomain
	}
	ah.mu.Lock()
	r := ah.runtimeOf(name)
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
		err := ah.healTunnel(ctx, j, name, edgeID, originID, cdnDomain, "manual trigger", true)
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
	if ti.CDN {
		tr += " (CDN)"
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

func (ah *autoHealer) healTunnel(ctx context.Context, j *job, name, relayID, foreignID, cdnDomain, reason string, force bool) (retErr error) {
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
		ah.mu.Lock()
		r := ah.runtimeOf(name)
		r.running = false
		r.lastCheck = time.Now()
		if retErr != nil {
			r.state = "error"
			r.lastNote = retErr.Error()
			ev.Success = false
			ev.Error = retErr.Error()
		} else {
			r.failCount = 0
			r.lastHeal = time.Now()
			r.state = "monitoring"
			r.lastNote = fmt.Sprintf("Switched to %s (Score %d/100)", ev.ToDesc, ev.Score)
			ev.Success = true
		}
		ah.mu.Unlock()

		if ev.FromDesc != "" || ev.Error != "" {
			_ = ah.p.store.update(func(st *State) error {
				if st.AutoHeal == nil {
					st.AutoHeal = map[string]AutoHealConfig{}
				}
				c := st.AutoHeal[name]
				c.LastHeal = ev.At
				c.LastNote = r.lastNote
				c.History = append([]AutoHealEvent{ev}, c.History...)
				if len(c.History) > 20 {
					c.History = c.History[:20]
				}
				st.AutoHeal[name] = c
				return nil
			})
		}
	}()

	// Refresh both servers first so we have fresh tunnel info and addresses.
	ah.p.refreshOne(relayID)
	ah.p.refreshOne(foreignID)

	var tv *tunnelView
	for _, item := range pairTunnels(ah.p.fleet.views()) {
		if item.Name == name {
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
				c := st.AutoHeal[name]
				if c.CDNDomain == "" {
					c.CDNDomain = dom
					st.AutoHeal[name] = c
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
	if r := ah.rt[name]; r != nil {
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
	if best.Transport == "kcp" {
		muxMode = "off"
	} else if !curInfo.Mux {
		muxMode = "off"
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

	spec := agent.EditSpec{
		Name:        name,
		Mode:        best.Mode,
		Transport:   best.Transport,
		LinkPort:    linkPort,
		PeerIP:      peerIP,
		LocalIP:     localIP,
		IPv6:        &ipv6Flag,
		ServerName:  serverName,
		CDN:         onOff(best.CDN),
		AltHost:     "",
		CleanIPs:    "",
		UTLS:        onOff(best.Stealth),
		TLSFragment: onOff(best.Stealth),
		HTTPHeader:  onOff(best.WebHeader),
		HTTPHost:    httpHost,
		RealSite:    onOff(realSite),
		GRE:         "off",
		Mux:         muxMode,
		MuxLinks:    max(1, curInfo.MuxLinks),
		Pool:        curInfo.PoolSize,
	}

	ev.Candidate = best.ID
	ev.Score = best.Score
	ev.ToDesc = describeCandidate(best)

	relayName := ah.p.serverName(relayID)
	foreignName := ah.p.serverName(foreignID)

	say("Preparing new configuration (%s on port %d) on %s...", ev.ToDesc, linkPort, relayName)
	spec.Stage = "prepare"
	var prep agent.EdgeResult
	status, err := ah.p.callJSON(ctx, relayID, "/api/tunnel/edit-edge", spec, &prep)
	if err != nil {
		return fmt.Errorf("%s could not prepare new mode: %s", relayName, plainAgentError(err))
	}
	if !prep.OK {
		if prep.Error == "" {
			prep.Error = fmt.Sprintf("HTTP %d", status)
		}
		return fmt.Errorf("%s rejected new mode: %s", relayName, prep.Error)
	}

	say("Applying new mode to %s (using active control channel)...", foreignName)
	var upd struct {
		OK       bool     `json:"ok"`
		Error    string   `json:"error"`
		Warnings []string `json:"warnings"`
	}
	_, uerr := ah.p.callJSON(ctx, foreignID, "/api/tunnel/update", map[string]string{"code": prep.Code}, &upd)
	if uerr == nil && !upd.OK {
		uerr = errors.New(upd.Error)
	}
	if uerr != nil {
		reason := plainAgentError(uerr)
		say("%s could not apply new mode (%s); rolling back %s...", foreignName, reason, relayName)
		var rb agent.EdgeResult
		_, _ = ah.p.callJSON(ctx, relayID, "/api/tunnel/edit-edge", agent.EditSpec{
			Name:    name,
			Stage:   "rollback",
			OldConf: prep.OldConf,
		}, &rb)
		return fmt.Errorf("%s could not switch modes: %s (rolled back cleanly)", foreignName, reason)
	}

	say("Committing firewall rules and restarting %s...", relayName)
	var commit agent.EdgeResult
	cstatus, cerr := ah.p.callJSON(ctx, relayID, "/api/tunnel/edit-edge", agent.EditSpec{
		Name:    name,
		Stage:   "commit",
		OldConf: prep.OldConf,
	}, &commit)
	if cerr != nil {
		return fmt.Errorf("%s could not finish restarting: %s", relayName, plainAgentError(cerr))
	}
	if !commit.OK {
		if commit.Error == "" {
			commit.Error = fmt.Sprintf("HTTP %d", cstatus)
		}
		return fmt.Errorf("%s could not restart on new mode: %s", relayName, commit.Error)
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
