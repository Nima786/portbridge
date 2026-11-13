package panel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
	"github.com/Nima786/portbridge/internal/engine"
)

type cfScanPanelRequest struct {
	Relay      string   `json:"relay"`
	Foreign    string   `json:"foreign"`
	Tunnel     string   `json:"tunnel,omitempty"`
	Domain     string   `json:"domain"`
	Port       int      `json:"port,omitempty"`
	Transport  string   `json:"transport,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	MaxSelect  int      `json:"max_select,omitempty"`
}

type cfScanAgentReply struct {
	OK     bool                 `json:"ok"`
	Report *engine.CFScanReport `json:"report"`
	Error  string               `json:"error"`
}

func isCDNCapablePort(port int) bool {
	return slices.Contains(engine.CDNHTTPSPorts, port)
}

func isDirectCDNTransport(tr string) bool {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "wss", "xhttp", "grpc", "h3":
		return true
	default:
		return false
	}
}

func allLoopbackCandidates(raw []string) bool {
	if len(raw) == 0 {
		return false
	}
	found := false
	for _, s := range raw {
		for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			if h, _, err := net.SplitHostPort(tok); err == nil && h != "" {
				tok = h
			}
			ip := net.ParseIP(strings.Trim(tok, "[]"))
			if ip == nil || !ip.IsLoopback() {
				return false
			}
			found = true
		}
	}
	return found
}

func normalisePanelCDNTransport(tr string) string {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "xhttp", "xhttp-cdn", "asymmetric-cdn":
		return "xhttp"
	case "grpc", "grpc-cdn":
		return "grpc"
	case "h3", "h3-cdn":
		return "h3"
	case "wss", "cdn", "website-cdn-backup", "":
		return "wss"
	default:
		return "wss"
	}
}

// canReuseLiveOriginForCFScan checks whether tunnelName has a running Foreign
// Origin listener on foreignID that speaks a Direct non-Asymmetric CDN transport
// on one of Cloudflare's HTTPS ports (or loopback in tests) matching the requested
// transport/port, allowing zero-conflict live Clean-IP scanning without opening a
// temporary ProbeListener.
func (p *Panel) canReuseLiveOriginForCFScan(relayID, foreignID, tunnelName, reqTransport string, reqPort int, loopback bool) (port int, transport string, ok bool) {
	tunnelName = strings.TrimSpace(tunnelName)
	if tunnelName == "" {
		return 0, "", false
	}
	rv, rok := p.viewOf(relayID)
	fv, fok := p.viewOf(foreignID)
	if !rok || !fok || rv.Overview == nil || fv.Overview == nil {
		return 0, "", false
	}
	var ei, oi *agent.TunnelInfo
	for i := range rv.Overview.Tunnels {
		t := &rv.Overview.Tunnels[i]
		if t.Name == tunnelName && t.Role == "edge" {
			ei = t
			break
		}
	}
	for i := range fv.Overview.Tunnels {
		t := &fv.Overview.Tunnels[i]
		if t.Name == tunnelName && t.Role == "origin" {
			oi = t
			break
		}
	}
	if ei == nil || oi == nil || !oi.Running {
		return 0, "", false
	}
	if oi.Mode != "direct" || oi.Asymmetric || oi.GRE || oi.SIT || oi.RealSite {
		return 0, "", false
	}
	if ei.PairID != "" && oi.PairID != "" && ei.PairID != oi.PairID {
		return 0, "", false
	}
	if !isDirectCDNTransport(oi.Transport) {
		return 0, "", false
	}
	if !loopback && !isCDNCapablePort(oi.LinkPort) {
		return 0, "", false
	}
	if reqPort > 0 && reqPort != oi.LinkPort {
		return 0, "", false
	}
	if reqTransport != "" {
		wantTr := normalisePanelCDNTransport(reqTransport)
		if wantTr != oi.Transport {
			return 0, "", false
		}
	}
	return oi.LinkPort, oi.Transport, true
}

func (p *Panel) scanCloudflareCleanIPs(parent context.Context, req cfScanPanelRequest) (*engine.CFScanReport, error) {
	relayID := strings.TrimSpace(req.Relay)
	foreignID := strings.TrimSpace(req.Foreign)
	rv, rok := p.viewOf(relayID)
	fv, fok := p.viewOf(foreignID)
	if !rok || !fok {
		return nil, errors.New("select both the Relay (Iran) and Foreign servers first")
	}
	if !rv.Online {
		return nil, fmt.Errorf("Relay server %s is currently offline", rv.Name)
	}
	if !fv.Online {
		return nil, fmt.Errorf("Foreign server %s is currently offline", fv.Name)
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" && strings.TrimSpace(req.Tunnel) != "" && rv.Overview != nil {
		for _, t := range rv.Overview.Tunnels {
			if t.Name == strings.TrimSpace(req.Tunnel) {
				domain = extractTunnelCDNDomain(t)
				break
			}
		}
	}
	if domain == "" || !engine.HostnameRe.MatchString(domain) {
		return nil, errors.New("enter your Cloudflare-proxied subdomain first (e.g. edge1.example.com)")
	}

	loopback := allLoopbackCandidates(req.Candidates)
	maxSelect := req.MaxSelect
	if maxSelect <= 0 {
		maxSelect = 5
	}

	// Fast path: reuse the live Foreign Origin tunnel if it is already listening
	// on a compatible Direct CDN transport and Cloudflare HTTPS port.
	if livePort, liveTr, ok := p.canReuseLiveOriginForCFScan(relayID, foreignID, req.Tunnel, req.Transport, req.Port, loopback); ok {
		sctx, cancel := context.WithTimeout(parent, 90*time.Second)
		defer cancel()
		var rep cfScanAgentReply
		_, err := p.callJSON(sctx, relayID, "/api/probe/cf-scan", map[string]any{
			"tunnel_name": strings.TrimSpace(req.Tunnel),
			"domain":      domain,
			"port":        livePort,
			"transport":   liveTr,
			"candidates":  req.Candidates,
			"max_select":  maxSelect,
		}, &rep)
		if errors.Is(err, errTooOld) {
			return nil, fmt.Errorf("PortBridge on %s needs to be updated to v0.17.67+ to scan Clean IPs", rv.Name)
		}
		if err != nil {
			return nil, fmt.Errorf("%s could not run Clean-IP scan: %s", rv.Name, plainAgentError(err))
		}
		if !rep.OK || rep.Report == nil {
			if rep.Error != "" {
				return nil, errors.New(rep.Error)
			}
			return nil, errors.New("Clean-IP scan failed")
		}
		return rep.Report, nil
	}

	// Ephemeral path: open a temporary ProbeListener on Foreign on one of
	// Cloudflare's 6 Orange-Cloud HTTPS ports (preferring req.Port or 2053).
	prefPort := 2053
	if req.Port > 0 && (isCDNCapablePort(req.Port) || loopback) {
		prefPort = req.Port
	}
	lctx, lcancel := context.WithTimeout(parent, 15*time.Second)
	var lrep probeListenReply
	_, lerr := p.callJSON(lctx, foreignID, "/api/probe/listen", map[string]any{
		"preferred_port": prefPort,
	}, &lrep)
	lcancel()
	if errors.Is(lerr, errTooOld) {
		return nil, fmt.Errorf("PortBridge on %s needs to be updated before running Clean-IP scans", fv.Name)
	}
	if lerr != nil {
		return nil, fmt.Errorf("could not open temporary Cloudflare test listener on %s: %s", fv.Name, plainAgentError(lerr))
	}
	if !lrep.OK || lrep.Port <= 0 || lrep.Secret == "" {
		msg := lrep.Error
		if msg == "" {
			msg = "probe listener did not start"
		}
		return nil, fmt.Errorf("could not open temporary Cloudflare test listener on %s: %s", fv.Name, msg)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		var dummy map[string]any
		_, _ = p.callJSON(stopCtx, foreignID, "/api/probe/stop", map[string]string{"id": lrep.ID}, &dummy)
	}()

	if !loopback && !isCDNCapablePort(lrep.Port) {
		return nil, fmt.Errorf(
			"all 6 Cloudflare HTTPS ports (443, 2053, 2083, 2087, 2096, 8443) are already occupied on %s; free one of them or run the scan from an active CDN tunnel's Diagnostics dialog",
			fv.Name,
		)
	}

	tr := normalisePanelCDNTransport(req.Transport)
	sctx, scancel := context.WithTimeout(parent, 90*time.Second)
	defer scancel()
	var rep cfScanAgentReply
	_, err := p.callJSON(sctx, relayID, "/api/probe/cf-scan", map[string]any{
		"domain":     domain,
		"port":       lrep.Port,
		"transport":  tr,
		"secret":     lrep.Secret,
		"candidates": req.Candidates,
		"max_select": maxSelect,
	}, &rep)
	if errors.Is(err, errTooOld) {
		return nil, fmt.Errorf("PortBridge on %s needs to be updated to v0.17.67+ to scan Clean IPs", rv.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s could not run Clean-IP scan: %s", rv.Name, plainAgentError(err))
	}
	if !rep.OK || rep.Report == nil {
		if rep.Error != "" {
			return nil, errors.New(rep.Error)
		}
		return nil, errors.New("Clean-IP scan failed")
	}
	if req.Port > 0 && lrep.Port != req.Port {
		rep.Report.Notes = append(rep.Report.Notes, fmt.Sprintf(
			"Port %d was busy on %s, so the end-to-end test used Cloudflare HTTPS port %d.",
			req.Port, fv.Name, lrep.Port,
		))
	}
	return rep.Report, nil
}

func normaliseCleanIPList(rawCSV string, rawList []string) ([]string, error) {
	var items []string
	if strings.TrimSpace(rawCSV) != "" {
		items = append(items, strings.Split(rawCSV, ",")...)
	}
	for _, s := range rawList {
		items = append(items, strings.Split(s, ",")...)
	}
	var out []string
	seen := map[string]bool{}
	for _, it := range items {
		ip := strings.TrimSpace(it)
		if ip == "" {
			continue
		}
		if err := engine.CheckCleanIP(ip); err != nil {
			return nil, fmt.Errorf("clean addresses: %w", err)
		}
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out, nil
}

func (p *Panel) applyTunnelCleanIPs(parent context.Context, edgeID, tunnelName string, cleanIPs []string) ([]string, error) {
	if p.healer != nil {
		defer p.healer.lockServers(strings.TrimSpace(edgeID))()
	}
	return p.applyTunnelCleanIPsLocked(parent, edgeID, tunnelName, cleanIPs)
}

func (p *Panel) applyTunnelCleanIPsLocked(parent context.Context, edgeID, tunnelName string, cleanIPs []string) ([]string, error) {
	edgeID = strings.TrimSpace(edgeID)
	tunnelName = strings.TrimSpace(tunnelName)
	if err := checkTunnelName(tunnelName); err != nil {
		return nil, err
	}
	ev, ok := p.viewOf(edgeID)
	if !ok {
		return nil, errors.New("that Relay server is not in the panel")
	}
	if !ev.Online {
		return nil, fmt.Errorf("Relay server %s is currently offline", ev.Name)
	}
	cleaned, err := normaliseCleanIPList("", cleanIPs)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(parent, tunnelOpTimeout)
	defer cancel()
	var res agent.EdgeResult
	status, err := p.callJSON(ctx, edgeID, "/api/tunnel/edit-edge", agent.EditSpec{
		Name:           tunnelName,
		CleanIPs:       strings.Join(cleaned, ", "),
		UpdateCleanIPs: true,
	}, &res)
	if errors.Is(err, errTooOld) {
		return nil, fmt.Errorf("PortBridge on %s needs to be updated to v0.17.67+ to update Clean IPs", ev.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s could not be reached: %s", ev.Name, plainAgentError(err))
	}
	if !res.OK {
		if res.Error == "" {
			res.Error = fmt.Sprintf("HTTP %d", status)
		}
		return nil, fmt.Errorf("%s refused the change: %s", ev.Name, res.Error)
	}
	p.refreshOne(edgeID)
	return cleaned, nil
}

func (p *Panel) handleProbeCFScan(w http.ResponseWriter, r *http.Request, _ authed) {
	agent.ExtendDeadlines(w, 4*time.Minute)
	var req cfScanPanelRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	rep, err := p.scanCloudflareCleanIPs(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, capitalise(plainAgentError(err))+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "report": rep})
}

func (p *Panel) handleSetTunnelCleanIPs(w http.ResponseWriter, r *http.Request, _ authed) {
	var req struct {
		Name        string   `json:"name"`
		Edge        string   `json:"edge"`
		CleanIPs    string   `json:"clean_ips"`
		CleanIPList []string `json:"clean_ip_list"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	parsed, err := normaliseCleanIPList(req.CleanIPs, req.CleanIPList)
	if err != nil {
		writeErr(w, http.StatusBadRequest, capitalise(err.Error())+".")
		return
	}
	applied, err := p.applyTunnelCleanIPs(r.Context(), req.Edge, req.Name, parsed)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, capitalise(plainAgentError(err))+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "clean_ips": applied})
}
