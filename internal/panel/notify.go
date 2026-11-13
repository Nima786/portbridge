package panel

// Iran-safe Telegram Bot and Webhook (Discord / Slack / Custom) notifications.
//
// Panels hosted on Iran Relay servers frequently cannot reach api.telegram.org,
// discord.com, or hooks.slack.com directly due to ISP filtering or DNS poisoning.
// Whenever a direct HTTPS attempt fails, notifier automatically dials TCP+TLS
// end-to-end through an online Foreign server's authenticated /api/net/* jump
// proxy so DNS resolution happens outside Iran while TLS remains encrypted all
// the way from the panel to Telegram/Discord/Slack.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultTelegramBaseURL = "https://api.telegram.org"
	serverOfflineThreshold = 2
	failoverAlertCooldown  = 30 * time.Minute
)

// NotifyView is the safe representation returned to the browser (never exposes raw tokens/URLs).
type NotifyView struct {
	Enabled          bool   `json:"enabled"`
	HasTelegramToken bool   `json:"has_telegram_token"`
	TelegramHint     string `json:"telegram_hint,omitempty"`
	TelegramChatID   string `json:"telegram_chat_id,omitempty"`
	HasWebhookURL    bool   `json:"has_webhook_url"`
	WebhookHint      string `json:"webhook_hint,omitempty"`
	OnServerOffline  bool   `json:"on_server_offline"`
	OnTunnelFailover bool   `json:"on_tunnel_failover"`
	OnTrafficQuota   bool   `json:"on_traffic_quota"`
	LastSentAt       string `json:"last_sent_at,omitempty"`
	LastRoute        string `json:"last_route,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

type saveNotifyRequest struct {
	Enabled            bool   `json:"enabled"`
	TelegramToken      string `json:"telegram_token"`
	ClearTelegramToken bool   `json:"clear_telegram_token"`
	TelegramChatID     string `json:"telegram_chat_id"`
	WebhookURL         string `json:"webhook_url"`
	ClearWebhookURL    bool   `json:"clear_webhook_url"`
	OnServerOffline    bool   `json:"on_server_offline"`
	OnTunnelFailover   bool   `json:"on_tunnel_failover"`
	OnTrafficQuota     bool   `json:"on_traffic_quota"`
}

type testNotifyRequest struct {
	TelegramToken  string `json:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id"`
	WebhookURL     string `json:"webhook_url"`
}

type serverNotifyState struct {
	failCount      int
	alertedOffline bool
	name           string
	address        string
}

type notifier struct {
	p *Panel

	mu               sync.Mutex
	bootstrapped     bool
	srvState         map[string]*serverNotifyState
	failoverCooldown map[string]time.Time
	lastSentAt       string
	lastRoute        string
	lastError        string

	// Hooks for unit testing.
	telegramBaseURL   string
	directDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	tlsConfig         *tls.Config
}

func newNotifier(p *Panel) *notifier {
	return &notifier{
		p:                p,
		srvState:         map[string]*serverNotifyState{},
		failoverCooldown: map[string]time.Time{},
		telegramBaseURL:  defaultTelegramBaseURL,
	}
}

func secretHint(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

func webhookHintOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return secretHint(raw)
	}
	tail := ""
	if len(u.Path) >= 4 {
		tail = u.Path[len(u.Path)-4:]
	}
	if tail != "" {
		return u.Host + "/••••" + tail
	}
	return u.Host
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("enter a valid webhook URL (https://...)")
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if scheme != "https" {
		if scheme == "http" && isLoopbackHost(host) {
			return nil
		}
		return errors.New("the webhook URL must use https://")
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return errors.New("the webhook URL cannot point to a private or link-local IP address")
		}
	}
	return nil
}

func validateTelegramToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if len(tok) < 10 || len(tok) > 256 || !strings.Contains(tok, ":") {
		return errors.New("that does not look like a Telegram Bot Token (expected format like 123456789:ABCdef...)")
	}
	return nil
}

func (n *notifier) view() NotifyView {
	cfg := n.p.store.get().Notify
	n.mu.Lock()
	defer n.mu.Unlock()
	return NotifyView{
		Enabled:          cfg.Enabled,
		HasTelegramToken: cfg.TelegramTokenEnc != "",
		TelegramHint:     cfg.TelegramHint,
		TelegramChatID:   cfg.TelegramChatID,
		HasWebhookURL:    cfg.WebhookURLEnc != "",
		WebhookHint:      cfg.WebhookHint,
		OnServerOffline:  cfg.OnServerOffline,
		OnTunnelFailover: cfg.OnTunnelFailover,
		OnTrafficQuota:   cfg.OnTrafficQuota,
		LastSentAt:       n.lastSentAt,
		LastRoute:        n.lastRoute,
		LastError:        n.lastError,
	}
}

func (n *notifier) save(req saveNotifyRequest) (NotifyView, error) {
	cur := n.p.store.get().Notify
	tokEnc := cur.TelegramTokenEnc
	tokHint := cur.TelegramHint
	if req.ClearTelegramToken {
		tokEnc = ""
		tokHint = ""
	}
	if tok := strings.TrimSpace(req.TelegramToken); tok != "" {
		if err := validateTelegramToken(tok); err != nil {
			return NotifyView{}, err
		}
		enc, err := n.p.store.seal(tok)
		if err != nil {
			return NotifyView{}, fmt.Errorf("encrypting Telegram token: %w", err)
		}
		tokEnc = enc
		tokHint = secretHint(tok)
	}

	chatID := strings.TrimSpace(req.TelegramChatID)
	if len(chatID) > 128 {
		return NotifyView{}, errors.New("Telegram Chat ID is too long")
	}

	whEnc := cur.WebhookURLEnc
	whHint := cur.WebhookHint
	if req.ClearWebhookURL {
		whEnc = ""
		whHint = ""
	}
	if wh := strings.TrimSpace(req.WebhookURL); wh != "" {
		if err := validateWebhookURL(wh); err != nil {
			return NotifyView{}, err
		}
		enc, err := n.p.store.seal(wh)
		if err != nil {
			return NotifyView{}, fmt.Errorf("encrypting webhook URL: %w", err)
		}
		whEnc = enc
		whHint = webhookHintOf(wh)
	}

	hasTG := tokEnc != "" && chatID != ""
	hasWH := whEnc != ""
	if tokEnc != "" && chatID == "" && req.Enabled && !hasWH {
		return NotifyView{}, errors.New("enter your Telegram Chat ID (or Channel ID) alongside the Bot Token")
	}
	if req.Enabled && !hasTG && !hasWH {
		return NotifyView{}, errors.New("configure either a Telegram Bot Token + Chat ID or a Webhook URL before enabling alerts")
	}

	next := NotifyConfig{
		Enabled:          req.Enabled,
		TelegramTokenEnc: tokEnc,
		TelegramHint:     tokHint,
		TelegramChatID:   chatID,
		WebhookURLEnc:    whEnc,
		WebhookHint:      whHint,
		OnServerOffline:  req.OnServerOffline,
		OnTunnelFailover: req.OnTunnelFailover,
		OnTrafficQuota:   req.OnTrafficQuota,
	}
	if err := n.p.store.update(func(st *State) error {
		st.Notify = next
		return nil
	}); err != nil {
		return NotifyView{}, err
	}
	return n.view(), nil
}

func (n *notifier) panelLabel() string {
	st := n.p.store.get()
	if st.ThisName != "" {
		return st.ThisName
	}
	if d := n.p.getConfig().Domain; d != "" {
		return d
	}
	return "PortBridge Panel"
}

func (n *notifier) sendTest(ctx context.Context, req testNotifyRequest) (string, error) {
	cfg := n.p.store.get().Notify
	tgToken := strings.TrimSpace(req.TelegramToken)
	if tgToken != "" {
		if err := validateTelegramToken(tgToken); err != nil {
			return "", err
		}
	} else if cfg.TelegramTokenEnc != "" {
		if t, err := n.p.store.open(cfg.TelegramTokenEnc); err == nil {
			tgToken = t
		}
	}
	chatID := strings.TrimSpace(req.TelegramChatID)
	if chatID == "" {
		chatID = cfg.TelegramChatID
	}

	whURL := strings.TrimSpace(req.WebhookURL)
	if whURL != "" {
		if err := validateWebhookURL(whURL); err != nil {
			return "", err
		}
	} else if cfg.WebhookURLEnc != "" {
		if u, err := n.p.store.open(cfg.WebhookURLEnc); err == nil {
			whURL = u
		}
	}

	hasTG := tgToken != "" && chatID != ""
	hasWH := whURL != ""
	if !hasTG && !hasWH {
		if tgToken != "" && chatID == "" {
			return "", errors.New("enter your Telegram Chat ID to send a test alert")
		}
		return "", errors.New("enter a Telegram Bot Token + Chat ID or a Webhook URL first")
	}

	msg := fmt.Sprintf("✅ PortBridge Test Alert\nPanel: %s\nTime: %s\nNotifications are active and reachable.",
		n.panelLabel(), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	return n.deliver(ctx, tgToken, chatID, whURL, "test", "PortBridge Test Alert", msg)
}

func (n *notifier) dispatchAsync(eventType, title, body string) {
	cfg := n.p.store.get().Notify
	if !cfg.Enabled {
		return
	}
	var tgToken, whURL string
	if cfg.TelegramTokenEnc != "" && cfg.TelegramChatID != "" {
		if t, err := n.p.store.open(cfg.TelegramTokenEnc); err == nil {
			tgToken = t
		}
	}
	if cfg.WebhookURLEnc != "" {
		if u, err := n.p.store.open(cfg.WebhookURLEnc); err == nil {
			whURL = u
		}
	}
	if tgToken == "" && whURL == "" {
		return
	}
	chatID := cfg.TelegramChatID
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if _, err := n.deliver(ctx, tgToken, chatID, whURL, eventType, title, body); err != nil {
			logf("[notify] %s delivery failed: %v", eventType, err)
		}
	}()
}

func (n *notifier) deliver(ctx context.Context, tgToken, chatID, whURL, eventType, title, text string) (string, error) {
	var routes []string
	var errs []string

	if tgToken != "" && chatID != "" {
		route, err := n.sendTelegram(ctx, tgToken, chatID, text)
		if err != nil {
			errs = append(errs, "Telegram: "+err.Error())
		} else {
			routes = append(routes, "Telegram ("+route+")")
		}
	}
	if whURL != "" {
		route, err := n.sendWebhook(ctx, whURL, eventType, title, text)
		if err != nil {
			errs = append(errs, "Webhook: "+err.Error())
		} else {
			routes = append(routes, "Webhook ("+route+")")
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	routeSummary := strings.Join(routes, ", ")
	errSummary := strings.Join(errs, "; ")

	n.mu.Lock()
	if routeSummary != "" {
		n.lastSentAt = nowStr
		n.lastRoute = routeSummary
	}
	n.lastError = errSummary
	n.mu.Unlock()

	if len(errs) > 0 {
		return routeSummary, errors.New(errSummary)
	}
	return routeSummary, nil
}

func (n *notifier) sendTelegram(ctx context.Context, token, chatID, text string) (string, error) {
	base := strings.TrimRight(n.telegramBaseURL, "/")
	if base == "" {
		base = defaultTelegramBaseURL
	}
	endpoint := base + "/bot" + token + "/sendMessage"
	payload, err := json.Marshal(map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"disable_web_page_preview": true,
	})
	if err != nil {
		return "", err
	}
	return n.sendHTTPWithForeignFallback(ctx, endpoint, payload, true)
}

func (n *notifier) sendWebhook(ctx context.Context, whURL, eventType, title, text string) (string, error) {
	u, err := url.Parse(whURL)
	if err != nil {
		return "", errors.New("invalid webhook URL")
	}
	host := strings.ToLower(u.Hostname())
	var bodyObj map[string]any
	if strings.Contains(host, "discord.com") || strings.Contains(host, "discordapp.com") {
		bodyObj = map[string]any{
			"username": "PortBridge",
			"content":  text,
		}
	} else {
		bodyObj = map[string]any{
			"text":      text,
			"content":   text,
			"event":     eventType,
			"title":     title,
			"panel":     n.panelLabel(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
	}
	payload, err := json.Marshal(bodyObj)
	if err != nil {
		return "", err
	}
	return n.sendHTTPWithForeignFallback(ctx, whURL, payload, false)
}

func (n *notifier) cloneTLSConfig() *tls.Config {
	if n.tlsConfig != nil {
		return n.tlsConfig.Clone()
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

type permanentNotifyError struct {
	msg string
}

func (e permanentNotifyError) Error() string { return e.msg }

func (n *notifier) doJSONPost(ctx context.Context, client *http.Client, targetURL string, payload []byte, isTelegram bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return permanentNotifyError{err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PortBridge-Notify/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	if isTelegram {
		var tgResp struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		if json.Unmarshal(raw, &tgResp) == nil {
			if tgResp.OK && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			if tgResp.Description != "" {
				return permanentNotifyError{tgResp.Description}
			}
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// HTTP 451 or non-Telegram HTML block pages on plain/intercepted routes may be retried via Foreign jump.
	if resp.StatusCode == http.StatusUnavailableForLegalReasons {
		return fmt.Errorf("HTTP %d blocked", resp.StatusCode)
	}
	snippet := strings.TrimSpace(string(raw))
	if len(snippet) > 160 {
		snippet = snippet[:160] + "..."
	}
	if snippet != "" {
		return permanentNotifyError{fmt.Sprintf("HTTP %d: %s", resp.StatusCode, snippet)}
	}
	return permanentNotifyError{fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

func (n *notifier) jumpCandidates() []Server {
	servers := n.p.store.get().Servers
	var foreign, others []Server
	for _, s := range servers {
		if s.ID == "" || s.ID == "this" {
			continue
		}
		v, ok := n.p.viewOf(s.ID)
		if !ok || !v.Online {
			continue
		}
		if s.Group == GroupForeign {
			foreign = append(foreign, s)
		} else {
			others = append(others, s)
		}
	}
	return append(foreign, others...)
}

func (n *notifier) sendHTTPWithForeignFallback(ctx context.Context, targetURL string, payload []byte, isTelegram bool) (string, error) {
	// 1. Try direct egress from the panel host first.
	dialFn := n.directDialContext
	if dialFn == nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		dialFn = d.DialContext
	}
	directTr := &http.Transport{
		DialContext:         dialFn,
		TLSClientConfig:     n.cloneTLSConfig(),
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	}
	directClient := &http.Client{Transport: directTr}
	dctx, dcancel := context.WithTimeout(ctx, 7*time.Second)
	directErr := n.doJSONPost(dctx, directClient, targetURL, payload, isTelegram)
	dcancel()
	directTr.CloseIdleConnections()

	if directErr == nil {
		return "Direct", nil
	}
	var perm permanentNotifyError
	if errors.As(directErr, &perm) {
		return "", directErr
	}

	// 2. Direct egress failed (e.g. api.telegram.org or Discord blocked on Iran Relay).
	// Fall back through online Foreign servers using authenticated /api/net/* TCP jump
	// with end-to-end TLS from this panel.
	u, uerr := url.Parse(targetURL)
	if uerr == nil && isLoopbackHost(u.Hostname()) && n.directDialContext == nil {
		return "", directErr
	}

	candidates := n.jumpCandidates()
	lastErr := directErr
	for _, srv := range candidates {
		if ctx.Err() != nil {
			break
		}
		jumpSrv := srv
		jumpTr := &http.Transport{
			DialContext: func(jctx context.Context, _, addr string) (net.Conn, error) {
				return dialViaAgent(jctx, n.p, jumpSrv, addr, 8*time.Second)
			},
			TLSClientConfig:     n.cloneTLSConfig(),
			TLSHandshakeTimeout: 8 * time.Second,
			DisableKeepAlives:   true,
		}
		jumpClient := &http.Client{Transport: jumpTr}
		jctx, jcancel := context.WithTimeout(ctx, 14*time.Second)
		err := n.doJSONPost(jctx, jumpClient, targetURL, payload, isTelegram)
		jcancel()
		jumpTr.CloseIdleConnections()

		if err == nil {
			label := jumpSrv.Name
			if label == "" {
				label = jumpSrv.Address
			}
			if jumpSrv.Group == GroupForeign {
				return "via Foreign server " + label, nil
			}
			return "via " + label, nil
		}
		if errors.As(err, &perm) {
			return "", err
		}
		lastErr = err
	}
	return "", lastErr
}

// observeServers checks the latest server views for Offline / Recovered transitions.
func (n *notifier) observeServers(views []serverView) {
	cfg := n.p.store.get().Notify
	type pendingAlert struct {
		event string
		title string
		body  string
	}
	var alerts []pendingAlert

	n.mu.Lock()
	firstPass := !n.bootstrapped
	n.bootstrapped = true
	seen := map[string]bool{}
	for _, v := range views {
		if v.This || v.ID == "" || v.ID == "this" {
			continue
		}
		seen[v.ID] = true
		st := n.srvState[v.ID]
		if st == nil {
			st = &serverNotifyState{name: v.Name, address: v.Address}
			n.srvState[v.ID] = st
			if firstPass && !v.Online {
				// Server was already offline when the panel booted; record it
				// without firing a startup alert, and notify when it recovers.
				st.failCount = serverOfflineThreshold
				st.alertedOffline = true
				continue
			}
		}
		if v.Name != "" {
			st.name = v.Name
		}
		if v.Address != "" {
			st.address = v.Address
		}

		if v.Online {
			wasAlerted := st.alertedOffline
			st.failCount = 0
			st.alertedOffline = false
			if wasAlerted && cfg.Enabled && cfg.OnServerOffline {
				alerts = append(alerts, pendingAlert{
					event: "server_recovered",
					title: "Server Recovered: " + st.name,
					body: fmt.Sprintf("🟢 Server Recovered\nServer: %s (%s)\nGroup: %s\nPanel: %s",
						st.name, st.address, strings.ToUpper(v.Group), n.panelLabel()),
				})
			}
		} else {
			st.failCount++
			if st.failCount >= serverOfflineThreshold && !st.alertedOffline {
				st.alertedOffline = true
				if cfg.Enabled && cfg.OnServerOffline {
					prob := strings.TrimSpace(v.Problem)
					if prob == "" {
						prob = "Did not answer in time"
					}
					alerts = append(alerts, pendingAlert{
						event: "server_offline",
						title: "Server Offline: " + st.name,
						body: fmt.Sprintf("🔴 Server Offline\nServer: %s (%s)\nGroup: %s\nReason: %s\nPanel: %s",
							st.name, st.address, strings.ToUpper(v.Group), prob, n.panelLabel()),
					})
				}
			}
		}
	}
	for id := range n.srvState {
		if !seen[id] {
			delete(n.srvState, id)
		}
	}
	n.mu.Unlock()

	for _, a := range alerts {
		n.dispatchAsync(a.event, a.title, a.body)
	}
}

func (n *notifier) notifyFailover(tunnelName, fromDesc, toDesc, reason string, ok bool, errMsg string) {
	cfg := n.p.store.get().Notify
	if !cfg.Enabled || !cfg.OnTunnelFailover {
		return
	}
	if ok {
		n.mu.Lock()
		delete(n.failoverCooldown, tunnelName)
		n.mu.Unlock()
		body := fmt.Sprintf("⚡ Tunnel Auto-Healed\nTunnel: %s\nSwitched: %s -> %s\nTrigger: %s\nPanel: %s",
			tunnelName, fromDesc, toDesc, reason, n.panelLabel())
		n.dispatchAsync("tunnel_failover", "Tunnel Auto-Healed: "+tunnelName, body)
		return
	}
	n.mu.Lock()
	now := time.Now()
	if last, has := n.failoverCooldown[tunnelName]; has && now.Sub(last) < failoverAlertCooldown {
		n.mu.Unlock()
		return
	}
	n.failoverCooldown[tunnelName] = now
	n.mu.Unlock()

	body := fmt.Sprintf("🚨 Tunnel Failover Failed\nTunnel: %s\nPrevious Mode: %s\nReason: %s\nError: %s\nPanel: %s",
		tunnelName, fromDesc, reason, errMsg, n.panelLabel())
	n.dispatchAsync("tunnel_blocked", "Tunnel Blocked: "+tunnelName, body)
}

func (n *notifier) notifyQuota(tunnelName string, pct int, usedGB, quotaGB float64, paused bool) {
	cfg := n.p.store.get().Notify
	if !cfg.Enabled || !cfg.OnTrafficQuota {
		return
	}
	if pct >= 100 {
		actionLine := "Status: Over monthly cap (Auto-Pause is off)"
		if paused {
			actionLine = "Action: Tunnel automatically paused until next month or quota increase"
		}
		body := fmt.Sprintf("🛑 Monthly Traffic Quota Reached (100%%)\nTunnel: %s\nUsed: %.2f GB / %.2f GB\n%s\nPanel: %s",
			tunnelName, usedGB, quotaGB, actionLine, n.panelLabel())
		n.dispatchAsync("quota_exceeded", "Quota Reached: "+tunnelName, body)
		return
	}
	body := fmt.Sprintf("⚠️ Monthly Traffic Quota Warning (80%%)\nTunnel: %s\nUsed: %.2f GB / %.2f GB (%.0f%%)\nPanel: %s",
		tunnelName, usedGB, quotaGB, (usedGB/quotaGB)*100, n.panelLabel())
	n.dispatchAsync("quota_warning", "Quota Warning: "+tunnelName, body)
}
