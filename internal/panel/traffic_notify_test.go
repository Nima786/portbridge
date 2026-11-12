package panel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nima786/portbridge/internal/agent"
)

func TestTrafficTrackerMonotonicAcrossRestartsQuotasAndRollover(t *testing.T) {
	p, foreignID, _ := twoServers(t)

	curTime := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	p.traffic.nowFn = func() time.Time { return curTime }

	// Configure a 10 GB monthly cap with Auto-Pause enabled on tunnel "alpha".
	const gb = int64(1024 * 1024 * 1024)
	view, err := p.traffic.applyRequest(tunnelTrafficRequest{
		Name:      "alpha",
		Edge:      "this",
		Origin:    foreignID,
		Action:    "set_quota",
		QuotaGB:   10,
		AutoPause: true,
	})
	if err != nil {
		t.Fatalf("set_quota failed: %v", err)
	}
	if view.QuotaGB != 10 || !view.AutoPause {
		t.Fatalf("unexpected quota view: %+v", view)
	}

	makePair := func(pid int, started string, up, down, upBps, downBps int64) []tunnelView {
		return []tunnelView{{
			Name: "alpha",
			Edge: &half{
				ServerID:   "this",
				ServerName: "Iran-Relay",
				Info: agent.TunnelInfo{
					Name:    "alpha",
					Role:    "edge",
					Running: true,
					Live: &agent.TunnelLive{
						PID:       pid,
						StartedAt: started,
						BytesUp:   up,
						BytesDown: down,
						UpBps:     upBps,
						DownBps:   downBps,
					},
				},
			},
			Origin: &half{
				ServerID:   foreignID,
				ServerName: "Aeza",
				Info: agent.TunnelInfo{
					Name:    "alpha",
					Role:    "origin",
					Running: true,
					// Deliberately populate identical bytes on Origin to prove Edge+Origin never double-count!
					Live: &agent.TunnelLive{
						PID:       999,
						StartedAt: started,
						BytesUp:   up,
						BytesDown: down,
					},
				},
			},
		}}
	}

	// Sample 1: PID 1001 transfers 3 GB up + 2 GB down (= 5 GB, 50%).
	tunnels := makePair(1001, "2026-11-12T09:00:00Z", 3*gb, 2*gb, 1_500_000, 4_000_000)
	p.traffic.observeAndAttach(tunnels)
	if tunnels[0].Traffic == nil {
		t.Fatal("expected Traffic attached to tunnelView")
	}
	if got := tunnels[0].Traffic.TotalUp + tunnels[0].Traffic.TotalDown; got != 5*gb {
		t.Fatalf("after sample 1 got total=%d, want %d (must not double-count Origin)", got, 5*gb)
	}
	if tunnels[0].Traffic.UpBps != 1_500_000 || tunnels[0].Traffic.DownBps != 4_000_000 {
		t.Fatalf("unexpected live bps: %+v", tunnels[0].Traffic)
	}

	// Sample 2: Same PID 1001 grows to 4 GB up + 4.5 GB down (= 8.5 GB, crosses 80% warning!).
	tunnels = makePair(1001, "2026-11-12T09:00:00Z", 4*gb, int64(4.5*float64(gb)), 0, 0)
	p.traffic.observeAndAttach(tunnels)
	if got := tunnels[0].Traffic.MonthUp + tunnels[0].Traffic.MonthDown; got != int64(8.5*float64(gb)) {
		t.Fatalf("after sample 2 got month=%d, want %d", got, int64(8.5*float64(gb)))
	}
	if tunnels[0].Traffic.PausedByQuota {
		t.Fatal("should not pause at 85% of quota")
	}
	st := p.store.get()
	if st.Traffic["this/alpha"].Warned80Month != "2026-11" {
		t.Fatalf("expected Warned80Month=2026-11 persisted in store, got %+v", st.Traffic["this/alpha"])
	}

	// Simulate panel restart: reload from store while PID 1001 is still running with identical counters.
	p.traffic.reloadFromStore()
	tunnels = makePair(1001, "2026-11-12T09:00:00Z", 4*gb, int64(4.5*float64(gb)), 0, 0)
	p.traffic.observeAndAttach(tunnels)
	if got := tunnels[0].Traffic.TotalUp + tunnels[0].Traffic.TotalDown; got != int64(8.5*float64(gb)) {
		t.Fatalf("panel restart double-counted running PID: got %d, want %d", got, int64(8.5*float64(gb)))
	}

	// Sample 3: Tunnel restarted or switched transport (new PID 2002) and transfers 1 GB up + 1 GB down
	// -> cumulative month reaches 10.5 GB (>= 10 GB cap -> triggers PausedByQuota!).
	tunnels = makePair(2002, "2026-11-12T10:05:00Z", 1*gb, 1*gb, 0, 0)
	p.traffic.observeAndAttach(tunnels)
	if got := tunnels[0].Traffic.TotalUp + tunnels[0].Traffic.TotalDown; got != int64(10.5*float64(gb)) {
		t.Fatalf("after PID restart got total=%d, want %d", got, int64(10.5*float64(gb)))
	}
	if !tunnels[0].Traffic.PausedByQuota {
		t.Fatal("expected PausedByQuota=true at 105% of monthly cap")
	}

	// Advance calendar to December 2026: monthly usage rolls over to 0 and PausedByQuota clears automatically,
	// while lifetime TotalUp + TotalDown stays intact!
	curTime = time.Date(2026, 12, 1, 0, 1, 0, 0, time.UTC)
	tunnels = makePair(2002, "2026-11-12T10:05:00Z", 1*gb, 1*gb, 0, 0)
	p.traffic.observeAndAttach(tunnels)
	if tunnels[0].Traffic.MonthKey != "2026-12" {
		t.Fatalf("expected MonthKey=2026-12, got %q", tunnels[0].Traffic.MonthKey)
	}
	if tunnels[0].Traffic.MonthUp != 0 || tunnels[0].Traffic.MonthDown != 0 {
		t.Fatalf("expected monthly counters reset on new month, got %+v", tunnels[0].Traffic)
	}
	if tunnels[0].Traffic.PausedByQuota {
		t.Fatal("expected PausedByQuota cleared on monthly rollover")
	}
	if got := tunnels[0].Traffic.TotalUp + tunnels[0].Traffic.TotalDown; got != int64(10.5*float64(gb)) {
		t.Fatalf("lifetime total should survive monthly rollover: got %d, want %d", got, int64(10.5*float64(gb)))
	}

	// Reset counters: zeros lifetime and monthly counters without re-adding already-elapsed bytes of PID 2002.
	if _, err := p.traffic.applyRequest(tunnelTrafficRequest{
		Name:   "alpha",
		Edge:   "this",
		Origin: foreignID,
		Action: "reset",
		Scope:  "all",
	}); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	tunnels = makePair(2002, "2026-11-12T10:05:00Z", 1*gb, 1*gb, 0, 0)
	p.traffic.observeAndAttach(tunnels)
	if tunnels[0].Traffic.TotalUp != 0 || tunnels[0].Traffic.TotalDown != 0 {
		t.Fatalf("expected 0 after reset when PID counters unchanged, got %+v", tunnels[0].Traffic)
	}
	time.Sleep(80 * time.Millisecond)
}

func TestIranSafeTelegramNotificationFallsBackViaForeignServerJump(t *testing.T) {
	agent.SetAllowLoopbackNetProxyForTest(true)
	t.Cleanup(func() { agent.SetAllowLoopbackNetProxyForTest(false) })

	// Start a mock Telegram HTTPS Bot API server.
	var receivedChatID, receivedText string
	var mu sync.Mutex
	tgSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot123456789:TEST_SECRET_TOKEN_ABCD/sendMessage" {
			http.Error(w, "wrong bot token path: "+r.URL.Path, http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		receivedChatID = body.ChatID
		receivedText = body.Text
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42}}`))
	}))
	t.Cleanup(tgSrv.Close)

	p := newTestPanel(t)
	_ = p.store.update(func(s *State) error {
		s.ThisName = "Iran-Relay-Panel"
		s.ThisGroup = GroupRelay
		return nil
	})

	// Add an online Foreign server that provides /api/net/* jump proxy.
	const jumpTok = "pba_foreign_notify_jump"
	jumpTS, jumpFP := startPinnedMockAgent(t, jumpTok)
	jumpSrv := addTestServer(t, p, Server{
		ID:          "de1",
		Name:        "Germany-Exit",
		Group:       GroupForeign,
		Address:     "203.0.113.55",
		AgentURL:    jumpTS.URL,
		Fingerprint: jumpFP,
	}, jumpTok)
	p.fleet.refresh(jumpSrv)

	// Trust the test Telegram server's TLS certificate on the Panel so end-to-end TLS verification is tested!
	pool := x509.NewCertPool()
	pool.AddCert(tgSrv.Certificate())
	p.notifier.telegramBaseURL = tgSrv.URL
	p.notifier.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	// Simulate Iran ISP blocking direct TCP connections to api.telegram.org.
	var directTries atomic.Int32
	p.notifier.directDialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		directTries.Add(1)
		return nil, errors.New("dial tcp: i/o timeout (filtered in Iran)")
	}

	// Save encrypted notification settings and verify raw token is encrypted on disk.
	nv, err := p.notifier.save(saveNotifyRequest{
		Enabled:          true,
		TelegramToken:    "123456789:TEST_SECRET_TOKEN_ABCD",
		TelegramChatID:   "-100987654321",
		OnServerOffline:  true,
		OnTunnelFailover: true,
		OnTrafficQuota:   true,
	})
	if err != nil {
		t.Fatalf("save notify config: %v", err)
	}
	if !nv.HasTelegramToken || nv.TelegramHint != "••••ABCD" {
		t.Fatalf("unexpected notify view: %+v", nv)
	}
	st := p.store.get()
	if strings.Contains(st.Notify.TelegramTokenEnc, "TEST_SECRET_TOKEN") {
		t.Fatal("Telegram bot token was stored in plaintext instead of AES-GCM encrypted!")
	}

	// Send Test Alert: direct dial fails, so notifier jumps end-to-end TLS via Germany-Exit!
	route, err := p.notifier.sendTest(context.Background(), testNotifyRequest{})
	if err != nil {
		t.Fatalf("sendTest via Foreign server jump failed: %v", err)
	}
	if directTries.Load() == 0 {
		t.Fatal("expected direct dial to be attempted first")
	}
	if !strings.Contains(route, "via Foreign server Germany-Exit") {
		t.Fatalf("expected delivery route via Foreign server Germany-Exit, got %q", route)
	}

	mu.Lock()
	gotChat, gotText := receivedChatID, receivedText
	mu.Unlock()
	if gotChat != "-100987654321" || !strings.Contains(gotText, "Iran-Relay-Panel") {
		t.Fatalf("unexpected Telegram payload chat=%q text=%q", gotChat, gotText)
	}

	// Also verify Backup & Restore preserves encrypted Notify credentials and Traffic counters!
	env, err := p.CreateBackup(context.Background(), "backupPass123!")
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}
	rawBackup, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	p2 := newTestPanel(t)
	if _, err := p2.RestoreBackup(context.Background(), rawBackup, RestoreOptions{
		Passphrase: "backupPass123!",
		Mode:       "replace",
	}); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}
	restoredTok, err := p2.store.open(p2.store.get().Notify.TelegramTokenEnc)
	if err != nil || restoredTok != "123456789:TEST_SECRET_TOKEN_ABCD" {
		t.Fatalf("restored Telegram token mismatch: tok=%q err=%v", restoredTok, err)
	}
}
