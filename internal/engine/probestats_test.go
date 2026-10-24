package engine

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func TestProbeRTTIgnoresTheSetUpCostOfTheFirstPing(t *testing.T) {
	// A KCP or spoofed link: the first ping pays for setting the link up.
	rtt, jitter := probeRTTStats([]float64{864, 97, 99, 98, 97})
	if rtt < 96 || rtt > 100 {
		t.Fatalf("rtt = %.1f, want about 98", rtt)
	}
	if jitter > 3 {
		t.Fatalf("jitter = %.1f, the slow first ping should not count", jitter)
	}
	if r, j := probeRTTStats(nil); r != 0 || j != 0 {
		t.Fatalf("no samples gave %v %v", r, j)
	}
	if r, _ := probeRTTStats([]float64{50, 70}); r != 60 {
		t.Fatalf("two samples gave %v, want 60", r)
	}
}

// Each attempt opens a fresh link whose first ping pays for setting it up.
// Only leaving out the very first sample, and measuring the jump from one
// attempt's last ping to the next attempt's set-up ping, made a steady KCP
// link (40 ms, ±1 ms) look like it had ~70 ms of jitter, which sank it in
// the Gaming score.
func TestProbeRTTAttemptsLeaveOutEveryAttemptsSetUpPing(t *testing.T) {
	a1 := []float64{864, 40, 41, 40, 41, 40, 41, 40, 41, 40, 41, 40}
	a2 := []float64{700, 41, 40, 41, 40, 41, 40, 41}
	rtt, jitter := probeRTTStatsAttempts(a1, a2)
	if rtt < 40 || rtt > 41 {
		t.Fatalf("rtt = %.1f, want about 40", rtt)
	}
	if jitter > 1.5 {
		t.Fatalf("jitter = %.1f, the set-up pings and the gap between attempts must not count", jitter)
	}
	if _, old := probeRTTStats(append(append([]float64(nil), a1...), a2...)); old < 30 {
		t.Fatalf("the single-list stats gave jitter %.1f; this test no longer shows the problem", old)
	}

	// The General mode shape: 3 pings, then 2.
	rtt, jitter = probeRTTStatsAttempts([]float64{500, 90, 92}, []float64{450, 91})
	if rtt < 90 || rtt > 92 || jitter > 3 {
		t.Fatalf("3+2 samples gave rtt %.1f jitter %.1f, want about 91 and small", rtt, jitter)
	}
	// Too few samples to leave any out still gives an answer.
	if r, j := probeRTTStatsAttempts([]float64{50, 70}, nil); r != 60 || j != 20 {
		t.Fatalf("two samples gave %v %v, want 60 20", r, j)
	}
	if r, j := probeRTTStatsAttempts(nil, nil); r != 0 || j != 0 {
		t.Fatalf("no samples gave %v %v", r, j)
	}
}

// A transfer that was over in a blink says little; one longer transfer, sized
// from the speed just seen, is what is reported.
func TestMeasureTransferTimesALongerOneWhenTheFirstWasTooShort(t *testing.T) {
	var asked []uint32
	run := func(sz uint32) (int64, float64, error) {
		asked = append(asked, sz)
		return int64(sz), float64(sz) / 20e6, nil // 20 MB/s
	}
	n, dur, ok, err := measureTransfer(context.Background(), run, 384<<10, true)
	if err != nil || !ok {
		t.Fatalf("not ok: %v", err)
	}
	if len(asked) != 2 || asked[1] <= asked[0]*2 {
		t.Fatalf("transfers asked for: %v, want a second, much longer one", asked)
	}
	if got := float64(n) / dur / 1e6; got < 19 || got > 21 {
		t.Fatalf("speed reported %.1f MB/s, want 20", got)
	}
}

func TestMeasureTransferLeavesALongEnoughOneAlone(t *testing.T) {
	calls := 0
	run := func(sz uint32) (int64, float64, error) { calls++; return int64(sz), 1.2, nil }
	if _, _, ok, _ := measureTransfer(context.Background(), run, 384<<10, true); !ok || calls != 1 {
		t.Fatalf("a slow transfer was repeated: %d calls", calls)
	}
	calls = 0
	fast := func(sz uint32) (int64, float64, error) { calls++; return int64(sz), 0.01, nil }
	if _, _, _, _ = measureTransfer(context.Background(), fast, 384<<10, false); calls != 1 {
		t.Fatalf("a longer transfer was asked for when not allowed: %d calls", calls)
	}
}

// The time left holds the longer transfer down, so a link that works but is
// slow is not taken for a frozen one.
func TestMeasureTransferStaysWithinTheTimeLeft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	var asked []uint32
	run := func(sz uint32) (int64, float64, error) {
		asked = append(asked, sz)
		return int64(sz), float64(sz) / 5e6, nil // 5 MB/s
	}
	if _, _, ok, _ := measureTransfer(ctx, run, 128<<10, true); !ok {
		t.Fatal("not ok")
	}
	if len(asked) == 2 && float64(asked[1])/5e6 > 0.6/2 {
		t.Fatalf("a %d byte transfer would take %.2fs of the 0.6s left", asked[1], float64(asked[1])/5e6)
	}
}

func TestMeasureTransferReportsAFailedLongerOne(t *testing.T) {
	calls := 0
	run := func(sz uint32) (int64, float64, error) {
		calls++
		if calls == 2 {
			return 1000, 0.5, errors.New("cut off")
		}
		return int64(sz), 0.01, nil
	}
	if _, _, ok, err := measureTransfer(context.Background(), run, 384<<10, true); ok || err == nil {
		t.Fatalf("a cut-off longer transfer counted as complete: ok=%v err=%v", ok, err)
	}
}

// While a connection is still speeding up, a short transfer shows far less than
// the link holds. Each step is sized from the last until one runs long enough.
func TestMeasureTransferFollowsAConnectionAsItSpeedsUp(t *testing.T) {
	const plateau = 25e6 // bytes per second
	rateFor := func(size uint32) float64 { return math.Min(plateau, 1e6+float64(size)*3) }
	calls := 0
	run := func(sz uint32) (int64, float64, error) {
		calls++
		return int64(sz), float64(sz) / rateFor(sz), nil
	}
	n, dur, ok, err := measureTransfer(context.Background(), run, 384<<10, true)
	if err != nil || !ok {
		t.Fatalf("not ok: %v", err)
	}
	if got := float64(n) / dur; got < plateau*0.9 {
		t.Fatalf("reported %.1f MB/s after %d transfers, the link holds %.1f", got/1e6, calls, plateau/1e6)
	}
	if calls > 4 {
		t.Fatalf("%d transfers were needed", calls)
	}
}

// A probe must tune KCP like a real tunnel, or ICMP and FakeTCP links are held
// to a small window and measured at a fraction of what a tunnel gets.
func TestProbeUsesTheTunnelsKCPTuning(t *testing.T) {
	c := &Config{Transport: TransportICMP}
	probeKCPDefaults(c)
	d := DefaultConfig()
	if c.KCPWindow != d.KCPWindow || c.KCPMTU != d.KCPMTU || c.KCPInterval != d.KCPInterval || c.KCPResend != d.KCPResend {
		t.Fatalf("probe tuning %+v differs from a tunnel's %+v", c, d)
	}
	if c.KCPWindow <= 256 {
		t.Fatalf("window %d is no larger than the small fallback", c.KCPWindow)
	}
	if c.KCPInterval != 5 {
		t.Fatalf("KCP interval = %d, want 5 ms low-latency tick", c.KCPInterval)
	}
}

func TestFinalizeProbeReportGamingMode(t *testing.T) {
	baseResults := []ProbeCandidateResult{
		{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:        "direct-stealth",
				Label:     "Direct · Stealth uTLS + TLS Fragmentation",
				Mode:      "direct",
				Link:      "website",
				Transport: "tls",
				Stealth:   true,
			},
			Status:    "ok",
			Attempts:  2,
			Successes: 2,
			RTTMS:     88,
			JitterMS:  14.5,
			DownMbps:  180,
			UpMbps:    160,
			AvgMbps:   170,
		},
		{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:        "direct-kcp",
				Label:     "Direct · KCP over UDP (FEC)",
				Mode:      "direct",
				Link:      "kcp",
				Transport: "kcp",
			},
			Status:    "ok",
			Attempts:  2,
			Successes: 2,
			RTTMS:     42,
			JitterMS:  1.2,
			DownMbps:  35,
			UpMbps:    32,
			AvgMbps:   33.5,
		},
		{
			ProbeCandidateSpec: ProbeCandidateSpec{
				ID:        "direct-cdn-ws",
				Label:     "Direct · Cloudflare CDN (WebSocket)",
				Mode:      "direct",
				Link:      "cdn",
				Transport: "wss",
				CDN:       true,
			},
			Status:    "ok",
			Attempts:  2,
			Successes: 2,
			RTTMS:     135,
			JitterMS:  22.0,
			DownMbps:  90,
			UpMbps:    80,
			AvgMbps:   85,
		},
	}

	// 1. In General mode, high-Mbps Stealth (or Hybrid Fake TLS + CDN) wins
	generalIn := make([]ProbeCandidateResult, len(baseResults))
	copy(generalIn, baseResults)
	genRep := FinalizeProbeReport(generalIn, "edge.example.com")
	if genRep.Recommended == nil || genRep.Recommended.ID == "direct-kcp" {
		t.Fatalf("general mode recommended %+v, expected high-throughput stealth/hybrid to win", genRep.Recommended)
	}

	// 2. In Gaming mode, low-ping low-jitter KCP (42 ms, ±1.2 ms) must beat 88 ms Stealth and 135 ms CDN
	gamingIn := make([]ProbeCandidateResult, len(baseResults))
	copy(gamingIn, baseResults)
	for i := range gamingIn {
		gamingIn[i].Gaming = true
	}
	gamRep := FinalizeProbeReport(gamingIn, "edge.example.com")
	if gamRep.Recommended == nil || gamRep.Recommended.ID != "direct-kcp" {
		t.Fatalf("gaming mode recommended %+v, want direct-kcp", gamRep.Recommended)
	}
	for _, r := range gamRep.Results {
		if r.Hybrid {
			t.Fatalf("gaming mode should not synthesize CDN hybrid recommendation")
		}
	}
}
