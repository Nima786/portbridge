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
