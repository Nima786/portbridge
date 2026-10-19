package engine

import (
	"context"
	"testing"
	"time"
)

func TestMultiTransportProbeEngine(t *testing.T) {
	ln, err := StartProbeListener("127.0.0.1", 0, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("StartProbeListener failed: %v", err)
	}
	defer ln.Close()

	cands := BuildProbeCandidates("direct", "127.0.0.1", "", ln.Port, "")
	if len(cands) == 0 {
		t.Fatalf("expected candidates from BuildProbeCandidates")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	results := RunProbeDialer(ctx, cands, ln.Secret, 64*1024)
	if len(results) != len(cands) {
		t.Fatalf("expected %d results, got %d", len(cands), len(results))
	}

	report := FinalizeProbeReport(results, "")
	if report.Recommended == nil {
		t.Fatalf("expected a recommended candidate in ProbeBenchmarkReport")
	}

	for _, r := range report.Results {
		if (r.Transport == string(TransportICMP) || r.Transport == string(TransportFakeTCP)) && r.Status != "ok" {
			// Raw ICMP and FakeTCP sockets require root / CAP_NET_RAW on Linux;
			// unprivileged unit tests verify their wire framing in icmp_test.go and faketcp_test.go.
			continue
		}
		if r.Status != "ok" {
			t.Errorf("candidate %s (%s) status = %s, error = %s", r.ID, r.Label, r.Status, r.Error)
		}
		if r.Score <= 0 {
			t.Errorf("candidate %s expected positive score, got %d", r.ID, r.Score)
		}
	}
}
