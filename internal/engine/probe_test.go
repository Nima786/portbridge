package engine

import (
	"context"
	"net"
	"strings"
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

// KCP over IPv6 must really carry a probe, not only be listed.
func TestProbeKCPOverIPv6Loopback(t *testing.T) {
	if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback here")
	} else {
		_ = l.Close()
	}
	ln, err := StartProbeListener("0.0.0.0", 0, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("StartProbeListener failed: %v", err)
	}
	defer ln.Close()
	var specs []ProbeCandidateSpec
	for _, c := range BuildProbeCandidates("direct", "127.0.0.1", "::1", ln.Port, "") {
		if c.ID == "direct-ipv6-kcp" || c.ID == "direct-ipv6-plain" {
			c.Gaming = true
			specs = append(specs, c)
		}
	}
	if len(specs) != 2 {
		t.Fatalf("got %d IPv6 candidates, want 2", len(specs))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, r := range RunProbeDialer(ctx, specs, ln.Secret, 0) {
		if r.Status != "ok" {
			t.Errorf("%s over IPv6: status %s, error %q", r.ID, r.Status, r.Error)
		}
	}
}

// The Gaming benchmark end to end over loopback: every candidate is marked,
// measured with the light burst, summarised for gaming and ranked without
// the CDN hybrid.
func TestGamingProbeEndToEnd(t *testing.T) {
	ln, err := StartProbeListener("127.0.0.1", 0, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("StartProbeListener failed: %v", err)
	}
	defer ln.Close()

	var cands []ProbeCandidateSpec
	for _, c := range BuildProbeCandidates("direct", "127.0.0.1", "", ln.Port, "") {
		switch c.ID {
		case "direct-kcp", "direct-tls", "direct-tls-stealth", "direct-http-tcp", "direct-plain":
			c.Gaming = true
			cands = append(cands, c)
		}
	}
	if len(cands) < 3 {
		t.Fatalf("expected at least 3 gaming candidates, got %d", len(cands))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	// 0 is what an agent gets from a panel that sends no burst size: the
	// Gaming spec must still hold the transfer check to the light 64 KB.
	start := time.Now()
	results := RunProbeDialer(ctx, cands, ln.Secret, 0)
	if len(results) != len(cands) {
		t.Fatalf("expected %d results, got %d", len(cands), len(results))
	}
	for _, r := range results {
		if !r.Gaming {
			t.Errorf("%s lost its Gaming flag", r.ID)
		}
		if r.Status != "ok" || r.Successes != 2 {
			t.Errorf("%s: status %s, %d/%d successes, error %q", r.ID, r.Status, r.Successes, r.Attempts, r.Error)
			continue
		}
		if !strings.HasPrefix(r.Summary, "Gaming Ready") {
			t.Errorf("%s summary %q, want a Gaming Ready summary", r.ID, r.Summary)
		}
		// (No check that the ping is above zero: loopback round trips are
		// below the clock's resolution on some systems, Windows among them.)
		if r.RTTMS < 0 || r.JitterMS < 0 {
			t.Errorf("%s has a negative ping %.2f or jitter %.2f", r.ID, r.RTTMS, r.JitterMS)
		}
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Errorf("gaming probe of %d candidates took %v; the light check should be quick", len(cands), el)
	}

	rep := FinalizeProbeReport(results, "edge.example.com")
	if rep.Recommended == nil || !rep.Recommended.Gaming {
		t.Fatalf("no gaming recommendation: %+v", rep.Recommended)
	}
	for i := 1; i < len(rep.Results); i++ {
		if rep.Results[i].Score > rep.Results[i-1].Score {
			t.Fatalf("results not sorted by score: %d before %d", rep.Results[i-1].Score, rep.Results[i].Score)
		}
	}
}
