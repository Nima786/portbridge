package engine

import (
	"slices"
	"testing"
)

func retestResult(id, mode, transport, addr, status string, down, up float64) ProbeCandidateResult {
	r := ProbeCandidateResult{
		ProbeCandidateSpec: ProbeCandidateSpec{ID: id, Mode: mode, Transport: transport, TargetAddr: addr, Link: "website"},
		Status:             status,
		Attempts:           2,
		DownMbps:           down,
		UpMbps:             up,
		AvgMbps:            (down + up) / 2,
	}
	if status == "ok" {
		r.Successes = 2
	}
	return r
}

// The run that showed the problem: on a healthy pair, three TCP links read
// 17, 9 and 2 Mbit/s next to others at 400 to 1,100, and gRPC was once shown
// as frozen. Those are re-tested; the healthy ones are not.
func TestProbeRetestIDsPicksTheDoubtful(t *testing.T) {
	a := "198.51.100.7:2053"
	res := []ProbeCandidateResult{
		retestResult("direct-tls-stealth", "direct", "tls", a, "ok", 17, 73),
		retestResult("direct-sni-spoof", "direct", "tls", a, "ok", 402, 328),
		retestResult("direct-tls", "direct", "tls", a, "ok", 388, 611),
		retestResult("direct-grpc", "direct", "grpc", a, "throttled", 0, 0),
		retestResult("direct-http-tcp", "direct", "plain", a, "ok", 1.9, 204),
		retestResult("direct-plain", "direct", "plain", a, "ok", 1146, 746),
		retestResult("direct-kcp", "direct", "kcp", a, "ok", 55, 40),
		retestResult("direct-ip-spoof", "direct", "kcp", a, "ok", 49, 52),
		// A dip in one direction only: 60 down where the others do 400+.
		retestResult("direct-ipv4-grpc-dip", "direct", "grpc", a, "ok", 60, 629),
		retestResult("direct-faketcp", "direct", "faketcp", a, "blocked", 0, 0), // KCP to the same address works
		retestResult("direct-icmp", "direct", "icmp", a, "blocked", 0, 0),       // nothing of its kind works
	}
	split := retestResult("direct-split", "direct", "tls", a, "ok", 0.6, 0.7)
	split.AntiFreeze = true
	res = append(res, split)

	got := ProbeRetestIDs(res)
	for _, id := range []string{"direct-grpc", "direct-tls-stealth", "direct-http-tcp", "direct-faketcp", "direct-ipv4-grpc-dip"} {
		if !slices.Contains(got, id) {
			t.Errorf("%s not re-tested; got %v", id, got)
		}
	}
	for _, id := range []string{"direct-tls", "direct-plain", "direct-sni-spoof", "direct-kcp", "direct-icmp", "direct-split"} {
		if slices.Contains(got, id) {
			t.Errorf("%s re-tested but looks fine (or has nothing to compare with); got %v", id, got)
		}
	}
	// Frozen ones first: they are the ones that lose a usable mode.
	if len(got) == 0 || got[0] != "direct-grpc" {
		t.Errorf("first re-test %v, want the frozen one first", got)
	}
}

// Only links to the same address are compared: a blocked IPv4 link is not
// re-tested because IPv6 works.
func TestProbeRetestIDsComparesLikeWithLike(t *testing.T) {
	res := []ProbeCandidateResult{
		retestResult("direct-tls", "direct", "tls", "198.51.100.7:2053", "blocked", 0, 0),
		retestResult("direct-ipv6-tls", "direct", "tls", "[2001:db8::7]:2053", "ok", 900, 800),
		retestResult("reverse-tls", "reverse", "tls", "203.0.113.9:2083", "ok", 5, 5),
		retestResult("reverse-plain", "reverse", "plain", "203.0.113.9:2083", "ok", 6, 6),
	}
	if got := ProbeRetestIDs(res); len(got) != 0 {
		t.Fatalf("re-tests %v, want none", got)
	}
	// Everything of a kind frozen to one address (Dagger to Aeza over IPv4)
	// is the network blocking it: not re-tested.
	a := "198.51.100.7:2053"
	frozen := []ProbeCandidateResult{
		retestResult("direct-kcp", "direct", "kcp", a, "throttled", 0, 0),
		retestResult("direct-faketcp", "direct", "faketcp", a, "throttled", 0, 0),
		retestResult("direct-plain", "direct", "plain", a, "throttled", 0, 0),
		retestResult("direct-icmp", "direct", "icmp", a, "ok", 66, 42),
	}
	if got := ProbeRetestIDs(frozen); len(got) != 0 {
		t.Fatalf("re-tests %v of links frozen like all their kind, want none", got)
	}
}

func TestMergeProbeRetests(t *testing.T) {
	a := "198.51.100.7:2053"
	first := []ProbeCandidateResult{
		retestResult("direct-tls-stealth", "direct", "tls", a, "ok", 17, 73),
		retestResult("direct-grpc", "direct", "grpc", a, "throttled", 0, 0),
		retestResult("direct-tls", "direct", "tls", a, "ok", 388, 611),
	}
	first[1].Successes, first[1].Attempts, first[1].Error = 1, 1, probeFrozenMsg
	again := []ProbeCandidateResult{
		retestResult("direct-tls-stealth", "direct", "tls", a, "ok", 926, 613),
		retestResult("direct-grpc", "direct", "grpc", a, "ok", 805, 667),
	}
	out := MergeProbeRetests(first, again)

	if s := out[0]; s.Status != "ok" || s.DownMbps != 926 || !s.Retested {
		t.Errorf("two working runs: %+v, want the faster, still ok", s)
	}
	g := out[1]
	if g.Status != "degraded" || g.DownMbps != 805 || !g.Retested {
		t.Errorf("frozen then working: %+v, want the working numbers, marked unstable", g)
	}
	if g.Successes >= g.Attempts {
		t.Errorf("frozen then working counts %d/%d, want the failure counted", g.Successes, g.Attempts)
	}
	if out[2].Retested {
		t.Errorf("a result with no re-test was changed: %+v", out[2])
	}
	// An unstable link scores below one that never failed, yet stays usable.
	rep := FinalizeProbeReport(out, "")
	var gs, ts int
	for _, r := range rep.Results {
		switch r.ID {
		case "direct-grpc":
			gs = r.Score
		case "direct-tls":
			ts = r.Score
		}
	}
	if gs == 0 || gs >= ts {
		t.Errorf("unstable gRPC scored %d, steady TLS %d; want 0 < unstable < steady", gs, ts)
	}
}

// The IPv6 stream links a real tunnel can use are all tried.
func TestBuildProbeCandidatesIPv6Streams(t *testing.T) {
	var ids []string
	for _, c := range BuildProbeCandidates("direct", "203.0.113.5", "2001:db8::5", 2053, "") {
		if c.IPv6 {
			ids = append(ids, c.ID)
			if c.TargetAddr != "[2001:db8::5]:2053" {
				t.Errorf("%s targets %s", c.ID, c.TargetAddr)
			}
		}
	}
	for _, want := range []string{"direct-ipv6-grpc", "direct-ipv6-split", "direct-ipv6-http-tcp", "direct-ipv6-tls", "direct-ipv6-kcp"} {
		if !slices.Contains(ids, want) {
			t.Errorf("IPv6 candidate %s missing; have %v", want, ids)
		}
	}
	for _, no := range []string{"direct-ipv6-icmp", "direct-ipv6-faketcp"} {
		if slices.Contains(ids, no) {
			t.Errorf("%s listed, but that link works over IPv4 only", no)
		}
	}
}
