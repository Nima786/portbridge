package engine

import (
	"fmt"
	"sort"
)

// A benchmark gives each candidate one real transfer of a few seconds. One
// bad moment in those seconds (a burst of loss, a short stall on the route)
// decided the candidate's fate: on a healthy pair of servers about one test in
// ten came back far off, links that carry 900 Mbit/s reading 2 to 17, and
// working links shown as frozen, which also took away their Use button. So the
// results that look wrong are tested again at the end of the run, and the two
// runs are combined (MergeProbeRetests).

// probeMaxRetests bounds how much a run can grow from re-tests.
const probeMaxRetests = 10

// probeOutlierShare: a working candidate this far below the middle of its
// group (one fifth or less) is taken for a bad moment, not for the link.
const probeOutlierShare = 0.2

// probeFamily groups candidates whose speeds can be compared: one link over
// the same address carries TCP-based links at much the same speed, and the
// KCP-based ones at much the same speed as each other.
func probeFamily(r *ProbeCandidateResult) string {
	switch Transport(r.Transport) {
	case TransportICMP:
		return "icmp"
	case TransportKCP, TransportFakeTCP:
		return "kcp"
	default:
		return "stream"
	}
}

func probeGroupKey(r *ProbeCandidateResult) string {
	return fmt.Sprintf("%s|%v|%s|%s", r.Mode, r.IPv6, r.TargetAddr, probeFamily(r))
}

// ProbeRetestIDs picks the results worth testing a second time:
//   - one that froze, or that was unstable;
//   - one that could not connect while another link of its kind to the same
//     address could (so the address and port are fine);
//   - one that worked but at a fifth or less of the speed of the others of
//     its kind to the same address.
//
// Split rotation is slow by design and is not compared on speed, and a
// Gaming run's speeds are not speeds, so neither is.
func ProbeRetestIDs(results []ProbeCandidateResult) []string {
	okSpeeds := map[string][]float64{}
	okAny := map[string]bool{}
	for i := range results {
		r := &results[i]
		if r.Hybrid || r.Status != "ok" {
			continue
		}
		k := probeGroupKey(r)
		okAny[k] = true
		if !r.AntiFreeze && !r.Gaming {
			okSpeeds[k] = append(okSpeeds[k], effectiveProbeMbps(r))
		}
	}
	median := func(v []float64) float64 {
		s := append([]float64(nil), v...)
		sort.Float64s(s)
		if n := len(s); n%2 == 1 {
			return s[n/2]
		}
		return (s[len(s)/2-1] + s[len(s)/2]) / 2
	}

	var first, second, third []string
	for i := range results {
		r := &results[i]
		if r.Hybrid || r.Retested || r.ID == "" {
			continue
		}
		k := probeGroupKey(r)
		switch r.Status {
		case "throttled", "degraded":
			first = append(first, r.ID)
		case "blocked":
			if okAny[k] {
				third = append(third, r.ID)
			}
		case "ok":
			if r.AntiFreeze || r.Gaming {
				continue
			}
			// Compare with the others, not with itself.
			var others []float64
			own := effectiveProbeMbps(r)
			skipped := false
			for _, v := range okSpeeds[k] {
				if !skipped && v == own {
					skipped = true
					continue
				}
				others = append(others, v)
			}
			if len(others) >= 2 && own < probeOutlierShare*median(others) {
				second = append(second, r.ID)
			}
		}
	}
	ids := append(append(first, second...), third...)
	if len(ids) > probeMaxRetests {
		ids = ids[:probeMaxRetests]
	}
	return ids
}

func probeStatusRank(s string) int {
	switch s {
	case "ok":
		return 3
	case "degraded":
		return 2
	case "throttled":
		return 1
	}
	return 0
}

// mergeProbePair combines a candidate's first result with its re-test. Two
// working runs keep the faster (the slow one was the bad moment). A run that
// failed and one that worked keep the working one, marked unstable: it did
// fail once, and should rank below a link that never did.
func mergeProbePair(a, b ProbeCandidateResult) ProbeCandidateResult {
	ra, rb := probeStatusRank(a.Status), probeStatusRank(b.Status)
	var out ProbeCandidateResult
	switch {
	case ra == 3 && rb == 3:
		out = a
		if effectiveProbeMbps(&b) > effectiveProbeMbps(&a) {
			out = b
		}
	case ra == rb:
		out = b
	default:
		best, other := a, b
		if rb > ra {
			best, other = b, a
		}
		out = best
		if best.Status == "ok" && other.Status != "ok" {
			out.Status = "degraded"
			out.Attempts = best.Attempts + 1
			if out.Successes > out.Attempts {
				out.Successes = out.Attempts
			}
			if out.Gaming {
				out.Summary = fmt.Sprintf("Unstable — failed once, then passed on a re-test (%.0f ms ping, ±%.1f ms jitter)", out.RTTMS, out.JitterMS)
			} else {
				out.Summary = fmt.Sprintf("Unstable — failed once, then worked on a re-test (%.1f Mbps avg, ↓%.1f / ↑%.1f Mbps, %.0f ms ping)",
					out.AvgMbps, out.DownMbps, out.UpMbps, out.RTTMS)
			}
			out.Error = "failed on the first try: " + other.Error
			if other.Error == "" {
				out.Error = "failed on the first try"
			}
		}
	}
	out.Retested = true
	return out
}

// MergeProbeRetests folds re-test results into the first results, matching
// them by candidate. A re-test of something not in results is ignored.
func MergeProbeRetests(results, retests []ProbeCandidateResult) []ProbeCandidateResult {
	if len(retests) == 0 {
		return results
	}
	byID := map[string]ProbeCandidateResult{}
	for _, r := range retests {
		if r.ID != "" {
			byID[r.ID] = r
		}
	}
	out := make([]ProbeCandidateResult, len(results))
	for i, r := range results {
		if b, ok := byID[r.ID]; ok && !r.Hybrid {
			out[i] = mergeProbePair(r, b)
			continue
		}
		out[i] = r
	}
	return out
}
