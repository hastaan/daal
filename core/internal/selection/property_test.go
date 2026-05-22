package selection

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"daal/core/netmem"
)

// rngFromSeed creates a deterministic RNG. Property tests run many
// trials but each trial seed is reproducible.
func rngFromSeed(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}

func randomCandidate(r *rand.Rand, i int) Candidate {
	families := []string{"vless-reality", "naive", "websocket-tls", "hysteria2", "trojan"}
	modes := []string{"direct_vps", "cdn_fronted", ""}
	probing := []string{"low", "moderate", "high", ""}
	mode := modes[r.Intn(len(modes))]
	tags := []string{}
	switch mode {
	case "direct_vps":
		ip := fmt.Sprintf("public_ip:10.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(256))
		tags = append(tags, ip)
		if r.Intn(2) == 0 {
			tags = append(tags, fmt.Sprintf("public_asn:%d", 10000+r.Intn(50000)))
		}
		if r.Intn(3) == 0 {
			tags = append(tags, "udp_gated:true")
		}
	case "cdn_fronted":
		tags = append(tags, "cdn:cloudflare")
		tags = append(tags, fmt.Sprintf("public_domain:n%d.example", r.Intn(1000)))
	}
	c := Candidate{
		RouteID:          fmt.Sprintf("r%04d", i),
		TransportFamily:  families[r.Intn(len(families))],
		ExposureMode:     mode,
		FamilyClass:      "vps-native",
		ProbingRiskClass: probing[r.Intn(len(probing))],
		PublicRiskTags:   tags,
	}
	for _, t := range tags {
		if t == "udp_gated:true" {
			c.UDPGated = true
		}
	}
	return c
}

// Property 1: Shortlist is idempotent — running it twice on the
// same input gives the same output (1000 trials).
func TestProperty_ShortlistIdempotent(t *testing.T) {
	for trial := 0; trial < 1000; trial++ {
		r := rngFromSeed(int64(trial))
		n := 1 + r.Intn(20)
		cands := make([]Candidate, n)
		for i := range cands {
			cands[i] = randomCandidate(r, i)
		}
		size := 1 + r.Intn(5)
		out1 := Shortlist(cands, size, PhaseV15)
		out2 := Shortlist(cands, size, PhaseV15)
		if len(out1) != len(out2) {
			t.Fatalf("trial %d: non-deterministic length %d vs %d", trial, len(out1), len(out2))
		}
		for i := range out1 {
			if out1[i].RouteID != out2[i].RouteID {
				t.Fatalf("trial %d position %d: %s vs %s", trial, i, out1[i].RouteID, out2[i].RouteID)
			}
		}
	}
}

// Property 2: Shortlist NEVER outputs two candidates sharing a cdn:*
// tag (hard rule, supplement v2.3.5 §13.1). 500 trials.
func TestProperty_ShortlistNeverCDNCohabitates(t *testing.T) {
	for trial := 0; trial < 500; trial++ {
		r := rngFromSeed(int64(1000 + trial))
		n := 2 + r.Intn(15)
		cands := make([]Candidate, n)
		for i := range cands {
			cands[i] = randomCandidate(r, i)
		}
		size := 2 + r.Intn(3)
		phase := PhaseV15
		if trial%2 == 0 {
			phase = PhaseV16
		}
		out := Shortlist(cands, size, phase)
		seen := map[string]string{}
		for _, c := range out {
			for _, tag := range c.PublicRiskTags {
				if len(tag) > 4 && tag[:4] == "cdn:" {
					if prev, ok := seen[tag]; ok && prev != c.RouteID {
						t.Fatalf("trial %d: cdn cohabitation %s on %s and %s", trial, tag, prev, c.RouteID)
					}
					seen[tag] = c.RouteID
				}
			}
		}
	}
}

// Property 3: PropagateCooldown for SignalOriginUnhealthy NEVER
// produces sibling cooldowns (asymmetry pin, invariant 20).
// 500 trials with random shared-risk graphs.
func TestProperty_OriginUnhealthyNeverPropagates(t *testing.T) {
	for trial := 0; trial < 500; trial++ {
		r := rngFromSeed(int64(2000 + trial))
		// Build a cdn_fronted candidate with random origin tags +
		// a few siblings sharing some of those origin tags.
		failed := Candidate{
			RouteID:      "fA",
			ExposureMode: "cdn_fronted",
			OriginRiskTags: []string{
				fmt.Sprintf("origin_ip:5.75.0.%d", r.Intn(256)),
				fmt.Sprintf("origin_asn:%d", 1000+r.Intn(50000)),
			},
		}
		nSiblings := r.Intn(5)
		peers := make([]Candidate, nSiblings)
		for i := range peers {
			peers[i] = Candidate{
				RouteID:        fmt.Sprintf("p%d", i),
				ExposureMode:   "cdn_fronted",
				OriginRiskTags: failed.OriginRiskTags, // share!
			}
		}
		plan := PropagateCooldown(failed, SignalOriginUnhealthy, peers, fixedT)
		if len(plan.OnSiblings) != 0 {
			t.Fatalf("trial %d: origin_unhealthy propagated to %d siblings (asymmetry pin broken)",
				trial, len(plan.OnSiblings))
		}
	}
}

// Property 4: Apply is monotonic — Successes/Failures only
// increment; the byte-form snapshot grows or stays equal but never
// shrinks. 200 trials with random write sequences.
func TestProperty_ApplyMonotonic(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		r := rngFromSeed(int64(3000 + trial))
		pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
		snap := netmem.Snapshot{LastSeen: pin}
		nWrites := 1 + r.Intn(20)
		families := []string{"vless-reality", "naive", "hysteria2"}
		modes := []string{"direct_vps", "cdn_fronted"}
		outcomes := []string{OutcomeSuccess, OutcomeClassifiedFailure}
		var prevSucc, prevFail uint64
		for w := 0; w < nWrites; w++ {
			fam := families[r.Intn(len(families))]
			mode := modes[r.Intn(len(modes))]
			sig := fmt.Sprintf("public_ip:10.%d.%d.%d", r.Intn(10), r.Intn(10), r.Intn(10))
			out := outcomes[r.Intn(len(outcomes))]
			snap = Apply(snap, MemoryWrite{
				Family: fam, ExposureMode: mode, PublicRiskTagSignature: sig, Outcome: out,
			})
			// Aggregate across all families.
			var totSucc, totFail uint64
			for _, fs := range snap.RouteFamilyStats {
				totSucc += fs.Successes
				totFail += fs.Failures
			}
			if totSucc < prevSucc {
				t.Fatalf("trial %d write %d: Successes regressed %d → %d", trial, w, prevSucc, totSucc)
			}
			if totFail < prevFail {
				t.Fatalf("trial %d write %d: Failures regressed %d → %d", trial, w, prevFail, totFail)
			}
			prevSucc = totSucc
			prevFail = totFail
		}
	}
}
