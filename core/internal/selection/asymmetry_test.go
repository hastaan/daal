package selection

import (
	"testing"
	"time"
)

// TestAsymmetry_OriginVsCDNWide is the asymmetry pin pair (invariant
// 20). It runs two near-identical scenarios — same candidates,
// same siblings, same shared origin tags — but differs in the
// signal: SignalOriginUnhealthy must NOT propagate; SignalCDNWideFailure
// MUST propagate. Both scenarios assert their counterpart's
// behaviour fails.
//
// This is the single most load-bearing semantic test in FRP-3:
// origin_unhealthy is operator-hygiene; if propagation fired, an
// unhealthy origin would knock out an entire CDN edge surface for
// 60 minutes.
func TestAsymmetry_OriginVsCDNWide(t *testing.T) {
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)

	// Setup: two cdn_fronted candidates on cdn:cloudflare sharing
	// the same origin_ip / origin_asn (a common one-VPS-behind-
	// two-CDN-hostnames deployment). The first fails.
	failed := Candidate{
		RouteID:        "rA",
		ExposureMode:   "cdn_fronted",
		PublicRiskTags: []string{"cdn:cloudflare", "public_domain:a.example", "host:a.example"},
		OriginRiskTags: []string{"origin_ip:5.75.0.1", "origin_asn:24940"},
	}
	sibling := Candidate{
		RouteID:        "rB",
		ExposureMode:   "cdn_fronted",
		PublicRiskTags: []string{"cdn:cloudflare", "public_domain:b.example", "host:b.example"},
		OriginRiskTags: []string{"origin_ip:5.75.0.1", "origin_asn:24940"}, // shares origin
	}

	// Half 1: SignalOriginUnhealthy → no sibling propagation.
	plan := PropagateCooldown(failed, SignalOriginUnhealthy, []Candidate{sibling}, now)
	if len(plan.OnSiblings) != 0 {
		t.Errorf("origin_unhealthy MUST NOT propagate; got %d sibling cooldowns: %+v",
			len(plan.OnSiblings), plan.OnSiblings)
	}
	// And: the failing candidate's origin_* tags ARE cooled.
	if !hasTag(plan.OnCandidate, "origin_ip:5.75.0.1") {
		t.Errorf("origin_unhealthy must cool origin_ip on the failing candidate")
	}
	if !hasTag(plan.OnCandidate, "origin_asn:24940") {
		t.Errorf("origin_unhealthy must cool origin_asn on the failing candidate")
	}
	// And: NO public_risk_tag is cooled.
	for _, e := range plan.OnCandidate {
		if e.Tag == "cdn:cloudflare" || e.Tag == "public_domain:a.example" || e.Tag == "host:a.example" {
			t.Errorf("origin_unhealthy must NOT cool public_risk_tag %q on the failing candidate", e.Tag)
		}
	}

	// Half 2: SignalCDNWideFailure on identical candidates → MUST
	// propagate to siblings on cdn:cloudflare.
	plan = PropagateCooldown(failed, SignalCDNWideFailure, []Candidate{sibling}, now)
	if len(plan.OnSiblings) != 1 {
		t.Errorf("cdn_wide_failure MUST propagate to 1 sibling; got %d: %+v",
			len(plan.OnSiblings), plan.OnSiblings)
	}
	if !tagPresent(plan.OnSiblings["rB"], "cdn:cloudflare") {
		t.Errorf("cdn_wide_failure must cool cdn:cloudflare on sibling rB; got %+v", plan.OnSiblings["rB"])
	}
	if !hasTag(plan.OnCandidate, "cdn:cloudflare") {
		t.Errorf("cdn_wide_failure must cool cdn:cloudflare on the failing candidate")
	}
}
