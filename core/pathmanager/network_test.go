package pathmanager

import (
	"testing"
	"time"

	"daal/core/diagnostics"
)

// Phase 2C: family-escalation key widened to (family, networkID).
// These tests exercise the network-axis behaviour without breaking
// 2B's family-escalation tests (which set activeNetwork = "" and
// observe the legacy `family`-only key).

func atTimeFn(t time.Time) func() time.Time {
	return func() time.Time { return t.UTC() }
}

func TestSetActiveNetworkRoundTripPM(t *testing.T) {
	m := New()
	if m.ActiveNetwork() != "" {
		t.Fatalf("default ActiveNetwork = %q, want empty", m.ActiveNetwork())
	}
	m.SetActiveNetwork("aaaa000000000000")
	if m.ActiveNetwork() != "aaaa000000000000" {
		t.Fatalf("ActiveNetwork roundtrip: %q", m.ActiveNetwork())
	}
}

func TestFamilyEscalationKeyedByNetwork(t *testing.T) {
	// Phase 2C: the FAMILY axis is per-network (a roam clears the
	// family cooldown for the new network). The route axis remains
	// device-wide on purpose — a TCP-RST on a route is a route-
	// specific failure regardless of network. This test exercises a
	// family-wide failure (UDPUnavailable on hysteria2) using
	// distinct routes per network, so the route axis is independent.
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	m := New()
	m.SetNow(atTimeFn(now))

	// Network A: trip UDP-unavailable (family-class) → ladder step 1.
	m.SetActiveNetwork("aaaa000000000000")
	m.Failed("rA", "hysteria2", diagnostics.UDPUnavailable)

	// On Network B: a DIFFERENT route in the same family must not
	// inherit Network A's family cooldown.
	m.SetActiveNetwork("bbbb000000000000")
	can, _ := m.CanAttempt("rB", "hysteria2")
	if !can {
		t.Fatalf("on Network B, family hysteria2 should NOT be in cooldown")
	}

	// Roam back to Network A: family hysteria2 is still in cooldown
	// for any route.
	m.SetActiveNetwork("aaaa000000000000")
	can, _ = m.CanAttempt("rA-other", "hysteria2")
	if can {
		t.Fatalf("on Network A, family hysteria2 should still be in cooldown")
	}
}

func TestFamilyEscalationLadderAdvancesPerNetwork(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	m := New()
	m.SetNow(atTimeFn(now))

	m.SetActiveNetwork("aaaa000000000000")

	// First trip: step 1 = 5 min.
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	skipped := m.SkippedFamilies()
	if len(skipped) != 1 {
		t.Fatalf("SkippedFamilies after first trip: %d", len(skipped))
	}
	if skipped[0].LadderStep != 1 {
		t.Fatalf("first ladder step: %d", skipped[0].LadderStep)
	}

	// Second trip on same (family, network): step 2 = 15 min.
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	skipped = m.SkippedFamilies()
	if skipped[0].LadderStep != 2 {
		t.Fatalf("second ladder step: %d", skipped[0].LadderStep)
	}
}

func TestSkippedFamiliesProjectsToActiveNetworkOnly(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	m := New()
	m.SetNow(atTimeFn(now))

	// Trip on Network A.
	m.SetActiveNetwork("aaaa000000000000")
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)

	// Switch to Network B; the projection should be empty.
	m.SetActiveNetwork("bbbb000000000000")
	skipped := m.SkippedFamilies()
	if len(skipped) != 0 {
		t.Fatalf("SkippedFamilies on Network B should be empty; got %d", len(skipped))
	}

	// Trip on Network B too.
	m.Failed("r2", "hysteria2", diagnostics.UDPUnavailable)
	skipped = m.SkippedFamilies()
	if len(skipped) != 1 || skipped[0].Family != "hysteria2" {
		t.Fatalf("SkippedFamilies on Network B = %+v", skipped)
	}

	// Back to A: only vless-reality.
	m.SetActiveNetwork("aaaa000000000000")
	skipped = m.SkippedFamilies()
	if len(skipped) != 1 || skipped[0].Family != "vless-reality" {
		t.Fatalf("SkippedFamilies on Network A = %+v", skipped)
	}
}

func TestConnectedResetsEscalationForCurrentNetworkOnly(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	m := New()
	m.SetNow(atTimeFn(now))

	// Trip on A.
	m.SetActiveNetwork("aaaa000000000000")
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)

	// Trip on B.
	m.SetActiveNetwork("bbbb000000000000")
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)

	// Successful connect on B: escalation for B reset; A intact.
	m.Attempt("r1", "vless-reality")
	m.Connected()

	// On A, the family is still escalated (cooldown still active),
	// so a fresh trip continues at step 2.
	m.SetActiveNetwork("aaaa000000000000")
	// Advance time past the existing 5-min cooldown so we don't bump
	// into the still-active timer; we're testing the escalation
	// counter, not the cooldown timer.
	m.SetNow(atTimeFn(now.Add(10 * time.Minute)))
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	skipped := m.SkippedFamilies()
	if len(skipped) != 1 {
		t.Fatalf("SkippedFamilies on A: %+v", skipped)
	}
	if skipped[0].LadderStep != 2 {
		t.Fatalf("A escalation step (untouched by Connected on B): %d, want 2",
			skipped[0].LadderStep)
	}
}

func TestNextRouteSkipsCooldownAndFamily(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	m := New()
	m.SetNow(atTimeFn(now))
	m.SetActiveNetwork("aaaa000000000000")

	rs := []Route{
		{RouteID: "r1", Family: "vless-reality", ModesAllowed: []string{"normal"}, BudgetTag: "normal"},
		{RouteID: "r2", Family: "hysteria2", ModesAllowed: []string{"normal"}, BudgetTag: "normal"},
		{RouteID: "r3", Family: "vless-reality", ModesAllowed: []string{"normal"}, BudgetTag: "normal"},
	}

	// All three live; rank should pick r1 (lex smallest at zero usage).
	id, ok := m.NextRoute(rs, "normal")
	if !ok || id != "r1" {
		t.Fatalf("NextRoute (clean) = (%q, %v), want r1", id, ok)
	}

	// Cool down r1 directly.
	m.Attempt("r1", "vless-reality")
	m.Failed("r1", "vless-reality", diagnostics.TCPReset)
	id, ok = m.NextRoute(rs, "normal")
	if !ok || id != "r2" {
		t.Fatalf("NextRoute (after r1 cooldown) = (%q, %v), want r2", id, ok)
	}

	// Trip a family-class failure on hysteria2 (puts the family in
	// cooldown on the active network), so r2 is skipped, r3 survives
	// (vless-reality, but r1 is still cooling).
	m.Failed("r2", "hysteria2", diagnostics.UDPUnavailable)
	id, ok = m.NextRoute(rs, "normal")
	if !ok || id != "r3" {
		t.Fatalf("NextRoute (after family hysteria2 cooldown) = (%q, %v), want r3", id, ok)
	}
}

func TestNextRouteRespectsBudgetExhausted(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	m := New()
	m.SetNow(atTimeFn(now))

	rs := []Route{
		{RouteID: "r1", Family: "vless-reality", ModesAllowed: []string{"normal"}, BudgetTag: "normal"},
		{RouteID: "r2", Family: "vless-reality", ModesAllowed: []string{"normal"}, BudgetTag: "normal"},
	}

	m.BudgetExhausted("r1", "vless-reality")
	id, ok := m.NextRoute(rs, "normal")
	if !ok || id != "r2" {
		t.Fatalf("NextRoute should skip budget-exhausted r1; got (%q, %v)", id, ok)
	}
}

func TestNextRouteEmptyOnAllSkipped(t *testing.T) {
	m := New()
	rs := []Route{
		{RouteID: "r1", Family: "f", ModesAllowed: []string{"bulk"}, BudgetTag: "normal"},
	}
	// Mode normal but route only allows bulk → filtered out.
	if _, ok := m.NextRoute(rs, "normal"); ok {
		t.Fatalf("NextRoute should have returned ok=false")
	}
}

func TestSplitFamilyEscKeyRoundTrip(t *testing.T) {
	tests := []struct {
		fam, net string
	}{
		{"vless-reality", ""},
		{"vless-reality", "aaaa000000000000"},
		{"hysteria2", "bbbb111111111111"},
		// Family names containing '@' (unlikely but defensive).
		{"weird@family", "aaaa000000000000"},
	}
	for _, tt := range tests {
		k := familyEscKey(tt.fam, tt.net)
		gotFam, gotNet := splitFamilyEscKey(k)
		if gotFam != tt.fam || gotNet != tt.net {
			t.Fatalf("split(%q) = (%q, %q), want (%q, %q)",
				k, gotFam, gotNet, tt.fam, tt.net)
		}
	}
}
