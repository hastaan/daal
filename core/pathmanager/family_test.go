package pathmanager

import (
	"testing"
	"time"

	"daal/core/diagnostics"
)

func TestFamilyCooldownStepLadder(t *testing.T) {
	cases := map[int]time.Duration{
		1: 5 * time.Minute,
		2: 15 * time.Minute,
		3: 1 * time.Hour,
		4: 4 * time.Hour,
		5: 24 * time.Hour,
	}
	for n, want := range cases {
		if got := FamilyCooldownStep(n); got != want {
			t.Errorf("FamilyCooldownStep(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestFamilyCooldownStepClampsAt24h(t *testing.T) {
	for _, n := range []int{6, 7, 100, 1000} {
		if got := FamilyCooldownStep(n); got != 24*time.Hour {
			t.Errorf("FamilyCooldownStep(%d) = %v, want 24h (clamp)", n, got)
		}
	}
}

func TestFamilyCooldownStepZeroForNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		if got := FamilyCooldownStep(n); got != 0 {
			t.Errorf("FamilyCooldownStep(%d) = %v, want 0", n, got)
		}
	}
}

func TestIsFamilyClass(t *testing.T) {
	familyClass := map[diagnostics.Category]bool{
		diagnostics.TLSSNIOrCertBlockSuspected: true,
		diagnostics.UDPUnavailable:             true,
		diagnostics.QUICUnavailable:            true,

		diagnostics.TCPReset:                false,
		diagnostics.TCPConnectTimeout:       false,
		diagnostics.TLSHandshakeFailed:      false,
		diagnostics.DNSPoisoned:             false,
		diagnostics.DNSTimeout:              false,
		diagnostics.AuthFailed:              false,
		diagnostics.RouteExpired:            false,
		diagnostics.PublisherRevoked:        false,
		diagnostics.PublisherKeyChanged:     false,
		diagnostics.SubscriptionUnreachable: false,
		diagnostics.EngineCrash:             false,
		diagnostics.BundleSignatureInvalid:  false,
		diagnostics.BundleCorrupted:         false,
		diagnostics.NetworkOffline:          false,
		diagnostics.Unknown:                 false,
	}
	for cat, want := range familyClass {
		if got := IsFamilyClass(cat); got != want {
			t.Errorf("IsFamilyClass(%q) = %v, want %v", cat, got, want)
		}
	}
}

// TestFamilyClassFiresImmediateLadderStep1 asserts the hybrid policy:
// a TLS-SNI failure on a fresh family triggers a 5-minute family
// cooldown on the FIRST occurrence (no 3-failure preamble).
func TestFamilyClassFiresImmediateLadderStep1(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	m.Attempt("r1", "vless-reality")
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)

	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); ok {
		t.Fatal("expected immediate family cooldown on TLS-SNI; got OK")
	}
	// Advance past 5 min — fresh attempt should be allowed.
	m.SetNow(func() time.Time { return now.Add(5*time.Minute + time.Second) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); !ok {
		t.Fatal("expected family cooldown to expire after 5 min")
	}
}

// TestPerRouteClassRequiresThreeFailuresThenLadder asserts the
// hybrid policy for per-route classes: TCP-reset on 1 or 2 routes
// only triggers per-route cooldowns; the 3rd failure trips the
// family cooldown at ladder step 1, and a 4th post-expiry failure
// escalates to step 2.
func TestPerRouteClassRequiresThreeFailuresThenLadder(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	// First TCP-reset: per-route cooldown only, family OK.
	m.Failed("r1", "vless-reality", diagnostics.TCPReset)
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); !ok {
		t.Fatal("family should NOT be in cooldown after 1 TCP-reset")
	}
	// Second.
	m.Failed("r2", "vless-reality", diagnostics.TCPReset)
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); !ok {
		t.Fatal("family should NOT be in cooldown after 2 TCP-resets")
	}
	// Third — family cooldown trips at ladder step 1 (5 min).
	m.Failed("r3", "vless-reality", diagnostics.TCPReset)
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); ok {
		t.Fatal("family should be in cooldown after 3 TCP-resets")
	}
	// Verify step 1 = 5 min.
	m.SetNow(func() time.Time { return now.Add(4 * time.Minute) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); ok {
		t.Fatal("family cooldown should still hold at +4 min")
	}
	m.SetNow(func() time.Time { return now.Add(5*time.Minute + time.Second) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); !ok {
		t.Fatal("family cooldown should expire at +5 min (step 1)")
	}
}

// TestEscalationResetsOnFamilySuccess asserts that a successful
// Connected() on the family resets the escalation counter so the
// next family cooldown event starts at step 1 again.
func TestEscalationResetsOnFamilySuccess(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	// Drive step 1.
	m.Attempt("r1", "vless-reality")
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	// Wait out the cooldown.
	m.SetNow(func() time.Time { return now.Add(6 * time.Minute) })
	// Successful connect on the family clears escalation.
	m.Attempt("r2", "vless-reality")
	m.Connected()

	// Next family-class failure must start at step 1, NOT step 2.
	m.SetNow(func() time.Time { return now.Add(20 * time.Minute) })
	m.Attempt("r3", "vless-reality")
	m.Failed("r3", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	// Verify ladder step 1 (5 min) — i.e., cooldown expires by +25 min from base.
	m.SetNow(func() time.Time { return now.Add(20*time.Minute + 4*time.Minute) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); ok {
		t.Fatal("post-reset escalation should still hold at step 1 (+24 min)")
	}
	m.SetNow(func() time.Time { return now.Add(20*time.Minute + 5*time.Minute + time.Second) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); !ok {
		t.Fatal("post-reset escalation should expire at step 1 (+25 min)")
	}
}

// TestFamilyClassEscalatesAcrossEvents asserts that consecutive
// family-class failures climb the ladder.
func TestFamilyClassEscalatesAcrossEvents(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })

	// Step 1: 5 min.
	m.Failed("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	// Wait past step 1.
	m.SetNow(func() time.Time { return now.Add(6 * time.Minute) })
	// Step 2: 15 min.
	m.Failed("r2", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)

	m.SetNow(func() time.Time { return now.Add(6*time.Minute + 14*time.Minute) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); ok {
		t.Fatal("step 2 should still hold at +20 min")
	}
	m.SetNow(func() time.Time { return now.Add(6*time.Minute + 15*time.Minute + time.Second) })
	if ok, _ := m.CanAttempt("r-fresh", "vless-reality"); !ok {
		t.Fatal("step 2 should expire at +21 min")
	}
}
