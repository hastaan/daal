package abi

import (
	"testing"
	"time"
)

// TestBurnPressureIgnoresExperimentalSkips — the canonical
// regression for the spec invariant: an experimental-only
// network must NOT trigger a burn-pressure auto-promotion.
//
// The 3A spec routes experimental skips through a separate
// counter (`experimental_routes_skipped` in diagnostics) and
// deliberately keeps them OUT of the failure-driven
// `SkippedFamilies()` ledger that the 2G burn-pressure detector
// consumes. This test exercises the engine-level wiring: even
// when 3 experimental routes are skipped, the burn-pressure
// detector fires zero verdicts.
func TestBurnPressureIgnoresExperimentalSkips(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	// Gate is OFF (default). Experimental routes will be filtered
	// at the rank step. We surface a non-zero per-rank-pass count
	// to simulate a network whose only candidates are
	// experimental.
	SetExperimentalRoutesSkipped(3)

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	// Burn-pressure detector consults SkippedFamilies(), which
	// is the failure-driven ledger. The pathmanager has no
	// failure-driven cooldowns at this point — only the synthetic
	// experimental skip count above. The detector MUST NOT fire.
	v := EvaluateAutoPromotion(now)
	if v.ShouldPromote {
		t.Fatalf("burn-pressure detector fired on experimental-only network: %+v", v)
	}
	if Mode() == "lifeline-strict" {
		t.Error("auto-promotion fired despite zero failure-driven cooldowns")
	}
}
