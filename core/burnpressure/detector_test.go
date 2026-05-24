package burnpressure

import (
	"testing"
	"time"
)

// TestThresholdsLocked — the v1 thresholds are constants. Any
// change is a v2 spec bump; this test is the canonical guard.
func TestThresholdsLocked(t *testing.T) {
	if DistinctFamilyMinimum != 3 {
		t.Errorf("DistinctFamilyMinimum drifted: %d", DistinctFamilyMinimum)
	}
	if WindowDuration != 30*time.Minute {
		t.Errorf("WindowDuration drifted: %s", WindowDuration)
	}
	if LadderStepMinimum != 3 {
		t.Errorf("LadderStepMinimum drifted: %d", LadderStepMinimum)
	}
}

// TestEvaluateBelowThreshold — a single family in cooldown does
// NOT promote, no matter how deep the ladder.
func TestEvaluateBelowThreshold(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	v := Evaluate(now, []Skipped{
		{Family: "vless-reality", Until: now.Add(24 * time.Hour), LadderStep: 5},
	})
	if v.ShouldPromote {
		t.Errorf("single-family cooldown should not promote: %+v", v)
	}
}

// TestEvaluateBreadthWithoutDepth — three families all at
// ladder step 1 do NOT promote (transient).
func TestEvaluateBreadthWithoutDepth(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	v := Evaluate(now, []Skipped{
		{Family: "vless-reality", Until: now.Add(5 * time.Minute), LadderStep: 1},
		{Family: "hysteria2", Until: now.Add(5 * time.Minute), LadderStep: 1},
		{Family: "trojan", Until: now.Add(5 * time.Minute), LadderStep: 1},
	})
	if v.ShouldPromote {
		t.Errorf("three transient families should not promote: %+v", v)
	}
}

// TestEvaluateBreadthAndDepth — three families with at least one
// at ladder step ≥ 3 promotes.
func TestEvaluateBreadthAndDepth(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	v := Evaluate(now, []Skipped{
		{Family: "vless-reality", Until: now.Add(24 * time.Hour), LadderStep: 5},
		{Family: "hysteria2", Until: now.Add(15 * time.Minute), LadderStep: 1},
		{Family: "trojan", Until: now.Add(15 * time.Minute), LadderStep: 2},
	})
	if !v.ShouldPromote {
		t.Errorf("three families with one deep should promote: %+v", v)
	}
	if v.Reason == "" {
		t.Error("verdict reason must be non-empty")
	}
}

// TestEvaluateExpiredCooldownsIgnored — a family whose cooldown
// has already expired does not count toward the breadth.
func TestEvaluateExpiredCooldownsIgnored(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	v := Evaluate(now, []Skipped{
		{Family: "vless-reality", Until: now.Add(-1 * time.Hour), LadderStep: 5}, // expired
		{Family: "hysteria2", Until: now.Add(15 * time.Minute), LadderStep: 1},
		{Family: "trojan", Until: now.Add(15 * time.Minute), LadderStep: 2},
	})
	if v.ShouldPromote {
		t.Errorf("expired cooldown must not count: %+v", v)
	}
}

// TestEvaluateZeroUntilIgnored — a zero-time `Until` is treated
// as "not currently skipped".
func TestEvaluateZeroUntilIgnored(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	v := Evaluate(now, []Skipped{
		{Family: "vless-reality", Until: time.Time{}, LadderStep: 5},
		{Family: "hysteria2", Until: now.Add(15 * time.Minute), LadderStep: 1},
		{Family: "trojan", Until: now.Add(15 * time.Minute), LadderStep: 2},
	})
	if v.ShouldPromote {
		t.Errorf("zero-Until family must not count: %+v", v)
	}
}

// TestEvaluateEmpty — empty input produces no promotion.
func TestEvaluateEmpty(t *testing.T) {
	v := Evaluate(time.Now(), nil)
	if v.ShouldPromote {
		t.Errorf("empty input must not promote: %+v", v)
	}
}
