package abi

import (
	"strings"
	"testing"
	"time"

	"daal/core/pathmanager"
)

// TestAutoPromotionDefaultsEnabled — engine_init starts with the
// preference enabled; the diagnostic field reflects it.
func TestAutoPromotionDefaultsEnabled(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if !AutoPromotionEnabled() {
		t.Error("auto-promotion should default to enabled")
	}
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"auto_promotion_enabled": true`) {
		t.Errorf("diagnostics missing/wrong auto_promotion_enabled:\n%s", body)
	}
	// Last-fired field must be ABSENT until the detector fires.
	if strings.Contains(body, "auto_promotion_last_fired_at") {
		t.Error("auto_promotion_last_fired_at must not appear before first fire")
	}
}

// TestSetAutoPromotionRoundTrip — flipping the flag round-trips
// through diagnostics.
func TestSetAutoPromotionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	SetAutoPromotion(false)
	if AutoPromotionEnabled() {
		t.Error("flag did not flip to false")
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, `"auto_promotion_enabled": false`) {
		t.Errorf("diagnostics did not reflect false: %s", body)
	}
	SetAutoPromotion(true)
	if !AutoPromotionEnabled() {
		t.Error("flag did not flip back to true")
	}
}

// TestEvaluateAutoPromotionFiresOnBurn — drives the pathmanager
// into a state where three families are skipped with one at
// ladder ≥ 3, then evaluates and asserts the engine flipped to
// lifeline-strict via the auto path.
func TestEvaluateAutoPromotionFiresOnBurn(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	c := mustCore()
	// Drive three families into skipped state, one of them deep.
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c.pm.SetNow(func() time.Time { return now })
	deepUntil := now.Add(24 * time.Hour) // ladder step 5 is 24h
	shallowUntil := now.Add(15 * time.Minute)
	c.pm.SetSkippedForTest("vless-reality", deepUntil, 5)
	c.pm.SetSkippedForTest("hysteria2", shallowUntil, 1)
	c.pm.SetSkippedForTest("trojan", shallowUntil, 2)

	verdict := EvaluateAutoPromotion(now)
	if !verdict.ShouldPromote {
		t.Fatalf("expected promote verdict; got %+v", verdict)
	}
	if Mode() != "lifeline-strict" {
		t.Fatalf("expected mode=lifeline-strict after auto-promotion; got %q", Mode())
	}
	body, _ := ExportDiagnostics()
	if !strings.Contains(body, "auto_promotion_last_fired_at") {
		t.Errorf("diagnostics missing last_fired_at after fire:\n%s", body)
	}
	if !strings.Contains(body, "lifeline_strict_active_since") {
		t.Error("lifeline_strict_active_since missing after auto-promotion")
	}
}

// TestEvaluateAutoPromotionRespectsManualOverride — the user's
// manual SetMode in the same hour-bucket suppresses auto-promotion.
func TestEvaluateAutoPromotionRespectsManualOverride(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	// Stamp the manual-override hour by way of the user-facing
	// SetMode (e.g. user picked Bulk five minutes ago).
	clockOverride.Store(now.Unix())
	defer clockOverride.Store(0)
	if err := SetMode("bulk"); err != nil {
		t.Fatal(err)
	}

	c := mustCore()
	c.pm.SetNow(func() time.Time { return now })
	c.pm.SetSkippedForTest("vless-reality", now.Add(24*time.Hour), 5)
	c.pm.SetSkippedForTest("hysteria2", now.Add(15*time.Minute), 1)
	c.pm.SetSkippedForTest("trojan", now.Add(15*time.Minute), 2)

	v := EvaluateAutoPromotion(now)
	if v.ShouldPromote {
		t.Errorf("manual override must suppress auto-promotion; got %+v", v)
	}
	if Mode() != "bulk" {
		t.Errorf("manual mode lost: %q", Mode())
	}
}

// TestEvaluateAutoPromotionDisabledFlag — when the flag is off,
// the verdict is empty and no flip happens even if the burn
// signal would otherwise fire.
func TestEvaluateAutoPromotionDisabledFlag(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	SetAutoPromotion(false)

	c := mustCore()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c.pm.SetNow(func() time.Time { return now })
	c.pm.SetSkippedForTest("vless-reality", now.Add(24*time.Hour), 5)
	c.pm.SetSkippedForTest("hysteria2", now.Add(15*time.Minute), 1)
	c.pm.SetSkippedForTest("trojan", now.Add(15*time.Minute), 2)

	v := EvaluateAutoPromotion(now)
	if v.ShouldPromote {
		t.Errorf("disabled flag must short-circuit: %+v", v)
	}
	if Mode() == "lifeline-strict" {
		t.Error("auto-promotion fired despite disabled flag")
	}
}

// TestEvaluateAutoPromotionDebouncesPerHour — the detector fires
// at most once per hour-bucket.
func TestEvaluateAutoPromotionDebouncesPerHour(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	c := mustCore()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c.pm.SetNow(func() time.Time { return now })
	c.pm.SetSkippedForTest("vless-reality", now.Add(24*time.Hour), 5)
	c.pm.SetSkippedForTest("hysteria2", now.Add(15*time.Minute), 1)
	c.pm.SetSkippedForTest("trojan", now.Add(15*time.Minute), 2)

	v1 := EvaluateAutoPromotion(now)
	if !v1.ShouldPromote {
		t.Fatalf("first evaluation should promote: %+v", v1)
	}
	// Move user back to normal manually (different hour bucket so
	// the manual override doesn't suppress the second evaluation
	// in the next hour). At the same hour, a second evaluation
	// inside the same hour-bucket must not fire again.
	v2 := EvaluateAutoPromotion(now.Add(5 * time.Minute))
	if v2.ShouldPromote {
		t.Errorf("debounce within same hour failed: %+v", v2)
	}
}

// TestEvaluateAutoPromotionAlreadyStrictNoOp — when already in
// lifeline-strict, the evaluator short-circuits.
func TestEvaluateAutoPromotionAlreadyStrictNoOp(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	// Fast-forward to a future hour so the manual SetMode below
	// doesn't poison the override hour for our evaluation hour.
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	clockOverride.Store(now.Add(-2 * time.Hour).Unix())
	if err := SetMode("lifeline-strict"); err != nil {
		t.Fatal(err)
	}
	clockOverride.Store(0)

	v := EvaluateAutoPromotion(now)
	if v.ShouldPromote {
		t.Errorf("already-strict must short-circuit: %+v", v)
	}
}

var _ = pathmanager.SkippedFamily{} // keep import live across edits
