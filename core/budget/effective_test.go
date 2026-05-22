package budget

import (
	"testing"
)

func TestModeFactor(t *testing.T) {
	cases := map[string]float64{
		"lifeline":        0.33,
		"normal":          1.0,
		"bulk":            1.0,
		"lifeline-strict": 0.33,
		"unknown":         1.0, // defensive default
		"":                1.0, // empty == default normal
	}
	for mode, want := range cases {
		got := ModeFactor(mode)
		if got != want {
			t.Errorf("ModeFactor(%q) = %v, want %v", mode, got, want)
		}
	}
}

func TestApplyFactorUnlimitedStaysUnlimited(t *testing.T) {
	for _, f := range []float64{0.33, 1.0, 0.5, 2.0} {
		if applyFactor(0, f) != 0 {
			t.Errorf("applyFactor(0, %v) should stay 0", f)
		}
	}
}

func TestApplyFactorRoundsTowardZero(t *testing.T) {
	// 50 MiB × 0.33 = 17301504.0 (uint64 cast). Verify exact math.
	got := applyFactor(50*MiB, 0.33)
	want := uint64(float64(50*MiB) * 0.33)
	if got != want {
		t.Errorf("applyFactor(50 MiB, 0.33) = %d, want %d", got, want)
	}
}

// TestEffectiveCapForEveryTagAcrossEveryMode asserts the V2.2
// multiplier matrix for every (tag × mode) pair. bulk-capable stays
// 0/0 in every mode; finite caps scale by the factor.
func TestEffectiveCapForEveryTagAcrossEveryMode(t *testing.T) {
	store := newFakeStore()
	e := New(store, clock("2026-04-26T12:00:00Z"))

	// Seed each tag against a unique route_id.
	tagFor := map[string]string{
		"r-em":  TagEmergency,
		"r-lo":  TagLifelineOnly,
		"r-low": TagLow,
		"r-no":  TagNormal,
		"r-bc":  TagBulkCapable,
		"r-ex":  TagExperimental,
	}
	for rid, tag := range tagFor {
		if err := e.SetTag(rid, tag); err != nil {
			t.Fatalf("SetTag(%s, %s): %v", rid, tag, err)
		}
	}

	modes := []string{"lifeline", "normal", "bulk", "lifeline-strict"}
	for _, mode := range modes {
		f := ModeFactor(mode)
		for rid, tag := range tagFor {
			full, _ := FullCapFor(tag)
			got := e.EffectiveCap(rid, mode)
			wantHourly := applyFactor(full.Hourly, f)
			wantSession := applyFactor(full.Session, f)
			if got.Hourly != wantHourly {
				t.Errorf("EffectiveCap(%s, %s).Hourly = %d, want %d", rid, mode, got.Hourly, wantHourly)
			}
			if got.Session != wantSession {
				t.Errorf("EffectiveCap(%s, %s).Session = %d, want %d", rid, mode, got.Session, wantSession)
			}
		}
	}
}

func TestEffectiveCapBulkCapableUnchanged(t *testing.T) {
	store := newFakeStore()
	e := New(store, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r-bc", TagBulkCapable)
	for _, mode := range []string{"lifeline", "normal", "bulk", "lifeline-strict"} {
		got := e.EffectiveCap("r-bc", mode)
		if got.Hourly != 0 || got.Session != 0 {
			t.Errorf("bulk-capable in %s mode: Hourly=%d Session=%d, want 0/0",
				mode, got.Hourly, got.Session)
		}
	}
}

func TestEffectiveCapLifelineThirdsCorrectly(t *testing.T) {
	store := newFakeStore()
	e := New(store, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r-em", TagEmergency)
	got := e.EffectiveCap("r-em", "lifeline")
	wantH := uint64(float64(50*MiB) * 0.33)
	wantS := uint64(float64(200*MiB) * 0.33)
	if got.Hourly != wantH || got.Session != wantS {
		t.Errorf("emergency lifeline: Hourly=%d Session=%d, want %d/%d", got.Hourly, got.Session, wantH, wantS)
	}
}

// === Engine.SetMode integration ===

func TestSetModeDoesNotResetCounters(t *testing.T) {
	store := newFakeStore()
	e := New(store, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r1", TagEmergency)
	if err := e.Add("r1", 5*MiB); err != nil {
		t.Fatalf("Add: %v", err)
	}
	e.SetMode("lifeline")
	if got := store.consume["r1"]; got != 5*MiB {
		t.Errorf("hourly counter changed on SetMode: got %d, want %d", got, 5*MiB)
	}
}

func TestSetModeDoesNotBumpSessionEpoch(t *testing.T) {
	store := newFakeStore()
	e := New(store, clock("2026-04-26T12:00:00Z"))
	beforeEpoch := e.SessionEpoch()
	e.SetMode("lifeline")
	e.SetMode("normal")
	e.SetMode("bulk")
	if got := e.SessionEpoch(); got != beforeEpoch {
		t.Errorf("session epoch advanced on SetMode: before=%d after=%d", beforeEpoch, got)
	}
}

// TestAddRespectsLifelineMultiplier exhausts an emergency-tagged
// route in lifeline mode at the *effective* hourly cap (50 MiB ×
// 0.33 = 16.5 MiB), not the raw 50 MiB cap.
func TestAddRespectsLifelineMultiplier(t *testing.T) {
	store := newFakeStore()
	e := New(store, clock("2026-04-26T12:00:00Z"))
	_ = e.SetTag("r1", TagEmergency)
	e.SetMode("lifeline")

	hourCap := applyFactor(50*MiB, 0.33)
	// Charge just under the effective cap → fits.
	if err := e.Add("r1", hourCap-1); err != nil {
		t.Fatalf("Add %d (cap-1): %v", hourCap-1, err)
	}
	// One more byte → exhaustion at the lifeline-multiplied cap.
	if err := e.Add("r1", 2); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted at lifeline-cap, got %v", err)
	}
	if got := store.consume["r1"]; got != hourCap {
		t.Errorf("consumed clamped wrong: got %d, want %d", got, hourCap)
	}
}
