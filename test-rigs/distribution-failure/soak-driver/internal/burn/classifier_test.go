package burn

import (
	"testing"
	"time"
)

// TestThresholdsLocked — lock the v1 classifier thresholds.
func TestThresholdsLocked(t *testing.T) {
	if WindowMinutes != 10 {
		t.Errorf("WindowMinutes drifted: %d", WindowMinutes)
	}
	if AggregateFailRate != 0.50 {
		t.Errorf("AggregateFailRate drifted: %f", AggregateFailRate)
	}
}

// TestClassifierBurnedAboveThreshold — > 50 % failure rate in
// the window flips the verdict.
func TestClassifierBurnedAboveThreshold(t *testing.T) {
	c := New()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		c.Record(Observation{
			ClientID: "c-0001",
			RouteID:  "r-1",
			At:       now.Add(-time.Duration(i) * time.Minute),
			Fail:     i < 7, // 7/10 fails
		})
	}
	if !c.Burned("r-1", now) {
		t.Error("expected burned at 70 % failure rate")
	}
}

// TestClassifierNotBurnedBelowThreshold — ≤ 50 % failure rate
// does NOT flip the verdict.
func TestClassifierNotBurnedBelowThreshold(t *testing.T) {
	c := New()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		c.Record(Observation{
			ClientID: "c-0001",
			RouteID:  "r-1",
			At:       now.Add(-time.Duration(i) * time.Minute),
			Fail:     i < 5, // 5/10 = 0.5, not strictly above
		})
	}
	if c.Burned("r-1", now) {
		t.Error("expected NOT burned at 50 % failure rate (strictly >)")
	}
}

// TestClassifierWindowExcludesOldData — observations outside the
// 10-minute sliding window are ignored.
func TestClassifierWindowExcludesOldData(t *testing.T) {
	c := New()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// 10 fails 1 hour ago — fully outside window.
	for i := 0; i < 10; i++ {
		c.Record(Observation{RouteID: "r-1", At: now.Add(-1 * time.Hour), Fail: true})
	}
	// Only 2 successes in the last 5 min.
	for i := 0; i < 2; i++ {
		c.Record(Observation{RouteID: "r-1", At: now.Add(-time.Duration(i+1) * time.Minute), Fail: false})
	}
	if c.Burned("r-1", now) {
		t.Error("old fails outside window must be ignored")
	}
}

// TestVerifyPrimaryPassWhenBurnIntervalAboveCadence — a route
// burned 49 hours after publish passes the 48-hour cadence.
func TestVerifyPrimaryPassWhenBurnIntervalAboveCadence(t *testing.T) {
	publish := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	burn := publish.Add(49 * time.Hour)
	rv := []RouteVerdict{{
		RouteID:        "r-1",
		FirstPublishAt: publish,
		FirstBurnAt:    burn,
		BurnInterval:   burn.Sub(publish),
		Burned:         true,
	}}
	a := Verify(rv, 48*time.Hour, true, true, true, true)
	if !a.AllPass() {
		t.Errorf("expected pass, got %+v", a)
	}
}

// TestVerifyPrimaryFailsWhenBurnIntervalBelowCadence — a route
// burned 47 hours after publish fails the 48-hour cadence.
func TestVerifyPrimaryFailsWhenBurnIntervalBelowCadence(t *testing.T) {
	publish := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	burn := publish.Add(47 * time.Hour)
	rv := []RouteVerdict{{
		RouteID:        "r-1",
		FirstPublishAt: publish,
		FirstBurnAt:    burn,
		BurnInterval:   burn.Sub(publish),
		Burned:         true,
	}}
	a := Verify(rv, 48*time.Hour, true, true, true, true)
	if a.PassByDirectoryRotation {
		t.Error("expected primary metric fail")
	}
	if a.AllPass() {
		t.Error("expected aggregate fail")
	}
	if len(a.Failures) == 0 {
		t.Error("expected failure detail messages")
	}
}

// TestVerifyPropagatesAuxiliaryFailures — when the rotation /
// budget / failure-reason / auto-promotion booleans are false,
// the aggregate fails even if the primary metric passes.
func TestVerifyPropagatesAuxiliaryFailures(t *testing.T) {
	a := Verify(nil, 48*time.Hour, false, true, true, true)
	if a.AllPass() {
		t.Error("rotation false should fail aggregate")
	}
	a = Verify(nil, 48*time.Hour, true, false, true, true)
	if a.AllPass() {
		t.Error("budget false should fail aggregate")
	}
	a = Verify(nil, 48*time.Hour, true, true, false, true)
	if a.AllPass() {
		t.Error("failure-reason false should fail aggregate")
	}
	a = Verify(nil, 48*time.Hour, true, true, true, false)
	if a.AllPass() {
		t.Error("auto-promotion false should fail aggregate")
	}
}
