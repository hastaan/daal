package burnsandbox

import (
	"fmt"
	"testing"
	"time"
)

// TestDeterministicBurnSchedule — the same seed + same routes
// produces the same per-tick burn output across runs. This is
// the parity guarantee the verifier depends on for replay.
func TestDeterministicBurnSchedule(t *testing.T) {
	routes := make([]string, 50)
	for i := range routes {
		routes[i] = fmt.Sprintf("route-%03d", i)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	s1 := New(42)
	s2 := New(42)
	for h := 0; h < 24*30; h++ {
		hourNow := now.Add(time.Duration(h) * time.Hour)
		b1 := s1.Tick(hourNow, routes)
		b2 := s2.Tick(hourNow, routes)
		if len(b1) != len(b2) {
			t.Fatalf("hour %d: len(b1)=%d, len(b2)=%d", h, len(b1), len(b2))
		}
		for i := range b1 {
			if b1[i] != b2[i] {
				t.Errorf("hour %d index %d: %s vs %s", h, i, b1[i], b2[i])
			}
		}
	}
}

// TestBurnRateApproximatesIRBlock — over a long horizon the
// fraction of burned routes should be in the right ballpark for
// the default rate. Loose bound — the test is a smoke check, not
// a statistical assertion.
func TestBurnRateApproximatesIRBlock(t *testing.T) {
	routes := make([]string, 50)
	for i := range routes {
		routes[i] = fmt.Sprintf("route-%03d", i)
	}
	s := New(7)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for h := 0; h < 24*30; h++ {
		s.Tick(now.Add(time.Duration(h)*time.Hour), routes)
	}
	burned := len(s.Snapshot())
	// At p=0.014 over 720 hours, almost every route should burn
	// at some point (1 - (1-0.014)^720 ≈ 1.0). A run that fails
	// to burn ≥40 of 50 indicates a rate-tuning regression.
	if burned < 40 {
		t.Errorf("only %d/50 routes burned in 30 days; rate may be wrong", burned)
	}
}

// TestAlreadyBurnedNotReBurned — a burned route stays burned and
// is never returned again from Tick.
func TestAlreadyBurnedNotReBurned(t *testing.T) {
	routes := []string{"r"}
	s := New(1)
	s.BurnRatePerRoutePerHour = 1.0 // force-burn on first tick
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := s.Tick(now, routes)
	if len(first) != 1 {
		t.Fatalf("first tick: %d burns, want 1", len(first))
	}
	// Subsequent ticks: route is already burned, never returned.
	for h := 1; h < 5; h++ {
		again := s.Tick(now.Add(time.Duration(h)*time.Hour), routes)
		if len(again) != 0 {
			t.Errorf("hour %d: re-burned %v", h, again)
		}
	}
}

// TestFirstBurnTimestampStable — the FirstBurn stamp is the
// instant of the original burn, not the latest tick.
func TestFirstBurnTimestampStable(t *testing.T) {
	s := New(2)
	s.BurnRatePerRoutePerHour = 1.0
	stamp := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.Tick(stamp, []string{"r"})
	got, ok := s.FirstBurn("r")
	if !ok {
		t.Fatal("not burned")
	}
	if !got.Equal(stamp) {
		t.Errorf("first-burn time: got %s, want %s", got, stamp)
	}
}
