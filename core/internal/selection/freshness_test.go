package selection

import (
	"testing"
	"time"
)

func TestShouldAttemptRefresh_FirstAttempt(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	if !ShouldAttemptRefresh(p, FreshnessState{}, now) {
		t.Error("first-ever attempt should fire")
	}
}

func TestShouldAttemptRefresh_RateLimited(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	s := FreshnessState{LastSuccessAt: now.Add(-5 * time.Minute)}
	if ShouldAttemptRefresh(p, s, now) {
		t.Error("within MinInterval should suppress")
	}
}

func TestShouldAttemptRefresh_AfterMinInterval(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	s := FreshnessState{LastSuccessAt: now.Add(-20 * time.Minute)}
	if !ShouldAttemptRefresh(p, s, now) {
		t.Error("after MinInterval should fire")
	}
}

func TestShouldAttemptRefresh_RetryBackoff(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	s := FreshnessState{LastFailureAt: now.Add(-2 * time.Minute)}
	if ShouldAttemptRefresh(p, s, now) {
		t.Error("during retry-backoff should suppress")
	}
}

func TestShouldAttemptRefresh_RetryBackoffExpired(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	s := FreshnessState{LastFailureAt: now.Add(-10 * time.Minute)}
	if !ShouldAttemptRefresh(p, s, now) {
		t.Error("after retry-backoff should fire")
	}
}

func TestShouldAttemptRefresh_OverStaleForces(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	// Last success 7h ago; MaxStaleness=6h.
	s := FreshnessState{LastSuccessAt: now.Add(-7 * time.Hour)}
	if !ShouldAttemptRefresh(p, s, now) {
		t.Error("over-stale should force")
	}
}

func TestShouldAttemptRefresh_OverStaleOverridesRetryBackoff(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	// Stale and just-failed: rule 2 (backoff) fires before rule 3 (over-stale).
	s := FreshnessState{
		LastSuccessAt: now.Add(-7 * time.Hour),
		LastFailureAt: now.Add(-1 * time.Minute),
	}
	if ShouldAttemptRefresh(p, s, now) {
		t.Error("retry-backoff should win over over-staleness in current rule order")
	}
}

func TestDefaultPolicy_LockedConstants(t *testing.T) {
	p := DefaultPolicy()
	if p.MinInterval != 15*time.Minute {
		t.Errorf("MinInterval = %v", p.MinInterval)
	}
	if p.MaxStaleness != 6*time.Hour {
		t.Errorf("MaxStaleness = %v", p.MaxStaleness)
	}
	if p.RetryBackoff != 5*time.Minute {
		t.Errorf("RetryBackoff = %v", p.RetryBackoff)
	}
}
