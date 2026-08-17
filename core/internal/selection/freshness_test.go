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

// A device whose mirrors are ALL blocked is the device this whole
// subsystem exists for, and it is also the device with no tunnel — so
// every attempt leaves the user's real address in the clear, aimed at a
// small set of enumerable hosts. A flat 5-minute retry made it a
// fixed-period beacon that polled THREE TIMES more often than a healthy
// device. It has to get quieter.
func TestEffectiveRetryBackoff_EscalatesAndCaps(t *testing.T) {
	p := DefaultPolicy()
	if got := EffectiveRetryBackoff(p, 0); got != p.RetryBackoff {
		t.Errorf("first failure = %v, want the base %v", got, p.RetryBackoff)
	}
	if got := EffectiveRetryBackoff(p, 1); got != p.RetryBackoff {
		t.Errorf("failure 1 = %v, want the base %v", got, p.RetryBackoff)
	}
	prev := EffectiveRetryBackoff(p, 1)
	for n := 2; n <= 8; n++ {
		got := EffectiveRetryBackoff(p, n)
		if got < prev {
			t.Fatalf("backoff went DOWN at failure %d: %v after %v", n, got, prev)
		}
		if got > p.MaxStaleness {
			t.Fatalf("backoff %v at failure %d exceeds MaxStaleness %v", got, n, p.MaxStaleness)
		}
		prev = got
	}
	// It settles at the ceiling rather than growing without bound; a
	// device must still check in eventually.
	if EffectiveRetryBackoff(p, 64) != p.MaxStaleness {
		t.Errorf("backoff did not settle at MaxStaleness")
	}
	if EffectiveRetryBackoff(p, 8) <= p.RetryBackoff {
		t.Errorf("eight consecutive failures still polls at the base rate")
	}
}

// The endpoint ORDER was already randomised; the attempt TIMES were
// not, and timing is the fingerprint the design notes name. Two devices
// holding the same pack must not sit on the same lattice.
func TestShouldAttemptRefresh_JitterDelaysButNeverAdvances(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	base := FreshnessState{LastSuccessAt: now.Add(-p.MinInterval)}

	if !ShouldAttemptRefresh(p, base, now) {
		t.Fatal("an un-jittered device at exactly MinInterval should fire")
	}
	jittered := base
	jittered.JitterOffset = 3 * time.Minute
	if ShouldAttemptRefresh(p, jittered, now) {
		t.Fatal("a jittered device fired on the un-jittered lattice")
	}
	if !ShouldAttemptRefresh(p, jittered, now.Add(3*time.Minute)) {
		t.Fatal("the jittered device never fired")
	}

	// A corrupt or hostile negative offset must not pull a due time
	// EARLIER — that would make a damaged device the loudest one on the
	// network.
	early := base
	early.JitterOffset = -time.Hour
	if ShouldAttemptRefresh(p, early, now.Add(-p.MinInterval)) {
		t.Fatal("a negative jitter offset advanced the due time")
	}

	// And it is clamped to MaxJitter, so a bad persisted value cannot
	// silence a device indefinitely.
	huge := base
	huge.JitterOffset = 100 * time.Hour
	if !ShouldAttemptRefresh(p, huge, now.Add(p.MaxJitter)) {
		t.Fatal("an absurd jitter offset was not clamped to MaxJitter")
	}
}

// Escalation must also show up through the public trigger, not only in
// the helper: the failure count is persisted precisely so both the
// planner and the policy read the same number.
func TestShouldAttemptRefresh_HonoursTheEscalatedGap(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	st := FreshnessState{LastFailureAt: now.Add(-20 * time.Minute), ConsecutiveFailures: 5}
	if ShouldAttemptRefresh(p, st, now) {
		t.Fatalf("fired 20 minutes after the 5th consecutive failure; the gap should be %v",
			EffectiveRetryBackoff(p, 5))
	}
	one := FreshnessState{LastFailureAt: now.Add(-20 * time.Minute), ConsecutiveFailures: 1}
	if !ShouldAttemptRefresh(p, one, now) {
		t.Fatal("a single failure should still retry after the base backoff")
	}
}
