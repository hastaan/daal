package pathmanager

import (
	"testing"
	"time"

	"daal/core/diagnostics"
)

func TestAuthFailedDoesNotCooldown(t *testing.T) {
	m := New()
	m.Attempt("r1", "vless-reality")
	m.Failed("r1", "vless-reality", diagnostics.AuthFailed)
	if m.State() != StateFailed {
		t.Fatalf("state %s, want Failed", m.State())
	}
	if ok, _ := m.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatal("auth_failed must NOT trigger cooldown (V0.3 hard rule)")
	}
}

func TestTCPResetCools30Minutes(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 19, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })
	m.Attempt("r1", "vless-reality")
	m.Failed("r1", "vless-reality", diagnostics.TCPReset)
	if ok, _ := m.CanAttempt("r1", "vless-reality"); ok {
		t.Fatal("expected route cooldown")
	}
	m.SetNow(func() time.Time { return now.Add(31 * time.Minute) })
	if ok, _ := m.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatal("expected cooldown to expire after 31 minutes")
	}
}

func TestFamilyCooldownAfterThreeFailures(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 19, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })
	for _, id := range []string{"r1", "r2", "r3"} {
		m.Attempt(id, "vless-reality")
		m.Failed(id, "vless-reality", diagnostics.TCPReset)
	}
	// A different route in the same family should now be blocked by
	// family-level cooldown.
	if ok, reason := m.CanAttempt("r-fresh", "vless-reality"); ok {
		t.Fatalf("expected family cooldown, got OK with reason %q", reason)
	}
}
