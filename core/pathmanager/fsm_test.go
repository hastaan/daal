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

// Revisions 2 and 3 of the failure taxonomy: a path that is only slow,
// and a relay that answers but reaches nothing, are never held against
// the route — and three of them in an hour must not cool the family
// down either (every route to one relay shares a relay_no_egress).
func TestFailed_SlowPathAndRelayNoEgressNeverCoolDown(t *testing.T) {
	for _, cat := range []diagnostics.Category{diagnostics.PathTooSlow, diagnostics.RelayNoEgress} {
		m := New()
		for i := 0; i < 5; i++ {
			m.Attempt("r1", "vless-reality")
			m.Failed("r1", "vless-reality", cat)
			if ok, why := m.CanAttempt("r1", "vless-reality"); !ok {
				t.Fatalf("%s, failure %d: %s", cat, i+1, why)
			}
		}
		if ok, why := m.CanAttempt("r2", "vless-reality"); !ok {
			t.Fatalf("%s cooled the whole family down: %s", cat, why)
		}
		if got := m.RouteHealth(); len(got) != 1 || got[0].InCooldown || got[0].CooldownReason != cat {
			t.Fatalf("%s: route health %+v; want the reason recorded and no cooldown", cat, got)
		}
	}
}

// A candidate of an automatic pass cools its own route down and never
// feeds the three-in-an-hour family count; a family-class category
// still cools the family at once.
func TestFailedCandidate_CoolsTheRouteNotTheFamilyCount(t *testing.T) {
	m := New()
	now := time.Date(2026, 4, 26, 19, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })
	for _, id := range []string{"a", "b", "c", "d"} {
		m.FailedCandidate(id, "vless-reality", diagnostics.TCPConnectTimeout)
	}
	if ok, _ := m.CanAttempt("a", "vless-reality"); ok {
		t.Fatal("the route itself must cool down")
	}
	if ok, why := m.CanAttempt("other", "vless-reality"); !ok {
		t.Fatalf("four candidate failures cooled the whole family: %s", why)
	}
	if len(m.SkippedFamilies()) != 0 {
		t.Fatalf("family cooldown: %+v", m.SkippedFamilies())
	}
	m.FailedCandidate("u", "hysteria2", diagnostics.UDPUnavailable)
	if ok, _ := m.CanAttempt("other-u", "hysteria2"); ok {
		t.Fatal("a family-class category must still cool the family")
	}
}

// Forgive lifts the route's cooldown and keeps the reason.
func TestForgive_LiftsTheCooldownAndKeepsTheReason(t *testing.T) {
	m := New()
	m.Failed("r1", "vless-reality", diagnostics.TCPConnectTimeout)
	m.Forgive("r1")
	if ok, why := m.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatalf("still cooling: %s", why)
	}
	h := m.RouteHealth()
	if len(h) != 1 || h[0].InCooldown || h[0].CooldownReason != diagnostics.TCPConnectTimeout {
		t.Fatalf("health: %+v", h)
	}
}

// ForgiveFamily lifts the family's cooldown on the active network only,
// and leaves route cooldowns alone.
func TestForgiveFamily_LiftsTheFamilyOnThisNetworkOnly(t *testing.T) {
	m := New()
	m.SetActiveNetwork("net-b")
	m.FailedCandidate("rb", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	m.SetActiveNetwork("net-a")
	m.FailedCandidate("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	if ok, _ := m.CanAttempt("r2", "vless-reality"); ok {
		t.Fatal("precondition: a hello block cools the family")
	}
	m.ForgiveFamily("vless-reality")
	if ok, why := m.CanAttempt("r2", "vless-reality"); !ok {
		t.Fatalf("family still cooling: %s", why)
	}
	if ok, _ := m.CanAttempt("r1", "vless-reality"); ok {
		t.Fatal("the route's own cooldown must stay")
	}
	m.SetActiveNetwork("net-b")
	if ok, _ := m.CanAttempt("r2", "vless-reality"); ok {
		t.Fatal("another network's family cooldown was lifted")
	}
}

// ForgiveFamily takes back one step: an escalation the family earned
// before stays.
func TestForgiveFamily_TakesBackOneStep(t *testing.T) {
	m := New()
	m.SetActiveNetwork("net-a")
	m.FailedCandidate("r1", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	m.FailedCandidate("r2", "vless-reality", diagnostics.TLSSNIOrCertBlockSuspected)
	m.ForgiveFamily("vless-reality")
	if ok, _ := m.CanAttempt("r9", "vless-reality"); !ok {
		t.Fatal("the family is still cooling")
	}
	if got := m.familyEscalation[familyEscKey("vless-reality", "net-a")]; got != 1 {
		t.Fatalf("escalation %d, want 1 (one step taken back)", got)
	}
}

// EndAttempt closes the attempt in flight without charging the route.
func TestEndAttempt_NoCooldownNoHealth(t *testing.T) {
	m := New()
	m.Attempt("r1", "vless-reality")
	m.Verifying()
	m.EndAttempt("r2", "x")
	if m.State() != StateVerifying {
		t.Fatal("ended another route's attempt")
	}
	m.EndAttempt("r1", "a changed first flight of r1 did not carry")
	if m.State() != StateFailed || m.LastReason() != "a changed first flight of r1 did not carry" {
		t.Fatalf("state %v reason %q", m.State(), m.LastReason())
	}
	if ok, _ := m.CanAttempt("r1", "vless-reality"); !ok {
		t.Fatal("the route was cooled")
	}
	for _, h := range m.RouteHealth() {
		if h.RouteID == "r1" {
			t.Fatalf("a health entry was written: %+v", h)
		}
	}
}
