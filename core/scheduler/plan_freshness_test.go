package scheduler

import (
	"context"
	"testing"
	"time"

	"daal/core/internal/selection"
)

// The freshness kind is the one scheduled action that talks to an
// endpoint whose whole security problem is that it is small, unique
// and pollable. So these tests are about restraint: what must NOT
// happen, and how often.

func TestPlan_FreshnessNeverAttemptedIsDue(t *testing.T) {
	now := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{{RelayPackID: "rp-1"}}}
	due := Plan(src, DefaultCadence(), now)
	if len(due) == 0 {
		t.Fatal("a pack that has never been polled must be due")
	}
	found := false
	for _, a := range due {
		if a.Kind == KindFreshness && a.Ref == "rp-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no freshness action in %+v", due)
	}
}

// THE TICK-STORM TEST. The pump ticks once a minute (desktop) and also
// at tunnel-up (Android). A pack that just succeeded must produce
// exactly zero fetches until MinInterval has passed, whatever the tick
// rate — otherwise the "cadence" is the tick rate and the endpoint
// gets 60 polls an hour from every recipient of the publisher.
func TestPlan_FreshnessFloorSurvivesATickStorm(t *testing.T) {
	start := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{
		{RelayPackID: "rp-1", LastSuccessAt: start},
	}}
	cad := DefaultCadence()
	fires := 0
	for i := 1; i <= 60; i++ {
		now := start.Add(time.Duration(i) * time.Minute)
		for _, a := range Plan(src, cad, now) {
			if a.Kind == KindFreshness {
				fires++
			}
		}
	}
	// 60 one-minute ticks over a 15-minute floor: the pack becomes
	// due at +15 and stays due (the stub never advances its stamp),
	// so the count is bounded by the ticks past the floor, not by the
	// tick count itself. What must never happen is a fire before +15.
	firstFire := 0
	for i := 1; i <= 60; i++ {
		now := start.Add(time.Duration(i) * time.Minute)
		hit := false
		for _, a := range Plan(src, cad, now) {
			if a.Kind == KindFreshness {
				hit = true
			}
		}
		if hit {
			firstFire = i
			break
		}
	}
	if firstFire != int(selection.DefaultPolicy().MinInterval/time.Minute) {
		t.Fatalf("first freshness fire at +%d min, want +%d",
			firstFire, int(selection.DefaultPolicy().MinInterval/time.Minute))
	}
	if fires == 0 {
		t.Fatal("the pack never became due at all — the floor turned into a ceiling")
	}
}

func TestPlan_FreshnessRetryBackoffSuppresses(t *testing.T) {
	start := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{
		{RelayPackID: "rp-1", LastFailureAt: start},
	}}
	cad := DefaultCadence()
	if len(freshnessDue(Plan(src, cad, start.Add(time.Minute)))) != 0 {
		t.Fatal("a pack that just failed must not be retried one minute later")
	}
	if len(freshnessDue(Plan(src, cad, start.Add(6*time.Minute)))) != 1 {
		t.Fatal("the retry backoff must expire")
	}
}

// A failure stamp suppresses even an over-stale pack. That ordering is
// the trigger policy's, and the planner must not quietly disagree with
// it — two gates that disagree is how a "rate limited" endpoint gets
// hammered by the one caller that took the other branch.
func TestPlan_FreshnessRetryBackoffBeatsStaleness(t *testing.T) {
	now := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{{
		RelayPackID:   "rp-1",
		LastSuccessAt: now.Add(-48 * time.Hour), // far past MaxStaleness
		LastFailureAt: now.Add(-time.Minute),    // but inside RetryBackoff
	}}}
	if len(freshnessDue(Plan(src, DefaultCadence(), now))) != 0 {
		t.Fatal("retry backoff must suppress an over-stale pack")
	}
}

func TestPlan_FreshnessForcesWhenOverStale(t *testing.T) {
	now := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{{
		RelayPackID:   "rp-1",
		LastSuccessAt: now.Add(-7 * time.Hour), // > MaxStaleness (6h)
	}}}
	if len(freshnessDue(Plan(src, DefaultCadence(), now))) != 1 {
		t.Fatal("an over-stale pack must force a refresh")
	}
}

// A hand-built Cadence with a zero Freshness policy must NOT mean
// "poll on every tick". The zero value of a duration is the most
// dangerous default this package has.
func TestPlan_ZeroFreshnessPolicyIsNotEveryTick(t *testing.T) {
	start := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{
		{RelayPackID: "rp-1", LastSuccessAt: start},
	}}
	cad := Cadence{Revocation: 6 * time.Hour, Bootstrap: 24 * time.Hour, BudgetReset: time.Hour}
	if len(freshnessDue(Plan(src, cad, start.Add(time.Minute)))) != 0 {
		t.Fatal("a zero-valued freshness policy became a per-tick poll")
	}
}

func TestPlan_FreshnessSkipsEmptyPackID(t *testing.T) {
	now := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{{RelayPackID: ""}}}
	if len(freshnessDue(Plan(src, DefaultCadence(), now))) != 0 {
		t.Fatal("a pack with no id must not be scheduled")
	}
}

func TestAllNextDues_ReportsFreshness(t *testing.T) {
	now := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{
		{RelayPackID: "rp-1", LastSuccessAt: now.Add(-time.Minute)},
	}}
	all := AllNextDues(src, DefaultCadence(), now)
	for _, a := range all {
		if a.Kind == KindFreshness && a.Ref == "rp-1" {
			want := now.Add(-time.Minute).Add(selection.DefaultPolicy().MinInterval)
			if !a.NextDue.Equal(want) {
				t.Fatalf("next due %s, want %s", a.NextDue, want)
			}
			return
		}
	}
	t.Fatal("freshness missing from the status projection")
}

func TestTick_DispatchesFreshness(t *testing.T) {
	now := ts("2026-08-17T12:00:00Z")
	src := fakeSource{packs: []RelayPackState{{RelayPackID: "rp-9"}}}
	rec := newRec()
	s := New(src, rec, DefaultCadence())
	s.Tick(now)
	found := false
	for _, c := range rec.calls {
		if c == "freshness:rp-9" {
			found = true
		}
	}
	if !found {
		t.Fatalf("freshness not dispatched: %v", rec.calls)
	}
	_ = context.Background()
}

func freshnessDue(actions []Action) []Action {
	var out []Action
	for _, a := range actions {
		if a.Kind == KindFreshness {
			out = append(out, a)
		}
	}
	return out
}
