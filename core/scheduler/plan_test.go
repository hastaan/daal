package scheduler

import (
	"reflect"
	"testing"
	"time"
)

// fakeSource is the canonical test stub for Source; tests construct
// one directly so failure messages are easy to read.
type fakeSource struct {
	subs    []SubscriptionState
	pubs    []PublisherState
	bs      time.Time
	budgRst time.Time // Phase 2A
	netSwp  time.Time // Wave 5: last per-network-memory sweep
	packs   []RelayPackState
}

func (f fakeSource) Subscriptions() []SubscriptionState         { return f.subs }
func (f fakeSource) PublishersWithRevocation() []PublisherState { return f.pubs }
func (f fakeSource) LastBootstrapRefresh() time.Time            { return f.bs }
func (f fakeSource) LastBudgetReset() time.Time                 { return f.budgRst }
func (f fakeSource) LastNetmemSweep() time.Time                 { return f.netSwp }
func (f fakeSource) RelayPacks() []RelayPackState               { return f.packs }

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func TestPlan_NeverRefreshedIsAlwaysDue(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s1", ProfileUpdateMin: 1440},
		},
		pubs: []PublisherState{
			{PublisherID: "p1"},
		},
	}
	due := Plan(src, DefaultCadence(), now)
	// 5 = sub + rev + bootstrap + budget-reset + netmem-sweep
	// (all never-fired ⇒ due)
	if len(due) != 5 {
		t.Fatalf("want 5 due (sub+rev+bootstrap+budget-reset+netmem-sweep), got %d: %+v", len(due), due)
	}
}

func TestPlan_StableOrdering(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s2", ProfileUpdateMin: 60},
			{SubscriptionID: "s1", ProfileUpdateMin: 60},
		},
		pubs: []PublisherState{
			{PublisherID: "pB"},
			{PublisherID: "pA"},
		},
	}
	got := Plan(src, DefaultCadence(), now)
	want := []string{
		"bootstrap:",
		"budget-reset:",
		"netmem-sweep:",
		"revocation:pA",
		"revocation:pB",
		"subscription:s1",
		"subscription:s2",
	}
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d: %+v", len(got), len(want), got)
	}
	for i, a := range got {
		key := string(a.Kind) + ":" + a.Ref
		if key != want[i] {
			t.Errorf("[%d] got %q want %q", i, key, want[i])
		}
	}
}

func TestPlan_RecentlyRefreshedIsNotDue(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	just30MinAgo := now.Add(-30 * time.Minute)
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s1", ProfileUpdateMin: 60, LastGoodRefresh: just30MinAgo},
		},
		pubs: []PublisherState{
			{PublisherID: "p1", LastRevocationCheck: just30MinAgo},
		},
		bs:      just30MinAgo,
		budgRst: just30MinAgo, // budget-reset cadence is 1 h
		netSwp:  just30MinAgo, // netmem-sweep cadence is 24 h
	}
	due := Plan(src, DefaultCadence(), now)
	if len(due) != 0 {
		t.Fatalf("want 0 due (all within window), got %d: %+v", len(due), due)
	}
}

func TestPlan_SubscriptionCadenceClamp(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	// profile_update_min=10 must be clamped UP to 60; a row refreshed
	// 30 minutes ago at the unclamped 10-minute interval would be due
	// but at the clamped 60-minute interval is NOT due.
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s1", ProfileUpdateMin: 10, LastGoodRefresh: now.Add(-30 * time.Minute)},
		},
	}
	due := Plan(src, DefaultCadence(), now)
	// Subscription should NOT be due (clamped). Bootstrap,
	// budget-reset and netmem-sweep are due (never fired).
	for _, a := range due {
		if a.Kind == KindSubscription {
			t.Fatalf("s1 should not be due (clamped to 60m, refreshed 30m ago): %+v", due)
		}
	}
	if len(due) != 3 {
		t.Fatalf("expected 3 due (bootstrap + budget-reset + netmem-sweep), got %+v", due)
	}
}

func TestPlan_SubscriptionCadenceUpperClamp(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	// 100 days = 144000 minutes; clamped DOWN to 7×24×60 = 10080.
	tenWeeksAgo := now.Add(-100 * 24 * time.Hour)
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s1", ProfileUpdateMin: 144000, LastGoodRefresh: tenWeeksAgo},
		},
	}
	due := Plan(src, DefaultCadence(), now)
	// The subscription was last refreshed 100 days ago, even at the
	// MAX cadence of 7 days it must be due.
	found := false
	for _, a := range due {
		if a.Kind == KindSubscription && a.Ref == "s1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected s1 due (last refresh 100 d ago > 7 d clamp), got %+v", due)
	}
}

func TestAllNextDues_IncludesEverything(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s1", ProfileUpdateMin: 60, LastGoodRefresh: now.Add(-90 * time.Minute)},
			{SubscriptionID: "s2", ProfileUpdateMin: 1440, LastGoodRefresh: now},
		},
		pubs: []PublisherState{
			{PublisherID: "p1", LastRevocationCheck: now.Add(-1 * time.Hour)},
			{PublisherID: "p2"},
		},
		bs: now.Add(-2 * time.Hour),
	}
	all := AllNextDues(src, DefaultCadence(), now)
	if len(all) != 7 {
		t.Fatalf("want 7 (2 sub + 2 rev + bootstrap + budget-reset + netmem-sweep), got %d: %+v",
			len(all), all)
	}
}

func TestPlan_DeterministicAcrossInvocations(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s2", ProfileUpdateMin: 60},
			{SubscriptionID: "s1", ProfileUpdateMin: 60},
			{SubscriptionID: "s3", ProfileUpdateMin: 60},
		},
		pubs: []PublisherState{
			{PublisherID: "p2"},
			{PublisherID: "p1"},
		},
	}
	a := Plan(src, DefaultCadence(), now)
	b := Plan(src, DefaultCadence(), now)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("Plan is not deterministic:\n  a=%+v\n  b=%+v", a, b)
	}
}
