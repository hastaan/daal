package scheduler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// recordingExecutor logs every invocation in call order and reports
// success unless the test injects a failing kind.
type recordingExecutor struct {
	calls []string
	fail  map[Kind]bool
}

func newRec() *recordingExecutor {
	return &recordingExecutor{fail: map[Kind]bool{}}
}

func (r *recordingExecutor) RefreshSubscription(_ context.Context, id string) error {
	r.calls = append(r.calls, "subscription:"+id)
	if r.fail[KindSubscription] {
		return errFake
	}
	return nil
}

func (r *recordingExecutor) RefreshRevocation(_ context.Context, pub string) error {
	r.calls = append(r.calls, "revocation:"+pub)
	if r.fail[KindRevocation] {
		return errFake
	}
	return nil
}

func (r *recordingExecutor) RefreshBootstrap(_ context.Context) error {
	r.calls = append(r.calls, "bootstrap:")
	if r.fail[KindBootstrap] {
		return errFake
	}
	return nil
}

func (r *recordingExecutor) RefreshBudgetReset(_ context.Context, _ time.Time) error {
	r.calls = append(r.calls, "budget-reset:")
	if r.fail[KindBudgetReset] {
		return errFake
	}
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

var errFake fakeErr = "fake"

func TestTickInvokesEveryDueAction(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{{SubscriptionID: "s1", ProfileUpdateMin: 60}},
		pubs: []PublisherState{{PublisherID: "p1"}},
	}
	rec := newRec()
	s := New(src, rec, DefaultCadence())
	s.Tick(now)
	want := []string{"bootstrap:", "budget-reset:", "revocation:p1", "subscription:s1"}
	if len(rec.calls) != len(want) {
		t.Fatalf("got %d calls, want %d: %+v", len(rec.calls), len(want), rec.calls)
	}
	for i, c := range rec.calls {
		if c != want[i] {
			t.Errorf("[%d] got %q want %q", i, c, want[i])
		}
	}
	if s.tickCount != 1 {
		t.Errorf("tickCount=%d, want 1", s.tickCount)
	}
}

func TestTickToleratesExecutorErrors(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{{SubscriptionID: "s1", ProfileUpdateMin: 60}},
	}
	rec := newRec()
	rec.fail[KindSubscription] = true
	s := New(src, rec, DefaultCadence())
	// Should not panic, should still record the call.
	s.Tick(now)
	if len(rec.calls) == 0 {
		t.Fatalf("expected a recorded call even on error")
	}
}

func TestStatusJSONShape(t *testing.T) {
	now := ts("2026-04-26T12:00:00Z")
	src := fakeSource{
		subs: []SubscriptionState{
			{SubscriptionID: "s1", ProfileUpdateMin: 60, LastGoodRefresh: now.Add(-30 * time.Minute)},
		},
		pubs: []PublisherState{
			{PublisherID: "p1", LastRevocationCheck: now.Add(-1 * time.Hour)},
		},
		bs: now.Add(-12 * time.Hour),
	}
	s := New(src, newRec(), DefaultCadence())
	s.SetNow(func() time.Time { return now })
	s.Tick(now)

	body, err := s.StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}
	if !strings.Contains(string(body), `"cadence"`) ||
		!strings.Contains(string(body), `"next_due"`) {
		t.Fatalf("expected cadence + next_due keys in: %s", string(body))
	}
	var got Status
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Cadence.RevocationSec != 6*3600 || got.Cadence.BootstrapSec != 24*3600 {
		t.Errorf("cadence shape wrong: %+v", got.Cadence)
	}
	if got.Ticks != 1 {
		t.Errorf("Ticks=%d want 1", got.Ticks)
	}
	if len(got.NextDue) != 4 {
		t.Errorf("NextDue len=%d want 4 (sub+rev+bootstrap+budget-reset): %+v", len(got.NextDue), got.NextDue)
	}
}

func TestStartStop(t *testing.T) {
	src := fakeSource{}
	rec := newRec()
	s := New(src, rec, DefaultCadence())
	s.SetTickEvery(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	time.Sleep(45 * time.Millisecond)
	s.Stop()

	// At least one tick must have fired against the bootstrap action
	// (which is always due when LastBootstrapRefresh is zero).
	got := false
	for _, c := range rec.calls {
		if c == "bootstrap:" {
			got = true
			break
		}
	}
	if !got {
		t.Fatalf("expected at least one bootstrap call after Start/Stop; got %+v", rec.calls)
	}
}
