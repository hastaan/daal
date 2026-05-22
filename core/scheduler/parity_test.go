package scheduler

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestParity30DayLedger is the V2-entry-criterion parity test. It
// replays a synthetic 30-day source-state series through Plan and
// asserts byte-identical action sequences across (a) two independent
// runs in this process and (b) a run after the cadence map is
// re-instantiated. The test is deliberately fast — milliseconds — so
// it is the inner loop for cadence/clamp regressions.
//
// The "ledger" we compare is the per-day list of due actions
// serialized as JSON. The serialization is stable because Plan sorts
// by (kind, ref) and the JSON encoder writes struct fields in
// declaration order.
//
// The longer-form parity test (replaying the 1.5C 30-day soak artifact
// through soak-driver `--mode in-engine`) lives in the soak-driver tree
// because it needs an actual engine subprocess.
func TestParity30DayLedger(t *testing.T) {
	freshSource := func() *replayingSource {
		return &replayingSource{
			// 5 subscriptions with assorted cadences (the first
			// row's 60-min cadence forces hourly refresh; the
			// others slow down).
			subs: []SubscriptionState{
				{SubscriptionID: "s-hourly", ProfileUpdateMin: 60},
				{SubscriptionID: "s-six-hourly", ProfileUpdateMin: 360},
				{SubscriptionID: "s-daily", ProfileUpdateMin: 1440},
				{SubscriptionID: "s-weekly", ProfileUpdateMin: 7 * 1440},
				{SubscriptionID: "s-clamped", ProfileUpdateMin: 5}, // clamps up to 60
			},
			// 3 publishers with revocation URLs.
			pubs: []PublisherState{
				{PublisherID: "pub-A"},
				{PublisherID: "pub-B"},
				{PublisherID: "pub-C"},
			},
		}
	}

	start := ts("2026-04-26T00:00:00Z")
	cad := DefaultCadence()

	ledgerA := replay30Days(t, freshSource(), cad, start)
	ledgerB := replay30Days(t, freshSource(), cad, start)
	if string(ledgerA) != string(ledgerB) {
		t.Fatalf("Plan is not deterministic across two replays:\n  A=%s\n  B=%s",
			string(ledgerA), string(ledgerB))
	}

	// Re-instantiate the cadence and Source; the ledger must remain
	// byte-identical because the planner is pure.
	cad2 := DefaultCadence()
	ledgerC := replay30Days(t, freshSource(), cad2, start)
	if string(ledgerA) != string(ledgerC) {
		t.Fatalf("Plan differs after re-instantiation:\n  A=%s\n  C=%s",
			string(ledgerA), string(ledgerC))
	}

	// Sanity: the daily cadence row must appear at least 25 times in
	// 30 days (6h cadence on revocation gives 4 fires/day for 3 pubs;
	// daily fires once; bootstrap fires once). Fewer than 25 means we
	// regressed cadence math.
	if got := strings.Count(string(ledgerA), `"subscription:s-daily"`); got < 25 {
		t.Errorf("expected s-daily to fire ≥25 times in 30 days, got %d", got)
	}
}

// replay30Days advances `now` in 1-hour ticks for 30 days, calls Plan
// at each tick, and stamps the LastGoodRefresh on every action that
// fires (so the next-due math advances correctly). Returns the
// per-tick ledger as a single JSON array.
func replay30Days(t *testing.T, src *replayingSource, cad Cadence, start time.Time) []byte {
	t.Helper()
	type row struct {
		Tick    int      `json:"tick"`
		NowRFC  string   `json:"now"`
		Actions []string `json:"actions"`
	}
	var out []row
	now := start
	deadline := start.Add(30 * 24 * time.Hour)
	tick := 0
	for now.Before(deadline) {
		due := Plan(src, cad, now)
		var keys []string
		for _, a := range due {
			keys = append(keys, fmt.Sprintf("%s:%s", a.Kind, a.Ref))
			src.markFired(a, now)
		}
		out = append(out, row{Tick: tick, NowRFC: now.UTC().Format(time.RFC3339), Actions: keys})
		now = now.Add(time.Hour)
		tick++
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal ledger: %v", err)
	}
	return body
}

// replayingSource keeps Subscriptions/Publishers state and lets the
// parity test stamp LastGoodRefresh / LastRevocationCheck after each
// fire so the next Plan call advances correctly.
type replayingSource struct {
	subs    []SubscriptionState
	pubs    []PublisherState
	bs      time.Time
	budgRst time.Time // Phase 2A: last budget-reset
}

func (r *replayingSource) Subscriptions() []SubscriptionState         { return r.subs }
func (r *replayingSource) PublishersWithRevocation() []PublisherState { return r.pubs }
func (r *replayingSource) LastBootstrapRefresh() time.Time            { return r.bs }
func (r *replayingSource) LastBudgetReset() time.Time                 { return r.budgRst }

func (r *replayingSource) markFired(a Action, now time.Time) {
	switch a.Kind {
	case KindSubscription:
		for i, s := range r.subs {
			if s.SubscriptionID == a.Ref {
				r.subs[i].LastGoodRefresh = now
			}
		}
	case KindRevocation:
		for i, p := range r.pubs {
			if p.PublisherID == a.Ref {
				r.pubs[i].LastRevocationCheck = now
			}
		}
	case KindBootstrap:
		r.bs = now
	case KindBudgetReset:
		r.budgRst = now
	}
}
