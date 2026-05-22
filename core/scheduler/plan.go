package scheduler

import (
	"sort"
	"time"
)

// Kind enumerates the schedulable refresh actions.
type Kind string

const (
	KindSubscription Kind = "subscription"
	KindRevocation   Kind = "revocation"
	KindBootstrap    Kind = "bootstrap"
	// KindBudgetReset (Phase 2A) fires once per hour. The executor's
	// RefreshBudgetReset implementation calls
	// budget.Engine.HourRollover at the new hour bucket. This action
	// has no Ref because budget rollover is process-global.
	KindBudgetReset Kind = "budget-reset"
)

// Cadence is the per-kind interval policy. Subscription cadence is
// per-row from the subscriptions.profile_update_min column (already
// clamped on write to [60, 10080] minutes); revocation and bootstrap
// cadences are constants per the V1.5 / V2 spec.
type Cadence struct {
	Revocation  time.Duration
	Bootstrap   time.Duration
	BudgetReset time.Duration // Phase 2A. Defaults to 1 h.
}

// DefaultCadence returns the production cadence: revocation every 6 h,
// bootstrap every 24 h, budget-reset every hour. Subscription cadence
// is per-row.
func DefaultCadence() Cadence {
	return Cadence{
		Revocation:  6 * time.Hour,
		Bootstrap:   24 * time.Hour,
		BudgetReset: 1 * time.Hour,
	}
}

// Action is one scheduled item. The Ref field carries the
// subscription_id (KindSubscription), the publisher_id
// (KindRevocation), or the empty string (KindBootstrap, which is
// process-global).
type Action struct {
	Kind    Kind      `json:"kind"`
	Ref     string    `json:"ref,omitempty"`
	NextDue time.Time `json:"next_due"`
}

// Source is the read-only view of the routestore the planner needs.
// We deliberately do NOT depend on the full routestore.Store interface
// so tests can stub this out and the parity test can replay state from
// JSON without sqlite.
type Source interface {
	// Subscriptions enumerates rows with their last-good refresh time
	// (zero time → never refreshed) and their cadence in minutes.
	Subscriptions() []SubscriptionState
	// PublishersWithRevocation enumerates rows with their last
	// revocation-check time (zero → never).
	PublishersWithRevocation() []PublisherState
	// LastBootstrapRefresh returns the wall-clock of the last
	// bootstrap-directory refresh; zero → never.
	LastBootstrapRefresh() time.Time
	// LastBudgetReset returns the wall-clock of the last budget-reset
	// hour-rollover. Phase 2A. Zero → never (so first tick fires).
	LastBudgetReset() time.Time
}

// SubscriptionState is a snapshot of one subscriptions row for the
// planner. ProfileUpdateMin is in minutes and is already clamped.
type SubscriptionState struct {
	SubscriptionID   string
	ProfileUpdateMin int
	LastGoodRefresh  time.Time // zero if never
	LastAttemptedAt  time.Time // zero if never
}

// PublisherState is a snapshot of one publishers row for the planner.
type PublisherState struct {
	PublisherID         string
	LastRevocationCheck time.Time
}

// Plan returns the deterministic ordered list of actions that have
// next_due ≤ now. Items already past-due are returned in (kind, ref)
// order so two callers with the same input get the same output.
//
// The function is pure: no clock reads, no I/O, no goroutines. Callers
// pass `now` explicitly so tests can drive every path.
func Plan(src Source, c Cadence, now time.Time) []Action {
	if c.Revocation == 0 {
		c.Revocation = 6 * time.Hour
	}
	if c.Bootstrap == 0 {
		c.Bootstrap = 24 * time.Hour
	}
	if c.BudgetReset == 0 {
		c.BudgetReset = 1 * time.Hour
	}
	var due []Action

	for _, s := range src.Subscriptions() {
		mins := s.ProfileUpdateMin
		if mins < 60 {
			mins = 60
		}
		if mins > 7*24*60 {
			mins = 7 * 24 * 60
		}
		interval := time.Duration(mins) * time.Minute
		next := nextDue(s.LastGoodRefresh, interval, now)
		if !next.After(now) {
			due = append(due, Action{
				Kind:    KindSubscription,
				Ref:     s.SubscriptionID,
				NextDue: next,
			})
		}
	}

	for _, p := range src.PublishersWithRevocation() {
		next := nextDue(p.LastRevocationCheck, c.Revocation, now)
		if !next.After(now) {
			due = append(due, Action{
				Kind:    KindRevocation,
				Ref:     p.PublisherID,
				NextDue: next,
			})
		}
	}

	bsNext := nextDue(src.LastBootstrapRefresh(), c.Bootstrap, now)
	if !bsNext.After(now) {
		due = append(due, Action{
			Kind:    KindBootstrap,
			NextDue: bsNext,
		})
	}

	brNext := nextDue(src.LastBudgetReset(), c.BudgetReset, now)
	if !brNext.After(now) {
		due = append(due, Action{
			Kind:    KindBudgetReset,
			NextDue: brNext,
		})
	}

	sort.SliceStable(due, func(i, j int) bool {
		if due[i].Kind != due[j].Kind {
			return due[i].Kind < due[j].Kind
		}
		return due[i].Ref < due[j].Ref
	})
	return due
}

// nextDue returns last + interval; if last is zero we say "due now"
// by returning a moment one nanosecond before now, so the action is
// included in the due list.
func nextDue(last time.Time, interval time.Duration, now time.Time) time.Time {
	if last.IsZero() {
		return now.Add(-time.Nanosecond)
	}
	return last.Add(interval)
}

// AllNextDues returns next_due for *every* registered item (whether
// past-due or future). Used by Status() for the JSON snapshot the GUI
// renders.
func AllNextDues(src Source, c Cadence, now time.Time) []Action {
	if c.Revocation == 0 {
		c.Revocation = 6 * time.Hour
	}
	if c.Bootstrap == 0 {
		c.Bootstrap = 24 * time.Hour
	}
	if c.BudgetReset == 0 {
		c.BudgetReset = 1 * time.Hour
	}
	var all []Action
	for _, s := range src.Subscriptions() {
		mins := s.ProfileUpdateMin
		if mins < 60 {
			mins = 60
		}
		if mins > 7*24*60 {
			mins = 7 * 24 * 60
		}
		all = append(all, Action{
			Kind:    KindSubscription,
			Ref:     s.SubscriptionID,
			NextDue: nextDue(s.LastGoodRefresh, time.Duration(mins)*time.Minute, now),
		})
	}
	for _, p := range src.PublishersWithRevocation() {
		all = append(all, Action{
			Kind:    KindRevocation,
			Ref:     p.PublisherID,
			NextDue: nextDue(p.LastRevocationCheck, c.Revocation, now),
		})
	}
	all = append(all, Action{
		Kind:    KindBootstrap,
		NextDue: nextDue(src.LastBootstrapRefresh(), c.Bootstrap, now),
	})
	all = append(all, Action{
		Kind:    KindBudgetReset,
		NextDue: nextDue(src.LastBudgetReset(), c.BudgetReset, now),
	})
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		return all[i].Ref < all[j].Ref
	})
	return all
}
