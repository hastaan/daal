package scheduler

import (
	"sort"
	"time"

	"daal/core/internal/selection"
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
	// KindFreshness (Wave 3 / Step 8) fires per RelayPack that carries
	// at least one freshness endpoint. Ref is the relay_pack_id. The
	// executor's RefreshFreshness implementation drives
	// refresh.RelayPackRefresher, which is what turns a publisher-side
	// rotation into something recipients pick up over the network
	// instead of by courier.
	//
	// Cadence for this kind is NOT a Cadence duration: it is the
	// FRP-8 trigger policy in core/internal/selection/freshness.go
	// (MinInterval / MaxStaleness / RetryBackoff), which already
	// encodes the "do not storm the endpoint" rule and the
	// "over-stale → force" rule. Reusing it rather than inventing a
	// second cadence is deliberate: two policies that must agree and
	// live in different files is exactly how this codebase acquired
	// its stock of code that exists and does nothing.
	KindFreshness Kind = "freshness"
	// KindNetmemSweep (Wave 5 / telemetry) fires once a day and drops
	// per-network memory blobs older than netmem.TTL. It has no Ref
	// because the sweep is process-global.
	//
	// This is a RETENTION action, not a refresh: netmem blobs are the
	// only structure in the engine that grows with the number of
	// networks the device has ever joined, and every one of them is a
	// small piece of evidence about where its owner has been. The TTL
	// and the Sweep that enforces it were written together in
	// core/netmem, whose doc comment says callers "wire into the
	// scheduler's hourly tick" — and until this pass no caller did, so
	// the retention bound existed on paper only.
	KindNetmemSweep Kind = "netmem-sweep"
)

// Cadence is the per-kind interval policy. Subscription cadence is
// per-row from the subscriptions.profile_update_min column (already
// clamped on write to [60, 10080] minutes); revocation and bootstrap
// cadences are constants per the V1.5 / V2 spec.
type Cadence struct {
	Revocation  time.Duration
	Bootstrap   time.Duration
	BudgetReset time.Duration // Phase 2A. Defaults to 1 h.

	// NetmemSweep is how often stale per-network memory is pruned.
	// Defaults to 24 h. It does not need to be tight — netmem.TTL is
	// 30 days, so a day of slack on the boundary is immaterial — and a
	// sweep reads and re-decrypts every blob, which is not free on a
	// phone.
	NetmemSweep time.Duration

	// Freshness is the FRP-8 per-RelayPack trigger policy. Zero value
	// is replaced by selection.DefaultPolicy() in Plan/AllNextDues, so
	// a host that constructs a Cadence by hand cannot accidentally get
	// "MinInterval 0" and hammer a publisher's freshness endpoint once
	// per tick.
	Freshness selection.FreshnessPolicy
}

// DefaultCadence returns the production cadence: revocation every 6 h,
// bootstrap every 24 h, budget-reset every hour, freshness on the FRP-8
// default policy (15 min floor, 6 h staleness ceiling, 5 min retry
// backoff). Subscription cadence is per-row.
func DefaultCadence() Cadence {
	return Cadence{
		Revocation:  6 * time.Hour,
		Bootstrap:   24 * time.Hour,
		BudgetReset: 1 * time.Hour,
		NetmemSweep: 24 * time.Hour,
		Freshness:   selection.DefaultPolicy(),
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
	// LastNetmemSweep returns the wall-clock of the last per-network
	// memory sweep. Zero → never (so the first tick after install
	// prunes whatever a previous, unswept build left behind).
	LastNetmemSweep() time.Time
	// RelayPacks enumerates every imported RelayPack that carries at
	// least one freshness endpoint, with its last successful and last
	// failed refresh. A pack with no endpoint MUST NOT be returned:
	// there is nothing to fetch, and emitting it would make the
	// scheduler's status JSON claim a capability the pack does not
	// have. Step 8.
	RelayPacks() []RelayPackState
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

// RelayPackState is a snapshot of one RelayPack's freshness state for
// the planner. Both timestamps are persisted by the executor
// (core/refresh writes them into secrets_kv), so the cadence survives a
// process restart — a tick storm caused by an app that is being killed
// and relaunched must not turn into a fetch storm at the endpoint.
type RelayPackState struct {
	RelayPackID   string
	LastSuccessAt time.Time // zero if never
	LastFailureAt time.Time // zero if never

	// ConsecutiveFailures drives the escalating retry gap, and
	// JitterOffset is the per-device random delay. Both are persisted
	// by the executor beside the timestamps and are passed through
	// unchanged: the planner must compute the SAME due time the
	// policy will accept, and it can only do that by reading the same
	// state rather than re-deriving either value.
	ConsecutiveFailures int
	JitterOffset        time.Duration
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
	if c.NetmemSweep == 0 {
		c.NetmemSweep = 24 * time.Hour
	}
	c.Freshness = defaultedFreshness(c.Freshness)
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

	nsNext := nextDue(src.LastNetmemSweep(), c.NetmemSweep, now)
	if !nsNext.After(now) {
		due = append(due, Action{
			Kind:    KindNetmemSweep,
			NextDue: nsNext,
		})
	}

	for _, rp := range src.RelayPacks() {
		if rp.RelayPackID == "" {
			continue
		}
		st := selection.FreshnessState{
			LastSuccessAt:       rp.LastSuccessAt,
			LastFailureAt:       rp.LastFailureAt,
			ConsecutiveFailures: rp.ConsecutiveFailures,
			JitterOffset:        rp.JitterOffset,
		}
		// Two gates that must agree, asserted together rather than
		// re-derived: nextFreshnessDue computes the instant the policy
		// first permits an attempt (that is what Status renders), and
		// ShouldAttemptRefresh is the policy itself. If they ever
		// disagree the conservative one wins, because the failure mode
		// on this path is a fixed-cadence beacon at a small, unique,
		// pollable URL.
		next := nextFreshnessDue(st, c.Freshness, now)
		if next.After(now) {
			continue
		}
		if !selection.ShouldAttemptRefresh(c.Freshness, st, now) {
			continue
		}
		due = append(due, Action{
			Kind:    KindFreshness,
			Ref:     rp.RelayPackID,
			NextDue: next,
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

// defaultedFreshness fills a zero-valued policy with the FRP-8 ship
// defaults. A zero MinInterval would mean "attempt on every tick",
// i.e. once a minute against a URL that exists precisely so a censor
// can find it — so the zero value must never be honoured literally.
func defaultedFreshness(p selection.FreshnessPolicy) selection.FreshnessPolicy {
	d := selection.DefaultPolicy()
	if p.MinInterval <= 0 {
		p.MinInterval = d.MinInterval
	}
	if p.MaxStaleness <= 0 {
		p.MaxStaleness = d.MaxStaleness
	}
	if p.RetryBackoff <= 0 {
		p.RetryBackoff = d.RetryBackoff
	}
	if p.MaxJitter <= 0 {
		p.MaxJitter = d.MaxJitter
	}
	return p
}

// nextFreshnessDue is the inverse of selection.ShouldAttemptRefresh: the
// earliest instant at which that function would return true, given the
// same policy and state. Status() renders it, and Plan cross-checks
// against it.
//
// The rule ordering is the policy's, not ours: retry backoff suppresses
// even an over-stale pack (freshness_test.go pins that), so a pack that
// has failed is gated on LastFailureAt+RetryBackoff regardless of how
// stale it is.
// The jitter offset and the failure count both come from the SAME
// persisted state the policy reads, so the two gates cannot disagree.
// Deriving either here would put the planner on a different lattice
// from the executor and render a due time the policy then refuses.
func nextFreshnessDue(s selection.FreshnessState, p selection.FreshnessPolicy, now time.Time) time.Time {
	p = defaultedFreshness(p)
	if s.LastSuccessAt.IsZero() && s.LastFailureAt.IsZero() {
		// Never attempted: due now. One nanosecond back, matching
		// nextDue's convention so the action lands in the due list.
		return now.Add(-time.Nanosecond)
	}
	j := s.JitterOffset
	if j < 0 {
		j = 0
	}
	if j > p.MaxJitter {
		j = p.MaxJitter
	}
	var next time.Time
	if !s.LastFailureAt.IsZero() {
		next = s.LastFailureAt.Add(selection.EffectiveRetryBackoff(p, s.ConsecutiveFailures) + j)
	}
	if !s.LastSuccessAt.IsZero() {
		if t := s.LastSuccessAt.Add(p.MinInterval + j); t.After(next) {
			next = t
		}
	}
	return next
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
	if c.NetmemSweep == 0 {
		c.NetmemSweep = 24 * time.Hour
	}
	c.Freshness = defaultedFreshness(c.Freshness)
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
	all = append(all, Action{
		Kind:    KindNetmemSweep,
		NextDue: nextDue(src.LastNetmemSweep(), c.NetmemSweep, now),
	})
	for _, rp := range src.RelayPacks() {
		if rp.RelayPackID == "" {
			continue
		}
		all = append(all, Action{
			Kind: KindFreshness,
			Ref:  rp.RelayPackID,
			NextDue: nextFreshnessDue(selection.FreshnessState{
				LastSuccessAt:       rp.LastSuccessAt,
				LastFailureAt:       rp.LastFailureAt,
				ConsecutiveFailures: rp.ConsecutiveFailures,
				JitterOffset:        rp.JitterOffset,
			}, c.Freshness, now),
		})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		return all[i].Ref < all[j].Ref
	})
	return all
}
