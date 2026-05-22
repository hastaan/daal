// freshness.go is the pure trigger-policy half of the FRP-8
// V1.6 freshness flow.
//
// LAYER SPLIT (phase doc §13 rule 3):
//
//   - core/internal/selection/freshness.go (this file): policy
//     only — given a clock and the per-RelayPack last-fetch
//     timestamp, decide whether the recipient should attempt
//     a refresh now. NO sockets, NO http, NO file IO. Position B
//     is enforced by core/internal/selection/opsec_test.go.
//
//   - core/refresh/relaypack.go: network IO + atomic swap.
//     Imports this file's policy fn but adds the dialer + the
//     bundle-go importer side.
//
//   - bundle/go/importer: applies verified bytes via
//     ApplyVerifiedRefresh.
//
// The recipient pipeline checks ShouldAttemptRefresh in a loop
// shorter than the minimum interval; when it returns true,
// the core/refresh side is invoked. The trigger policy here is
// stateless w.r.t. the network and is therefore safe to evaluate
// frequently inside the selection hot path.

package selection

import "time"

// FreshnessPolicy is the pure trigger-policy struct. The fields
// are bundle-derived constants (loaded once when the manifest
// imports) plus the recipient's last successful refresh.
type FreshnessPolicy struct {
	// MinInterval is the minimum gap between refresh attempts.
	// Recipients honour this even if the bundle was just
	// imported, to avoid storming the FRP's freshness endpoint
	// when the device wakes up.
	MinInterval time.Duration

	// MaxStaleness is the upper bound: if the recipient has
	// not successfully refreshed within MaxStaleness of now,
	// the next ShouldAttemptRefresh returns true regardless
	// of any retry backoff.
	MaxStaleness time.Duration

	// RetryBackoff is the gap after a failed attempt. The
	// recipient pipeline tracks LastFailureAt; when non-zero
	// and now < LastFailureAt+RetryBackoff, the trigger is
	// suppressed.
	RetryBackoff time.Duration
}

// FreshnessState is the recipient-side per-RelayPack state. The
// network adapter (core/refresh) owns the persistence of these
// values; this file's policy fn is pure.
type FreshnessState struct {
	LastSuccessAt time.Time
	LastFailureAt time.Time
}

// DefaultPolicy returns the FRP-8 ship defaults. The phase doc
// pins these at:
//
//   - MinInterval:  15 minutes
//   - MaxStaleness: 6 hours
//   - RetryBackoff: 5 minutes
//
// V1.6 closure may tighten / widen these per the alpha-soak
// metrics; the constants are reviewed at FRP-9.
func DefaultPolicy() FreshnessPolicy {
	return FreshnessPolicy{
		MinInterval:  15 * time.Minute,
		MaxStaleness: 6 * time.Hour,
		RetryBackoff: 5 * time.Minute,
	}
}

// ShouldAttemptRefresh decides whether a refresh attempt should
// fire NOW given the supplied policy + state + wall clock.
//
// Rules, in order:
//
//  1. If LastSuccessAt is zero (never refreshed) and
//     LastFailureAt is zero (never tried), allow immediately.
//  2. If now < LastFailureAt + RetryBackoff, suppress (still
//     in retry cool-off).
//  3. If now >= LastSuccessAt + MaxStaleness, force
//     (over-stale; emergency refresh).
//  4. If now < LastSuccessAt + MinInterval, suppress (rate
//     limit).
//  5. Otherwise allow.
//
// The policy is pure: no IO, no clocks captured at module load.
func ShouldAttemptRefresh(p FreshnessPolicy, s FreshnessState, now time.Time) bool {
	// 1. First-ever attempt.
	if s.LastSuccessAt.IsZero() && s.LastFailureAt.IsZero() {
		return true
	}
	// 2. Retry cool-off.
	if !s.LastFailureAt.IsZero() && now.Before(s.LastFailureAt.Add(p.RetryBackoff)) {
		return false
	}
	// 3. Force on over-staleness.
	if !s.LastSuccessAt.IsZero() && !now.Before(s.LastSuccessAt.Add(p.MaxStaleness)) {
		return true
	}
	// 4. Rate limit.
	if !s.LastSuccessAt.IsZero() && now.Before(s.LastSuccessAt.Add(p.MinInterval)) {
		return false
	}
	// 5. Allow.
	return true
}
