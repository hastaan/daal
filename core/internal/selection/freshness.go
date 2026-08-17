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

	// RetryBackoff is the BASE gap after a failed attempt. The
	// recipient pipeline tracks LastFailureAt; when non-zero
	// and now < LastFailureAt+EffectiveRetryBackoff(...), the
	// trigger is suppressed.
	//
	// The effective gap DOUBLES per consecutive failure, capped at
	// MaxStaleness. A flat gap was the wrong shape for the one case
	// this whole subsystem exists for: when every mirror is
	// blackholed, a flat 5 minutes turns each censored device into a
	// fixed-period, zero-variance emitter of TLS handshakes to a
	// small set of known, enumerable hosts — from the user's real
	// address, because no route is up and Wave 1 forbids tunnelling
	// the repair through the thing being repaired. A working device
	// polled every 15 minutes while a device under attack polled
	// three times as often, which is exactly backwards.
	RetryBackoff time.Duration

	// MaxJitter bounds the random offset added to every computed due
	// time. See FreshnessState.JitterOffset for why an offset that
	// the planner and the policy both read from persisted state — as
	// opposed to one drawn here — is what keeps this function pure
	// and the two gates in agreement.
	MaxJitter time.Duration
}

// maxBackoffDoublings caps the escalation exponent so the shift
// cannot overflow on an absurd failure count; MaxStaleness caps the
// result long before this bites.
const maxBackoffDoublings = 12

// EffectiveRetryBackoff is the gap after `failures` consecutive
// failed attempts: RetryBackoff doubled per failure, capped at
// MaxStaleness.
//
// Pure and total, so the planner's next-due projection and the
// policy's own decision compute the same number from the same
// persisted state rather than each estimating it.
func EffectiveRetryBackoff(p FreshnessPolicy, failures int) time.Duration {
	base := p.RetryBackoff
	if base <= 0 {
		base = DefaultPolicy().RetryBackoff
	}
	if failures <= 1 {
		return base
	}
	n := failures - 1
	if n > maxBackoffDoublings {
		n = maxBackoffDoublings
	}
	out := base << uint(n)
	cap := p.MaxStaleness
	if cap <= 0 {
		cap = DefaultPolicy().MaxStaleness
	}
	if out > cap || out <= 0 {
		out = cap
	}
	return out
}

// jitter returns the offset to add to a computed due time, clamped
// into [0, MaxJitter]. A negative persisted offset (a corrupt record)
// must never pull a due time EARLIER, which would make a damaged
// device the loudest one on the network.
func jitter(p FreshnessPolicy, s FreshnessState) time.Duration {
	maxJ := p.MaxJitter
	if maxJ <= 0 {
		return 0
	}
	off := s.JitterOffset
	if off <= 0 {
		return 0
	}
	if off > maxJ {
		off = maxJ
	}
	return off
}

// FreshnessState is the recipient-side per-RelayPack state. The
// network adapter (core/refresh) owns the persistence of these
// values; this file's policy fn is pure.
type FreshnessState struct {
	LastSuccessAt time.Time
	LastFailureAt time.Time

	// ConsecutiveFailures is how many attempts in a row have failed
	// since the last success. Drives EffectiveRetryBackoff.
	ConsecutiveFailures int

	// JitterOffset is a random delay, drawn once by the network
	// adapter (crypto/rand) and PERSISTED alongside the timestamps,
	// added to every due time this policy computes.
	//
	// Persisted rather than drawn per call for two reasons. First,
	// this file is Position B — no clocks, no randomness, no IO —
	// and the opsec test enforces it. Second, the scheduler's
	// next-due projection and this policy are two gates that must
	// agree; if each drew its own offset they would disagree on
	// every tick, and the planner would render a due time the policy
	// then refused, which reads as a stuck device.
	//
	// What it buys: the endpoint order is already randomised per
	// attempt, but the attempt TIMES were not, and timing is the
	// fingerprint. Without an offset every device of one publisher
	// sits on the same lattice, and a passive observer locks onto it
	// after two samples.
	JitterOffset time.Duration
}

// DefaultPolicy returns the FRP-8 ship defaults. The phase doc
// pins these at:
//
//   - MinInterval:  15 minutes
//   - MaxStaleness: 6 hours
//   - RetryBackoff: 5 minutes (base; doubles per consecutive failure)
//   - MaxJitter:    4 minutes
//
// MaxJitter is ~27% of MinInterval, the same order as the ±20–30%
// the endpoint shuffle reasons about, and it is applied to the
// escalating retry gap too. It is deliberately large enough that two
// devices which imported the same pack on the same day do not share
// a lattice, and small enough that it never doubles a wait.
//
// V1.6 closure may tighten / widen these per the alpha-soak
// metrics; the constants are reviewed at FRP-9.
func DefaultPolicy() FreshnessPolicy {
	return FreshnessPolicy{
		MinInterval:  15 * time.Minute,
		MaxStaleness: 6 * time.Hour,
		RetryBackoff: 5 * time.Minute,
		MaxJitter:    4 * time.Minute,
	}
}

// ShouldAttemptRefresh decides whether a refresh attempt should
// fire NOW given the supplied policy + state + wall clock.
//
// Rules, in order:
//
//  1. If LastSuccessAt is zero (never refreshed) and
//     LastFailureAt is zero (never tried), allow immediately.
//  2. If now < LastFailureAt + EffectiveRetryBackoff + jitter,
//     suppress (still in retry cool-off).
//  3. If now >= LastSuccessAt + MaxStaleness + jitter, force
//     (over-stale; emergency refresh).
//  4. If now < LastSuccessAt + MinInterval + jitter, suppress
//     (rate limit).
//  5. Otherwise allow.
//
// Rule 1 is deliberately NOT jittered: a pack that has never been
// polled has no persisted offset to read, and delaying the very
// first fetch would delay the moment the device learns it is stale
// for no privacy gain — the import itself already happened at a
// time only the user chose.
//
// The policy is pure: no IO, no clocks captured at module load, and
// no randomness. The offset arrives in FreshnessState, drawn and
// persisted by the network adapter.
func ShouldAttemptRefresh(p FreshnessPolicy, s FreshnessState, now time.Time) bool {
	// 1. First-ever attempt.
	if s.LastSuccessAt.IsZero() && s.LastFailureAt.IsZero() {
		return true
	}
	j := jitter(p, s)
	// 2. Retry cool-off, escalating with consecutive failures.
	if !s.LastFailureAt.IsZero() {
		gap := EffectiveRetryBackoff(p, s.ConsecutiveFailures)
		if now.Before(s.LastFailureAt.Add(gap + j)) {
			return false
		}
	}
	// 3. Force on over-staleness.
	if !s.LastSuccessAt.IsZero() && !now.Before(s.LastSuccessAt.Add(p.MaxStaleness+j)) {
		return true
	}
	// 4. Rate limit.
	if !s.LastSuccessAt.IsZero() && now.Before(s.LastSuccessAt.Add(p.MinInterval+j)) {
		return false
	}
	// 5. Allow.
	return true
}
