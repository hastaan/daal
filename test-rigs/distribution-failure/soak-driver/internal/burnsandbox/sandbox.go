// Package burnsandbox is the Phase 2G simulated-DPI burn driver.
//
// Each route in the directory is independently subject to a
// per-hour Bernoulli burn draw. Once burned, a route remains
// burned for the rest of the soak — it does not "un-burn" because
// the directory's natural rotation cadence is the recovery
// mechanism (the next directory refresh ships a new route ID).
//
// The default burn rate (0.014 / route / hour) matches the
// IRBlock-modelled rate of ~1 burn per 72 hours. Tunable via
// `--burn-rate-per-route-per-hour`.
//
// Determinism: a seeded RNG produces a reproducible burn schedule
// for a given (seed, directory). This is essential so that a
// `run-burn --clients 1000` run can be replayed against an engine
// fix and the per-route ledger compared for parity.
package burnsandbox

import (
	"math/rand"
	"sort"
	"time"
)

// Sandbox is the burn-event driver. It is consulted once per
// simulated hour; on each consultation it decides which routes
// (if any) to burn this hour.
type Sandbox struct {
	// BurnRatePerRoutePerHour is the Bernoulli probability per
	// route per hour. Default 0.014 (one burn per 72 hours per
	// route on average).
	BurnRatePerRoutePerHour float64

	// Style records the simulated-DPI behaviour applied to a
	// burned route. v1 collapses all of {tls-reset, handshake-stall,
	// blackhole} into a single composite "burned" verdict; the
	// burn classifier in `internal/burn/` only needs to know that
	// the route is unhealthy.
	Style string

	// Seed is the RNG seed. Stable across runs at the same seed.
	Seed int64

	rng     *rand.Rand
	burned  map[string]time.Time // route_id -> first-burn instant
	startup time.Time
}

// New returns a Sandbox initialised with deterministic RNG state.
func New(seed int64) *Sandbox {
	return &Sandbox{
		BurnRatePerRoutePerHour: 0.014,
		Style:                   "tls-reset+handshake-stall",
		Seed:                    seed,
		rng:                     rand.New(rand.NewSource(seed)),
		burned:                  map[string]time.Time{},
	}
}

// Tick runs one simulated-hour Bernoulli draw across every route
// in `routeIDs`. Returns the slice of route IDs that transitioned
// from healthy to burned this tick. Already-burned routes are
// never re-drawn.
//
// `now` is the simulated wall-clock at the tick instant. The
// sandbox stamps the first-burn time so the verifier can compute
// `firstBurn - firstPublish` for the primary metric.
func (s *Sandbox) Tick(now time.Time, routeIDs []string) []string {
	if s.startup.IsZero() {
		s.startup = now
	}
	// Sort for deterministic iteration order at a given seed.
	ids := append([]string(nil), routeIDs...)
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		if _, already := s.burned[id]; already {
			continue
		}
		if s.rng.Float64() < s.BurnRatePerRoutePerHour {
			s.burned[id] = now
			out = append(out, id)
		}
	}
	return out
}

// FirstBurn returns the instant at which `routeID` was first
// burned, and a bool reporting whether it was burned at all.
func (s *Sandbox) FirstBurn(routeID string) (time.Time, bool) {
	t, ok := s.burned[routeID]
	return t, ok
}

// IsBurned reports whether the route is currently burned. Once
// burned, always burned (within a single soak run).
func (s *Sandbox) IsBurned(routeID string) bool {
	_, ok := s.burned[routeID]
	return ok
}

// Snapshot returns a copy of the burn map keyed by route ID. Used
// by the verifier to walk every burned route in the run.
func (s *Sandbox) Snapshot() map[string]time.Time {
	out := make(map[string]time.Time, len(s.burned))
	for k, v := range s.burned {
		out[k] = v
	}
	return out
}
