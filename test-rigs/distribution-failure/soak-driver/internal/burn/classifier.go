// Package burn is the Phase 2G aggregate burn classifier and
// the verifier that compares per-route burn intervals against
// the directory's natural rotation cadence.
//
// The classifier consumes per-client diagnostics output (already
// produced by the existing rig) plus the burn-sandbox's own
// verdict. A route is "burned" when:
//
//  1. The simulated DPI sandbox has flipped its classifier
//     verdict to blocked (i.e. `sandbox.IsBurned(routeID) == true`),
//     AND
//  2. The aggregate failure rate across all clients on that
//     route exceeds 50 % within a sliding 10-minute window.
//
// Condition #1 alone is the unambiguous burn signal in the
// 2G rig (the sandbox runs deterministically); condition #2 is
// retained as a sanity check on the engine's actual cooldown
// pipeline and to reject any false positives.
package burn

import (
	"sort"
	"time"
)

// V1 thresholds (LOCKED).
const (
	WindowMinutes     = 10
	AggregateFailRate = 0.50
)

// Classifier aggregates per-client cooldown observations and
// emits a per-route verdict.
type Classifier struct {
	WindowMinutes     int
	AggregateFailRate float64

	// observations: route_id -> list of (clientID, fail) at time t
	obs map[string][]Observation
}

// Observation is a single client's verdict on a single route at
// a single tick. `Fail` is true if the engine recorded a cooldown
// in any of the burn-relevant V0.3 categories
// (`tcp_reset`, `tls_handshake_failed`,
// `tls_sni_or_cert_block_suspected`).
type Observation struct {
	ClientID string
	RouteID  string
	At       time.Time
	Fail     bool
}

// New returns a Classifier with the v1 thresholds.
func New() *Classifier {
	return &Classifier{
		WindowMinutes:     WindowMinutes,
		AggregateFailRate: AggregateFailRate,
		obs:               map[string][]Observation{},
	}
}

// Record adds an observation to the running aggregate.
func (c *Classifier) Record(o Observation) {
	c.obs[o.RouteID] = append(c.obs[o.RouteID], o)
}

// Burned reports whether the route's aggregate failure rate
// exceeds the threshold in a sliding window ending at `now`. Used
// as the engine-side condition #2; the sandbox verdict is
// condition #1 (orthogonal).
func (c *Classifier) Burned(routeID string, now time.Time) bool {
	rows := c.obs[routeID]
	if len(rows) == 0 {
		return false
	}
	windowStart := now.Add(-time.Duration(c.WindowMinutes) * time.Minute)
	var total, fails int
	for _, r := range rows {
		if r.At.Before(windowStart) || r.At.After(now) {
			continue
		}
		total++
		if r.Fail {
			fails++
		}
	}
	if total == 0 {
		return false
	}
	return float64(fails)/float64(total) > c.AggregateFailRate
}

// Routes returns the sorted list of route IDs the classifier has
// any observations for. Used by the verifier to walk every route.
func (c *Classifier) Routes() []string {
	out := make([]string, 0, len(c.obs))
	for id := range c.obs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
