// Package v3verifier is the Phase 3-Soak V3 success-metric aggregate
// verifier. Mirror of `internal/burn/verifier.go` (which produced the
// V2 5-metric aggregate at 2G), widened across the three real
// platform stubs (Linux / Android / iOS) and the V3 transport
// surface (3A → 3F).
//
// The five metrics are independent — a single failure does NOT
// short-circuit the others (the verifier reports all failures so
// the operator can fix in one pass). See
// `phases of development/27-phase-3-soak-success-metric.md` §6.
//
// Stdlib only.
package v3verifier

import (
	"fmt"
	"sort"
	"time"
)

// PlatformTag mirrors load.PlatformTag verbatim. We keep a local
// copy so the verifier package does not import the load package
// (avoids a circular dependency through the soak driver).
type PlatformTag string

const (
	PlatformLinux   PlatformTag = "linux"
	PlatformAndroid PlatformTag = "android"
	PlatformIOS     PlatformTag = "ios"
)

// Maturity is the closed-enum maturity tag the trust-UI parity
// metric checks against. Mirrors specs/transport-families-v1.md.
type Maturity string

const (
	MaturityGA           Maturity = "ga"
	MaturityExperimental Maturity = "experimental"
)

// LockedFamilyMaturity is the V3 family-maturity table the parity
// metric asserts against. Locked at 3-Soak per
// `phases of development/27-phase-3-soak-success-metric.md` §8.
var LockedFamilyMaturity = map[string]Maturity{
	"vless":            MaturityGA, // alias for tcp443/vless-reality
	"hysteria2":        MaturityGA,
	"wireguard":        MaturityGA,
	"webtunnel":        MaturityExperimental, // 3A
	"snowflake":        MaturityExperimental, // 3B
	"masque":           MaturityExperimental, // 3C
	"psiphon":          MaturityExperimental, // 3D
	"conjure":          MaturityExperimental, // 3D
	"transport_module": MaturityExperimental, // 3E
}

// PickupObservation is one (client, platform, slug, observed_at)
// tuple recorded by the rig as the published transport_module
// propagates across the fleet. The primary metric walks these
// observations and asserts every platform observed the slug
// within the cadence.
type PickupObservation struct {
	ClientID    string
	Platform    PlatformTag
	ModuleSlug  string
	PublishedAt time.Time
	ObservedAt  time.Time
}

// Activation is one (client, gate_state, family) triple: the rig
// records every route activation a client performs over the soak
// run. The experimental-gate cross-product metric walks these and
// asserts gate-OFF clients never activate an experimental family.
type Activation struct {
	ClientID   string
	Platform   PlatformTag
	GateOn     bool
	Family     string
	OccurredAt time.Time
}

// TrustUIObservation is one (client, family, badge) triple: the rig
// records the badge surfaced for every route × every client at end
// of soak. The trust-UI parity metric walks these and asserts the
// badge equals the family's locked maturity.
type TrustUIObservation struct {
	ClientID string
	Family   string
	Badge    Maturity
}

// FamilyBurn is one (family, first_publish, first_burn) triple.
// The per-family burn-rate metric walks these and asserts no
// family burns faster than its directory's natural rotation
// cadence. Mirror of internal/burn.RouteVerdict, aggregated by
// family.
type FamilyBurn struct {
	Family         string
	FirstPublishAt time.Time
	FirstBurnAt    time.Time
	BurnInterval   time.Duration
	Burned         bool
}

// Aggregate is the verifier's top-level output. Five aggregate
// metrics, all independent. `Failures` is human-readable detail
// for any failed metric; the booleans are the machine-readable
// gates.
type Aggregate struct {
	// 0 — Run identity.
	RunID                      string        `json:"run_id"`
	CrossPlatformPickupCadence time.Duration `json:"cross_platform_pickup_cadence_ns"`

	// 1 (primary) — cross-platform pickup ≤ cadence.
	CrossPlatformPickupPass bool `json:"cross_platform_pickup_pass"`

	// 2 (secondary) — experimental-gate cross-product.
	ExperimentalGateCrossProductPass bool `json:"experimental_gate_cross_product_pass"`

	// 3 (secondary) — trust-UI parity.
	TrustUIParityPass bool `json:"trust_ui_parity_pass"`

	// 4 (secondary) — no V1/V2 regression (caller supplies the
	// boolean from running the v2-superset selector).
	NoV1V2RegressionPass bool `json:"no_v1_v2_regression_pass"`

	// 5 (secondary) — per-family burn rate.
	PerFamilyBurnRatePass bool `json:"per_family_burn_rate_pass"`

	// Detail messages for any failed aggregate metric.
	Failures []string `json:"failures,omitempty"`
}

// Verify computes the aggregate verdict over the rig's observation
// ledger. The cadence is the locked `--cross-platform-pickup-cadence`
// (default 24h per spec §6 primary). The directoryRefreshCadence is
// the per-family burn-rate threshold (re-uses 2G's primary metric
// shape, applied per-family).
//
// `noV1V2Regression` is supplied by the caller — the v2-superset
// pass/fail is computed by the existing soak-driver path; this
// verifier just wires it into the aggregate.
func Verify(
	runID string,
	crossPlatformPickupCadence time.Duration,
	directoryRefreshCadence time.Duration,
	pickups []PickupObservation,
	activations []Activation,
	trustUI []TrustUIObservation,
	familyBurns []FamilyBurn,
	noV1V2Regression bool,
) Aggregate {
	a := Aggregate{
		RunID:                            runID,
		CrossPlatformPickupCadence:       crossPlatformPickupCadence,
		CrossPlatformPickupPass:          true,
		ExperimentalGateCrossProductPass: true,
		TrustUIParityPass:                true,
		NoV1V2RegressionPass:             noV1V2Regression,
		PerFamilyBurnRatePass:            true,
	}

	// Primary: cross-platform pickup ≤ cadence.
	// Bucket by (slug, platform) and assert every platform that
	// observed this slug observed it within `cadence` of publish.
	type key struct {
		Slug     string
		Platform PlatformTag
	}
	earliestObs := map[key]time.Time{}
	publishedAt := map[string]time.Time{}
	platformsSeen := map[string]map[PlatformTag]bool{}
	for _, o := range pickups {
		k := key{o.ModuleSlug, o.Platform}
		if prev, ok := earliestObs[k]; !ok || o.ObservedAt.Before(prev) {
			earliestObs[k] = o.ObservedAt
		}
		if prev, ok := publishedAt[o.ModuleSlug]; !ok || o.PublishedAt.Before(prev) {
			publishedAt[o.ModuleSlug] = o.PublishedAt
		}
		if platformsSeen[o.ModuleSlug] == nil {
			platformsSeen[o.ModuleSlug] = map[PlatformTag]bool{}
		}
		platformsSeen[o.ModuleSlug][o.Platform] = true
	}
	requiredPlatforms := []PlatformTag{PlatformLinux, PlatformAndroid, PlatformIOS}
	for slug, pubAt := range publishedAt {
		for _, p := range requiredPlatforms {
			if !platformsSeen[slug][p] {
				a.CrossPlatformPickupPass = false
				a.Failures = append(a.Failures, fmt.Sprintf(
					"primary: slug %q never observed on platform %q after publish at %s",
					slug, p, pubAt))
				continue
			}
			obsAt := earliestObs[key{slug, p}]
			if delta := obsAt.Sub(pubAt); delta > crossPlatformPickupCadence {
				a.CrossPlatformPickupPass = false
				a.Failures = append(a.Failures, fmt.Sprintf(
					"primary: slug %q on %q observed %s after publish (> cadence %s)",
					slug, p, delta, crossPlatformPickupCadence))
			}
		}
	}

	// Secondary 1: experimental-gate cross-product.
	// Per-client: if GateOn=false, NO experimental-family activation
	// allowed. If GateOn=true, at least ONE experimental activation
	// required by end of run.
	type clientGate struct {
		ClientID string
		GateOn   bool
	}
	gateSeen := map[string]bool{} // ClientID → GateOn at first observation
	expActs := map[string]bool{}  // ClientID → had at least one experimental activation
	clientGates := []clientGate{}
	for _, act := range activations {
		if !gateSeen[act.ClientID] {
			gateSeen[act.ClientID] = true
			clientGates = append(clientGates, clientGate{act.ClientID, act.GateOn})
		}
		if isExperimental(act.Family) {
			if !act.GateOn {
				a.ExperimentalGateCrossProductPass = false
				a.Failures = append(a.Failures, fmt.Sprintf(
					"secondary-1: gate-OFF client %q activated experimental family %q at %s",
					act.ClientID, act.Family, act.OccurredAt))
			}
			expActs[act.ClientID] = true
		}
	}
	for _, cg := range clientGates {
		if cg.GateOn && !expActs[cg.ClientID] {
			a.ExperimentalGateCrossProductPass = false
			a.Failures = append(a.Failures, fmt.Sprintf(
				"secondary-1: gate-ON client %q activated zero experimental families",
				cg.ClientID))
		}
	}

	// Secondary 2: trust-UI parity. Every observation's Badge MUST
	// equal LockedFamilyMaturity[family].
	for _, t := range trustUI {
		want, known := LockedFamilyMaturity[t.Family]
		if !known {
			a.TrustUIParityPass = false
			a.Failures = append(a.Failures, fmt.Sprintf(
				"secondary-2: client %q observed unknown family %q",
				t.ClientID, t.Family))
			continue
		}
		if t.Badge != want {
			a.TrustUIParityPass = false
			a.Failures = append(a.Failures, fmt.Sprintf(
				"secondary-2: client %q family %q badge=%s want %s",
				t.ClientID, t.Family, t.Badge, want))
		}
	}

	// Secondary 3: no V1/V2 regression. Caller-supplied boolean
	// (the v2-superset pass/fail). Already wired above.
	if !a.NoV1V2RegressionPass {
		a.Failures = append(a.Failures, "secondary-3: v2-superset regression detected")
	}

	// Secondary 4: per-family burn rate. Aggregate by family;
	// any family whose burn interval < directoryRefreshCadence
	// fails. Families with no burns trivially pass.
	for _, fb := range familyBurns {
		if !fb.Burned {
			continue
		}
		if fb.BurnInterval < directoryRefreshCadence {
			a.PerFamilyBurnRatePass = false
			a.Failures = append(a.Failures, fmt.Sprintf(
				"secondary-4: family %q burned at %s, %s after publish (< cadence %s)",
				fb.Family, fb.FirstBurnAt, fb.BurnInterval, directoryRefreshCadence))
		}
	}

	// Sort failures for deterministic output (eases diffing
	// across runs).
	sort.Strings(a.Failures)
	return a
}

// AllPass returns true iff every metric is green. Convenience for
// the soak driver's exit-code computation.
func (a Aggregate) AllPass() bool {
	return a.CrossPlatformPickupPass &&
		a.ExperimentalGateCrossProductPass &&
		a.TrustUIParityPass &&
		a.NoV1V2RegressionPass &&
		a.PerFamilyBurnRatePass
}

// isExperimental reports whether a family is Experimental at the
// 3-Soak locked maturity table. Unknown families are treated as
// non-experimental (they fail the trust-UI parity metric instead;
// the gate-cross-product metric does not double-fault on them).
func isExperimental(family string) bool {
	m, ok := LockedFamilyMaturity[family]
	return ok && m == MaturityExperimental
}
