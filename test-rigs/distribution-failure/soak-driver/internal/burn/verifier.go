package burn

import (
	"fmt"
	"time"
)

// RouteVerdict is the per-route ledger row the verifier emits.
// `BurnInterval` is the elapsed time between the route's first
// publication into the directory and its first burn instant. The
// primary metric requires this interval to be ≥ the directory's
// refresh cadence.
type RouteVerdict struct {
	RouteID        string        `json:"route_id"`
	FirstPublishAt time.Time     `json:"first_publish_at"`
	FirstBurnAt    time.Time     `json:"first_burn_at,omitempty"`
	BurnInterval   time.Duration `json:"burn_interval_ns,omitempty"`
	Burned         bool          `json:"burned"`
	PassesPrimary  bool          `json:"passes_primary"`
}

// Aggregate is the verifier's top-level output.
type Aggregate struct {
	DirectoryRefreshCadence time.Duration  `json:"directory_refresh_cadence_ns"`
	RouteVerdicts           []RouteVerdict `json:"route_verdicts"`

	// Five aggregate metrics — see specs/v2-success-metric-v1.md.
	PassByDirectoryRotation  bool `json:"pass_by_directory_rotation"`      // primary
	RotationCorrectnessPass  bool `json:"rotation_correctness_pass"`       // secondary
	BudgetEnforcementPass    bool `json:"budget_enforcement_pass"`         // tertiary
	FailureReasonCoverage    bool `json:"failure_reason_coverage"`         // quaternary
	AutoPromotionCorrectPass bool `json:"auto_promotion_correctness_pass"` // quinary

	// Detail messages for any failed aggregate metric.
	Failures []string `json:"failures,omitempty"`
}

// Verify computes the aggregate verdict over the per-route ledger.
// The five metrics are independent; a single failure does NOT
// short-circuit the others (the verifier reports all failures so
// the operator can fix in one pass).
func Verify(
	routeVerdicts []RouteVerdict,
	directoryRefreshCadence time.Duration,
	rotationCorrectness bool,
	budgetEnforcement bool,
	failureReasonCoverage bool,
	autoPromotionCorrectness bool,
) Aggregate {
	a := Aggregate{
		DirectoryRefreshCadence:  directoryRefreshCadence,
		RouteVerdicts:            routeVerdicts,
		PassByDirectoryRotation:  true,
		RotationCorrectnessPass:  rotationCorrectness,
		BudgetEnforcementPass:    budgetEnforcement,
		FailureReasonCoverage:    failureReasonCoverage,
		AutoPromotionCorrectPass: autoPromotionCorrectness,
	}
	for i := range a.RouteVerdicts {
		v := &a.RouteVerdicts[i]
		if !v.Burned {
			v.PassesPrimary = true
			continue
		}
		v.PassesPrimary = v.BurnInterval >= directoryRefreshCadence
		if !v.PassesPrimary {
			a.PassByDirectoryRotation = false
			a.Failures = append(a.Failures, fmt.Sprintf(
				"primary: route %s burned at %s, %s after publish (< cadence %s)",
				v.RouteID, v.FirstBurnAt, v.BurnInterval, directoryRefreshCadence))
		}
	}
	if !rotationCorrectness {
		a.Failures = append(a.Failures, "secondary: rotation correctness failed")
	}
	if !budgetEnforcement {
		a.Failures = append(a.Failures, "tertiary: budget enforcement failed")
	}
	if !failureReasonCoverage {
		a.Failures = append(a.Failures, "quaternary: failure-reason coverage failed")
	}
	if !autoPromotionCorrectness {
		a.Failures = append(a.Failures, "quinary: auto-promotion correctness failed")
	}
	return a
}

// AllPass reports whether every aggregate metric passed.
func (a Aggregate) AllPass() bool {
	return a.PassByDirectoryRotation &&
		a.RotationCorrectnessPass &&
		a.BudgetEnforcementPass &&
		a.FailureReasonCoverage &&
		a.AutoPromotionCorrectPass
}
