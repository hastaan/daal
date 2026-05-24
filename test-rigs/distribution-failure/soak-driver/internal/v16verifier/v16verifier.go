// Package v16verifier aggregates the FRP-9 V1.6 CDN-fronted
// alpha-soak evidence rows. It mirrors internal/v3verifier's role:
// it is a local, stdlib-only closure helper, not a telemetry path.
package v16verifier

import (
	"fmt"
	"sort"
)

type Metric string

const (
	MetricP1 Metric = "V1.6-P1"
	MetricP2 Metric = "V1.6-P2"
	MetricS1 Metric = "V1.6-S1"
	MetricS2 Metric = "V1.6-S2"
	MetricS3 Metric = "V1.6-S3"
	MetricG1 Metric = "V1.6-G1"
)

// Observation is one anonymized metric row. FRPID is empty only for
// synthetic-only rows such as V1.6-G1.
type Observation struct {
	FRPID  string `json:"frp_id,omitempty"`
	Metric Metric `json:"metric"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Aggregate is the machine-readable V1.6 closure verdict. The first
// five metric booleans require two distinct pilot FRPs to pass. G1 is
// the synthetic rig gate.
type Aggregate struct {
	RunID string `json:"run_id"`

	P1ConnectedWithin60sPass     bool     `json:"p1_connected_within_60s_pass"`
	P2FreshnessAtomicSwapPass    bool     `json:"p2_freshness_atomic_swap_pass"`
	S1UptimeCooldownRotationPass bool     `json:"s1_uptime_cooldown_rotation_pass"`
	S2HardeningLeakProbePass     bool     `json:"s2_hardening_leak_probe_pass"`
	S3RelayPackConformancePass   bool     `json:"s3_relaypack_conformance_pass"`
	G1SyntheticSupersetPass      bool     `json:"g1_synthetic_superset_pass"`
	RequiredPilotFRPs            int      `json:"required_pilot_frps"`
	ObservedPilotFRPs            int      `json:"observed_pilot_frps"`
	Failures                     []string `json:"failures,omitempty"`
}

func Verify(runID string, observations []Observation) Aggregate {
	const requiredPilotFRPs = 2
	a := Aggregate{
		RunID:                        runID,
		P1ConnectedWithin60sPass:     true,
		P2FreshnessAtomicSwapPass:    true,
		S1UptimeCooldownRotationPass: true,
		S2HardeningLeakProbePass:     true,
		S3RelayPackConformancePass:   true,
		G1SyntheticSupersetPass:      false,
		RequiredPilotFRPs:            requiredPilotFRPs,
	}

	byMetric := map[Metric]map[string]bool{}
	pilotFRPs := map[string]bool{}
	for _, obs := range observations {
		if byMetric[obs.Metric] == nil {
			byMetric[obs.Metric] = map[string]bool{}
		}
		key := obs.FRPID
		if key == "" {
			key = "_synthetic"
		} else {
			pilotFRPs[obs.FRPID] = true
		}
		if obs.Pass {
			byMetric[obs.Metric][key] = true
		} else {
			byMetric[obs.Metric][key] = false
			if obs.Detail != "" {
				a.Failures = append(a.Failures, fmt.Sprintf("%s/%s: %s", obs.Metric, key, obs.Detail))
			}
		}
	}
	a.ObservedPilotFRPs = len(pilotFRPs)

	a.P1ConnectedWithin60sPass = requirePilotPass(byMetric[MetricP1], requiredPilotFRPs)
	a.P2FreshnessAtomicSwapPass = requirePilotPass(byMetric[MetricP2], requiredPilotFRPs)
	a.S1UptimeCooldownRotationPass = requirePilotPass(byMetric[MetricS1], requiredPilotFRPs)
	a.S2HardeningLeakProbePass = requirePilotPass(byMetric[MetricS2], requiredPilotFRPs)
	a.S3RelayPackConformancePass = requirePilotPass(byMetric[MetricS3], requiredPilotFRPs)
	a.G1SyntheticSupersetPass = byMetric[MetricG1]["_synthetic"]

	addMissing := func(ok bool, metric Metric) {
		if !ok {
			a.Failures = append(a.Failures, fmt.Sprintf("%s: need %d passing pilot FRPs", metric, requiredPilotFRPs))
		}
	}
	addMissing(a.P1ConnectedWithin60sPass, MetricP1)
	addMissing(a.P2FreshnessAtomicSwapPass, MetricP2)
	addMissing(a.S1UptimeCooldownRotationPass, MetricS1)
	addMissing(a.S2HardeningLeakProbePass, MetricS2)
	addMissing(a.S3RelayPackConformancePass, MetricS3)
	if !a.G1SyntheticSupersetPass {
		a.Failures = append(a.Failures, string(MetricG1)+": synthetic v1-6-superset did not pass")
	}
	sort.Strings(a.Failures)
	return a
}

func requirePilotPass(rows map[string]bool, want int) bool {
	if len(rows) < want {
		return false
	}
	n := 0
	for frp, pass := range rows {
		if frp == "_synthetic" {
			continue
		}
		if pass {
			n++
		}
	}
	return n >= want
}

func (a Aggregate) AllPass() bool {
	return a.P1ConnectedWithin60sPass &&
		a.P2FreshnessAtomicSwapPass &&
		a.S1UptimeCooldownRotationPass &&
		a.S2HardeningLeakProbePass &&
		a.S3RelayPackConformancePass &&
		a.G1SyntheticSupersetPass
}
