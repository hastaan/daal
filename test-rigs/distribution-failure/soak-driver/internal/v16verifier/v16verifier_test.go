package v16verifier

import "testing"

func TestVerify_AllPass(t *testing.T) {
	got := Verify("run-pass", append(twoFRPsAllMetrics(), Observation{Metric: MetricG1, Pass: true}))
	if !got.AllPass() {
		t.Fatalf("expected all pass: %+v", got)
	}
	if got.ObservedPilotFRPs != 2 {
		t.Fatalf("ObservedPilotFRPs=%d, want 2", got.ObservedPilotFRPs)
	}
}

func TestVerify_MissingPilotFRP(t *testing.T) {
	rows := []Observation{
		{FRPID: "frp-1", Metric: MetricP1, Pass: true},
		{FRPID: "frp-1", Metric: MetricP2, Pass: true},
		{FRPID: "frp-1", Metric: MetricS1, Pass: true},
		{FRPID: "frp-1", Metric: MetricS2, Pass: true},
		{FRPID: "frp-1", Metric: MetricS3, Pass: true},
		{Metric: MetricG1, Pass: true},
	}
	got := Verify("run-one-frp", rows)
	if got.AllPass() {
		t.Fatal("one FRP must not close V1.6")
	}
	if got.P1ConnectedWithin60sPass {
		t.Fatal("P1 should fail with only one FRP")
	}
}

func TestVerify_ExplicitFailure(t *testing.T) {
	rows := append(twoFRPsAllMetrics(), Observation{Metric: MetricG1, Pass: true})
	rows = append(rows, Observation{FRPID: "frp-2", Metric: MetricS2, Pass: false, Detail: "origin leak probe failed"})
	got := Verify("run-fail", rows)
	if got.S2HardeningLeakProbePass {
		t.Fatal("S2 should fail when an FRP row fails")
	}
	if got.AllPass() {
		t.Fatal("AllPass should be false")
	}
	if len(got.Failures) == 0 {
		t.Fatal("expected failure details")
	}
}

func TestVerify_SyntheticGateRequired(t *testing.T) {
	got := Verify("run-no-g1", twoFRPsAllMetrics())
	if got.G1SyntheticSupersetPass {
		t.Fatal("G1 should require explicit synthetic pass row")
	}
	if got.AllPass() {
		t.Fatal("AllPass should be false without G1")
	}
}

func twoFRPsAllMetrics() []Observation {
	var rows []Observation
	for _, frp := range []string{"frp-1", "frp-2"} {
		for _, metric := range []Metric{MetricP1, MetricP2, MetricS1, MetricS2, MetricS3} {
			rows = append(rows, Observation{FRPID: frp, Metric: metric, Pass: true})
		}
	}
	return rows
}
