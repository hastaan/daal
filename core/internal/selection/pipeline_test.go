package selection

import (
	"testing"
	"time"

	"daal/core/netmem"
	"daal/core/routestore"
)

func makeRow(id, family, mode string, tags ...string) routestore.RouteRow {
	return routestore.RouteRow{
		RouteID:             id,
		TransportFamily:     family,
		ExposureMode:        mode,
		FamilyClass:         "vps-native",
		ProbingRiskClass:    "low",
		PublicRiskTags:      append([]string{}, tags...),
		SharedRiskGraphJSON: "[]",
	}
}

func TestDecide_NoRoutes(t *testing.T) {
	out := Decide(Input{Phase: PhaseV15, Now: time.Now(), DecisionID: "test-empty"})
	if out.Pick != nil {
		t.Errorf("expected nil pick on empty input")
	}
	if out.Explanation.Reason != "No candidates available." {
		t.Errorf("reason = %q", out.Explanation.Reason)
	}
	if out.Explanation.DecisionID != "test-empty" {
		t.Errorf("decision_id not propagated")
	}
}

func TestDecide_SingleVPSPickAndStagger(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
		makeRow("rB", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
		makeRow("rC", "naive", "direct_vps", "public_ip:5.75.0.1"),
	}
	out := Decide(Input{
		Routes:     rows,
		Phase:      PhaseV15,
		Mode:       ModeNormal,
		Now:        time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		DecisionID: "test-single-vps",
	})
	if out.Pick == nil || out.Pick.RouteID != "rA" {
		t.Fatalf("expected leader rA; got %+v", out.Pick)
	}
	if len(out.Explanation.Shortlist) != 3 {
		t.Errorf("expected shortlist size 3; got %d", len(out.Explanation.Shortlist))
	}
	if out.Explanation.Shortlist[0].StartedAtMs != 0 {
		t.Errorf("leader start_at_ms must be 0; got %d", out.Explanation.Shortlist[0].StartedAtMs)
	}
	if out.Explanation.Shortlist[1].StartedAtMs != 400 {
		t.Errorf("position-1 start_at_ms must be 400; got %d", out.Explanation.Shortlist[1].StartedAtMs)
	}
	if out.Explanation.Shortlist[2].StartedAtMs != 800 {
		t.Errorf("position-2 start_at_ms must be 800; got %d", out.Explanation.Shortlist[2].StartedAtMs)
	}
	if out.Race.Racemates != 3 || out.Race.StaggerMs != 400 {
		t.Errorf("default race plan wrong: %+v", out.Race)
	}
}

func TestDecide_MemoryHintPopulated(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
	}
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	snap := &netmem.Snapshot{
		LastSeen: pin,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {
				Successes: 2,
				ByRelayPack: []netmem.RelayPackStat{
					{
						Key: netmem.RelayPackKey{
							Family:                 "vless-reality",
							ExposureMode:           "direct_vps",
							PublicRiskTagSignature: "public_ip:5.75.0.1",
							Outcome:                OutcomeSuccess,
						},
						Successes: 2,
					},
				},
			},
		},
	}
	out := Decide(Input{
		Routes: rows, NetMem: snap, Phase: PhaseV15, Mode: ModeNormal,
		Now: pin, DecisionID: "test-mem-hint",
	})
	if out.Explanation.MemoryHint == nil {
		t.Fatal("memory_hint must be populated when exact match exists")
	}
	if out.Explanation.MemoryHint.Signature != "public_ip:5.75.0.1" {
		t.Errorf("hint signature wrong: %q", out.Explanation.MemoryHint.Signature)
	}
	if out.Explanation.MemoryHint.LastOutcome != OutcomeSuccess {
		t.Errorf("hint outcome wrong: %q", out.Explanation.MemoryHint.LastOutcome)
	}
}

func TestDecide_MemorySuccessInfluencesLeader(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.1.1.1"),
		makeRow("rB", "naive", "direct_vps", "public_ip:2.2.2.2"),
	}
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	snap := &netmem.Snapshot{
		LastSeen: pin,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"naive": {
				Successes: 4,
				ByRelayPack: []netmem.RelayPackStat{{
					Key: netmem.RelayPackKey{
						Family:                 "naive",
						ExposureMode:           "direct_vps",
						PublicRiskTagSignature: "public_ip:2.2.2.2",
						Outcome:                OutcomeSuccess,
					},
					Successes: 4,
				}},
			},
		},
	}
	out := Decide(Input{
		Routes: rows, NetMem: snap, Phase: PhaseV15, Mode: ModeNormal,
		Now: pin, DecisionID: "test-memory-rank",
	})
	if out.Pick == nil || out.Pick.RouteID != "rB" {
		t.Fatalf("memory winner must become leader; got %+v", out.Pick)
	}
	if out.Explanation.MemoryHint == nil || out.Explanation.MemoryHint.LastOutcome != OutcomeSuccess {
		t.Fatalf("expected success memory hint for leader; got %+v", out.Explanation.MemoryHint)
	}
}

func TestDecide_LifelineStrictShortlistSizedOne(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.1.1.1"),
		makeRow("rB", "naive", "direct_vps", "public_ip:2.2.2.2"),
		makeRow("rC", "websocket-tls", "direct_vps", "public_ip:3.3.3.3"),
	}
	out := Decide(Input{
		Routes: rows, Phase: PhaseV15, Mode: ModeLifelineStrict,
		Now: time.Now(), DecisionID: "test-lifeline-size",
	})
	if len(out.Shortlist) != 1 || len(out.Explanation.Shortlist) != 1 {
		t.Fatalf("lifeline-strict must expose one candidate; got shortlist=%d explanation=%d",
			len(out.Shortlist), len(out.Explanation.Shortlist))
	}
	if out.Race.Racemates != 1 || !out.Race.Sequential {
		t.Fatalf("lifeline-strict race plan wrong: %+v", out.Race)
	}
}

func TestDecide_StatefulSignalShortlistSizedTwo(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.1.1.1"),
		makeRow("rB", "naive", "direct_vps", "public_ip:2.2.2.2"),
		makeRow("rC", "websocket-tls", "direct_vps", "public_ip:3.3.3.3"),
	}
	out := Decide(Input{
		Routes: rows, Phase: PhaseV15, Mode: ModeNormal,
		NetworkSignals: []NetworkSignal{SignalStatefulReassemblyPresent},
		Now:            time.Now(), DecisionID: "test-stateful-size",
	})
	if len(out.Shortlist) != 2 || len(out.Explanation.Shortlist) != 2 {
		t.Fatalf("stateful signal must expose two candidates; got shortlist=%d explanation=%d",
			len(out.Shortlist), len(out.Explanation.Shortlist))
	}
	if out.Race.Racemates != 2 || out.Race.Sequential {
		t.Fatalf("stateful signal race plan wrong: %+v", out.Race)
	}
}

func TestDecide_AllHighAfterRankingShortlistSizedOne(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.1.1.1"),
		{
			RouteID:             "rB",
			TransportFamily:     "naive",
			ExposureMode:        "direct_vps",
			FamilyClass:         "vps-native",
			ProbingRiskClass:    "high",
			PublicRiskTags:      []string{"public_ip:2.2.2.2"},
			SharedRiskGraphJSON: "[]",
		},
		{
			RouteID:             "rC",
			TransportFamily:     "websocket-tls",
			ExposureMode:        "direct_vps",
			FamilyClass:         "vps-native",
			ProbingRiskClass:    "high",
			PublicRiskTags:      []string{"public_ip:3.3.3.3"},
			SharedRiskGraphJSON: "[]",
		},
		{
			RouteID:             "rD",
			TransportFamily:     "hysteria2",
			ExposureMode:        "direct_vps",
			FamilyClass:         "vps-native",
			ProbingRiskClass:    "high",
			PublicRiskTags:      []string{"public_ip:4.4.4.4"},
			SharedRiskGraphJSON: "[]",
		},
	}
	pin := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	snap := &netmem.Snapshot{
		LastSeen: pin,
		RouteFamilyStats: map[string]netmem.FamilyStats{
			"vless-reality": {
				Failures: 4,
				ByRelayPack: []netmem.RelayPackStat{{
					Key: netmem.RelayPackKey{
						Family:                 "vless-reality",
						ExposureMode:           "direct_vps",
						PublicRiskTagSignature: "public_ip:1.1.1.1",
						Outcome:                OutcomeClassifiedFailure,
					},
					Failures: 4,
				}},
			},
		},
	}
	out := Decide(Input{
		Routes: rows, NetMem: snap, Phase: PhaseV15, Mode: ModeNormal,
		Now: pin, DecisionID: "test-post-rank-high-size",
	})
	if len(out.Shortlist) != 1 || len(out.Explanation.Shortlist) != 1 {
		t.Fatalf("all-high final shortlist must expose one candidate; got shortlist=%d explanation=%d",
			len(out.Shortlist), len(out.Explanation.Shortlist))
	}
	if out.Race.Racemates != 1 || !out.Race.Sequential {
		t.Fatalf("all-high final race plan wrong: %+v", out.Race)
	}
}

func TestDecide_NetworkSignalsPropagated(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.2.3.4"),
	}
	out := Decide(Input{
		Routes:         rows,
		NetworkSignals: []NetworkSignal{SignalDNSBogonDetected, SignalUDPCollapsed},
		Phase:          PhaseV15,
		Mode:           ModeNormal,
		Now:            time.Now(),
		DecisionID:     "test-signals",
	})
	if len(out.Explanation.NetworkSignals) != 2 {
		t.Fatalf("expected 2 signals propagated; got %v", out.Explanation.NetworkSignals)
	}
}

func TestDecide_MalformedRowsFilteredOut(t *testing.T) {
	rows := []routestore.RouteRow{
		{RouteID: "broken", SharedRiskGraphJSON: "not json"},
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.2.3.4"),
	}
	out := Decide(Input{
		Routes: rows, Phase: PhaseV15, Mode: ModeNormal,
		Now: time.Now(), DecisionID: "test-malformed",
	})
	if out.Pick == nil || out.Pick.RouteID != "rA" {
		t.Errorf("malformed row must be filtered; got pick %+v", out.Pick)
	}
}

func TestDecide_DefaultPhaseIsV15(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:1.2.3.4"),
	}
	out := Decide(Input{
		Routes: rows, Mode: ModeNormal, Now: time.Now(), DecisionID: "test-default-phase",
	})
	if out.Explanation.Phase != string(PhaseV15) {
		t.Errorf("default phase must be V1.5; got %q", out.Explanation.Phase)
	}
}

func TestDecide_DeterministicAcrossRuns(t *testing.T) {
	rows := []routestore.RouteRow{
		makeRow("rA", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
		makeRow("rB", "vless-reality", "direct_vps", "public_ip:5.75.0.1"),
		makeRow("rC", "naive", "direct_vps", "public_ip:5.75.0.1"),
	}
	in := Input{
		Routes: rows, Phase: PhaseV15, Mode: ModeNormal,
		Now:        time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
		DecisionID: "test-determinism",
	}
	a := Decide(in)
	b := Decide(in)
	if a.Pick.RouteID != b.Pick.RouteID {
		t.Errorf("non-determinism: %s vs %s", a.Pick.RouteID, b.Pick.RouteID)
	}
	if a.Explanation.Reason != b.Explanation.Reason {
		t.Errorf("reason non-deterministic")
	}
}
