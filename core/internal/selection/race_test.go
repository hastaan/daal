package selection

import (
	"testing"
)

func TestPlanRace_DefaultThreeWith400msStagger(t *testing.T) {
	cands := []Candidate{
		cand("a", "vless-reality", "direct_vps", "low"),
		cand("b", "naive", "direct_vps", "low"),
		cand("c", "websocket-tls", "direct_vps", "low"),
	}
	p := PlanRace(cands, ModeNormal, nil)
	if p.Racemates != 3 || p.StaggerMs != 400 || p.Sequential {
		t.Errorf("default plan wrong: %+v", p)
	}
}

func TestPlanRace_LifelineStrictSequential(t *testing.T) {
	cands := []Candidate{
		cand("a", "vless-reality", "direct_vps", "low"),
		cand("b", "naive", "direct_vps", "low"),
	}
	p := PlanRace(cands, ModeLifelineStrict, nil)
	if p.Racemates != 1 || p.StaggerMs != 0 || !p.Sequential {
		t.Errorf("lifeline-strict must be sequential 1; got %+v", p)
	}
}

func TestPlanRace_StatefulReassemblyLimitsToTwo(t *testing.T) {
	cands := []Candidate{
		cand("a", "vless-reality", "direct_vps", "low"),
		cand("b", "naive", "direct_vps", "low"),
		cand("c", "websocket-tls", "direct_vps", "low"),
	}
	p := PlanRace(cands, ModeNormal, []NetworkSignal{SignalStatefulReassemblyPresent})
	if p.Racemates != 2 || p.StaggerMs != 400 || p.Sequential {
		t.Errorf("stateful_reassembly must yield 2-mate race; got %+v", p)
	}
}

func TestPlanRace_AllHighProbingRiskSequential(t *testing.T) {
	cands := []Candidate{
		cand("a", "vless-reality", "direct_vps", "high"),
		cand("b", "naive", "direct_vps", "high"),
	}
	p := PlanRace(cands, ModeNormal, nil)
	if p.Racemates != 1 || !p.Sequential {
		t.Errorf("all-high-probing must be sequential; got %+v", p)
	}
}

// TestPlanRace_ShortlistShorterThanThree caps racemates to shortlist
// length to avoid over-counting.
func TestPlanRace_ShortlistShorterThanThree(t *testing.T) {
	cands := []Candidate{
		cand("a", "vless-reality", "direct_vps", "low"),
	}
	p := PlanRace(cands, ModeNormal, nil)
	if p.Racemates != 1 {
		t.Errorf("racemates must cap at shortlist len 1; got %d", p.Racemates)
	}
}
