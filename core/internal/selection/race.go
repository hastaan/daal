package selection

// Mode is the user-selected mode that influences race policy.
// 1.5/2 vocabulary: lifeline / normal / bulk. Lifeline-strict is a
// stricter sub-mode of lifeline; selector treats it sequentially.
type Mode string

const (
	ModeLifeline       Mode = "lifeline"
	ModeLifelineStrict Mode = "lifeline-strict"
	ModeNormal         Mode = "normal"
	ModeBulk           Mode = "bulk"
)

// RacePlan describes how the engine should race the shortlist.
//
// `Racemates` is the count of candidates that should be raced
// concurrently (with `StaggerMs` between them). `Sequential` is
// true when racing is disallowed and the engine must try
// candidates strictly one at a time.
type RacePlan struct {
	Racemates  int
	StaggerMs  int
	Sequential bool
}

// PlanRace computes the anti-burn race policy per supplement §15:
//
//   - Default: 3 racemates, 400 ms stagger.
//   - lifeline-strict: 1 (sequential).
//   - StatefulReassemblyPresent in signals: 2 (active-probe shape).
//   - All-probing_risk_class:high shortlist: sequential
//     per §15.3 (a careless deployment with all-high shortlist
//     self-limits to non-parallel racing).
//
// Pure function; no clock; no state.
func PlanRace(shortlist []Candidate, mode Mode, signals []NetworkSignal) RacePlan {
	size := RaceShortlistSize(shortlist, mode, signals)
	if size == 0 {
		return RacePlan{Racemates: 0, StaggerMs: 0, Sequential: false}
	}
	if mode == ModeLifelineStrict || allHighProbingRisk(shortlist) {
		return RacePlan{Racemates: 1, StaggerMs: 0, Sequential: true}
	}
	for _, s := range signals {
		if s == SignalStatefulReassemblyPresent {
			return RacePlan{Racemates: size, StaggerMs: 400, Sequential: false}
		}
	}
	return RacePlan{Racemates: size, StaggerMs: 400, Sequential: false}
}

// RaceShortlistSize returns the maximum shortlist size allowed by
// the anti-burn race policy. Decide calls this before Shortlist so
// Explanation.Shortlist exposes only the candidates the engine is
// allowed to race in this decision.
func RaceShortlistSize(cands []Candidate, mode Mode, signals []NetworkSignal) int {
	if len(cands) == 0 {
		return 0
	}
	if mode == ModeLifelineStrict {
		return 1
	}
	if allHighProbingRisk(cands) {
		return 1
	}
	for _, s := range signals {
		if s == SignalStatefulReassemblyPresent {
			return minInt(2, len(cands))
		}
	}
	return minInt(3, len(cands))
}

// allHighProbingRisk reports whether every candidate on the
// shortlist has probing_risk_class == "high". A non-empty shortlist
// with one or more empty/low/moderate values returns false.
func allHighProbingRisk(cands []Candidate) bool {
	if len(cands) == 0 {
		return false
	}
	for _, c := range cands {
		if c.ProbingRiskClass != "high" {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
