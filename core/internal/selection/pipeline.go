package selection

import (
	"time"

	"daal/core/netmem"
	"daal/core/routestore"
)

// Input is the complete read-side state the FRP-3 selector pipeline
// needs to make a decision. The pipeline never reads anywhere else;
// the caller assembles this struct from store + netmem + clock.
type Input struct {
	// Routes are the candidate RouteRows the selector may pick.
	// Caller is responsible for filtering out cooled-down rows
	// (CooldownUntil > now); the pipeline does not re-check.
	Routes []routestore.RouteRow

	// NetMem is the per-network memory snapshot. nil-safe.
	NetMem *netmem.Snapshot

	// NetworkSignals are the active probe-derived signals at decision
	// time (e.g. SignalUDPCollapsed, SignalDNSBogonDetected). The
	// pipeline preserves these in Explanation.NetworkSignals and
	// uses them to inform PlanRace + scoring.
	NetworkSignals []NetworkSignal

	// Mode is the user's race mode (lifeline / lifeline-strict /
	// normal / bulk).
	Mode Mode

	// Phase pins which selection rules are live. Defaults to V1.5
	// when zero-value.
	Phase Phase

	// Now is the decision-time wall clock. Pure for tests.
	Now time.Time

	// DecisionID is supplied by the caller; surfaced in Explanation.
	DecisionID string
}

// Output is the pipeline's decision: the picked candidate (if any),
// the staggered race plan, and the locked Explanation contract for
// FRP-6 / diagnostics.
type Output struct {
	Pick        *Candidate
	Shortlist   []Candidate
	Race        RacePlan
	Explanation *Explanation
}

// Decide is the FRP-3 selector pipeline entry point. Pure function
// of (Input). Never mutates Input. Never opens a network connection.
//
// Steps:
//  1. Project RouteRows → Candidates (one parse per row).
//  2. Compute Shortlist via diversity scoring + hard cdn rule.
//  3. PlanRace from shortlist + mode + signals.
//  4. Build Explanation: pick (shortlist[0]), shortlist positions
//     with staggered start_at_ms, network_signals, memory_hint
//     (for the leader), and a human-readable reason.
//
// The pipeline does NOT apply cooldowns or write to network memory
// here — those are the caller's responsibility once the race
// outcome is known. The selector is read-only; PropagateCooldown
// and Apply are pure functions the caller invokes after the race.
func Decide(in Input) Output {
	if in.Phase == "" {
		in.Phase = PhaseV15
	}

	// 1. Project. Drop rows that fail to parse (defensive — the
	//    importer should have rejected them, but the selector
	//    must not panic on malformed graphs).
	cands := make([]Candidate, 0, len(in.Routes))
	for _, r := range in.Routes {
		c, err := ProjectFromRouteRow(r)
		if err != nil {
			continue
		}
		c.RankScore = rankCandidate(c, in.NetMem, in.NetworkSignals)
		cands = append(cands, c)
	}

	// 2. Shortlist. The race policy determines the visible
	// shortlist size up front; lifeline-strict and active-probe
	// signals must not leak extra candidates into the explanation.
	shortlistSize := RaceShortlistSize(cands, in.Mode, in.NetworkSignals)
	shortlist := Shortlist(cands, shortlistSize, in.Phase)

	// 3. Race plan.
	race := PlanRace(shortlist, in.Mode, in.NetworkSignals)
	if race.Racemates < len(shortlist) {
		shortlist = shortlist[:race.Racemates]
		race = PlanRace(shortlist, in.Mode, in.NetworkSignals)
	}

	// 4. Build Explanation.
	exp := NewExplanation(in.DecisionID, in.Phase)
	exp.NetworkSignals = SignalStrings(in.NetworkSignals)

	if len(shortlist) == 0 {
		exp.Reason = "No candidates available."
		return Output{Shortlist: shortlist, Race: race, Explanation: exp}
	}

	leader := shortlist[0]
	pick := leader

	exp.Pick = PickedCandidate{
		RouteID:      pick.RouteID,
		Family:       pick.TransportFamily,
		ExposureMode: pick.ExposureMode,
		FamilyClass:  pick.FamilyClass,
		ProbingRisk:  pick.ProbingRiskClass,
	}

	// Shortlist entries with staggered start_at_ms. Outcome is
	// "success" for the leader (we don't simulate the race here;
	// the pipeline returns a *plan* for the engine to execute) and
	// "not_started" for the others — this matches the Explanation
	// contract before race execution.
	for i, c := range shortlist {
		entry := ShortlistEntry{
			RouteID:     c.RouteID,
			Position:    i,
			StartedAtMs: i * race.StaggerMs,
		}
		if i == 0 {
			entry.Outcome = "success"
		} else {
			entry.Outcome = "not_started"
		}
		exp.Shortlist = append(exp.Shortlist, entry)
	}

	// Memory hint for the leader.
	if in.NetMem != nil {
		sig := PublicRiskTagSignature(leader.PublicRiskTags)
		if hint := LookupHint(in.NetMem, leader.TransportFamily, leader.ExposureMode, sig); hint != nil {
			exp.MemoryHint = hint
		}
	}

	exp.Reason = renderReason(in.Phase, leader, len(shortlist), race)

	return Output{
		Pick:        &pick,
		Shortlist:   shortlist,
		Race:        race,
		Explanation: exp,
	}
}

func rankCandidate(c Candidate, snap *netmem.Snapshot, signals []NetworkSignal) int {
	score := 0
	switch c.ProbingRiskClass {
	case "low":
		score += 50
	case "moderate":
		score += 20
	case "high":
		score -= 100
	}
	if c.UDPGated {
		for _, s := range signals {
			switch s {
			case SignalUDPCollapsed, SignalQUICCollapsed, SignalProtocolWhitelistMode:
				score -= 500
			}
		}
	}
	if snap != nil {
		sig := PublicRiskTagSignature(c.PublicRiskTags)
		if hint := LookupHint(snap, c.TransportFamily, c.ExposureMode, sig); hint != nil {
			exact := hint.Signature == sig && sig != ""
			switch hint.LastOutcome {
			case OutcomeSuccess:
				if exact {
					score += 2000
				} else {
					score += 150
				}
			case OutcomeClassifiedFailure:
				if exact {
					score -= 1200
				} else {
					score -= 150
				}
			}
		}
	}
	return score
}

// renderReason produces a stable, human-readable reason string for
// the Explanation. Pure function; same inputs → same output.
func renderReason(phase Phase, leader Candidate, shortlistN int, race RacePlan) string {
	mode := leader.ExposureMode
	if mode == "" {
		mode = "legacy"
	}
	switch {
	case race.Sequential:
		return "Selected " + leader.TransportFamily + " on the leader (" + mode + "); race is sequential (lifeline-strict or all-high probing risk)."
	case shortlistN == 1:
		return "Only one eligible candidate at " + string(phase) + "; running " + leader.TransportFamily + " on " + mode + "."
	default:
		return "Used " + leader.TransportFamily + " on the leader " + mode + "; secondary candidates staggered."
	}
}
