package pathmanager

import (
	"fmt"
	"sort"
	"time"
)

// SkippedFamily explains, in one short sentence, why a transport family
// was not chosen at the time of the most recent decision.
//
// Phase 2B widens the struct additively with `Until` (the cooldown
// expiry) and `LadderStep` (1-indexed V2.3 backoff ladder step). The
// pre-2B Reason field is preserved for the legacy Explain() output;
// the new fields are populated by Manager.SkippedFamilies(), which
// drives the `skipped_families[]` array in engine_export_diagnostics.
type SkippedFamily struct {
	Family     string    `json:"family"`
	Reason     string    `json:"reason,omitempty"`
	Until      time.Time `json:"until,omitempty"`
	LadderStep int       `json:"ladder_step,omitempty"`
}

// WhyExplain is a structured "Why this route?" record. It is a
// deterministic transcription of the FSM state — no scoring, no ML.
type WhyExplain struct {
	Bucket          string          `json:"bucket"`
	State           string          `json:"state"`
	ActiveRoute     string          `json:"active_route,omitempty"`
	WhyChoseRoute   string          `json:"why_chose_route"`
	SkippedFamilies []SkippedFamily `json:"skipped_families"`
	LastFailure     *LastFailure    `json:"last_failure,omitempty"`
}

// LastFailure summarizes the most recent failure observed by the FSM.
type LastFailure struct {
	Category string `json:"category"`
	Route    string `json:"route"`
}

// Explain returns the current "Why this route?" record. It locks the
// manager's state once, then emits a deterministic projection.
func (m *Manager) Explain() WhyExplain {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := WhyExplain{
		Bucket:      now.UTC().Truncate(time.Hour).Format("2006-01-02T15:04:05Z"),
		State:       string(m.state),
		ActiveRoute: m.currentRoute,
	}
	switch m.state {
	case StateConnected:
		out.WhyChoseRoute = fmt.Sprintf("Tunnel up on %s.", m.currentRoute)
	case StateConnecting:
		out.WhyChoseRoute = fmt.Sprintf("Attempting %s.", m.currentRoute)
	case StateCooldown:
		out.WhyChoseRoute = fmt.Sprintf("Last attempt failed; cooling down. Reason: %s.", m.lastReason)
	case StateFailed:
		out.WhyChoseRoute = fmt.Sprintf("Last attempt failed without cooldown. Reason: %s.", m.lastReason)
	default:
		out.WhyChoseRoute = "No route is active."
	}

	// Skipped families: anything currently in familyCooldown.
	families := make([]string, 0, len(m.familyCooldown))
	for f := range m.familyCooldown {
		families = append(families, f)
	}
	sort.Strings(families)
	for _, f := range families {
		until := m.familyCooldown[f]
		if !now.Before(until) {
			continue
		}
		out.SkippedFamilies = append(out.SkippedFamilies, SkippedFamily{
			Family: f,
			Reason: fmt.Sprintf("cooldown until %s", until.UTC().Format(time.RFC3339)),
		})
	}
	return out
}
