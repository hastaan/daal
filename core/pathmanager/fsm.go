// Package pathmanager is the deterministic state machine that decides
// whether to attempt a route, leave it cooling down, or surface a failure
// to the user. Phase 1B ships the minimal slice: per-route cooldown,
// per-family cooldown, the auth_failed exemption, and the "why this
// route?" explanation strings.
//
// Phase 2 (V2) adds shortlist racing, per-network memory, route budgets,
// and mode-aware selection. None of those are implemented here.
package pathmanager

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"daal/core/diagnostics"
)

// sortRouteHealth sorts a RouteHealth slice in-place by route_id
// (stable, ascending) so diagnostics output is byte-stable.
func sortRouteHealth(rh []RouteHealth) {
	sort.SliceStable(rh, func(i, j int) bool { return rh[i].RouteID < rh[j].RouteID })
}

// sortSkipped sorts a SkippedFamily slice in-place by family name.
func sortSkipped(s []SkippedFamily) {
	sort.SliceStable(s, func(i, j int) bool { return s[i].Family < s[j].Family })
}

// State is the FSM state.
type State string

const (
	StateNoRoute    State = "NoRoute"
	StateConnecting State = "Connecting"
	StateConnected  State = "Connected"
	StateCooldown   State = "Cooldown"
	StateFailed     State = "Failed"
	// StateBudgetExhausted (Phase 2A) is entered when a route's hourly
	// byte cap is hit. The state clears at the next hour bucket; the
	// scheduler's KindBudgetReset action fires HourRollover and the
	// caller flips back to NoRoute. The 8-state FSM landing in 2B
	// expands this into per-cause cooldowns; 2A keeps it minimal.
	StateBudgetExhausted State = "BudgetExhausted"
)

// RouteHealth is the per-route attribute tracked by the FSM. Phase
// 2B surfaces it through `engine_export_diagnostics.route_health[]`.
// It is the projection the desktop's RouteHealthTable consumes.
type RouteHealth struct {
	RouteID         string               `json:"route_id"`
	InCooldown      bool                 `json:"in_cooldown"`
	CooldownReason  diagnostics.Category `json:"cooldown_reason,omitempty"`
	CooldownUntil   time.Time            `json:"cooldown_until,omitempty"`
	BudgetExhausted bool                 `json:"budget_exhausted"`
}

// Manager owns the FSM. Phase 2B widens it with a parallel `posture`
// axis (V2.3 8-state vocabulary), per-route health (`routeHealth`),
// and the V2.3 family-escalation counter (`familyEscalation`). All
// existing fields and methods that 1B/1C/1.5/2A callers rely on are
// preserved untouched.
type Manager struct {
	mu             sync.Mutex
	state          State
	currentRoute   string
	currentFamily  string
	routeCooldown  map[string]time.Time
	familyCooldown map[string]time.Time
	failures       map[string][]time.Time // family → recent failure timestamps (hour-bucketed)
	lastReason     string
	now            func() time.Time

	// Phase 2B additions:

	// posture is the V2.3 application-posture axis. Orthogonal to
	// `state`. Default is PostureNoRoute.
	posture Posture

	// routeHealth carries per-route cooldown/budget attributes.
	// Updated on Failed and on BudgetExhausted; consumed by
	// RouteHealth().
	routeHealth map[string]RouteHealth

	// familyEscalation is the family-cooldown ladder step counter
	// keyed by `familyEscKey(family, activeNetwork)`. 0 = no
	// cooldown. Reset on a successful Connected() in the same
	// family on the same network.
	//
	// Phase 2C widens the key from `family` to `(family,
	// network_id)`; the empty-string activeNetwork case (which is
	// what every pre-2C call site supplies) collapses to the legacy
	// `family` form so 2B tests stay byte-stable.
	familyEscalation map[string]int

	// familyLastReason carries the V0.3 category that drove the most
	// recent family cooldown. Surfaced as part of LastReason for the
	// V2.3 user-visible "VLESS-Reality routes are cooling down…"
	// message. Keyed identically to familyEscalation.
	familyLastReason map[string]diagnostics.Category

	// activeNetwork is the V2.4 hashed network ID the manager is
	// currently bound to. Empty string == sentinel "unset" / "global"
	// for back-compat with pre-2C callers.
	activeNetwork string
}

// New returns a fresh Manager.
func New() *Manager {
	return &Manager{
		state:            StateNoRoute,
		routeCooldown:    map[string]time.Time{},
		familyCooldown:   map[string]time.Time{},
		failures:         map[string][]time.Time{},
		now:              func() time.Time { return time.Now().UTC() },
		posture:          PostureNoRoute,
		routeHealth:      map[string]RouteHealth{},
		familyEscalation: map[string]int{},
		familyLastReason: map[string]diagnostics.Category{},
	}
}

// SetNow overrides the clock for tests.
func (m *Manager) SetNow(f func() time.Time) { m.now = f }

// SetActiveNetwork records the network ID the manager is currently
// bound to. Phase 2C. The family-escalation counter is keyed by
// (family, network_id); a roam to a different network resets the
// ladder for that family on the new network. Empty string is the
// legacy "global" key (preserves 2B test behaviour).
//
// MUST NOT touch state or session-level structures.
func (m *Manager) SetActiveNetwork(networkID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeNetwork = networkID
}

// ActiveNetwork returns the manager's currently bound network ID.
func (m *Manager) ActiveNetwork() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeNetwork
}

// familyEscKey is the composite key used by familyEscalation,
// familyLastReason, and familyCooldown. Pre-2C callers (and 2B
// tests) supply activeNetwork == "" and observe the legacy
// `family`-only key.
func familyEscKey(family, networkID string) string {
	if networkID == "" {
		return family
	}
	return family + "@" + networkID
}

// State returns the current state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// LastReason returns the last "why this route?" explanation.
func (m *Manager) LastReason() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastReason
}

// CanAttempt reports whether routeID is currently outside its cooldown
// window. The reason is human-readable and shown in Diagnostics.
func (m *Manager) CanAttempt(routeID, family string) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if t, ok := m.routeCooldown[routeID]; ok && now.Before(t) {
		return false, fmt.Sprintf("route cooling down until %s", t.UTC().Format(time.RFC3339))
	}
	famKey := familyEscKey(family, m.activeNetwork)
	if t, ok := m.familyCooldown[famKey]; ok && now.Before(t) {
		return false, fmt.Sprintf("transport family %s cooling down until %s",
			family, t.UTC().Format(time.RFC3339))
	}
	return true, ""
}

// Attempt records that we are about to try routeID.
func (m *Manager) Attempt(routeID, family string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = StateConnecting
	m.currentRoute = routeID
	m.currentFamily = family
	m.lastReason = "attempting route " + routeID
}

// Connected records a successful tunnel. Phase 2B: also resets the
// family-escalation counter so a freshly-recovered family starts the
// next cooldown event at ladder step 1.
func (m *Manager) Connected() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = StateConnected
	m.lastReason = "tunnel up on " + m.currentRoute
	if m.currentFamily != "" {
		// Family is healthy on THIS network → reset escalation for
		// (family, activeNetwork). Pre-existing family cooldown
		// (still pending in familyCooldown) keeps its expiry, but
		// the next family cooldown event on this same network
		// re-starts at step 1. A different network's escalation for
		// the same family is intentionally untouched (V2.4: per-
		// network memory).
		key := familyEscKey(m.currentFamily, m.activeNetwork)
		delete(m.familyEscalation, key)
		delete(m.familyLastReason, key)
	}
	if rid := m.currentRoute; rid != "" {
		// A successful Connected() clears the route's cooldown.
		delete(m.routeCooldown, rid)
		h := m.routeHealth[rid]
		h.RouteID = rid
		h.InCooldown = false
		h.CooldownReason = ""
		h.CooldownUntil = time.Time{}
		m.routeHealth[rid] = h
	}
}

// Disconnect clears the active state without recording a failure.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = StateNoRoute
	m.currentRoute = ""
	m.currentFamily = ""
	m.lastReason = "user disconnected"
}

// Failed records a failure with its V0.3 category, applies cooldown
// according to category rules, and updates the FSM.
//
// Phase 2B: the family-cooldown trigger is now hybrid:
//   - Family-class categories (TLS-SNI, UDP-unavailable,
//     QUIC-unavailable per `IsFamilyClass`) fire a family cooldown
//     immediately at ladder step 1, advancing through the V2.3
//     5min/15min/1h/4h/24h ladder on subsequent events.
//   - Per-route classes keep the legacy "3 failures in 1h on the
//     same family → fire family cooldown" trigger; the duration is
//     now drawn from the same V2.3 ladder rather than a hard-coded
//     1 h.
//
// `route_health[routeID]` is updated on every call; it carries the
// V0.3 category and the cooldown expiry into the diagnostics blob.
func (m *Manager) Failed(routeID, family string, cat diagnostics.Category) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	switch cat {
	case diagnostics.AuthFailed, diagnostics.RouteExpired, diagnostics.PublisherRevoked,
		diagnostics.PublisherKeyChanged, diagnostics.BundleSignatureInvalid,
		diagnostics.BundleCorrupted, diagnostics.NetworkOffline:
		// Non-cooldown classes per V0.3. Surface the failure via
		// routeHealth (no cooldown, but the reason is recorded so
		// the desktop can render an "auth failed" badge).
		m.state = StateFailed
		m.lastReason = string(cat) + " — no automatic cooldown"
		h := m.routeHealth[routeID]
		h.RouteID = routeID
		h.InCooldown = false
		h.CooldownReason = cat
		h.CooldownUntil = time.Time{}
		m.routeHealth[routeID] = h
		return
	}

	dur := perRouteCooldown(cat)
	m.routeCooldown[routeID] = now.Add(dur)

	// === Hybrid family-cooldown trigger (Phase 2B) ===
	//
	// Family-class categories: fire the next ladder step immediately.
	// Per-route classes: keep the 3-failures-in-1h preamble; on trip,
	// fire the next ladder step.
	famKey := familyEscKey(family, m.activeNetwork)
	if IsFamilyClass(cat) {
		m.familyEscalation[famKey]++
		step := m.familyEscalation[famKey]
		m.familyCooldown[famKey] = now.Add(FamilyCooldownStep(step))
		m.familyLastReason[famKey] = cat
	} else {
		// Per-route class: track failures within the current hour
		// bucket on this (family, network) and trip family cooldown
		// after 3 (preserves legacy 2A behaviour for these classes,
		// now correctly partitioned by network).
		bucket := now.Truncate(time.Hour)
		bucketed := append([]time.Time{}, m.failures[famKey]...)
		bucketed = append(bucketed, bucket)
		prune := bucketed[:0]
		for _, t := range bucketed {
			if !t.Before(bucket.Add(-1 * time.Hour)) {
				prune = append(prune, t)
			}
		}
		m.failures[famKey] = prune
		if len(prune) >= 3 {
			m.familyEscalation[famKey]++
			step := m.familyEscalation[famKey]
			m.familyCooldown[famKey] = now.Add(FamilyCooldownStep(step))
			m.familyLastReason[famKey] = cat
		}
	}

	m.state = StateCooldown
	m.lastReason = fmt.Sprintf("%s on %s; cooldown %s", cat, routeID, dur)
	h := m.routeHealth[routeID]
	h.RouteID = routeID
	h.InCooldown = true
	h.CooldownReason = cat
	h.CooldownUntil = m.routeCooldown[routeID]
	m.routeHealth[routeID] = h
}

func perRouteCooldown(cat diagnostics.Category) time.Duration {
	switch cat {
	case diagnostics.TCPConnectTimeout, diagnostics.DNSTimeout:
		return 5 * time.Minute
	case diagnostics.TCPReset, diagnostics.TLSHandshakeFailed:
		return 30 * time.Minute
	case diagnostics.TLSSNIOrCertBlockSuspected:
		return 1 * time.Hour
	case diagnostics.UDPUnavailable, diagnostics.QUICUnavailable:
		return 2 * time.Hour
	case diagnostics.DNSPoisoned:
		return 30 * time.Minute
	case diagnostics.EngineCrash:
		return 5 * time.Minute
	}
	return 5 * time.Minute
}

// CurrentRoute returns the active route id (empty if none).
func (m *Manager) CurrentRoute() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentRoute
}

// BudgetExhausted (Phase 2A) is the FSM entry-point invoked when a
// route hits its hourly byte cap. The route is added to the cooldown
// map until the next hour bucket; LastReason carries the V2.1 message
// the GUI / diagnostics surfaces.
//
// The cooldown duration is set to the time until the next hour bucket
// rolls; the scheduler's KindBudgetReset action also clears the
// counter at that boundary, so the route is selectable again on the
// next attempt.
func (m *Manager) BudgetExhausted(routeID, family string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	nextHour := now.Truncate(time.Hour).Add(time.Hour)
	m.routeCooldown[routeID] = nextHour
	m.state = StateBudgetExhausted
	m.lastReason = fmt.Sprintf("route %s exhausted hourly budget; resumes %s",
		routeID, nextHour.UTC().Format(time.RFC3339))
	h := m.routeHealth[routeID]
	h.RouteID = routeID
	h.BudgetExhausted = true
	h.CooldownUntil = nextHour
	m.routeHealth[routeID] = h
	_ = family
}

// === Phase 2B posture-axis accessors ===

// Posture returns the current V2.3 posture state.
func (m *Manager) Posture() Posture {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.posture
}

// SetPosture transitions the posture to `to` via `event`. Returns
// an error if the transition is not in the closed LegalTransitions
// table; the posture is NOT changed on illegal transitions and
// LastReason is updated to surface the violation.
func (m *Manager) SetPosture(event PostureEvent, to Posture) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	from := m.posture
	if !IsLegal(from, event, to) {
		m.lastReason = fmt.Sprintf("posture: illegal transition %s --%s--> %s", from, event, to)
		return fmt.Errorf("pathmanager: illegal posture transition %s --%s--> %s", from, event, to)
	}
	m.posture = to
	return nil
}

// RouteHealth returns the per-route health table sorted by route_id.
// Includes routes in cooldown, with budget exhausted, or with a
// non-cooldown V0.3 category recently surfaced (auth_failed etc).
func (m *Manager) RouteHealth() []RouteHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]RouteHealth, 0, len(m.routeHealth))
	for rid, h := range m.routeHealth {
		// Project cooldown freshness against the current time so a
		// stale entry from an earlier bucket doesn't render as still
		// in cooldown.
		if !h.CooldownUntil.IsZero() && now.Before(h.CooldownUntil) {
			h.InCooldown = true
		} else {
			h.InCooldown = false
		}
		// Budget exhaustion clears at the next hour bucket; the FSM
		// caller (engine layer) flips the BudgetExhausted bit back to
		// false on the next successful Connected(). We keep the bit
		// stable here to avoid hiding the state from diagnostics.
		h.RouteID = rid
		out = append(out, h)
	}
	sortRouteHealth(out)
	return out
}

// SkippedFamilies returns the family-cooldown table projected for
// diagnostics. Entries with expired `until` are dropped. Phase 2C
// projects the composite (family, network_id) key down to family
// only — the diagnostics root already carries `current_network_id`,
// and emitting the full composite would needlessly duplicate it on
// every row. If a family is in cooldown on multiple networks, only
// the row matching the active network is surfaced (which is the
// information the user can act on right now).
func (m *Manager) SkippedFamilies() []SkippedFamily {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]SkippedFamily, 0, len(m.familyCooldown))
	for famKey, until := range m.familyCooldown {
		if !now.Before(until) {
			continue
		}
		fam, net := splitFamilyEscKey(famKey)
		// Only surface entries that belong to the current network
		// (or the legacy "global" key for pre-2C behaviour).
		if net != "" && net != m.activeNetwork {
			continue
		}
		out = append(out, SkippedFamily{
			Family:     fam,
			Until:      until.UTC(),
			LadderStep: m.familyEscalation[famKey],
		})
	}
	sortSkipped(out)
	return out
}

// splitFamilyEscKey is the inverse of familyEscKey. Returns
// (family, networkID); networkID is empty for legacy keys.
func splitFamilyEscKey(k string) (string, string) {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == '@' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

// NextRoute is the engine-facing "best route under the current mode
// and network" picker. It wires pathmanager.Rank (Phase 2B, pure
// filter+sort) into the FSM by additionally filtering out routes
// that are in cooldown OR whose family is in cooldown on the active
// network. Returns the chosen route_id and ok=true; ok=false when
// no route survives all filters.
//
// Phase 2C: the connect path (engine_set_route) still accepts a
// user-chosen route_id verbatim. NextRoute is exposed for the
// desktop's "best route on this network" suggestion and for tests;
// 2D may wire it into the auto-route path.
func (m *Manager) NextRoute(rs []Route, mode string) (string, bool) {
	ranked := Rank(rs, mode)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, r := range ranked {
		if t, ok := m.routeCooldown[r.RouteID]; ok && now.Before(t) {
			continue
		}
		famKey := familyEscKey(r.Family, m.activeNetwork)
		if t, ok := m.familyCooldown[famKey]; ok && now.Before(t) {
			continue
		}
		// Skip routes flagged budget-exhausted in routeHealth (the
		// budget engine has already tripped them at this hour).
		if h, ok := m.routeHealth[r.RouteID]; ok && h.BudgetExhausted {
			continue
		}
		return r.RouteID, true
	}
	return "", false
}
