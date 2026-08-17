package abi

// D-2.1 — display-summary ABI extensions.
//
// These methods produce the cross-platform shapes that the GUI binds
// to (D2FunctionalContract). They never expose engine-internal types;
// they emit small JSON envelopes designed for direct render.
//
// New surface (all return JSON):
//   RouteSummary(routeId)        -> {route_id, publisher_name, route_nickname, trust_class, family, family_maturity, in_cooldown, cooldown_until_unix_ms, budget_exhausted, health_pct, proven}
//   AvailableRoutes()            -> {routes: [...routesummary...]}
//   ThroughputSnapshot()         -> {up_bps, down_bps, window_ms}
//
// Plus PanicWipe() (no JSON; tears down state and returns error|nil).
//
// MEASURED-vs-UNMEASURED (Wave-1 honesty pass). `in_cooldown`,
// `budget_exhausted` and `health_pct` are JSON `null` when the engine
// has observed nothing about the route, and a real value otherwise.
// They used to be non-nullable, which meant every route on a fresh
// install reported `in_cooldown:false, budget_exhausted:false,
// health_pct:50` — three confident claims backed by nothing, because
// the three routestore columns they read (`last_success_bucket`,
// `consecutive_failures`, `cooldown_until`) are written by NO code
// path: `routestore/store.go`'s INSERT hard-codes them to NULL/0 and
// no UPDATE ever touches them (the durable RecordOutcome hook is
// Wave-3 work). A UI cannot distinguish "measured healthy" from
// "never measured" through a non-nullable field, so the field is
// nullable and the UI renders "not measured yet" on null.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"daal/core/engine"
	"daal/core/pathmanager"
	"daal/core/routestore"
)

// ---- public functions used by the gomobile + cshared facades --------

// RouteSummaryDisplay is the wire shape (D2FunctionalContract).
//
// The three pointer fields are the measured/unmeasured seam: `null`
// means "the engine has observed nothing", never "observed a zero".
// None of them carries `omitempty` — an absent key and a null key must
// not be distinguishable to the client, and `omitempty` on a *bool
// would hide a legitimate `false`.
type RouteSummaryDisplay struct {
	RouteID       string `json:"route_id"`
	PublisherID   string `json:"publisher_id"`
	PublisherName string `json:"publisher_name"`
	RouteNickname string `json:"route_nickname"`
	TrustClass    string `json:"trust_class"`
	Family        string `json:"family"`
	// FamilyMaturity is the routestore taxonomy label:
	// stable | experimental | promotion-candidate | unsupported |
	// unhandled. Carried so the UI can say "this build cannot dial
	// it" (unsupported) rather than guessing from the family string.
	FamilyMaturity string `json:"family_maturity"`
	// InCooldown / BudgetExhausted come from the LIVE pathmanager FSM,
	// which is the only component that records them today. It holds an
	// entry only for routes attempted in this engine session, so nil
	// means "not attempted yet", not "healthy".
	InCooldown          *bool `json:"in_cooldown"`
	CooldownUntilUnixMs int64 `json:"cooldown_until_unix_ms,omitempty"`
	BudgetExhausted     *bool `json:"budget_exhausted"`
	// HealthPct is nil until at least one outcome has been recorded
	// durably. See the measured-vs-unmeasured note at the top of the
	// file: today no writer exists, so this is nil for every route and
	// the UI shows "not measured yet" instead of the old fixed 50%.
	HealthPct *float64 `json:"health_pct"`
	// Proven is true once the route has recorded at least one success
	// (LastSuccessBucket set). It is the coarse form of the same fact
	// HealthPct==nil carries; kept because existing UI binds to it.
	Proven bool `json:"proven"`
}

// routeObservations is everything the engine has actually MEASURED
// about one route. Every field is a pointer on purpose: the whole
// point of this struct is that "not measured" and "measured zero"
// are different answers and must survive the trip to the UI.
type routeObservations struct {
	InCooldown      *bool
	CooldownUntilMs int64
	BudgetExhausted *bool
	HealthPct       *float64
}

// hasDurableOutcome reports whether ANY outcome has ever been written
// to this route's history columns. It is the guard that keeps
// computeHealthPctLastHour from manufacturing a score out of three
// structurally-empty columns.
//
// Today it returns false for every route in every install, because
// nothing writes those columns (routestore.RecordOutcome does not
// exist yet). That is the correct answer and it is why health_pct is
// null everywhere: the moment the Wave-3 outcome hook lands, this
// starts returning true and the number lights up on its own.
func hasDurableOutcome(r routestore.RouteRow) bool {
	return strings.TrimSpace(r.LastSuccessBucket) != "" ||
		strings.TrimSpace(r.LastFailureBucket) != "" ||
		strings.TrimSpace(r.CooldownUntil) != "" ||
		r.ConsecutiveFailures > 0
}

// observeRoute collects the measured facts for one route from the two
// places that can hold them: the live FSM (session-scoped) and the
// routestore's history columns (durable).
func observeRoute(r routestore.RouteRow, live map[string]pathmanager.RouteHealth) routeObservations {
	var out routeObservations

	// Live FSM. `pathmanager` records a route only once it has been
	// attempted (Attempt/Failed/BudgetExhausted), so presence in the
	// map IS the evidence that these two booleans mean something.
	if h, ok := live[r.RouteID]; ok {
		inCooldown := h.InCooldown
		budget := h.BudgetExhausted
		out.InCooldown = &inCooldown
		out.BudgetExhausted = &budget
		if h.InCooldown && !h.CooldownUntil.IsZero() {
			out.CooldownUntilMs = h.CooldownUntil.UTC().UnixMilli()
		}
	}

	// Durable history. Only compute a percentage when at least one
	// column carries evidence; otherwise leave HealthPct nil.
	if hasDurableOutcome(r) {
		// A health PERCENTAGE is a statement about successes. A route
		// with failures and no success has no rate to report: the old
		// code answered "50" there — a cap, not a measurement — and
		// that placeholder is exactly what this pass exists to delete.
		// `Proven` already carries "has it ever worked", and
		// in_cooldown / budget_exhausted carry the failure side, so
		// nothing is hidden by leaving the number nil.
		//
		// This also keeps ONE rule across every surface: healthPct
		// present ⇔ proven. RouteHealthBars.tsx tests `proven` and
		// NetworkPage tests presence; if those two could disagree,
		// the same route would render "50%" on one screen and
		// "not tested yet" on the other.
		if strings.TrimSpace(r.LastSuccessBucket) != "" {
			pct := computeHealthPctLastHour(r)
			out.HealthPct = &pct
		}
		// A durable cooldown timestamp is also an observation, and it
		// outlives the session the live FSM is scoped to.
		if out.InCooldown == nil {
			if t, err := time.Parse(time.RFC3339, r.CooldownUntil); err == nil {
				cooled := t.After(time.Now().UTC())
				out.InCooldown = &cooled
				if cooled {
					out.CooldownUntilMs = t.UnixMilli()
				}
			}
		}
	}

	return out
}

// displayMaturity is routestore's family taxonomy narrowed by what
// THIS ARTIFACT can actually dial.
//
// The taxonomy in core/routestore/family.go is a property of the
// family: "has this transport been soaked, does a publisher mint it,
// can the engine express it." That is the right thing for the family
// table to hold and the wrong thing to render on its own, because one
// family's dialability is a property of the BUILD: `naive` needs
// libcronet.so shipped beside the engine, and tools/build-engine-android.sh
// warns-and-continues when it cannot find one. An APK built on a fresh
// machine therefore renders naive routes exactly like vless-reality
// routes — no badge, full standing — and they die at connect. That is
// strictly worse than the three families this pass demoted to
// `unsupported` for the same reason.
//
// Only narrows, never widens: a family the table calls experimental
// does not become stable because a library loaded.
func displayMaturity(family string) string {
	m := routestore.FamilyMaturity(family)
	if family == "naive" && m != routestore.MaturityUnsupported {
		// (false, _) means the driver has not started yet, so we have
		// not looked — say nothing rather than guess "unsupported".
		if attempted, ok := engine.CronetStatus(); attempted && !ok {
			return routestore.MaturityUnsupported.String()
		}
	}
	return m.String()
}

// rowToDisplay maps a routestore.RouteRow to the wire shape.
func rowToDisplay(r routestore.RouteRow, obs routeObservations) RouteSummaryDisplay {
	publisherName := strings.TrimSpace(r.PublisherLabel)
	if publisherName == "" {
		publisherName = r.PublisherID
	}
	// Nickname: parse from UserNote if populated; otherwise fall back to
	// the engine routestore's UserNote (often empty), then the route_id
	// short suffix.
	nickname := strings.TrimSpace(r.UserNote)
	if nickname == "" {
		// Best-effort: take the last path segment of the route_id.
		if i := strings.LastIndex(r.RouteID, "/"); i >= 0 && i < len(r.RouteID)-1 {
			nickname = r.RouteID[i+1:]
		} else if len(r.RouteID) > 8 {
			nickname = r.RouteID[len(r.RouteID)-8:]
		} else {
			nickname = r.RouteID
		}
	}

	trustClass := mapTrustClass(r.TrustState, r.SourceType)

	return RouteSummaryDisplay{
		FamilyMaturity:      displayMaturity(r.TransportFamily),
		RouteID:             r.RouteID,
		PublisherID:         r.PublisherID,
		PublisherName:       publisherName,
		RouteNickname:       nickname,
		TrustClass:          trustClass,
		Family:              r.TransportFamily,
		InCooldown:          obs.InCooldown,
		CooldownUntilUnixMs: obs.CooldownUntilMs,
		BudgetExhausted:     obs.BudgetExhausted,
		HealthPct:           obs.HealthPct,
		Proven:              strings.TrimSpace(r.LastSuccessBucket) != "",
	}
}

// mapTrustClass collapses engine trust_state + source_type to the four
// UI classes the design uses: trusted | pinned | lan | unknown.
func mapTrustClass(trustState, sourceType string) string {
	switch strings.ToLower(trustState) {
	case "trusted":
		return "trusted"
	case "pinned", "verify_once", "verify-once":
		return "pinned"
	case "revoked":
		return "unknown"
	}
	if strings.HasPrefix(strings.ToLower(sourceType), "lan") {
		return "lan"
	}
	return "unknown"
}

// computeHealthPctLastHour returns a 0..100 score derived from the
// route's recent success/failure buckets and consecutive_failures.
//
// ONLY call this via observeRoute, and only for a route that has a
// recorded success (LastSuccessBucket non-empty). Called
// unconditionally it returned 50 for every route in a fresh install —
// a plausible-looking number computed from three empty columns, which
// is exactly the failure this pass removes. The old "cap an unproven
// route at 50" branch is gone with it: a cap is not a measurement, and
// observeRoute no longer asks for a number it could apply to.
//
// Heuristic (deterministic, no LLM):
//   - Start at 100.
//   - Subtract 20 per consecutive_failures (cap subtract at 60).
//   - If currently in cooldown, subtract another 30.
//   - Floor at 0.
func computeHealthPctLastHour(r routestore.RouteRow) float64 {
	pct := 100.0
	cf := r.ConsecutiveFailures
	if cf > 3 {
		cf = 3
	}
	pct -= float64(cf) * 20.0
	if r.CooldownUntil != "" {
		if t, err := time.Parse(time.RFC3339, r.CooldownUntil); err == nil && t.After(time.Now().UTC()) {
			pct -= 30.0
		}
	}
	if pct < 0 {
		pct = 0
	}
	return pct
}

// RouteSummary returns the display shape for a single route_id.
func RouteSummary(routeID string) (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	c := loadedCore()
	row, err := c.store.GetRoute(routeID)
	if err != nil {
		return "", err
	}
	disp := rowToDisplay(row, observeRoute(row, liveRouteHealth(c)))
	body, _ := json.Marshal(disp)
	return string(body), nil
}

// liveRouteHealth indexes the pathmanager's per-route health by
// route_id. Absent key == "this route has not been attempted in this
// session", which observeRoute turns into a null, not a false.
func liveRouteHealth(c *Core) map[string]pathmanager.RouteHealth {
	if c == nil || c.pm == nil {
		return nil
	}
	rows := c.pm.RouteHealth()
	out := make(map[string]pathmanager.RouteHealth, len(rows))
	for _, h := range rows {
		out[h.RouteID] = h
	}
	return out
}

// AvailableRoutes returns all routes the user could connect to,
// ordered by health_pct descending (routes with no measured health
// sort last, ahead of nothing — see sortByHealthDesc). Revoked routes
// are excluded.
func AvailableRoutes() (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	c := loadedCore()
	rows, err := c.store.ListRoutes()
	if err != nil {
		return "", err
	}
	live := liveRouteHealth(c)
	out := make([]RouteSummaryDisplay, 0, len(rows))
	for _, r := range rows {
		if strings.EqualFold(r.TrustState, "revoked") {
			continue
		}
		out = append(out, rowToDisplay(r, observeRoute(r, live)))
	}
	// Sort by health_pct desc, then by publisher_name asc for stability.
	sortByHealthDesc(out)
	body, _ := json.Marshal(map[string]any{"routes": out})
	return string(body), nil
}

// sortByHealthDesc orders measured-health routes first (descending),
// then unmeasured ones, each group broken by publisher_name.
//
// Unmeasured routes deliberately do NOT sort as 0: that would bury
// every route on a fresh install under any route with a real score,
// implying they are the worst options when in fact nothing is known
// about them. They sort after the measured ones because a route with
// a known-good record IS a better suggestion than an unknown one.
func sortByHealthDesc(rs []RouteSummaryDisplay) {
	// Tiny insertion sort — we typically have under 20 routes.
	for i := 1; i < len(rs); i++ {
		j := i
		for j > 0 {
			a, b := rs[j-1], rs[j]
			if !healthLess(a, b) {
				break
			}
			rs[j-1], rs[j] = b, a
			j--
		}
	}
}

// healthLess reports whether `a` should sort AFTER `b`.
func healthLess(a, b RouteSummaryDisplay) bool {
	switch {
	case a.HealthPct == nil && b.HealthPct == nil:
		return a.PublisherName > b.PublisherName
	case a.HealthPct == nil:
		return true // unmeasured sorts after measured
	case b.HealthPct == nil:
		return false
	case *a.HealthPct != *b.HealthPct:
		return *a.HealthPct < *b.HealthPct
	default:
		return a.PublisherName > b.PublisherName
	}
}

// ---- ThroughputSnapshot ---------------------------------------------

type throughputCounters struct {
	mu          sync.Mutex
	upBytes     int64
	downBytes   int64
	windowStart time.Time
}

var globalThroughput = &throughputCounters{windowStart: time.Now()}

// ThroughputSnapshot returns up_bps, down_bps and window_ms. After
// reading, the counters are reset so the next call covers a fresh
// window — caller must poll at the rate it wants.
func ThroughputSnapshot() (string, error) {
	globalThroughput.mu.Lock()
	defer globalThroughput.mu.Unlock()
	now := time.Now()
	windowMs := now.Sub(globalThroughput.windowStart).Milliseconds()
	if windowMs <= 0 {
		windowMs = 1
	}
	upBps := globalThroughput.upBytes * 1000 / windowMs
	downBps := globalThroughput.downBytes * 1000 / windowMs
	globalThroughput.upBytes = 0
	globalThroughput.downBytes = 0
	globalThroughput.windowStart = now
	body, _ := json.Marshal(map[string]any{
		"up_bps":    upBps,
		"down_bps":  downBps,
		"window_ms": windowMs,
	})
	return string(body), nil
}

// ---- PanicWipe ------------------------------------------------------

// PanicWipe shuts down the engine cleanly, removes the on-disk state
// directory, and returns. The caller (UI) is responsible for exiting
// the process — this avoids surprising background services.
//
// Wipe scope:
//   - state_dir directory tree (sqlite db, secrets vault, prefs, logs)
//
// Wipe NEVER touches:
//   - the user's home directory generally
//   - OS keystore entries (those are platform-specific; clients
//     should call platform-specific keystore-wipe before invoking this)
func PanicWipe() error {
	c := loadedCore()
	stateDir := ""
	if c != nil {
		stateDir = c.stateDir
	}
	// Best-effort shutdown — Shutdown() may already have been called by
	// the UI's animation; ignore "not initialized" errors.
	_ = Shutdown()
	if stateDir == "" {
		return errors.New("abi: panic_wipe: no state_dir known (engine never initialized)")
	}
	// Sanity: never wipe a directory that doesn't look like ours.
	if !strings.Contains(stateDir, "daal") {
		return fmt.Errorf("abi: panic_wipe: refusing non-daal state_dir %q", stateDir)
	}
	if err := os.RemoveAll(stateDir); err != nil {
		return fmt.Errorf("abi: panic_wipe: %w", err)
	}
	return nil
}
