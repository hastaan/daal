package abi

// D-2.1 — display-summary ABI extensions.
//
// These methods produce the cross-platform shapes that the GUI binds
// to (D2FunctionalContract). They never expose engine-internal types;
// they emit small JSON envelopes designed for direct render.
//
// New surface (all return JSON):
//   RouteSummary(routeId)        -> {route_id, publisher_name, route_nickname, trust_class, family, in_cooldown, cooldown_until_unix_ms, budget_exhausted, health_pct}
//   AvailableRoutes()            -> {routes: [...routesummary...]}
//   ThroughputSnapshot()         -> {up_bps, down_bps, window_ms}
//
// Plus PanicWipe() (no JSON; tears down state and returns error|nil).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"daal/core/routestore"
)

// ---- public functions used by the gomobile + cshared facades --------

// RouteSummaryDisplay is the wire shape (D2FunctionalContract).
type RouteSummaryDisplay struct {
	RouteID             string  `json:"route_id"`
	PublisherName       string  `json:"publisher_name"`
	RouteNickname       string  `json:"route_nickname"`
	TrustClass          string  `json:"trust_class"`
	Family              string  `json:"family"`
	InCooldown          bool    `json:"in_cooldown"`
	CooldownUntilUnixMs int64   `json:"cooldown_until_unix_ms,omitempty"`
	BudgetExhausted     bool    `json:"budget_exhausted"`
	HealthPct           float64 `json:"health_pct,omitempty"`
}

// rowToDisplay maps a routestore.RouteRow to the wire shape.
func rowToDisplay(r routestore.RouteRow, healthPct float64) RouteSummaryDisplay {
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
	now := time.Now().UTC()
	inCooldown := false
	var cooldownUntilMs int64
	if r.CooldownUntil != "" {
		if t, err := time.Parse(time.RFC3339, r.CooldownUntil); err == nil {
			if t.After(now) {
				inCooldown = true
				cooldownUntilMs = t.UnixMilli()
			}
		}
	}

	// Heuristic budget-exhausted: if BytesUsedThisSession > a high mark
	// (we don't know the cap here without engine context). The proper
	// engine field is engine_route_health, but that surfaces differently.
	// Conservative default: false.
	budgetExhausted := false

	return RouteSummaryDisplay{
		RouteID:             r.RouteID,
		PublisherName:       publisherName,
		RouteNickname:       nickname,
		TrustClass:          trustClass,
		Family:              r.TransportFamily,
		InCooldown:          inCooldown,
		CooldownUntilUnixMs: cooldownUntilMs,
		BudgetExhausted:     budgetExhausted,
		HealthPct:           healthPct,
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
// Heuristic (deterministic, no LLM):
//   - Start at 100.
//   - Subtract 20 per consecutive_failures (cap subtract at 60).
//   - If currently in cooldown, subtract another 30.
//   - If LastSuccessBucket is empty (never succeeded), cap at 50.
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
	if r.LastSuccessBucket == "" && pct > 50 {
		pct = 50
	}
	if pct < 0 {
		pct = 0
	}
	return pct
}

// RouteSummary returns the display shape for a single route_id.
func RouteSummary(routeID string) (string, error) {
	if globalCore == nil {
		return "", errors.New("abi: not initialized")
	}
	c := globalCore
	row, err := c.store.GetRoute(routeID)
	if err != nil {
		return "", err
	}
	disp := rowToDisplay(row, computeHealthPctLastHour(row))
	body, _ := json.Marshal(disp)
	return string(body), nil
}

// AvailableRoutes returns all routes the user could connect to,
// ordered by health_pct descending. Revoked routes are excluded.
func AvailableRoutes() (string, error) {
	if globalCore == nil {
		return "", errors.New("abi: not initialized")
	}
	c := globalCore
	rows, err := c.store.ListRoutes()
	if err != nil {
		return "", err
	}
	out := make([]RouteSummaryDisplay, 0, len(rows))
	for _, r := range rows {
		if strings.EqualFold(r.TrustState, "revoked") {
			continue
		}
		out = append(out, rowToDisplay(r, computeHealthPctLastHour(r)))
	}
	// Sort by health_pct desc, then by publisher_name asc for stability.
	sortByHealthDesc(out)
	body, _ := json.Marshal(map[string]any{"routes": out})
	return string(body), nil
}

func sortByHealthDesc(rs []RouteSummaryDisplay) {
	// Tiny insertion sort — we typically have under 20 routes.
	for i := 1; i < len(rs); i++ {
		j := i
		for j > 0 {
			a, b := rs[j-1], rs[j]
			if a.HealthPct > b.HealthPct {
				break
			}
			if a.HealthPct == b.HealthPct && a.PublisherName <= b.PublisherName {
				break
			}
			rs[j-1], rs[j] = b, a
			j--
		}
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

// RecordThroughput is a hook the tunnel layer can call to feed
// up/down byte counters. It is safe to call from any goroutine. If the
// tunnel isn't wired (current state in many builds), the snapshot
// returns zeros, which is the correct disconnected-state value.
func RecordThroughput(upDelta, downDelta int64) {
	globalThroughput.mu.Lock()
	defer globalThroughput.mu.Unlock()
	globalThroughput.upBytes += upDelta
	globalThroughput.downBytes += downDelta
}

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
// Wipe NEVER touches:
//   - the user's home directory generally
//   - OS keystore entries (those are platform-specific; clients
//     should call platform-specific keystore-wipe before invoking this)
func PanicWipe() error {
	c := globalCore
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
