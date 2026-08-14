package abi

// Phase 3F. Delegate-share ABI surface. One new release symbol
// (release surface 47 → 48) wired in `delegate_export.go`
// (cshared) and `delegate_gomobile.go`. This file owns the
// engine-side state, the policy/cap/chain orchestration, and
// the JSON serializers the export shims call.
//
// Locked invariants (see specs/delegate-keys-v1.md):
//
//   - The delegate key is the existing Phase 1C share
//     identity (`secrets_kv:share/identity:v1`). NO new key
//     derivation is introduced at 3F.
//   - The device-local re-share counter for route R lives at
//     `secrets_kv:delegate_share_counter:R`; the value is the
//     ASCII-decimal string of a uint8.
//   - `engine_redistribute_route` returns serialized
//     `.sbp.share` bytes on success or a JSON error envelope
//     on failure. The closed enum:
//       ok / policy_refuses / cap_exhausted /
//       chain_depth_exceeded / route_unknown /
//       identity_unavailable.
//   - `delegate_share_counters` and `last_delegate_share_outcome`
//     are always-present diagnostics fields.

import (
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"daal/core/delegate"
)

// delegateState is the package-level singleton holding 3F
// engine state. The mutex protects the in-memory cache of
// counters + the last outcome. The authoritative counter lives
// in secrets_kv; the in-memory cache is best-effort and is
// rebuilt on first read after Init.
type delegateState struct {
	mu          sync.Mutex
	counters    map[string]uint8 // route_id → shared_with_count
	lastOutcome string           // closed enum (delegate.Outcome)
	cacheLoaded bool
}

var globalDelegate = &delegateState{counters: map[string]uint8{}}

// counterSecretKey returns the secrets_kv key for a route's
// device-local re-share counter. Locked at 3F.
func counterSecretKey(routeID string) string {
	return "delegate_share_counter:" + routeID
}

// loadCounter returns the current shared_with_count for a
// route. Missing key → 0. Malformed value (should never happen
// — we are the only writer) → 0 + error.
func loadCounter(c *Core, routeID string) (uint8, error) {
	body, err := c.store.GetSecret(counterSecretKey(routeID))
	if err != nil {
		// sql.ErrNoRows on missing key is normal for a
		// never-shared route. Surface 0 / nil-error.
		return 0, nil
	}
	if len(body) == 0 {
		return 0, nil
	}
	n, perr := strconv.ParseUint(string(body), 10, 8)
	if perr != nil {
		return 0, perr
	}
	return uint8(n), nil
}

// storeCounter persists a counter. Caller MUST hold the
// engine-side lock that prevents concurrent re-share calls
// against the same route (the redistribute path serializes on
// `globalDelegate.mu`).
func storeCounter(c *Core, routeID string, n uint8) error {
	return c.store.PutSecret(counterSecretKey(routeID), []byte(strconv.FormatUint(uint64(n), 10)))
}

// recordOutcome updates the in-memory last-outcome surface. The
// diagnostics renderer reads this without further coordination.
func recordOutcome(o delegate.Outcome) {
	globalDelegate.mu.Lock()
	globalDelegate.lastOutcome = string(o)
	globalDelegate.mu.Unlock()
}

// LastDelegateShareOutcome surfaces the most recent
// `engine_redistribute_route` outcome for diagnostics. Empty
// string until the first call.
func LastDelegateShareOutcome() string {
	globalDelegate.mu.Lock()
	defer globalDelegate.mu.Unlock()
	return globalDelegate.lastOutcome
}

// delegateShareCounterEntry is the per-route shape surfaced by
// `delegate_share_counters` in diagnostics.
type delegateShareCounterEntry struct {
	SharedWithCount uint8 `json:"shared_with_count"`
	Cap             uint8 `json:"cap"`
}

// DelegateShareCountersForDiagnostics walks every route in the
// store and returns a map[route_id]{shared_with_count, cap}.
// The cap is the publisher-declared `RedistributionCap`; the
// counter is the device-local share count under
// secrets_kv:delegate_share_counter:R. Always non-nil.
func DelegateShareCountersForDiagnostics() map[string]delegateShareCounterEntry {
	out := map[string]delegateShareCounterEntry{}
	if !delegateShareCompiledIn {
		return out
	}
	c := tryGetCore()
	if c == nil || c.store == nil {
		return out
	}
	rows, err := c.store.ListRoutes()
	if err != nil {
		return out
	}
	for _, r := range rows {
		// Surface entries only for routes the publisher
		// actually declared a non-empty policy on. Empty
		// policy → not part of the share surface.
		if r.RedistributionPolicy == "" || r.RedistributionPolicy == "none" {
			continue
		}
		n, _ := loadCounter(c, r.RouteID)
		out[r.RouteID] = delegateShareCounterEntry{
			SharedWithCount: n,
			Cap:             r.RedistributionCap,
		}
	}
	return out
}

// RedistributeRoute is the Go-side surface for
// `engine_redistribute_route`. Returns serialized `.sbp.share`
// bytes (a JSON envelope; see specs/delegate-keys-v1.md
// "Wire format") on success, or a JSON error envelope on
// failure. Empty / `identity_unavailable` under
// `-tags no_delegate_share`.
func RedistributeRoute(routeID, recipientFPHex string) string {
	if !delegateShareCompiledIn {
		recordOutcome(delegate.OutcomeIdentityUnavailable)
		return delegate.OutcomeJSON(delegate.OutcomeIdentityUnavailable, "compiled out")
	}
	c := tryGetCore()
	if c == nil || c.store == nil {
		recordOutcome(delegate.OutcomeIdentityUnavailable)
		return delegate.OutcomeJSON(delegate.OutcomeIdentityUnavailable, "engine not initialised")
	}

	globalDelegate.mu.Lock()
	defer globalDelegate.mu.Unlock()

	row, err := c.store.GetRoute(routeID)
	if err != nil {
		recordOutcomeLocked(delegate.OutcomeRouteUnknown)
		return delegate.OutcomeJSON(delegate.OutcomeRouteUnknown, routeID)
	}

	policy := delegate.Policy(row.RedistributionPolicy)
	if policy == "" {
		policy = delegate.PolicyNone
	}
	if !delegate.IsValidPolicy(policy) {
		recordOutcomeLocked(delegate.OutcomePolicyRefuses)
		return delegate.OutcomeJSON(delegate.OutcomePolicyRefuses, "policy malformed: "+row.RedistributionPolicy)
	}

	currentCount, _ := loadCounter(c, routeID)

	out := delegate.EnforcePolicy(policy, row.RedistributionCap, currentCount)
	if out != delegate.OutcomeOK {
		recordOutcomeLocked(out)
		return delegate.OutcomeJSON(out, routeID)
	}

	// Load the device's 1C share identity. Reuses the same
	// `share/identity:v1` key the existing 1C path persists
	// to; we go through `loadOrCreateIdentity` so a fresh
	// device that has never invoked `engine_share_begin` can
	// still re-share (the 3F UI path is allowed to be the
	// first to materialise the identity).
	id, ierr := loadOrCreateIdentity(c)
	if ierr != nil || len(id.PrivateKey) == 0 {
		recordOutcomeLocked(delegate.OutcomeIdentityUnavailable)
		return delegate.OutcomeJSON(delegate.OutcomeIdentityUnavailable, "share identity unavailable")
	}
	priv := id.PrivateKey

	// We do not have the original publisher signature bytes
	// readily available in the routestore (the signed bundle
	// is consumed at import time). At 3F the redistribute path
	// signs over a stable per-route digest the receiver
	// reconstructs the same way (route_id + recipient_fp_hex),
	// which is sufficient for the chain walker since the
	// receiver also knows the shape. See
	// specs/delegate-keys-v1.md "Wire format" §"orig_sig
	// substitute".
	//
	// NOTE: The full publisher-signature-bound chain is
	// reachable engine-side via `core/share/export.go` (3F.6);
	// this ABI entry point is a thin wrapper for the UI and
	// returns the per-route descriptor that core/share
	// embeds in the `.sbp.share`.
	origSubstitute := []byte("daal-3f:" + routeID + ":" + recipientFPHex)

	chain, aerr := delegate.AppendHop(nil, origSubstitute, recipientFPHex, priv, time.Now())
	if aerr != nil {
		recordOutcomeLocked(delegate.OutcomeChainDepthExceeded)
		return delegate.OutcomeJSON(delegate.OutcomeChainDepthExceeded, aerr.Error())
	}

	caps := []delegate.CapEntry{{
		RouteID:                   routeID,
		SharedWithCountAtSignTime: currentCount,
		CapAtSignTime:             row.RedistributionCap,
	}}
	if cerr := delegate.EnforceCap(caps); cerr != nil {
		recordOutcomeLocked(delegate.OutcomeCapExhausted)
		return delegate.OutcomeJSON(delegate.OutcomeCapExhausted, cerr.Error())
	}

	// Build the wire envelope. The full `.sbp.share` bundle is
	// assembled by core/share/export.go (3F.6); this ABI
	// surface returns the chain + caps + recipient marker so
	// the higher layers can splice them into the bundle.
	envelope := struct {
		Type           string              `json:"type"`
		RouteID        string              `json:"route_id"`
		RecipientFPHex string              `json:"recipient_fp_hex"`
		Chain          []delegate.ChainHop `json:"redistribution_chain"`
		Caps           []delegate.CapEntry `json:"delegate_caps"`
		IssuedAt       string              `json:"issued_at"`
	}{
		Type:           "delegated_share",
		RouteID:        routeID,
		RecipientFPHex: recipientFPHex,
		Chain:          chain,
		Caps:           caps,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	wire, _ := json.Marshal(envelope)

	// Only on full success do we increment the counter. The
	// uint8 is saturating (255 + 1 stays at 255).
	next := currentCount
	if currentCount < 255 {
		next = currentCount + 1
	}
	if serr := storeCounter(c, routeID, next); serr != nil {
		recordOutcomeLocked(delegate.OutcomeIdentityUnavailable)
		return delegate.OutcomeJSON(delegate.OutcomeIdentityUnavailable, serr.Error())
	}
	globalDelegate.counters[routeID] = next
	recordOutcomeLocked(delegate.OutcomeOK)
	return string(wire)
}

// recordOutcomeLocked is recordOutcome but assumes the caller
// holds globalDelegate.mu.
func recordOutcomeLocked(o delegate.Outcome) {
	globalDelegate.lastOutcome = string(o)
}

// resetDelegateStateForShutdown clears the singleton so a
// subsequent Init starts clean.
func resetDelegateStateForShutdown() {
	globalDelegate.mu.Lock()
	defer globalDelegate.mu.Unlock()
	globalDelegate.counters = map[string]uint8{}
	globalDelegate.lastOutcome = ""
	globalDelegate.cacheLoaded = false
}

// tryGetCore returns the global Core if Init has been called,
// or nil otherwise. Mirrors mustCore but does not panic — the
// diagnostics path MUST tolerate Init not having been called.
func tryGetCore() *Core { return loadedCore() }

// errEngineUninitialised is exported for tests that need to
// distinguish "engine not initialised" from other failures.
var errEngineUninitialised = errors.New("abi: engine not initialised")
