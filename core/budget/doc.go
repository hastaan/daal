// Package budget is Daal's authoritative per-route byte counter and
// hourly-cap enforcer (V2.1).
//
// The engine landed in Phase 2A. It owns one `routes.bytes_used_this_hour`
// column per route plus a per-route hour-bucket cursor persisted in
// `secrets_kv` under `budget:bucket:<route_id>`. Every time the
// middleware shovels n bytes for a route, it calls Engine.Add(routeID,
// n); the engine charges the current hour bucket. When the consumed
// total crosses the cap, Add returns ErrExhausted and the route's
// caller is expected to (a) close cleanly and (b) drive the FSM into
// StateBudgetExhausted.
//
// The mapping from V2's "scarcity_class" / "budget_tag" string to
// bytes-per-hour lives in caps.go. The map is closed; new tags require
// a roadmap-level decision.
//
// Phase 2A does NOT add mode multipliers (lifeline 0.33×, etc.) — that
// is 2B's scope. Phase 2A also does NOT bucket budgets by network ID —
// that is 2C's scope. This package's API is shaped so both extensions
// are additive: EffectiveCap takes a mode argument that Add() routes
// through; a future PerNetwork wrapper layer will key the engine on
// (routeID, networkID) pairs.
package budget
