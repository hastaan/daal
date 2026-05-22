// Package selection is the deterministic local selection brain that
// turns a RelayPack candidate set into a race plan, drives mode-aware
// cooldown propagation, and emits the locked Explanation struct that
// the FRP-6 UI binds to.
//
// FRP-3 (Phase 31) ships:
//
//   - The Explanation JSON schema (explain.go). Locked at FRP-3; the
//     UI binds to this exact shape.
//   - The 9-element NetworkSignal vocabulary (signals.go). Frozen at
//     FRP-3; adding a new signal in a later phase is allowed,
//     renaming or removing one is a breaking change.
//   - A pure-function selector pipeline that consumes:
//   - core/routestore.RouteRow (FRP-2's 9 RelayPack columns)
//     projected via candidate.go;
//   - core/netmem.Snapshot (FRP-2's ByRelayPack widening)
//     read + written via network_memory.go.
//
// The package is Go-private (under core/internal/) and exports
// nothing at the engine ABI release surface. FRP-3 locks the
// Explanation JSON shape; a later integration phase routes it
// through the existing diagnostics export path.
//
// Position B is preserved: no net.Dial, no net/http, no
// project-owned probe, no inference call. The selector's only
// inputs are local state (probe results from the engine, RouteRow,
// netmem Snapshot, clock).
package selection
