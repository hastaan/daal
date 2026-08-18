package abi

import (
	"errors"

	"daal/core/transports/conjure"
)

// DORMANT (Wave 5) — this file records activations that cannot
// happen, and it is kept, not deleted, so the reason survives.
//
// Phase 3D. Refraction-family (psiphon + conjure) per-session
// recording helpers. NO new release-surface ABI symbols are
// added at 3D; all of these functions are Go-package-internal,
// invoked by the transport handlers as they activate routes.
// The diagnostics renderer in `ExportDiagnostics` reads the
// recorded state through the in-memory Core fields.
//
// WHY DORMANT. There are no such transport handlers, and there
// cannot be. Neither family has a dialer in this build and
// neither can be served by a self-hosted publisher: psiphon is a
// third party's proprietary network (hand-off only, never
// hosting) and conjure needs a cooperating ISP running a
// refraction station. The full reasons are on the enum values in
// `bundle/go/bundle/types.go`; the vendor-tree audit is in
// `refraction_compiled.go`. `core/transports/conjure` — the only
// thing this file imports — is itself dormant for the same
// reason.
//
// So both recorders below now REFUSE a non-empty route ID, and
// the three diagnostics fields they feed
// (`psiphon_active_route`, `conjure_active_route`,
// `conjure_phantom_in_use`) are permanently empty strings. That
// is the honest reading: nothing activated, because nothing can.
// Refusing loudly is deliberate — the alternative is a
// diagnostics blob that names an active route on a family the
// engine has no way to dial, which is the exact shape of failure
// this wave exists to remove.
//
// KEPT rather than deleted because: `ExportDiagnostics` emits
// the fields (a documented shape), `HashPhantom` is the only
// implementation of the no-raw-IP redaction invariant that
// `test-rigs/distribution-failure`'s
// `ruleNoRawPhantomIPLeakInDiagnostics` asserts against, and the
// two 3D soak scenarios are registered in the rig's driver. The
// two scenarios now exercise a refusal instead of a fiction;
// retiring them belongs to the rig lane, not here.
//
// Locked invariants (this phase):
//   - Recordings are session-scoped snapshots, not cumulative
//     counters; engine init starts every session with empty
//     fields.
//   - The conjure phantom-IP is HASHED at the boundary (8-byte
//     SHA-256 truncation, hex-encoded) so the raw IP NEVER
//     appears in diagnostics. The hashing happens here AND in
//     the conjure transport package; the abi package recomputes
//     the hash from the raw IP rather than trusting the caller
//     to pre-hash, which keeps the boundary explicit and makes
//     the redaction invariant easy to audit.
//   - Psiphon AND conjure recordings are rejected whenever the
//     matching compile-in flag is false: the engine must not
//     advertise an active route on a family whose implementation
//     is not in the binary. Both flags are constant false (see
//     refraction_compiled.go), so in every shipped build both
//     recorders refuse any non-empty route ID. Clearing (empty
//     route ID) always succeeds, so a caller can still reset
//     state without special-casing.
//
//     The conjure gate is new in Wave 5. Phase 3D left conjure
//     ungated on the stated grounds that "the conjure tree is
//     Apache-2.0 and ships unconditionally" — the tree does not
//     ship at all and is not in `core/go.mod`, so the asymmetry
//     was resting on a false premise.
//
// See specs/psiphon-route-v1.md "Diagnostics" and
// specs/conjure-route-v1.md "Diagnostics".

// RecordPsiphonActiveRoute is the engine-side hook for the
// psiphon handler's per-session diagnostic. Updates the
// in-memory `psiphon_active_route` diagnostic field.
//
// `routeID` is the route the psiphon handler activated; pass
// empty string to clear (e.g., on engine_clear_route).
func RecordPsiphonActiveRoute(routeID string) error {
	if loadedCore() == nil {
		return errors.New("abi: not initialised")
	}
	if !psiphonCompiledIn && routeID != "" {
		return errors.New("abi: psiphon has no implementation in this build; cannot record an active route")
	}
	c := loadedCore()
	c.mu.Lock()
	c.lastActivePsiphonRouteID = routeID
	c.mu.Unlock()
	return nil
}

// PsiphonActiveRoute is a pure read of the most recently
// activated psiphon route ID this session. Empty string ⇒ no
// activation this session.
func PsiphonActiveRoute() string {
	if loadedCore() == nil {
		return ""
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastActivePsiphonRouteID
}

// RecordConjureActivation is the engine-side hook for the
// conjure handler's per-session diagnostic. Updates the
// in-memory `conjure_active_route` and `conjure_phantom_in_use`
// diagnostic fields.
//
// `routeID` is the route the conjure handler activated; pass
// empty string to clear. `rawPhantomIP` is the un-hashed IP
// the handler bound to; this function HASHES it at the
// boundary (8-byte SHA-256 truncation, hex-encoded) and stores
// only the hash. Empty `rawPhantomIP` clears the hash.
func RecordConjureActivation(routeID, rawPhantomIP string) error {
	if loadedCore() == nil {
		return errors.New("abi: not initialised")
	}
	if !conjureCompiledIn && (routeID != "" || rawPhantomIP != "") {
		return errors.New("abi: conjure has no implementation in this build; cannot record an active route")
	}
	c := loadedCore()
	c.mu.Lock()
	c.lastActiveConjureRouteID = routeID
	if rawPhantomIP == "" {
		c.lastConjurePhantomHashHex = ""
	} else {
		c.lastConjurePhantomHashHex = conjure.HashPhantom(rawPhantomIP)
	}
	c.mu.Unlock()
	return nil
}

// ConjureActiveRoute is a pure read of the most recently
// activated conjure route ID this session.
func ConjureActiveRoute() string {
	if loadedCore() == nil {
		return ""
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastActiveConjureRouteID
}

// ConjurePhantomInUseHash is a pure read of the HASHED phantom
// IP the conjure handler most recently bound to this session.
// 8-byte SHA-256 truncation, hex-encoded; the raw IP NEVER
// leaves the conjure transport package.
func ConjurePhantomInUseHash() string {
	if loadedCore() == nil {
		return ""
	}
	c := loadedCore()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastConjurePhantomHashHex
}
