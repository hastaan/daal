package abi

import (
	"errors"

	"daal/core/transports/conjure"
)

// Phase 3D. Refraction-family (psiphon + conjure) per-session
// recording helpers. NO new release-surface ABI symbols are
// added at 3D; all of these functions are Go-package-internal,
// invoked by the transport handlers as they activate routes.
// The diagnostics renderer in `ExportDiagnostics` reads the
// recorded state through the in-memory Core fields.
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
//   - Psiphon recordings are rejected when
//     `psiphon_compiled_in` is false (`-tags no_psiphon`
//     builds): the engine must not advertise an active psiphon
//     route when the vendor tree is excluded.
//   - Conjure recordings are not gated on a compile-in flag —
//     the conjure tree is Apache-2.0 and ships unconditionally
//     at 3D.
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
		return errors.New("abi: psiphon vendor tree excluded; cannot record active route")
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
