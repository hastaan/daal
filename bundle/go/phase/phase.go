// Package phase holds THE canonical RelayPack phase enum and the one
// constant that says which phase this build ships.
//
// WHY THIS PACKAGE EXISTS
//
// Before this package there were three independent `type Phase string`
// declarations — `relaypackvalidate`, `core/internal/selection`, and
// `publisher/deploy/modifiers` — with two different spellings of the
// same value (`"PostV2"` vs `"post-V2"`). Nothing type-checked across
// the boundary: every cross-package comparison went through the
// underlying string, so the mismatch was invisible to the compiler and
// would have surfaced as a silently-skipped gate.
//
// Worse, six sites hard-coded a phase *literal* and they disagreed. The
// recipient import path validated at V1.5 while the publisher wizard
// signed at V1.6, so the two gates FRP-8 had already lifted
// (`RP004` cdn_fronted, `RP021` freshness_url) stayed shut on the only
// path that matters — the device.
//
// The fix has two halves and both live here:
//
//  1. ONE type. Every other package now declares `type Phase =
//     phase.Phase` (a type *alias*, not a definition), so all four
//     packages are literally the same type and a wrong-spelling
//     constant cannot be constructed.
//
//  2. ONE default. `Current` is the single place a phase literal is
//     written. Producers (wizard, CLI, rotation re-sign) and consumers
//     (importer, refresh, selector) all read it, so they cannot drift
//     apart again. `tools/check-phase.sh` fails the build if a phase
//     literal reappears anywhere else.
//
// This package deliberately has ZERO imports. `publisher/deploy/modifiers`
// documents an asymmetric guard — it must be consumable without pulling
// in the validator — and a leaf package with no dependencies preserves
// that while still unifying the type.
package phase

// Phase is the RelayPack spec-version cohort a bundle is validated,
// signed, and selected under. Phase progression flips constants, not
// validator code: the same binary enforces every phase.
type Phase string

const (
	// V15 — V1.5 ship. direct_vps only; cdn_fronted (RP004) and
	// serverless_external (RP003) rejected; non-empty modifiers[]
	// rejected (RP013); non-empty freshness_url rejected (RP021);
	// non-empty cell_scope rejected (RP016).
	V15 Phase = "V1.5"

	// V16 — V1.6 / FRP-8 ship. Lifts RP004 and RP021, and replaces
	// the blanket cdn_fronted rejection with the real §11.7
	// hardening checks (RP007 family matrix, RP022 attestation
	// soundness, RP023 DNS-only posture). The RP021 lift is likewise
	// a REPLACEMENT, not a removal: freshness_url stops being
	// rejected outright and starts being shape-checked
	// (https, real hostname, no credentials).
	//
	// STILL REJECTED at V1.6: serverless_external (RP003), non-empty
	// modifiers[] (RP013), and non-empty cell_scope (RP016 — cells
	// require V2 / FRP-11, so the rule spans every pre-V2 phase, not
	// just V1.5). Anything added to this list must be written into
	// the validator as an explicit phase list; a rule keyed to
	// `== PhaseV15` alone switches itself off the moment Current
	// moves.
	V16 Phase = "V1.6"

	// V2 — reserved. Used only by the selector's explanation
	// vocabulary; the validator has no V2 rule-set and rejects it
	// (see relaypackvalidate.Validate) rather than falling through
	// to the most-permissive branch.
	V2 Phase = "V2"

	// PostV2 — FRP-12 ship. Lifts serverless_external and allows
	// non-empty modifiers[] per-kind via AllowedModifierKinds.
	//
	// NOTE the spelling. `core/internal/selection` used to spell this
	// "post-V2"; that value is gone. If a persisted artefact somewhere
	// still carries the old spelling, Parse accepts it and normalises.
	PostV2 Phase = "PostV2"
)

// Current is the phase this build produces and accepts. It is THE
// canonical constant: the wizard signs at Current, the CLI defaults to
// Current, the rotation re-sign re-signs at Current, the on-device
// importer validates at Current, and the selector decides at Current.
//
// Changing this line changes the whole system's phase in one edit.
// That is the entire point — see the package doc.
const Current = V16

// legacyPostV2 is the pre-unification `core/internal/selection`
// spelling. It is not a Phase constant (nothing should produce it);
// Parse maps it onto PostV2 so an explanation JSON persisted by an
// older build still round-trips instead of landing on the
// "unknown phase" path.
const legacyPostV2 = "post-V2"

// Known reports whether p is one of the four enum values. It does NOT
// mean the validator supports p — see relaypackvalidate for that.
func (p Phase) Known() bool {
	switch p {
	case V15, V16, V2, PostV2:
		return true
	}
	return false
}

// String returns the wire spelling.
func (p Phase) String() string { return string(p) }

// Parse converts an operator- or wire-supplied string into a Phase.
//
// The empty string means "whatever this build ships" and yields
// Current — a zero value must never fall through to the most permissive
// rule-set, which is exactly what the old `ValidateOpts{}` did.
//
// An unrecognised value is an error, not a silent default: a typo in
// `--phase` must fail loudly rather than pick a gate set at random.
func Parse(s string) (Phase, error) {
	if s == "" {
		return Current, nil
	}
	if s == legacyPostV2 {
		return PostV2, nil
	}
	p := Phase(s)
	if !p.Known() {
		return "", &UnknownPhaseError{Value: s}
	}
	return p, nil
}

// UnknownPhaseError is returned by Parse for an unrecognised phase.
type UnknownPhaseError struct{ Value string }

func (e *UnknownPhaseError) Error() string {
	return "unknown phase " + e.Value + " (want " + string(V15) + " | " +
		string(V16) + " | " + string(V2) + " | " + string(PostV2) + ")"
}

// All returns the enum in progression order. Callers that iterate
// phases (fixture generators, ordinal tables) use this so a new phase
// constant cannot be added without every iterator seeing it.
func All() []Phase { return []Phase{V15, V16, V2, PostV2} }
