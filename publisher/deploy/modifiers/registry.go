package modifiers

import (
	"errors"
	"fmt"
	"sort"
)

// ErrUnknownKind is returned by Lookup when the requested kind is
// not present in the registry. Callers populating
// relaypackvalidate.ValidateOpts.AllowedModifierKinds MUST treat
// this as a hard reject (locked invariant 38).
var ErrUnknownKind = errors.New("modifier: unknown kind")

// Lookup returns the registered Meta for the given kind, or
// ErrUnknownKind. The lookup is case-sensitive.
func Lookup(kind string) (Meta, error) {
	r := registryFromGen()
	m, ok := r[kind]
	if !ok {
		return Meta{}, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	return m, nil
}

// AllKinds returns every registered kind in deterministic
// (alphabetical) order. Useful for UI surfaces and tests.
func AllKinds() []string {
	r := registryFromGen()
	out := make([]string, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AllowedKindsAt returns the set of modifier kinds that the
// validator MAY accept at the given phase. A kind appears in the
// returned map iff:
//
//  1. its registered Status is PASS (locked invariant 38: PENDING /
//     REJECTED / DEPRECATED never accepted), AND
//  2. its registered MinPhase ordinal is <= the requested phase
//     ordinal (locked invariant 39).
//
// Callers pass the returned map to
// relaypackvalidate.ValidateOpts.AllowedModifierKinds. The validator
// itself was NOT modified at FRP-12 — RP013's existing per-kind
// allow-list logic (already plumbed at FRP-1) is the gate.
//
// At FRP-12 ship the registry contains zero PASS records (locked
// invariant 37), so AllowedKindsAt(PostV2) returns an empty map.
func AllowedKindsAt(phase Phase) map[string]bool {
	want := phaseOrdinal(phase)
	if want < 0 {
		return map[string]bool{}
	}
	r := registryFromGen()
	out := map[string]bool{}
	for k, m := range r {
		if m.Status != StatusPass {
			continue
		}
		got := phaseOrdinal(m.MinPhase)
		if got < 0 || got > want {
			continue
		}
		out[k] = true
	}
	return out
}

// HasPassAt is a convenience wrapper: true iff AllowedKindsAt
// contains the given kind.
func HasPassAt(kind string, phase Phase) bool {
	return AllowedKindsAt(phase)[kind]
}
