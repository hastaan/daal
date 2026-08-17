package selection

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrModifierPlatform is returned by RejectByPlatform when a
// candidate's modifiers[] contains a kind whose platforms[] list
// does not include the runtime platform. Locked invariant 40.
//
// The error code surface name is IMP_MODIFIER_PLATFORM (matches the
// FRP-12 phase doc text); we expose the Go sentinel as
// ErrModifierPlatform and a Code() method that returns the wire
// label.
var ErrModifierPlatform = errors.New("IMP_MODIFIER_PLATFORM")

// modifierPolicyAllowOf is the engine-local view of one
// publisher/deploy/modifiers.Meta record. The engine never imports
// daal/publisher (asymmetric guard preserved); the publisher side
// projects its registry onto this shape and passes it as a closure
// to RejectByPlatform.
type modifierPolicyAllowOf struct {
	// Platforms is the list of permitted platform strings (e.g.
	// "linux-desktop", "android"). Empty list means no platform.
	Platforms []string
	// Pass is true iff the kind's pass record is PASS at and above
	// the current validator phase. False for PENDING / REJECTED /
	// DEPRECATED kinds and for unknown kinds.
	Pass bool
}

// PolicyFn returns the engine-local view of a modifier kind. The
// publisher side wires this to publisher/deploy/modifiers.Lookup +
// AllowedKindsAt. At FRP-12 ship every registered kind is PENDING
// so PolicyFn returns Pass=false for every kind.
type PolicyFn func(kind string) modifierPolicyAllowOf

// modifierItem is the bundle.Modifier shape, duplicated here
// because core/ MUST NOT import bundle/ as a circular concern (the
// engine importer passes ModifiersJSON as an opaque string).
type modifierItem struct {
	Kind             string `json:"kind"`
	Platform         string `json:"platform,omitempty"`
	ProbingRiskClass string `json:"probing_risk_class,omitempty"`
}

// RejectByPlatform inspects a candidate's ModifiersJSON. For each
// modifier kind, it consults the supplied PolicyFn. If the kind is
// not Pass, it rejects (locked invariant 38). If Pass, it requires
// that the runtime platform appear in the Platforms list (locked
// invariant 40).
//
// Returns nil for candidates whose ModifiersJSON is empty / "null"
// / "[]" (no modifiers requested = no gate fires).
//
// The desktopHint disambiguates linux/desktop vs android (both
// runtime.GOOS == "linux") and darwin/desktop vs ios. Engine builds
// for android / ios pass desktopHint=false; desktop UI builds pass
// true.
//
// runtimeGOOS is parameterised so tests can drive every platform
// without GOOS hacks.
func RejectByPlatform(modifiersJSON string, runtimeGOOS string, desktopHint bool, policy PolicyFn) error {
	switch modifiersJSON {
	case "", "null", "[]":
		return nil
	}
	var items []modifierItem
	if err := json.Unmarshal([]byte(modifiersJSON), &items); err != nil {
		return fmt.Errorf("%w: malformed modifiers JSON: %v", ErrModifierPlatform, err)
	}
	if len(items) == 0 {
		return nil
	}
	platform, ok := platformFromGOOS(runtimeGOOS, desktopHint)
	if !ok {
		// Unknown GOOS. Per locked invariant 40 the importer rejects
		// any modifier-bearing candidate when the runtime platform
		// cannot be resolved.
		return fmt.Errorf("%w: unknown runtime GOOS %q", ErrModifierPlatform, runtimeGOOS)
	}
	if policy == nil {
		// No policy → no kind can be PASS → reject any non-empty
		// modifier list. Equivalent to FRP-12-ship behaviour.
		return fmt.Errorf("%w: no policy supplied; modifiers cannot be allowed", ErrModifierPlatform)
	}
	for _, it := range items {
		view := policy(it.Kind)
		if !view.Pass {
			return fmt.Errorf("%w: modifier kind %q is not PASS at this phase", ErrModifierPlatform, it.Kind)
		}
		ok := false
		for _, p := range view.Platforms {
			if p == platform {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: modifier kind %q not permitted on platform %q (allowed: %v)",
				ErrModifierPlatform, it.Kind, platform, view.Platforms)
		}
	}
	return nil
}

// platformFromGOOS is the engine-local mirror of
// publisher/deploy/modifiers.PlatformFromGOOS. We duplicate it here
// so core/ does not import daal/publisher (asymmetric guard).
// Returns one of {linux-desktop, windows-desktop, macos-desktop,
// android, ios} or ("", false) for unknown.
func platformFromGOOS(goos string, desktopHint bool) (string, bool) {
	switch goos {
	case "linux":
		if desktopHint {
			return "linux-desktop", true
		}
		return "android", true
	case "darwin":
		if desktopHint {
			return "macos-desktop", true
		}
		return "ios", true
	case "windows":
		return "windows-desktop", true
	case "android":
		return "android", true
	case "ios":
		return "ios", true
	}
	return "", false
}

// AllowOf is the type-cleaner export of modifierPolicyAllowOf for
// callers (the publisher-side wiring) that need to construct the
// view value.
type AllowOf = modifierPolicyAllowOf

// MakeAllow returns an AllowOf with the given fields. Convenience
// for callers that don't want to spell out the struct.
func MakeAllow(pass bool, platforms ...string) AllowOf {
	return AllowOf{Pass: pass, Platforms: platforms}
}
