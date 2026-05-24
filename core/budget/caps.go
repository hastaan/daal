package budget

import "errors"

// Tag is the V2 "scarcity_class" / "budget_tag". Already validated at
// the bundle layer (`bundle.ScarcityClass`); we re-export the string
// constants here so `core/budget` does not need to import the bundle
// types.
const (
	TagEmergency    = "emergency"
	TagLifelineOnly = "lifeline-only"
	TagLow          = "low"
	TagNormal       = "normal"
	TagBulkCapable  = "bulk-capable"
	TagExperimental = "experimental"
)

// Byte-count constants (uint64 to avoid signed-overflow surprises).
const (
	MiB uint64 = 1024 * 1024
	GiB uint64 = 1024 * MiB
)

// Cap is the full V2.1 cap row for a single budget tag. Phase 2A
// landed only the Hourly axis; Phase 2A-Polish adds Session and
// ModesAllowed, which together complete the canonical V2.1 table:
//
//	| Tag          | Hourly  | Session | Allowed modes              |
//	|--------------|---------|---------|----------------------------|
//	| emergency    | 50 MiB  | 200 MiB | lifeline                   |
//	| lifeline-only| 100 MiB | 500 MiB | lifeline                   |
//	| low          | 500 MiB |  2 GiB  | lifeline, normal           |
//	| normal       |  5 GiB  | unlim   | lifeline, normal           |
//	| bulk-capable | unlim   | unlim   | lifeline, normal, bulk     |
//	| experimental |  5 GiB  | unlim   | lifeline, normal           |
//
// `0` in either Hourly or Session means unlimited on that axis.
type Cap struct {
	Hourly       uint64
	Session      uint64
	ModesAllowed []string // closed set: lifeline, normal, bulk
}

// caps is the V2.1 cap table. The map is closed; new tags require a
// roadmap-level decision because changing a cap breaks V2
// success-metric soak parity.
//
// `modes_allowed` lists the THREE roadmap V2.2 budget modes only —
// lifeline, normal, bulk. The 2D `lifeline-strict` mode is treated by
// the path-manager as a strict super-set of "lifeline" for filtering;
// the budget engine itself stays mode-policy-free.
var caps = map[string]Cap{
	TagEmergency:    {Hourly: 50 * MiB, Session: 200 * MiB, ModesAllowed: []string{"lifeline"}},
	TagLifelineOnly: {Hourly: 100 * MiB, Session: 500 * MiB, ModesAllowed: []string{"lifeline"}},
	TagLow:          {Hourly: 500 * MiB, Session: 2 * GiB, ModesAllowed: []string{"lifeline", "normal"}},
	TagNormal:       {Hourly: 5 * GiB, Session: 0, ModesAllowed: []string{"lifeline", "normal"}},
	TagBulkCapable:  {Hourly: 0, Session: 0, ModesAllowed: []string{"lifeline", "normal", "bulk"}},
	TagExperimental: {Hourly: 5 * GiB, Session: 0, ModesAllowed: []string{"lifeline", "normal"}}, // alias of Normal until 2B's mode policy
}

// ErrUnknownTag is returned by Engine.SetTag when the tag is not in
// the closed `caps` map.
var ErrUnknownTag = errors.New("budget: unknown tag")

// ErrExhausted is returned by Engine.Add when EITHER the hourly OR
// per-session cap would be exceeded by the requested charge. The
// caller MUST stop pushing more bytes and SHOULD drive the FSM into
// StateBudgetExhausted.
var ErrExhausted = errors.New("budget: hourly cap exhausted")

// CapFor returns the hourly cap in bytes for tag, or (0, ErrUnknownTag)
// if the tag is unknown. A return of (0, nil) means unlimited.
//
// Phase 2A signature preserved verbatim; new call sites use FullCapFor
// to read the full Cap row (hourly + session + modes_allowed).
func CapFor(tag string) (uint64, error) {
	c, ok := caps[tag]
	if !ok {
		return 0, ErrUnknownTag
	}
	return c.Hourly, nil
}

// FullCapFor returns the complete Cap row for tag, or
// (Cap{}, ErrUnknownTag) if the tag is unknown. The returned Cap's
// ModesAllowed slice is a defensive copy; mutating it does not mutate
// the closed table.
func FullCapFor(tag string) (Cap, error) {
	c, ok := caps[tag]
	if !ok {
		return Cap{}, ErrUnknownTag
	}
	out := c
	out.ModesAllowed = append([]string(nil), c.ModesAllowed...)
	return out, nil
}

// KnownTags returns the set of accepted tag strings, sorted, for use
// in error messages and validation.
func KnownTags() []string {
	out := make([]string, 0, len(caps))
	for k := range caps {
		out = append(out, k)
	}
	// Stable order for tests and diagnostics.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
