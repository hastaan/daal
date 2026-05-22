package routestore

// Phase 3A. Family taxonomy + maturity table.
//
// Locked at the start of Phase 3A per
// specs/transport-families-v1.md. The set of valid family values
// is a CLOSED list; adding a value is a roadmap-level decision and
// requires a fresh soak run. The bundle parser
// (`bundle/go/bundle/sbp.go::validTransport`) is the gatekeeper.
//
// Every family enters at Experimental maturity. The experimental
// gate is consulted by `core/pathmanager/family_filter.go` before
// the trust / budget / network-memory layers; with the gate OFF,
// experimental-maturity routes are filtered out of selection
// entirely, but remain visible in `ListRoutes` (so the UI can
// render the Experimental badge on the route card).
//
// The V0 `other` value remains accepted at parse time for forward
// compatibility but is never selected by the path manager — its
// maturity is `Unhandled` here, distinct from `Stable`.

// Maturity is the per-family lifecycle level governing whether
// the family is selectable without the user-toggled experimental
// gate.
type Maturity int

const (
	// MaturityUnhandled is the entry for the V0 `other` value.
	// The bundle parser accepts it (forward compatibility) but
	// the path manager never selects it — there is no engine-side
	// handler.
	MaturityUnhandled Maturity = iota

	// MaturityExperimental is the entry maturity for every new
	// V3+ family. Routes are filtered out of selection unless
	// the per-engine experimental gate is enabled. Auto-promotion
	// (2G) cannot promote into a network whose only available
	// routes are experimental.
	MaturityExperimental

	// MaturityPromotionCandidate is reserved at 3A. No family
	// ships at this level until a roadmap-level decision; the
	// constant exists so 3B–3G ship into a stable shape.
	MaturityPromotionCandidate

	// MaturityStable is the V1 baseline level. Family is
	// selectable in any build with the appropriate handler
	// compiled in.
	MaturityStable
)

// String renders a maturity value as the diagnostics-stable
// snake-case label.
func (m Maturity) String() string {
	switch m {
	case MaturityUnhandled:
		return "unhandled"
	case MaturityExperimental:
		return "experimental"
	case MaturityPromotionCandidate:
		return "promotion-candidate"
	case MaturityStable:
		return "stable"
	default:
		return "unknown"
	}
}

// familyMaturity is the locked V3 taxonomy. The map's keys
// correspond 1:1 with the closed enum exposed by the bundle
// parser; missing keys (a family present in the bundle parser
// but not here) is a build-time bug, asserted by the
// TestFamilyTaxonomyMatchesBundleParser regression.
//
// Phase 3A locks this map. Adding a family requires:
//  1. A roadmap-level decision.
//  2. A new entry here at MaturityExperimental.
//  3. A widening of the bundle parser's validTransport list.
//  4. A fresh soak run.
var familyMaturity = map[string]Maturity{
	// V1 baseline (1B). All stable.
	"vless-reality": MaturityStable,
	"naive":         MaturityStable,
	"websocket-tls": MaturityStable,
	"hysteria2":     MaturityStable,
	"tuic":          MaturityStable,
	"shadowsocks":   MaturityStable,
	"tor-bridge":    MaturityStable,
	"wireguard":     MaturityStable,
	"amneziawg":     MaturityStable,

	// 3A — first V3 family.
	"webtunnel": MaturityExperimental,

	// 3B–3G planned families. Reserved here so
	// `FamilyMaturity` returns the right value the moment a
	// later sub-phase wires them up; the bundle parser still
	// has to accept them before they're selectable.
	"snowflake":        MaturityExperimental,
	"masque":           MaturityExperimental,
	"psiphon":          MaturityExperimental,
	"conjure":          MaturityExperimental,
	"transport_module": MaturityExperimental,
	"lifeline_relay":   MaturityExperimental,

	// V0 forward-compat slot.
	"other": MaturityUnhandled,
}

// familyOpportunistic is the locked-at-3D opportunistic-family
// table. Auto-promotion (2G) consults this map: a network whose
// only available family is opportunistic is treated as having
// no auto-promotable routes.
//
// The defaults reflect the per-family operational posture:
//   - MASQUE (3C): opportunistic — sub-modes degrade through
//     UDP probing; never the steady-state choice on a network
//     where another family works.
//   - Conjure (3D): opportunistic — phantom-IPv6 stations are
//     partner-operated and capacity-rated for displacement,
//     not for steady state.
//   - Psiphon (3D): NOT opportunistic — Psiphon-the-org's
//     protocol-class is battle-tested at scale; auto-promotion
//     into a Psiphon-only network is acceptable.
//   - All other families default to NOT opportunistic.
//
// Locked at Phase 3D per `specs/transport-families-v1.md` 3D
// amendment. Re-classifying a family is a roadmap-level
// decision.
var familyOpportunistic = map[string]bool{
	"masque":  true, // 3C; retroactively annotated at 3D.
	"conjure": true, // 3D.
}

// IsOpportunisticFamily reports whether a family is treated as
// opportunistic by the 2G auto-promotion detector. Unknown
// families return false; treating an unknown family as
// non-opportunistic is the conservative default (auto-promotion
// considers it eligible, which means burn-pressure detection
// runs normally).
func IsOpportunisticFamily(family string) bool {
	return familyOpportunistic[family]
}

// FamilyMaturity returns the maturity for a given family value.
// Unknown families return MaturityUnhandled — the path manager
// treats unknown families as unselectable, so an out-of-sync
// older client that imported a future-family bundle simply
// skips the route rather than crashing.
func FamilyMaturity(family string) Maturity {
	if m, ok := familyMaturity[family]; ok {
		return m
	}
	return MaturityUnhandled
}

// IsExperimentalFamily is the hot-path predicate consulted by
// the pathmanager's experimental filter. Equivalent to
// `FamilyMaturity(f) == MaturityExperimental`; the dedicated
// helper exists so the filter site reads cleanly.
func IsExperimentalFamily(family string) bool {
	return FamilyMaturity(family) == MaturityExperimental
}

// IsSelectableFamily reports whether a family is even
// in-principle selectable by the path manager, ignoring the
// experimental gate. False for the V0 `other` slot and for any
// family the bundle parser has accepted but the engine doesn't
// know about.
func IsSelectableFamily(family string) bool {
	m := FamilyMaturity(family)
	return m == MaturityExperimental ||
		m == MaturityPromotionCandidate ||
		m == MaturityStable
}

// KnownFamilies returns a stable-sorted list of every family in
// the locked taxonomy. Used by the regression test that asserts
// the routestore taxonomy and the bundle parser's accepted-enum
// list never drift apart.
func KnownFamilies() []string {
	out := make([]string, 0, len(familyMaturity))
	for f := range familyMaturity {
		out = append(out, f)
	}
	// Stable order so test diffs are readable.
	sortStrings(out)
	return out
}

// sortStrings is a stdlib-free string sort kept here so this
// file has no transitive imports beyond the package — the
// taxonomy is consulted from many call sites and we keep its
// import graph minimal.
func sortStrings(s []string) {
	// Insertion sort; the list is ~17 entries.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
