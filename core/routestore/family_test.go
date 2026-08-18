package routestore

import "testing"

// Phase 3A.

// Only the four field-proven tiers are Stable. The Wave-1 honesty
// pass demoted the other five: a family is Stable only if the
// publisher can mint it AND the shipped engine can dial it.
func TestFamilyMaturity_V1BaselineIsStable(t *testing.T) {
	for _, fam := range []string{
		"vless-reality", "naive", "websocket-tls", "hysteria2",
	} {
		if FamilyMaturity(fam) != MaturityStable {
			t.Errorf("expected %s to be stable, got %s", fam, FamilyMaturity(fam))
		}
	}
}

// Dialable by the shipped engine, never minted by a publisher and
// never soaked. Experimental, therefore behind the gate.
func TestFamilyMaturity_DialableButUnprovenAreExperimental(t *testing.T) {
	for _, fam := range []string{"tuic", "shadowsocks", "wireguard"} {
		if FamilyMaturity(fam) != MaturityExperimental {
			t.Errorf("expected %s to be experimental, got %s", fam, FamilyMaturity(fam))
		}
		if !IsSelectableFamily(fam) {
			t.Errorf("%s must stay in-principle selectable behind the gate", fam)
		}
	}
}

// Families this build physically cannot dial. They must NOT read as
// "experimental" — that would invite the user to enable the gate and
// watch every route fail identically — and must not be selectable.
func TestFamilyMaturity_UndialableAreUnsupported(t *testing.T) {
	// amneziawg is the whole list now, and deliberately so: sing-box
	// 1.13.12 contains no AmneziaWG code at all, so the obfuscation that
	// IS the family cannot be produced. An AmneziaWG conf imports as a
	// plain `wireguard` route with a Downgrade notice (see
	// bundle/go/uri/wireguard.go); the amneziawg VALUE stays
	// undialable so a pack that declares it is refused rather than
	// badged as something it is not.
	for _, fam := range []string{"amneziawg"} {
		if FamilyMaturity(fam) != MaturityUnsupported {
			t.Errorf("expected %s to be unsupported, got %s", fam, FamilyMaturity(fam))
		}
		if !IsUnsupportedFamily(fam) {
			t.Errorf("IsUnsupportedFamily(%q) must be true", fam)
		}
		if IsExperimentalFamily(fam) {
			t.Errorf("%s must not read as experimental", fam)
		}
		if IsSelectableFamily(fam) {
			t.Errorf("%s must not be selectable — this build cannot dial it", fam)
		}
	}
}

// Wave 5. Every V3 family is Unsupported, not Experimental.
// "Experimental" means "unproven, may fail"; each of these means
// "this build cannot dial it", which is a different promise to
// the user and a different button in the UI. The arbiter is
// sing-box 1.13.12's outbound registry, which has no webtunnel,
// snowflake, masque, psiphon, conjure or wasm-module outbound.
// Reasons per family are in family.go.
func TestFamilyMaturity_V3FamiliesAreUnsupported(t *testing.T) {
	for _, fam := range []string{
		"webtunnel", "snowflake", "masque", "psiphon", "conjure",
		"transport_module", "lifeline_relay",
	} {
		if FamilyMaturity(fam) != MaturityUnsupported {
			t.Errorf("expected %s to be unsupported, got %s", fam, FamilyMaturity(fam))
		}
		if IsExperimentalFamily(fam) {
			t.Errorf("%s must not read as experimental — the gate has nothing to enable", fam)
		}
		if IsSelectableFamily(fam) {
			t.Errorf("%s must not be selectable — this build cannot dial it", fam)
		}
	}
}

// The three whose obstacle is not code, pinned separately so a
// future engineer who makes webtunnel or transport_module work
// does not sweep these along on the assumption they are the same
// kind of "not yet". They are not: no build this project could
// ship will ever dial them.
func TestFamilyMaturity_StructurallyUnavailableStayUnsupported(t *testing.T) {
	// psiphon — a third party's proprietary network; a client can
	//           hand off to it, a publisher cannot host it.
	// conjure — refraction needs a COOPERATING ISP running a
	//           station on a transit link; a rented VPS has none.
	// masque  — no masque outbound exists in sing-box 1.13.12,
	//           and its value is a large provider's anonymity set
	//           that a self-hosted relay cannot supply.
	for _, fam := range []string{"psiphon", "conjure", "masque"} {
		if !IsUnsupportedFamily(fam) {
			t.Errorf("%s is structurally unavailable to a self-hosted publisher "+
				"and must stay unsupported; the reason is on the enum value in "+
				"bundle/go/bundle/types.go", fam)
		}
	}
}

// webtunnel and snowflake are Tor pluggable transports, and the
// capability is REACHABLE in this build — as a bridge line inside
// a `tor-bridge` route (core/engine/torbin.go dispatches
// libwebtunnel.so / libsnowflake.so). What is unreachable is the
// family VALUE: a pack declaring transport_family "webtunnel"
// gets no dialer, while the identical bridge declared as
// tor-bridge connects. Locking that asymmetry so nobody
// "restores" the family values as an easier-looking fix.
func TestFamilyMaturity_TorPTFamiliesAreNotTheirOwnFamily(t *testing.T) {
	for _, pt := range []string{"webtunnel", "snowflake"} {
		if IsSelectableFamily(pt) {
			t.Errorf("%s must not be selectable as its own family — it is a Tor PT, "+
				"carried by a tor-bridge route", pt)
		}
	}
	// tor-bridge is ALSO unsupported today — the repair pass demoted it
	// because no shipped artifact contains libtor.so — but the
	// asymmetry this test locks is unaffected and is about to matter
	// more, not less: when the binaries ship, `tor-bridge` becomes
	// dialable and `webtunnel`/`snowflake` still must not, because they
	// are bridge lines inside a tor route and not outbound types.
	// Restoring them as their own families would be the easy-looking
	// wrong fix.
	if IsSelectableFamily("tor-bridge") {
		t.Error("tor-bridge cannot be dialled by any build that ships today " +
			"(no libtor.so in jniLibs, tools/build-tor-android.sh has never been run); " +
			"if this now fails, flip it in core/routestore/family.go in the SAME commit " +
			"that packages the binaries")
	}
}

func TestFamilyMaturity_OtherIsUnhandled(t *testing.T) {
	if FamilyMaturity("other") != MaturityUnhandled {
		t.Fatalf("other must be unhandled (V0 forward-compat slot)")
	}
	if IsSelectableFamily("other") {
		t.Fatalf("other must not be selectable")
	}
}

func TestFamilyMaturity_UnknownFamilyIsUnhandled(t *testing.T) {
	if FamilyMaturity("nonexistent-family-2999") != MaturityUnhandled {
		t.Fatalf("unknown families must default to unhandled")
	}
	if IsSelectableFamily("nonexistent-family-2999") {
		t.Fatalf("unknown families must not be selectable")
	}
}

func TestIsSelectableFamily(t *testing.T) {
	cases := map[string]bool{
		"vless-reality":    true,  // stable
		"tuic":             true,  // experimental — demoted in Wave 1, still dialable
		"shadowsocks":      true,  // experimental — demoted in Wave 1, still dialable
		"webtunnel":        false, // unsupported — a Tor PT, not its own outbound
		"snowflake":        false, // unsupported — a Tor PT, not its own outbound
		"masque":           false, // unsupported — no masque outbound in 1.13.12
		"psiphon":          false, // unsupported — someone else's network to host
		"conjure":          false, // unsupported — needs a cooperating ISP's station
		"transport_module": false, // unsupported — core/wasm.Dial has no production caller
		"lifeline_relay":   false, // unsupported — core/lifelinerelay does not exist
		"wireguard":        true,  // Wave 5: real endpoints[] slot + real endpoint options
		"amneziawg":        false, // unsupported — sing-box 1.13.12 has no AmneziaWG at all
		// Wave 5 emitted sing-box's real `tor` outbound, but no build
		// packages the tor binary the outbound execs, so nothing can
		// dial it. Repair pass returned it to unsupported.
		"tor-bridge":      false,
		"other":           false, // unhandled
		"future-family-X": false, // unknown
	}
	for fam, want := range cases {
		if got := IsSelectableFamily(fam); got != want {
			t.Errorf("IsSelectableFamily(%q) = %v, want %v", fam, got, want)
		}
	}
}

func TestKnownFamilies_IsStableSorted(t *testing.T) {
	known := KnownFamilies()
	for i := 1; i < len(known); i++ {
		if known[i-1] > known[i] {
			t.Fatalf("KnownFamilies must be stable-sorted; got %v", known)
		}
	}
}

func TestKnownFamilies_ContainsTaxonomyClosedList(t *testing.T) {
	// Locked closed-list size after Wave 5:
	//   4 stable       vless-reality, naive, websocket-tls, hysteria2
	//   4 experimental tuic, shadowsocks, anytls, wireguard
	//   9 unsupported  tor-bridge (no tor binary in any artifact),
	//                  amneziawg, webtunnel, snowflake, masque,
	//                  psiphon, conjure, transport_module,
	//                  lifeline_relay
	//   1 unhandled    other
	// = 18. Wave 5 added exactly one value (anytls) and re-graded
	// eight; the size moved 17 → 18 for the addition alone. If the
	// COUNT drifts again that is a roadmap-level change and this
	// test must be updated alongside specs/transport-families-v1.md
	// and docs/transport-family-inventory.md.
	want := 18
	if got := len(KnownFamilies()); got != want {
		t.Fatalf("taxonomy size drifted: got %d, want %d (update specs/transport-families-v1.md if intentional)", got, want)
	}
}

func TestMaturityString(t *testing.T) {
	cases := map[Maturity]string{
		MaturityUnhandled:          "unhandled",
		MaturityUnsupported:        "unsupported",
		MaturityExperimental:       "experimental",
		MaturityPromotionCandidate: "promotion-candidate",
		MaturityStable:             "stable",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Maturity(%d).String() = %q, want %q", int(m), got, want)
		}
	}
}

// Phase 3D additions.

// Phase 3E. Lock the `transport_module` family wiring against
// the WASM loader's `FamilyID` constant so a future rename of
// either side is caught at test time. The string match is
// intentional — the routestore package must not import
// `core/wasm` (the wasm package depends on the route's family
// string, never the other way round).
func TestFamilyMaturity_TransportModuleIsUnsupportedAndNonOpportunistic(t *testing.T) {
	const transportModuleSlug = "transport_module"
	// Wave 5 demotion. The wazero runtime is real and compiled in,
	// which made "experimental" look defensible at 3E — but
	// `core/wasm.Dial` has no production caller (only tests) and
	// nothing turns a loaded module into a sing-box outbound the
	// engine config can hold, so a transport_module route cannot
	// carry a byte. Restore Experimental when a production dial
	// path exists, not before.
	if FamilyMaturity(transportModuleSlug) != MaturityUnsupported {
		t.Fatalf("transport_module must be unsupported until core/wasm.Dial has a production caller")
	}
	if IsOpportunisticFamily(transportModuleSlug) {
		t.Fatalf("transport_module must NOT be opportunistic")
	}
	if IsSelectableFamily(transportModuleSlug) {
		t.Fatalf("transport_module must not be selectable")
	}
}

// TestIsOpportunisticFamily_3DLockedClassification — lock the
// per-family opportunistic flag so a future re-classification
// is a deliberate change rather than an accidental drift.
//
// 3D locked decision per spec:
//   - MASQUE: opportunistic (carried forward from 3C, retroactively
//     annotated at 3D when the IsOpportunistic field was added).
//   - Conjure: opportunistic (refraction stations are partner-
//     operated, displacement-only).
//   - Psiphon: NOT opportunistic (Psiphon-the-org's protocols
//     are battle-tested at scale).
//   - All other families: NOT opportunistic (default).
func TestIsOpportunisticFamily_3DLockedClassification(t *testing.T) {
	opportunistic := []string{"masque", "conjure"}
	notOpportunistic := []string{
		"vless-reality", "naive", "websocket-tls", "hysteria2",
		"tuic", "shadowsocks", "tor-bridge", "wireguard", "amneziawg",
		"webtunnel", "snowflake", "psiphon",
		"transport_module", "lifeline_relay", "other",
		"unknown-family-9999",
	}
	for _, fam := range opportunistic {
		if !IsOpportunisticFamily(fam) {
			t.Errorf("IsOpportunisticFamily(%q) = false; want true", fam)
		}
	}
	for _, fam := range notOpportunistic {
		if IsOpportunisticFamily(fam) {
			t.Errorf("IsOpportunisticFamily(%q) = true; want false", fam)
		}
	}
}

// Wave 5 built the tor CLIENT CODE: the importer emits sing-box's real
// `tor` outbound type instead of the invented `tor-bridge`, and
// core/engine/torconfig.go materialises the device paths tor needs. The
// tor lane then promoted the label to Experimental — which the repair
// pass reversed, because the label is a claim about the ARTIFACT and
// the artifact has no tor binary in it.
//
// This test is the label's guard. It fails the moment somebody promotes
// the family again, and the message says what has to be true first.
func TestFamilyMaturity_TorBridgeStaysUnsupportedUntilBinariesShip(t *testing.T) {
	if got := FamilyMaturity("tor-bridge"); got != MaturityUnsupported {
		t.Fatalf("tor-bridge maturity = %s, want unsupported.\n"+
			"Promote it ONLY in the commit that packages libtor.so and the PT binaries "+
			"into jniLibs for every shipped ABI — see the PACKAGING REQUIREMENT block in "+
			"core/engine/torbin.go and tools/build-tor-android.sh, which says STATUS: NEVER RUN. "+
			"Until then every tor route fails at config time on every artifact a user can install, "+
			"and Experimental invites them to flip the gate and watch it fail.", got)
	}
	if !IsUnsupportedFamily("tor-bridge") {
		t.Error("tor-bridge must read as 'this build cannot dial it', which is the truth")
	}
	if IsSelectableFamily("tor-bridge") {
		t.Error("tor-bridge must not be selectable while no build can dial it")
	}
}
