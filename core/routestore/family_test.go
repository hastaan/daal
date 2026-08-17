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
	for _, fam := range []string{"tuic", "shadowsocks"} {
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
	for _, fam := range []string{"tor-bridge", "wireguard", "amneziawg"} {
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

func TestFamilyMaturity_3AFamilyIsExperimental(t *testing.T) {
	if FamilyMaturity("webtunnel") != MaturityExperimental {
		t.Fatalf("webtunnel must enter at experimental maturity")
	}
	if !IsExperimentalFamily("webtunnel") {
		t.Fatalf("IsExperimentalFamily(webtunnel) must be true")
	}
}

func TestFamilyMaturity_PlannedV3FamiliesAreExperimental(t *testing.T) {
	// These are reserved in the taxonomy ahead of their sub-phase
	// implementation per spec/transport-families-v1.md.
	for _, fam := range []string{
		"snowflake", "masque", "psiphon", "conjure",
		"transport_module", "lifeline_relay",
	} {
		if FamilyMaturity(fam) != MaturityExperimental {
			t.Errorf("planned family %s must be experimental, got %s", fam, FamilyMaturity(fam))
		}
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
		"webtunnel":        true,  // experimental — selectable in principle
		"snowflake":        true,  // experimental
		"transport_module": true,  // experimental
		"tuic":             true,  // experimental (demoted, still dialable)
		"wireguard":        false, // unsupported — no Endpoints slot in the config
		"amneziawg":        false, // unsupported — "unknown outbound type"
		"tor-bridge":       false, // unsupported — "tor-bridge" is not a sing-box type
		"other":            false, // unhandled
		"future-family-X":  false, // unknown
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
	// Locked closed-list size = 4 stable + 9 experimental
	// + 3 unsupported + 1 other = 17. The Wave-1 honesty pass
	// re-graded six families but added and removed none, so the size
	// is unchanged. If the COUNT drifts, that is a roadmap-level
	// change and the test must be updated alongside the spec.
	want := 17
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
func TestFamilyMaturity_3ETransportModuleIsExperimentalAndNonOpportunistic(t *testing.T) {
	const transportModuleSlug = "transport_module"
	if FamilyMaturity(transportModuleSlug) != MaturityExperimental {
		t.Fatalf("transport_module must be experimental at 3E")
	}
	if !IsExperimentalFamily(transportModuleSlug) {
		t.Fatalf("IsExperimentalFamily(transport_module) must be true")
	}
	if IsOpportunisticFamily(transportModuleSlug) {
		t.Fatalf("transport_module must NOT be opportunistic at 3E")
	}
	if !IsSelectableFamily(transportModuleSlug) {
		t.Fatalf("transport_module must be in-principle selectable at 3E")
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
