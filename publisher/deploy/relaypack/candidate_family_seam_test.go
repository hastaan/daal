package relaypack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/relayports"
)

// WAVE-5 REPAIR REGRESSION — the candidate→manifest seam.
//
// A transport family has to pass through THREE lists before a recipient
// can dial it: the toolbox profile that offers it, this package's
// candidate renderer, and the client-outbound renderer. The matrix test
// next door covers the third against relayports; nothing covered the
// SECOND, and it had gone stale.
//
// The concrete failure: `validTransport` was a hand-kept switch that
// never received `anytls`, so `renderCandidates` refused an anytls
// candidate as an "unknown transport_family" — and because the binder
// calls it before anything else, BuildOperatorPack failed outright. The
// operator got NO pack: not a pack missing anytls, no pack at all,
// losing the four families that work. A publisher-side family list
// which is a subset of the recipient-side one does not fail closed on
// the route; it fails closed on the bundle.
//
// This test asserts the two directions that actually bite: every family
// a shipped toolbox profile can offer, and every family relayports
// assigns a port to, must render.
func TestRenderCandidates_AcceptsEveryFamilyTheProfilesOffer(t *testing.T) {
	for _, family := range profileFamilies(t) {
		t.Run(family, func(t *testing.T) {
			assertCandidateRenders(t, family)
		})
	}
}

func TestRenderCandidates_AcceptsEveryFamilyRelayportsDeclares(t *testing.T) {
	for _, family := range relayports.Declared() {
		t.Run(family, func(t *testing.T) {
			assertCandidateRenders(t, family)
		})
	}
}

func assertCandidateRenders(t *testing.T, family string) {
	t.Helper()
	rec := &provider.OperatorRecord{
		Candidates: []provider.CandidateMeta{{
			Family:           family,
			ExposureMode:     "direct_vps",
			FamilyClass:      "vpn",
			ProbingRiskClass: "low",
			Port:             relayports.For(family).Port,
		}},
	}
	out, err := renderCandidates(rec, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")
	if err != nil {
		t.Fatalf("renderCandidates refused family %q: %v\n"+
			"This is the whole-pack failure: the binder calls renderCandidates first, "+
			"so BuildOperatorPack returns no pack at all — not even the families that work.",
			family, err)
	}
	if len(out.routes) != 1 {
		t.Fatalf("family %q produced %d routes, want 1", family, len(out.routes))
	}
}

// profileFamilies reads the shipped toolbox profiles off disk rather
// than restating them, so a family added to a profile is covered here
// the moment it is added.
func profileFamilies(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "profiles", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no toolbox profiles found (glob err %v); this test would silently prove nothing", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var doc struct {
			Candidates []struct {
				Family string `json:"family"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		for _, c := range doc.Candidates {
			// normaliseFamily is part of the seam under test: profiles
			// spell one family "amnezia-wg" and the enum spells it
			// "amneziawg".
			f := normaliseFamily(c.Family)
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}
