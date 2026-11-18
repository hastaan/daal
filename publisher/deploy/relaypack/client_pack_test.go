package relaypack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// buildStubPack builds a signed operator .sbp with metadata-stub
// profiles (the pre-Tier-2 shape) for the given families.
func buildStubPack(t *testing.T, families []string) []byte {
	t.Helper()
	return buildStubPackWithout(t, families)
}

// buildStubPackWithout is buildStubPack with the named families signed
// WITHOUT an endpoint commitment — what bind-and-sign produces for a
// family whose connection material it did not have.
func buildStubPackWithout(t *testing.T, families []string, without ...string) []byte {
	t.Helper()
	uncommitted := map[string]bool{}
	for _, f := range without {
		uncommitted[f] = true
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	from := now.Add(-time.Hour).Format(time.RFC3339)
	until := now.Add(30 * 24 * time.Hour).Format(time.RFC3339)

	var routes []bundle.RouteManifestEntry
	profiles := map[string][]byte{}
	for i, fam := range families {
		id := "r" + string(rune('1'+i))
		cp := "profiles/" + id + ".json"
		stub, _ := json.Marshal(map[string]any{
			"port":       443,
			"_relaypack": map[string]any{"exposure_mode": "direct_vps"},
		})
		profiles[cp] = stub
		// The signed half: where this route points and what proves the
		// relay is the relay, for the relay fullParams() describes.
		fsc := map[string]any{"port": 443, "_relaypack": map[string]any{"exposure_mode": "direct_vps"}}
		if ep, _ := endpointFor(fam, 443, EndpointMaterialFromParams(fullParams())); ep != nil && !uncommitted[fam] {
			fsc[bundle.EndpointKey] = ep
		}
		fscBytes, _ := json.Marshal(fsc)
		routes = append(routes, bundle.RouteManifestEntry{
			ID:                   id,
			ScarcityClass:        "normal",
			TransportFamily:      fam,
			ConfigPath:           cp,
			ValidFrom:            from,
			ValidUntil:           until,
			FamilySpecificConfig: fscBytes,
		})
	}
	m := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              "Test",
			KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      from,
			TrustClass:        "community",
		},
		Bundle: bundle.BundleInfo{
			ID: "rp-test", Type: "provider", CreatedAt: from, ExpiresAt: until,
		},
		Routes: routes,
	}
	sbp, err := bundle.BuildSignedBundle(m, profiles, pub, priv)
	if err != nil {
		t.Fatalf("build stub pack: %v", err)
	}
	return sbp
}

func TestRewriteProfiles_KeepsSignatureAndInjectsOutbounds(t *testing.T) {
	sbp := buildStubPack(t, []string{"vless-reality", "websocket-tls"})

	rewritten, skipped, err := RewriteProfilesForRecipient(sbp, fullParams())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("nothing should have been skipped here: %v", skipped)
	}

	// 1. The rewritten pack still verifies (signature intact).
	parsed, err := bundle.ParseSBP(bytes.NewReader(rewritten), int64(len(rewritten)))
	if err != nil {
		t.Fatalf("parse rewritten: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("rewritten pack failed verification: %v", err)
	}

	// 2. Each route's profile is now a real client outbound with a type.
	for _, route := range parsed.Manifest.Routes {
		var ob map[string]any
		if err := json.Unmarshal(parsed.Profiles[route.ConfigPath], &ob); err != nil {
			t.Fatalf("route %s profile not JSON: %v", route.ID, err)
		}
		if ob["type"] == nil || ob["type"] == "" {
			t.Errorf("route %s (%s): profile still has no type: %v",
				route.ID, route.TransportFamily, ob)
		}
		if ob["tag"] != "active" {
			t.Errorf("route %s: tag = %v, want active", route.ID, ob["tag"])
		}
		if ob["server"] != "78.47.152.16" {
			t.Errorf("route %s: server = %v", route.ID, ob["server"])
		}
	}
}

func TestRewriteProfiles_FailsClosedWhenNoRouteRenders(t *testing.T) {
	// A pack whose ONLY route cannot be rendered is still a hard error:
	// an .sbp with no connectable route is not a pack.
	sbp := buildStubPack(t, []string{"hysteria2"})
	p := fullParams()
	p.Hy2Password = ""
	if _, _, err := RewriteProfilesForRecipient(sbp, p); err == nil {
		t.Fatal("expected rewrite to fail closed when not one route renders")
	}
}

// WAVE-5 REPAIR REGRESSION. One family's missing credential used to
// abort the whole rewrite, so a relay running an mgmt artifact that
// predates (say) tuic could not have ANY recipient added to it — the
// four working families died with the one that was missing. The blast
// radius of the old fail-closed was strictly larger than the problem.
func TestRewriteProfiles_DegradesPerRouteRatherThanKillingThePack(t *testing.T) {
	sbp := buildStubPack(t, []string{"vless-reality", "hysteria2", "websocket-tls"})
	p := fullParams()
	p.Hy2Password = "" // the relay reported no hysteria2 credential

	rewritten, skipped, err := RewriteProfilesForRecipient(sbp, p)
	if err != nil {
		t.Fatalf("rewrite must survive one unrenderable route: %v", err)
	}
	if len(skipped) != 1 || skipped[0].Family != "hysteria2" {
		t.Fatalf("skipped = %+v, want exactly the hysteria2 route", skipped)
	}
	if skipped[0].Reason == "" {
		t.Error("a skipped route with no reason tells the operator nothing")
	}

	parsed, err := bundle.ParseSBP(bytes.NewReader(rewritten), int64(len(rewritten)))
	if err != nil {
		t.Fatalf("parse rewritten: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("degraded pack failed verification: %v", err)
	}
	for _, route := range parsed.Manifest.Routes {
		var ob map[string]any
		if err := json.Unmarshal(parsed.Profiles[route.ConfigPath], &ob); err != nil {
			t.Fatalf("route %s profile not JSON: %v", route.ID, err)
		}
		if route.TransportFamily == "hysteria2" {
			// The route survives in the SIGNED manifest — it cannot be
			// removed without breaking the signature — so what matters
			// is that its profile has no outbound type and says why.
			if ob["type"] != nil {
				t.Errorf("skipped route %s still carries an outbound type %v; it would be dialled",
					route.ID, ob["type"])
			}
			if ob[unavailableMarkerKey] == nil {
				t.Errorf("skipped route %s carries no %s marker", route.ID, unavailableMarkerKey)
			}
			continue
		}
		if ob["type"] == nil || ob["type"] == "" {
			t.Errorf("route %s (%s) should have rendered but has no type",
				route.ID, route.TransportFamily)
		}
	}
}

// F-004, publisher side. The minter holds its own output to the signed
// endpoint: a route with no commitment is dropped and reported (the
// recipient's client would refuse it), and an outbound that disagrees
// with the commitment — the relay moved after the pack was signed — is
// an error HERE, where the operator is watching, not a file every
// recipient's phone rejects.
func TestRewriteProfiles_HoldsItsOutputToTheSignedEndpoint(t *testing.T) {
	// 1. No commitment for one family: dropped, reported, marked.
	sbp := buildStubPackWithout(t, []string{"vless-reality", "hysteria2"}, "hysteria2")
	out, skipped, err := RewriteProfilesForRecipient(sbp, fullParams())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(skipped) != 1 || skipped[0].Family != "hysteria2" {
		t.Fatalf("skipped = %+v, want the uncommitted hysteria2 route", skipped)
	}
	parsed, _ := bundle.ParseSBP(bytes.NewReader(out), int64(len(out)))
	for _, r := range parsed.Manifest.Routes {
		typ := bundle.ProfileOutboundType(parsed.Profiles[r.ConfigPath])
		if r.TransportFamily == "hysteria2" && (typ != "" || !bundle.ProfileUnavailable(parsed.Profiles[r.ConfigPath])) {
			t.Errorf("uncommitted route carries an outbound (%q) or no marker", typ)
		}
		if r.TransportFamily == "vless-reality" {
			ep, err := bundle.ParseEndpoint(r.FamilySpecificConfig)
			if err != nil {
				t.Fatal(err)
			}
			if err := bundle.CheckOutbound(r.TransportFamily, ep, parsed.Profiles[r.ConfigPath]); err != nil {
				t.Errorf("minted outbound does not match its signed endpoint: %v", err)
			}
		}
	}

	// 2. The relay moved (L3) after signing: refuse to mint.
	sbp = buildStubPack(t, []string{"vless-reality", "hysteria2"})
	moved := fullParams()
	moved.Server = "203.0.113.77"
	if _, _, err := RewriteProfilesForRecipient(sbp, moved); !errors.Is(err, ErrStaleSignedPack) {
		t.Fatalf("minting against a moved relay: err=%v, want ErrStaleSignedPack", err)
	}
	// 3. Its cover host moved (L2): same.
	rotated := fullParams()
	rotated.CoverSNI = "another-cover.example.net"
	if _, _, err := RewriteProfilesForRecipient(sbp, rotated); !errors.Is(err, ErrStaleSignedPack) {
		t.Fatalf("minting against a rotated cover host: err=%v, want ErrStaleSignedPack", err)
	}
}
