package relaypack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// buildStubPack builds a signed operator .sbp with metadata-stub
// profiles (the pre-Tier-2 shape) for the given families.
func buildStubPack(t *testing.T, families []string) []byte {
	t.Helper()
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
		routes = append(routes, bundle.RouteManifestEntry{
			ID:              id,
			ScarcityClass:   "normal",
			TransportFamily: fam,
			ConfigPath:      cp,
			ValidFrom:       from,
			ValidUntil:      until,
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
