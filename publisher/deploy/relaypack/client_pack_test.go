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

	rewritten, err := RewriteProfilesForRecipient(sbp, fullParams())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
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

func TestRewriteProfiles_FailsClosedOnUnserviceableFamily(t *testing.T) {
	// hysteria2 with no hy2 password → the whole rewrite must error,
	// never ship a route that can't connect.
	sbp := buildStubPack(t, []string{"hysteria2"})
	p := fullParams()
	p.Hy2Password = ""
	if _, err := RewriteProfilesForRecipient(sbp, p); err == nil {
		t.Fatal("expected rewrite to fail closed on missing hy2 password")
	}
}
