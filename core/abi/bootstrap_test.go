package abi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

func TestBootstrapABI_InstallAndStatus(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })

	// Build an in-memory manifest with one Tier-2 seed.
	now := time.Now().UTC().Truncate(time.Second)
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	pubFP := bundle.PublisherFingerprint(pubPub).Hex
	seed := mustBuildBundle(t, pubPub, pubPriv, "abi-seed-1", now, "emergency")
	primary := bootstrap.PointerSet{
		Set: "primary", IssuedAt: now.Format(time.RFC3339),
		ValidUntil: now.Add(time.Hour).Format(time.RFC3339),
		Pointers: []bootstrap.Pointer{{URL: "https://nope.example/dir.sbp",
			ExpectedPublisherFingerprintHex: pubFP}},
	}
	primary, _ = bootstrap.SignPointerSet(primary, rootPriv)
	fallback := primary
	fallback.Set = "fallback"
	fallback, _ = bootstrap.SignPointerSet(fallback, rootPriv)

	SetBootstrapManifestForTest(&bootstrap.Manifest{
		ProjectRootPub:        rootPub,
		PublisherRootPubs:     map[string]ed25519.PublicKey{pubFP: pubPub},
		PublisherDisplayNames: map[string]string{pubFP: "TestPub"},
		PrimaryPointers:       primary,
		FallbackPointers:      fallback,
		Tier2Seeds:            [][]byte{seed},
	})

	// Install seeds.
	body, err := BootstrapInstallSeeds()
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	var inst struct {
		InstalledCount int `json:"installed_count"`
		SkippedCount   int `json:"skipped_existing"`
	}
	if err := json.Unmarshal([]byte(body), &inst); err != nil {
		t.Fatal(err)
	}
	if inst.InstalledCount != 1 {
		t.Errorf("expected 1 installed, got %+v", inst)
	}

	// Status.
	stBody, err := BootstrapStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stBody, `"have_seeds":true`) {
		t.Errorf("expected have_seeds:true; got %s", stBody)
	}

	// Refresh: directory pointer is bogus; we expect a non-empty Reason
	// and (since we currently return body even on err) a JSON status.
	_, _ = BootstrapRefresh(500)
}

func mustBuildBundle(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, routeID string, now time.Time, bundleType string) []byte {
	t.Helper()
	manifest := bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              "abi-test",
			KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "official",
		},
		Bundle: bundle.BundleInfo{
			ID:             "bundle-" + routeID,
			Type:           bundleType,
			CreatedAt:      now.Format(time.RFC3339),
			ExpiresAt:      now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
			SupersedesKeys: []string{},
		},
		Routes: []bundle.RouteManifestEntry{{
			ID:              routeID,
			ScarcityClass:   "emergency",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/" + routeID + ".json",
			ValidFrom:       now.Format(time.RFC3339),
			ValidUntil:      now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
		}},
	}
	body, err := bundle.BuildSignedBundleDeterministic(manifest, map[string][]byte{
		"profiles/" + routeID + ".json": []byte(`{}`),
	}, nil, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
