package publisher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

func writeManifest(t *testing.T, dir string, m bundle.Manifest) string {
	t.Helper()
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeProfile(t *testing.T, profilesDir, name, body string) {
	t.Helper()
	p := filepath.Join(profilesDir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func goodManifest(pub ed25519.PublicKey, now time.Time) bundle.Manifest {
	return bundle.Manifest{
		SpecVersion: 1,
		Publisher: bundle.PublisherInfo{
			Name:              "Test Publisher",
			KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "community",
		},
		Bundle: bundle.BundleInfo{
			ID:             "bundle-test",
			Type:           "provider",
			CreatedAt:      now.Format(time.RFC3339),
			ExpiresAt:      now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
			SupersedesKeys: []string{},
		},
		Routes: []bundle.RouteManifestEntry{{
			ID:              "route-test",
			ScarcityClass:   "normal",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/route-test.json",
			ValidFrom:       now.Format(time.RFC3339),
			ValidUntil:      now.Add(6 * 24 * time.Hour).Format(time.RFC3339),
		}},
	}
}

func TestBundleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPub(filepath.Join(dir, "publisher.pub"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)

	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{"type":"vless","tag":"r"}`)

	out := filepath.Join(dir, "out.sbp")
	res, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              out,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, err := os.Stat(res.OutPath); err != nil {
		t.Fatalf("output missing: %v", err)
	}

	// Verify round-trips.
	vres, err := Verify(VerifyOptions{Path: out})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vres.OK {
		t.Fatalf("verify did not return OK: %+v", vres)
	}
	if vres.RouteCount != 1 {
		t.Fatalf("route count = %d, want 1", vres.RouteCount)
	}
}

func TestBundleRefusesUnsignedNamedAsProduction(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	_, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              filepath.Join(dir, "out.sbp"),
		UnsafeUnsigned:   true,
		Now:              now,
	})
	if err == nil || !strings.Contains(err.Error(), "UNSIGNED.sbp") {
		t.Fatalf("expected UNSIGNED.sbp suffix enforcement, got %v", err)
	}
}

func TestBundleRejectsExpiredBundle(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	m.Bundle.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	_, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              filepath.Join(dir, "out.sbp"),
		Now:              now,
	})
	if err == nil || !strings.Contains(err.Error(), "must be in the future") {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}

func TestBundleLintBlocksUDPGatedNotMarked(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	m.Routes = []bundle.RouteManifestEntry{{
		ID: "r-h2", ScarcityClass: "normal", TransportFamily: "hysteria2",
		ConfigPath: "profiles/h2.json",
		ValidFrom:  now.Format(time.RFC3339),
		ValidUntil: now.Add(6 * 24 * time.Hour).Format(time.RFC3339),
		// UDPGated intentionally false.
	}}
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "h2.json", `{"type":"hysteria2"}`)

	_, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              filepath.Join(dir, "out.sbp"),
		Now:              now,
	})
	if err == nil || !strings.Contains(err.Error(), "UDP_GATED_NOT_MARKED") {
		t.Fatalf("expected UDP_GATED_NOT_MARKED block, got %v", err)
	}
}

func TestBundleFingerprintMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	m.Publisher.KeyFingerprintHex = strings.Repeat("a", 64)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	_, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              filepath.Join(dir, "out.sbp"),
		Now:              now,
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint does not match") {
		t.Fatalf("expected fingerprint-mismatch rejection, got %v", err)
	}
}

func TestBundleDeterministic(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	out1 := filepath.Join(dir, "a.sbp")
	out2 := filepath.Join(dir, "b.sbp")
	if _, err := Bundle(BundleOptions{
		ManifestPath: manifestPath, ProfilesDir: profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              out1, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Bundle(BundleOptions{
		ManifestPath: manifestPath, ProfilesDir: profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              out2, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(out1)
	b, _ := os.ReadFile(out2)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic byte at %d", i)
		}
	}
}

// TestBundleAppliesRedistributionPolicy — Phase 3F. The
// CLI-side --redistribution-policy / --delegate-cap pair is
// stamped onto every route at manifest-load time, then
// round-trips through ParseSBP / VerifyBundle.
func TestBundleAppliesRedistributionPolicy(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	out := filepath.Join(dir, "out.sbp")
	if _, err := Bundle(BundleOptions{
		ManifestPath: manifestPath, ProfilesDir: profilesDir,
		SigningPrivPath:      filepath.Join(dir, "publisher.priv"),
		PublisherPubPath:     filepath.Join(dir, "publisher.pub"),
		Out:                  out,
		RedistributionPolicy: "delegated_n",
		RedistributionCap:    7,
		Now:                  now,
	}); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	body, _ := os.ReadFile(out)
	parsed, err := bundle.ParseSBP(strings.NewReader(string(body)), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := parsed.Manifest.Routes[0].RedistributionPolicy; got != "delegated_n" {
		t.Errorf("policy: %q", got)
	}
	if got := parsed.Manifest.Routes[0].RedistributionCap; got != 7 {
		t.Errorf("cap: %d", got)
	}
}

// TestBundleRejectsBadRedistributionPolicy — invalid policy or
// missing/extra cap must be rejected at the publisher CLI
// layer (not just downstream).
func TestBundleRejectsBadRedistributionPolicy(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	cases := []struct {
		policy string
		cap    uint8
	}{
		{"yolo", 0},
		{"delegated_n", 0}, // missing cap
		{"none", 5},        // cap with non-delegated_n
		{"transitive", 1},  // cap with non-delegated_n
	}
	for _, c := range cases {
		_, err := Bundle(BundleOptions{
			ManifestPath: manifestPath, ProfilesDir: profilesDir,
			SigningPrivPath:      filepath.Join(dir, "publisher.priv"),
			PublisherPubPath:     filepath.Join(dir, "publisher.pub"),
			Out:                  filepath.Join(dir, "x.sbp"),
			RedistributionPolicy: c.policy,
			RedistributionCap:    c.cap,
			Now:                  now,
		})
		if err == nil {
			t.Errorf("policy=%q cap=%d: expected error, got nil", c.policy, c.cap)
		}
	}
}

// FRP-7.5: Bundle signs with a sub-key when SigningPrivPath
// points at a sub-key whose sibling subkey.cert is on disk.
// The resulting .sbp carries trust/subkey-cert.json, has
// spec_version forced to ≥ 4, and self-verifies.
func TestBundleSubkeySignSucceedsAndSelfVerifies(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPub(filepath.Join(dir, "publisher.pub"))
	if err != nil {
		t.Fatal(err)
	}
	// Mint a sub-key under dir/subkeys/<fp>/.
	sub, err := Subkey(SubkeyOptions{
		RootPrivPath: filepath.Join(dir, "publisher.priv"),
		OutDir:       dir,
		Validity:     90 * 24 * time.Hour,
		Label:        "test-subkey",
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{"type":"vless"}`)

	out := filepath.Join(dir, "subkey-out.sbp")
	res, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  sub.SubkeyPrivPath,
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              out,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("sub-key bundle: %v", err)
	}
	if res.OutPath != out {
		t.Fatalf("OutPath = %q, want %q", res.OutPath, out)
	}
	// Verify round-trips through the chain branch.
	vres, err := Verify(VerifyOptions{Path: out})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vres.OK {
		t.Fatalf("sub-key verify not OK: %+v", vres)
	}
	// Confirm the output carries trust/subkey-cert.json and
	// SpecVersion=4.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.SubkeyCertJSON) == 0 {
		t.Fatal("sub-key bundle missing trust/subkey-cert.json")
	}
	if parsed.Manifest.SpecVersion < 4 {
		t.Fatalf("sub-key bundle spec_version = %d, want ≥ 4", parsed.Manifest.SpecVersion)
	}
}

// FRP-7.5: Bundle errors clearly when the operator points
// SigningPrivPath at a sub-key but the sibling subkey.cert is
// missing. Pre-FRP-7.5 this was a "staged for a later phase"
// hard reject; post-FRP-7.5 it is a "cert not found" error.
func TestBundleSubkeySignMissingCertFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	// Generate an ad-hoc sub-key that has NO subkey.cert sibling.
	subPub, subPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = subPub
	subPrivPath := filepath.Join(dir, "rogue-subkey.priv")
	if err := os.WriteFile(subPrivPath, subPriv, 0o600); err != nil {
		t.Fatal(err)
	}

	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	_, err = Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  subPrivPath,
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              filepath.Join(dir, "should-fail.sbp"),
		Now:              now,
	})
	if err == nil || !strings.Contains(err.Error(), "subkey.cert") {
		t.Fatalf("expected missing-cert error, got %v", err)
	}
}

// FRP-7.5: Root-key signing path still works (regression guard).
func TestBundleRootKeySigningStillWorks(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	now := time.Now().UTC()
	m := goodManifest(pub, now)
	manifestPath := writeManifest(t, dir, m)
	profilesDir := filepath.Join(dir, "profiles")
	writeProfile(t, profilesDir, "route-test.json", `{}`)

	out := filepath.Join(dir, "root-signed.sbp")
	if _, err := Bundle(BundleOptions{
		ManifestPath:     manifestPath,
		ProfilesDir:      profilesDir,
		SigningPrivPath:  filepath.Join(dir, "publisher.priv"),
		PublisherPubPath: filepath.Join(dir, "publisher.pub"),
		Out:              out,
		Now:              now,
	}); err != nil {
		t.Fatalf("root sign: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.SubkeyCertJSON) != 0 {
		t.Fatal("root-signed bundle should NOT carry trust/subkey-cert.json")
	}
}
