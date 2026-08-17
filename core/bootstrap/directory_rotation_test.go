package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// The pointer layer is what the freshness path falls through to when
// every mirror in a pack is blocked. These tests pin the two halves it
// needs and never had a caller for: reading a rotation envelope out of
// a fetched directory, and preferring the persisted (rotated) pointers
// on the next fetch.

func makeDirectoryWithRotation(t *testing.T, signerPub ed25519.PublicKey,
	signerPriv ed25519.PrivateKey, rot *PointerRotation, now time.Time) []byte {
	t.Helper()
	manifest := bundle.Manifest{
		SpecVersion: 2,
		Publisher: bundle.PublisherInfo{
			Name:              "tier-1",
			KeyFingerprintHex: bundle.PublisherFingerprint(signerPub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "official",
		},
		Bundle: bundle.BundleInfo{
			ID:        "dir-1",
			Type:      "directory",
			CreatedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
		},
		Routes: []bundle.RouteManifestEntry{{
			ID:              "dir-route-1",
			ScarcityClass:   "emergency",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/dir-route-1.json",
			ValidFrom:       now.Format(time.RFC3339),
			ValidUntil:      now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
		}},
	}
	extras := map[string][]byte{}
	if rot != nil {
		manifest.Bundle.PointerRotation = &bundle.PointerRotationRef{Path: "trust/pointer-rotation.json"}
		body, err := json.Marshal(rot)
		if err != nil {
			t.Fatal(err)
		}
		extras["trust/pointer-rotation.json"] = body
	}
	out, err := bundle.BuildSignedBundleDeterministic(manifest,
		map[string][]byte{"profiles/dir-route-1.json": []byte(`{}`)}, extras, signerPub, signerPriv)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExtractPointerRotation_ReadsTheEnvelope(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	rot := &PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary: mustSignedPointerSet(t, rootPriv, "primary",
			now.Add(60*24*time.Hour), "https://rotated.invalid/dir.sbp"),
	}
	body := makeDirectoryWithRotation(t, pubPub, pubPriv, rot, now)

	parsed, err := bundle.ParseSBP(bytesReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ExtractPointerRotation(body, parsed.Manifest)
	if !ok {
		t.Fatal("the envelope was not found")
	}
	if len(got.Primary.Pointers) != 1 || got.Primary.Pointers[0].URL != "https://rotated.invalid/dir.sbp" {
		t.Fatalf("wrong envelope: %+v", got)
	}

	// A directory with no ref yields nothing, and that is not an error.
	plain := makeDirectoryWithRotation(t, pubPub, pubPriv, nil, now)
	parsedPlain, _ := bundle.ParseSBP(bytesReader(plain), int64(len(plain)))
	if _, ok := ExtractPointerRotation(plain, parsedPlain.Manifest); ok {
		t.Fatal("a directory with no rotation ref produced one")
	}
}

// The path comes out of the same archive we do not trust, so it is
// input. Traversal, absolute paths and anything outside trust/ are
// refused before the zip is even read.
func TestArchiveEntry_RefusesUnsafePaths(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := makeDirectoryWithRotation(t, pubPub, pubPriv, nil, time.Now().UTC())
	for _, bad := range []string{
		"", "/etc/passwd", "../secrets", "trust/../../x",
		"profiles/route.json", "trust/", "manifest.json",
	} {
		if _, ok := ArchiveEntry(body, bad); ok {
			t.Errorf("unsafe path %q was read", bad)
		}
	}
}

// A tampered envelope is a silent no-op, never a downgrade: the inner
// sets carry their own project-root signatures and the persist step
// refuses anything that does not extend the window already held.
func TestApplyDirectoryPointerRotation_TamperedIsDropped(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()

	embedded := &Manifest{
		ProjectRootPub:   rootPub,
		PrimaryPointers:  mustSignedPointerSet(t, rootPriv, "primary", now.Add(7*24*time.Hour), "https://embed.invalid/a"),
		FallbackPointers: mustSignedPointerSet(t, rootPriv, "fallback", now.Add(7*24*time.Hour), "https://embed.invalid/b"),
	}
	// Signed by an attacker's key, not the project root.
	rot := &PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary: mustSignedPointerSet(t, attackerPriv, "primary",
			now.Add(60*24*time.Hour), "https://attacker.invalid/dir.sbp"),
	}
	body := makeDirectoryWithRotation(t, pubPub, pubPriv, rot, now)
	parsed, _ := bundle.ParseSBP(bytesReader(body), int64(len(body)))

	store := mustStore(t)
	wrote, err := ApplyDirectoryPointerRotation(store, body, parsed.Manifest, embedded, now)
	if err != nil {
		t.Fatalf("a tampered envelope must be a silent no-op, got %v", err)
	}
	if wrote {
		t.Fatal("a tampered envelope was persisted")
	}
	primary, _ := EffectivePointerSets(store, embedded)
	if primary.Pointers[0].URL != "https://embed.invalid/a" {
		t.Fatalf("the embedded pointer was replaced: %+v", primary)
	}
}

func TestApplyDirectoryPointerRotation_ValidEnvelopeWins(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()

	embedded := &Manifest{
		ProjectRootPub:   rootPub,
		PrimaryPointers:  mustSignedPointerSet(t, rootPriv, "primary", now.Add(7*24*time.Hour), "https://embed.invalid/a"),
		FallbackPointers: mustSignedPointerSet(t, rootPriv, "fallback", now.Add(7*24*time.Hour), "https://embed.invalid/b"),
	}
	rot := &PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary: mustSignedPointerSet(t, rootPriv, "primary",
			now.Add(60*24*time.Hour), "https://rotated.invalid/dir.sbp"),
	}
	body := makeDirectoryWithRotation(t, pubPub, pubPriv, rot, now)
	parsed, _ := bundle.ParseSBP(bytesReader(body), int64(len(body)))

	store := mustStore(t)
	wrote, err := ApplyDirectoryPointerRotation(store, body, parsed.Manifest, embedded, now)
	if err != nil || !wrote {
		t.Fatalf("valid envelope not persisted: wrote=%v err=%v", wrote, err)
	}
	// THE POINT: the next fetch must use the rotated pointer, without
	// mutating the shared manifest (which another goroutine renders).
	primary, fallback := EffectivePointerSets(store, embedded)
	if primary.Pointers[0].URL != "https://rotated.invalid/dir.sbp" {
		t.Fatalf("rotation did not take effect: %+v", primary)
	}
	if fallback.Pointers[0].URL != "https://embed.invalid/b" {
		t.Fatal("the untouched fallback set was replaced")
	}
	if embedded.PrimaryPointers.Pointers[0].URL != "https://embed.invalid/a" {
		t.Fatal("EffectivePointerSets mutated the shared manifest")
	}
}

// An expired embedded set plus a live persisted rotation must still
// produce a fetch. This is the device the recovery layer exists for: a
// build old enough that its baked-in pointers have lapsed.
func TestEffectivePointerSets_RescuesAnExpiredEmbeddedSet(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	embedded := &Manifest{
		ProjectRootPub:   rootPub,
		PrimaryPointers:  mustSignedPointerSet(t, rootPriv, "primary", now.Add(-time.Hour), "https://stale.invalid/a"),
		FallbackPointers: mustSignedPointerSet(t, rootPriv, "fallback", now.Add(-time.Hour), "https://stale.invalid/b"),
	}
	store := mustStore(t)
	rot := PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary:  mustSignedPointerSet(t, rootPriv, "primary", now.Add(30*24*time.Hour), "https://live.invalid/a"),
		Fallback: mustSignedPointerSet(t, rootPriv, "fallback", now.Add(30*24*time.Hour), "https://live.invalid/b"),
	}
	if _, err := PersistPointerRotation(store, rot, rootPub, embedded, now); err != nil {
		t.Fatal(err)
	}
	primary, fallback := EffectivePointerSets(store, embedded)
	if err := VerifyPointerSet(primary, rootPub, now); err != nil {
		t.Fatalf("primary still expired: %v", err)
	}
	if err := VerifyPointerSet(fallback, rootPub, now); err != nil {
		t.Fatalf("fallback still expired: %v", err)
	}
}
