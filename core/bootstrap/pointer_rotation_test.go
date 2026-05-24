package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"daal/core/routestore"
)

func mustStore(t *testing.T) *routestore.Store {
	t.Helper()
	st, err := routestore.Open(filepath.Join(t.TempDir(), "rs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustSignedPointerSet(t *testing.T, priv ed25519.PrivateKey, set string,
	validUntil time.Time, urls ...string) PointerSet {
	t.Helper()
	ps := PointerSet{
		V: 1, Kind: "bootstrap_pointers", Set: set,
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		ValidUntil: validUntil.UTC().Format(time.RFC3339),
	}
	for _, u := range urls {
		ps.Pointers = append(ps.Pointers, Pointer{
			URL: u, ExpectedPublisherFingerprintHex: "0000000000000000000000000000000000000000000000000000000000000000",
		})
	}
	signed, err := SignPointerSet(ps, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestPersistPointerRotationAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	embedded := &Manifest{
		PrimaryPointers:  mustSignedPointerSet(t, priv, "primary", now.Add(7*24*time.Hour), "https://embed.invalid/dir.sbp"),
		FallbackPointers: mustSignedPointerSet(t, priv, "fallback", now.Add(7*24*time.Hour), "https://embed.invalid/dir2.sbp"),
	}
	rot := PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary:  mustSignedPointerSet(t, priv, "primary", now.Add(60*24*time.Hour), "https://newer.invalid/dir.sbp"),
		Fallback: mustSignedPointerSet(t, priv, "fallback", now.Add(60*24*time.Hour), "https://newer.invalid/dir2.sbp"),
	}
	store := mustStore(t)
	wrote, err := PersistPointerRotation(store, rot, pub, embedded, now)
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected persist to write a fresh rotation")
	}
	persisted, _ := LoadPersistedPointers(store)
	if persisted.Primary.Pointers[0].URL != "https://newer.invalid/dir.sbp" {
		t.Fatalf("primary not picked up: %+v", persisted.Primary)
	}
}

func TestPersistPointerRotationTamperedDropped(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	embedded := &Manifest{
		PrimaryPointers:  mustSignedPointerSet(t, priv, "primary", now.Add(7*24*time.Hour), "https://embed.invalid/dir.sbp"),
		FallbackPointers: mustSignedPointerSet(t, priv, "fallback", now.Add(7*24*time.Hour), "https://embed.invalid/dir2.sbp"),
	}
	rot := PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary: mustSignedPointerSet(t, priv, "primary", now.Add(60*24*time.Hour), "https://newer.invalid/dir.sbp"),
	}
	last := len(rot.Primary.SignatureHex) - 1
	if rot.Primary.SignatureHex[last] == '0' {
		rot.Primary.SignatureHex = rot.Primary.SignatureHex[:last] + "1"
	} else {
		rot.Primary.SignatureHex = rot.Primary.SignatureHex[:last] + "0"
	}

	store := mustStore(t)
	wrote, err := PersistPointerRotation(store, rot, pub, embedded, now)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("tampered rotation must NOT be persisted")
	}
	if _, err := store.GetSecret(PersistKey); err == nil {
		t.Fatal("secrets_kv must remain empty after tampered rotation")
	}
	_ = otherPub
}

func TestPersistPointerRotationOlderIgnored(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	embedded := &Manifest{
		PrimaryPointers:  mustSignedPointerSet(t, priv, "primary", now.Add(60*24*time.Hour), "https://embed.invalid/dir.sbp"),
		FallbackPointers: mustSignedPointerSet(t, priv, "fallback", now.Add(60*24*time.Hour), "https://embed.invalid/dir2.sbp"),
	}
	rot := PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary: mustSignedPointerSet(t, priv, "primary", now.Add(7*24*time.Hour), "https://older.invalid/dir.sbp"),
	}
	store := mustStore(t)
	wrote, err := PersistPointerRotation(store, rot, pub, embedded, now)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("older rotation must NOT replace newer embedded")
	}
}

func TestOverlayPersistedOntoManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	embedded := &Manifest{
		PrimaryPointers:  mustSignedPointerSet(t, priv, "primary", now.Add(7*24*time.Hour), "https://embed.invalid/dir.sbp"),
		FallbackPointers: mustSignedPointerSet(t, priv, "fallback", now.Add(7*24*time.Hour), "https://embed.invalid/dir2.sbp"),
	}
	rot := PointerRotation{
		V: 1, Kind: "pointer_rotation",
		Primary: mustSignedPointerSet(t, priv, "primary", now.Add(60*24*time.Hour), "https://newer.invalid/dir.sbp"),
	}
	store := mustStore(t)
	if _, err := PersistPointerRotation(store, rot, pub, embedded, now); err != nil {
		t.Fatal(err)
	}
	OverlayPersistedOntoManifest(store, embedded)
	if embedded.PrimaryPointers.Pointers[0].URL != "https://newer.invalid/dir.sbp" {
		t.Fatalf("overlay did not apply to primary: %+v", embedded.PrimaryPointers)
	}
	if embedded.FallbackPointers.Pointers[0].URL != "https://embed.invalid/dir2.sbp" {
		t.Fatalf("fallback was overwritten unexpectedly: %+v", embedded.FallbackPointers)
	}
}
