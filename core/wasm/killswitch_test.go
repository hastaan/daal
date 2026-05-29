//go:build !no_wasm

package wasm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

// memKV is a tiny in-memory SecretsKV used by the kill-switch
// tests; it skips the age-encryption layer the production
// routestore wraps PutSecret with — sufficient for verifier
// behaviour tests.
type memKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemKV() *memKV { return &memKV{m: map[string][]byte{}} }

func (k *memKV) PutSecret(key string, b []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = append([]byte(nil), b...)
	return nil
}

func (k *memKV) GetSecret(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), v...), nil
}

func (k *memKV) ListSecretKeys(prefix string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []string{}
	for kk := range k.m {
		if strings.HasPrefix(kk, prefix) {
			out = append(out, kk)
		}
	}
	return out, nil
}

func signEntry(t *testing.T, priv ed25519.PrivateKey, e KillSwitchEntry) KillSwitchEntry {
	t.Helper()
	payload := canonicalEntryBytes(e.Slug, e.SHA256Hex, e.Generation)
	sig := ed25519.Sign(priv, payload)
	e.SignatureB64 = base64.RawStdEncoding.EncodeToString(sig)
	return e
}

func mustGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestVerifyEntry_HappyPath — a freshly-signed entry verifies.
func TestVerifyEntry_HappyPath(t *testing.T) {
	pub, priv := mustGenKey(t)
	sha := strings.Repeat("a", 64)
	e := signEntry(t, priv, KillSwitchEntry{
		Slug: "evil-mod", SHA256Hex: sha, Generation: 1,
	})
	if err := VerifyEntry(pub, e); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
}

// TestVerifyEntry_BadSignatureRejected — flipping the signature
// fails ErrKillSwitchSignature.
func TestVerifyEntry_BadSignatureRejected(t *testing.T) {
	pub, priv := mustGenKey(t)
	sha := strings.Repeat("b", 64)
	e := signEntry(t, priv, KillSwitchEntry{
		Slug: "evil-mod", SHA256Hex: sha, Generation: 1,
	})
	// Flip a bit in the signature.
	raw, _ := base64.RawStdEncoding.DecodeString(e.SignatureB64)
	raw[0] ^= 0x80
	e.SignatureB64 = base64.RawStdEncoding.EncodeToString(raw)
	if err := VerifyEntry(pub, e); !errors.Is(err, ErrKillSwitchSignature) {
		t.Fatalf("got %v, want ErrKillSwitchSignature", err)
	}
}

// TestVerifyEntry_MalformedRejected — short sha256, missing
// slug, missing signature.
func TestVerifyEntry_MalformedRejected(t *testing.T) {
	pub, _ := mustGenKey(t)
	cases := []KillSwitchEntry{
		{Slug: "", SHA256Hex: strings.Repeat("a", 64), Generation: 1, SignatureB64: "AA"},
		{Slug: "x", SHA256Hex: "tooshort", Generation: 1, SignatureB64: "AA"},
		{Slug: "x", SHA256Hex: strings.Repeat("a", 64), Generation: 1, SignatureB64: "?!?!"},
	}
	for i, e := range cases {
		if err := VerifyEntry(pub, e); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// TestApply_NewKillsAreAppliedAndPersisted — happy-path apply
// inserts the (sha256) into both the loader's killed set and
// secrets_kv. Idempotent on re-apply.
func TestApply_NewKillsAreAppliedAndPersisted(t *testing.T) {
	pub, priv := mustGenKey(t)
	loader := NewLoader()
	kv := newMemKV()
	v := NewKillSwitchVerifier(pub, loader, kv)

	sha := strings.Repeat("c", 64)
	e := signEntry(t, priv, KillSwitchEntry{
		Slug: "first-kill", SHA256Hex: sha, Generation: 1,
	})
	newly, skipped, err := v.Apply([]KillSwitchEntry{e})
	if err != nil {
		t.Fatal(err)
	}
	if newly != 1 || skipped != 0 {
		t.Errorf("got newly=%d skipped=%d; want 1/0", newly, skipped)
	}
	if !loader.IsKilled(sha) {
		t.Error("loader missed the kill")
	}
	if _, err := kv.GetSecret("wasm_killed:" + sha); err != nil {
		t.Errorf("secrets_kv missed the kill: %v", err)
	}

	// Re-apply same entry: still in kv, generation does not
	// advance (already <= last), skipped++.
	newly, skipped, err = v.Apply([]KillSwitchEntry{e})
	if err != nil {
		t.Fatal(err)
	}
	if newly != 0 || skipped != 1 {
		t.Errorf("idempotent re-apply: got newly=%d skipped=%d; want 0/1", newly, skipped)
	}
}

// TestApply_GenerationMustIncrease — once generation N is
// applied, an entry at gen ≤ N is silently skipped.
func TestApply_GenerationMustIncrease(t *testing.T) {
	pub, priv := mustGenKey(t)
	loader := NewLoader()
	kv := newMemKV()
	v := NewKillSwitchVerifier(pub, loader, kv)

	shaA := strings.Repeat("d", 64)
	shaB := strings.Repeat("e", 64)
	eA := signEntry(t, priv, KillSwitchEntry{Slug: "a", SHA256Hex: shaA, Generation: 5})
	if _, _, err := v.Apply([]KillSwitchEntry{eA}); err != nil {
		t.Fatal(err)
	}
	// Lower generation entry — must skip.
	eB := signEntry(t, priv, KillSwitchEntry{Slug: "b", SHA256Hex: shaB, Generation: 2})
	newly, skipped, err := v.Apply([]KillSwitchEntry{eB})
	if err != nil {
		t.Fatal(err)
	}
	if newly != 0 || skipped != 1 {
		t.Errorf("got newly=%d skipped=%d; want 0/1", newly, skipped)
	}
	if loader.IsKilled(shaB) {
		t.Error("low-generation entry should not be applied")
	}
}

// TestPubkeyMissing — a verifier with no pubkey rejects all
// applies.
func TestPubkeyMissing(t *testing.T) {
	v := NewKillSwitchVerifier(nil, NewLoader(), newMemKV())
	_, _, err := v.Apply([]KillSwitchEntry{{Slug: "x", SHA256Hex: strings.Repeat("a", 64), Generation: 1, SignatureB64: "AA"}})
	if !errors.Is(err, ErrKillSwitchPubkeyMissing) {
		t.Fatalf("got %v, want ErrKillSwitchPubkeyMissing", err)
	}
	if v.PubkeyHex() != "" {
		t.Error("PubkeyHex must be empty when unconfigured")
	}
}

// TestPubkeyHex_Roundtrip — configured pubkey surfaces hex-
// encoded.
func TestPubkeyHex_Roundtrip(t *testing.T) {
	pub, _ := mustGenKey(t)
	v := NewKillSwitchVerifier(pub, NewLoader(), newMemKV())
	if got, want := v.PubkeyHex(), hex.EncodeToString(pub); got != want {
		t.Errorf("PubkeyHex = %q; want %q", got, want)
	}
}

// TestPublisherCanonicalPayload_RoundTrips — the canonical
// payload bytes are the exact bytes the publisher CLI signs
// (see `bundle-go/publisher.canonicalKillswitchPayload`).
// Locking the byte-for-byte equality here keeps the publisher
// and engine honest even though they live in separate go.mods.
func TestPublisherCanonicalPayload_RoundTrips(t *testing.T) {
	got := canonicalEntryBytes("evil-mod", strings.Repeat("a", 64), 7)
	want := `{"slug":"evil-mod","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":7}`
	if string(got) != want {
		t.Errorf("canonical payload drift:\n got %s\n want %s", got, want)
	}
}

// TestDaalteFromKV — a fresh verifier with a populated kv
// repopulates the loader's killed set on Daalte.
func TestDaalteFromKV(t *testing.T) {
	pub, _ := mustGenKey(t)
	kv := newMemKV()
	for _, sha := range []string{
		strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64),
	} {
		_ = kv.PutSecret("wasm_killed:"+sha, []byte("{}"))
	}
	_ = kv.PutSecret("wasm_killed:_generation", []byte("7"))

	loader := NewLoader()
	v := NewKillSwitchVerifier(pub, loader, kv)
	n, err := v.DaalteFromKV()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("daalted %d; want 3", n)
	}
	for _, sha := range []string{
		strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64),
	} {
		if !loader.IsKilled(sha) {
			t.Errorf("loader missed sha %s", sha[:8])
		}
	}
}
