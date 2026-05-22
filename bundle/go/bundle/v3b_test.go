package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Phase 3B bundle-format widening tests. See
// specs/sbp-v1.md "Phase 3B widening" and
// specs/rendezvous-channels-v1.md.

func TestSBPv1_RendezvousPriorityKnownChannelsAccepted(t *testing.T) {
	m := baseManifest(t, "experimental", "snowflake", time.Now().Add(24*time.Hour))
	m.Routes[0].RendezvousPriority = []string{
		"sqs", "domain_fronted_broker", "amp_cache", "offline_hint",
	}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := len(b.Manifest.Routes[0].RendezvousPriority); got != 4 {
		t.Errorf("priority round-trip: got %d entries", got)
	}
}

func TestSBPv1_RendezvousPriorityRejectsUnknown(t *testing.T) {
	m := baseManifest(t, "experimental", "snowflake", time.Now().Add(24*time.Hour))
	m.Routes[0].RendezvousPriority = []string{"sqs", "telepathy"}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrInvalidRendezvousChannel) {
		t.Fatalf("got %v, want ErrInvalidRendezvousChannel", err)
	}
}

func TestSBPv1_RendezvousPriorityEmptyOrAbsentAccepted(t *testing.T) {
	// Absent: route has no `rendezvous_priority` key at all.
	m := baseManifest(t, "experimental", "snowflake", time.Now().Add(24*time.Hour))
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Errorf("absent: %v", err)
	}
	// Empty array: explicit "use engine default."
	m.Routes[0].RendezvousPriority = []string{}
	data = mustSignedBundle(t, m, nil)
	b, _ = ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err := VerifyBundle(b); err != nil {
		t.Errorf("empty array: %v", err)
	}
}

// TestSBPv1_RendezvousHintsSignedRoundTrip — top-level
// rendezvous_hints[] verifies under the publisher's signing key.
func TestSBPv1_RendezvousHintsSignedRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := baseManifestWithKey(t, pub, "experimental", "snowflake", time.Now().Add(24*time.Hour))

	hint := json.RawMessage(`{"bridge":"203.0.113.5:443","fp":"deadbeef","not_after":"2026-12-01T00:00:00Z"}`)
	sig := ed25519.Sign(priv, hint)
	m.RendezvousHints = []RendezvousHint{{
		Payload:   hint,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}}

	data, err := BuildSignedBundle(m, map[string][]byte{
		"profiles/route.json": []byte(`{"type":"direct"}`),
	}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(b.Manifest.RendezvousHints) != 1 {
		t.Errorf("hint round-trip: got %d entries", len(b.Manifest.RendezvousHints))
	}
}

// TestSBPv1_RendezvousHintsBadSignatureRejected — a hint signed
// by an attacker key is rejected.
func TestSBPv1_RendezvousHintsBadSignatureRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	m := baseManifestWithKey(t, pub, "experimental", "snowflake", time.Now().Add(24*time.Hour))

	hint := json.RawMessage(`{"bridge":"x"}`)
	sig := ed25519.Sign(attacker, hint) // wrong key
	m.RendezvousHints = []RendezvousHint{{
		Payload:   hint,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}}

	data, _ := BuildSignedBundle(m, map[string][]byte{
		"profiles/route.json": []byte(`{"type":"direct"}`),
	}, pub, priv)
	b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err := VerifyBundle(b); !errors.Is(err, ErrRendezvousHintBadSignature) {
		t.Fatalf("got %v, want ErrRendezvousHintBadSignature", err)
	}
}

// TestSBPv1_RendezvousHintsMalformedRejected — empty signature
// or non-base64 signature → ErrRendezvousHintMalformed.
func TestSBPv1_RendezvousHintsMalformedRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := baseManifestWithKey(t, pub, "experimental", "snowflake", time.Now().Add(24*time.Hour))

	// Empty signature.
	m.RendezvousHints = []RendezvousHint{{Payload: json.RawMessage(`{"x":1}`), Signature: ""}}
	data, _ := BuildSignedBundle(m, map[string][]byte{
		"profiles/route.json": []byte(`{"type":"direct"}`),
	}, pub, priv)
	b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err := VerifyBundle(b); !errors.Is(err, ErrRendezvousHintMalformed) {
		t.Fatalf("got %v, want ErrRendezvousHintMalformed (empty signature)", err)
	}

	// Non-base64 signature.
	m.RendezvousHints = []RendezvousHint{{Payload: json.RawMessage(`{"x":1}`), Signature: "!!!not-base64!!!"}}
	data, _ = BuildSignedBundle(m, map[string][]byte{
		"profiles/route.json": []byte(`{"type":"direct"}`),
	}, pub, priv)
	b, _ = ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err := VerifyBundle(b); !errors.Is(err, ErrRendezvousHintMalformed) {
		t.Fatalf("got %v, want ErrRendezvousHintMalformed (non-base64 signature)", err)
	}
}

// TestRendezvousChannelV1ListMatchesEngine — the bundle-internal
// closed list must match the engine's KnownChannels list. The
// two packages do not import each other (separate go.mod), so a
// drift would silently allow the parser and the Selector to
// disagree. The list is pinned by literal here.
func TestRendezvousChannelV1ListMatchesEngine(t *testing.T) {
	want := []string{
		"amp_cache", "domain_fronted_broker", "offline_hint",
		"push", "sqs",
	}
	got := make([]string, 0, len(rendezvousChannelV1))
	for k := range rendezvousChannelV1 {
		got = append(got, k)
	}
	// Sort for stable compare.
	stringsSort(got)
	stringsSort(want)
	if len(got) != len(want) {
		t.Fatalf("v1 channel-list length: got %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("v1 channel %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func stringsSort(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
