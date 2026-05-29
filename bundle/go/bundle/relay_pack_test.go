package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// FRP-1: round-trip a bundle carrying both the bundle-level
// Manifest.RelayPack slot and a per-candidate _relaypack
// sub-object inside FamilySpecificConfig. The canonical
// bytes must be byte-identical across two consecutive
// CanonicalManifestJSON calls.
func TestRelayPackRoundTripCanonical(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 3
	m.RelayPack = &RelayPack{
		RelayPackID: "rp-test-001",
		SharedRiskGraph: []SharedRiskEdge{
			{Tag: "public_ip:5.75.0.1", Members: []string{"route-test"}},
			{Tag: "public_asn:24940", Members: []string{"route-test"}},
		},
	}
	// Inject the per-candidate _relaypack sub-object inside the
	// existing FamilySpecificConfig opaque blob.
	rpEntry := RelayPackEntry{
		ExposureMode:     "direct_vps",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		PublicRiskTags: []string{
			"public_ip:5.75.0.1",
			"public_asn:24940",
			"public_provider:hetzner",
			"public_dc:fsn1",
			"public_port:tcp443",
			"sni:www.microsoft.com",
		},
		OriginRiskTags: []string{},
	}
	familyConfig := map[string]any{
		"sni":        "www.microsoft.com",
		"_relaypack": rpEntry,
	}
	fcBytes, err := json.Marshal(familyConfig)
	if err != nil {
		t.Fatalf("marshal family config: %v", err)
	}
	m.Routes[0].FamilySpecificConfig = json.RawMessage(fcBytes)

	canon1, err := CanonicalManifestJSON(m)
	if err != nil {
		t.Fatalf("canonical 1: %v", err)
	}
	canon2, err := CanonicalManifestJSON(m)
	if err != nil {
		t.Fatalf("canonical 2: %v", err)
	}
	if !bytes.Equal(canon1, canon2) {
		t.Fatalf("canonical bytes not byte-identical across two calls")
	}
	// Sanity: the canonical output contains the new top-level slot
	// AND the _relaypack key inside the family blob.
	if !bytes.Contains(canon1, []byte(`"relay_pack":`)) {
		t.Fatalf("canonical output missing relay_pack slot: %s", canon1)
	}
	if !bytes.Contains(canon1, []byte(`"_relaypack":`)) {
		t.Fatalf("canonical output missing _relaypack sub-object: %s", canon1)
	}
}

// FRP-1: a sealed-and-parsed bundle round-trips the typed
// Manifest.RelayPack and the per-candidate _relaypack stays
// recoverable via ParseRelayPackEntry.
func TestRelayPackSignedBundleRoundTrip(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 3
	m.RelayPack = &RelayPack{
		RelayPackID: "rp-signed-001",
		SharedRiskGraph: []SharedRiskEdge{
			{Tag: "public_ip:5.75.0.1", Members: []string{"route-test"}},
		},
	}
	rpEntry := RelayPackEntry{
		ExposureMode:     "direct_vps",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:tcp443"},
		OriginRiskTags:   []string{},
	}
	fcBytes, err := json.Marshal(map[string]any{"_relaypack": rpEntry})
	if err != nil {
		t.Fatal(err)
	}
	m.Routes[0].FamilySpecificConfig = json.RawMessage(fcBytes)

	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Manifest.RelayPack == nil {
		t.Fatalf("expected Manifest.RelayPack to round-trip, got nil")
	}
	if b.Manifest.RelayPack.RelayPackID != "rp-signed-001" {
		t.Fatalf("RelayPackID did not round-trip: %q", b.Manifest.RelayPack.RelayPackID)
	}
	parsed, err := ParseRelayPackEntry(b.Manifest.Routes[0].FamilySpecificConfig)
	if err != nil {
		t.Fatalf("ParseRelayPackEntry: %v", err)
	}
	if parsed.ExposureMode != "direct_vps" {
		t.Fatalf("ExposureMode did not round-trip: %q", parsed.ExposureMode)
	}
	if len(parsed.PublicRiskTags) != 2 {
		t.Fatalf("expected 2 public risk tags, got %d", len(parsed.PublicRiskTags))
	}
}

// FRP-1: A spec_version=2 bundle that somehow carries
// Manifest.RelayPack must be rejected by VerifyBundle.
// (Defence-in-depth — the producer should have set v3.)
func TestRelayPackRequiresSpecV3(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 2
	m.RelayPack = &RelayPack{
		RelayPackID:     "rp-mismatch",
		SharedRiskGraph: []SharedRiskEdge{},
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.Publisher.KeyFingerprintHex = PublisherFingerprint(pub).Hex
	data, err := BuildSignedBundle(m,
		map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrUnsupportedSpec) {
		t.Fatalf("expected ErrUnsupportedSpec for spec_version=2 + RelayPack, got %v", err)
	}
}

// FRP-1: ParseRelayPackEntry returns ErrNoRelayPack for blobs
// that don't carry a _relaypack key.
func TestParseRelayPackEntryAbsent(t *testing.T) {
	cases := []json.RawMessage{
		nil,
		json.RawMessage(`{}`),
		json.RawMessage(`{"sni":"example.com"}`),
	}
	for i, c := range cases {
		_, err := ParseRelayPackEntry(c)
		if !errors.Is(err, ErrNoRelayPack) {
			t.Fatalf("case %d: expected ErrNoRelayPack, got %v", i, err)
		}
	}
}

// FRP-1: ParseRelayPackEntry parses a valid _relaypack sub-object.
func TestParseRelayPackEntryHappyPath(t *testing.T) {
	blob := json.RawMessage(`{
        "sni": "www.example.com",
        "_relaypack": {
            "exposure_mode":      "cdn_fronted",
            "family_class":       "vps-native",
            "probing_risk_class": "low",
            "public_risk_tags":   ["cdn:cloudflare", "public_domain:e.example.com"],
            "origin_risk_tags":   ["origin_ip:5.75.0.1", "origin_provider:hetzner"]
        }
    }`)
	entry, err := ParseRelayPackEntry(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.ExposureMode != "cdn_fronted" {
		t.Fatalf("ExposureMode: %q", entry.ExposureMode)
	}
	if len(entry.PublicRiskTags) != 2 || entry.PublicRiskTags[0] != "cdn:cloudflare" {
		t.Fatalf("PublicRiskTags: %+v", entry.PublicRiskTags)
	}
	if len(entry.OriginRiskTags) != 2 {
		t.Fatalf("OriginRiskTags: %+v", entry.OriginRiskTags)
	}
}

// FRP-1: ParseRelayPackEntry returns a typed JSON error if
// _relaypack is present but malformed.
func TestParseRelayPackEntryMalformed(t *testing.T) {
	blob := json.RawMessage(`{"_relaypack": "not-an-object"}`)
	_, err := ParseRelayPackEntry(blob)
	if err == nil {
		t.Fatalf("expected error for malformed _relaypack")
	}
	if errors.Is(err, ErrNoRelayPack) {
		t.Fatalf("malformed _relaypack should NOT return ErrNoRelayPack")
	}
}

// FRP-1: a non-RelayPack v3 bundle (no Manifest.RelayPack slot,
// no _relaypack inside FamilySpecificConfig) verifies cleanly.
// This is the future-proofing case: v3 producers can choose not
// to carry RelayPack metadata.
func TestSpecV3WithoutRelayPackVerifies(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 3
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Manifest.RelayPack != nil {
		t.Fatalf("expected RelayPack to be nil, got %+v", b.Manifest.RelayPack)
	}
}

// FRP-1: a v3 bundle's canonical output places the new
// "relay_pack" key in alphabetical order (between "publisher"
// and "rendezvous_hints"). Locks the canonical sort contract.
func TestRelayPackCanonicalKeyOrder(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.SpecVersion = 3
	m.RelayPack = &RelayPack{RelayPackID: "rp-order", SharedRiskGraph: []SharedRiskEdge{}}
	canon, err := CanonicalManifestJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(canon)
	pubIdx := strings.Index(s, `"publisher":`)
	rpIdx := strings.Index(s, `"relay_pack":`)
	routesIdx := strings.Index(s, `"routes":`)
	if pubIdx < 0 || rpIdx < 0 || routesIdx < 0 {
		t.Fatalf("missing keys in canonical: %s", s)
	}
	if !(pubIdx < rpIdx && rpIdx < routesIdx) {
		t.Fatalf("keys not alphabetically sorted: pub@%d rp@%d routes@%d in %s", pubIdx, rpIdx, routesIdx, s)
	}
}
