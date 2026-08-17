package relaypack

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/freshness"
	"daal/publisher/deploy/provider"
)

func freshnessRecord(pub ed25519.PublicKey) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "12345",
		ServerType:      "cx22",
		Region:          "fsn1",
		ToolboxProfile:  "iran-default",
		PublisherPubKey: pub,
		Candidates: []provider.CandidateMeta{
			{
				Family:           "vless-reality",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:tcp443"},
				OriginRiskTags:   []string{},
			},
			{
				// RP014 requires >=2 vps-native candidates.
				Family:           "hysteria2",
				ExposureMode:     "direct_vps",
				FamilyClass:      "vps-native",
				ProbingRiskClass: "low",
				Port:             443,
				PublicRiskTags:   []string{"public_ip:5.75.0.1", "public_port:udp443"},
				OriginRiskTags:   []string{},
			},
		},
	}
}

func testMirrorSet(t *testing.T) *freshness.MirrorSet {
	t.Helper()
	set, err := freshness.NewMirrorSet([]freshness.Mirror{
		{Provider: freshness.ProviderR2, URL: "https://f.example.com/rp.json"},
		{Provider: freshness.ProviderGHPages, URL: "https://frp.github.io/f/rp.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func archiveEntry(t *testing.T, sbp []byte, name string) ([]byte, bool) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(sbp), int64(len(sbp)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return body, true
	}
	return nil, false
}

// The pack carries the SET, not just the scalar — and the set is
// verifiable against the same publisher key the pack was.
func TestBindAndSign_EmitsSignedMirrorSet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	res, err := BindAndSign(freshnessRecord(pub), priv, BindOpts{
		Now:       now,
		Phase:     relaypackvalidate.CurrentPhase,
		Freshness: testMirrorSet(t),
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}

	body, ok := archiveEntry(t, res.SBPBytes, freshness.MirrorsArchivePath)
	if !ok {
		t.Fatalf("%s missing from the signed pack", freshness.MirrorsArchivePath)
	}
	set, err := freshness.VerifyMirrors(body, pub, res.RelayPackID, now)
	if err != nil {
		t.Fatalf("mirror document does not verify: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("mirror count = %d", set.Len())
	}

	// The scalar slot is populated too, so a recipient build that
	// predates the mirror document still has an endpoint.
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Manifest.RelayPack.FreshnessURL == "" {
		t.Fatal("scalar freshness_url not populated")
	}

	// And the pack itself still verifies: the mirror document is
	// an extra archive entry, so it must not disturb the manifest
	// signature or require a spec_version bump.
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("pack with a mirror document must still verify: %v", err)
	}
	if parsed.Manifest.SpecVersion != 3 {
		t.Fatalf("spec_version moved to %d — that is a wire break for every "+
			"already-distributed recipient", parsed.Manifest.SpecVersion)
	}
}

// A pack can carry no freshness at all, but it can never carry a
// freshness path built on one host: the only way in is a
// MirrorSet, and a MirrorSet cannot be constructed with one
// member (see freshness.TestNewMirrorSet_RefusesSingleURL).
func TestBindAndSign_NoFreshnessLeavesSlotEmpty(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	res, err := BindAndSign(freshnessRecord(pub), priv, BindOpts{
		Now:   time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		Phase: relaypackvalidate.CurrentPhase,
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Manifest.RelayPack.FreshnessURL != "" {
		t.Fatalf("freshness_url = %q, want empty", parsed.Manifest.RelayPack.FreshnessURL)
	}
	if _, ok := archiveEntry(t, res.SBPBytes, freshness.MirrorsArchivePath); ok {
		t.Fatal("mirror document emitted without a mirror set")
	}
}

// The duplication of the RP021 shape rule inside freshness is
// only safe while the two agree. Bind every mirror through the
// REAL validator by putting it in the scalar slot: a URL the
// mirror validator accepts and RP021 rejects would produce a pack
// that fails to import on the recipient.
func TestMirrorURLsPassTheRealRP021Gate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set := testMirrorSet(t)
	for _, m := range set.Mirrors() {
		rec := freshnessRecord(pub)
		res, err := BindAndSign(rec, priv, BindOpts{
			Now:   time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
			Phase: relaypackvalidate.CurrentPhase,
			// One-off: bind each member as the scalar so RP021
			// itself judges it.
			Freshness: singleForTest(t, m),
		})
		if err != nil {
			t.Fatalf("mirror %s (%s) is rejected by the shared validator: %v", m.Provider, m.URL, err)
		}
		if len(res.SBPBytes) == 0 {
			t.Fatal("empty pack")
		}
	}
}

// singleForTest builds a two-member set whose lowest-sorting
// member is the one under test, so the scalar slot carries it.
func singleForTest(t *testing.T, m freshness.Mirror) *freshness.MirrorSet {
	t.Helper()
	other := freshness.Mirror{Provider: "zzz-filler", URL: "https://filler.example.net/z.json"}
	set, err := freshness.NewMirrorSet([]freshness.Mirror{m, other})
	if err != nil {
		t.Fatal(err)
	}
	if set.LegacyScalarURL() != m.URL {
		t.Fatalf("test helper: scalar is %q, want %q", set.LegacyScalarURL(), m.URL)
	}
	return set
}

// Determinism: the binder's contract is byte-identical output for
// identical inputs, and the mirror document is signed material
// inside that output.
func TestBindAndSign_MirrorSetIsDeterministic(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	opts := BindOpts{
		Now:       time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		Phase:     relaypackvalidate.CurrentPhase,
		Freshness: testMirrorSet(t),
	}
	a, err := BindAndSign(freshnessRecord(pub), priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BindAndSign(freshnessRecord(pub), priv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.SBPBytes, b.SBPBytes) {
		t.Fatal("BindAndSign is no longer deterministic with a mirror set")
	}
}

// ---- revocation -------------------------------------------------

// The one unset field that kept the whole revocation subsystem
// inert: ListPublishersWithRevocationURL filters on a non-empty
// revocation_url, and no Daal pack ever set one.
func TestBindAndSign_SetsRevocationURL(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	revPub, _, _ := ed25519.GenerateKey(rand.Reader)
	revPubHex := strings.ToLower(hexOf(revPub))

	res, err := BindAndSign(freshnessRecord(pub), priv, BindOpts{
		Now:              time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		Phase:            relaypackvalidate.CurrentPhase,
		RevocationURL:    "https://frp.example.com/revocation.json",
		RevocationPubHex: revPubHex,
	})
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Manifest.Publisher.RevocationURL != "https://frp.example.com/revocation.json" {
		t.Fatalf("revocation_url = %q", parsed.Manifest.Publisher.RevocationURL)
	}
	if parsed.Manifest.Publisher.RevocationFingerprintHex != revPubHex {
		t.Fatalf("revocation key = %q", parsed.Manifest.Publisher.RevocationFingerprintHex)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("pack must still verify: %v", err)
	}
}

// Half-configured revocation fails silently on the recipient (an
// audit row nobody reads), so it is refused at sign time.
func TestBindAndSign_RejectsHalfConfiguredRevocation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := BindOpts{
		Now:   time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		Phase: relaypackvalidate.CurrentPhase,
	}

	o := base
	o.RevocationURL = "https://frp.example.com/revocation.json"
	if _, err := BindAndSign(freshnessRecord(pub), priv, o); !errors.Is(err, ErrBadRevocationPub) {
		t.Fatalf("URL without key: want ErrBadRevocationPub, got %v", err)
	}

	o = base
	o.RevocationPubHex = strings.Repeat("ab", 32)
	if _, err := BindAndSign(freshnessRecord(pub), priv, o); !errors.Is(err, ErrBadRevocationPub) {
		t.Fatalf("key without URL: want ErrBadRevocationPub, got %v", err)
	}

	// A SHA-256 fingerprint is also 64 hex chars, so length alone
	// cannot catch the classic mistake — but a short or non-hex
	// value can and must be caught here rather than on a device.
	o = base
	o.RevocationURL = "https://frp.example.com/revocation.json"
	o.RevocationPubHex = "not-hex"
	if _, err := BindAndSign(freshnessRecord(pub), priv, o); !errors.Is(err, ErrBadRevocationPub) {
		t.Fatalf("non-hex key: want ErrBadRevocationPub, got %v", err)
	}

	o = base
	o.RevocationURL = "http://frp.example.com/revocation.json"
	o.RevocationPubHex = strings.Repeat("ab", 32)
	if _, err := BindAndSign(freshnessRecord(pub), priv, o); !errors.Is(err, ErrBadRevocationURL) {
		t.Fatalf("plaintext URL: want ErrBadRevocationURL, got %v", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
