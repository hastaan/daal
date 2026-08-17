package relaypack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	bundlepublisher "daal/bundle-go/publisher"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/provider"
)

// fixedKey returns a deterministic Ed25519 keypair seeded by a
// fixed byte (for reproducible tests). The pub bytes are returned
// alongside so tests can stamp them on OperatorRecord.PublisherPubKey.
func fixedKey(t *testing.T, seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// minimalRec is a two-candidate record that satisfies the FRP-1
// validator at PhaseV15 (RP014 requires ≥2 vps-native candidates).
func minimalRec(t *testing.T) *provider.OperatorRecord {
	t.Helper()
	pub, _ := fixedKey(t, 0x42)
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "12345",
		Region:          "fsn1",
		ServerType:      "cx22",
		PublicIP:        net.ParseIP("5.75.0.1"),
		ToolboxProfile:  "iran-default",
		PublisherPubKey: append([]byte(nil), pub...),
		Candidates: []provider.CandidateMeta{
			{
				Family: "vless-reality", ExposureMode: "direct_vps",
				FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 443,
				PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:tcp443"},
				OriginRiskTags: []string{},
			},
			{
				Family: "hysteria2", ExposureMode: "direct_vps",
				FamilyClass: "vps-native", ProbingRiskClass: "low", Port: 443,
				PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:udp443"},
				OriginRiskTags: []string{},
			},
		},
		ProvisionedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
}

// testBindNow anchors every BindAndSign fixture to this run's clock,
// once, so a binary's two builds of the same bundle stay byte-identical
// while the manifest it signs is never already expired.
//
// It used to be a hard-coded `2026-05-01` with a 30-day expiry, which
// made every signature test a time bomb: from 2026-05-31 onwards
// `bundle.VerifyBundle` — which checks the manifest against the real
// `time.Now()` — failed with "bundle expired" in five tests at once,
// and the failure said nothing about the code under test.
var testBindNow = time.Now().UTC().Add(-time.Hour)

func defaultOpts() BindOpts {
	return BindOpts{
		Now:    testBindNow,
		Expiry: 30 * 24 * time.Hour,
		Phase:  relaypackvalidate.PhaseV15,
	}
}

func subkeyForRoot(t *testing.T, rootPriv ed25519.PrivateKey) (ed25519.PrivateKey, []byte) {
	t.Helper()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "publisher.priv")
	if err := os.WriteFile(rootPath, rootPriv, 0o600); err != nil {
		t.Fatal(err)
	}
	art, err := bundlepublisher.Subkey(bundlepublisher.SubkeyOptions{
		RootPrivPath: rootPath,
		OutDir:       dir,
		Validity:     90 * 24 * time.Hour,
		Label:        "binder-test-subkey",
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(art.SubkeyCertPath)
	if err != nil {
		t.Fatal(err)
	}
	return art.SubkeyPrivBytes, cert
}

// (1) Same inputs -> byte-identical output.
func TestBindAndSign_DeterministicRoundTrip(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	a, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign(1): %v", err)
	}
	b, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign(2): %v", err)
	}
	if !bytes.Equal(a.SBPBytes, b.SBPBytes) {
		t.Fatalf("non-deterministic output: %d vs %d bytes",
			len(a.SBPBytes), len(b.SBPBytes))
	}
	if a.BundleSHA256 != b.BundleSHA256 {
		t.Fatalf("sha256 differs: %s vs %s", a.BundleSHA256, b.BundleSHA256)
	}
	if a.RelayPackID != b.RelayPackID {
		t.Fatalf("relay_pack_id differs")
	}
}

// (2) Validator hard-error halts bind. We force RP013 by passing
// PostV2 first to construct, then we engineer a record with a
// modifier-like shape that PhaseV15 rejects: easiest way is a
// single candidate (RP014), since BindAndSign should refuse to
// emit an .sbp on validator error.
func TestBindAndSign_HaltsOnValidatorError(t *testing.T) {
	rec := minimalRec(t)
	rec.Candidates = rec.Candidates[:1] // RP014: <2 vps-native candidates
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err == nil {
		t.Fatalf("expected validator error, got result %+v", res)
	}
	if res != nil {
		t.Fatalf("BindResult must be nil on validator error")
	}
	if !contains(err.Error(), "RP014") {
		t.Fatalf("error should mention RP014, got %v", err)
	}
}

// (3) Lint warning RP019 (no public-surface diversity) is propagated
// in BindResult.LintReport but does NOT halt the bind. We engineer
// it by giving every candidate identical public_risk_tags.
func TestBindAndSign_LintWarningPropagated(t *testing.T) {
	rec := minimalRec(t)
	// Make all candidates share every public_risk_tag.
	sharedTags := []string{"public_ip:5.75.0.1", "public_port:tcp443", "public_provider:hetzner"}
	for i := range rec.Candidates {
		rec.Candidates[i].PublicRiskTags = sharedTags
	}
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign should not error on lint-warn: %v", err)
	}
	foundRP019 := false
	for _, w := range res.LintReport.Warnings {
		if w.Code == relaypackvalidate.CodeRP019 {
			foundRP019 = true
		}
	}
	if !foundRP019 {
		t.Fatalf("expected RP019 lint warning in report, got %+v", res.LintReport.Warnings)
	}
}

// (4) BindAndSign must not mutate the input OperatorRecord.
func TestBindAndSign_DoesNotMutateRecord(t *testing.T) {
	rec := minimalRec(t)
	before := deepCopyRec(rec)
	_, priv := fixedKey(t, 0x42)
	if _, err := BindAndSign(rec, priv, defaultOpts()); err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	// Per-field diff so we get a useful failure mode if some sub-slice
	// is the culprit.
	if rec.Provider != before.Provider {
		t.Fatalf("Provider mutated")
	}
	for i := range rec.Candidates {
		a, b := rec.Candidates[i], before.Candidates[i]
		if !reflect.DeepEqual(a.PublicRiskTags, b.PublicRiskTags) {
			t.Fatalf("Candidates[%d].PublicRiskTags mutated: got %v want %v",
				i, a.PublicRiskTags, b.PublicRiskTags)
		}
		if !reflect.DeepEqual(a.OriginRiskTags, b.OriginRiskTags) {
			t.Fatalf("Candidates[%d].OriginRiskTags mutated: got %#v (nil=%v) want %#v (nil=%v)",
				i, a.OriginRiskTags, a.OriginRiskTags == nil, b.OriginRiskTags, b.OriginRiskTags == nil)
		}
		if !reflect.DeepEqual(a.Params, b.Params) {
			t.Fatalf("Candidates[%d].Params mutated: got %v want %v",
				i, a.Params, b.Params)
		}
		// nil-vs-empty separately:
		if (a.Params == nil) != (b.Params == nil) {
			t.Fatalf("Candidates[%d].Params nil-state changed", i)
		}
	}
}

// (5) freshness_url is "" at V1.5 and round-trips through canonical.
func TestBindAndSign_FreshnessURLEmptyAtV15(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if parsed.Manifest.RelayPack == nil {
		t.Fatalf("RelayPack slot missing on parsed bundle")
	}
	if parsed.Manifest.RelayPack.FreshnessURL != "" {
		t.Fatalf("freshness_url should be empty at V1.5, got %q",
			parsed.Manifest.RelayPack.FreshnessURL)
	}
}

// (6) shared_risk_graph is part of the signed payload — mutating it
// post-sign breaks VerifyBundle.
func TestBindAndSign_SharedRiskGraphInsideSignedPayload(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle pre-mutation: %v", err)
	}
	// Mutate one tag and assert verify now fails.
	if len(parsed.Manifest.RelayPack.SharedRiskGraph) == 0 {
		t.Fatalf("expected non-empty SharedRiskGraph for shared-IP candidates")
	}
	parsed.Manifest.RelayPack.SharedRiskGraph[0].Tag = "tampered:tag"
	if err := bundle.VerifyBundle(parsed); err == nil {
		t.Fatalf("VerifyBundle should fail after tampering with shared_risk_graph")
	}
}

// (7) cdn_fronted is rejected at V1.5 (RP004).
func TestBindAndSign_RejectsCDNCandidateAtV15(t *testing.T) {
	rec := minimalRec(t)
	rec.Candidates[0].ExposureMode = "cdn_fronted"
	rec.Candidates[0].PublicRiskTags = []string{"cdn:cloudflare", "public_domain:e.example.com"}
	rec.Candidates[0].OriginRiskTags = []string{"origin_ip:5.75.0.1"}
	_, priv := fixedKey(t, 0x42)
	_, err := BindAndSign(rec, priv, defaultOpts())
	if err == nil {
		t.Fatalf("expected RP004 error for cdn_fronted at V1.5")
	}
	if !contains(err.Error(), "RP004") {
		t.Fatalf("error should mention RP004, got %v", err)
	}
}

// (8) RP014 — the bundle must contain ≥2 vps-native candidates.
func TestBindAndSign_TwoCandidatesMinimum(t *testing.T) {
	rec := minimalRec(t)
	rec.Candidates = rec.Candidates[:1]
	_, priv := fixedKey(t, 0x42)
	if _, err := BindAndSign(rec, priv, defaultOpts()); err == nil {
		t.Fatalf("expected RP014 error for single-candidate")
	}
}

// (9) Pure function: parallel BindAndSign calls produce identical bytes.
func TestBindAndSign_NoGlobalState(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	const N = 4
	results := make([][]byte, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			res, err := BindAndSign(rec, priv, defaultOpts())
			if err != nil {
				t.Errorf("parallel call %d: %v", i, err)
				return
			}
			results[i] = res.SBPBytes
		}(i)
	}
	wg.Wait()
	for i := 1; i < N; i++ {
		if !bytes.Equal(results[0], results[i]) {
			t.Fatalf("parallel call %d produced different bytes", i)
		}
	}
}

// (10) RP008 satisfied — sanity that candidate_render emits public_ip:* tag.
func TestBindAndSign_PublicIPInTags(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	entry, err := bundle.ParseRelayPackEntry(parsed.Manifest.Routes[0].FamilySpecificConfig)
	if err != nil {
		t.Fatalf("ParseRelayPackEntry: %v", err)
	}
	hasIP := false
	for _, tag := range entry.PublicRiskTags {
		if tag == "public_ip:5.75.0.1" {
			hasIP = true
			break
		}
	}
	if !hasIP {
		t.Fatalf("public_ip:* tag missing from candidate: %+v", entry.PublicRiskTags)
	}
}

// (11) Round-trip through ParseSBP + VerifyBundle.
func TestBindAndSign_SignatureVerifies(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	// Sanity: SHA256 hex-string is 64 chars.
	if len(res.BundleSHA256) != 64 {
		t.Fatalf("BundleSHA256 wrong length: %d", len(res.BundleSHA256))
	}
	if _, err := hex.DecodeString(res.BundleSHA256); err != nil {
		t.Fatalf("BundleSHA256 not hex: %v", err)
	}
}

func TestBindAndSign_SubkeyCertSignsAsRootPublisher(t *testing.T) {
	rec := minimalRec(t)
	_, rootPriv := fixedKey(t, 0x42)
	subPriv, cert := subkeyForRoot(t, rootPriv)
	opts := defaultOpts()
	opts.SubkeyCertJSON = cert

	res, err := BindAndSign(rec, subPriv, opts)
	if err != nil {
		t.Fatalf("BindAndSign subkey: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if parsed.Manifest.SpecVersion != 4 {
		t.Fatalf("spec_version = %d, want 4", parsed.Manifest.SpecVersion)
	}
	if len(parsed.SubkeyCertJSON) == 0 {
		t.Fatal("sub-key signed RelayPack missing trust/subkey-cert.json")
	}
	if !bytes.Equal(parsed.PublisherPub, rec.PublisherPubKey) {
		t.Fatal("publisher.pub must remain the root publisher key")
	}
	if got := parsed.Manifest.Publisher.KeyFingerprintHex; got != bundle.PublisherFingerprint(rec.PublisherPubKey).Hex {
		t.Fatalf("manifest publisher fp = %s, want root fp", got)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle subkey bundle: %v", err)
	}
}

func TestBindAndSign_SubkeyCertRequiresSubkeySigner(t *testing.T) {
	rec := minimalRec(t)
	_, rootPriv := fixedKey(t, 0x42)
	_, cert := subkeyForRoot(t, rootPriv)
	opts := defaultOpts()
	opts.SubkeyCertJSON = cert

	if _, err := BindAndSign(rec, rootPriv, opts); !errors.Is(err, ErrSubkeyCertWithRootKey) {
		t.Fatalf("want ErrSubkeyCertWithRootKey, got %v", err)
	}
}

// (12) Invalid privkey rejected before any work happens.
func TestBindAndSign_EmptyPrivKeyRejected(t *testing.T) {
	rec := minimalRec(t)
	_, err := BindAndSign(rec, ed25519.PrivateKey{}, defaultOpts())
	if !errors.Is(err, ErrEmptyPrivKey) {
		t.Fatalf("want ErrEmptyPrivKey, got %v", err)
	}
	zero := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	if _, err := BindAndSign(rec, zero, defaultOpts()); !errors.Is(err, ErrEmptyPrivKey) {
		t.Fatalf("want ErrEmptyPrivKey for zero-bytes, got %v", err)
	}
}

// (13) Pubkey mismatch rejected.
func TestBindAndSign_PubKeyMismatch(t *testing.T) {
	rec := minimalRec(t)
	// Replace the recorded pubkey with a different one.
	otherPub, _ := fixedKey(t, 0x77)
	rec.PublisherPubKey = append([]byte(nil), otherPub...)
	_, priv := fixedKey(t, 0x42)
	if _, err := BindAndSign(rec, priv, defaultOpts()); !errors.Is(err, ErrPubKeyMismatch) {
		t.Fatalf("want ErrPubKeyMismatch, got %v", err)
	}
}

// (14) nil OperatorRecord rejected.
func TestBindAndSign_NilRecord(t *testing.T) {
	_, priv := fixedKey(t, 0x42)
	if _, err := BindAndSign(nil, priv, defaultOpts()); !errors.Is(err, ErrNilRecord) {
		t.Fatalf("want ErrNilRecord, got %v", err)
	}
}

// (15) opts.Phase is required.
func TestBindAndSign_PhaseRequired(t *testing.T) {
	rec := minimalRec(t)
	_, priv := fixedKey(t, 0x42)
	opts := defaultOpts()
	opts.Phase = ""
	if _, err := BindAndSign(rec, priv, opts); !errors.Is(err, ErrNoPhase) {
		t.Fatalf("want ErrNoPhase, got %v", err)
	}
}

// (16) Random keys round-trip end-to-end (not just fixed seed).
func TestBindAndSign_WithRandomKey(t *testing.T) {
	rec := minimalRec(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec.PublisherPubKey = append([]byte(nil), pub...)
	res, err := BindAndSign(rec, priv, defaultOpts())
	if err != nil {
		t.Fatalf("BindAndSign: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(res.SBPBytes), int64(len(res.SBPBytes)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

// helpers ------------------------------------------------------------

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

func deepCopyRec(rec *provider.OperatorRecord) *provider.OperatorRecord {
	out := *rec
	out.PublisherPubKey = copyBytes(rec.PublisherPubKey)
	out.Candidates = make([]provider.CandidateMeta, len(rec.Candidates))
	for i, c := range rec.Candidates {
		out.Candidates[i] = c
		out.Candidates[i].PublicRiskTags = copyStrings(c.PublicRiskTags)
		out.Candidates[i].OriginRiskTags = copyStrings(c.OriginRiskTags)
		out.Candidates[i].Params = copyBytes(c.Params)
	}
	return &out
}

// copyStrings preserves the nil-vs-empty distinction (deep-copy
// helpers built on append([]T(nil), src...) collapse []T{} to nil
// when src is empty, breaking reflect.DeepEqual against the original).
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
