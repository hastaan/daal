package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FRP-7.5 — end-to-end "no root touch after cert sign" guard.
//
// The whole point of the sub-key cert chain is that a long-running
// FRP can rotate sub-keys, and re-emit fresh RelayPacks, WITHOUT
// touching the publisher root key on every rotation. The root key
// is touched ONCE at cert sign time; every subsequent bundle is
// signed by the sub-key, and verifies through the cert chain.
//
// This test counts how many times the root signing function is
// invoked across a multi-bundle round-trip and asserts the count
// matches the design contract:
//
//	root.Sign() count = number of cert refreshes (cert refresh
//	  IS expected to require a root touch — that's the trust
//	  anchor for the chain).
//
//	Specifically, we drive the following transcript:
//	  1. Generate root keypair.
//	  2. Sign cert(sub-key 1) with root        → root touched #1
//	  3. Sign bundle 1 with sub-key 1          → root NOT touched
//	  4. Verify bundle 1                       → root NOT touched
//	  5. Sign bundle 2 with sub-key 1          → root NOT touched
//	  6. Verify bundle 2                       → root NOT touched
//	  7. Generate sub-key 2; sign cert(sub-key 2) with root
//	                                           → root touched #2
//	  8. Sign bundle 3 with sub-key 2          → root NOT touched
//	  9. Verify bundle 3                       → root NOT touched
//
//	Final root.Sign() count: 2 (one per cert; zero per bundle).

// rootCounter wraps an ed25519 private key and counts every
// Sign() call against it. It deliberately does NOT implement
// crypto.Signer to keep the surface narrow; tests call .Sign()
// directly.
type rootCounter struct {
	priv  ed25519.PrivateKey
	count int
}

func (rc *rootCounter) Sign(payload []byte) []byte {
	rc.count++
	return ed25519.Sign(rc.priv, payload)
}

func (rc *rootCounter) Public() ed25519.PublicKey {
	return rc.priv.Public().(ed25519.PublicKey)
}

// makeCert produces a cert byte payload + canonical signature
// using the supplied root counter. Mirrors the publisher-side
// canonical-JSON signing exactly.
func makeCertCounted(
	t *testing.T,
	root *rootCounter,
	subPub ed25519.PublicKey,
	validFrom, validUntil time.Time,
	label string,
) []byte {
	t.Helper()
	cert := subkeyCertWire{
		V:                  1,
		Kind:               "subkey_cert",
		RootFingerprintHex: PublisherFingerprint(root.Public()).Hex,
		SubkeyPubHex:       hex.EncodeToString(subPub),
		ValidFrom:          validFrom.Format(time.RFC3339),
		ValidUntil:         validUntil.Format(time.RFC3339),
		Label:              label,
	}
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.SignatureHex = hex.EncodeToString(root.Sign(body))
	out, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSubkeyChainNoRootTouchAfterCertSign(t *testing.T) {
	// 1. Root keypair.
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &rootCounter{priv: rootPriv}
	if root.count != 0 {
		t.Fatalf("counter pre-condition: count = %d, want 0", root.count)
	}
	now := time.Now().UTC()

	// 2. Sub-key 1 + cert. Root touched #1.
	sub1Pub, sub1Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert1 := makeCertCounted(t, root, sub1Pub,
		now.Add(-time.Hour), now.Add(90*24*time.Hour), "sub-1")
	if root.count != 1 {
		t.Fatalf("after cert1: root.count = %d, want 1", root.count)
	}

	// 3. Bundle 1 signed by sub-key 1.
	m := baseManifestWithKey(t, rootPub, "normal", "vless-reality", now.Add(24*time.Hour))
	m.Bundle.ID = "no-root-touch-bundle-1"
	bundle1 := buildSubkeyBundle(t, m, nil, rootPub, sub1Priv, cert1)
	if root.count != 1 {
		t.Fatalf("after bundle1 sign: root.count = %d, want 1", root.count)
	}
	// 4. Verify bundle 1.
	b1, err := ParseSBP(bytes.NewReader(bundle1), int64(len(bundle1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b1); err != nil {
		t.Fatal(err)
	}
	if root.count != 1 {
		t.Fatalf("after bundle1 verify: root.count = %d, want 1", root.count)
	}

	// 5/6. Bundle 2 signed by sub-key 1 (still). No root touch.
	m2 := baseManifestWithKey(t, rootPub, "normal", "vless-reality", now.Add(48*time.Hour))
	m2.Bundle.ID = "no-root-touch-bundle-2"
	bundle2 := buildSubkeyBundle(t, m2, nil, rootPub, sub1Priv, cert1)
	if root.count != 1 {
		t.Fatalf("after bundle2 sign: root.count = %d, want 1", root.count)
	}
	b2, err := ParseSBP(bytes.NewReader(bundle2), int64(len(bundle2)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b2); err != nil {
		t.Fatal(err)
	}
	if root.count != 1 {
		t.Fatalf("after bundle2 verify: root.count = %d, want 1", root.count)
	}

	// 7. Rotate to sub-key 2: cert refresh requires root touch.
	sub2Pub, sub2Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert2 := makeCertCounted(t, root, sub2Pub,
		now.Add(-time.Hour), now.Add(90*24*time.Hour), "sub-2")
	if root.count != 2 {
		t.Fatalf("after cert2: root.count = %d, want 2", root.count)
	}

	// 8/9. Bundle 3 signed by sub-key 2. Verify. No root touch.
	m3 := baseManifestWithKey(t, rootPub, "normal", "vless-reality", now.Add(72*time.Hour))
	m3.Bundle.ID = "no-root-touch-bundle-3"
	bundle3 := buildSubkeyBundle(t, m3, nil, rootPub, sub2Priv, cert2)
	if root.count != 2 {
		t.Fatalf("after bundle3 sign: root.count = %d, want 2", root.count)
	}
	b3, err := ParseSBP(bytes.NewReader(bundle3), int64(len(bundle3)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b3); err != nil {
		t.Fatal(err)
	}
	if root.count != 2 {
		t.Fatalf("after bundle3 verify: root.count = %d, want 2", root.count)
	}

	// Final attestation. The contract is: 1 root touch per cert,
	// zero per bundle. We did 2 cert signs + 3 bundle signs +
	// 3 bundle verifies → 2 root touches.
	if root.count != 2 {
		t.Fatalf("final root.count = %d, want 2 (one per cert sign, zero per bundle)", root.count)
	}
}

// FRP-7.5 — read the sample artefact at
// `specs/test-vectors/bundles/samples/subkey-signed-A.sbp` and
// verify it through the chain branch end-to-end. This is the
// fixture-based regression guard against drift between the
// generator (cmd/bundle-subkey-sample) and the verifier
// (bundle.VerifyBundle).
//
// The sample is generated with a 90-day cert window centred on
// the FRP-7.5 ship date (2026-05-03), and this test verifies it at
// that SAME pinned instant via VerifyBundleAt.
//
// It did not always. It used to call VerifyBundle, i.e. verify a
// fixture with a fixed window against the wall clock, so on
// 2026-08-01 it went red on every machine forever — a scheduled
// alarm dressed as a test, un-fixable here because regenerating the
// artefact needs samples/keys-A/publisher.priv, which is
// deliberately not in this repo. It was then softened to skip on
// exactly that expiry, which stopped the noise but also stopped the
// test: the fixture went unverified.
//
// Pinning the clock restores the assertion permanently. Nothing is
// weakened — VerifyBundleAt runs every check VerifyBundle runs,
// including the sub-key window, only against the instant the
// generator pinned. The check that this fixture's window is honoured
// at all is TestSubkeySignedSampleRejectedOutsideWindow below.
func TestSubkeySignedSampleArtefact(t *testing.T) {
	body, err := os.ReadFile(subkeySamplePath(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	if len(b.SubkeyCertJSON) == 0 {
		t.Fatal("sample missing trust/subkey-cert.json")
	}
	if b.Manifest.SpecVersion != 4 {
		t.Fatalf("sample spec_version = %d, want 4", b.Manifest.SpecVersion)
	}
	if err := VerifyBundleAt(b, subkeySamplePinnedNow); err != nil {
		t.Fatalf("sample verify at the pinned instant %s: %v",
			subkeySamplePinnedNow.Format(time.RFC3339), err)
	}
}

// subkeySamplePinnedNow is cmd/bundle-subkey-sample's `pinnedNowUnix`
// (2026-05-03T00:00:00Z), the instant the artefact's 90-day sub-key
// window is centred on. It is duplicated rather than imported because
// the generator is package main; TestSubkeySignedSamplePinMatchesCert
// pins the duplicate to the artefact so the two cannot drift.
var subkeySamplePinnedNow = time.Unix(1_777_795_200, 0).UTC()

// subkeySamplePath locates the FRP-7.5 sample relative to
// bundle/go/bundle/, or skips when it is not checked out.
func subkeySamplePath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wd, "..", "..", "..", "specs",
		"test-vectors", "bundles", "samples", "subkey-signed-A.sbp")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("sample not present (regenerate with cmd/bundle-subkey-sample): %v", err)
	}
	return p
}

// TestSubkeySignedSamplePinMatchesCert guards the duplicated constant
// above: it reads the window out of the artefact itself and asserts the
// pinned instant falls inside it. If somebody regenerates the sample
// with a new pinnedNowUnix and forgets this file, this fails loudly
// instead of the pin quietly drifting outside the window.
func TestSubkeySignedSamplePinMatchesCert(t *testing.T) {
	body, err := os.ReadFile(subkeySamplePath(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	var cert struct {
		ValidFrom  string `json:"valid_from"`
		ValidUntil string `json:"valid_until"`
	}
	if err := json.Unmarshal(b.SubkeyCertJSON, &cert); err != nil {
		t.Fatalf("parse sample subkey cert: %v", err)
	}
	from, err := time.Parse(time.RFC3339, cert.ValidFrom)
	if err != nil {
		t.Fatalf("valid_from: %v", err)
	}
	until, err := time.Parse(time.RFC3339, cert.ValidUntil)
	if err != nil {
		t.Fatalf("valid_until: %v", err)
	}
	if subkeySamplePinnedNow.Before(from) || !subkeySamplePinnedNow.Before(until) {
		t.Fatalf("subkeySamplePinnedNow %s is outside the sample cert window %s..%s "+
			"— update it to cmd/bundle-subkey-sample's pinnedNowUnix",
			subkeySamplePinnedNow.Format(time.RFC3339),
			from.Format(time.RFC3339), until.Format(time.RFC3339))
	}
}

// TestSubkeySignedSampleRejectedOutsideWindow is the other half of the
// pinned-clock fix: proving the seam did not disable the window check.
// The same artefact, verified one second after its cert lapses, must
// still be refused with ErrSubkeyCertOutOfWindow.
func TestSubkeySignedSampleRejectedOutsideWindow(t *testing.T) {
	body, err := os.ReadFile(subkeySamplePath(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	var cert struct {
		ValidUntil string `json:"valid_until"`
	}
	if err := json.Unmarshal(b.SubkeyCertJSON, &cert); err != nil {
		t.Fatalf("parse sample subkey cert: %v", err)
	}
	until, err := time.Parse(time.RFC3339, cert.ValidUntil)
	if err != nil {
		t.Fatalf("valid_until: %v", err)
	}
	err = VerifyBundleAt(b, until.Add(time.Second))
	if !errors.Is(err, ErrSubkeyCertOutOfWindow) {
		t.Fatalf("verify after the cert window = %v, want ErrSubkeyCertOutOfWindow", err)
	}
}
