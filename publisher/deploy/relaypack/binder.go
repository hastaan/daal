package relaypack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/relaypackvalidate"
	"daal/publisher/deploy/modifiers"
	"daal/publisher/deploy/provider"
)

// defaultExpiry is the bundle validity window when BindOpts.Expiry
// is zero. 30 days is the V1.5 ship default agreed at FRP-4b spec
// review (rotation lands at FRP-7; recipients re-import on next
// QR scan).
const defaultExpiry = 30 * 24 * time.Hour

// defaultPublisherDisplayName is used when BindOpts.PublisherDisplayName
// is empty. Kept neutral; the Helper UI lets the operator override.
const defaultPublisherDisplayName = "Family Relay Publisher"

// BindOpts configures BindAndSign. Now is the only non-deterministic
// input; same (rec, priv, opts) ⇒ byte-identical .sbp output.
type BindOpts struct {
	// Now is stamped into Bundle.CreatedAt and used as the base for
	// expiry windows. The CLI exposes --now-unix to make determinism
	// testable at the binary boundary.
	Now time.Time

	// Expiry is the bundle validity window. Default 30 days.
	Expiry time.Duration

	// Phase selects the validator gate. V1.5 at FRP-4b ship; FRP-8
	// flips to V1.6 to lift cdn_fronted; FRP-12 to PostV2 to lift
	// modifiers.
	Phase relaypackvalidate.Phase

	// FreshnessURL is empty at V1.5 (RP021 rejects non-empty values);
	// FRP-8 populates the actual URL at V1.6.
	FreshnessURL string

	// PublisherDisplayName is the human-readable name shown to the
	// recipient on TOFU. Optional; defaults to "Family Relay
	// Publisher".
	PublisherDisplayName string

	// SubkeyCertJSON is optional FRP-7.5 cert-chain material. When
	// non-empty, priv is allowed to be the certified sub-key while
	// rec.PublisherPubKey remains the root publisher key shipped as
	// publisher.pub. The bundle is emitted at spec_version=4 with
	// trust/subkey-cert.json.
	SubkeyCertJSON []byte
}

// BindResult is returned by BindAndSign. Carries the signed .sbp
// bytes plus the metadata the wizard renders on screen 6.
type BindResult struct {
	// SBPBytes is the deterministic signed bundle.
	SBPBytes []byte

	// BundleSHA256 is hex(sha256(SBPBytes)).
	BundleSHA256 string

	// FingerprintHex / EN / FA describe the publisher key
	// (sha256(pub) + per-implementation wordlist mappings).
	FingerprintHex string
	FingerprintEN  string
	FingerprintFA  string

	// LintReport carries non-blocking warnings (RP019 / RP020). The
	// wizard surfaces these in a yellow banner; they never halt the
	// bind.
	LintReport relaypackvalidate.LintReport

	// RelayPackID is the deterministic id derived by DeriveRelayPackID.
	RelayPackID string

	// SharedRiskGraph is the bundle-wide §12.3 graph (signed inside
	// the bundle; surfaced here for the wizard's diagnostics view).
	SharedRiskGraph []bundle.SharedRiskEdge
}

// errors -------------------------------------------------------------

var (
	// ErrNilRecord is returned when BindAndSign is called with rec=nil.
	ErrNilRecord = errors.New("relaypack: nil OperatorRecord")
	// ErrEmptyPrivKey is returned when priv is zero-length or wrong size.
	ErrEmptyPrivKey = errors.New("relaypack: empty or wrong-size ed25519 private key")
	// ErrMissingPubKey is returned when rec.PublisherPubKey is empty.
	ErrMissingPubKey = errors.New("relaypack: OperatorRecord.PublisherPubKey is empty")
	// ErrPubKeyMismatch is returned when the privkey's public half
	// disagrees with rec.PublisherPubKey.
	ErrPubKeyMismatch = errors.New("relaypack: priv.Public() does not match OperatorRecord.PublisherPubKey")
	// ErrSubkeyCertWithRootKey is returned when callers supply a
	// sub-key cert but still pass the root private key. The cert-chain
	// path must actually sign with the certified sub-key.
	ErrSubkeyCertWithRootKey = errors.New("relaypack: sub-key cert supplied with root signing key")
	// ErrNoPhase is returned when opts.Phase is empty.
	ErrNoPhase = errors.New("relaypack: BindOpts.Phase is required")
)

// BindAndSign is the FRP-4b binder.
//
// Pure function: same (rec, priv, opts) ⇒ byte-identical .sbp output.
// Reads no environment, opens no network connections, touches no files.
//
// Steps:
//
//  1. Validate inputs (nil record, key shape, key/record agreement).
//  2. Render the OperatorRecord candidates into bundle routes +
//     RelayPackEntry objects via candidate_render.
//  3. Compute the deterministic RelayPackID and the bundle-wide
//     shared_risk_graph.
//  4. Build the bundle.Manifest with SpecVersion=3, Publisher info,
//     Bundle id/type/created/expires, Routes, and the RelayPack slot.
//  5. Run relaypackvalidate.Validate(b, ValidateOpts{Phase: opts.Phase})
//     BEFORE signing. Hard-stop on any error (RP001..RP018/RP021);
//     LintReport carries non-blocking RP019/RP020 warnings.
//  6. Sign deterministically via bundle.BuildSignedBundleDeterministic.
//  7. Compute bundle-byte sha256 + the publisher fingerprint render.
//
// Signature locked at FRP-4b spec §5; BindResult shape locked there too.
func BindAndSign(rec *provider.OperatorRecord, priv ed25519.PrivateKey, opts BindOpts) (*BindResult, error) {
	// ---- 1. Input validation -------------------------------------
	if rec == nil {
		return nil, ErrNilRecord
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrEmptyPrivKey
	}
	if isAllZero(priv) {
		return nil, ErrEmptyPrivKey
	}
	if len(rec.PublisherPubKey) == 0 {
		return nil, ErrMissingPubKey
	}
	rootPub := ed25519.PublicKey(rec.PublisherPubKey)
	signingPub := ed25519.PublicKey(priv.Public().(ed25519.PublicKey))
	usingSubkey := len(opts.SubkeyCertJSON) > 0
	if !usingSubkey && !bytes.Equal(signingPub, rootPub) {
		return nil, ErrPubKeyMismatch
	}
	if usingSubkey && bytes.Equal(signingPub, rootPub) {
		return nil, ErrSubkeyCertWithRootKey
	}
	if opts.Phase == "" {
		return nil, ErrNoPhase
	}

	now := opts.Now.UTC()
	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultExpiry
	}
	displayName := opts.PublisherDisplayName
	if displayName == "" {
		displayName = defaultPublisherDisplayName
	}

	createdAt := now.Format(time.RFC3339)
	expiresAt := now.Add(expiry).Format(time.RFC3339)

	// ---- 2. Render candidates ------------------------------------
	rendered, err := renderCandidates(rec, createdAt, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("relaypack: render candidates: %w", err)
	}

	// ---- 3. RelayPackID + shared_risk_graph ---------------------
	relayPackID := DeriveRelayPackID(rec)
	srg := BuildSharedRiskGraph(rendered.ids, rendered.entries)

	// ---- 4. Build the manifest -----------------------------------
	specVersion := 3
	extras := map[string][]byte(nil)
	if usingSubkey {
		specVersion = 4
		extras = map[string][]byte{
			"trust/subkey-cert.json": append([]byte(nil), opts.SubkeyCertJSON...),
		}
	}
	fingerprint := bundle.PublisherFingerprint(rootPub)
	manifest := bundle.Manifest{
		SpecVersion: specVersion,
		Publisher: bundle.PublisherInfo{
			Name:              displayName,
			KeyFingerprintHex: fingerprint.Hex,
			KeyCreatedAt:      createdAt,
			TrustClass:        "unknown",
		},
		Bundle: bundle.BundleInfo{
			ID:             relayPackID,
			Type:           "provider",
			CreatedAt:      createdAt,
			ExpiresAt:      expiresAt,
			SupersedesKeys: []string{},
		},
		Routes: rendered.routes,
		RelayPack: &bundle.RelayPack{
			RelayPackID:     relayPackID,
			SharedRiskGraph: srg,
			FreshnessURL:    opts.FreshnessURL,
		},
	}

	// ---- 5. Validate BEFORE signing ------------------------------
	// We need a Bundle, not a Manifest, because relaypackvalidate
	// reads both Manifest.RelayPack and per-route FamilySpecificConfig
	// off a Bundle struct.
	preBundle := &bundle.Bundle{Manifest: manifest, PublisherPub: rootPub}
	// FRP-12: populate AllowedModifierKinds from the modifier
	// registry. At FRP-12 ship the registry has zero PASS records
	// (locked invariant 37) so this map is empty and RP013 keeps
	// rejecting every non-empty modifiers[] array. The wiring
	// itself is what FRP-12 ships; the first concrete PASS record
	// is a separate post-track phase that re-runs genregistry with
	// --allow-pass.
	lintReport, err := relaypackvalidate.Validate(preBundle, relaypackvalidate.ValidateOpts{
		Phase:                opts.Phase,
		AllowedModifierKinds: allowedModifierKindsForPhase(opts.Phase),
	})
	if err != nil {
		return nil, fmt.Errorf("relaypack validate (%s): %w", opts.Phase, err)
	}

	// ---- 6. Sign deterministically -------------------------------
	sbpBytes, err := bundle.BuildSignedBundleDeterministic(manifest, rendered.profiles, extras, rootPub, priv)
	if err != nil {
		return nil, fmt.Errorf("relaypack: sign: %w", err)
	}

	// ---- 7. Render fingerprint + final result --------------------
	sum := sha256.Sum256(sbpBytes)
	bundleSHA := hex.EncodeToString(sum[:])
	rendered2, _ := bundle.RenderFingerprint(fingerprint, defaultWordlists())

	return &BindResult{
		SBPBytes:        sbpBytes,
		BundleSHA256:    bundleSHA,
		FingerprintHex:  fingerprint.Hex,
		FingerprintEN:   rendered2.EN,
		FingerprintFA:   rendered2.FA,
		LintReport:      lintReport,
		RelayPackID:     relayPackID,
		SharedRiskGraph: srg,
	}, nil
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// allowedModifierKindsForPhase translates the validator's Phase
// enum into the modifier-registry equivalent and returns the
// AllowedModifierKinds map for relaypackvalidate.ValidateOpts.
//
// At FRP-12 ship every registered kind is PENDING, so the returned
// map is empty for every phase (locked invariant 37). The first
// concrete modifier PASS record is a separate post-track phase.
func allowedModifierKindsForPhase(p relaypackvalidate.Phase) map[string]bool {
	var rp modifiers.Phase
	switch p {
	case relaypackvalidate.PhaseV15:
		rp = modifiers.PhaseV15
	case relaypackvalidate.PhaseV16:
		rp = modifiers.PhaseV16
	case relaypackvalidate.PhasePostV2:
		rp = modifiers.PhasePostV2
	default:
		return map[string]bool{}
	}
	return modifiers.AllowedKindsAt(rp)
}

// defaultWordlists returns the 16-word EN+FA placeholders that the
// FRP-5 wizard ports verbatim. FRP-7.5 lifts both sides to BIP-39 +
// curated Persian; the same commit will replace this list AND the
// Rust-side EN_WORDLIST/FA_WORDLIST in publisher_key.rs.
//
// Kept small and identical to bundle/go/publisher/keystore.go's
// defaultWordlists so cross-implementation parity holds at FRP-4b.
func defaultWordlists() bundle.Wordlists {
	return bundle.Wordlists{
		English: []string{
			"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
			"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
		},
		Persian: []string{
			"یک", "دو", "سه", "چهار", "پنج", "شش", "هفت", "هشت",
			"نه", "ده", "یازده", "دوازده", "سیزده", "چهارده", "پانزده", "شانزده",
		},
	}
}
