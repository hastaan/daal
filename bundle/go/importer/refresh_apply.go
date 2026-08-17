// refresh_apply.go is the FRP-8 narrow entry point the recipient
// uses to apply a freshness-driven RelayPack swap.
//
// LAYER SPLIT (phase doc §13 rule 3):
//
//   - core/internal/selection/freshness.go: pure trigger policy.
//   - core/refresh/relaypack.go: network IO + atomic swap.
//   - bundle/go/importer/refresh_apply.go (this file): apply the
//     supplied bundle bytes after the recipient's freshness verifier
//     has independently verified the freshness JSON. The importer
//     re-verifies the SBP signature itself; the supplied
//     freshnessBundleSHA256Hex must match the signed .sbp body
//     SHA-256, otherwise we reject — defence in depth across the
//     three modules that touch the swap.
//
// Phase closure semantics:
//
//   - We DO call into the RelayPack validator at relaypack.CurrentPhase
//     — the SAME constant the QR-scan import path uses, so RP022/RP023/
//     RP024 fire identically on both and the freshness path can never
//     relax §11.7 hardening. This file used to hard-code V1.6 while
//     importer.go hard-coded V1.5; that disagreement is what
//     bundle/go/phase now makes impossible.
//   - We DO upsert atomically via State.SaveImport, the same path
//     ImportBytes uses. SaveImport's atomicity contract is the swap
//     primitive.

package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"daal/bundle-go/bundle"
	relaypack "daal/bundle-go/relaypackvalidate"
)

// ErrFreshnessFingerprintMismatch is returned when the supplied
// freshnessBundleSHA256Hex does not match the SHA-256 of the signed
// .sbp bytes in `body`. The recipient's
// network adapter must surface this as a refresh failure so the
// FRP gets observability through the audit log; the cause is
// almost always "the freshness endpoint is publishing a stale
// current_bundle_sha256 that does not match the bundle the FRP is
// shipping".
var ErrFreshnessFingerprintMismatch = errors.New("freshness current_bundle_sha256 does not match signed bundle")

// ApplyVerifiedRefresh applies bundle bytes whose freshness JSON
// has ALREADY been verified by the caller (core/refresh) and
// whose freshness current_bundle_sha256 matches
// `freshnessBundleSHA256Hex`.
//
// This function:
//
//  1. Parses + signature-verifies the bundle (defence in depth).
//  2. Re-computes the signed bundle SHA-256 and asserts it matches
//     freshnessBundleSHA256Hex. Mismatch → reject with
//     ErrFreshnessFingerprintMismatch.
//  3. Runs the V16 relaypack validator (RP022/RP023/RP024 etc.).
//  4. Looks up the publisher; if not pinned, refuses (recipient
//     must scan a QR before any freshness-driven import). If
//     pinned + revoked, refuses.
//  5. Upserts atomically via State.SaveImport.
//
// Returns the resulting Verdict on success.
func ApplyVerifiedRefresh(
	body []byte,
	freshnessBundleSHA256Hex string,
	st State,
	wordlists bundle.Wordlists,
	now time.Time,
) (Verdict, error) {
	got := sha256.Sum256(body)
	gotHex := hex.EncodeToString(got[:])
	if !equalHex(gotHex, freshnessBundleSHA256Hex) {
		return Verdict{Kind: VerdictRejected, Reason: "freshness_fp_mismatch"}, ErrFreshnessFingerprintMismatch
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "bundle_corrupted"}, err
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		return Verdict{Kind: VerdictRejected, Reason: classifyVerifyError(err)}, err
	}

	// RelayPack validator at the shipped phase — ensures the §11.7
	// hardening attestation holds even on the freshness-driven swap path.
	if _, vErr := relaypack.Validate(parsed, relaypack.ValidateOpts{Phase: relaypack.CurrentPhase}); vErr != nil {
		var ve *relaypack.ValidationError
		if errors.As(vErr, &ve) {
			return Verdict{Kind: VerdictRejected, Reason: "relaypack_" + string(ve.Code)}, vErr
		}
		return Verdict{Kind: VerdictRejected, Reason: "relaypack_invalid"}, vErr
	}

	fp := bundle.PublisherFingerprint(parsed.PublisherPub)
	rendered, _ := bundle.RenderFingerprint(fp, wordlists)
	bucket := hourBucket(now)

	pin, pinned, err := st.LookupPublisher(fp.Hex)
	if err != nil {
		return Verdict{Kind: VerdictRejected, Reason: "lookup_failed"}, err
	}
	if !pinned {
		// Refuse: a freshness-driven swap MUST NOT introduce a new
		// publisher. The recipient must scan a fresh QR before
		// trusting a different root key.
		return Verdict{Kind: VerdictRejected, Reason: "publisher_unknown_freshness_path"},
			fmt.Errorf("freshness import refused: publisher %s not pinned", fp.Hex)
	}
	if pin.TrustLevel == "revoked" {
		return Verdict{Kind: VerdictRejected, Reason: "publisher_revoked",
				Fingerprint: fp.Hex, HexEN: rendered.EN, HexFA: rendered.FA},
			errors.New("publisher revoked")
	}
	return applyWithRelayPackPhase(st, parsed, fp, rendered, bucket, pin.TrustLevel, false, relaypack.CurrentPhase)
}

// equalHex compares two hex strings case-insensitively.
func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
