//go:build !no_delegate_share

// Package delegate implements Phase 3F: the chain walker, cap
// enforcer, and `.sbp.share` builder/verifier for delegate-signed
// re-shares.
//
// Locked invariants (see specs/delegate-keys-v1.md):
//
//   - The delegate key is the existing Phase 1C share identity
//     (`secrets_kv:share/identity:v1`). NO new key derivation is
//     introduced at 3F.
//   - `redistribution_policy` is a closed enum:
//     `none` / `delegated_n` / `transitive`. Default when absent
//     is `none` (fail-closed).
//   - `transitive` chains are capped at depth 5; deeper chains
//     are rejected per-bundle (soft-validation discipline
//     preserved).
//   - The original publisher's signature is preserved verbatim;
//     delegate signatures are *appended*, never replaced.
//   - Re-share counters live in
//     `secrets_kv:delegate_share_counter:<route_id>`; the
//     authoritative hop count lives inside the
//     `redistribution_chain[]`.

package delegate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Compiled is the build-tag-conditional flag the ABI's
// diagnostics path consults to populate
// `delegate_share_compiled_in`. The non-excluded twin sets it
// true; the `-tags no_delegate_share` twin sets it false.
const Compiled = true

// Policy is the closed enum of redistribution policies a
// publisher may attach to a route. Absent / empty maps to
// PolicyNone (fail-closed) at the receiver side.
type Policy string

const (
	PolicyNone       Policy = "none"
	PolicyDelegatedN Policy = "delegated_n"
	PolicyTransitive Policy = "transitive"

	// MaxChainDepth is the locked-at-3F transitive-chain cap.
	// Deeper chains are rejected per-bundle.
	MaxChainDepth = 5
)

// IsValidPolicy returns true for any of the three locked v1
// values. Empty string is INVALID at this layer; callers MUST
// substitute PolicyNone on absence before reaching this check.
func IsValidPolicy(p Policy) bool {
	switch p {
	case PolicyNone, PolicyDelegatedN, PolicyTransitive:
		return true
	}
	return false
}

// ChainHop is one entry in a re-share's redistribution_chain[].
// The signature covers `canonicalChainState(origSig, prior)`
// where prior is the ordered list of hops accumulated before
// this one. A receiver verifying hop[i] reconstructs prior
// state from hop[0..i-1] and the original publisher signature.
type ChainHop struct {
	DelegateFPHex  string `json:"delegate_fp_hex"`
	DelegatePub    string `json:"delegate_pub"`     // base64-RawStd of pub
	SignedAt       string `json:"signed_at"`        // RFC3339
	RecipientFPHex string `json:"recipient_fp_hex"` // intended recipient
	SignatureB64   string `json:"signature"`        // base64-RawStd Ed25519
}

// CapEntry pins the per-route advisory counter at the moment
// the sender signed the re-share. The receiver uses these
// values to enforce caps at import time.
type CapEntry struct {
	RouteID                   string `json:"route_id"`
	SharedWithCountAtSignTime uint8  `json:"shared_with_count_at_sign_time"`
	CapAtSignTime             uint8  `json:"cap_at_sign_time"`
}

// Outcome is the closed-enum surface emitted by
// engine_redistribute_route and the diagnostics path. Mirrors
// the v1 surface in specs/delegate-keys-v1.md.
type Outcome string

const (
	OutcomeOK                  Outcome = "ok"
	OutcomePolicyRefuses       Outcome = "policy_refuses"
	OutcomeCapExhausted        Outcome = "cap_exhausted"
	OutcomeChainDepthExceeded  Outcome = "chain_depth_exceeded"
	OutcomeRouteUnknown        Outcome = "route_unknown"
	OutcomeIdentityUnavailable Outcome = "identity_unavailable"
)

// Errors emitted by the chain walker / cap enforcer. The
// bundle-package mirror lives in `bundle/go/bundle/errors.go`
// and uses the same wording so receiver and sender agree.
var (
	ErrChainBroken         = errors.New("delegate: redistribution chain signature walk failed")
	ErrChainTooDeep        = errors.New("delegate: redistribution chain depth > 5")
	ErrChainOrphan         = errors.New("delegate: redistribution chain does not terminate in the publisher signature")
	ErrCapExceeded         = errors.New("delegate: redistribution cap exceeded")
	ErrPolicyForbids       = errors.New("delegate: redistribution policy forbids re-share")
	ErrIdentityUnavailable = errors.New("delegate: device share identity unavailable")
	ErrRouteUnknown        = errors.New("delegate: unknown route_id")
	ErrPolicyMalformed     = errors.New("delegate: redistribution_policy malformed")
	ErrCapMalformed        = errors.New("delegate: redistribution_cap malformed")
)

// EnforcePolicy converts a publisher-declared policy into the
// pre-flight engine check. Callers pass the parsed Policy, the
// declared cap (uint8 — only meaningful for PolicyDelegatedN),
// and the current local share counter. Returns OutcomeOK on
// pass and the matching Outcome on rejection.
func EnforcePolicy(p Policy, cap uint8, currentSharedCount uint8) Outcome {
	switch p {
	case PolicyNone:
		return OutcomePolicyRefuses
	case PolicyDelegatedN:
		if currentSharedCount >= cap {
			return OutcomeCapExhausted
		}
		return OutcomeOK
	case PolicyTransitive:
		// Transitive permits re-share unconditionally at the
		// sender side; the depth cap is enforced at the
		// receiver-side chain walk.
		return OutcomeOK
	}
	return OutcomePolicyRefuses
}

// EnforceChainDepth pre-flights a chain walk against the
// MaxChainDepth = 5 cap.
func EnforceChainDepth(currentDepth int) Outcome {
	if currentDepth >= MaxChainDepth {
		return OutcomeChainDepthExceeded
	}
	return OutcomeOK
}

// AppendHop signs and appends a new ChainHop to the supplied
// chain. The signature covers `canonicalChainState(origSig,
// chain)` — i.e. the prior state, not the new hop itself, so
// a receiver verifying hop[i] reconstructs prior state from
// hop[0..i-1] and the original publisher signature.
//
// The caller's privKey MUST be the device's 1C share identity
// private key. The corresponding pubkey is embedded in
// `DelegatePub` (base64) for receiver-side verification.
func AppendHop(chain []ChainHop, origSig []byte, recipientFPHex string,
	priv ed25519.PrivateKey, now time.Time) ([]ChainHop, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrIdentityUnavailable
	}
	pub := priv.Public().(ed25519.PublicKey)
	if EnforceChainDepth(len(chain)) != OutcomeOK {
		return nil, ErrChainTooDeep
	}
	state := canonicalChainState(origSig, chain)
	sig := ed25519.Sign(priv, state)
	hop := ChainHop{
		DelegateFPHex:  hex.EncodeToString(fingerprint(pub)),
		DelegatePub:    base64.RawStdEncoding.EncodeToString(pub),
		SignedAt:       now.UTC().Format(time.RFC3339),
		RecipientFPHex: recipientFPHex,
		SignatureB64:   base64.RawStdEncoding.EncodeToString(sig),
	}
	return append(chain, hop), nil
}

// VerifyChain walks a redistribution chain back to the
// publisher's signature. Returns the depth of the chain on
// success, or an error per the locked-at-3F failure surface.
//
//   - origSig: the original .sbp's manifest signature bytes
//     (already-verified by the caller against the publisher's
//     pubkey via the existing 0B path).
//   - expectedRecipientFP (optional): if non-empty, the LAST
//     hop's RecipientFPHex MUST match. Empty disables the
//     check (used by intermediate hops or by callers who do
//     not yet know their own delegate fp).
func VerifyChain(chain []ChainHop, origSig []byte, expectedRecipientFP string) (int, error) {
	if len(chain) == 0 {
		// An empty chain is a valid `.sbp` (not `.sbp.share`).
		// Callers that distinguish should check the bundle.type.
		return 0, nil
	}
	if len(chain) > MaxChainDepth {
		return 0, ErrChainTooDeep
	}
	prior := []ChainHop{}
	for i, hop := range chain {
		pub, err := base64.RawStdEncoding.DecodeString(hop.DelegatePub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return 0, fmt.Errorf("%w: hop %d: bad delegate_pub", ErrChainBroken, i)
		}
		want := hex.EncodeToString(fingerprint(pub))
		if want != hop.DelegateFPHex {
			return 0, fmt.Errorf("%w: hop %d: delegate_fp_hex mismatch", ErrChainBroken, i)
		}
		sig, err := base64.RawStdEncoding.DecodeString(hop.SignatureB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return 0, fmt.Errorf("%w: hop %d: bad signature encoding", ErrChainBroken, i)
		}
		state := canonicalChainState(origSig, prior)
		if !ed25519.Verify(pub, state, sig) {
			return 0, fmt.Errorf("%w: hop %d: signature does not verify", ErrChainBroken, i)
		}
		prior = append(prior, hop)
	}
	if expectedRecipientFP != "" {
		last := chain[len(chain)-1]
		if last.RecipientFPHex != expectedRecipientFP {
			return 0, fmt.Errorf("%w: last hop addressed to %q, not %q",
				ErrChainBroken, last.RecipientFPHex, expectedRecipientFP)
		}
	}
	return len(chain), nil
}

// EnforceCap walks the per-route caps in a `.sbp.share` and
// returns ErrCapExceeded if any entry's
// shared_with_count_at_sign_time >= cap_at_sign_time.
func EnforceCap(caps []CapEntry) error {
	for _, c := range caps {
		if c.CapAtSignTime > 0 && c.SharedWithCountAtSignTime >= c.CapAtSignTime {
			return fmt.Errorf("%w: route %s: %d/%d", ErrCapExceeded,
				c.RouteID, c.SharedWithCountAtSignTime, c.CapAtSignTime)
		}
	}
	return nil
}

// canonicalChainState returns the canonical bytes a hop signs
// over. It is the JSON encoding (Go's encoding/json — keys in
// struct literal order, no extra whitespace) of
// `{orig_sig: <base64>, prior_hops: [...]}`. The prior_hops
// array is normalised to `[]` for empty input (NEVER `null`)
// so the bytes a sender signs are byte-identical to those a
// receiver verifies. Locked at 3F; any change requires a
// spec-version bump.
func canonicalChainState(origSig []byte, prior []ChainHop) []byte {
	if prior == nil {
		prior = []ChainHop{}
	}
	wire := struct {
		OrigSig string     `json:"orig_sig"`
		Prior   []ChainHop `json:"prior_hops"`
	}{
		OrigSig: base64.RawStdEncoding.EncodeToString(origSig),
		Prior:   prior,
	}
	body, _ := json.Marshal(wire)
	return body
}

// fingerprint returns the 8-byte truncation of SHA-256(pub),
// matching the publisher fingerprint convention used elsewhere
// in the bundle package.
func fingerprint(pub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(pub)
	return sum[:8]
}

// OutcomeJSON renders an outcome envelope for the ABI's JSON
// error path. On success the caller serializes the bundle bytes
// instead.
func OutcomeJSON(o Outcome, detail string) string {
	body := map[string]string{
		"error":  string(o),
		"detail": detail,
	}
	out, _ := json.Marshal(body)
	return string(out)
}

// ParseUint8Cap returns the parsed cap if valid, or 0 + error.
// Used by the bundle parser to validate `redistribution_cap`.
func ParseUint8Cap(s string) (uint8, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, ErrCapMalformed
	}
	return uint8(n), nil
}
