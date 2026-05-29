// Package bundle — FRP-11 cell-document canonicalisation and
// admin-quorum signature verification.
//
// Module-boundary invariant (FRP-track v1 §61, FRP-11 invariant 33):
// `bundle/go/bundle/` MUST NOT import `daal/core`. The cell trust
// chain walk (admin-quorum → membership → delegation → bundle-signer
// → inner-publisher) lives at `core/trust/cell_verify.go`; this file
// supplies only the bundle-local primitives that cell_verify and the
// publisher/cell aggregator both reach for:
//
//   - canonical byte forms for the membership and delegation docs
//     (deterministic, sorted-key JSON without the admin_signatures
//     field — that field IS the signature carrier and cannot cover
//     itself);
//   - M-of-N independent Ed25519 admin-signature quorum verification
//     against those canonical bytes (FRP-11 invariant 31: NO
//     threshold cryptosystem);
//   - shape validation (cell_id non-empty, N ∈ [1,25], M ≤ N, admin
//     pubkeys decode to 32 bytes, signatures decode and reference
//     valid indices, no duplicate quorum-idx).
//
// Anything that needs to know publisher fingerprints, route IDs, or
// engine state stays in core/trust/cell_verify.go.
//
// Locked at FRP-11 — append-only thereafter; widening the closed
// error list at bundle/go/bundle/errors.go requires a roadmap-level
// decision.
package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
)

// MaxCellAdminN is the locked-at-FRP-11 ceiling on the number of
// independent admins per cell, mirroring supplement §16.1
// ("3–25 helpers"). N=1 is permitted (single-admin cell, useful for
// solo-helper aggregation tests); N=25 is the upper bound on the
// member list per supplement and on the admin set here for parity.
const MaxCellAdminN = 25

// CanonicalCellMembership returns the canonical bytes of a cell
// membership document with the `admin_signatures` field stripped.
// The admin quorum signs over these bytes; absorbing
// `admin_signatures` into the signed payload would be circular.
//
// Determinism: sorted struct field order is enforced by re-marshaling
// through a fixed-shape struct (no map iteration in the signed
// payload). The function does NOT mutate the input.
func CanonicalCellMembership(doc CellMembershipDoc) ([]byte, error) {
	stripped := struct {
		CellID       string       `json:"cell_id"`
		AdminPubkeys []string     `json:"admin_pubkeys"`
		QuorumM      int          `json:"quorum_m"`
		Members      []CellMember `json:"members"`
		RuleSet      CellRuleSet  `json:"rule_set"`
	}{
		CellID:       doc.CellID,
		AdminPubkeys: append([]string(nil), doc.AdminPubkeys...),
		QuorumM:      doc.QuorumM,
		Members:      append([]CellMember(nil), doc.Members...),
		RuleSet:      doc.RuleSet,
	}
	return json.Marshal(stripped)
}

// CanonicalCellDelegation returns the canonical bytes of a cell
// delegation document with the `admin_signatures` field stripped.
func CanonicalCellDelegation(doc CellDelegationDoc) ([]byte, error) {
	stripped := struct {
		CellID             string `json:"cell_id"`
		BundleSignerPubkey string `json:"bundle_signer_pubkey"`
		ValidFromUnix      int64  `json:"valid_from_unix"`
		ValidUntilUnix     int64  `json:"valid_until_unix"`
	}{
		CellID:             doc.CellID,
		BundleSignerPubkey: doc.BundleSignerPubkey,
		ValidFromUnix:      doc.ValidFromUnix,
		ValidUntilUnix:     doc.ValidUntilUnix,
	}
	return json.Marshal(stripped)
}

// validateCellMembershipShape enforces the locked-at-FRP-11 shape
// constraints on a parsed CellMembershipDoc. Signature verification
// is in VerifyCellMembershipQuorum.
func validateCellMembershipShape(doc *CellMembershipDoc) error {
	if doc.CellID == "" {
		return ErrCellMembershipMalformed
	}
	n := len(doc.AdminPubkeys)
	if n < 1 || n > MaxCellAdminN {
		return ErrCellQuorumOutOfRange
	}
	if doc.QuorumM < 1 || doc.QuorumM > n {
		return ErrCellQuorumOutOfRange
	}
	for _, pk := range doc.AdminPubkeys {
		raw, err := base64.RawStdEncoding.DecodeString(pk)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return ErrCellAdminPubkeyMalformed
		}
	}
	return nil
}

// VerifyCellMembershipQuorum confirms that at least QuorumM
// independent Ed25519 admin signatures cover the canonical
// membership bytes, with NO duplicate AdminPubkeyIdx values.
// Returns nil iff the M-of-N quorum is met. FRP-11 invariant 31:
// independent signatures, NO threshold cryptosystem.
func VerifyCellMembershipQuorum(doc CellMembershipDoc) error {
	if err := validateCellMembershipShape(&doc); err != nil {
		return err
	}
	canonical, err := CanonicalCellMembership(doc)
	if err != nil {
		return ErrCellMembershipMalformed
	}
	return verifyAdminQuorum(canonical, doc.AdminPubkeys, doc.QuorumM, doc.AdminSignatures)
}

// VerifyCellDelegationQuorum confirms that at least QuorumM
// independent Ed25519 admin signatures from the GIVEN membership doc
// cover the canonical delegation bytes. The delegation cannot stand
// alone — it inherits its quorum from the membership doc that
// authorised it, hence the membership doc is passed in as the
// authoritative pubkey source. Cell IDs MUST match.
func VerifyCellDelegationQuorum(membership CellMembershipDoc, delegation CellDelegationDoc) error {
	if delegation.CellID == "" {
		return ErrCellDelegationMalformed
	}
	if delegation.CellID != membership.CellID {
		return ErrCellDelegationCellIDMismatch
	}
	if delegation.BundleSignerPubkey == "" {
		return ErrCellDelegationMalformed
	}
	raw, err := base64.RawStdEncoding.DecodeString(delegation.BundleSignerPubkey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return ErrCellDelegationMalformed
	}
	if delegation.ValidUntilUnix != 0 && delegation.ValidFromUnix > delegation.ValidUntilUnix {
		return ErrCellDelegationMalformed
	}
	canonical, err := CanonicalCellDelegation(delegation)
	if err != nil {
		return ErrCellDelegationMalformed
	}
	return verifyAdminQuorum(canonical, membership.AdminPubkeys, membership.QuorumM, delegation.AdminSignatures)
}

// verifyAdminQuorum is the shared M-of-N verifier used by both
// membership and delegation. Signatures are checked in order; on
// success the count of unique-idx valid signatures must be ≥ M.
// Duplicate AdminPubkeyIdx values reject (defence-in-depth: a
// publisher who could trivially repeat one signature N times would
// otherwise game any "≥M" check).
func verifyAdminQuorum(canonical []byte, adminPubkeys []string, quorumM int, sigs []CellAdminSignature) error {
	if len(sigs) < quorumM {
		return ErrCellAdminQuorumNotMet
	}
	seen := map[int]bool{}
	// Sort sigs by AdminPubkeyIdx for deterministic walk; doesn't
	// affect verification outcome but stabilises test ordering.
	ordered := append([]CellAdminSignature(nil), sigs...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].AdminPubkeyIdx < ordered[j].AdminPubkeyIdx
	})
	valid := 0
	for _, s := range ordered {
		if s.AdminPubkeyIdx < 0 || s.AdminPubkeyIdx >= len(adminPubkeys) {
			return ErrCellAdminSignatureMalformed
		}
		if seen[s.AdminPubkeyIdx] {
			return ErrCellAdminQuorumDuplicateIdx
		}
		seen[s.AdminPubkeyIdx] = true
		pkRaw, err := base64.RawStdEncoding.DecodeString(adminPubkeys[s.AdminPubkeyIdx])
		if err != nil || len(pkRaw) != ed25519.PublicKeySize {
			return ErrCellAdminPubkeyMalformed
		}
		sigRaw, err := base64.RawStdEncoding.DecodeString(s.SignatureB64)
		if err != nil || len(sigRaw) != ed25519.SignatureSize {
			return ErrCellAdminSignatureMalformed
		}
		if !ed25519.Verify(ed25519.PublicKey(pkRaw), canonical, sigRaw) {
			// Invalid signatures don't count toward the quorum but
			// don't reject either — a quorum can still be met by the
			// other M valid ones. (Standard M-of-N semantics.)
			continue
		}
		valid++
	}
	if valid < quorumM {
		return ErrCellAdminQuorumNotMet
	}
	return nil
}

// SignCellMembership produces a single admin signature over the
// canonical membership bytes. The publisher/cell admin layer holds
// the admin private keys; this helper exists in the bundle module so
// authors of cell-doc unit tests can produce valid signatures
// without pulling in the publisher module. NOT used by recipient
// code (recipient never holds admin private keys).
func SignCellMembership(doc CellMembershipDoc, idx int, priv ed25519.PrivateKey) (CellAdminSignature, error) {
	canonical, err := CanonicalCellMembership(doc)
	if err != nil {
		return CellAdminSignature{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	return CellAdminSignature{
		AdminPubkeyIdx: idx,
		SignatureB64:   base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// SignCellDelegation produces a single admin signature over the
// canonical delegation bytes. Same caveats as SignCellMembership.
func SignCellDelegation(doc CellDelegationDoc, idx int, priv ed25519.PrivateKey) (CellAdminSignature, error) {
	canonical, err := CanonicalCellDelegation(doc)
	if err != nil {
		return CellAdminSignature{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	return CellAdminSignature{
		AdminPubkeyIdx: idx,
		SignatureB64:   base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// ParseCellDocs parses the bundle's trust/cell-membership.json +
// trust/cell-delegation.json files into typed CellMembershipDoc /
// CellDelegationDoc values. Returns (nil, nil, nil) when neither
// file is present (non-cell bundle). Returns an error if EITHER
// file is present without the OTHER (cells require both docs to
// be a coherent grant), or if either file is malformed JSON, or if
// the membership doc fails the FRP-11 shape check (cell_id non-empty,
// 1 <= M <= N <= MaxCellAdminN, admin pubkeys decode to 32 bytes).
//
// ParseCellDocs does NOT verify the admin-quorum signatures — the
// caller (core/trust/cell_verify.go) drives the verification chain
// after fetching the canonical bytes from these structs. This split
// keeps `bundle/go/bundle/` free of trust-state concerns (FRP-11
// invariant 33).
func ParseCellDocs(b *Bundle) (*CellMembershipDoc, *CellDelegationDoc, error) {
	hasMem := len(b.CellMembershipJSON) > 0
	hasDel := len(b.CellDelegationJSON) > 0
	if !hasMem && !hasDel {
		return nil, nil, nil
	}
	if hasMem != hasDel {
		// Either-but-not-both is a malformed cell bundle; the
		// admin grant chain is invalid without both files.
		if !hasMem {
			return nil, nil, ErrCellMembershipMalformed
		}
		return nil, nil, ErrCellDelegationMalformed
	}
	var memb CellMembershipDoc
	if err := json.Unmarshal(b.CellMembershipJSON, &memb); err != nil {
		return nil, nil, ErrCellMembershipMalformed
	}
	if err := validateCellMembershipShape(&memb); err != nil {
		return nil, nil, err
	}
	var deleg CellDelegationDoc
	if err := json.Unmarshal(b.CellDelegationJSON, &deleg); err != nil {
		return nil, nil, ErrCellDelegationMalformed
	}
	if deleg.CellID == "" {
		return nil, nil, ErrCellDelegationMalformed
	}
	if deleg.CellID != memb.CellID {
		return nil, nil, ErrCellDelegationCellIDMismatch
	}
	return &memb, &deleg, nil
}
