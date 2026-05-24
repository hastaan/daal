// Package cell — FRP-11 publisher-side primitives for trusted cells.
//
// This package supplies what helper-side cell admins, cell members,
// and the cell aggregator need:
//
//   - admin keypair generation + storage shape (NOT reusing publisher
//     keys; FRP-11 locked answer #1: fresh per-admin Ed25519 keypair);
//   - membership-doc construction + admin-quorum-signature collection;
//   - delegation-doc construction (admin-quorum-signed grant of
//     bundle-signer authority to a per-cell Ed25519 bundle-signer key);
//   - aggregator (commit 4) that ingests member RelayPacks and emits a
//     cell-aggregated `.sbp`;
//   - freshness publisher (commit 5) that adapts the FRP-9 R2 + GH
//     Pages backends to per-cell directory + revocation publication.
//
// The package never reaches into `core/`; it builds bundle bytes via
// the `daal/bundle-go` module's existing primitives (FRP-1 RelayPack
// shape) plus the FRP-11 cellcanon helpers. Recipient-side chain walk
// stays at `core/trust/cell_verify.go`.
//
// FRP-11 invariant 31: cell admin scheme is M-of-N independent
// Ed25519. NO threshold cryptosystem. N in [1,25]; M <= N.
package cell

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	bundle "daal/bundle-go/bundle"
)

// Common errors specific to publisher-side cell construction. The
// recipient-side closed list at bundle/go/bundle/errors.go covers
// parse + verification; this list covers authoring failure modes.
var (
	ErrAdminCountOutOfRange   = errors.New("cell admin count must be 1..25")
	ErrQuorumOutOfRange       = errors.New("cell quorum must satisfy 1 <= M <= N")
	ErrAdminKeyMismatch       = errors.New("admin private key does not match the membership doc admin pubkey")
	ErrInsufficientQuorum     = errors.New("collected fewer admin signatures than the quorum requires")
	ErrAdminKeyAlreadyPresent = errors.New("admin pubkey already present in the membership doc")
)

// AdminKeypair is the locked-at-FRP-11 in-memory pair held by a
// single cell admin. The private key never leaves the host; the
// public key is base64-RawStd encoded into the membership doc's
// `admin_pubkeys[]` slot. FRP-11 locked answer #1: this is a fresh
// per-admin keypair, NEVER reused as the publisher key for that
// admin's FRP RelayPacks.
type AdminKeypair struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// NewAdminKeypair generates a fresh Ed25519 admin keypair using
// crypto/rand. The caller persists Priv to the wizard's encrypted
// keystore; Pub is published into the membership doc.
func NewAdminKeypair() (AdminKeypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return AdminKeypair{}, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	return AdminKeypair{Pub: pub, Priv: priv}, nil
}

// PubB64 returns the base64-RawStd encoding suitable for the
// membership doc's admin_pubkeys[] slot.
func (a AdminKeypair) PubB64() string {
	return base64.RawStdEncoding.EncodeToString(a.Pub)
}

// BundleSigner is the per-cell Ed25519 keypair authorised by the
// admin-quorum-signed delegation grant. Aggregated RelayPacks are
// signed by this key so the bundle-signer can be rotated without
// admin-quorum re-sign of every aggregate. The aggregator (commit 4)
// holds Priv; the membership doc holds Pub via the delegation doc.
type BundleSigner struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// NewBundleSigner generates a fresh per-cell Ed25519 bundle-signer
// keypair.
func NewBundleSigner() (BundleSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return BundleSigner{}, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	return BundleSigner{Pub: pub, Priv: priv}, nil
}

// PubB64 returns the base64-RawStd encoding suitable for the
// delegation doc's bundle_signer_pubkey slot.
func (s BundleSigner) PubB64() string {
	return base64.RawStdEncoding.EncodeToString(s.Pub)
}

// DefaultQuorum returns the FRP-11 default M = ceil((N+1)/2). Cell
// admins MAY override at cell creation but MUST satisfy 1 <= M <= N.
func DefaultQuorum(n int) int {
	if n <= 0 {
		return 0
	}
	return (n + 2) / 2
}

// MembershipBuilder assembles a CellMembershipDoc from a cell
// configuration plus member entries plus admin pubkey set, and
// collects admin signatures one-at-a-time as the M admins co-sign.
// Once Quorum signatures are collected the builder returns the
// finalised doc + a check that bundle.VerifyCellMembershipQuorum
// passes.
type MembershipBuilder struct {
	doc bundle.CellMembershipDoc
}

// NewMembership starts building a fresh membership doc. Returns an
// error if N or M is out of range or if any admin pubkey is malformed.
func NewMembership(cellID string, adminPubkeysB64 []string, quorumM int, ruleSet bundle.CellRuleSet) (*MembershipBuilder, error) {
	n := len(adminPubkeysB64)
	if n < 1 || n > bundle.MaxCellAdminN {
		return nil, ErrAdminCountOutOfRange
	}
	if quorumM < 1 || quorumM > n {
		return nil, ErrQuorumOutOfRange
	}
	for _, pk := range adminPubkeysB64 {
		raw, err := base64.RawStdEncoding.DecodeString(pk)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, bundle.ErrCellAdminPubkeyMalformed
		}
	}
	return &MembershipBuilder{
		doc: bundle.CellMembershipDoc{
			CellID:       cellID,
			AdminPubkeys: append([]string(nil), adminPubkeysB64...),
			QuorumM:      quorumM,
			RuleSet:      ruleSet,
		},
	}, nil
}

// AddMember appends a publisher member entry. Idempotent on
// (publisher_fp_hex, subkey_fp_hex) pairs: a duplicate is silently
// dropped so bulk re-imports don't bloat the doc.
func (b *MembershipBuilder) AddMember(m bundle.CellMember) {
	for _, existing := range b.doc.Members {
		if existing.PublisherFPHex == m.PublisherFPHex && existing.SubkeyFPHex == m.SubkeyFPHex {
			return
		}
	}
	b.doc.Members = append(b.doc.Members, m)
}

// Sign collects one admin signature into the doc. Idx must reference
// an entry in AdminPubkeys; the priv key MUST match that pubkey.
// Returns the running signature count.
func (b *MembershipBuilder) Sign(idx int, priv ed25519.PrivateKey) (int, error) {
	if idx < 0 || idx >= len(b.doc.AdminPubkeys) {
		return 0, bundle.ErrCellAdminSignatureMalformed
	}
	expected, err := base64.RawStdEncoding.DecodeString(b.doc.AdminPubkeys[idx])
	if err != nil {
		return 0, bundle.ErrCellAdminPubkeyMalformed
	}
	derived := priv.Public().(ed25519.PublicKey)
	if !ed25519.PublicKey(expected).Equal(derived) {
		return 0, ErrAdminKeyMismatch
	}
	for _, existing := range b.doc.AdminSignatures {
		if existing.AdminPubkeyIdx == idx {
			// Replace if same admin re-signs after an edit; otherwise
			// the duplicate-idx-rejects rule at the verifier would
			// fire.
			break
		}
	}
	// Strip prior signature for this idx if any (idempotent re-sign).
	keep := b.doc.AdminSignatures[:0]
	for _, s := range b.doc.AdminSignatures {
		if s.AdminPubkeyIdx != idx {
			keep = append(keep, s)
		}
	}
	b.doc.AdminSignatures = keep
	sig, err := bundle.SignCellMembership(b.doc, idx, priv)
	if err != nil {
		return 0, err
	}
	b.doc.AdminSignatures = append(b.doc.AdminSignatures, sig)
	return len(b.doc.AdminSignatures), nil
}

// Finalize returns the membership doc once at least Quorum
// signatures are present and bundle.VerifyCellMembershipQuorum
// confirms the M-of-N admin quorum is met.
func (b *MembershipBuilder) Finalize() (bundle.CellMembershipDoc, error) {
	if len(b.doc.AdminSignatures) < b.doc.QuorumM {
		return bundle.CellMembershipDoc{}, ErrInsufficientQuorum
	}
	if err := bundle.VerifyCellMembershipQuorum(b.doc); err != nil {
		return bundle.CellMembershipDoc{}, err
	}
	out := b.doc
	out.AdminPubkeys = append([]string(nil), b.doc.AdminPubkeys...)
	out.Members = append([]bundle.CellMember(nil), b.doc.Members...)
	out.AdminSignatures = append([]bundle.CellAdminSignature(nil), b.doc.AdminSignatures...)
	return out, nil
}

// DelegationBuilder is the analogue of MembershipBuilder for the
// admin-quorum-signed delegation grant. The delegation doc inherits
// the admin pubkey set + quorum from its membership doc.
type DelegationBuilder struct {
	memb bundle.CellMembershipDoc
	doc  bundle.CellDelegationDoc
}

// NewDelegation starts building a fresh delegation grant against an
// already-finalised membership doc. validFromUnix MUST be <=
// validUntilUnix; validUntilUnix==0 means "no upper bound" (the
// recipient still rejects expired-window grants if upper bound is
// set; 0 is treated as open-ended).
func NewDelegation(memb bundle.CellMembershipDoc, signerPubB64 string, validFromUnix, validUntilUnix int64) (*DelegationBuilder, error) {
	if memb.CellID == "" {
		return nil, bundle.ErrCellMembershipMalformed
	}
	raw, err := base64.RawStdEncoding.DecodeString(signerPubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, bundle.ErrCellDelegationMalformed
	}
	if validUntilUnix != 0 && validFromUnix > validUntilUnix {
		return nil, bundle.ErrCellDelegationMalformed
	}
	return &DelegationBuilder{
		memb: memb,
		doc: bundle.CellDelegationDoc{
			CellID:             memb.CellID,
			BundleSignerPubkey: signerPubB64,
			ValidFromUnix:      validFromUnix,
			ValidUntilUnix:     validUntilUnix,
		},
	}, nil
}

// Sign collects one admin signature into the delegation doc. Same
// idempotency rules as MembershipBuilder.Sign.
func (b *DelegationBuilder) Sign(idx int, priv ed25519.PrivateKey) (int, error) {
	if idx < 0 || idx >= len(b.memb.AdminPubkeys) {
		return 0, bundle.ErrCellAdminSignatureMalformed
	}
	expected, err := base64.RawStdEncoding.DecodeString(b.memb.AdminPubkeys[idx])
	if err != nil {
		return 0, bundle.ErrCellAdminPubkeyMalformed
	}
	derived := priv.Public().(ed25519.PublicKey)
	if !ed25519.PublicKey(expected).Equal(derived) {
		return 0, ErrAdminKeyMismatch
	}
	keep := b.doc.AdminSignatures[:0]
	for _, s := range b.doc.AdminSignatures {
		if s.AdminPubkeyIdx != idx {
			keep = append(keep, s)
		}
	}
	b.doc.AdminSignatures = keep
	sig, err := bundle.SignCellDelegation(b.doc, idx, priv)
	if err != nil {
		return 0, err
	}
	b.doc.AdminSignatures = append(b.doc.AdminSignatures, sig)
	return len(b.doc.AdminSignatures), nil
}

// Finalize returns the delegation doc once the membership doc's
// quorum is met by the collected delegation signatures.
func (b *DelegationBuilder) Finalize() (bundle.CellDelegationDoc, error) {
	if len(b.doc.AdminSignatures) < b.memb.QuorumM {
		return bundle.CellDelegationDoc{}, ErrInsufficientQuorum
	}
	if err := bundle.VerifyCellDelegationQuorum(b.memb, b.doc); err != nil {
		return bundle.CellDelegationDoc{}, err
	}
	out := b.doc
	out.AdminSignatures = append([]bundle.CellAdminSignature(nil), b.doc.AdminSignatures...)
	return out, nil
}
