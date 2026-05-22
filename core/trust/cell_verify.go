// Package trust — FRP-11 cell verification chain.
//
// VerifyCellChain walks the cell trust chain on the recipient side:
//
//	admin-quorum (M-of-N independent Ed25519)  ──signs──▶  membership doc
//	↓
//	admin-quorum (same, against canonical delegation bytes)  ──signs──▶  delegation grant
//	↓
//	bundle-signer pubkey from delegation  ──must equal──  archive publisher.pub
//	↓
//	per-route _relaypack._inner_provenance  ──must name──  membership member
//
// The walk is recipient-only. Bundle-local primitives (parse +
// canonicalise + admin-quorum verify) live at
// bundle/go/bundle/cellcanon.go to preserve the FRP-track v1 §61 +
// FRP-11 invariant 33 module-direction `core → bundle` (NEVER the
// reverse).
//
// On success VerifyCellChain returns the parsed cell-membership
// doc + cell-delegation doc plus a chain-status struct the import
// path renders into the recipient's TOFU prompt.
package trust

import (
	"bytes"
	"encoding/base64"
	"errors"
	"time"

	bundle "daal/bundle-go/bundle"
)

// ChainStatus carries the recipient-facing summary of a successful
// cell-chain walk. The TOFU prompt renders all four fields.
type ChainStatus struct {
	CellID            string
	BundleSignerFPHex string
	QuorumM           int
	QuorumN           int
	ValidUntilUnix    int64
}

// Recipient-side closed errors. Bundle-side errors flow up
// unchanged via errors.Is().
var (
	ErrCellChainNotPresent              = errors.New("cell chain: no cell docs in bundle")
	ErrCellChainBundleSignerMismatch    = errors.New("cell chain: delegation bundle-signer pubkey does not match signed bundle publisher key")
	ErrCellChainDelegationOutOfWindow   = errors.New("cell chain: delegation grant outside its valid_from..valid_until window")
	ErrCellChainMembershipExpired       = errors.New("cell chain: membership document expired")
	ErrCellChainInnerProvenanceMissing  = errors.New("cell chain: route missing inner-publisher provenance")
	ErrCellChainInnerPublisherNotMember = errors.New("cell chain: route inner-publisher provenance is not a cell member")
)

// VerifyCellChain walks the FRP-11 trust chain against a parsed
// bundle. Returns ErrCellChainNotPresent for non-cell bundles
// (caller can fall through to the standard publisher TOFU prompt).
//
// Required pre-condition: bundle.VerifyBundle(b) MUST have returned
// nil before this call. VerifyCellChain trusts the manifest signature
// (the bundle-signer's signature) was already checked.
func VerifyCellChain(b *bundle.Bundle, now time.Time) (*ChainStatus, *bundle.CellMembershipDoc, *bundle.CellDelegationDoc, error) {
	if b == nil {
		return nil, nil, nil, ErrCellChainNotPresent
	}
	memb, deleg, err := bundle.ParseCellDocs(b)
	if err != nil {
		return nil, nil, nil, err
	}
	if memb == nil || deleg == nil {
		return nil, nil, nil, ErrCellChainNotPresent
	}
	// Walk step 1: membership admin-quorum.
	if err := bundle.VerifyCellMembershipQuorum(*memb); err != nil {
		return nil, nil, nil, err
	}
	if memb.RuleSet.ValidUntilUnix != 0 && now.Unix() > memb.RuleSet.ValidUntilUnix {
		return nil, nil, nil, ErrCellChainMembershipExpired
	}
	// Walk step 2: delegation admin-quorum (inherits pubkey set
	// from membership; cell_id mismatch already caught at parse).
	if err := bundle.VerifyCellDelegationQuorum(*memb, *deleg); err != nil {
		return nil, nil, nil, err
	}
	// Walk step 3: delegation must be within its window.
	if deleg.ValidUntilUnix != 0 && now.Unix() > deleg.ValidUntilUnix {
		return nil, nil, nil, ErrCellChainDelegationOutOfWindow
	}
	if deleg.ValidFromUnix != 0 && now.Unix() < deleg.ValidFromUnix {
		return nil, nil, nil, ErrCellChainDelegationOutOfWindow
	}
	// Walk step 4: bundle-signer pubkey from delegation must match
	// the manifest's publisher fingerprint (the key VerifyBundle
	// already checked the signature against).
	signerPubRaw, err := base64.RawStdEncoding.DecodeString(deleg.BundleSignerPubkey)
	if err != nil {
		return nil, nil, nil, bundle.ErrCellDelegationMalformed
	}
	if !bytes.Equal(signerPubRaw, b.PublisherPub) {
		return nil, nil, nil, ErrCellChainBundleSignerMismatch
	}
	signerFP := bundle.PublisherFingerprint(signerPubRaw)
	if b.Manifest.Publisher.KeyFingerprintHex != "" &&
		b.Manifest.Publisher.KeyFingerprintHex != signerFP.Hex {
		return nil, nil, nil, ErrCellChainBundleSignerMismatch
	}
	if err := verifyCellRouteProvenance(b.Manifest.Routes, *memb); err != nil {
		return nil, nil, nil, err
	}
	validUntil := deleg.ValidUntilUnix
	if memb.RuleSet.ValidUntilUnix != 0 && (validUntil == 0 || memb.RuleSet.ValidUntilUnix < validUntil) {
		validUntil = memb.RuleSet.ValidUntilUnix
	}
	return &ChainStatus{
		CellID:            memb.CellID,
		BundleSignerFPHex: signerFP.Hex,
		QuorumM:           memb.QuorumM,
		QuorumN:           len(memb.AdminPubkeys),
		ValidUntilUnix:    validUntil,
	}, memb, deleg, nil
}

func verifyCellRouteProvenance(routes []bundle.RouteManifestEntry, memb bundle.CellMembershipDoc) error {
	members := make(map[string]struct{}, len(memb.Members))
	for _, member := range memb.Members {
		members[cellMemberKey(member.PublisherFPHex, member.SubkeyFPHex)] = struct{}{}
	}
	for _, route := range routes {
		entry, err := bundle.ParseRelayPackEntry(route.FamilySpecificConfig)
		if err != nil {
			return ErrCellChainInnerProvenanceMissing
		}
		if entry.InnerProvenance == nil || entry.InnerProvenance.PublisherFPHex == "" {
			return ErrCellChainInnerProvenanceMissing
		}
		key := cellMemberKey(entry.InnerProvenance.PublisherFPHex, entry.InnerProvenance.SubkeyFPHex)
		if _, ok := members[key]; !ok {
			return ErrCellChainInnerPublisherNotMember
		}
	}
	return nil
}

func cellMemberKey(publisherFPHex, subkeyFPHex string) string {
	return publisherFPHex + "\x00" + subkeyFPHex
}
