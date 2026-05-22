package cell

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bundle "daal/bundle-go/bundle"
)

// Errors specific to cell-aggregation. Recipient-side parse + chain
// walk failure modes live in bundle/go/bundle/errors.go and
// core/trust/cell_verify.go (commit 6).
var (
	ErrAggregateNoMembers               = errors.New("cell aggregator: no member RelayPacks supplied")
	ErrAggregateCellIDMismatch          = errors.New("cell aggregator: cell_id mismatch across input docs")
	ErrAggregateMissingProfile          = errors.New("cell aggregator: member route missing profile bytes")
	ErrAggregateMissingRelayPack        = errors.New("cell aggregator: member route missing _relaypack metadata")
	ErrAggregateInnerPublisherNotMember = errors.New("cell aggregator: member route provenance does not match membership doc")
	ErrAggregateMembershipExpired       = errors.New("cell aggregator: membership document expired")
	ErrAggregateBundleSignerExpired     = errors.New("cell aggregator: delegation grant outside its valid_from..valid_until window")
)

// MemberRoute is a single route contributed by a cell-member
// publisher into the aggregate. It carries the route manifest entry
// AND the inner-publisher provenance metadata so the
// recipient can walk admin-quorum -> membership -> delegation ->
// bundle-signer -> inner-publisher and land at the original
// publisher fingerprint named by this route's RelayPack.
//
// The cell aggregator itself is NOT a TOFU promotion: the bundle-
// signer's signature on the aggregate manifest is what core/import
// + bundle.VerifyBundle key off; inner-publisher provenance is the
// chain-walk's terminus.
type MemberRoute struct {
	Route               bundle.RouteManifestEntry
	ProfileBytes        []byte
	PublisherFPHex      string
	SubkeyFPHex         string
	InnerPublisherProof []byte // optional opaque envelope; encoded into proof_b64
}

// AggregateInput bundles everything the aggregator needs to seal a
// cell-aggregated `.sbp`.
type AggregateInput struct {
	CellID       string
	Membership   bundle.CellMembershipDoc
	Delegation   bundle.CellDelegationDoc
	BundleSigner BundleSigner
	Routes       []MemberRoute
	BundleType   string // optional; defaults to "relay_pack"
	ExpiresAt    time.Time
	Now          time.Time // injected for testability; defaults to time.Now()
}

// AggregateOutput carries the sealed `.sbp` bytes plus the
// publisher-side metadata the freshness publisher needs.
type AggregateOutput struct {
	SBPBytes          []byte
	BundleSignerFPHex string
	CellID            string
	RouteCount        int
}

// Aggregate seals a cell-aggregated `.sbp`. The bundle-signer key
// produces the manifest signature; trust/cell-membership.json and
// trust/cell-delegation.json are written into the archive verbatim
// as the recipient's chain-walk inputs. The membership + delegation
// docs MUST already be admin-quorum-valid (Aggregate re-checks this
// defensively).
func Aggregate(in AggregateInput) (AggregateOutput, error) {
	if len(in.Routes) == 0 {
		return AggregateOutput{}, ErrAggregateNoMembers
	}
	if in.CellID != "" && in.CellID != in.Membership.CellID {
		return AggregateOutput{}, ErrAggregateCellIDMismatch
	}
	if in.Membership.CellID != in.Delegation.CellID {
		return AggregateOutput{}, ErrAggregateCellIDMismatch
	}
	if err := bundle.VerifyCellMembershipQuorum(in.Membership); err != nil {
		return AggregateOutput{}, fmt.Errorf("membership re-verify: %w", err)
	}
	if err := bundle.VerifyCellDelegationQuorum(in.Membership, in.Delegation); err != nil {
		return AggregateOutput{}, fmt.Errorf("delegation re-verify: %w", err)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if in.Membership.RuleSet.ValidUntilUnix != 0 && now.Unix() > in.Membership.RuleSet.ValidUntilUnix {
		return AggregateOutput{}, ErrAggregateMembershipExpired
	}
	if in.Delegation.ValidUntilUnix != 0 && now.Unix() > in.Delegation.ValidUntilUnix {
		return AggregateOutput{}, ErrAggregateBundleSignerExpired
	}
	// Confirm the BundleSigner private key matches the delegation's
	// pubkey: signing with a wrong key would produce an unverifiable
	// aggregate.
	derivedPubB64 := in.BundleSigner.PubB64()
	if derivedPubB64 != in.Delegation.BundleSignerPubkey {
		return AggregateOutput{}, fmt.Errorf("bundle-signer pubkey does not match delegation")
	}

	// Construct the manifest. SpecVersion stays at 4 (FRP-7.5
	// high-water; FRP-11 invariant 32 — no schema bump).
	bundleType := in.BundleType
	if bundleType == "" {
		bundleType = "relay_pack"
	}
	expires := in.ExpiresAt
	if expires.IsZero() {
		expires = now.Add(7 * 24 * time.Hour)
	}
	bsFP := bundle.PublisherFingerprint(in.BundleSigner.Pub)

	manifest := bundle.Manifest{
		SpecVersion: 4,
		Publisher: bundle.PublisherInfo{
			KeyFingerprintHex: bsFP.Hex,
		},
		Bundle: bundle.BundleInfo{
			Type:      bundleType,
			ExpiresAt: expires.Format(time.RFC3339),
		},
	}
	manifest.Routes = make([]bundle.RouteManifestEntry, 0, len(in.Routes))
	files := map[string][]byte{}
	for _, m := range in.Routes {
		if len(m.ProfileBytes) == 0 {
			return AggregateOutput{}, ErrAggregateMissingProfile
		}
		if !membershipHasRoutePublisher(in.Membership, m.PublisherFPHex, m.SubkeyFPHex) {
			return AggregateOutput{}, ErrAggregateInnerPublisherNotMember
		}
		route, err := injectInnerProvenance(m)
		if err != nil {
			return AggregateOutput{}, err
		}
		manifest.Routes = append(manifest.Routes, route)
		files[route.ConfigPath] = append([]byte(nil), m.ProfileBytes...)
	}

	// Serialize the membership + delegation docs into bundle files.
	memBytes, err := json.Marshal(in.Membership)
	if err != nil {
		return AggregateOutput{}, fmt.Errorf("marshal membership: %w", err)
	}
	delBytes, err := json.Marshal(in.Delegation)
	if err != nil {
		return AggregateOutput{}, fmt.Errorf("marshal delegation: %w", err)
	}

	// Sign the manifest with the bundle-signer key.
	sig, err := bundle.SignManifest(manifest, in.BundleSigner.Priv)
	if err != nil {
		return AggregateOutput{}, fmt.Errorf("sign manifest: %w", err)
	}

	files["manifest.sig"] = sig
	files["publisher.pub"] = ed25519.PublicKey(in.BundleSigner.Pub)
	files["trust/cell-membership.json"] = memBytes
	files["trust/cell-delegation.json"] = delBytes
	sbpBytes, err := bundle.BuildUnsignedBundle(manifest, files)
	if err != nil {
		return AggregateOutput{}, fmt.Errorf("build bundle: %w", err)
	}
	return AggregateOutput{
		SBPBytes:          sbpBytes,
		BundleSignerFPHex: bsFP.Hex,
		CellID:            in.Membership.CellID,
		RouteCount:        len(in.Routes),
	}, nil
}

func membershipHasRoutePublisher(memb bundle.CellMembershipDoc, publisherFPHex, subkeyFPHex string) bool {
	for _, member := range memb.Members {
		if member.PublisherFPHex == publisherFPHex && member.SubkeyFPHex == subkeyFPHex {
			return true
		}
	}
	return false
}

func injectInnerProvenance(m MemberRoute) (bundle.RouteManifestEntry, error) {
	if m.PublisherFPHex == "" {
		return bundle.RouteManifestEntry{}, ErrAggregateInnerPublisherNotMember
	}
	if len(m.Route.FamilySpecificConfig) == 0 {
		return bundle.RouteManifestEntry{}, ErrAggregateMissingRelayPack
	}
	var family map[string]json.RawMessage
	if err := json.Unmarshal(m.Route.FamilySpecificConfig, &family); err != nil {
		return bundle.RouteManifestEntry{}, ErrAggregateMissingRelayPack
	}
	rawRelayPack, ok := family["_relaypack"]
	if !ok {
		return bundle.RouteManifestEntry{}, ErrAggregateMissingRelayPack
	}
	var relayPack map[string]json.RawMessage
	if err := json.Unmarshal(rawRelayPack, &relayPack); err != nil {
		return bundle.RouteManifestEntry{}, ErrAggregateMissingRelayPack
	}
	provenance := bundle.CellInnerProvenance{
		PublisherFPHex: m.PublisherFPHex,
		SubkeyFPHex:    m.SubkeyFPHex,
	}
	if len(m.InnerPublisherProof) > 0 {
		provenance.ProofB64 = base64.RawStdEncoding.EncodeToString(m.InnerPublisherProof)
	}
	provBytes, err := json.Marshal(provenance)
	if err != nil {
		return bundle.RouteManifestEntry{}, err
	}
	relayPack["_inner_provenance"] = provBytes
	relayPackBytes, err := json.Marshal(relayPack)
	if err != nil {
		return bundle.RouteManifestEntry{}, err
	}
	family["_relaypack"] = relayPackBytes
	familyBytes, err := json.Marshal(family)
	if err != nil {
		return bundle.RouteManifestEntry{}, err
	}
	route := m.Route
	route.FamilySpecificConfig = familyBytes
	return route, nil
}
