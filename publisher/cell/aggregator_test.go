package cell

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	bundle "daal/bundle-go/bundle"
)

func parseSBP(t *testing.T, b []byte) *bundle.Bundle {
	t.Helper()
	out, err := bundle.ParseSBP(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	return out
}

// helper: a fully-signed (membership, delegation, bundle-signer)
// triple ready for aggregation.
func sealedCell(t *testing.T) (bundle.CellMembershipDoc, bundle.CellDelegationDoc, BundleSigner, []AdminKeypair) {
	t.Helper()
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("cell-test-1", pubs, 2, ruleSet())
	mb.AddMember(bundle.CellMember{PublisherFPHex: "9f3a", SubkeyFPHex: "1c2b", JoinedAtUnix: 1})
	mb.Sign(0, kps[0].Priv)
	mb.Sign(1, kps[1].Priv)
	memb, err := mb.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	bs, err := NewBundleSigner()
	if err != nil {
		t.Fatal(err)
	}
	// Window: 2026-01-01 .. 2030-01-01 (ample for test runtime).
	db, _ := NewDelegation(memb, bs.PubB64(), 1735689600, 1893456000)
	db.Sign(0, kps[0].Priv)
	db.Sign(2, kps[2].Priv)
	deleg, err := db.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	return memb, deleg, bs, kps
}

func minimalRoute(routeID string) MemberRoute {
	relayPack := bundle.RelayPackEntry{
		ExposureMode:     "direct_vps",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		PublicRiskTags:   []string{"public_ip:5.75.0.1"},
		OriginRiskTags:   []string{},
	}
	familySpecific, _ := json.Marshal(map[string]any{"_relaypack": relayPack})
	return MemberRoute{
		Route: bundle.RouteManifestEntry{
			ID:                   routeID,
			TransportFamily:      "vless-reality",
			ScarcityClass:        "normal",
			ConfigPath:           "profiles/" + routeID + ".json",
			ValidFrom:            "2026-01-01T00:00:00Z",
			ValidUntil:           "2026-12-31T00:00:00Z",
			RedistributionPolicy: "delegated_n",
			RedistributionCap:    1,
			FamilySpecificConfig: familySpecific,
		},
		ProfileBytes:   []byte(`{"route":"` + routeID + `"}`),
		PublisherFPHex: "9f3a",
		SubkeyFPHex:    "1c2b",
	}
}

// 1. Aggregate happy path: produces a bundle whose manifest.sig
// verifies under the bundle-signer pubkey, with both cell docs
// embedded in the archive.
func TestAggregate_HappyPath(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	in := AggregateInput{
		CellID:       memb.CellID,
		Membership:   memb,
		Delegation:   deleg,
		BundleSigner: bs,
		Routes:       []MemberRoute{minimalRoute("r-1"), minimalRoute("r-2")},
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		Now:          time.Unix(1735689700, 0).UTC(),
	}
	out, err := Aggregate(in)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if out.RouteCount != 2 {
		t.Fatalf("RouteCount=%d want 2", out.RouteCount)
	}
	if out.CellID != memb.CellID {
		t.Fatalf("CellID mismatch")
	}
	// Round-trip: ParseSBP + ParseCellDocs should recover the docs.
	parsed := parseSBP(t, out.SBPBytes)
	pmemb, pdeleg, err := bundle.ParseCellDocs(parsed)
	if err != nil {
		t.Fatalf("ParseCellDocs: %v", err)
	}
	if pmemb.CellID != memb.CellID || pdeleg.CellID != deleg.CellID {
		t.Fatalf("cell_id round-trip mismatch")
	}
	if err := bundle.VerifyCellMembershipQuorum(*pmemb); err != nil {
		t.Fatalf("round-trip membership: %v", err)
	}
	if err := bundle.VerifyCellDelegationQuorum(*pmemb, *pdeleg); err != nil {
		t.Fatalf("round-trip delegation: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle aggregate: %v", err)
	}
}

// 2. No member routes rejects.
func TestAggregate_NoMembers(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	if _, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
	}); !errors.Is(err, ErrAggregateNoMembers) {
		t.Fatalf("want ErrAggregateNoMembers, got %v", err)
	}
}

// 3. Membership re-verify failure surfaces (an admin sig tampered).
func TestAggregate_TamperedMembership(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	memb.AdminSignatures[0].SignatureB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	memb.AdminSignatures = memb.AdminSignatures[:1] // strip second so now only the bad one is left
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err == nil {
		t.Fatal("expected tampered-membership error")
	}
}

// 4. Delegation outside its valid window rejects.
func TestAggregate_DelegationExpired(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
		Now:    time.Unix(1893456000+1, 0).UTC(), // one second past valid_until
	})
	if !errors.Is(err, ErrAggregateBundleSignerExpired) {
		t.Fatalf("want ErrAggregateBundleSignerExpired, got %v", err)
	}
}

// 4b. Expired membership docs reject even when the delegation
// itself is still inside its window.
func TestAggregate_MembershipExpired(t *testing.T) {
	memb, deleg, bs, kps := sealedCell(t)
	memb.RuleSet.ValidUntilUnix = 1740000000
	memb.AdminSignatures = nil
	for _, i := range []int{0, 1} {
		s, _ := bundle.SignCellMembership(memb, i, kps[i].Priv)
		memb.AdminSignatures = append(memb.AdminSignatures, s)
	}
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
		Now:    time.Unix(1750000000, 0).UTC(),
	})
	if !errors.Is(err, ErrAggregateMembershipExpired) {
		t.Fatalf("want ErrAggregateMembershipExpired, got %v", err)
	}
}

// 5. Wrong bundle-signer key rejects.
func TestAggregate_WrongBundleSignerKey(t *testing.T) {
	memb, deleg, _, _ := sealedCell(t)
	other, _ := NewBundleSigner()
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: other,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err == nil {
		t.Fatal("expected wrong-key error")
	}
}

// 6. Aggregate output's manifest signature verifies under the
// bundle-signer pubkey via VerifyBundle.
func TestAggregate_ManifestSignatureVerifiesUnderBundleSigner(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	out, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes:    []MemberRoute{minimalRoute("r-1")},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		Now:       time.Unix(1735689700, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseSBP(t, out.SBPBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyManifest(parsed.Manifest, parsed.Signature, ed25519.PublicKey(parsed.PublisherPub)); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

// 7. BundleSigner fingerprint matches the manifest publisher fp.
func TestAggregate_BundleSignerFPMatchesManifest(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	out, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseSBP(t, out.SBPBytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Manifest.Publisher.KeyFingerprintHex != out.BundleSignerFPHex {
		t.Fatalf("manifest fp %q != aggregate fp %q", parsed.Manifest.Publisher.KeyFingerprintHex, out.BundleSignerFPHex)
	}
}

// 8. Default BundleType is "relay_pack" when input is empty.
func TestAggregate_DefaultBundleType(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	out, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseSBP(t, out.SBPBytes)
	if parsed.Manifest.Bundle.Type != "relay_pack" {
		t.Fatalf("bundle.type = %q want relay_pack", parsed.Manifest.Bundle.Type)
	}
}

// 9. Aggregated bundle's spec_version is 4 (UNCHANGED).
func TestAggregate_SpecVersionUnchanged(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	out, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseSBP(t, out.SBPBytes)
	if parsed.Manifest.SpecVersion != 4 {
		t.Fatalf("spec_version = %d want 4 (FRP-11 invariant 32)", parsed.Manifest.SpecVersion)
	}
}

// 10. Embedded membership + delegation JSON round-trip equals input.
func TestAggregate_EmbeddedDocsRoundTripEqual(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	out, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseSBP(t, out.SBPBytes)
	pmemb, pdeleg, err := bundle.ParseCellDocs(parsed)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(memb)
	b, _ := json.Marshal(*pmemb)
	if string(a) != string(b) {
		t.Fatalf("membership round-trip not byte-equal\n%s\nvs\n%s", a, b)
	}
	c, _ := json.Marshal(deleg)
	d, _ := json.Marshal(*pdeleg)
	if string(c) != string(d) {
		t.Fatalf("delegation round-trip not byte-equal\n%s\nvs\n%s", c, d)
	}
}

// 11. Aggregator injects signed per-route inner provenance, linking
// the aggregate route back to a membership entry.
func TestAggregate_InjectsInnerProvenance(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	out, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{minimalRoute("r-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseSBP(t, out.SBPBytes)
	entry, err := bundle.ParseRelayPackEntry(parsed.Manifest.Routes[0].FamilySpecificConfig)
	if err != nil {
		t.Fatal(err)
	}
	if entry.InnerProvenance == nil {
		t.Fatal("missing inner provenance")
	}
	if entry.InnerProvenance.PublisherFPHex != "9f3a" || entry.InnerProvenance.SubkeyFPHex != "1c2b" {
		t.Fatalf("wrong provenance: %+v", entry.InnerProvenance)
	}
}

// 12. Missing route profile bytes rejects before producing a broken
// aggregate that would fail VerifyBundle.
func TestAggregate_MissingProfileRejects(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	r := minimalRoute("r-1")
	r.ProfileBytes = nil
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{r},
	})
	if !errors.Is(err, ErrAggregateMissingProfile) {
		t.Fatalf("want ErrAggregateMissingProfile, got %v", err)
	}
}

// 13. A route can only be aggregated if its provenance names a
// member listed in the cell membership doc.
func TestAggregate_InnerPublisherMustBeMember(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	r := minimalRoute("r-1")
	r.PublisherFPHex = "not-a-member"
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{r},
	})
	if !errors.Is(err, ErrAggregateInnerPublisherNotMember) {
		t.Fatalf("want ErrAggregateInnerPublisherNotMember, got %v", err)
	}
}

// 14. Member routes must be RelayPack routes so the signed manifest
// has a place to carry cell inner provenance.
func TestAggregate_MissingRelayPackRejects(t *testing.T) {
	memb, deleg, bs, _ := sealedCell(t)
	r := minimalRoute("r-1")
	r.Route.FamilySpecificConfig = nil
	_, err := Aggregate(AggregateInput{
		CellID: memb.CellID, Membership: memb, Delegation: deleg, BundleSigner: bs,
		Routes: []MemberRoute{r},
	})
	if !errors.Is(err, ErrAggregateMissingRelayPack) {
		t.Fatalf("want ErrAggregateMissingRelayPack, got %v", err)
	}
}
