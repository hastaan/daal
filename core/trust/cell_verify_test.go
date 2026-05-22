package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	bundle "daal/bundle-go/bundle"
)

func mkAdmins(t *testing.T, n int) ([]string, []ed25519.PrivateKey) {
	t.Helper()
	pubs := make([]string, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pubs[i] = base64.RawStdEncoding.EncodeToString(pk)
		privs[i] = sk
	}
	return pubs, privs
}

func sealedBundle(t *testing.T) *bundle.Bundle {
	t.Helper()
	pubs, privs := mkAdmins(t, 3)
	memb := bundle.CellMembershipDoc{
		CellID:       "cell-test-1",
		AdminPubkeys: pubs,
		QuorumM:      2,
		Members: []bundle.CellMember{
			{PublisherFPHex: "9f3a", SubkeyFPHex: "1c2b", JoinedAtUnix: 1},
		},
		RuleSet: bundle.CellRuleSet{
			CellMaxDepth:   1,
			AbuseRoute:     "cell-internal",
			ValidUntilUnix: 1999999999,
		},
	}
	for _, i := range []int{0, 1} {
		s, _ := bundle.SignCellMembership(memb, i, privs[i])
		memb.AdminSignatures = append(memb.AdminSignatures, s)
	}
	bsPub, _, _ := ed25519.GenerateKey(rand.Reader)
	deleg := bundle.CellDelegationDoc{
		CellID:             "cell-test-1",
		BundleSignerPubkey: base64.RawStdEncoding.EncodeToString(bsPub),
		ValidFromUnix:      1735689600,
		ValidUntilUnix:     1893456000,
	}
	for _, i := range []int{0, 2} {
		s, _ := bundle.SignCellDelegation(deleg, i, privs[i])
		deleg.AdminSignatures = append(deleg.AdminSignatures, s)
	}
	memBytes, _ := json.Marshal(memb)
	delBytes, _ := json.Marshal(deleg)
	bsFP := bundle.PublisherFingerprint(bsPub)
	return &bundle.Bundle{
		Manifest: bundle.Manifest{
			SpecVersion: 4,
			Publisher:   bundle.PublisherInfo{KeyFingerprintHex: bsFP.Hex},
		},
		PublisherPub:       bsPub,
		CellMembershipJSON: memBytes,
		CellDelegationJSON: delBytes,
	}
}

func now() time.Time { return time.Unix(1750000000, 0).UTC() }

func cellRouteConfig(t *testing.T, publisherFPHex, subkeyFPHex string) json.RawMessage {
	t.Helper()
	entry := bundle.RelayPackEntry{
		ExposureMode:     "direct_vps",
		FamilyClass:      "vps-native",
		ProbingRiskClass: "low",
		PublicRiskTags:   []string{"public_ip:5.75.0.1"},
		OriginRiskTags:   []string{},
		InnerProvenance: &bundle.CellInnerProvenance{
			PublisherFPHex: publisherFPHex,
			SubkeyFPHex:    subkeyFPHex,
		},
	}
	raw, err := json.Marshal(map[string]any{"_relaypack": entry})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// 1. Non-cell bundle returns ErrCellChainNotPresent.
func TestVerifyCellChain_NoCellDocs(t *testing.T) {
	_, _, _, err := VerifyCellChain(&bundle.Bundle{}, now())
	if !errors.Is(err, ErrCellChainNotPresent) {
		t.Fatalf("want ErrCellChainNotPresent, got %v", err)
	}
}

// 2. Happy path: chain walks; ChainStatus populated correctly.
func TestVerifyCellChain_HappyPath(t *testing.T) {
	b := sealedBundle(t)
	st, memb, deleg, err := VerifyCellChain(b, now())
	if err != nil {
		t.Fatalf("VerifyCellChain: %v", err)
	}
	if st.CellID != "cell-test-1" {
		t.Fatalf("cell_id = %q", st.CellID)
	}
	if st.QuorumM != 2 || st.QuorumN != 3 {
		t.Fatalf("quorum = %d-of-%d", st.QuorumM, st.QuorumN)
	}
	if memb == nil || deleg == nil {
		t.Fatal("expected non-nil docs")
	}
	if st.BundleSignerFPHex == "" {
		t.Fatal("expected BundleSignerFPHex")
	}
}

// 3. Bundle-signer fp mismatch rejects.
func TestVerifyCellChain_BundleSignerMismatch(t *testing.T) {
	b := sealedBundle(t)
	b.Manifest.Publisher.KeyFingerprintHex = "deadbeef"
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, ErrCellChainBundleSignerMismatch) {
		t.Fatalf("want ErrCellChainBundleSignerMismatch, got %v", err)
	}
}

// 4. Delegation outside window rejects.
func TestVerifyCellChain_OutOfWindow(t *testing.T) {
	b := sealedBundle(t)
	_, _, _, err := VerifyCellChain(b, time.Unix(1893456001, 0).UTC())
	if !errors.Is(err, ErrCellChainDelegationOutOfWindow) {
		t.Fatalf("want ErrCellChainDelegationOutOfWindow, got %v", err)
	}
}

// 4b. Membership expiry is enforced independently of the delegation window.
func TestVerifyCellChain_MembershipExpired(t *testing.T) {
	b := sealedBundle(t)
	var memb bundle.CellMembershipDoc
	if err := json.Unmarshal(b.CellMembershipJSON, &memb); err != nil {
		t.Fatal(err)
	}
	memb.RuleSet.ValidUntilUnix = 1740000000
	memb.AdminSignatures = nil
	pubs, privs := mkAdmins(t, 3)
	memb.AdminPubkeys = pubs
	for _, i := range []int{0, 1} {
		s, _ := bundle.SignCellMembership(memb, i, privs[i])
		memb.AdminSignatures = append(memb.AdminSignatures, s)
	}
	b.CellMembershipJSON, _ = json.Marshal(memb)
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, ErrCellChainMembershipExpired) {
		t.Fatalf("want ErrCellChainMembershipExpired, got %v", err)
	}
}

// 4c. Even when the manifest fingerprint is empty, the delegated
// bundle-signer key must match the actual publisher.pub bytes.
func TestVerifyCellChain_BundleSignerPubkeyMismatchEvenWithoutManifestFP(t *testing.T) {
	b := sealedBundle(t)
	b.Manifest.Publisher.KeyFingerprintHex = ""
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	b.PublisherPub = otherPub
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, ErrCellChainBundleSignerMismatch) {
		t.Fatalf("want ErrCellChainBundleSignerMismatch, got %v", err)
	}
}

// 4d. Cell aggregate routes must carry per-candidate inner
// provenance metadata.
func TestVerifyCellChain_RouteMissingInnerProvenance(t *testing.T) {
	b := sealedBundle(t)
	b.Manifest.Routes = []bundle.RouteManifestEntry{{
		ID:                   "r-1",
		TransportFamily:      "vless-reality",
		ScarcityClass:        "normal",
		ConfigPath:           "routes/r-1.json",
		ValidUntil:           "2026-12-31T00:00:00Z",
		FamilySpecificConfig: json.RawMessage(`{"_relaypack":{"exposure_mode":"direct_vps","family_class":"vps-native","probing_risk_class":"low","public_risk_tags":["public_ip:5.75.0.1"],"origin_risk_tags":[]}}`),
	}}
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, ErrCellChainInnerProvenanceMissing) {
		t.Fatalf("want ErrCellChainInnerProvenanceMissing, got %v", err)
	}
}

// 4e. Provenance must point at a member listed in the membership doc.
func TestVerifyCellChain_RouteInnerPublisherMustBeMember(t *testing.T) {
	b := sealedBundle(t)
	b.Manifest.Routes = []bundle.RouteManifestEntry{{
		ID:                   "r-1",
		TransportFamily:      "vless-reality",
		ScarcityClass:        "normal",
		ConfigPath:           "routes/r-1.json",
		ValidUntil:           "2026-12-31T00:00:00Z",
		FamilySpecificConfig: cellRouteConfig(t, "not-a-member", "1c2b"),
	}}
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, ErrCellChainInnerPublisherNotMember) {
		t.Fatalf("want ErrCellChainInnerPublisherNotMember, got %v", err)
	}
}

// 4f. Matching per-route provenance is accepted.
func TestVerifyCellChain_RouteInnerPublisherMemberHappyPath(t *testing.T) {
	b := sealedBundle(t)
	b.Manifest.Routes = []bundle.RouteManifestEntry{{
		ID:                   "r-1",
		TransportFamily:      "vless-reality",
		ScarcityClass:        "normal",
		ConfigPath:           "routes/r-1.json",
		ValidUntil:           "2026-12-31T00:00:00Z",
		FamilySpecificConfig: cellRouteConfig(t, "9f3a", "1c2b"),
	}}
	if _, _, _, err := VerifyCellChain(b, now()); err != nil {
		t.Fatalf("VerifyCellChain: %v", err)
	}
}

// 5. Tampered membership signature rejects.
func TestVerifyCellChain_TamperedMembership(t *testing.T) {
	b := sealedBundle(t)
	var memb bundle.CellMembershipDoc
	if err := json.Unmarshal(b.CellMembershipJSON, &memb); err != nil {
		t.Fatal(err)
	}
	// Strip one valid signature → quorum drops below M.
	memb.AdminSignatures = memb.AdminSignatures[:1]
	memb.AdminSignatures[0].SignatureB64 = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	b.CellMembershipJSON, _ = json.Marshal(memb)
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, bundle.ErrCellAdminQuorumNotMet) {
		t.Fatalf("want ErrCellAdminQuorumNotMet, got %v", err)
	}
}

// 6. Membership-only without delegation rejects (parse-side).
func TestVerifyCellChain_MembershipOnly(t *testing.T) {
	b := sealedBundle(t)
	b.CellDelegationJSON = nil
	_, _, _, err := VerifyCellChain(b, now())
	if !errors.Is(err, bundle.ErrCellDelegationMalformed) {
		t.Fatalf("want ErrCellDelegationMalformed, got %v", err)
	}
}

// 7. Nil bundle rejects (defensive).
func TestVerifyCellChain_NilBundle(t *testing.T) {
	_, _, _, err := VerifyCellChain(nil, now())
	if !errors.Is(err, ErrCellChainNotPresent) {
		t.Fatalf("want ErrCellChainNotPresent, got %v", err)
	}
}

// ---- Label store tests ----

func mkLabelStore(t *testing.T) *MemoryLabelStore {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	s, err := NewMemoryLabelStore(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// 8. NewMemoryLabelStore rejects wrong key size.
func TestLabelStore_WrongKeySize(t *testing.T) {
	if _, err := NewMemoryLabelStore(make([]byte, 16)); err == nil {
		t.Fatal("want error for 16-byte key")
	}
}

// 9. Set/Get round-trip.
func TestLabelStore_SetGet(t *testing.T) {
	s := mkLabelStore(t)
	if err := s.Set("cell-fp-1", "family"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("cell-fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "family" {
		t.Fatalf("got %q", got)
	}
}

// 10. Get on missing key returns ErrLabelNotFound (distinct from
// empty-string label).
func TestLabelStore_GetMissing(t *testing.T) {
	s := mkLabelStore(t)
	_, err := s.Get("cell-fp-2")
	if !errors.Is(err, ErrLabelNotFound) {
		t.Fatalf("want ErrLabelNotFound, got %v", err)
	}
}

// 11. Delete removes the label entirely.
func TestLabelStore_Delete(t *testing.T) {
	s := mkLabelStore(t)
	s.Set("cell-fp-3", "friends")
	s.Delete("cell-fp-3")
	if _, err := s.Get("cell-fp-3"); !errors.Is(err, ErrLabelNotFound) {
		t.Fatalf("want ErrLabelNotFound, got %v", err)
	}
}

// 12. SerializedCiphertext + LoadCiphertext round-trips.
func TestLabelStore_CiphertextRoundTrip(t *testing.T) {
	s := mkLabelStore(t)
	s.Set("cell-fp-4", "org-acme")
	ct, err := s.SerializedCiphertext("cell-fp-4")
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) == "org-acme" {
		t.Fatal("ciphertext equals plaintext")
	}
	// Fresh store → load → recover.
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	other, _ := NewMemoryLabelStore(key)
	if err := other.LoadCiphertext("cell-fp-4", ct); err == nil {
		t.Fatal("expected AEAD failure under different key")
	}
	// Same store → re-load → recovers value.
	if err := s.LoadCiphertext("cell-fp-4", ct); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("cell-fp-4")
	if got != "org-acme" {
		t.Fatalf("recovered %q", got)
	}
}

// 13. SerializedCiphertext on missing key returns ErrLabelNotFound.
func TestLabelStore_SerializedMissing(t *testing.T) {
	s := mkLabelStore(t)
	if _, err := s.SerializedCiphertext("cell-fp-5"); !errors.Is(err, ErrLabelNotFound) {
		t.Fatalf("want ErrLabelNotFound, got %v", err)
	}
}

// 14. OPSec: empty Set rejects empty cellIDFPHex (defence-in-depth
// — cell-id-fp is never empty in production but a bug elsewhere
// must not silently store labels under "").
func TestLabelStore_RejectsEmptyKey(t *testing.T) {
	s := mkLabelStore(t)
	if err := s.Set("", "family"); err == nil {
		t.Fatal("want error for empty cellIDFPHex")
	}
}
