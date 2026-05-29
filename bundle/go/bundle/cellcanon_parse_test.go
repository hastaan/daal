package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// helper: build a valid {membership,delegation} pair as JSON bytes.
func buildPair(t *testing.T) (membJSON, delegJSON []byte, memb CellMembershipDoc, deleg CellDelegationDoc) {
	t.Helper()
	pubs, privs := genAdmins(t, 3)
	memb = baseDoc(pubs, 2)
	memb.AdminSignatures = signWith(t, memb, privs, 0, 1)
	bsPub, _, _ := ed25519.GenerateKey(rand.Reader)
	deleg = CellDelegationDoc{
		CellID:             memb.CellID,
		BundleSignerPubkey: encodePubkeyB64(bsPub),
		ValidFromUnix:      1735689600,
		ValidUntilUnix:     1767225600,
	}
	for _, i := range []int{0, 2} {
		s, err := SignCellDelegation(deleg, i, privs[i])
		if err != nil {
			t.Fatal(err)
		}
		deleg.AdminSignatures = append(deleg.AdminSignatures, s)
	}
	mb, err := json.Marshal(memb)
	if err != nil {
		t.Fatal(err)
	}
	db, err := json.Marshal(deleg)
	if err != nil {
		t.Fatal(err)
	}
	return mb, db, memb, deleg
}

// 1. Both files absent → (nil, nil, nil) (non-cell bundle).
func TestParseCellDocs_NeitherPresent(t *testing.T) {
	b := &Bundle{}
	memb, deleg, err := ParseCellDocs(b)
	if err != nil || memb != nil || deleg != nil {
		t.Fatalf("want (nil, nil, nil), got (%v, %v, %v)", memb, deleg, err)
	}
}

// 2. Both files present + valid → typed values populated; cell_id matches.
func TestParseCellDocs_HappyPath(t *testing.T) {
	mb, db, _, _ := buildPair(t)
	b := &Bundle{CellMembershipJSON: mb, CellDelegationJSON: db}
	memb, deleg, err := ParseCellDocs(b)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if memb == nil || deleg == nil {
		t.Fatal("expected non-nil docs")
	}
	if memb.CellID != deleg.CellID || memb.CellID == "" {
		t.Fatalf("cell_id mismatch / empty: %q / %q", memb.CellID, deleg.CellID)
	}
}

// 3. Membership-only (delegation missing) rejects.
func TestParseCellDocs_MembershipOnly(t *testing.T) {
	mb, _, _, _ := buildPair(t)
	b := &Bundle{CellMembershipJSON: mb}
	_, _, err := ParseCellDocs(b)
	if !errors.Is(err, ErrCellDelegationMalformed) {
		t.Fatalf("want ErrCellDelegationMalformed, got %v", err)
	}
}

// 4. Delegation-only (membership missing) rejects.
func TestParseCellDocs_DelegationOnly(t *testing.T) {
	_, db, _, _ := buildPair(t)
	b := &Bundle{CellDelegationJSON: db}
	_, _, err := ParseCellDocs(b)
	if !errors.Is(err, ErrCellMembershipMalformed) {
		t.Fatalf("want ErrCellMembershipMalformed, got %v", err)
	}
}

// 5. Malformed JSON in membership file rejects.
func TestParseCellDocs_MembershipMalformedJSON(t *testing.T) {
	_, db, _, _ := buildPair(t)
	b := &Bundle{CellMembershipJSON: []byte("{not-json"), CellDelegationJSON: db}
	_, _, err := ParseCellDocs(b)
	if !errors.Is(err, ErrCellMembershipMalformed) {
		t.Fatalf("want ErrCellMembershipMalformed, got %v", err)
	}
}

// 6. cell_id mismatch between membership and delegation rejects.
func TestParseCellDocs_CellIDMismatch(t *testing.T) {
	mb, _, _, deleg := buildPair(t)
	deleg.CellID = "different-cell"
	db2, err := json.Marshal(deleg)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{CellMembershipJSON: mb, CellDelegationJSON: db2}
	_, _, err = ParseCellDocs(b)
	if !errors.Is(err, ErrCellDelegationCellIDMismatch) {
		t.Fatalf("want ErrCellDelegationCellIDMismatch, got %v", err)
	}
}

// Bonus: shape-failure (out-of-range pubkey) propagates from
// validateCellMembershipShape.
func TestParseCellDocs_ShapeFailureOutOfRangePubkey(t *testing.T) {
	mb, db, memb, _ := buildPair(t)
	_ = mb
	memb.AdminPubkeys[0] = base64.RawStdEncoding.EncodeToString([]byte("too-short"))
	mb2, _ := json.Marshal(memb)
	b := &Bundle{CellMembershipJSON: mb2, CellDelegationJSON: db}
	_, _, err := ParseCellDocs(b)
	if !errors.Is(err, ErrCellAdminPubkeyMalformed) {
		t.Fatalf("want ErrCellAdminPubkeyMalformed, got %v", err)
	}
}
