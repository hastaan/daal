package cell

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	bundle "daal/bundle-go/bundle"
)

// 1. Abuse ticket happy path: SignAbuseTicket -> VerifyAbuseTicket.
func TestAbuseTicket_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t1 := AbuseTicket{
		CellID:                 "cell-1",
		ReporterPublisherFPHex: "9f3a",
		RevokedPublisherFPHex:  "8e22",
		Reason:                 "phishing-route",
		ObservedAtUnix:         1735689700,
	}
	signed, err := SignAbuseTicket(t1, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAbuseTicket(signed, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 2. Abuse ticket missing required fields rejects.
func TestAbuseTicket_MissingFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := SignAbuseTicket(AbuseTicket{CellID: "c1"}, priv); !errors.Is(err, ErrAbuseTicketEmpty) {
		t.Fatalf("want ErrAbuseTicketEmpty, got %v", err)
	}
}

// 3. Abuse ticket tampered signature rejects.
func TestAbuseTicket_TamperedSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t1 := AbuseTicket{
		CellID: "cell-1", ReporterPublisherFPHex: "9f3a",
		RevokedPublisherFPHex: "8e22", Reason: "phishing",
	}
	signed, _ := SignAbuseTicket(t1, priv)
	signed.Reason = "tampered" // changes canonical bytes; signature no longer valid
	if err := VerifyAbuseTicket(signed, pub); !errors.Is(err, ErrAbuseTicketUnsigned) {
		t.Fatalf("want ErrAbuseTicketUnsigned, got %v", err)
	}
}

// 4. Cell revocation happy path: collect M-of-N admin sigs, verify.
func TestCellRevocation_HappyPath(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("cell-1", pubs, 2, ruleSet())
	mb.Sign(0, kps[0].Priv)
	mb.Sign(1, kps[1].Priv)
	memb, _ := mb.Finalize()
	rev := CellRevocationDoc{
		CellID: "cell-1", RevokedPublisherFPHex: "9f3a",
		Reason: "abuse", IssuedAtUnix: 1735689700,
	}
	for _, i := range []int{0, 2} {
		s, _ := SignCellRevocation(rev, i, kps[i].Priv)
		rev.AdminSignatures = append(rev.AdminSignatures, s)
	}
	if err := VerifyCellRevocation(memb, rev); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 5. Cell revocation below quorum rejects.
func TestCellRevocation_BelowQuorum(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("cell-1", pubs, 2, ruleSet())
	mb.Sign(0, kps[0].Priv)
	mb.Sign(1, kps[1].Priv)
	memb, _ := mb.Finalize()
	rev := CellRevocationDoc{CellID: "cell-1", RevokedPublisherFPHex: "9f3a", Reason: "abuse"}
	s, _ := SignCellRevocation(rev, 0, kps[0].Priv)
	rev.AdminSignatures = []bundle.CellAdminSignature{s}
	if err := VerifyCellRevocation(memb, rev); !errors.Is(err, bundle.ErrCellAdminQuorumNotMet) {
		t.Fatalf("want ErrCellAdminQuorumNotMet, got %v", err)
	}
}

// 6. Cell revocation cell_id mismatch rejects.
func TestCellRevocation_CellIDMismatch(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("cell-1", pubs, 2, ruleSet())
	mb.Sign(0, kps[0].Priv)
	mb.Sign(1, kps[1].Priv)
	memb, _ := mb.Finalize()
	rev := CellRevocationDoc{CellID: "cell-OTHER", RevokedPublisherFPHex: "9f3a", Reason: "abuse"}
	for _, i := range []int{0, 1} {
		s, _ := SignCellRevocation(rev, i, kps[i].Priv)
		rev.AdminSignatures = append(rev.AdminSignatures, s)
	}
	if err := VerifyCellRevocation(memb, rev); !errors.Is(err, bundle.ErrCellDelegationCellIDMismatch) {
		t.Fatalf("want cell_id mismatch, got %v", err)
	}
}

// 7. Cell revocation duplicate admin idx rejects.
func TestCellRevocation_DuplicateIdx(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("cell-1", pubs, 2, ruleSet())
	mb.Sign(0, kps[0].Priv)
	mb.Sign(1, kps[1].Priv)
	memb, _ := mb.Finalize()
	rev := CellRevocationDoc{CellID: "cell-1", RevokedPublisherFPHex: "9f3a", Reason: "abuse"}
	s, _ := SignCellRevocation(rev, 0, kps[0].Priv)
	rev.AdminSignatures = []bundle.CellAdminSignature{s, s}
	if err := VerifyCellRevocation(memb, rev); !errors.Is(err, bundle.ErrCellAdminQuorumDuplicateIdx) {
		t.Fatalf("want ErrCellAdminQuorumDuplicateIdx, got %v", err)
	}
}

// 8. CanonicalCellRevocationBytes does NOT include admin_signatures.
func TestCanonicalCellRevocation_StripsSignatures(t *testing.T) {
	rev := CellRevocationDoc{
		CellID: "cell-1", RevokedPublisherFPHex: "9f3a", Reason: "abuse",
		AdminSignatures: []bundle.CellAdminSignature{{AdminPubkeyIdx: 0, SignatureB64: "deadbeef"}},
	}
	bytes, err := CanonicalCellRevocationBytes(rev)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(bytes), "admin_signatures") {
		t.Fatalf("canonical bytes contain admin_signatures: %s", bytes)
	}
}

// 9. Empty fields on CellRevocationDoc reject in VerifyCellRevocation.
func TestCellRevocation_EmptyFieldsReject(t *testing.T) {
	_, pubs := makeAdmins(t, 3)
	memb := bundle.CellMembershipDoc{CellID: "cell-1", AdminPubkeys: pubs, QuorumM: 2}
	if err := VerifyCellRevocation(memb, CellRevocationDoc{CellID: "cell-1"}); !errors.Is(err, ErrRevocationDocEmpty) {
		t.Fatalf("want ErrRevocationDocEmpty, got %v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
