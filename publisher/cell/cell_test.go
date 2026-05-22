package cell

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	bundle "daal/bundle-go/bundle"
)

func makeAdmins(t *testing.T, n int) ([]AdminKeypair, []string) {
	t.Helper()
	kps := make([]AdminKeypair, n)
	pubs := make([]string, n)
	for i := 0; i < n; i++ {
		kp, err := NewAdminKeypair()
		if err != nil {
			t.Fatal(err)
		}
		kps[i] = kp
		pubs[i] = kp.PubB64()
	}
	return kps, pubs
}

func ruleSet() bundle.CellRuleSet {
	return bundle.CellRuleSet{
		CellMaxDepth:   1,
		AbuseRoute:     "cell-internal",
		ValidUntilUnix: 1999999999,
	}
}

// 1. NewAdminKeypair produces a working ed25519 keypair distinct from
// any publisher key (it's freshly generated per call).
func TestNewAdminKeypair_FreshPerCall(t *testing.T) {
	a, err := NewAdminKeypair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAdminKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if a.PubB64() == b.PubB64() {
		t.Fatal("two NewAdminKeypair calls produced equal pubkeys")
	}
	if got := len(a.Pub); got != ed25519.PublicKeySize {
		t.Fatalf("pub size = %d want %d", got, ed25519.PublicKeySize)
	}
}

// 2. DefaultQuorum returns ceil((N+1)/2).
func TestDefaultQuorum_CeilFormula(t *testing.T) {
	cases := []struct{ n, want int }{
		{1, 1}, {2, 2}, {3, 2}, {4, 3}, {5, 3}, {6, 4}, {7, 4}, {25, 13},
	}
	for _, c := range cases {
		if got := DefaultQuorum(c.n); got != c.want {
			t.Errorf("DefaultQuorum(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

// 3. NewMembership rejects N=0 and N>25.
func TestNewMembership_NOutOfRange(t *testing.T) {
	if _, err := NewMembership("c1", nil, 1, ruleSet()); !errors.Is(err, ErrAdminCountOutOfRange) {
		t.Fatalf("want ErrAdminCountOutOfRange for N=0, got %v", err)
	}
	tooMany := make([]string, 26)
	for i := range tooMany {
		kp, _ := NewAdminKeypair()
		tooMany[i] = kp.PubB64()
	}
	if _, err := NewMembership("c1", tooMany, 1, ruleSet()); !errors.Is(err, ErrAdminCountOutOfRange) {
		t.Fatalf("want ErrAdminCountOutOfRange for N=26, got %v", err)
	}
}

// 4. NewMembership rejects M out of range.
func TestNewMembership_MOutOfRange(t *testing.T) {
	_, pubs := makeAdmins(t, 3)
	if _, err := NewMembership("c1", pubs, 5, ruleSet()); !errors.Is(err, ErrQuorumOutOfRange) {
		t.Fatalf("want ErrQuorumOutOfRange for M>N, got %v", err)
	}
	if _, err := NewMembership("c1", pubs, 0, ruleSet()); !errors.Is(err, ErrQuorumOutOfRange) {
		t.Fatalf("want ErrQuorumOutOfRange for M=0, got %v", err)
	}
}

// 5. NewMembership rejects malformed pubkey base64.
func TestNewMembership_MalformedPubkey(t *testing.T) {
	bad := []string{"not-base64-!!!"}
	if _, err := NewMembership("c1", bad, 1, ruleSet()); !errors.Is(err, bundle.ErrCellAdminPubkeyMalformed) {
		t.Fatalf("want ErrCellAdminPubkeyMalformed, got %v", err)
	}
}

// 6. AddMember dedup on (publisher_fp_hex, subkey_fp_hex).
func TestAddMember_Dedup(t *testing.T) {
	_, pubs := makeAdmins(t, 3)
	mb, err := NewMembership("c1", pubs, 2, ruleSet())
	if err != nil {
		t.Fatal(err)
	}
	m := bundle.CellMember{PublisherFPHex: "9f3a", SubkeyFPHex: "1c2b", JoinedAtUnix: 1}
	mb.AddMember(m)
	mb.AddMember(m)
	if len(mb.doc.Members) != 1 {
		t.Fatalf("want dedup; got %d entries", len(mb.doc.Members))
	}
}

// 7. Membership Sign + Finalize 2-of-3 happy path.
func TestMembership_HappyPath(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, err := NewMembership("c1", pubs, 2, ruleSet())
	if err != nil {
		t.Fatal(err)
	}
	mb.AddMember(bundle.CellMember{PublisherFPHex: "9f3a", SubkeyFPHex: "1c2b", JoinedAtUnix: 1})
	if _, err := mb.Sign(0, kps[0].Priv); err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Sign(2, kps[2].Priv); err != nil {
		t.Fatal(err)
	}
	doc, err := mb.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := bundle.VerifyCellMembershipQuorum(doc); err != nil {
		t.Fatalf("doc not verifiable: %v", err)
	}
}

// 8. Sign rejects priv-key/pubkey mismatch (admin tries to sign as
// another admin's idx).
func TestMembership_SignKeyMismatch(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, err := NewMembership("c1", pubs, 2, ruleSet())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Sign(0, kps[1].Priv); !errors.Is(err, ErrAdminKeyMismatch) {
		t.Fatalf("want ErrAdminKeyMismatch, got %v", err)
	}
}

// 9. Finalize without enough signatures rejects.
func TestMembership_FinalizeBelowQuorum(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("c1", pubs, 2, ruleSet())
	if _, err := mb.Sign(0, kps[0].Priv); err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Finalize(); !errors.Is(err, ErrInsufficientQuorum) {
		t.Fatalf("want ErrInsufficientQuorum, got %v", err)
	}
}

// 10. Sign re-call by same idx replaces prior signature (idempotent).
func TestMembership_SignReSignReplaces(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("c1", pubs, 2, ruleSet())
	mb.Sign(0, kps[0].Priv)
	mb.Sign(2, kps[2].Priv)
	mb.Sign(0, kps[0].Priv) // re-sign
	if got := len(mb.doc.AdminSignatures); got != 2 {
		t.Fatalf("want 2 sigs after re-sign, got %d", got)
	}
}

// 11. Delegation happy path: builder + finalize verify under
// VerifyCellDelegationQuorum.
func TestDelegation_HappyPath(t *testing.T) {
	kps, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("c1", pubs, 2, ruleSet())
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
	db, err := NewDelegation(memb, bs.PubB64(), 1735689600, 1767225600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Sign(0, kps[0].Priv); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Sign(2, kps[2].Priv); err != nil {
		t.Fatal(err)
	}
	deleg, err := db.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyCellDelegationQuorum(memb, deleg); err != nil {
		t.Fatalf("delegation not verifiable: %v", err)
	}
}

// 12. NewDelegation rejects malformed bundle-signer pubkey.
func TestDelegation_MalformedSignerPubkey(t *testing.T) {
	_, pubs := makeAdmins(t, 3)
	mb, _ := NewMembership("c1", pubs, 2, ruleSet())
	memb := bundle.CellMembershipDoc{CellID: "c1", AdminPubkeys: pubs, QuorumM: 2}
	_ = mb
	bad := base64.RawStdEncoding.EncodeToString([]byte("short"))
	if _, err := NewDelegation(memb, bad, 1, 2); !errors.Is(err, bundle.ErrCellDelegationMalformed) {
		t.Fatalf("want ErrCellDelegationMalformed, got %v", err)
	}
	// Also reject backwards window.
	bs, _ := NewBundleSigner()
	if _, err := NewDelegation(memb, bs.PubB64(), 100, 50); !errors.Is(err, bundle.ErrCellDelegationMalformed) {
		t.Fatalf("want ErrCellDelegationMalformed for backwards window, got %v", err)
	}
}

// Sanity: ed25519.GenerateKey is reachable; rand.Reader produces.
var _ = rand.Reader
