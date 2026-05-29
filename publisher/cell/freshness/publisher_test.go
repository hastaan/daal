package freshness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	bundle "daal/bundle-go/bundle"
	deployFresh "daal/publisher/deploy/freshness"
)

func jsonUnmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }

// stubBackend is a test-only deployFresh.Backend that captures the
// bytes uploaded into a slice. The narrow FRP-9 Backend interface
// is Put(bytes) only — there's no per-key dispatch — so the stub
// records all puts in order.
type stubBackend struct {
	url   string
	puts  [][]byte
	fails error
}

func (s *stubBackend) PublicURL() string { return s.url }
func (s *stubBackend) Put(_ context.Context, b []byte) error {
	if s.fails != nil {
		return s.fails
	}
	s.puts = append(s.puts, append([]byte(nil), b...))
	return nil
}

var _ deployFresh.Backend = (*stubBackend)(nil)

func makeMembership(t *testing.T, cellID string) bundle.CellMembershipDoc {
	t.Helper()
	pubs := make([]string, 3)
	privs := make([]ed25519.PrivateKey, 3)
	for i := 0; i < 3; i++ {
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pubs[i] = base64.RawStdEncoding.EncodeToString(pk)
		privs[i] = sk
	}
	doc := bundle.CellMembershipDoc{
		CellID:       cellID,
		AdminPubkeys: pubs,
		QuorumM:      2,
		Members: []bundle.CellMember{
			{PublisherFPHex: "9f3a", SubkeyFPHex: "1c2b", JoinedAtUnix: 1},
		},
		RuleSet: bundle.CellRuleSet{CellMaxDepth: 1, AbuseRoute: "cell-internal", ValidUntilUnix: 1893456000},
	}
	for _, i := range []int{0, 2} {
		s, err := bundle.SignCellMembership(doc, i, privs[i])
		if err != nil {
			t.Fatal(err)
		}
		doc.AdminSignatures = append(doc.AdminSignatures, s)
	}
	return doc
}

// 1. New rejects nil backend.
func TestNew_NilBackend(t *testing.T) {
	if _, err := New(nil, "cell-1"); !errors.Is(err, ErrCellPublisherNoBackend) {
		t.Fatalf("want ErrCellPublisherNoBackend, got %v", err)
	}
}

// 2. New rejects empty cellID.
func TestNew_EmptyCellID(t *testing.T) {
	if _, err := New(&stubBackend{url: "https://x"}, ""); err == nil {
		t.Fatal("want error for empty cellID")
	}
}

// 3. PublishMembershipDoc happy path: stub captures bytes; verify
// JSON parses back into a quorum-valid doc.
func TestPublishMembershipDoc_HappyPath(t *testing.T) {
	bk := &stubBackend{url: "https://r2.example.com"}
	pub, err := New(bk, "cell-1")
	if err != nil {
		t.Fatal(err)
	}
	doc := makeMembership(t, "cell-1")
	if err := pub.PublishMembershipDoc(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	if len(bk.puts) != 1 {
		t.Fatalf("want 1 put, got %d", len(bk.puts))
	}
	var roundtrip bundle.CellMembershipDoc
	if err := jsonUnmarshal(bk.puts[0], &roundtrip); err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyCellMembershipQuorum(roundtrip); err != nil {
		t.Fatalf("round-trip quorum invalid: %v", err)
	}
}

// 4. PublishMembershipDoc rejects an unsigned doc (quorum invalid).
func TestPublishMembershipDoc_RejectsUnsigned(t *testing.T) {
	bk := &stubBackend{url: "https://r2.example.com"}
	pub, _ := New(bk, "cell-1")
	doc := makeMembership(t, "cell-1")
	doc.AdminSignatures = nil
	if err := pub.PublishMembershipDoc(context.Background(), doc); err == nil {
		t.Fatal("want error for unsigned doc")
	}
}

// 5. PublishDelegationDoc round-trips through the stub.
func TestPublishDelegationDoc_HappyPath(t *testing.T) {
	bk := &stubBackend{url: "https://r2.example.com"}
	pub, _ := New(bk, "cell-1")
	deleg := bundle.CellDelegationDoc{
		CellID:             "cell-1",
		BundleSignerPubkey: base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		ValidFromUnix:      1735689600,
		ValidUntilUnix:     1893456000,
	}
	if err := pub.PublishDelegationDoc(context.Background(), deleg); err != nil {
		t.Fatal(err)
	}
	if len(bk.puts) != 1 {
		t.Fatalf("want 1 put, got %d", len(bk.puts))
	}
}

// 6. PublishDirectory rejects empty bytes.
func TestPublishDirectory_RejectsEmpty(t *testing.T) {
	bk := &stubBackend{url: "https://r2.example.com"}
	pub, _ := New(bk, "cell-1")
	if err := pub.PublishDirectory(context.Background(), nil); err == nil {
		t.Fatal("want error for empty directory bytes")
	}
}

// 7. PublishRevocationList accepts nil → "[]".
func TestPublishRevocationList_NilToEmptyArray(t *testing.T) {
	bk := &stubBackend{url: "https://r2.example.com"}
	pub, _ := New(bk, "cell-1")
	if err := pub.PublishRevocationList(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if string(bk.puts[0]) != "[]" {
		t.Fatalf("want []; got %q", bk.puts[0])
	}
}

// 8. CellDirectoryURL composes correctly + R2 / GH-Pages adapters
// produce equivalent output (they wrap New).
func TestCellDirectoryURL_Composition(t *testing.T) {
	bk := &stubBackend{url: "https://r2.example.com/some-bucket"}
	pub, _ := New(bk, "moms-extended-family-may-2026")
	want := "https://r2.example.com/some-bucket/cell/moms-extended-family-may-2026/directory.json"
	if got := pub.CellDirectoryURL(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	r2Pub, err := NewR2Adapter(bk, "moms-extended-family-may-2026")
	if err != nil {
		t.Fatal(err)
	}
	if r2Pub.CellDirectoryURL() != want {
		t.Fatal("R2 adapter URL mismatch")
	}
	ghPub, err := NewGHPagesAdapter(bk, "moms-extended-family-may-2026")
	if err != nil {
		t.Fatal(err)
	}
	if ghPub.CellDirectoryURL() != want {
		t.Fatal("GH-Pages adapter URL mismatch")
	}
}
