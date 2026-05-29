package refresh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"daal/bundle-go/publisher"
	"daal/core/bootstrap"
	"daal/core/routestore"
)

// fakeRevStore implements RevocationStore.
type fakeRevStore struct {
	pubs              []routestore.PublisherRow
	revokedRoutes     []string
	revokedPublishers []string
	checkedAt         map[string]time.Time
	audit             []auditEntry
}

func newFakeRevStore() *fakeRevStore {
	return &fakeRevStore{checkedAt: map[string]time.Time{}}
}
func (s *fakeRevStore) ListPublishersWithRevocationURL() ([]routestore.PublisherRow, error) {
	return s.pubs, nil
}
func (s *fakeRevStore) MarkRouteRevoked(id string) error {
	s.revokedRoutes = append(s.revokedRoutes, id)
	return nil
}
func (s *fakeRevStore) MarkPublisherRoutesRevoked(id string) error {
	s.revokedPublishers = append(s.revokedPublishers, id)
	return nil
}
func (s *fakeRevStore) MarkPublisherRevocationChecked(id string, now time.Time) error {
	s.checkedAt[id] = now
	return nil
}
func (s *fakeRevStore) AppendRefreshAudit(kind, refID, outcome string, n int64, via bool, _ time.Time) error {
	s.audit = append(s.audit, auditEntry{kind, refID, outcome, n, via})
	return nil
}

func TestRevocationRefreshAppliesRevocations(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := publisher.BuildSignedRevocationList(priv,
		time.Now().UTC().Format(time.RFC3339),
		[]string{"pubA"}, []string{"routeX", "routeY"}, "key compromised")
	if err != nil {
		t.Fatal(err)
	}

	st := newFakeRevStore()
	st.pubs = []routestore.PublisherRow{{
		PublisherID:              "pubA",
		RevocationURL:            "https://example.invalid/rev.json",
		RevocationFingerprintHex: hex.EncodeToString(pub),
	}}
	r := &RevocationRefresher{
		Store: st, Now: func() time.Time { return time.Now().UTC() },
		Dialer: func() (bootstrap.Dialer, bool, error) { return nil, true, nil },
		Fetch: func(_ context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			return body, nil
		},
	}
	out, err := r.RefreshAll(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Outcome != "ok" {
		t.Fatalf("unexpected: %+v", out)
	}
	if len(st.revokedRoutes) != 2 {
		t.Fatalf("expected 2 routes revoked, got %v", st.revokedRoutes)
	}
	if len(st.revokedPublishers) != 1 || st.revokedPublishers[0] != "pubA" {
		t.Fatalf("expected pubA revoked, got %v", st.revokedPublishers)
	}
	if _, ok := st.checkedAt["pubA"]; !ok {
		t.Fatal("expected MarkPublisherRevocationChecked")
	}
}

func TestRevocationRefreshTamperedSignatureRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := publisher.BuildSignedRevocationList(priv,
		time.Now().UTC().Format(time.RFC3339),
		[]string{"pubA"}, nil, "x")
	body[10] ^= 0xff // flip a byte

	st := newFakeRevStore()
	st.pubs = []routestore.PublisherRow{{
		PublisherID:              "pubA",
		RevocationURL:            "https://example.invalid/rev.json",
		RevocationFingerprintHex: hex.EncodeToString(pub),
	}}
	r := &RevocationRefresher{
		Store: st, Now: func() time.Time { return time.Now().UTC() },
		Fetch: func(_ context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			return body, nil
		},
	}
	out, _ := r.RefreshAll(context.Background(), time.Second)
	if len(out) != 1 || out[0].Outcome == "ok" {
		t.Fatalf("expected non-ok outcome, got %+v", out)
	}
	if len(st.revokedRoutes) != 0 || len(st.revokedPublishers) != 0 {
		t.Fatal("must not apply revocations on signature failure")
	}
}
