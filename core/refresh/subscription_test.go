package refresh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/importer"
	bundleshare "daal/bundle-go/share"
	"daal/core/bootstrap"
	"daal/core/routestore"
)

// fakeStore is a minimal in-memory implementation of the Store interface
// used by Refresher tests. It also tracks audit rows so the tests can
// assert the URL never leaks into the audit ref_id.
type fakeStore struct {
	secrets   map[string][]byte
	subs      map[string]routestore.SubscriptionRow
	audit     []auditEntry
	saveCalls int
	pubs      map[string]importer.Pin
}

type auditEntry struct {
	kind, refID, outcome string
	bytes                int64
	via                  bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		secrets: map[string][]byte{},
		subs:    map[string]routestore.SubscriptionRow{},
		pubs:    map[string]importer.Pin{},
	}
}

func (s *fakeStore) GetSecret(k string) ([]byte, error) {
	v, ok := s.secrets[k]
	if !ok {
		return nil, errors.New("no secret")
	}
	return v, nil
}
func (s *fakeStore) PutSecret(k string, v []byte) error {
	s.secrets[k] = append([]byte(nil), v...)
	return nil
}
func (s *fakeStore) GetSubscription(id string) (routestore.SubscriptionRow, error) {
	r, ok := s.subs[id]
	if !ok {
		return routestore.SubscriptionRow{}, errors.New("no sub")
	}
	return r, nil
}
func (s *fakeStore) UpsertSubscription(r routestore.SubscriptionRow) error {
	s.subs[r.SubscriptionID] = r
	return nil
}
func (s *fakeStore) ListSubscriptions() ([]routestore.SubscriptionRow, error) {
	out := []routestore.SubscriptionRow{}
	for _, r := range s.subs {
		out = append(out, r)
	}
	return out, nil
}
func (s *fakeStore) DeleteSubscription(id string) error {
	delete(s.subs, id)
	return nil
}
func (s *fakeStore) AppendRefreshAudit(kind, refID, outcome string, bytesIn int64, viaTunnel bool, _ time.Time) error {
	s.audit = append(s.audit, auditEntry{kind, refID, outcome, bytesIn, viaTunnel})
	return nil
}

// importer.State implementation.
func (s *fakeStore) LookupPublisher(fp string) (importer.Pin, bool, error) {
	p, ok := s.pubs[fp]
	return p, ok, nil
}
func (s *fakeStore) SaveImport(p importer.PublisherInput, routes []importer.RouteInput) error {
	s.saveCalls++
	s.pubs[p.Fingerprint] = importer.Pin{
		TrustLevel:    p.TrustLevel,
		KeyStatus:     p.KeyStatus,
		DisplayName:   p.DisplayName,
		RotationChain: p.RotationChain,
	}
	return nil
}
func (s *fakeStore) MarkPublisherRevoked(_, _, _ string, _ time.Time) error { return nil }
func (s *fakeStore) MarkRouteRevoked(_ string) error                        { return nil }

func mustIdentity(t *testing.T) bundleshare.PublisherIdentity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return bundleshare.PublisherIdentity{
		DisplayName:  "device",
		PublicKey:    pub,
		PrivateKey:   priv,
		KeyCreatedAt: time.Now().UTC(),
		TrustClass:   "tofu_friend",
	}
}

// nowFn returns a clock fixed at "real now" so synthetic bundle expiry
// checks (which read real wall-clock time inside bundle.VerifyBundle)
// continue to pass.
func nowFn(_, _ int) func() time.Time {
	t := time.Now().UTC()
	return func() time.Time { return t }
}

func TestSubscriptionAddPersistsURL(t *testing.T) {
	s := newFakeStore()
	r := &Refresher{Store: s, Now: nowFn(2026, 1)}
	out, err := r.Add(AddInput{
		PublisherID: "fpA", URL: "https://example.invalid/sub", DisplayName: "test",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if out.SubscriptionID == "" {
		t.Fatal("missing subscription id")
	}
	row := s.subs[out.SubscriptionID]
	if row.URLSecretKey == "" || !strings.HasPrefix(row.URLSecretKey, "subscription-url:") {
		t.Fatalf("url key: %q", row.URLSecretKey)
	}
	stored := string(s.secrets[row.URLSecretKey])
	if stored != "https://example.invalid/sub" {
		t.Fatalf("stored URL mismatch: %q", stored)
	}
	for _, e := range s.audit {
		if strings.Contains(e.refID, "https://") {
			t.Fatalf("audit leaked URL: %+v", e)
		}
	}
}

func TestSubscriptionRefreshURIList(t *testing.T) {
	body := []byte("vless://2eb73a7c-8c7e-4e1a-aaaa-aaaaaaaaaaaa@server.example:443?encryption=none&type=tcp&security=reality&pbk=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ&fp=chrome&sni=example.com#test-route\n")

	st := newFakeStore()
	id := mustIdentity(t)
	r := &Refresher{
		Store: st, Identity: id, Adapter: st, Now: nowFn(2026, 1),
		Fetch: func(ctx context.Context, url string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			return body, nil
		},
		Dialer: func() (bootstrap.Dialer, bool, error) {
			return nil, true, nil
		},
	}
	add, err := r.Add(AddInput{PublisherID: "device", URL: "https://example.invalid/sub", DisplayName: "test-list"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	res, err := r.Refresh(context.Background(), add.SubscriptionID, 5*time.Second)
	if err != nil {
		t.Fatalf("refresh: %v (verdict=%s)", err, res.Verdict)
	}
	if res.RouteCount != 1 {
		t.Fatalf("route count: %d", res.RouteCount)
	}
	// First-seen publisher → trust prompt is the expected outcome.
	if res.Verdict != "trust_prompt_needed" && res.Verdict != "imported" {
		t.Fatalf("unexpected verdict: %s", res.Verdict)
	}
	if !res.ViaTunnel {
		t.Fatal("expected ViaTunnel=true")
	}
	for _, e := range st.audit {
		if strings.Contains(e.refID, "://") {
			t.Fatalf("audit leaked URL: %+v", e)
		}
	}
}

func TestSubscriptionRefreshFailureKeepsCache(t *testing.T) {
	st := newFakeStore()
	r := &Refresher{
		Store: st, Identity: mustIdentity(t), Adapter: st, Now: nowFn(2026, 1),
		Fetch: func(ctx context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			return nil, errors.New("blocked")
		},
		Dialer: func() (bootstrap.Dialer, bool, error) { return nil, false, nil },
	}
	add, _ := r.Add(AddInput{PublisherID: "device", URL: "https://blocked.invalid/sub", DisplayName: "x"})
	res, err := r.Refresh(context.Background(), add.SubscriptionID, time.Second)
	if err == nil {
		t.Fatal("expected fetch error")
	}
	if res.Outcome != "" && res.Outcome != "subscription_unreachable" {
		t.Fatalf("unexpected outcome: %q", res.Outcome)
	}
	row := st.subs[add.SubscriptionID]
	if row.LastRefreshOutcome != "subscription_unreachable" {
		t.Fatalf("expected outcome stamped, got %q", row.LastRefreshOutcome)
	}
	if row.LastGoodRefreshBkt != "" {
		t.Fatal("last_good_refresh_bkt must remain empty after a failure")
	}
}

func TestSubscriptionRefreshMalformedBody(t *testing.T) {
	st := newFakeStore()
	r := &Refresher{
		Store: st, Identity: mustIdentity(t), Adapter: st, Now: nowFn(2026, 1),
		Fetch: func(ctx context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			return []byte("this is not a known format\n"), nil
		},
		Dialer: func() (bootstrap.Dialer, bool, error) { return nil, false, nil },
	}
	add, _ := r.Add(AddInput{PublisherID: "device", URL: "https://example.invalid/sub", DisplayName: "y"})
	if _, err := r.Refresh(context.Background(), add.SubscriptionID, 5*time.Second); err == nil {
		t.Fatal("expected parse error")
	}
	row := st.subs[add.SubscriptionID]
	if row.LastRefreshOutcome != "bundle_corrupted" {
		t.Fatalf("expected bundle_corrupted, got %q", row.LastRefreshOutcome)
	}
}

// TestLifelineStrictRefreshGateBlocksScheduled — Phase 2D. In
// lifeline-strict mode, Refresh() (the scheduler entrypoint) returns
// the SkippedLifelineStrict outcome without making a fetch.
func TestLifelineStrictRefreshGateBlocksScheduled(t *testing.T) {
	st := newFakeStore()
	fetched := false
	r := &Refresher{
		Store: st, Identity: mustIdentity(t), Adapter: st, Now: nowFn(2026, 1),
		Mode: "lifeline-strict",
		Fetch: func(ctx context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			fetched = true
			return []byte("vless://2eb73a7c-8c7e-4e1a-aaaa-aaaaaaaaaaaa@server.example:443?encryption=none&type=tcp&security=reality&pbk=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ&fp=chrome&sni=example.com#x\n"), nil
		},
		Dialer: func() (bootstrap.Dialer, bool, error) { return nil, true, nil },
	}
	add, _ := r.Add(AddInput{PublisherID: "device", URL: "https://example.invalid/sub", DisplayName: "y"})
	res, err := r.Refresh(context.Background(), add.SubscriptionID, 5*time.Second)
	if err != nil {
		t.Fatalf("expected nil error on gated refresh, got %v", err)
	}
	if res.Outcome != SkippedLifelineStrict {
		t.Errorf("outcome = %q, want %q", res.Outcome, SkippedLifelineStrict)
	}
	if fetched {
		t.Error("Fetch was called despite the lifeline-strict gate")
	}
}

// TestLifelineStrictRefreshGatePassesUserTriggered — RefreshUser
// bypasses the gate and proceeds with the fetch.
func TestLifelineStrictRefreshGatePassesUserTriggered(t *testing.T) {
	st := newFakeStore()
	fetched := false
	r := &Refresher{
		Store: st, Identity: mustIdentity(t), Adapter: st, Now: nowFn(2026, 1),
		Mode: "lifeline-strict",
		Fetch: func(ctx context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			fetched = true
			return []byte("vless://2eb73a7c-8c7e-4e1a-aaaa-aaaaaaaaaaaa@server.example:443?encryption=none&type=tcp&security=reality&pbk=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ&fp=chrome&sni=example.com#u\n"), nil
		},
		Dialer: func() (bootstrap.Dialer, bool, error) { return nil, true, nil },
	}
	add, _ := r.Add(AddInput{PublisherID: "device", URL: "https://example.invalid/sub", DisplayName: "u"})
	if _, err := r.RefreshUser(context.Background(), add.SubscriptionID, 5*time.Second); err != nil {
		t.Fatalf("user-triggered refresh failed: %v", err)
	}
	if !fetched {
		t.Error("user-triggered refresh did not call Fetch")
	}
}

// TestRefreshGateUnchangedInOtherModes — for every non-strict mode,
// the gate is a no-op.
func TestRefreshGateUnchangedInOtherModes(t *testing.T) {
	for _, m := range []string{"", "normal", "lifeline", "bulk"} {
		st := newFakeStore()
		fetched := false
		r := &Refresher{
			Store: st, Identity: mustIdentity(t), Adapter: st, Now: nowFn(2026, 1),
			Mode: m,
			Fetch: func(ctx context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
				fetched = true
				return []byte("vless://2eb73a7c-8c7e-4e1a-aaaa-aaaaaaaaaaaa@server.example:443?encryption=none&type=tcp&security=reality&pbk=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ&fp=chrome&sni=example.com#k\n"), nil
			},
			Dialer: func() (bootstrap.Dialer, bool, error) { return nil, true, nil },
		}
		add, _ := r.Add(AddInput{PublisherID: "device", URL: "https://example.invalid/sub", DisplayName: "k"})
		_, _ = r.Refresh(context.Background(), add.SubscriptionID, 5*time.Second)
		if !fetched {
			t.Errorf("mode=%q: Fetch was not called (should be ungated)", m)
		}
	}
}
