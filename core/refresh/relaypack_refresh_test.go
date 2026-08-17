package refresh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/bootstrap"
	"daal/core/routestore"
)

// ---------------------------------------------------------------
// scaffolding
// ---------------------------------------------------------------

type fakeRelayStore struct {
	*fakeStore
	routes []routestore.RouteRow
}

func (s *fakeRelayStore) ListRoutes() ([]routestore.RouteRow, error) {
	return append([]routestore.RouteRow(nil), s.routes...), nil
}

// scriptedFetch is a FetchFn whose behaviour is per-URL. It records the
// order URLs were tried in, which is how the randomisation and the
// "a blocked host must not stall the walk" properties are observed.
type scriptedFetch struct {
	mu      sync.Mutex
	order   []string
	bodies  map[string][]byte
	hang    map[string]bool
	fail    map[string]bool
	perCall time.Duration
}

func newScriptedFetch() *scriptedFetch {
	return &scriptedFetch{
		bodies: map[string][]byte{},
		hang:   map[string]bool{},
		fail:   map[string]bool{},
	}
}

func (s *scriptedFetch) fn() FetchFn {
	return func(ctx context.Context, url string, _ bootstrap.Dialer, timeout time.Duration) ([]byte, error) {
		s.mu.Lock()
		s.order = append(s.order, url)
		body, haveBody := s.bodies[url]
		hang := s.hang[url]
		fail := s.fail[url]
		s.mu.Unlock()

		if hang {
			// A blackholed host in Iran fails by timeout, not by RST.
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if fail || !haveBody {
			return nil, errors.New("connection refused")
		}
		if s.perCall > 0 {
			select {
			case <-time.After(s.perCall):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return body, nil
	}
}

func (s *scriptedFetch) tried() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
}

func fingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// newRelayFixture wires a refresher over one pack with `endpoints`
// freshness URLs (encoded in the manifest scalar slot as a list), owned
// by one pinned publisher.
func newRelayFixture(t *testing.T, endpoints []string) (*RelayPackRefresher, *fakeRelayStore,
	*scriptedFetch, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fp := fingerprintOf(pub)
	fs := newFakeStore()
	fs.pubs[fp] = importer.Pin{TrustLevel: "trusted", KeyStatus: "active", DisplayName: "pubA"}
	store := &fakeRelayStore{
		fakeStore: fs,
		routes: []routestore.RouteRow{{
			RouteID:      "r-1",
			PublisherID:  fp,
			RelayPackID:  "rp-1",
			FreshnessURL: strings.Join(endpoints, " "),
		}},
	}
	sf := newScriptedFetch()
	r := &RelayPackRefresher{
		Store:         store,
		Adapter:       fs,
		Fetch:         sf.fn(),
		Dialer:        DialerFn(func() (bootstrap.Dialer, bool, error) { return nil, true, nil }),
		Now:           func() time.Time { return time.Now().UTC() },
		PerURLTimeout: 200 * time.Millisecond,
		TotalBudget:   2 * time.Second,
	}
	return r, store, sf, pub, priv
}

func servedDoc(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	mutate func(*FreshnessDocument)) []byte {
	t.Helper()
	doc := baseDoc(pub, time.Now().UTC())
	if mutate != nil {
		mutate(doc)
	}
	return signFreshnessDoc(t, doc, priv)
}

func outcomeOf(store *fakeRelayStore) string {
	if len(store.audit) == 0 {
		return ""
	}
	return store.audit[len(store.audit)-1].outcome
}

// ---------------------------------------------------------------
// the walk
// ---------------------------------------------------------------

// The unchanged path is the common one: the publisher has not rotated,
// so the poll costs one small request and no bundle fetch.
func TestRelayPackRefresh_UnchangedDigestDoesNotFetchABundle(t *testing.T) {
	r, store, sf, pub, priv := newRelayFixture(t,
		[]string{"https://a.example.com/f.json", "https://b.example.com/f.json"})
	body := servedDoc(t, pub, priv, nil)
	sf.bodies["https://a.example.com/f.json"] = body
	sf.bodies["https://b.example.com/f.json"] = body

	// Seed the persisted digest so the document reports "unchanged".
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})

	res, err := r.Refresh(context.Background(), "rp-1")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if res.Outcome != OutcomeFreshnessUnchanged {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessUnchanged)
	}
	if res.Changed {
		t.Fatal("digest matched but Changed was set")
	}
	if len(sf.tried()) != 1 {
		t.Fatalf("expected one request, got %v", sf.tried())
	}
	if !res.ViaTunnel {
		t.Fatal("ViaTunnel must reflect the dialer's report")
	}
	if outcomeOf(store) != OutcomeFreshnessUnchanged {
		t.Fatalf("audit says %q", outcomeOf(store))
	}
	// The high-water mark advances even on the unchanged path.
	if got := r.loadRecord("rp-1").HighWaterSequence; got != 10 {
		t.Fatalf("high-water mark is %d, want 10", got)
	}
}

// N endpoints, tried in randomised order. The property under test is
// not "shuffled once" but "no fleet-wide primary": across repeated
// attempts every member must appear first at least once.
func TestRelayPackRefresh_RandomisesEndpointOrder(t *testing.T) {
	eps := []string{
		"https://a.example.com/f.json",
		"https://b.example.com/f.json",
		"https://c.example.com/f.json",
	}
	firsts := map[string]int{}
	for i := 0; i < 60; i++ {
		r, _, sf, pub, priv := newRelayFixture(t, eps)
		body := servedDoc(t, pub, priv, nil)
		for _, e := range eps {
			sf.bodies[e] = body
		}
		r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})
		if _, err := r.Refresh(context.Background(), "rp-1"); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		tried := sf.tried()
		if len(tried) == 0 {
			t.Fatal("no endpoint was tried")
		}
		firsts[tried[0]]++
	}
	if len(firsts) != len(eps) {
		t.Fatalf("only %d of %d endpoints were ever tried first: %v — "+
			"a deterministic order means one host is the whole fleet's primary",
			len(firsts), len(eps), firsts)
	}
}

// A blackholed first host must cost one per-URL timeout, not the
// attempt. This is the difference between "one provider is blocked" and
// "freshness is broken".
func TestRelayPackRefresh_BlockedHostsDoNotStallTheWalk(t *testing.T) {
	eps := []string{
		"https://a.example.com/f.json",
		"https://b.example.com/f.json",
		"https://good.example.com/f.json",
	}
	r, _, sf, pub, priv := newRelayFixture(t, eps)
	sf.hang["https://a.example.com/f.json"] = true
	sf.hang["https://b.example.com/f.json"] = true
	sf.bodies["https://good.example.com/f.json"] = servedDoc(t, pub, priv, nil)
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})

	start := time.Now()
	res, err := r.Refresh(context.Background(), "rp-1")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("two dead hosts killed the refresh: %v", err)
	}
	if res.Outcome != OutcomeFreshnessUnchanged {
		t.Fatalf("outcome %q", res.Outcome)
	}
	if elapsed > r.TotalBudget {
		t.Fatalf("walk took %s, over the %s budget", elapsed, r.TotalBudget)
	}
}

// Every host dead: bounded by the total budget, reported as
// unreachable (a censorship signal), and escalated to the
// bootstrap-pointer layer.
func TestRelayPackRefresh_AllBlockedFallsThroughToPointerRecovery(t *testing.T) {
	eps := []string{
		"https://a.example.com/f.json",
		"https://b.example.com/f.json",
		"https://c.example.com/f.json",
	}
	r, store, sf, _, _ := newRelayFixture(t, eps)
	for _, e := range eps {
		sf.hang[e] = true
	}
	recovered := 0
	r.Recover = func(context.Context) (string, error) {
		recovered++
		return "https://bootstrap-primary.daal.example/dir.sbp", nil
	}

	start := time.Now()
	res, err := r.Refresh(context.Background(), "rp-1")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error when every endpoint is blocked")
	}
	if res.Outcome != OutcomeFreshnessUnreachable {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessUnreachable)
	}
	if elapsed > r.TotalBudget+time.Second {
		t.Fatalf("walk overran the budget: %s", elapsed)
	}
	if recovered != 1 {
		t.Fatalf("pointer recovery ran %d times, want 1", recovered)
	}
	if res.EndpointsTried != len(eps) {
		t.Fatalf("tried %d endpoints, want %d", res.EndpointsTried, len(eps))
	}
	var sawRecovery bool
	for _, a := range store.audit {
		if a.outcome == OutcomeFreshnessRecovery {
			sawRecovery = true
		}
	}
	if !sawRecovery {
		t.Fatal("the recovery attempt left no audit trail")
	}
	// And the failure is stamped, so the next tick honours the retry
	// backoff instead of re-walking every dead host immediately.
	if r.loadRecord("rp-1").LastFailureAt == "" {
		t.Fatal("no failure stamp: the next tick would re-attempt at once")
	}
}

// ---------------------------------------------------------------
// Wave 1's guard
// ---------------------------------------------------------------

// The whole point: while a route is active and no tunnel dialer is
// installed, the fetch does not happen. Not "happens directly", not
// "happens and is logged" — does not happen. And recovery must not
// become the back door, since it egresses from the same address.
func TestRelayPackRefresh_FailsClosedWithNoTunnelDialer(t *testing.T) {
	t.Cleanup(func() {
		SetTunnelRequired(false)
		SetGlobalDialer(nil)
	})
	SetGlobalDialer(nil)
	SetTunnelRequired(true)

	r, store, sf, _, _ := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	r.Dialer = nil // the scheduler's shape: no per-instance dialer
	recovered := 0
	r.Recover = func(context.Context) (string, error) { recovered++; return "", nil }

	res, err := r.Refresh(context.Background(), "rp-1")
	if !errors.Is(err, ErrTunnelRequired) {
		t.Fatalf("want ErrTunnelRequired, got %v", err)
	}
	if res.Outcome != OutcomeFreshnessTunnel {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessTunnel)
	}
	if n := len(sf.tried()); n != 0 {
		t.Fatalf("%d fetches happened while the guard was closed", n)
	}
	if recovered != 0 {
		t.Fatal("pointer recovery ran under the closed guard — that is the same leak by another name")
	}
	if res.ViaTunnel {
		t.Fatal("a refused fetch must not claim to be tunnelled")
	}
	if outcomeOf(store) != OutcomeFreshnessTunnel {
		t.Fatalf("audit says %q", outcomeOf(store))
	}
}

// With a tunnel dialer installed the same call proceeds and reports
// viaTunnel=true, which is what the audit trail shows the user.
func TestRelayPackRefresh_RidesTheTunnelWhenOneIsInstalled(t *testing.T) {
	t.Cleanup(func() {
		SetTunnelRequired(false)
		SetGlobalDialer(nil)
	})
	SetTunnelRequired(true)
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		return bootstrap.NewDirectDialer(time.Second), true, nil
	})

	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	r.Dialer = nil
	body := servedDoc(t, pub, priv, nil)
	sf.bodies["https://a.example.com/f.json"] = body
	sf.bodies["https://b.example.com/f.json"] = body
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})

	res, err := r.Refresh(context.Background(), "rp-1")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !res.ViaTunnel {
		t.Fatal("viaTunnel must be true when the installed dialer says so")
	}
	if !store.audit[len(store.audit)-1].via {
		t.Fatal("the audit row must record that the fetch was tunnelled")
	}
}

// ---------------------------------------------------------------
// cadence
// ---------------------------------------------------------------

func TestRelayPackRefresh_RateLimitedWithoutTouchingTheNetwork(t *testing.T) {
	now := time.Now().UTC()
	r, _, sf, _, _ := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	r.Now = func() time.Time { return now }
	r.saveRecord("rp-1", freshnessRecord{V: 1,
		LastSuccessAt: now.Add(-time.Minute).Format(time.RFC3339)})

	res, _ := r.Refresh(context.Background(), "rp-1")
	if res.Outcome != OutcomeFreshnessRateLimited {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessRateLimited)
	}
	if len(sf.tried()) != 0 {
		t.Fatal("a rate-limited attempt reached the network")
	}
	// A user-triggered call bypasses the floor, exactly as the
	// subscription path does.
	if res2, _ := r.RefreshUser(context.Background(), "rp-1"); res2.Outcome == OutcomeFreshnessRateLimited {
		t.Fatal("a user-triggered refresh must bypass the cadence floor")
	}
}

func TestRelayPackRefresh_LifelineStrictSkipsScheduledOnly(t *testing.T) {
	r, _, sf, _, _ := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	r.Mode = "lifeline-strict"
	res, err := r.Refresh(context.Background(), "rp-1")
	if err != nil || res.Outcome != SkippedLifelineStrict {
		t.Fatalf("outcome %q err %v", res.Outcome, err)
	}
	if len(sf.tried()) != 0 {
		t.Fatal("lifeline-strict did not stop the fetch")
	}
}

func TestRelayPackRefresh_NoEndpointsIsNotAFetchFailure(t *testing.T) {
	r, _, sf, _, _ := newRelayFixture(t, nil)
	res, err := r.Refresh(context.Background(), "rp-1")
	if err != nil {
		t.Fatalf("a pack with no endpoint must not error: %v", err)
	}
	if res.Outcome != OutcomeFreshnessNoEndpoints {
		t.Fatalf("outcome %q", res.Outcome)
	}
	if len(sf.tried()) != 0 {
		t.Fatal("something was fetched with no endpoints configured")
	}
}

// ---------------------------------------------------------------
// hostile documents at the walk
// ---------------------------------------------------------------

// A replayed document is refused at the endpoint that served it, and
// the walk moves on: one poisoned mirror must not take the pack down.
func TestRelayPackRefresh_ReplayAtOneMirrorFallsToTheNext(t *testing.T) {
	eps := []string{"https://stale.example.com/f.json", "https://fresh.example.com/f.json"}
	r, _, sf, pub, priv := newRelayFixture(t, eps)
	sf.bodies[eps[0]] = servedDoc(t, pub, priv, func(d *FreshnessDocument) { d.Sequence = 4 })
	sf.bodies[eps[1]] = servedDoc(t, pub, priv, func(d *FreshnessDocument) { d.Sequence = 12 })
	r.saveRecord("rp-1", freshnessRecord{V: 1,
		CurrentBundleSHA256: repeatHex("de"), HighWaterSequence: 10})

	res, err := r.Refresh(context.Background(), "rp-1")
	if err != nil {
		t.Fatalf("a replayed mirror killed the refresh: %v", err)
	}
	if res.Outcome != OutcomeFreshnessUnchanged {
		t.Fatalf("outcome %q", res.Outcome)
	}
	if got := r.loadRecord("rp-1").HighWaterSequence; got != 12 {
		t.Fatalf("high-water mark %d, want 12", got)
	}
}

// Every mirror serving a rollback is reported as REJECTED, not as
// unreachable. The two demand different responses and rendering both
// as "refresh failed" is how a device stops being able to tell an
// attack from an outage.
func TestRelayPackRefresh_AllMirrorsReplayedIsReportedAsRejection(t *testing.T) {
	eps := []string{"https://a.example.com/f.json", "https://b.example.com/f.json"}
	r, _, sf, pub, priv := newRelayFixture(t, eps)
	for _, e := range eps {
		sf.bodies[e] = servedDoc(t, pub, priv, func(d *FreshnessDocument) { d.Sequence = 4 })
	}
	r.saveRecord("rp-1", freshnessRecord{V: 1, HighWaterSequence: 10})
	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if res.Outcome != OutcomeFreshnessRejected {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessRejected)
	}
}

// A document signed by another (pinned!) publisher, served at this
// pack's mirror. The fingerprint binding refuses it before the
// signature is even consulted.
func TestRelayPackRefresh_ForeignPublisherDocumentRejected(t *testing.T) {
	eps := []string{"https://a.example.com/f.json", "https://b.example.com/f.json"}
	r, _, sf, _, _ := newRelayFixture(t, eps)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	for _, e := range eps {
		sf.bodies[e] = servedDoc(t, otherPub, otherPriv, nil)
	}
	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if res.Outcome != OutcomeFreshnessRejected {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessRejected)
	}
}

// The endpoint set advertised by a verified document is adopted, which
// is how a publisher retires a burned freshness host without
// re-delivering a pack.
func TestRelayPackRefresh_AdoptsAdvertisedMirrors(t *testing.T) {
	r, _, sf, pub, priv := newRelayFixture(t, []string{"https://old.example.com/f.json",
		"https://old2.example.com/f.json"})
	sf.bodies["https://old.example.com/f.json"] = servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.Mirrors = []FreshnessMirror{
			{Provider: "r2", URL: "https://new1.example.net/f.json"},
			{Provider: "ghpages", URL: "https://new2.example.org/f.json"},
		}
	})
	sf.bodies["https://old2.example.com/f.json"] = sf.bodies["https://old.example.com/f.json"]
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})

	if _, err := r.Refresh(context.Background(), "rp-1"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	targets, err := r.Targets()
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets: %v %v", targets, err)
	}
	joined := strings.Join(targets[0].Endpoints, " ")
	for _, want := range []string{"new1.example.net", "new2.example.org", "old.example.com"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("endpoint set %q lost %s", joined, want)
		}
	}
	if targets[0].Providers < 3 {
		t.Fatalf("provider count %d, want ≥3", targets[0].Providers)
	}
}

// A document that advertises a degraded (single-provider) set must not
// shrink the recipient down to one host.
func TestRelayPackRefresh_RefusesToAdoptADegradedMirrorSet(t *testing.T) {
	r, _, sf, pub, priv := newRelayFixture(t, []string{"https://old.example.com/f.json",
		"https://old2.example.com/f.json"})
	body := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.Mirrors = []FreshnessMirror{{Provider: "r2", URL: "https://only.example.com/f.json"}}
	})
	sf.bodies["https://old.example.com/f.json"] = body
	sf.bodies["https://old2.example.com/f.json"] = body
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})

	// The document itself is refused (VerifyFreshnessDocument rejects a
	// malformed advertised set), so nothing is adopted.
	if _, err := r.Refresh(context.Background(), "rp-1"); err == nil {
		t.Fatal("a document advertising a one-host set was accepted")
	}
	if len(r.loadRecord("rp-1").Mirrors) != 0 {
		t.Fatal("a degraded mirror set was persisted")
	}
}

// ---------------------------------------------------------------
// hostile bundles at the apply
// ---------------------------------------------------------------

func makePackSBP(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	routeIDs []string, now time.Time) []byte {
	t.Helper()
	routes := make([]bundle.RouteManifestEntry, 0, len(routeIDs))
	profiles := map[string][]byte{}
	for _, id := range routeIDs {
		routes = append(routes, bundle.RouteManifestEntry{
			ID:              id,
			ScarcityClass:   "normal",
			TransportFamily: "vless-reality",
			ConfigPath:      "profiles/" + id + ".json",
			ValidFrom:       now.Format(time.RFC3339),
			ValidUntil:      now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
		})
		profiles["profiles/"+id+".json"] = []byte(`{}`)
	}
	manifest := bundle.Manifest{
		SpecVersion: 2,
		Publisher: bundle.PublisherInfo{
			Name:              "pubA",
			KeyFingerprintHex: bundle.PublisherFingerprint(pub).Hex,
			KeyCreatedAt:      now.Format(time.RFC3339),
			TrustClass:        "friend",
		},
		Bundle: bundle.BundleInfo{
			ID:        "b-1",
			Type:      "friend_share",
			CreatedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(25 * 24 * time.Hour).Format(time.RFC3339),
		},
		Routes: routes,
	}
	body, err := bundle.BuildSignedBundleDeterministic(manifest, profiles, nil, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// The happy path end to end: the publisher rotated, the digest moved,
// the pack is fetched and applied atomically.
func TestRelayPackRefresh_AppliesARotatedPack(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now)
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc

	res, err := r.Refresh(context.Background(), "rp-1")
	if err != nil {
		t.Fatalf("apply: %v (outcome %s)", err, res.Outcome)
	}
	if !res.Applied || res.Outcome != OutcomeFreshnessOK {
		t.Fatalf("res %+v", res)
	}
	if store.saveCalls == 0 {
		t.Fatal("the importer never wrote the pack")
	}
	if got := r.loadRecord("rp-1").CurrentBundleSHA256; got != sha256Hex(packBody) {
		t.Fatalf("digest not recorded: %q", got)
	}
	// Second run: nothing moved, so no bundle fetch.
	before := len(sf.tried())
	r.Now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	res2, err := r.Refresh(context.Background(), "rp-1")
	if err != nil || res2.Outcome != OutcomeFreshnessUnchanged {
		t.Fatalf("second run: %+v %v", res2, err)
	}
	if got := len(sf.tried()) - before; got != 1 {
		t.Fatalf("second run made %d requests, want 1 (document only)", got)
	}
}

// HOSTILE: the freshness document is this publisher's, but the pack it
// points at is signed by someone else. The importer's own "publisher
// must be pinned" rule would pass for any of the device's several
// pinned publishers, so this check is the one that matters.
func TestRelayPackRefresh_RefusesAPackSignedByAnotherPublisher(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	store.pubs[fingerprintOf(otherPub)] = importer.Pin{TrustLevel: "trusted", KeyStatus: "active"}

	packBody := makePackSBP(t, otherPub, otherPriv, []string{"r-1"}, now)
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc

	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("a pack signed by a different publisher was applied")
	}
	if !errors.Is(err, ErrFreshnessPublisher) {
		t.Fatalf("err %v", err)
	}
	if res.Applied || store.saveCalls != 0 {
		t.Fatal("the importer was reached")
	}
}

// HOSTILE: publisher A's pack re-homes a route that currently belongs
// to publisher B. Nothing in the importer stops that — both are pinned
// — so a fetched pack could silently change WHICH publisher a route
// belongs to.
func TestRelayPackRefresh_RefusesToRehomeAnotherPublishersRoute(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	// A route owned by a DIFFERENT publisher already exists.
	store.routes = append(store.routes, routestore.RouteRow{
		RouteID:     "r-victim",
		PublisherID: fingerprintOf(otherPub),
	})

	packBody := makePackSBP(t, pub, priv, []string{"r-1", "r-victim"}, now)
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc

	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("a route re-home was accepted")
	}
	if res.Outcome != OutcomeFreshnessRebind {
		t.Fatalf("outcome %q, want %q", res.Outcome, OutcomeFreshnessRebind)
	}
	if store.saveCalls != 0 {
		t.Fatal("the importer was reached")
	}
}

// HOSTILE: the pack body is truncated in flight. It must fail as a
// corrupt bundle, and the digest cross-check must not be what saves us
// by accident — the parse must refuse first.
func TestRelayPackRefresh_RefusesATruncatedPack(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now)
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody[:len(packBody)/2]
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc

	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("a truncated pack was applied")
	}
	if res.Applied || store.saveCalls != 0 {
		t.Fatal("the importer was reached")
	}
	if res.Outcome != OutcomeFreshnessBundleReject {
		t.Fatalf("outcome %q", res.Outcome)
	}
}

// A pack whose bundle has expired is refused by the importer's own
// verification. We assert it here because the freshness path is a
// second door into the same store and must not be a softer one.
func TestRelayPackRefresh_RefusesAnExpiredPack(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now.Add(-60*24*time.Hour))
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc

	if _, err := r.Refresh(context.Background(), "rp-1"); err == nil {
		t.Fatal("an expired pack was applied")
	}
	if store.saveCalls != 0 {
		t.Fatal("the importer wrote an expired pack")
	}
}

// A pack claimed by two publishers has no answer to "whose document
// governs this", and guessing is how ownership changes silently.
func TestRelayPackRefresh_AmbiguousPackIsRefused(t *testing.T) {
	r, _, sf, _, _ := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	store := r.Store.(*fakeRelayStore)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	store.routes = append(store.routes, routestore.RouteRow{
		RouteID:      "r-2",
		PublisherID:  fingerprintOf(otherPub),
		RelayPackID:  "rp-1",
		FreshnessURL: "https://a.example.com/f.json",
	})
	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("an ambiguous pack was refreshed")
	}
	if res.Outcome != OutcomeFreshnessAmbiguous {
		t.Fatalf("outcome %q", res.Outcome)
	}
	if len(sf.tried()) != 0 {
		t.Fatal("an ambiguous pack reached the network")
	}
}

// A verified document raises the high-water mark even when the bundle
// fetch that follows it fails. Otherwise a censor who lets the
// document through and blackholes the pack URL gets the rollback
// protection reset for free on the next attempt.
func TestRelayPackRefresh_HighWaterSurvivesAFailedBundleFetch(t *testing.T) {
	r, _, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json",
		"https://b.example.com/f.json"})
	packURL := "https://packs.example.com/current.sbp"
	sf.fail[packURL] = true
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.Sequence = 77
		d.CurrentSignedURL = packURL
	})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc

	res, err := r.Refresh(context.Background(), "rp-1")
	if err == nil {
		t.Fatal("expected the bundle fetch to fail")
	}
	if res.Outcome != OutcomeFreshnessBundleFetch {
		t.Fatalf("outcome %q", res.Outcome)
	}
	if got := r.loadRecord("rp-1").HighWaterSequence; got != 77 {
		t.Fatalf("high-water mark %d, want 77 — a replay would now be accepted", got)
	}
	if r.loadRecord("rp-1").LastFailureAt == "" {
		t.Fatal("no failure stamp")
	}
}
