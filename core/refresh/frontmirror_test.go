package refresh

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// The Google update channel on the recipient (frontmirror.go).

const (
	testGoogleSlot   = "AAAAAAAAAAA"
	testGoogleMirror = "https://script.google.com/macros/s/AKfycbTEST0000000000000001/exec?s=" + testGoogleSlot + "&k=AAAAAAAAAAAAAAAAAAAAAA"
)

func TestIsAppsScriptMirrorURL(t *testing.T) {
	const base = "https://script.google.com/macros/s/AKfycbTEST0000000000000001/exec"
	good := []string{
		testGoogleMirror,
		"https://script.google.com/macros/s/" + strings.Repeat("A", 120) + "/exec?s=ab_-0123456&k=abcdefghijklmnopqrstu_",
	}
	bad := []string{
		"",
		// The single-relay shape of the first build: never deployed.
		base + "?k=AAAAAAAAAAAAAAAAAAAAAA",
		base,
		base + "?s=AAAAAAAAAAA",
		base + "?k=AAAAAAAAAAAAAAAAAAAAAA&s=AAAAAAAAAAA",
		base + "?s=AAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?s=AAAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?s=AAAAAAAAA%41A&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?s=AAAAAAAAAAA&k=AAAA",
		base + "?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA&x=1",
		base + "?s=AAAAAAAAAAA&s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA#f",
		"http://script.google.com/macros/s/AKfycbTEST0000000000000001/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		"https://script.google.com:443/macros/s/AKfycbTEST0000000000000001/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		"https://u@script.google.com/macros/s/AKfycbTEST0000000000000001/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		"https://script.google.com/macros/s/AKfycbTEST0000000000000001/dev?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		"https://script.google.com/macros/s/short/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		"https://script.googleusercontent.com/macros/s/AKfycbTEST0000000000000001/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		"https://evil.example/macros/s/AKfycbTEST0000000000000001/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
	}
	for _, u := range good {
		if !IsAppsScriptMirrorURL(u) {
			t.Errorf("refused %s", u)
		}
	}
	for _, u := range bad {
		if IsAppsScriptMirrorURL(u) {
			t.Errorf("accepted %s", u)
		}
	}
	if s, ok := appsScriptSlot(testGoogleMirror); !ok || s != testGoogleSlot {
		t.Fatalf("slot %q %v", s, ok)
	}
}

// D-3 on the recipient: one appsscript mirror is a set; one of anything
// else is not, and the label cannot buy the exception for another host.
func TestValidateMirrorSet_D3(t *testing.T) {
	if _, err := ValidateMirrorSet([]FreshnessMirror{{Provider: "appsscript", URL: testGoogleMirror}}); err != nil {
		t.Fatalf("a lone appsscript mirror was refused: %v", err)
	}
	for name, set := range map[string][]FreshnessMirror{
		"lone r2":                      {{Provider: "r2", URL: "https://a.example.com/f.json"}},
		"lone appsscript, other host":  {{Provider: "appsscript", URL: "https://a.example.com/f.json"}},
		"lone Google URL, other label": {{Provider: "r2", URL: testGoogleMirror}},
		"appsscript label in a pair, other host": {
			{Provider: "appsscript", URL: "https://a.example.com/f.json"},
			{Provider: "r2", URL: "https://b.example.com/f.json"},
		},
		"empty": {},
	} {
		if _, err := ValidateMirrorSet(set); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ValidateMirrorSet([]FreshnessMirror{
		{Provider: "appsscript", URL: testGoogleMirror},
		{Provider: "r2", URL: "https://b.example.com/f.json"},
	}); err != nil {
		t.Fatalf("appsscript beside r2: %v", err)
	}
	if !MeetsMirrorFloor([]string{"appsscript"}) || MeetsMirrorFloor([]string{"r2"}) || MeetsMirrorFloor(nil) ||
		!MeetsMirrorFloor([]string{"r2", "ghpages"}) {
		t.Fatal("MeetsMirrorFloor disagrees with the publisher's rule")
	}
}

func containerJSON(t *testing.T, doc, pack []byte, key string) []byte {
	t.Helper()
	w := map[string]string{"kind": "daal-refresh-v2", "slot": testGoogleSlot}
	if doc != nil {
		w["freshness"] = base64.StdEncoding.EncodeToString(doc)
	}
	if pack != nil {
		w["pack"] = base64.StdEncoding.EncodeToString(pack)
	}
	if key != "" {
		w["standby_key"] = key
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRefreshContainer_Limits(t *testing.T) {
	doc := []byte(`{"kind":"daal/freshness-v2"}`)
	c, err := parseRefreshContainer(containerJSON(t, doc, []byte("pk"), "0123456789ABCDEFGHJKMNPQR0"), testGoogleSlot)
	if err != nil || string(c.freshness) != string(doc) || string(c.pack) != "pk" || c.standbyKey == "" {
		t.Fatalf("good container: %+v %v", c, err)
	}
	if c, err := parseRefreshContainer([]byte(`{"kind":"daal-refresh-v2","slot":"AAAAAAAAAAA"}`), testGoogleSlot); err != nil || c.freshness != nil {
		t.Fatalf("empty container: %+v %v", c, err)
	}
	if c, err := parseRefreshContainer([]byte(`{"kind":"daal-refresh-v2","slot":"AAAAAAAAAAA","future":1,"freshness":"`+
		base64.StdEncoding.EncodeToString(doc)+`"}`), testGoogleSlot); err != nil || c.freshness == nil {
		t.Fatalf("unknown member: %v", err)
	}
	// Another relay's slot in the same script: not this relay's text.
	if _, err := parseRefreshContainer(containerJSON(t, doc, nil, ""), "BBBBBBBBBBB"); err == nil {
		t.Error("another slot's container accepted")
	}
	for name, body := range map[string][]byte{
		"not JSON":            []byte("<html>Sign in</html>"),
		"bland page":          []byte("Nothing here."),
		"wrong kind":          []byte(`{"kind":"daal/freshness-v2"}`),
		"v1 container":        []byte(`{"kind":"daal-refresh-v1","freshness":"` + base64.StdEncoding.EncodeToString(doc) + `"}`),
		"no slot":             []byte(`{"kind":"daal-refresh-v2","freshness":"` + base64.StdEncoding.EncodeToString(doc) + `"}`),
		"parts without doc":   []byte(`{"kind":"daal-refresh-v2","slot":"AAAAAAAAAAA","pack":"cGs="}`),
		"bad base64":          []byte(`{"kind":"daal-refresh-v2","slot":"AAAAAAAAAAA","freshness":"!!"}`),
		"big document":        containerJSON(t, make([]byte, maxContainerFreshness+1), nil, ""),
		"lower-case key":      containerJSON(t, doc, nil, strings.ToLower("0123456789ABCDEFGHJKMNPQR0")),
		"short key":           containerJSON(t, doc, nil, "0123"),
		"over the whole size": append(containerJSON(t, doc, nil, ""), make([]byte, maxRefreshContainer)...),
	} {
		if _, err := parseRefreshContainer(body, testGoogleSlot); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// googleFixture: a failure-walk fixture whose pack lists two ordinary
// mirrors and the Google one; the Google mirror is served by a scripted
// front fetcher.
type scriptedFront struct {
	mu    sync.Mutex
	urls  []string
	body  []byte
	err   error
	maxes []time.Duration // GoogleJitter bounds seen
}

func (s *scriptedFront) fn() FrontFetchFn {
	return func(ctx context.Context, url string, d bootstrap.Dialer, timeout time.Duration) ([]byte, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.urls = append(s.urls, url)
		if d == nil {
			return nil, errors.New("no dialer")
		}
		return s.body, s.err
	}
}

func googleFixture(t *testing.T, endpoints []string) (*RelayPackRefresher, *fakeRelayStore, *scriptedFetch, *scriptedFront, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	t.Cleanup(func() { SetTunnelRequired(false); SetGlobalDialer(nil) })
	SetTunnelRequired(false)
	SetGlobalDialer(nil)
	r, store, sf, pub, priv := newRelayFixture(t, endpoints)
	r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) { return bootstrap.NewDirectDialer(time.Second), false, nil })
	fr := &scriptedFront{}
	r.FrontFetch = fr.fn()
	r.GoogleJitter = func(max time.Duration) time.Duration {
		fr.mu.Lock()
		fr.maxes = append(fr.maxes, max)
		fr.mu.Unlock()
		return 0
	}
	return r, store, sf, fr, pub, priv
}

var threeMirrors = []string{"https://a.example.com/f.json", "https://b.example.com/f.json", testGoogleMirror}

// The C0 walk: the ordinary mirrors first (both blocked here), then the
// Google mirror through the front; its document verifies like any other.
func TestGoogleMirror_LastInTheFailureWalk(t *testing.T) {
	r, _, sf, fr, pub, priv := googleFixture(t, threeMirrors)
	doc := servedDoc(t, pub, priv, nil) // names repeatHex("de"), the bundle we run
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})
	fr.body = containerJSON(t, doc, nil, "")

	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessUnchanged || !res.ViaGoogle {
		t.Fatalf("%+v %v", res, err)
	}
	if got := sf.tried(); len(got) != 2 || strings.Contains(strings.Join(got, " "), "script.google.com") {
		t.Fatalf("ordinary fetches %v", got)
	}
	if len(fr.urls) != 1 || fr.urls[0] != testGoogleMirror || res.EndpointsTried != 3 {
		t.Fatalf("front fetches %v, tried %d", fr.urls, res.EndpointsTried)
	}
	if len(fr.maxes) != 1 || fr.maxes[0] <= 0 || fr.maxes[0] > MaxGoogleJitter {
		t.Fatalf("jitter bounds %v", fr.maxes)
	}
}

// When an ordinary mirror answers, the script is never touched.
func TestGoogleMirror_NotReachedWhenAnOrdinaryMirrorAnswers(t *testing.T) {
	r, _, sf, fr, pub, priv := googleFixture(t, threeMirrors)
	doc := servedDoc(t, pub, priv, nil)
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})
	sf.bodies["https://a.example.com/f.json"] = doc
	sf.bodies["https://b.example.com/f.json"] = doc
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || res.ViaGoogle || len(fr.urls) != 0 {
		t.Fatalf("%+v %v, front %v", res, err, fr.urls)
	}
}

// "On an ordinary day a recipient's phone never touches the script":
// the scheduled poll (tunnelled or not) and the button riding a healthy
// tunnel skip it. A pack whose only mirror is Google's then has nothing
// to walk, which is not a failure.
func TestGoogleMirror_OnlyTheDirectUnscheduledWalksReachIt(t *testing.T) {
	r, store, sf, fr, pub, priv := googleFixture(t, threeMirrors)
	doc := servedDoc(t, pub, priv, nil)
	fr.body = containerJSON(t, doc, nil, "")
	if _, err := r.Refresh(context.Background(), "rp-1"); err == nil {
		t.Fatal("premise: both ordinary mirrors are blocked")
	}
	if len(fr.urls) != 0 || len(sf.tried()) != 2 {
		t.Fatalf("scheduled poll: front %v, ordinary %v", fr.urls, sf.tried())
	}

	// The button while a route is up rides the tunnel: no Google.
	SetTunnelRequired(true)
	if _, err := r.RefreshOnDemand(context.Background(), "rp-1"); err == nil {
		t.Fatal("premise: blocked")
	}
	SetTunnelRequired(false)
	if len(fr.urls) != 0 {
		t.Fatalf("tunnelled button reached the script: %v", fr.urls)
	}

	_ = store

	// Google-only pack (D-3), scheduled: nothing goes out, nothing
	// escalates.
	r2, _, sf2, fr2, pub2, priv2 := googleFixture(t, []string{testGoogleMirror})
	res, err := r2.Refresh(context.Background(), "rp-1")
	if err != nil || res.Outcome != OutcomeFreshnessNoEndpoints || res.EndpointsTried != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(fr2.urls) != 0 || len(sf2.tried()) != 0 || r2.loadRecord("rp-1").ConsecutiveFailures != 0 {
		t.Fatal("a Google-only pack's scheduled poll reached the network or escalated")
	}

	// The same pack, the person's button with no route: through the
	// front.
	r2.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})
	fr2.body = containerJSON(t, servedDoc(t, pub2, priv2, nil), nil, "")
	res, err = r2.RefreshOnDemand(context.Background(), "rp-1")
	if err != nil || res.Outcome != OutcomeFreshnessUnchanged || !res.ViaGoogle || len(fr2.urls) != 1 {
		t.Fatalf("button, Google-only: %+v %v", res, err)
	}
}

// The document in a container gets exactly the checks of any mirror's.
func TestGoogleMirror_ContainerDocumentIsVerifiedLikeAnyOther(t *testing.T) {
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]func(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte{
		"another publisher": func(t *testing.T, _ ed25519.PublicKey, _ ed25519.PrivateKey) []byte {
			return servedDoc(t, otherPub, otherPriv, nil)
		},
		"bad signature": func(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
			d := servedDoc(t, pub, priv, nil)
			return []byte(strings.Replace(string(d), `"sequence":10`, `"sequence":11`, 1))
		},
		"rolled back": func(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
			return servedDoc(t, pub, priv, func(d *FreshnessDocument) { d.Sequence = 5 })
		},
		"expired": func(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
			return servedDoc(t, pub, priv, func(d *FreshnessDocument) {
				d.NotAfter = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
			})
		},
		"another pack": func(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
			return servedDoc(t, pub, priv, func(d *FreshnessDocument) { d.RelayPackID = "rp-other" })
		},
	}
	for name, mk := range cases {
		r, _, _, fr, pub, priv := googleFixture(t, threeMirrors)
		r.saveRecord("rp-1", freshnessRecord{V: 1, HighWaterSequence: 9, CurrentBundleSHA256: repeatHex("aa")})
		sink := &recordingSink{accept: true}
		r.StandbyKeys = sink
		fr.body = containerJSON(t, mk(t, pub, priv), []byte("pack"), "0123456789ABCDEFGHJKMNPQR0")
		res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
		if err == nil || res.Applied || res.StandbyKeyAccepted {
			t.Errorf("%s: %+v %v", name, res, err)
		}
		if res.Outcome != OutcomeFreshnessRejected {
			t.Errorf("%s: outcome %s", name, res.Outcome)
		}
		if len(sink.calls) != 0 {
			t.Errorf("%s: a standby key from an unverified container was offered", name)
		}
	}
}

type recordingSink struct {
	accept bool
	calls  []string
}

func (s *recordingSink) AcceptStandbyKey(relayPackID string, raw []byte) (int, error) {
	key, err := bundle.StandbyKeyFromBytes(raw)
	if err != nil {
		return 0, err
	}
	s.calls = append(s.calls, relayPackID+":"+key.Text())
	if s.accept {
		return 1, nil
	}
	return 0, nil
}

// The inline pack is applied through the same gate as a downloaded one,
// and current_signed_url is not fetched. Then the standby key is offered
// for the applied pack, and its acceptance is new information.
func TestGoogleMirror_InlinePackAndStandbyKey(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, fr, pub, priv := googleFixture(t, threeMirrors)
	r.saveRecord("rp-1", freshnessRecord{V: 1, OnFailureMisses: 2})
	packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now)
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = "https://packs.example.com/current.sbp"
	})
	key := "0123456789ABCDEFGHJKMNPQR0"
	fr.body = containerJSON(t, doc, packBody, key)
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink

	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || !res.Applied || !res.ViaGoogle || !res.StandbyKeyAccepted {
		t.Fatalf("%+v %v", res, err)
	}
	for _, u := range sf.tried() {
		if strings.Contains(u, "packs.example.com") {
			t.Fatal("the pack was fetched although the container carried it")
		}
	}
	if store.saveCalls == 0 {
		t.Fatal("the importer never wrote the pack")
	}
	want, _ := bundle.ParseStandbyKeyText(key)
	if len(sink.calls) != 1 || sink.calls[0] != res.RelayPackID+":"+want.Text() {
		t.Fatalf("offers %v", sink.calls)
	}
}

// A pack in the container that is not the one the document names is
// ignored: the walk fetches current_signed_url as for any mirror.
func TestGoogleMirror_ForeignInlinePackIsIgnored(t *testing.T) {
	now := time.Now().UTC()
	r, store, sf, fr, pub, priv := googleFixture(t, threeMirrors)
	packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now)
	packURL := "https://packs.example.com/current.sbp"
	sf.bodies[packURL] = packBody
	doc := servedDoc(t, pub, priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = packURL
	})
	fr.body = containerJSON(t, doc, []byte("some other file"), "")
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || !res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	fetched := false
	for _, u := range sf.tried() {
		fetched = fetched || u == packURL
	}
	if !fetched || store.saveCalls == 0 {
		t.Fatal("the named pack was not fetched and applied")
	}
}

// A standby key alone (nothing else new) is still new information when
// the store accepts it; one it does not accept changes nothing.
func TestGoogleMirror_StandbyKeyOnAnUnchangedDocument(t *testing.T) {
	for _, accept := range []bool{true, false} {
		r, _, _, fr, pub, priv := googleFixture(t, threeMirrors)
		r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de"), OnFailureMisses: 3})
		fr.body = containerJSON(t, servedDoc(t, pub, priv, nil), nil, "0123456789ABCDEFGHJKMNPQR0")
		sink := &recordingSink{accept: accept}
		r.StandbyKeys = sink
		res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
		if err != nil || res.Outcome != OutcomeFreshnessUnchanged || res.StandbyKeyAccepted != accept || len(sink.calls) != 1 {
			t.Fatalf("accept=%v: %+v %v %v", accept, res, err, sink.calls)
		}
		misses := r.loadRecord("rp-1").OnFailureMisses
		if accept && misses != 0 || !accept && misses != 4 {
			t.Fatalf("accept=%v: misses %d", accept, misses)
		}
	}
	// No store wired: the key is dropped, nothing breaks.
	r, _, _, fr, pub, priv := googleFixture(t, threeMirrors)
	r.saveRecord("rp-1", freshnessRecord{V: 1, CurrentBundleSHA256: repeatHex("de")})
	fr.body = containerJSON(t, servedDoc(t, pub, priv, nil), nil, "0123456789ABCDEFGHJKMNPQR0")
	if res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a"); err != nil || res.StandbyKeyAccepted {
		t.Fatalf("%+v %v", res, err)
	}
}

// The empty container (a removed channel) is "nothing here", not a
// refusal of the publisher's signature.
func TestGoogleMirror_EmptyContainer(t *testing.T) {
	r, _, _, fr, _, _ := googleFixture(t, threeMirrors)
	fr.body = []byte(`{"kind":"daal-refresh-v2","slot":"AAAAAAAAAAA"}`)
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if !errors.Is(err, errChannelEmpty) || res.Outcome != OutcomeFreshnessUnreachable {
		t.Fatalf("%+v %v", res, err)
	}
}

// One script serves many relays: a correctly signed document of this
// very relay, served in a container that names another slot, is not
// taken. The slot is part of what the walk checks, never the signature
// alone.
func TestGoogleMirror_AnotherSlotsContainerIsRefused(t *testing.T) {
	r, _, _, fr, pub, priv := googleFixture(t, threeMirrors)
	body := containerJSON(t, servedDoc(t, pub, priv, nil), nil, "")
	fr.body = []byte(strings.Replace(string(body), `"slot":"`+testGoogleSlot+`"`, `"slot":"BBBBBBBBBBB"`, 1))
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err == nil || res.Applied {
		t.Fatalf("another slot's container applied: %+v %v", res, err)
	}
}

// The jitter is bounded by the walk's own slack and by MaxGoogleJitter.
func TestGoogleDelay_Bounded(t *testing.T) {
	r := &RelayPackRefresher{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for i := 0; i < 50; i++ {
		if d := r.googleDelay(ctx); d < 0 || d >= 300*time.Millisecond {
			t.Fatalf("delay %v past the walk's slack", d)
		}
	}
	r.MaxGoogleJitter = time.Millisecond
	if d := r.googleDelay(context.Background()); d >= time.Millisecond {
		t.Fatalf("delay %v past MaxGoogleJitter", d)
	}
	r.GoogleJitter = func(max time.Duration) time.Duration { return max } // out of range
	if d := r.googleDelay(context.Background()); d != 0 {
		t.Fatalf("an out-of-range hook was used: %v", d)
	}
	dead, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if sleepCtx(dead, time.Hour) {
		t.Fatal("slept through a cancelled context")
	}
}

// ---- end to end through the real front fetcher ----------------------

// localFront is a fake Google front for the end-to-end test: one TLS
// listener for every Google name, /exec redirecting to
// script.googleusercontent.com, which serves the container.
type localFront struct {
	srv        *httptest.Server
	pool       *x509.CertPool
	mu         sync.Mutex
	container  []byte
	blockFront bool
	snis       []string
	hosts      []string
}

func newLocalFront(t *testing.T) *localFront {
	t.Helper()
	f := &localFront{}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake google"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"www.google.com", "script.google.com", "script.googleusercontent.com"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(leaf)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hosts = append(f.hosts, r.Host)
		body := f.container
		f.mu.Unlock()
		switch {
		case r.Host == "script.google.com" && strings.HasPrefix(r.URL.Path, "/macros/s/") && r.URL.Query().Get("k") == "AAAAAAAAAAAAAAAAAAAAAA":
			http.Redirect(w, r, "https://script.googleusercontent.com/macros/echo?user_content_key=k1", http.StatusFound)
		case r.Host == "script.googleusercontent.com":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.snis = append(f.snis, h.ServerName)
			if h.ServerName == "www.google.com" && f.blockFront {
				return nil, errors.New("cut")
			}
			return nil, nil
		},
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func TestGoogleMirror_EndToEndThroughTheFront(t *testing.T) {
	for _, blockFront := range []bool{false, true} {
		r, _, _, _, pub, priv := googleFixture(t, threeMirrors)
		r.PerURLTimeout = 3 * time.Second
		r.TotalBudget = 5 * time.Second
		f := newLocalFront(t)
		f.blockFront = blockFront
		now := time.Now().UTC()
		packBody := makePackSBP(t, pub, priv, []string{"r-1"}, now)
		f.container = containerJSON(t, servedDoc(t, pub, priv, func(d *FreshnessDocument) {
			d.CurrentBundleSHA256 = sha256Hex(packBody)
		}), packBody, "")
		var dialMu sync.Mutex
		var dialed []string
		target := f.srv.Listener.Addr().String()
		r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) {
			return dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
				dialMu.Lock()
				dialed = append(dialed, address)
				dialMu.Unlock()
				var d net.Dialer
				return d.DialContext(ctx, network, target)
			}), false, nil
		})
		r.FrontFetch = func(ctx context.Context, url string, d bootstrap.Dialer, timeout time.Duration) ([]byte, error) {
			res, err := bootstrap.FetchAppsScript(ctx, url, d, timeout, bootstrap.FrontOptions{RootCAs: f.pool})
			return res.Body, err
		}
		res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
		if err != nil || !res.Applied || !res.ViaGoogle {
			t.Fatalf("blockFront=%v: %+v %v", blockFront, res, err)
		}
		want := "[www.google.com]"
		if blockFront {
			want = "[www.google.com script.google.com]"
		}
		if got := strings.Join(f.snis, " "); "["+got+"]" != want {
			t.Fatalf("blockFront=%v: SNIs %v", blockFront, f.snis)
		}
		// Only the Google connections went through the dialer here
		// (the ordinary mirrors are scripted), and no more than two.
		if len(dialed) > 2 {
			t.Fatalf("blockFront=%v: %d connections to Google", blockFront, len(dialed))
		}
		if strings.Join(f.hosts, " ") != "script.google.com script.googleusercontent.com" {
			t.Fatalf("blockFront=%v: authorities %v", blockFront, f.hosts)
		}
	}
}
