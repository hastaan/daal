package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const boxFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var attackerFingerprint = strings.Repeat("ee", 32)

// onPath is a machine between the publisher and the box during the
// provisioning window. It forwards every request to the real box,
// records what it saw go by, and rewrites the reply.
type onPath struct {
	t       *testing.T
	box     string
	rewrite func(map[string]any)

	mu   sync.Mutex
	seen []string // every request path, as sent by the publisher
}

func (o *onPath) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.seen = append(o.seen, r.URL.Path)
	o.mu.Unlock()
	resp, err := http.Get(o.box + r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(raw)
		return
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		o.t.Errorf("box reply not JSON: %v", err)
	}
	o.rewrite(m)
	_ = json.NewEncoder(w).Encode(m)
}

func pollerFor(t *testing.T, url string) *Poller {
	t.Helper()
	host, port, err := splitURL(url)
	if err != nil {
		t.Fatal(err)
	}
	return &Poller{BoxIP: net.ParseIP(host), Port: port, Token: testToken, Timeout: 2 * time.Second}
}

func realBox(t *testing.T) *httptest.Server {
	t.Helper()
	h, err := NewHandler(HandlerConfig{Token: testToken, Probe: stubProbe{out: Status{Healthy: true, MgmtTLSFingerprint: boxFingerprint}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// The finding this file exists for: the fingerprint the publisher pins
// (and then believes every later management reply on, including the
// keys it signs into a pack) was whatever the plain-HTTP reply said. A
// machine on the path swapped one JSON field and owned the relay's
// identity. It must now be refused — by every entry point a provider
// adapter uses.
func TestPoller_RefusesAFingerprintRewrittenOnThePath(t *testing.T) {
	box := realBox(t)
	for name, rewrite := range map[string]func(map[string]any){
		"fingerprint swapped, box's MAC kept": func(m map[string]any) {
			m["mgmt_tls_fingerprint"] = attackerFingerprint
		},
		"fingerprint swapped, MAC removed": func(m map[string]any) {
			m["mgmt_tls_fingerprint"] = attackerFingerprint
			delete(m, "mgmt_tls_fingerprint_mac")
		},
		"fingerprint swapped, MAC made from everything the path can see": func(m map[string]any) {
			m["mgmt_tls_fingerprint"] = attackerFingerprint
			// The attacker holds the path token (it is in the URL) and
			// tries it as the secret.
			m["mgmt_tls_fingerprint_mac"] = FingerprintMAC(PathToken(testToken), attackerFingerprint)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mitm := &onPath{t: t, box: box.URL, rewrite: rewrite}
			srv := httptest.NewServer(mitm)
			defer srv.Close()
			p := pollerFor(t, srv.URL)

			fp, err := p.WaitForMgmtFingerprint(context.Background(), 2, time.Millisecond)
			if fp != "" || !errors.Is(err, ErrFingerprintUnauthenticated) {
				t.Fatalf("WaitForMgmtFingerprint = %q, %v; want no fingerprint and ErrFingerprintUnauthenticated", fp, err)
			}
			// The Hetzner adapter runs its own loop over PollOnce and
			// reads the field itself: it must never be handed one.
			st, err := p.PollOnce(context.Background())
			if st != nil || !errors.Is(err, ErrFingerprintUnauthenticated) {
				t.Fatalf("PollOnce = %+v, %v; want no status and ErrFingerprintUnauthenticated", st, err)
			}
		})
	}
}

// An honest path changes nothing: the box's own fingerprint verifies.
func TestPoller_AcceptsTheBoxesOwnFingerprint(t *testing.T) {
	box := realBox(t)
	mitm := &onPath{t: t, box: box.URL, rewrite: func(map[string]any) {}}
	srv := httptest.NewServer(mitm)
	defer srv.Close()
	fp, err := pollerFor(t, srv.URL).WaitForMgmtFingerprint(context.Background(), 1, time.Millisecond)
	if err != nil || fp != boxFingerprint {
		t.Fatalf("got %q, %v; want the box's fingerprint", fp, err)
	}
}

// The MAC key is derived from the health token, so the token must not
// be readable off the wire: the URL carries a derived value, and the
// box does not answer the raw token.
func TestPoller_NeverSendsTheHealthToken(t *testing.T) {
	box := realBox(t)
	mitm := &onPath{t: t, box: box.URL, rewrite: func(map[string]any) {}}
	srv := httptest.NewServer(mitm)
	defer srv.Close()
	if _, err := pollerFor(t, srv.URL).WaitForMgmtFingerprint(context.Background(), 1, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if len(mitm.seen) == 0 {
		t.Fatal("the path saw no request")
	}
	for _, path := range mitm.seen {
		if strings.Contains(path, testToken) {
			t.Fatalf("the health token went out in the URL: %s", path)
		}
	}
	resp, err := http.Get(box.URL + "/healthz/" + testToken)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the box answered the raw token with %d; want 404", resp.StatusCode)
	}
}

// The two derived values must not be interchangeable, and the MAC must
// depend on both the secret and the fingerprint.
func TestFingerprintMAC(t *testing.T) {
	mac := FingerprintMAC(testToken, boxFingerprint)
	if !VerifyFingerprintMAC(testToken, boxFingerprint, mac) {
		t.Fatal("a MAC does not verify against its own inputs")
	}
	if !VerifyFingerprintMAC(testToken, "  "+strings.ToUpper(boxFingerprint)+"\n", strings.ToUpper(mac)) {
		t.Error("case and surrounding space in the fingerprint file must not matter")
	}
	for name, ok := range map[string]bool{
		"another fingerprint": VerifyFingerprintMAC(testToken, attackerFingerprint, mac),
		"another secret":      VerifyFingerprintMAC(testToken+"x", boxFingerprint, mac),
		"empty secret":        VerifyFingerprintMAC("", boxFingerprint, FingerprintMAC("", boxFingerprint)),
		"empty MAC":           VerifyFingerprintMAC(testToken, boxFingerprint, ""),
		"truncated MAC":       VerifyFingerprintMAC(testToken, boxFingerprint, mac[:32]),
		"path token as MAC":   VerifyFingerprintMAC(testToken, boxFingerprint, PathToken(testToken)),
	} {
		if ok {
			t.Errorf("%s: verified", name)
		}
	}
	if PathToken(testToken) == testToken || PathToken(testToken) == mac {
		t.Error("the path token must be its own derived value")
	}
	// Pinned vector: the box and the publisher are released separately
	// (cloudinit/artifacts.go), so the derivation is a wire format.
	const wantPath = "ec458bcc5ada54679b67f5dc2a803ff199ce544a8ae49d7bb5e544e69eaa62a3"
	const wantMAC = "c5e0cec94dd3c83f8f3269c292aa6df26853b799ea7adf5b1cd9690cfe7d8c26"
	if got := PathToken("health-token-vector"); got != wantPath {
		t.Errorf("PathToken vector = %s", got)
	}
	if got := FingerprintMAC("health-token-vector", boxFingerprint); got != wantMAC {
		t.Errorf("FingerprintMAC vector = %s", got)
	}
}

// A probe cannot supply (or leak through) its own MAC, and a box with
// no fingerprint yet sends none.
func TestHandler_MakesTheMACItself(t *testing.T) {
	for _, tc := range []struct {
		name    string
		probe   Status
		wantMAC string
	}{
		{"fingerprint", Status{Healthy: true, MgmtTLSFingerprint: strings.ToUpper(boxFingerprint) + "\n", MgmtTLSFingerprintMAC: "probe-wrote-this"}, FingerprintMAC(testToken, boxFingerprint)},
		{"no fingerprint yet", Status{Healthy: true, MgmtTLSFingerprintMAC: "probe-wrote-this"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := NewHandler(HandlerConfig{Token: testToken, Probe: stubProbe{out: tc.probe}})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz/"+PathToken(testToken), nil))
			var st Status
			if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
				t.Fatal(err)
			}
			if st.MgmtTLSFingerprintMAC != tc.wantMAC {
				t.Fatalf("MAC = %q want %q", st.MgmtTLSFingerprintMAC, tc.wantMAC)
			}
		})
	}
}

// A health endpoint that keeps answering 404 will never answer 200:
// it holds another secret, or it is a binary from before the derived
// path token. The wait says so instead of running out the clock — but
// not on the first 404, which a machine mid-rebuild can produce.
func TestWaitForMgmtFingerprint_StopsOnAStandingRefusal(t *testing.T) {
	old := refusalPatience
	refusalPatience = 30 * time.Millisecond
	defer func() { refusalPatience = old }()

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.NotFound(w, r)
	}))
	defer srv.Close()
	start := time.Now()
	_, err := pollerFor(t, srv.URL).WaitForMgmtFingerprint(context.Background(), 100000, time.Millisecond)
	if !errors.Is(err, ErrBootstrapRefused) {
		t.Fatalf("err = %v; want ErrBootstrapRefused", err)
	}
	if hits < 2 || time.Since(start) < refusalPatience {
		t.Fatalf("gave up after %d refusals in %s; want at least two, spanning %s", hits, time.Since(start), refusalPatience)
	}

	// A refusal and then the real box: the run is over, the wait goes on.
	box := realBox(t)
	early := 1
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if early > 0 {
			early--
			http.NotFound(w, r)
			return
		}
		resp, err := http.Get(box.URL + r.URL.Path)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(w, resp.Body)
	}))
	defer flaky.Close()
	fp, err := pollerFor(t, flaky.URL).WaitForMgmtFingerprint(context.Background(), 1000, 40*time.Millisecond)
	if err != nil || fp != boxFingerprint {
		t.Fatalf("got %q, %v; want the box's fingerprint after the early refusal", fp, err)
	}
}

func TestRefusalCounter_AnyOtherAnswerEndsTheRun(t *testing.T) {
	old := refusalPatience
	refusalPatience = 0
	defer func() { refusalPatience = old }()
	var c RefusalCounter
	if c.Final(ErrBootstrapRefused) {
		t.Fatal("the first refusal is never final")
	}
	if c.Final(errors.New("connection refused")) {
		t.Fatal("a transport error is not a refusal")
	}
	if c.Final(ErrBootstrapRefused) {
		t.Fatal("a refusal after another answer starts a new run")
	}
	if !c.Final(ErrBootstrapRefused) {
		t.Fatal("a standing refusal past the patience is final")
	}
}
