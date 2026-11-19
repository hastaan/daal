package mgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// rosterBox is a fake relay management service with a real roster:
// /users/list, /users/provision (409 on an existing name, or when full),
// /users/revoke (404 on an unknown name), /identity. Every call is
// signature-checked, and every mutation is counted.
type rosterBox struct {
	mu         sync.Mutex
	users      map[string]int // name -> generation
	gen        int
	max        int
	writes     []string // "provision rN" / "revoke rN", in order
	listStale  bool     // /users/list omits everyone (a lagging list)
	identityOK bool
}

func (b *rosterBox) mux(pub ed25519.PublicKey) *http.ServeMux {
	m := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, ok := boxVerifies(pub, r); !ok {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	m.HandleFunc("/users/list", auth(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		out := []UserMeta{}
		if !b.listStale {
			for n := range b.users {
				out = append(out, UserMeta{Name: n})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": out})
	}))
	m.HandleFunc("/users/provision", auth(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.users[req.Name]; ok {
			http.Error(w, fmt.Sprintf("user %q already exists", req.Name), http.StatusConflict)
			return
		}
		if b.max > 0 && len(b.users) >= b.max {
			http.Error(w, fmt.Sprintf("max recipients (%d) reached on this server", b.max), http.StatusConflict)
			return
		}
		b.gen++
		b.users[req.Name] = b.gen
		b.writes = append(b.writes, "provision "+req.Name)
		_ = json.NewEncoder(w).Encode(UserCreds{Name: req.Name, VLESSUUID: fmt.Sprintf("uuid-%d", b.gen)})
	}))
	m.HandleFunc("/users/revoke", auth(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.users[req.Name]; !ok {
			http.Error(w, fmt.Sprintf("user %q not found", req.Name), http.StatusNotFound)
			return
		}
		delete(b.users, req.Name)
		b.writes = append(b.writes, "revoke "+req.Name)
		_ = json.NewEncoder(w).Encode(RevokeResp{RevokedAtUnix: 1})
	}))
	m.HandleFunc("/identity", auth(func(w http.ResponseWriter, r *http.Request) {
		if !b.identityOK {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(RelayIdentity{IdentityVersion: IdentityVersion, CoverSNI: "www.example.org",
			Families: []RelayIdentityFamily{{Family: "vless-reality", Port: 443, Listening: true}}})
	}))
	return m
}

func newRosterBox(t *testing.T, names ...string) (*rosterBox, ed25519.PrivateKey, *stubProvider, func(reqs []RenewRequest) (*RenewReport, error)) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := &rosterBox{users: map[string]int{}}
	for _, n := range names {
		b.gen++
		b.users[n] = b.gen
	}
	rec, closeFn := mkLiveRec(t, b.mux(pub))
	t.Cleanup(closeFn)
	prov := &stubProvider{}
	run := func(reqs []RenewRequest) (*RenewReport, error) {
		return RenewUsersWithFW(context.Background(), prov, rec, priv, "198.51.100.7", reqs, nil)
	}
	return b, priv, prov, run
}

func resultFor(t *testing.T, rep *RenewReport, name string) RenewResult {
	t.Helper()
	for _, r := range rep.Results {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no result for %s: %+v", name, rep.Results)
	return RenewResult{}
}

func TestRenewUsers_EnsureReplaceRevokeSemantics(t *testing.T) {
	// On the box: r1 (ensure, present), r2 (replace, present), r4
	// (revoke, present). Absent: r3 (ensure), r5 (replace), r6 (revoke).
	b, _, prov, run := newRosterBox(t, "r1", "r2", "r4")
	rep, err := run([]RenewRequest{
		{"r1", RenewEnsure}, {"r2", RenewReplace}, {"r3", RenewEnsure},
		{"r4", RenewRevoke}, {"r5", RenewReplace}, {"r6", RenewRevoke},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertWindowBalanced(t, prov, 1)
	want := map[string]string{"r1": RenewKept, "r2": RenewProvisioned, "r3": RenewProvisioned,
		"r4": RenewRevoked, "r5": RenewProvisioned, "r6": RenewAbsent}
	for name, action := range want {
		r := resultFor(t, rep, name)
		if r.Action != action || !r.OK {
			t.Errorf("%s: %+v, want %s ok", name, r, action)
		}
		if (action == RenewProvisioned) != (r.Creds != nil) {
			t.Errorf("%s: creds present=%v for action %s", name, r.Creds != nil, action)
		}
	}
	if strings.Join(rep.UsersBefore, ",") == "" {
		t.Error("users_before empty")
	}
	if _, ok := b.users["r4"]; ok {
		t.Error("revoked person still on the box")
	}
	// Argv order, and the replace of a present person is revoke-then-provision.
	got := strings.Join(b.writes, "|")
	if got != "revoke r2|provision r2|provision r3|revoke r4|provision r5" {
		t.Errorf("box writes = %s", got)
	}
}

func TestRenewUsers_SecondRunWritesNothingForEnsuredPeople(t *testing.T) {
	b, _, prov, run := newRosterBox(t)
	reqs := []RenewRequest{{"r1", RenewEnsure}, {"r2", RenewEnsure}, {"r3", RenewRevoke}}
	if _, err := run(reqs); err != nil {
		t.Fatal(err)
	}
	before := len(b.writes)
	rep, err := run(reqs)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.writes) != before {
		t.Fatalf("second press wrote to the box: %v", b.writes[before:])
	}
	for _, r := range rep.Results {
		if r.Creds != nil {
			t.Errorf("second press re-keyed %s", r.Name)
		}
	}
	assertWindowBalanced(t, prov, 2)
}

func TestRenewUsers_A409ExistingRetriesOnceA409FullIsRelayFull(t *testing.T) {
	b, _, _, run := newRosterBox(t, "r1")
	b.listStale = true // the list says nobody; the box says r1 exists
	rep, err := run([]RenewRequest{{"r1", RenewEnsure}})
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(t, rep, "r1"); !r.OK || r.Action != RenewProvisioned || r.Creds == nil {
		t.Fatalf("409 retry: %+v", r)
	}
	if got := strings.Join(b.writes, "|"); got != "revoke r1|provision r1" {
		t.Errorf("writes = %s", got)
	}

	b2, _, _, run2 := newRosterBox(t, "r1")
	b2.max = 1
	rep, err = run2([]RenewRequest{{"r2", RenewEnsure}})
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(t, rep, "r2"); r.OK || r.ErrorCode != RenewErrRelayFull || r.Creds != nil {
		t.Fatalf("full relay: %+v", r)
	}
}

func TestRenewUsers_RefusesARevokedPersonListedForAnythingElse(t *testing.T) {
	_, _, prov, run := newRosterBox(t)
	for _, reqs := range [][]RenewRequest{
		{{"r3", RenewRevoke}, {"r3", RenewEnsure}},
		{{"r3", RenewReplace}, {"r3", RenewRevoke}},
		{{"bob", RenewEnsure}},
		{{"r1", "provision"}},
	} {
		if _, err := run(reqs); !errors.Is(err, ErrRenewUsage) {
			t.Errorf("%v: err = %v, want ErrRenewUsage", reqs, err)
		}
	}
	if prov.setCalls != 0 {
		t.Fatal("a refused request opened the firewall")
	}
}

func TestRenewUsers_AnUnreadableRosterChangesNothing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := http.NewServeMux()
	wrote := false
	m.HandleFunc("/users/provision", func(w http.ResponseWriter, r *http.Request) { wrote = true })
	_ = pub
	rec, closeFn := mkLiveRec(t, m) // no /users/list: 404 → too old
	defer closeFn()
	prov := &stubProvider{}
	_, err := RenewUsersWithFW(context.Background(), prov, rec, priv, "198.51.100.7", []RenewRequest{{"r1", RenewEnsure}}, nil)
	if !errors.Is(err, ErrRelayRosterTooOld) {
		t.Fatalf("err = %v, want ErrRelayRosterTooOld", err)
	}
	if wrote {
		t.Fatal("provisioned on a relay whose roster could not be read")
	}
	assertWindowBalanced(t, prov, 1)
}

// --- D3: the management leg of the health check ---

func TestHealthWithFW_AnswersInOneWindow(t *testing.T) {
	b, priv, prov, _ := newRosterBox(t, "r1", "r2")
	b.identityOK = true
	pub := priv.Public().(ed25519.PublicKey)
	rec, closeFn := mkLiveRec(t, b.mux(pub))
	defer closeFn()
	h := HealthWithFW(context.Background(), prov, rec, priv, "198.51.100.7", 2*time.Second)
	if h.State != MgmtAnswers || h.Identity == nil || len(h.Users) != 2 {
		t.Fatalf("health = %+v", h)
	}
	assertWindowBalanced(t, prov, 1)
}

func TestHealthWithFW_OlderRelayWithoutIdentityStillAnswers(t *testing.T) {
	b, priv, prov, _ := newRosterBox(t, "r1")
	pub := priv.Public().(ed25519.PublicKey)
	rec, closeFn := mkLiveRec(t, b.mux(pub))
	defer closeFn()
	h := HealthWithFW(context.Background(), prov, rec, priv, "198.51.100.7", 2*time.Second)
	if h.State != MgmtAnswers || h.Identity != nil || len(h.Users) != 1 {
		t.Fatalf("health = %+v", h)
	}
}

func TestHealthWithFW_WrongKeyOrWrongCertificateIsRefused(t *testing.T) {
	b, _, prov, _ := newRosterBox(t, "r1")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec, closeFn := mkLiveRec(t, b.mux(pub))
	defer closeFn()
	if h := HealthWithFW(context.Background(), prov, rec, otherPriv, "198.51.100.7", 2*time.Second); h.State != MgmtRefused {
		t.Errorf("token the box refuses: %+v", h)
	}
	rec.MgmtTLSFingerprint = strings.Repeat("00", 32)
	if h := HealthWithFW(context.Background(), prov, rec, otherPriv, "198.51.100.7", 2*time.Second); h.State != MgmtRefused {
		t.Errorf("certificate that is not the pinned one: %+v", h)
	}
}

func TestHealthWithFW_NothingListeningIsNoAnswer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if port < 10000 {
		t.Skip("ephemeral port below the mgmt range")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := mkRec(t, strings.Repeat("ab", 32), port)
	prov := &stubProvider{}
	h := HealthWithFW(context.Background(), prov, rec, priv, "198.51.100.7", time.Second)
	if h.State != MgmtNoAnswer {
		t.Fatalf("health = %+v", h)
	}
	assertWindowBalanced(t, prov, 1)
}
