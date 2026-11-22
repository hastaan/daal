package refresh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// The update ladder (ladder.go): order, budgets, strikes, what it
// trusts, and when it never runs. Every carrier here is a FakeCarrier:
// no test reaches the network.

type callLog struct {
	mu    sync.Mutex
	names []string
}

func (l *callLog) add(n string) {
	l.mu.Lock()
	l.names = append(l.names, n)
	l.mu.Unlock()
}

func (l *callLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.names...)
}

func (l *callLog) count(n string) int {
	c := 0
	for _, x := range l.all() {
		if x == n {
			c++
		}
	}
	return c
}

// fakeC is a FakeCarrier that logs its name and returns its Notes / Err
// as they are when it is called (tests change them between walks).
func fakeC(log *callLog, name, label, class string, rung int, cost CarrierCost, kinds NoteKind) *FakeCarrier {
	fc := &FakeCarrier{InfoV: CarrierInfo{Name: name, Label: label, Class: class, Rung: rung, Cost: cost, Kinds: kinds}}
	fc.FetchFn = func(ctx context.Context, env *CarrierEnv) ([]Note, error) {
		log.add(name)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fc.mu.Lock()
		notes, err := append([]Note(nil), fc.Notes...), fc.Err
		fc.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return notes, nil
	}
	return fc
}

func (f *FakeCarrier) set(notes []Note, err error) {
	f.mu.Lock()
	f.Notes, f.Err = notes, err
	f.mu.Unlock()
}

// ladderSet is the five readers of this wave, handed to the ladder out
// of order (and one on rung 6, which is not walked).
type ladderSet struct {
	log                                   *callLog
	github, front, direct, jsdelivr, dnsC *FakeCarrier
	rung6                                 *FakeCarrier
}

func newLadderSet() *ladderSet {
	l := &callLog{}
	g := bundle.NoteCarrierGitTag
	return &ladderSet{
		log:      l,
		github:   fakeC(l, "github", g, ClassGitHub, RungGitTag, CarrierCost{TCP: 2}, NoteBoth),
		front:    fakeC(l, "goproxy-front", g, ClassGoogle, RungGoogle, CarrierCost{TCP: 2}, NoteBoth),
		direct:   fakeC(l, "goproxy-direct", g, ClassGoProxy, RungReaders, CarrierCost{TCP: 1}, NoteBoth),
		jsdelivr: fakeC(l, "jsdelivr", g, ClassJSDelivr, RungReaders, CarrierCost{TCP: 1}, NoteBoth),
		dnsC:     fakeC(l, "dns", bundle.NoteCarrierDNS, ClassDNS, RungDNS, CarrierCost{DNS: 6}, NoteMicro),
		rung6:    fakeC(l, "domestic", g, "domestic", 6, CarrierCost{TCP: 1}, NoteBoth),
	}
}

func (s *ladderSet) list() []Carrier {
	return []Carrier{s.dnsC, s.jsdelivr, s.rung6, s.front, s.direct, s.github}
}

// ladderKit is what the pack's file gave the phone.
type ladderKit struct {
	secret bundle.UpdateSecret
	key    bundle.StandbyKeyBytes
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

const (
	ladderTestOwner = "someowner"
	ladderTestRepo  = "somerepo"
	ladderTestZone  = "notes.example.org"
)

// ladderFixture: the failure-walk fixture (two ordinary mirrors, both
// refusing), whose route r-1 holds a people secret, a carriers member
// and a sealed standby. The mirrors' fetches are logged as "mirror".
func ladderFixture(t *testing.T) (*RelayPackRefresher, *fakeRelayStore, *ladderSet, *time.Time, ladderKit) {
	t.Helper()
	t.Cleanup(func() { SetTunnelRequired(false); SetGlobalDialer(nil) })
	SetTunnelRequired(false)
	SetGlobalDialer(nil)
	r, store, sf, pub, priv := newRelayFixture(t, []string{"https://a.example.com/f.json", "https://b.example.com/f.json"})
	nowV := time.Now().UTC().Truncate(time.Second)
	now := &nowV
	r.Now = func() time.Time { return *now }
	r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) { return bootstrap.NewDirectDialer(time.Second), false, nil })
	set := newLadderSet()
	inner := sf.fn()
	r.Fetch = func(ctx context.Context, url string, d bootstrap.Dialer, timeout time.Duration) ([]byte, error) {
		set.log.add("mirror")
		return inner(ctx, url, d, timeout)
	}
	r.LadderCarriers = set.list()
	r.LadderGap = func() time.Duration { return 0 }

	kit := ladderKit{pub: pub, priv: priv}
	kit.secret.Audience = bundle.UpdateAudiencePeople(1)
	if _, err := rand.Read(kit.secret.Secret[:]); err != nil {
		t.Fatal(err)
	}
	k, err := bundle.NewStandbyKey("93.184.216.34", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kit.key = k
	us, err := bundle.MarshalUpdateSecret(kit.secret)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := bundle.MarshalUpdateCarriers(bundle.UpdateCarriers{
		GitTag: &bundle.GitTagCarrier{Owner: ladderTestOwner, Repo: ladderTestRepo},
		DNS:    &bundle.DNSCarrier{Zone: ladderTestZone},
	})
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := json.Marshal(bundle.SealedStandby(k))
	store.secrets[bundle.UpdateSecretStoreKey("r-1")] = us
	store.secrets[bundle.UpdateCarriersStoreKey("r-1")] = cs
	store.secrets[bundle.StandbyStoreKey("r-1")] = sb
	return r, store, set, now, kit
}

func (k ladderKit) slot(t *testing.T, now time.Time) string {
	t.Helper()
	n, err := bundle.NoteName(k.secret.Secret, bundle.NoteCarrierGitTag, bundle.NoteEpochAt(bundle.NoteCarrierGitTag, now))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// fullNote is an opened full note as a carrier hands it over.
func fullNote(t *testing.T, carrier, slot, containerSlot string, doc, pack []byte, key string) Note {
	t.Helper()
	w := map[string]string{"kind": "daal-refresh-v2", "slot": containerSlot}
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
	return Note{Kind: NoteFull, Carrier: carrier, Container: b, Slot: slot}
}

func microNote(carrier string, k bundle.StandbyKeyBytes) Note {
	return Note{Kind: NoteMicro, Carrier: carrier, StandbyKey: k}
}

func ladderAudit(store *fakeRelayStore) []string {
	var out []string
	for _, a := range store.audit {
		if a.kind == auditKindLadder {
			out = append(out, a.outcome)
		}
	}
	return out
}

// ---------------------------------------------------------------------

// 0 → 5 → 1 → 2 → 4 → 3: today's mirrors first, then the git tag, the
// Google front, the other readers, DNS last; rung 6 is not walked.
func TestLadder_WalkOrderAfterTheMirrors(t *testing.T) {
	r, _, set, _, _ := ladderFixture(t)
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err == nil || res.Outcome != OutcomeFreshnessUnreachable {
		t.Fatalf("%+v %v", res, err)
	}
	// Rung 4 gives ONE reader per walk (pickReader): either of the two.
	got := strings.Join(set.log.all(), ",")
	if got != "mirror,mirror,github,goproxy-front,goproxy-direct,dns" && got != "mirror,mirror,github,goproxy-front,jsdelivr,dns" {
		t.Fatalf("order %v", got)
	}
	if res.EndpointsTried != 6 {
		t.Fatalf("tried %d", res.EndpointsTried)
	}
	for _, c := range []string{ClassGitHub, ClassGoogle, ClassDNS} {
		if res.Ladder[c] != LadderNothingNew {
			t.Fatalf("ladder %v", res.Ladder)
		}
	}
	if (res.Ladder[ClassGoProxy] == "") == (res.Ladder[ClassJSDelivr] == "") {
		t.Fatalf("not exactly one rung-4 reader: %v", res.Ladder)
	}
	env := set.github.Envs()[0]
	if env.RelayPackID != "rp-1" || len(env.Secrets) != 1 || env.Carriers == nil || env.Carriers.GitTag == nil ||
		env.Standby == nil || env.Dialer == nil {
		t.Fatalf("env %+v", env)
	}
	// A walk that found nothing is a miss, as before.
	if m := r.loadRecord("rp-1").OnFailureMisses; m != 1 {
		t.Fatalf("misses %d", m)
	}
}

// The person's button runs the ladder too (dialling direct, no route).
func TestLadder_OnDemandWalksItToo(t *testing.T) {
	r, _, set, _, _ := ladderFixture(t)
	r.NetworkKey = func() string { return "net-x" }
	if _, err := r.RefreshOnDemand(context.Background(), "rp-1"); err == nil {
		t.Fatal("premise: nothing should verify")
	}
	if set.github.Calls() != 1 || set.dnsC.Calls() != 1 {
		t.Fatalf("calls %v", set.log.all())
	}
}

// At most 8 TCP connections: a carrier that would not fit is skipped,
// and a smaller one after it still goes.
func TestLadder_TCPBudget(t *testing.T) {
	r, _, _, _, _ := ladderFixture(t)
	l := &callLog{}
	g := bundle.NoteCarrierGitTag
	r.LadderCarriers = []Carrier{
		fakeC(l, "a", g, "c1", RungGitTag, CarrierCost{TCP: 3}, NoteBoth),
		fakeC(l, "b", g, "c2", RungGitTag, CarrierCost{TCP: 3}, NoteBoth),
		fakeC(l, "c", g, "c3", RungGitTag, CarrierCost{TCP: 3}, NoteBoth),
		fakeC(l, "d", g, "c4", RungGitTag, CarrierCost{TCP: 2}, NoteBoth),
		fakeC(l, "e", g, "c5", RungGitTag, CarrierCost{TCP: 1}, NoteBoth),
	}
	_, _ = r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if got := strings.Join(l.all(), ","); got != "a,b,d" {
		t.Fatalf("fetched %s (3+3+2 = 8; c and e do not fit)", got)
	}
}

// At most 6 DNS questions.
func TestLadder_DNSBudget(t *testing.T) {
	r, _, _, _, _ := ladderFixture(t)
	l := &callLog{}
	r.LadderCarriers = []Carrier{
		fakeC(l, "tag", bundle.NoteCarrierGitTag, ClassGitHub, RungGitTag, CarrierCost{TCP: 1, DNS: 1}, NoteBoth),
		fakeC(l, "dns", bundle.NoteCarrierDNS, ClassDNS, RungDNS, CarrierCost{DNS: 6}, NoteMicro),
		fakeC(l, "dns-small", bundle.NoteCarrierDNS, "dns2", RungDNS, CarrierCost{DNS: 5}, NoteMicro),
	}
	_, _ = r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if got := strings.Join(l.all(), ","); got != "tag,dns-small" {
		t.Fatalf("fetched %s", got)
	}
}

// The ladder's own time: a host that never answers holds it to the
// budget, the next host is not reached, and a cut-off is not a strike.
// The waits between hosts count against the same time.
func TestLadder_TimeBudget(t *testing.T) {
	r, store, set, _, _ := ladderFixture(t)
	r.LadderBudget = 300 * time.Millisecond
	set.github.FetchFn = func(ctx context.Context, env *CarrierEnv) ([]Note, error) {
		set.log.add("github")
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("walk took %v", el)
	}
	if set.front.Calls() != 0 || set.dnsC.Calls() != 0 {
		t.Fatalf("hosts after the budget: %v", set.log.all())
	}
	if _, ok := store.secrets[ladderStrikesKey]; ok || res.Ladder[ClassGitHub] != "" {
		t.Fatalf("a cut-off was recorded: %v %s", res.Ladder, store.secrets[ladderStrikesKey])
	}

	// A gap longer than the budget: no host at all.
	r2, _, set2, _, _ := ladderFixture(t)
	r2.LadderBudget = 200 * time.Millisecond
	r2.LadderGap = func() time.Duration { return time.Hour }
	_, _ = r2.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if set2.github.Calls() != 0 {
		t.Fatal("a host was dialled past the ladder's time")
	}
}

// One host per class: the second carrier of a class is not walked, even
// when the first failed. A carrier that says it is unconfigured spends
// nothing and is no strike; Usable false is skipped without a call.
func TestLadder_OneHostPerClass(t *testing.T) {
	r, store, _, _, _ := ladderFixture(t)
	l := &callLog{}
	g := bundle.NoteCarrierGitTag
	a := fakeC(l, "a-unconf", g, ClassGitHub, RungGitTag, CarrierCost{TCP: 1}, NoteBoth)
	a.set(nil, ErrCarrierUnconfigured)
	b := fakeC(l, "b-fails", g, ClassGitHub, RungGitTag, CarrierCost{TCP: 1}, NoteBoth)
	b.set(nil, errors.New("connection reset"))
	c := fakeC(l, "c-same-class", g, ClassGitHub, RungGitTag, CarrierCost{TCP: 1}, NoteBoth)
	u := fakeC(l, "d-unusable", g, ClassGoogle, RungGoogle, CarrierCost{TCP: 1}, NoteBoth)
	u.UsableFn = func(*CarrierEnv) bool { return false }
	r.LadderCarriers = []Carrier{c, b, a, u}
	res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if got := strings.Join(l.all(), ","); got != "a-unconf,b-fails" {
		t.Fatalf("fetched %s", got)
	}
	if res.Ladder[ClassGitHub] != LadderFailed || res.Ladder[ClassGoogle] != "" {
		t.Fatalf("ladder %v", res.Ladder)
	}
	if res.EndpointsTried != 3 { // two mirrors and b
		t.Fatalf("tried %d", res.EndpointsTried)
	}
	st := r.loadStrikes()
	if len(st.Nets) != 1 || st.Nets[0].Classes[ClassGitHub].N != 1 {
		t.Fatalf("strikes %+v", st)
	}
	_ = store
}

// 2–10 s before each host.
func TestLadder_GapBetweenHosts(t *testing.T) {
	r, _, set, _, _ := ladderFixture(t)
	gaps := 0
	r.LadderGap = func() time.Duration { gaps++; return 0 }
	_, _ = r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if gaps != 4 || len(set.log.all()) != 6 {
		t.Fatalf("gaps %d for %v", gaps, set.log.all())
	}
	for i := 0; i < 300; i++ {
		if d := drawLadderGap(); d < 2*time.Second || d > 10*time.Second {
			t.Fatalf("gap %v", d)
		}
	}
}

// A class that failed twice on this network is skipped for 6 hours;
// another network is not held by it; an answer clears it; a clock that
// jumped back holds nothing.
func TestLadder_StrikeRule(t *testing.T) {
	r, _, set, now, _ := ladderFixture(t)
	set.github.set(nil, errors.New("connection reset"))
	walk := func(net string) {
		t.Helper()
		if _, err := r.refresh(context.Background(), "rp-1", kindFailure, net); err == nil {
			t.Fatal("premise: nothing should verify")
		}
	}
	advance := func(d time.Duration) { *now = now.Add(d) }

	walk("net-a")
	advance(time.Hour)
	walk("net-a")
	if set.github.Calls() != 2 {
		t.Fatalf("calls %d", set.github.Calls())
	}
	advance(time.Hour)
	walk("net-a") // struck: skipped, the rest of the walk goes on
	if set.github.Calls() != 2 || set.front.Calls() != 3 {
		t.Fatalf("struck class walked: github %d front %d", set.github.Calls(), set.front.Calls())
	}
	walk("net-b") // another network: walked
	if set.github.Calls() != 3 {
		t.Fatalf("net-b: %d", set.github.Calls())
	}
	advance(5*time.Hour + time.Minute) // 6 h after the second failure on net-a
	walk("net-a")
	if set.github.Calls() != 4 {
		t.Fatalf("after the hold: %d", set.github.Calls())
	}
	advance(time.Hour)
	walk("net-a") // it failed again: held again
	if set.github.Calls() != 4 {
		t.Fatalf("re-held: %d", set.github.Calls())
	}

	// An answer (nothing new) clears the class on that network.
	set.github.set(nil, nil)
	advance(6 * time.Hour)
	walk("net-a")
	if set.github.Calls() != 5 {
		t.Fatalf("after hold: %d", set.github.Calls())
	}
	set.github.set(nil, errors.New("connection reset"))
	advance(time.Minute)
	walk("net-a") // one failure: not yet struck
	advance(time.Minute)
	walk("net-a")
	if set.github.Calls() != 7 {
		t.Fatalf("one failure after an answer held the class: %d", set.github.Calls())
	}
	advance(time.Minute)
	walk("net-a")
	if set.github.Calls() != 7 {
		t.Fatalf("two failures did not hold: %d", set.github.Calls())
	}

	// The clock jumps back past the stamp: no hold.
	advance(-48 * time.Hour)
	walk("net-a")
	if set.github.Calls() != 8 {
		t.Fatalf("future stamp held the class: %d", set.github.Calls())
	}
}

// The first note that verifies as newer ends the walk: a micro note the
// signed standby accepts, offered to the store and kept.
func TestLadder_StopsAtTheFirstNewer_Micro(t *testing.T) {
	r, _, set, _, kit := ladderFixture(t)
	r.saveRecord("rp-1", freshnessRecord{V: 1, OnFailureMisses: 2})
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink
	set.front.set([]Note{microNote("goproxy-front", kit.key)}, nil)
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessStandbyKey || !res.StandbyKeyAccepted || res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	if len(sink.calls) != 1 || sink.calls[0] != "rp-1:"+kit.key.Text() {
		t.Fatalf("offers %v", sink.calls)
	}
	if set.direct.Calls() != 0 || set.jsdelivr.Calls() != 0 || set.dnsC.Calls() != 0 {
		t.Fatalf("walked past the note: %v", set.log.all())
	}
	if res.Ladder[ClassGoogle] != LadderReached || res.Ladder[ClassGitHub] != LadderNothingNew {
		t.Fatalf("ladder %v", res.Ladder)
	}
	if m := r.loadRecord("rp-1").OnFailureMisses; m != 0 {
		t.Fatalf("new information did not reset the misses: %d", m)
	}

	// The same key, already kept on the route: nothing new, walk on.
	r2, store2, set2, _, kit2 := ladderFixture(t)
	sink2 := &recordingSink{accept: true}
	r2.StandbyKeys = sink2
	store2.secrets[bundle.StandbyKeyStoreKey("r-1")] = append([]byte(nil), kit2.key[:]...)
	set2.github.set([]Note{microNote("github", kit2.key)}, nil)
	res2, _ := r2.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if len(sink2.calls) != 0 || res2.StandbyKeyAccepted || set2.github.Calls() != 1 {
		t.Fatalf("a held key was news: %+v %v", res2, sink2.calls)
	}
	// ... and the micro-only DNS reader, which could only bring that same
	// key, is not asked at all (its questions would only go out).
	if set2.dnsC.Calls() != 0 || res2.Ladder[ClassDNS] != "" {
		t.Fatalf("micro-only carrier asked for a key already kept: %v", set2.log.all())
	}

	// A store that refuses it: nothing new either.
	r3, _, set3, _, kit3 := ladderFixture(t)
	r3.StandbyKeys = &recordingSink{accept: false}
	set3.github.set([]Note{microNote("github", kit3.key)}, nil)
	if res3, _ := r3.RefreshFailureTriggered(context.Background(), "rp-1", "net-a"); res3.StandbyKeyAccepted || set3.front.Calls() != 1 {
		t.Fatalf("%+v", res3)
	}
}

// A full note that verifies and names a newer pack ends the walk; the
// pack goes through the same gate as a mirror's.
func TestLadder_StopsAtTheFirstNewer_Full(t *testing.T) {
	r, store, set, now, kit := ladderFixture(t)
	pubK, privK := kit.pub, kit.priv
	packBody := makePackSBP(t, pubK, privK, []string{"r-1"}, *now)
	doc := servedDoc(t, pubK, privK, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = "https://packs.example.com/current.sbp"
	})
	slot := kit.slot(t, *now)
	set.github.set([]Note{fullNote(t, "github", slot, slot, doc, packBody, "")}, nil)
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || !res.Applied || !res.ViaLadder || res.ViaGoogle {
		t.Fatalf("%+v %v", res, err)
	}
	if set.front.Calls() != 0 || set.dnsC.Calls() != 0 {
		t.Fatalf("walked past the note: %v", set.log.all())
	}
	if store.saveCalls == 0 {
		t.Fatal("the importer never wrote the pack")
	}
	if res.Ladder[ClassGitHub] != LadderReached {
		t.Fatalf("ladder %v", res.Ladder)
	}
}

// A full note that verifies but says nothing new does not end the walk;
// when nothing newer comes it is the walk's answer (unchanged).
func TestLadder_UnchangedFullNoteIsNotNewer(t *testing.T) {
	r, store, set, now, kit := ladderFixture(t)
	pubK, privK := kit.pub, kit.priv
	_ = store
	r.saveRecord("rp-1", freshnessRecord{V: 1, HighWaterSequence: 10, CurrentBundleSHA256: repeatHex("de")})
	slot := kit.slot(t, *now)
	set.github.set([]Note{fullNote(t, "github", slot, slot, servedDoc(t, pubK, privK, nil), nil, "")}, nil)
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessUnchanged || !res.ViaLadder || res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	if set.dnsC.Calls() != 1 {
		t.Fatalf("an unchanged note ended the walk: %v", set.log.all())
	}
	if res.Ladder[ClassGitHub] != LadderNothingNew {
		t.Fatalf("ladder %v", res.Ladder)
	}
}

// A micro candidate the signed commitment does not accept is never
// offered, and the walk goes on.
func TestLadder_MicroThatDoesNotMatch(t *testing.T) {
	r, _, set, _, _ := ladderFixture(t)
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink
	other, _ := bundle.NewStandbyKey("93.184.216.35", rand.Reader)
	set.github.set([]Note{microNote("github", other)}, nil)
	set.dnsC.set([]Note{microNote("dns", other)}, nil)
	res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if len(sink.calls) != 0 || res.StandbyKeyAccepted {
		t.Fatalf("a foreign key was offered: %v", sink.calls)
	}
	if set.front.Calls() != 1 || res.Ladder[ClassGitHub] != LadderNothingNew || res.Ladder[ClassDNS] != LadderNothingNew {
		t.Fatalf("%+v %v", res, set.log.all())
	}
}

// A full note at the wrong name, or one that fails any check a mirror's
// document gets, is nothing: no pack, no key, the walk goes on.
func TestLadder_FullNoteRefused(t *testing.T) {
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	type mk func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note
	newer := func(pub ed25519.PublicKey, priv ed25519.PrivateKey, mut func(*FreshnessDocument)) []byte {
		return servedDoc(t, pub, priv, func(d *FreshnessDocument) {
			d.Sequence = 11
			d.CurrentBundleSHA256 = repeatHex("ab")
			if mut != nil {
				mut(d)
			}
		})
	}
	cases := map[string]mk{
		"a name no held secret gives": func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note {
			return fullNote(t, "github", "aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa", newer(pub, priv, nil), nil, "")
		},
		"container names another slot": func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note {
			return fullNote(t, "github", slot, "aaaaaaaaaaaaaaaa", newer(pub, priv, nil), nil, "")
		},
		"old sequence": func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note {
			return fullNote(t, "github", slot, slot, newer(pub, priv, func(d *FreshnessDocument) { d.Sequence = 5 }), nil, "")
		},
		"another publisher": func(t *testing.T, slot string, _ ed25519.PublicKey, _ ed25519.PrivateKey) Note {
			return fullNote(t, "github", slot, slot, newer(otherPub, otherPriv, nil), nil, "")
		},
		"expired": func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note {
			return fullNote(t, "github", slot, slot, newer(pub, priv, func(d *FreshnessDocument) {
				d.NotAfter = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
			}), nil, "")
		},
		"another pack": func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note {
			return fullNote(t, "github", slot, slot, newer(pub, priv, func(d *FreshnessDocument) { d.RelayPackID = "rp-other" }), nil, "")
		},
		"bad signature": func(t *testing.T, slot string, pub ed25519.PublicKey, priv ed25519.PrivateKey) Note {
			d := strings.Replace(string(newer(pub, priv, nil)), `"sequence":11`, `"sequence":12`, 1)
			return fullNote(t, "github", slot, slot, []byte(d), nil, "")
		},
	}
	for name, mkNote := range cases {
		r, store, set, now, kit := ladderFixture(t)
		pubK, privK := kit.pub, kit.priv
		_ = store
		r.saveRecord("rp-1", freshnessRecord{V: 1, HighWaterSequence: 9, CurrentBundleSHA256: repeatHex("de")})
		sink := &recordingSink{accept: true}
		r.StandbyKeys = sink
		set.github.set([]Note{mkNote(t, kit.slot(t, *now), pubK, privK)}, nil)
		res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
		if err == nil || res.Applied || res.StandbyKeyAccepted || res.ViaLadder || len(sink.calls) != 0 {
			t.Errorf("%s: %+v %v", name, res, err)
		}
		if set.front.Calls() != 1 || res.Ladder[ClassGitHub] != LadderNothingNew {
			t.Errorf("%s: %v %v", name, set.log.all(), res.Ladder)
		}
		if hw := r.loadRecord("rp-1").HighWaterSequence; hw != 9 {
			t.Errorf("%s: high-water moved to %d", name, hw)
		}
	}
}

// An older file (no update secret, or no carriers member, or a member
// naming no carrier): the ladder does nothing and the walk is today's.
func TestLadder_NoOpForAnOlderFile(t *testing.T) {
	cases := map[string]func(s *fakeRelayStore){
		"no secret":   func(s *fakeRelayStore) { delete(s.secrets, bundle.UpdateSecretStoreKey("r-1")) },
		"no carriers": func(s *fakeRelayStore) { delete(s.secrets, bundle.UpdateCarriersStoreKey("r-1")) },
		"empty member": func(s *fakeRelayStore) {
			s.secrets[bundle.UpdateCarriersStoreKey("r-1")] = []byte(`{"v":1}`)
		},
		"malformed member": func(s *fakeRelayStore) {
			s.secrets[bundle.UpdateCarriersStoreKey("r-1")] = []byte(`{"v":1,"gittag":{"owner":"x"}}`)
		},
	}
	// Today's walk, as it is with no ladder at all.
	base, _, baseSet, _, _ := ladderFixture(t)
	base.LadderCarriers = []Carrier{}
	want, wantErr := base.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	wantRec := base.loadRecord("rp-1")
	if len(baseSet.log.all()) != 2 {
		t.Fatalf("premise: %v", baseSet.log.all())
	}
	for name, strip := range cases {
		r, store, set, _, _ := ladderFixture(t)
		strip(store)
		gaps := 0
		r.LadderGap = func() time.Duration { gaps++; return 0 }
		res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
		if (err == nil) != (wantErr == nil) || res.Outcome != want.Outcome || res.EndpointsTried != want.EndpointsTried ||
			res.Ladder != nil || res.ViaLadder || res.StandbyKeyAccepted {
			t.Errorf("%s: %+v %v, want %+v %v", name, res, err, want, wantErr)
		}
		for _, c := range []*FakeCarrier{set.github, set.front, set.direct, set.jsdelivr, set.dnsC} {
			if c.Calls() != 0 {
				t.Errorf("%s: %s was called", name, c.InfoV.Name)
			}
		}
		if gaps != 0 || len(ladderAudit(store)) != 0 {
			t.Errorf("%s: gaps %d audit %v", name, gaps, ladderAudit(store))
		}
		if _, ok := store.secrets[ladderStrikesKey]; ok {
			t.Errorf("%s: strikes written", name)
		}
		rec := r.loadRecord("rp-1")
		if rec.OnFailureMisses != wantRec.OnFailureMisses || rec.LastOutcome != wantRec.LastOutcome ||
			len(rec.OnFailureLog) != len(wantRec.OnFailureLog) {
			t.Errorf("%s: record %+v, want %+v", name, rec, wantRec)
		}
	}
}

// Never under a live route, never from the scheduled poll.
func TestLadder_NeverUnderALiveRoute(t *testing.T) {
	calls := func(s *ladderSet) int {
		return s.github.Calls() + s.front.Calls() + s.direct.Calls() + s.jsdelivr.Calls() + s.dnsC.Calls()
	}

	// The scheduled poll (due: no record), riding the tunnel.
	r, _, set, _, _ := ladderFixture(t)
	if res, _ := r.Refresh(context.Background(), "rp-1"); res.Outcome != OutcomeFreshnessUnreachable || calls(set) != 0 {
		t.Fatalf("scheduled: %+v %v", res, set.log.all())
	}
	// The scheduled poll dialling direct (no tunnel dialer installed).
	r, _, set, _, _ = ladderFixture(t)
	r.Dialer = DialerFn(func() (bootstrap.Dialer, bool, error) { return bootstrap.NewDirectDialer(time.Second), false, nil })
	if res, _ := r.Refresh(context.Background(), "rp-1"); res.Outcome != OutcomeFreshnessUnreachable || calls(set) != 0 {
		t.Fatalf("scheduled direct: %+v %v", res, set.log.all())
	}
	// The user kind of the scheduler's API.
	r, _, set, _, _ = ladderFixture(t)
	if _, _ = r.RefreshUser(context.Background(), "rp-1"); calls(set) != 0 {
		t.Fatalf("user: %v", set.log.all())
	}

	// A route is up: the button rides the tunnel, the ladder stays home.
	r, _, set, _, _ = ladderFixture(t)
	SetTunnelRequired(true)
	if res, _ := r.RefreshOnDemand(context.Background(), "rp-1"); !res.ViaTunnel || calls(set) != 0 {
		t.Fatalf("button under a route: %+v %v", res, set.log.all())
	}
	// ... and the engine's walk is refused outright.
	if res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a"); res.Outcome != OutcomeFreshnessTunnel || calls(set) != 0 {
		t.Fatalf("failure under a route: %+v", res)
	}
	SetTunnelRequired(false)

	// A route comes up half-way: the carrier's dialer refuses, the
	// ladder stops, and that is no strike.
	r, store, set, _, _ := ladderFixture(t)
	set.github.FetchFn = func(ctx context.Context, env *CarrierEnv) ([]Note, error) {
		set.log.add("github")
		SetTunnelRequired(true)
		if _, err := env.Dialer.DialContext(ctx, "tcp", "192.0.2.1:443"); !errors.Is(err, ErrTunnelRequired) {
			t.Errorf("the carrier's dialer dialled under a route: %v", err)
		}
		return nil, ErrTunnelRequired
	}
	res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	SetTunnelRequired(false)
	if set.front.Calls() != 0 || set.dnsC.Calls() != 0 {
		t.Fatalf("walked on under a route: %v", set.log.all())
	}
	if _, ok := store.secrets[ladderStrikesKey]; ok || res.Ladder[ClassGitHub] != "" {
		t.Fatalf("a refusal was a strike: %v", res.Ladder)
	}
}

// What is recorded: a class and a coarse word. Never the repository,
// the zone, a note name or an address.
func TestLadder_DiagnosticsAreCoarse(t *testing.T) {
	r, store, set, now, kit := ladderFixture(t)
	set.github.set(nil, errors.New("dial tcp 140.82.112.3:443: connection reset"))
	res, _ := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	got := strings.Join(ladderAudit(store), ",")
	if got != "dns:nothing_new,github:failed,google:nothing_new,goproxy:nothing_new" &&
		got != "dns:nothing_new,github:failed,google:nothing_new,jsdelivr:nothing_new" {
		t.Fatalf("audit %s", got)
	}
	body, _ := json.Marshal(res)
	var all []string
	for _, a := range store.audit {
		all = append(all, a.kind, a.refID, a.outcome)
	}
	for _, blob := range []string{string(body), strings.Join(all, " "), string(store.secrets[ladderStrikesKey]),
		string(store.secrets[freshnessKey("rp-1")])} {
		for _, secret := range []string{ladderTestOwner, ladderTestRepo, ladderTestZone, kit.slot(t, *now), "140.82", "net-a"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("%q recorded in %s", secret, blob)
			}
		}
	}
	for c, w := range res.Ladder {
		if w != LadderReached && w != LadderNothingNew && w != LadderFailed {
			t.Fatalf("word %s=%s", c, w)
		}
	}
}
