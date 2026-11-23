package refresh

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// The drill (drill.go): the ladder only, every class it may ask, the
// strike hold ignored, its own rate limit, never under a route, and the
// same trust as any walk. Every carrier is a fake: no network.

func drillCalls(s *ladderSet) int {
	return s.github.Calls() + s.front.Calls() + s.direct.Calls() + s.jsdelivr.Calls() + s.dnsC.Calls()
}

// Every class is asked once, within the caps; the mirrors are not
// walked; the unchosen rung-4 class says budget.
func TestDrill_AsksEveryClassOnce(t *testing.T) {
	r, store, set, _, _ := ladderFixture(t)
	res, err := r.RefreshDrill(context.Background(), "rp-1")
	if err == nil || res.Outcome != OutcomeFreshnessUnreachable || res.Kind != "drill" {
		t.Fatalf("%+v %v", res, err)
	}
	if set.log.count("mirror") != 0 {
		t.Fatalf("the drill walked the mirrors: %v", set.log.all())
	}
	if set.github.Calls() != 1 || set.front.Calls() != 1 || set.dnsC.Calls() != 1 || set.rung6.Calls() != 0 {
		t.Fatalf("calls %v", set.log.all())
	}
	if set.direct.Calls()+set.jsdelivr.Calls() != 1 {
		t.Fatalf("not exactly one rung-4 reader: %v", set.log.all())
	}
	for _, c := range []string{ClassGitHub, ClassGoogle, ClassDNS} {
		if res.Drill[c].Result != DrillNothingNew {
			t.Fatalf("drill %v", res.Drill)
		}
	}
	asked, other := ClassGoProxy, ClassJSDelivr
	if set.jsdelivr.Calls() == 1 {
		asked, other = ClassJSDelivr, ClassGoProxy
	}
	if res.Drill[asked].Result != DrillNothingNew || res.Drill[other] != (DrillClass{Result: DrillSkipped, Reason: DrillSkipBudget}) {
		t.Fatalf("drill %v", res.Drill)
	}
	if len(res.Drill) != 5 {
		t.Fatalf("classes %v", res.Drill)
	}
	// Normal words for the audit, as any ladder walk.
	for _, a := range ladderAudit(store) {
		if !strings.HasSuffix(a, ":"+LadderNothingNew) {
			t.Fatalf("audit %v", ladderAudit(store))
		}
	}
	if res.Ladder[ClassGitHub] != LadderNothingNew {
		t.Fatalf("ladder %v", res.Ladder)
	}
}

// A note that verifies and is not newer does not end the drill: it says
// verified, the walk goes on, and the document is adopted as usual.
func TestDrill_GoesOnAfterAVerifiedNote(t *testing.T) {
	r, _, set, now, kit := ladderFixture(t)
	r.saveRecord("rp-1", freshnessRecord{V: 1, HighWaterSequence: 10, CurrentBundleSHA256: repeatHex("de")})
	slot := kit.slot(t, *now)
	set.github.set([]Note{fullNote(t, "github", slot, slot, servedDoc(t, kit.pub, kit.priv, nil), nil, "")}, nil)
	// A micro note for the key the route keeps already: verified too, and
	// the micro-only DNS reader is asked although nothing can be news.
	store := r.Store.(*fakeRelayStore)
	store.secrets[bundle.StandbyKeyStoreKey("r-1")] = append([]byte(nil), kit.key[:]...)
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink
	set.dnsC.set([]Note{microNote("dns", kit.key)}, nil)
	res, err := r.RefreshDrill(context.Background(), "rp-1")
	if err != nil || res.Outcome != OutcomeFreshnessUnchanged || res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	if set.front.Calls() != 1 || set.dnsC.Calls() != 1 {
		t.Fatalf("the drill stopped at a note: %v", set.log.all())
	}
	if res.Drill[ClassGitHub].Result != DrillVerified || res.Drill[ClassDNS].Result != DrillVerified ||
		res.Drill[ClassGoogle].Result != DrillNothingNew {
		t.Fatalf("drill %v", res.Drill)
	}
	if res.Ladder[ClassGitHub] != LadderNothingNew || res.Ladder[ClassDNS] != LadderNothingNew {
		t.Fatalf("ladder words changed: %v", res.Ladder)
	}
	if len(sink.calls) != 0 || res.StandbyKeyAccepted {
		t.Fatalf("a kept key was offered: %v", sink.calls)
	}
}

// A newer note is applied through the same gate; the walk still asks
// the rest; the class that brought it says reached, a second class with
// the same news says verified.
func TestDrill_NewerNoteIsApplied(t *testing.T) {
	r, store, set, now, kit := ladderFixture(t)
	packBody := makePackSBP(t, kit.pub, kit.priv, []string{"r-1"}, *now)
	doc := servedDoc(t, kit.pub, kit.priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = "https://packs.example.com/current.sbp"
	})
	slot := kit.slot(t, *now)
	set.github.set([]Note{fullNote(t, "github", slot, slot, doc, packBody, "")}, nil)
	set.front.set([]Note{fullNote(t, "goproxy-front", slot, slot, doc, packBody, "")}, nil)
	res, err := r.RefreshDrill(context.Background(), "rp-1")
	if err != nil || !res.Applied || !res.ViaLadder || res.Outcome != OutcomeFreshnessOK {
		t.Fatalf("%+v %v", res, err)
	}
	if store.saveCalls == 0 {
		t.Fatal("the importer never wrote the pack")
	}
	if set.dnsC.Calls() != 1 || set.front.Calls() != 1 {
		t.Fatalf("the drill stopped at the first newer note: %v", set.log.all())
	}
	if res.Drill[ClassGitHub].Result != DrillReached || res.Drill[ClassGoogle].Result != DrillVerified {
		t.Fatalf("drill %v", res.Drill)
	}

	// A newer note whose pack cannot be had: verified, not reached.
	r2, _, set2, now2, kit2 := ladderFixture(t)
	doc2 := servedDoc(t, kit2.pub, kit2.priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = repeatHex("ab")
		d.CurrentSignedURL = "https://packs.example.com/current.sbp"
	})
	slot2 := kit2.slot(t, *now2)
	set2.github.set([]Note{fullNote(t, "github", slot2, slot2, doc2, nil, "")}, nil)
	res2, _ := r2.RefreshDrill(context.Background(), "rp-1")
	if res2.Applied || res2.Drill[ClassGitHub].Result != DrillVerified {
		t.Fatalf("%+v %v", res2, res2.Drill)
	}
}

// A micro note the store keeps: reached, and the walk goes on.
func TestDrill_MicroNoteKept(t *testing.T) {
	r, _, set, _, kit := ladderFixture(t)
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink
	set.github.set([]Note{microNote("github", kit.key)}, nil)
	res, err := r.RefreshDrill(context.Background(), "rp-1")
	if err != nil || !res.StandbyKeyAccepted || res.Outcome != OutcomeFreshnessStandbyKey {
		t.Fatalf("%+v %v", res, err)
	}
	if set.front.Calls() != 1 || set.dnsC.Calls() != 1 || len(sink.calls) != 1 {
		t.Fatalf("calls %v offers %v", set.log.all(), sink.calls)
	}
	if res.Drill[ClassGitHub].Result != DrillReached {
		t.Fatalf("drill %v", res.Drill)
	}
}

// A class the strike rule holds is asked; its failure still counts.
func TestDrill_AsksAStruckClass(t *testing.T) {
	r, _, set, now, _ := ladderFixture(t)
	r.NetworkKey = func() string { return "net-a" }
	set.github.set(nil, errors.New("connection reset"))
	for i := 0; i < 3; i++ {
		_, _ = r.refresh(context.Background(), "rp-1", kindFailure, "net-a")
		*now = now.Add(time.Hour)
	}
	if set.github.Calls() != 2 {
		t.Fatalf("premise: the hold: %d", set.github.Calls())
	}
	res, _ := r.RefreshDrill(context.Background(), "rp-1")
	if set.github.Calls() != 3 || res.Drill[ClassGitHub].Result != DrillFailed {
		t.Fatalf("the drill did not ask the held class: %d %v", set.github.Calls(), res.Drill)
	}
	st := r.loadStrikes()
	if len(st.Nets) != 1 || st.Nets[0].Classes[ClassGitHub].N != 3 {
		t.Fatalf("the failure did not count: %+v", st)
	}
}

// Once per 10 minutes per pack; a clock that jumped back does not hold
// it; a drill refused before anything went out gives the stamp back.
func TestDrill_RateLimit(t *testing.T) {
	r, _, set, now, _ := ladderFixture(t)
	if _, err := r.RefreshDrill(context.Background(), "rp-1"); err == nil {
		t.Fatal("premise: nothing should verify")
	}
	n := drillCalls(set)
	*now = now.Add(9 * time.Minute)
	res, _ := r.RefreshDrill(context.Background(), "rp-1")
	if res.Outcome != OutcomeFreshnessRateLimited || res.RetryAfterS != 60 || drillCalls(set) != n {
		t.Fatalf("%+v calls %d", res, drillCalls(set))
	}
	// The on-demand button is not held by the drill, nor the drill by it.
	if due, _ := r.OnDemandDue("rp-1"); !due {
		t.Fatal("the drill spent the button's minute")
	}
	*now = now.Add(time.Minute)
	if res, _ := r.RefreshDrill(context.Background(), "rp-1"); res.Outcome == OutcomeFreshnessRateLimited {
		t.Fatalf("after 10 minutes: %+v", res)
	}
	// The clock jumps back a day: the stamp is in the future, no hold.
	*now = now.Add(-24 * time.Hour)
	if res, _ := r.RefreshDrill(context.Background(), "rp-1"); res.Outcome == OutcomeFreshnessRateLimited {
		t.Fatalf("a future stamp held the drill: %+v", res)
	}

	// Nothing usable: nothing went out, the stamp is given back.
	r2, _, set2, _, _ := ladderFixture(t)
	for _, c := range []*FakeCarrier{set2.github, set2.front, set2.direct, set2.jsdelivr, set2.dnsC} {
		c.UsableFn = func(*CarrierEnv) bool { return false }
	}
	res2, _ := r2.RefreshDrill(context.Background(), "rp-1")
	if res2.Outcome != OutcomeFreshnessNoEndpoints || drillCalls(set2) != 0 {
		t.Fatalf("%+v", res2)
	}
	if r2.loadRecord("rp-1").DrillAt != "" {
		t.Fatal("a drill that sent nothing kept its stamp")
	}
	if res2.Drill[ClassGitHub] != (DrillClass{Result: DrillSkipped, Reason: DrillSkipNotHeld}) {
		t.Fatalf("drill %v", res2.Drill)
	}
}

// Never while a route is up: refused, nothing dialled, nothing stamped,
// every class "route_up". A route coming up half-way stops it.
func TestDrill_NeverUnderARoute(t *testing.T) {
	r, store, set, _, _ := ladderFixture(t)
	SetTunnelRequired(true)
	res, err := r.RefreshDrill(context.Background(), "rp-1")
	SetTunnelRequired(false)
	if !errors.Is(err, ErrTunnelRequired) || res.Outcome != OutcomeFreshnessTunnel || drillCalls(set) != 0 ||
		set.log.count("mirror") != 0 {
		t.Fatalf("%+v %v %v", res, err, set.log.all())
	}
	if len(res.Drill) != 5 || res.Drill[ClassDNS] != (DrillClass{Result: DrillSkipped, Reason: DrillSkipRouteUp}) {
		t.Fatalf("drill %v", res.Drill)
	}
	if r.loadRecord("rp-1").DrillAt != "" || len(store.audit) != 0 {
		t.Fatal("a refused drill left a trace")
	}

	r2, store2, set2, _, _ := ladderFixture(t)
	set2.front.FetchFn = func(ctx context.Context, env *CarrierEnv) ([]Note, error) {
		set2.log.add("goproxy-front")
		SetTunnelRequired(true)
		return nil, ErrTunnelRequired
	}
	res2, _ := r2.RefreshDrill(context.Background(), "rp-1")
	SetTunnelRequired(false)
	if set2.dnsC.Calls() != 0 || set2.direct.Calls()+set2.jsdelivr.Calls() != 0 {
		t.Fatalf("walked on under a route: %v", set2.log.all())
	}
	if res2.Drill[ClassGitHub].Result != DrillNothingNew || res2.Drill[ClassGoogle].Reason != DrillSkipRouteUp ||
		res2.Drill[ClassDNS].Reason != DrillSkipRouteUp {
		t.Fatalf("drill %v", res2.Drill)
	}
	if st := r2.loadStrikes(); len(st.Nets) != 0 {
		t.Fatalf("a route coming up was a strike: %+v %s", st, store2.secrets[ladderStrikesKey])
	}
}

// A file with no update secret or no carriers member: a clear refusal,
// nothing dialled, nothing stamped.
func TestDrill_RefusedForAnOlderFile(t *testing.T) {
	for name, strip := range map[string]func(s *fakeRelayStore){
		"no secret":   func(s *fakeRelayStore) { delete(s.secrets, bundle.UpdateSecretStoreKey("r-1")) },
		"no carriers": func(s *fakeRelayStore) { delete(s.secrets, bundle.UpdateCarriersStoreKey("r-1")) },
	} {
		r, store, set, _, _ := ladderFixture(t)
		strip(store)
		dialled := false
		r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) {
			dialled = true
			return NoDialer, false, nil
		})
		res, err := r.RefreshDrill(context.Background(), "rp-1")
		if err != nil || res.Outcome != OutcomeDrillNotHeld || res.Drill != nil {
			t.Errorf("%s: %+v %v", name, res, err)
		}
		if dialled || len(set.log.all()) != 0 || len(store.audit) != 0 || r.loadRecord("rp-1").DrillAt != "" {
			t.Errorf("%s: dialled=%v calls %v audit %v", name, dialled, set.log.all(), store.audit)
		}
	}
}

// Skip reasons: a carrier the file does not name says not_in_file; the
// DNS reader with no resolver known says no_resolver (not a failure, not
// a strike, nothing asked).
func TestDrill_SkipReasons(t *testing.T) {
	r, store, set, _, _ := ladderFixture(t)
	cs, err := bundle.MarshalUpdateCarriers(bundle.UpdateCarriers{DNS: &bundle.DNSCarrier{Zone: ladderTestZone}})
	if err != nil {
		t.Fatal(err)
	}
	store.secrets[bundle.UpdateCarriersStoreKey("r-1")] = cs
	gitUsable := func(env *CarrierEnv) bool { return env.Carriers != nil && env.Carriers.GitTag != nil }
	for _, c := range []*FakeCarrier{set.github, set.front, set.direct, set.jsdelivr} {
		c.UsableFn = gitUsable
	}
	noResolver := &dnsCarrier{linkResolver: func() (netip.AddrPort, bool) { return netip.AddrPort{}, false }}
	r.LadderCarriers = []Carrier{set.github, set.front, set.direct, set.jsdelivr, noResolver}
	res, _ := r.RefreshDrill(context.Background(), "rp-1")
	want := map[string]DrillClass{
		ClassGitHub:   {Result: DrillSkipped, Reason: DrillSkipNotInFile},
		ClassGoogle:   {Result: DrillSkipped, Reason: DrillSkipNotInFile},
		ClassGoProxy:  {Result: DrillSkipped, Reason: DrillSkipNotInFile},
		ClassJSDelivr: {Result: DrillSkipped, Reason: DrillSkipNotInFile},
		ClassDNS:      {Result: DrillSkipped, Reason: DrillSkipNoResolver},
	}
	for c, w := range want {
		if res.Drill[c] != w {
			t.Fatalf("%s: %v (all %v)", c, res.Drill[c], res.Drill)
		}
	}
	if len(set.log.all()) != 0 || res.Ladder[ClassDNS] != "" {
		t.Fatalf("calls %v ladder %v", set.log.all(), res.Ladder)
	}
	if _, ok := store.secrets[ladderStrikesKey]; ok {
		t.Fatal("no resolver was a strike")
	}
	// The DNS reader's own words, directly.
	env := &CarrierEnv{Carriers: &bundle.UpdateCarriers{GitTag: &bundle.GitTagCarrier{Owner: "o", Repo: "r"}}}
	if w := noResolver.SkipReason(env); w != DrillSkipNotInFile {
		t.Fatalf("no zone: %s", w)
	}
	env.Carriers.DNS = &bundle.DNSCarrier{Zone: ladderTestZone}
	if w := noResolver.SkipReason(env); w != DrillSkipNotHeld {
		t.Fatalf("no standby: %s", w)
	}
}

// What the caller gets: words only. Never the repository, the zone, a
// note name or an address.
func TestDrill_AnswerIsCoarse(t *testing.T) {
	r, store, set, now, kit := ladderFixture(t)
	set.github.set(nil, errors.New("dial tcp 140.82.112.3:443: connection reset"))
	res, _ := r.RefreshDrill(context.Background(), "rp-1")
	body, _ := json.Marshal(res)
	drill, _ := json.Marshal(res.Drill)
	var all []string
	for _, a := range store.audit {
		all = append(all, a.kind, a.refID, a.outcome)
	}
	for _, blob := range []string{string(body), string(drill), strings.Join(all, " "), string(store.secrets[freshnessKey("rp-1")])} {
		for _, secret := range []string{ladderTestOwner, ladderTestRepo, ladderTestZone, kit.slot(t, *now), "140.82"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("%q in %s", secret, blob)
			}
		}
	}
	if strings.Contains(string(body), "drill\":{") {
		t.Fatalf("the per-class map is marshalled with the pack result: %s", body)
	}
	words := map[string]bool{DrillReached: true, DrillVerified: true, DrillNothingNew: true, DrillFailed: true, DrillSkipped: true}
	for c, w := range res.Drill {
		if !words[w.Result] || (w.Result == DrillSkipped) != (w.Reason != "") {
			t.Fatalf("%s=%+v", c, w)
		}
	}
	if res.Drill[ClassGitHub].Result != DrillFailed {
		t.Fatalf("drill %v", res.Drill)
	}
}

// The backup routes a file holds: names nothing, present only with a
// secret and the carrier (and, for DNS, a sealed standby and a secret
// DNS may use).
func TestBackupRoutes(t *testing.T) {
	r, store, _, _, _ := ladderFixture(t)
	if got := strings.Join(r.BackupRoutes("rp-1"), ","); got != "gittag,dns" {
		t.Fatalf("both: %s", got)
	}
	if got := r.BackupRoutes("rp-other"); got != nil {
		t.Fatalf("unknown pack: %v", got)
	}
	delete(store.secrets, bundle.StandbyStoreKey("r-1"))
	if got := strings.Join(r.BackupRoutes("rp-1"), ","); got != "gittag" {
		t.Fatalf("no standby: %s", got)
	}
	cs, _ := bundle.MarshalUpdateCarriers(bundle.UpdateCarriers{DNS: &bundle.DNSCarrier{Zone: ladderTestZone}})
	store.secrets[bundle.UpdateCarriersStoreKey("r-1")] = cs
	if got := r.BackupRoutes("rp-1"); len(got) != 0 {
		t.Fatalf("dns without standby: %v", got)
	}
	delete(store.secrets, bundle.UpdateSecretStoreKey("r-1"))
	if got := r.BackupRoutes("rp-1"); got != nil {
		t.Fatalf("no secret: %v", got)
	}
}
