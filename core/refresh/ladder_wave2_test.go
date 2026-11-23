package refresh

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
)

// The review's repairs of the ladder: a pack with no mirror, one rung-4
// reader per walk, micro-only carriers skipped when nothing can be news,
// two connections to Google per walk, the DNS reader's e−1 and its stop
// under a route.

// noMirrorFixture: ladderFixture's pack, but signed with no mirror set
// (a relay under the two-mirror floor).
func noMirrorFixture(t *testing.T) (*RelayPackRefresher, *fakeRelayStore, *ladderSet, *time.Time, ladderKit) {
	t.Helper()
	r, store, set, now, kit := ladderFixture(t)
	for i := range store.routes {
		store.routes[i].FreshnessURL = ""
	}
	return r, store, set, now, kit
}

func TestLadder_PackWithNoMirror_MicroNote(t *testing.T) {
	r, _, set, _, kit := noMirrorFixture(t)
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink
	set.github.set([]Note{microNote("github", kit.key)}, nil)
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessStandbyKey || !res.StandbyKeyAccepted {
		t.Fatalf("%+v %v", res, err)
	}
	if set.log.count("mirror") != 0 || set.github.Calls() != 1 || len(sink.calls) != 1 {
		t.Fatalf("calls %v offers %v", set.log.all(), sink.calls)
	}
}

func TestLadder_PackWithNoMirror_FullNote(t *testing.T) {
	r, store, set, now, kit := noMirrorFixture(t)
	packBody := makePackSBP(t, kit.pub, kit.priv, []string{"r-1"}, *now)
	doc := servedDoc(t, kit.pub, kit.priv, func(d *FreshnessDocument) {
		d.CurrentBundleSHA256 = sha256Hex(packBody)
		d.CurrentSignedURL = "https://packs.example.com/current.sbp"
	})
	slot := kit.slot(t, *now)
	set.github.set([]Note{fullNote(t, "github", slot, slot, doc, packBody, "")}, nil)
	res, err := r.RefreshOnDemand(context.Background(), "rp-1")
	if err != nil || !res.Applied || !res.ViaLadder {
		t.Fatalf("%+v %v", res, err)
	}
	if store.saveCalls == 0 || set.log.count("mirror") != 0 {
		t.Fatalf("saves %d calls %v", store.saveCalls, set.log.all())
	}
}

// Without a carriers member the answer is today's: no_endpoints, nothing
// dialled. The scheduled poll never runs the ladder either.
func TestLadder_PackWithNoMirror_OlderFile(t *testing.T) {
	r, store, set, _, _ := noMirrorFixture(t)
	delete(store.secrets, bundle.UpdateCarriersStoreKey("r-1"))
	dialled := false
	r.DirectDialer = DialerFn(func() (bootstrap.Dialer, bool, error) {
		dialled = true
		return NoDialer, false, nil
	})
	res, err := r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessNoEndpoints || dialled || len(set.log.all()) != 0 {
		t.Fatalf("%+v %v dialled=%v %v", res, err, dialled, set.log.all())
	}

	r2, _, set2, _, _ := noMirrorFixture(t)
	if res, _ := r2.Refresh(context.Background(), "rp-1"); res.Outcome != OutcomeFreshnessNoEndpoints || len(set2.log.all()) != 0 {
		t.Fatalf("scheduled: %+v %v", res, set2.log.all())
	}
	// Nothing found by the ladder: still no_endpoints.
	r3, _, set3, _, _ := noMirrorFixture(t)
	if res, _ := r3.RefreshFailureTriggered(context.Background(), "rp-1", "net-a"); res.Outcome != OutcomeFreshnessNoEndpoints || set3.github.Calls() != 1 {
		t.Fatalf("ladder found nothing: %+v %v", res, set3.log.all())
	}
}

// One rung-4 reader per walk; over days and salts every reader is chosen.
func TestLadder_OneRung4ReaderPerWalk(t *testing.T) {
	r, _, _, now, _ := ladderFixture(t)
	l := &callLog{}
	g := bundle.NoteCarrierGitTag
	readers := []Carrier{
		fakeC(l, "goproxy-cn", g, ClassGoProxy, RungReaders, CarrierCost{TCP: 2}, NoteBoth),
		fakeC(l, "goproxy-direct", g, ClassGoProxy, RungReaders, CarrierCost{TCP: 2}, NoteBoth),
		fakeC(l, "goproxy-io", g, ClassGoProxy, RungReaders, CarrierCost{TCP: 2}, NoteBoth),
		fakeC(l, "jsdelivr", g, ClassJSDelivr, RungReaders, CarrierCost{TCP: 4}, NoteBoth),
	}
	r.LadderCarriers = readers
	seen := map[string]bool{}
	for day := 0; day < 40; day++ {
		before := len(l.all())
		if _, err := r.refresh(context.Background(), "rp-1", kindFailure, "net-a"); err == nil {
			t.Fatal("premise: nothing should verify")
		}
		got := l.all()[before:]
		n := 0
		for _, x := range got {
			if x != "mirror" {
				n++
				seen[x] = true
			}
		}
		if n != 1 {
			t.Fatalf("day %d: %d rung-4 readers fetched: %v", day, n, got)
		}
		*now = now.Add(24 * time.Hour)
	}
	if len(seen) != 4 {
		t.Fatalf("readers chosen over 40 days: %v", seen)
	}
	// The pure choice: every index over salts and days.
	var u [bundle.UpdateSecretLen]byte
	idx := map[int]bool{}
	for i := 0; i < 64; i++ {
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		idx[readerIndex(u, salt, uint64(20000+i), 4)] = true
	}
	if len(idx) != 4 {
		t.Fatalf("indices %v", idx)
	}
	// The device salt is kept, not remade.
	s1 := r.deviceSalt()
	if s2 := r.deviceSalt(); string(s1) != string(s2) || len(s1) != 16 {
		t.Fatal("device salt not kept")
	}
}

// The Apps Script door made two connections to Google: goproxy-front is
// not called; with one, it is.
func TestLadder_TwoGoogleConnectionsPerWalk(t *testing.T) {
	for _, conns := range []int{2, 1} {
		r, store, set, _, _ := ladderFixture(t)
		for i := range store.routes {
			store.routes[i].FreshnessURL = testGoogleMirror
		}
		r.MaxGoogleJitter = time.Millisecond
		set.front.InfoV.Cost = CarrierCost{TCP: 1}
		c := conns
		r.FrontFetch = func(ctx context.Context, url string, d bootstrap.Dialer, timeout time.Duration) ([]byte, error) {
			set.log.add("appsscript")
			NoteGoogleConnections(ctx, c)
			return nil, errors.New("connection reset")
		}
		_, _ = r.RefreshFailureTriggered(context.Background(), "rp-1", "net-a")
		if set.log.count("appsscript") != 1 {
			t.Fatalf("premise: %v", set.log.all())
		}
		want := 0
		if conns == 1 {
			want = 1
		}
		if set.front.Calls() != want {
			t.Fatalf("conns %d: goproxy-front called %d times (%v)", conns, set.front.Calls(), set.log.all())
		}
	}
}

// The DNS reader with the walk's default six questions reaches a reveal
// written at e−1 by the second walk: the first finds e absent and leaves
// the hint, the second asks e−1 first.
func TestLadder_DNSPreviousEpochByTheSecondWalk(t *testing.T) {
	r, store, _, now, kit := ladderFixture(t)
	sink := &recordingSink{accept: true}
	r.StandbyKeys = sink
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	e := bundle.NoteEpochAt(bundle.NoteCarrierDNS, *now)
	if e == 0 {
		t.Skip("epoch 0")
	}
	sealed, err := bundle.SealMicroNote(kit.secret.Secret, bundle.NoteCarrierDNS, e-1, kit.key)
	if err != nil {
		t.Fatal(err)
	}
	names, _ := bundle.DNSNoteNames(kit.secret.Secret, e-1, ladderTestZone)
	ips, _ := bundle.DNSNoteAddresses(sealed, rand.Reader)
	for i, n := range names {
		f.records[n] = ips[i]
	}
	r.LadderCarriers = []Carrier{testDNSCarrier(f, nil)}

	res, _ := r.refresh(context.Background(), "rp-1", kindFailure, "net-a")
	if res.StandbyKeyAccepted || f.count() != 1 {
		t.Fatalf("first walk: %+v asked %d", res, f.count())
	}
	if string(store.secrets[ladderDNSHintKey("rp-1")]) == "" {
		t.Fatal("no hint left")
	}
	*now = now.Add(time.Minute)
	res, err = r.refresh(context.Background(), "rp-1", kindFailure, "net-a")
	if err != nil || res.Outcome != OutcomeFreshnessStandbyKey || f.count() != 7 {
		t.Fatalf("second walk: %+v %v asked %d", res, err, f.count())
	}
	if len(store.secrets[ladderDNSHintKey("rp-1")]) != 0 {
		t.Fatal("hint not cleared")
	}
}

// A route coming up between two questions stops the DNS reader.
func TestDNSCarrier_StopsWhenARouteComesUp(t *testing.T) {
	t.Cleanup(func() { SetTunnelRequired(false) })
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	fx.publish(t, f.records, epochNow(), true)
	c := testDNSCarrier(f, nil)
	waits := 0
	c.pace = func(ctx context.Context) error {
		waits++
		if waits == 2 {
			SetTunnelRequired(true)
		}
		return ctx.Err()
	}
	notes, err := c.Fetch(context.Background(), fx.env)
	if !errors.Is(err, ErrTunnelRequired) || len(notes) != 0 {
		t.Fatalf("notes %v err %v", notes, err)
	}
	if f.count() > 2 {
		t.Fatalf("asked %d questions after the route came up", f.count())
	}
	_ = strings.TrimSpace
}
