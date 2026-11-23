package refresh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"daal/bundle-go/bundle"
)

// fakeResolver is a local UDP DNS server playing the network's resolver.
type fakeResolver struct {
	mu      sync.Mutex
	records map[string]net.IP // lower fqdn without dot → A
	asked   []string
	types   []uint16
	edns    int
	noRD    int
	// behaviour
	aOnly    bool                // anything but A gets no reply
	drop     map[int]bool        // question index (0-based) → no reply
	refuseAt int                 // from this question on: REFUSED (0 = never)
	answer   func(string) net.IP // overrides records when set
	silent   bool                // never replies
	addr     string
}

func startResolver(t *testing.T, f *fakeResolver) *fakeResolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(f.serve)}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	f.addr = pc.LocalAddr().String()
	return f
}

func (f *fakeResolver) serve(w dns.ResponseWriter, r *dns.Msg) {
	f.mu.Lock()
	idx := len(f.asked)
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	f.asked = append(f.asked, name)
	f.types = append(f.types, q.Qtype)
	if r.IsEdns0() != nil {
		f.edns++
	}
	if !r.RecursionDesired {
		f.noRD++
	}
	silent := f.silent || f.drop[idx] || (f.aOnly && q.Qtype != dns.TypeA)
	refuse := f.refuseAt > 0 && idx >= f.refuseAt
	ip, ok := f.records[name]
	if f.answer != nil {
		ip, ok = f.answer(name), true
	}
	f.mu.Unlock()
	if silent {
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	switch {
	case refuse:
		m.Rcode = dns.RcodeRefused
	case !ok || q.Qtype != dns.TypeA:
		m.Rcode = dns.RcodeNameError
	default:
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: ip})
	}
	w.WriteMsg(m)
}

func (f *fakeResolver) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

var dnsNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const dnsZone = "example.org"

type dnsFixture struct {
	u   *bundle.UpdateSecret
	k   bundle.StandbyKeyBytes
	st  bundle.Standby
	env *CarrierEnv
}

func newDNSFixture(t *testing.T, aud string) *dnsFixture {
	t.Helper()
	u := &bundle.UpdateSecret{Audience: aud}
	for i := range u.Secret {
		u.Secret[i] = byte(7 + i)
	}
	k, err := bundle.NewStandbyKey("5.6.7.8", bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	st := bundle.SealedStandby(k)
	return &dnsFixture{u: u, k: k, st: st, env: &CarrierEnv{
		RelayPackID: "rp1",
		Secrets:     []*bundle.UpdateSecret{u},
		Carriers:    &bundle.UpdateCarriers{DNS: &bundle.DNSCarrier{Zone: dnsZone}},
		Standby:     &st,
		Now:         dnsNow,
		Dialer:      NoDialer,
	}}
}

// publish writes the six records the publisher's app would write.
func (fx *dnsFixture) publish(t *testing.T, recs map[string]net.IP, e uint64, reveal bool) {
	t.Helper()
	var sealed [16]byte
	var err error
	if reveal {
		sealed, err = bundle.SealMicroNote(fx.u.Secret, bundle.NoteCarrierDNS, e, fx.k)
	} else {
		sealed, err = bundle.MicroFiller(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	names, _ := bundle.DNSNoteNames(fx.u.Secret, e, dnsZone)
	ips, _ := bundle.DNSNoteAddresses(sealed, rand.Reader)
	for i, n := range names {
		recs[n] = ips[i]
	}
}

func testDNSCarrier(f *fakeResolver, waits *int) *dnsCarrier {
	return &dnsCarrier{
		pace: func(ctx context.Context) error {
			if waits != nil {
				*waits++
			}
			return ctx.Err()
		},
		timeout:      300 * time.Millisecond,
		linkResolver: func() (netip.AddrPort, bool) { return netip.MustParseAddrPort(f.addr), true },
	}
}

func epochNow() uint64 { return bundle.NoteEpochAt(bundle.NoteCarrierDNS, dnsNow) }

func TestDNSCarrier_GoodNote_AOnlyResolver(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}, aOnly: true})
	fx.publish(t, f.records, epochNow(), true)
	waits := 0
	c := testDNSCarrier(f, &waits)
	if !c.Usable(fx.env) {
		t.Fatal("not usable")
	}
	notes, err := c.Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 1 {
		t.Fatalf("notes %v err %v", notes, err)
	}
	n := notes[0]
	if n.Kind != NoteMicro || n.StandbyKey != fx.k || n.Carrier != CarrierNameDNS || n.Epoch != epochNow() || n.Audience != bundle.AudiencePeople {
		t.Fatalf("note %+v", n)
	}
	if !fx.st.Matches(n.StandbyKey) {
		t.Fatal("candidate does not match the signed commit")
	}
	if f.count() != 6 || waits != 5 {
		t.Fatalf("asked %d waited %d, want 6 and 5", f.count(), waits)
	}
	for i, ty := range f.types {
		if ty != dns.TypeA {
			t.Fatalf("question %d is type %d", i, ty)
		}
	}
	if f.edns != 0 || f.noRD != 0 {
		t.Fatalf("edns %d, no-RD %d", f.edns, f.noRD)
	}
	names, _ := bundle.DNSNoteNames(fx.u.Secret, epochNow(), dnsZone)
	for i, n := range names {
		if f.asked[i] != n {
			t.Fatalf("question %d out of order", i)
		}
	}
}

func TestDNSCarrier_FillerIsNothingNew(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	fx.publish(t, f.records, epochNow(), false)
	notes, err := testDNSCarrier(f, nil).Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 0 || f.count() != 6 {
		t.Fatalf("notes %v err %v asked %d", notes, err, f.count())
	}
}

func TestDNSCarrier_DroppedAnswerIsNothingNew(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}, drop: map[int]bool{3: true}})
	fx.publish(t, f.records, epochNow(), true)
	notes, err := testDNSCarrier(f, nil).Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 0 {
		t.Fatalf("notes %v err %v", notes, err)
	}
	if f.count() != 4 {
		t.Fatalf("asked %d, want 4 (the try stops at the dropped one)", f.count())
	}
}

func TestDNSCarrier_SinkholeIsNothingNew(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{answer: func(string) net.IP { return net.IPv4(10, 10, 34, 36) }})
	notes, err := testDNSCarrier(f, nil).Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 0 || f.count() != 1 {
		t.Fatalf("notes %v err %v asked %d", notes, err, f.count())
	}
	// A sinkhole on one answer only, the rest a real note.
	fx2 := newDNSFixture(t, bundle.AudiencePeople)
	recs := map[string]net.IP{}
	fx2.publish(t, recs, epochNow(), true)
	names, _ := bundle.DNSNoteNames(fx2.u.Secret, epochNow(), dnsZone)
	recs[names[5]] = net.IPv4(10, 10, 34, 35)
	f2 := startResolver(t, &fakeResolver{records: recs})
	notes, err = testDNSCarrier(f2, nil).Fetch(context.Background(), fx2.env)
	if err != nil || len(notes) != 0 {
		t.Fatalf("partial sinkhole: notes %v err %v", notes, err)
	}
}

func TestDNSCarrier_RateLimitedIsNothingNew(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}, refuseAt: 2})
	fx.publish(t, f.records, epochNow(), true)
	notes, err := testDNSCarrier(f, nil).Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 0 || f.count() != 3 {
		t.Fatalf("notes %v err %v asked %d", notes, err, f.count())
	}
}

func TestDNSCarrier_SilentResolverIsAStrike(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{silent: true})
	notes, err := testDNSCarrier(f, nil).Fetch(context.Background(), fx.env)
	if err == nil || errors.Is(err, ErrCarrierUnconfigured) || len(notes) != 0 {
		t.Fatalf("notes %v err %v", notes, err)
	}
	if f.count() != 1 {
		t.Fatalf("asked %d", f.count())
	}
}

func TestDNSCarrier_PreviousEpochNeedsBudget(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	fx.publish(t, f.records, epochNow()-1, true) // the publisher missed this week
	c := testDNSCarrier(f, nil)

	notes, err := c.Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 0 || f.count() != 1 {
		t.Fatalf("default budget: notes %v err %v asked %d", notes, err, f.count())
	}
	notes, err = c.Fetch(WithDNSQuestionBudget(context.Background(), 12), fx.env)
	if err != nil || len(notes) != 1 || notes[0].Epoch != epochNow()-1 || notes[0].StandbyKey != fx.k {
		t.Fatalf("budget 12: notes %v err %v", notes, err)
	}
	if f.count() != 1+1+6 {
		t.Fatalf("asked %d in all", f.count())
	}
	if _, err := c.Fetch(WithDNSQuestionBudget(context.Background(), 5), fx.env); err != nil || f.count() != 8 {
		t.Fatalf("budget 5 asked something: %d %v", f.count(), err)
	}
}

func TestDNSCarrier_NotUsable(t *testing.T) {
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	c := testDNSCarrier(f, nil)
	cases := map[string]func(fx *dnsFixture){
		"everyone":  func(fx *dnsFixture) { fx.u.Audience = bundle.AudienceEveryone },
		"no member": func(fx *dnsFixture) { fx.env.Carriers = nil },
		"no dns": func(fx *dnsFixture) {
			fx.env.Carriers = &bundle.UpdateCarriers{GitTag: &bundle.GitTagCarrier{Owner: "o", Repo: "r"}}
		},
		"no standby": func(fx *dnsFixture) { fx.env.Standby = nil },
		"open standby": func(fx *dnsFixture) {
			s := bundle.OpenStandby("5.6.7.8")
			fx.env.Standby = &s
		},
		"public resolver": func(fx *dnsFixture) { fx.env.Resolver = "8.8.8.8:53" },
		"bad resolver":    func(fx *dnsFixture) { fx.env.Resolver = "not-an-address" },
	}
	for name, mut := range cases {
		fx := newDNSFixture(t, bundle.AudiencePeople)
		mut(fx)
		if c.Usable(fx.env) {
			t.Errorf("%s: usable", name)
		}
		if _, err := c.Fetch(context.Background(), fx.env); !errors.Is(err, ErrCarrierUnconfigured) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	// No resolver found at all.
	none := &dnsCarrier{linkResolver: func() (netip.AddrPort, bool) { return netip.AddrPort{}, false }}
	fx := newDNSFixture(t, bundle.AudiencePeople)
	if none.Usable(fx.env) {
		t.Error("usable without a resolver")
	}
	if f.count() != 0 {
		t.Fatalf("an unusable carrier asked %d questions", f.count())
	}
}

func TestDNSCarrier_EnvResolverAndEveryoneSkipped(t *testing.T) {
	// The env names the resolver; a held Everyone secret is skipped and
	// the People one behind it is used.
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	fx.publish(t, f.records, epochNow(), true)
	ev := &bundle.UpdateSecret{Audience: bundle.AudienceEveryone}
	fx.env.Secrets = []*bundle.UpdateSecret{ev, fx.u}
	fx.env.Resolver = f.addr
	c := &dnsCarrier{pace: func(context.Context) error { return nil }, timeout: 300 * time.Millisecond,
		linkResolver: func() (netip.AddrPort, bool) { t.Fatal("link resolver asked"); return netip.AddrPort{}, false }}
	notes, err := c.Fetch(context.Background(), fx.env)
	if err != nil || len(notes) != 1 || f.count() != 6 {
		t.Fatalf("notes %v err %v asked %d", notes, err, f.count())
	}
}

func TestDNSCarrier_Registered(t *testing.T) {
	var found bool
	for _, c := range RegisteredCarriers() {
		if c.Info().Name == CarrierNameDNS {
			found = true
			i := c.Info()
			if i.Class != ClassDNS || i.Rung != RungDNS || i.Cost.DNS != 6 || i.Cost.TCP != 0 || i.Kinds != NoteMicro {
				t.Fatalf("info %+v", i)
			}
		}
	}
	if !found {
		t.Fatal("dns carrier not registered")
	}
}

func TestDNSCarrier_CancelledMidway(t *testing.T) {
	fx := newDNSFixture(t, bundle.AudiencePeople)
	f := startResolver(t, &fakeResolver{records: map[string]net.IP{}})
	fx.publish(t, f.records, epochNow(), true)
	ctx, cancel := context.WithCancel(context.Background())
	c := testDNSCarrier(f, nil)
	n := 0
	c.pace = func(ctx context.Context) error {
		n++
		if n == 2 {
			cancel()
		}
		return ctx.Err()
	}
	notes, err := c.Fetch(ctx, fx.env)
	if err != nil || len(notes) != 0 || f.count() != 2 {
		t.Fatalf("notes %v err %v asked %d", notes, err, f.count())
	}
}
