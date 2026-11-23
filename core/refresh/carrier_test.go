package refresh

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fullnote"
)

func testNoteEnv(t *testing.T) (*CarrierEnv, bundle.StandbyKeyBytes, *bundle.UpdateSecret, *bundle.UpdateSecret) {
	t.Helper()
	k, err := bundle.NewStandbyKey("203.0.113.20", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sb := bundle.SealedStandby(k)
	people := &bundle.UpdateSecret{Audience: bundle.AudiencePeople}
	everyone := &bundle.UpdateSecret{Audience: bundle.AudienceEveryone}
	_, _ = rand.Read(people.Secret[:])
	_, _ = rand.Read(everyone.Secret[:])
	return &CarrierEnv{
		RelayPackID: "rp-1",
		Secrets:     []*bundle.UpdateSecret{people, everyone},
		Standby:     &sb,
		Now:         time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
		Dialer:      NoDialer,
	}, k, people, everyone
}

func TestCarrierEnv_TriesAndAudienceRule(t *testing.T) {
	env, _, people, everyone := testNoteEnv(t)
	g := env.Tries(bundle.NoteCarrierGitTag, NoteBoth)
	if len(g) != 4 || g[0].Secret != people || g[2].Secret != everyone || g[0].Epoch != g[1].Epoch+1 {
		t.Fatalf("gittag tries: %+v", g)
	}
	want, _ := bundle.NoteName(people.Secret, bundle.NoteCarrierGitTag, g[0].Epoch)
	if g[0].Name != want {
		t.Fatal("name")
	}
	d := env.Tries(bundle.NoteCarrierDNS, NoteMicro)
	if len(d) != 2 || d[0].Secret != people || d[1].Secret != people {
		t.Fatalf("dns tries must skip the Everyone secret: %+v", d)
	}
}

func TestCarrierEnv_OpenMicroAndFull(t *testing.T) {
	env, k, people, _ := testNoteEnv(t)
	e := bundle.NoteEpochAt(bundle.NoteCarrierGitTag, env.Now) - 1
	sealed, _ := bundle.SealMicroNote(people.Secret, bundle.NoteCarrierGitTag, e, k)
	n, ok := env.OpenMicro("github", bundle.NoteCarrierGitTag, sealed)
	if !ok || n.Kind != NoteMicro || n.StandbyKey != k || n.Epoch != e || n.Audience != bundle.AudiencePeople || n.Carrier != "github" {
		t.Fatalf("micro: %+v %v", n, ok)
	}
	if !env.Standby.Matches(n.StandbyKey) {
		t.Fatal("candidate does not match")
	}
	fill, _ := bundle.MicroFiller(rand.Reader)
	if _, ok := env.OpenMicro("github", bundle.NoteCarrierGitTag, fill); ok {
		t.Fatal("filler opened")
	}
	noSB := *env
	noSB.Standby = nil
	if _, ok := noSB.OpenMicro("github", bundle.NoteCarrierGitTag, sealed); ok {
		t.Fatal("opened without a standby")
	}

	container := []byte(`{"kind":"daal-refresh-v2"}`)
	full, _ := fullnote.Seal(people.Secret, bundle.NoteCarrierGitTag, e, container, rand.Reader)
	fn, ok := env.OpenFull("github", bundle.NoteCarrierGitTag, full)
	slot, _ := bundle.NoteName(people.Secret, bundle.NoteCarrierGitTag, e)
	if !ok || fn.Kind != NoteFull || string(fn.Container) != string(container) || fn.Slot != slot {
		t.Fatalf("full: %+v %v", fn, ok)
	}
	tries := env.Tries(bundle.NoteCarrierGitTag, NoteFull)
	if fa, ok := env.OpenFullAt("github", bundle.NoteCarrierGitTag, tries[1], full); !ok || fa.Slot != slot {
		t.Fatalf("full at: %+v %v", fa, ok)
	}
	if _, ok := env.OpenFullAt("github", bundle.NoteCarrierGitTag, tries[0], full); ok {
		t.Fatal("opened at the wrong epoch")
	}
}

func TestRegistry_AndFake(t *testing.T) {
	carrierMu.Lock()
	saved := carrierReg
	carrierReg = map[string]Carrier{}
	carrierMu.Unlock()
	defer func() { carrierMu.Lock(); carrierReg = saved; carrierMu.Unlock() }()

	dns := &FakeCarrier{InfoV: CarrierInfo{Name: "dns", Label: bundle.NoteCarrierDNS, Class: ClassDNS, Rung: RungDNS,
		Cost: CarrierCost{DNS: 6}, Kinds: NoteMicro}}
	gh := &FakeCarrier{InfoV: CarrierInfo{Name: "github", Label: bundle.NoteCarrierGitTag, Class: ClassGitHub, Rung: RungGitTag,
		Cost: CarrierCost{TCP: 2}, Kinds: NoteBoth}, Err: errors.New("reset")}
	RegisterCarrier(dns)
	RegisterCarrier(gh)
	got := RegisteredCarriers()
	if len(got) != 2 || got[0] != Carrier(gh) || got[1] != Carrier(dns) {
		t.Fatalf("order: %v", got)
	}
	for name, c := range map[string]Carrier{
		"duplicate": dns,
		"no name":   &FakeCarrier{InfoV: CarrierInfo{Label: "dns", Class: "x", Kinds: NoteMicro, Cost: CarrierCost{DNS: 1}}},
		"bad label": &FakeCarrier{InfoV: CarrierInfo{Name: "x", Label: "Bad", Class: "x", Kinds: NoteMicro, Cost: CarrierCost{DNS: 1}}},
		"no kinds":  &FakeCarrier{InfoV: CarrierInfo{Name: "y", Label: "dns", Class: "x", Cost: CarrierCost{DNS: 1}}},
		"no cost":   &FakeCarrier{InfoV: CarrierInfo{Name: "z", Label: "dns", Class: "x", Kinds: NoteMicro}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: registered", name)
				}
			}()
			RegisterCarrier(c)
		}()
	}
	env, _, _, _ := testNoteEnv(t)
	if _, err := gh.Fetch(context.Background(), env); err == nil || gh.Calls() != 1 || gh.Envs()[0] != env {
		t.Fatal("fake error")
	}
	dns.Notes = []Note{{Kind: NoteMicro, Carrier: "dns"}}
	if n, err := dns.Fetch(context.Background(), env); err != nil || len(n) != 1 {
		t.Fatal("fake notes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dns.Fetch(ctx, env); err == nil {
		t.Fatal("fake ignores ctx")
	}
	if !dns.Usable(env) {
		t.Fatal("usable")
	}
	if _, err := NoDialer.DialContext(context.Background(), "tcp", "192.0.2.1:443"); err == nil {
		t.Fatal("NoDialer dialled")
	}
}
