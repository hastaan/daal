package hetzner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// --- PA-1: release ONE address left reserved for a live relay ---

func TestReleaseOneAddress_EveryCode(t *testing.T) {
	cases := []struct {
		name     string
		seed     func(f *fakeClient)
		recFIP   string
		ask      string
		want     string
		released bool
		gone     string // id that must be gone afterwards
		kept     string // id that must still be there
	}{
		{name: "by id, unattached and Daal's", ask: "fip-left",
			seed: func(f *fakeClient) { f.seedFIP("fip-left", "198.51.100.20", "fsn1", "", ownedLabels(relayA())) },
			want: provider.AddrReleased, released: true, gone: "fip-left"},
		{name: "by IP, unattached and Daal's", ask: "198.51.100.20",
			seed: func(f *fakeClient) { f.seedFIP("fip-left", "198.51.100.20", "fsn1", "", ownedLabels(relayA())) },
			want: provider.AddrReleased, released: true, gone: "fip-left"},
		{name: "already gone", ask: "fip-nothere", seed: func(*fakeClient) {},
			want: provider.AddrReleased, released: true},
		{name: "the relay's recorded address", ask: "fip-live", recFIP: "fip-live",
			seed: func(f *fakeClient) { f.seedFIP("fip-live", "198.51.100.21", "fsn1", "", ownedLabels(relayA())) },
			want: provider.AddrInUse, kept: "fip-live"},
		{name: "the relay's public IP", ask: "5.75.0.1",
			seed: func(f *fakeClient) { f.seedFIP("fip-pub", "5.75.0.1", "fsn1", "", ownedLabels(relayA())) },
			want: provider.AddrInUse, kept: "fip-pub"},
		{name: "not Daal's", ask: "fip-mine",
			seed: func(f *fakeClient) { f.seedFIP("fip-mine", "198.51.100.22", "fsn1", "", nil) },
			want: provider.AddrNotDaal, kept: "fip-mine"},
		{name: "another relay's", ask: "fip-b",
			seed: func(f *fakeClient) { f.seedFIP("fip-b", "198.51.100.23", "hel1", "", ownedLabels(relayB())) },
			want: provider.AddrNotDaal, kept: "fip-b"},
		{name: "attached to the live relay", ask: "fip-att",
			seed: func(f *fakeClient) { f.seedFIP("fip-att", "198.51.100.24", "fsn1", "10", ownedLabels(relayA())) },
			want: provider.AddrStillAttached, kept: "fip-att"},
		{name: "attached elsewhere", ask: "fip-att2",
			seed: func(f *fakeClient) { f.seedFIP("fip-att2", "198.51.100.25", "fsn1", "99", ownedLabels(relayA())) },
			want: provider.AddrStillAttached, kept: "fip-att2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.seedServer("10", relayA(), "fsn1", ownedLabels(relayA()))
			c.seed(f)
			rec := recordFor(pubKeyA, "fsn1", "10")
			rec.FloatingIPID = c.recFIP
			o := New(f).ReleaseOneAddress(context.Background(), rec, c.ask)
			if o.Code != c.want || o.Released != c.released {
				t.Fatalf("outcome %+v, want code %s released %v", o, c.want, c.released)
			}
			if c.gone != "" {
				if _, ok := f.fips[c.gone]; ok {
					t.Errorf("%s is still reserved", c.gone)
				}
			}
			if c.kept != "" {
				if _, ok := f.fips[c.kept]; !ok {
					t.Errorf("%s was deleted but must be kept (%s)", c.kept, c.want)
				}
			}
			if _, ok := f.servers["10"]; !ok {
				t.Error("the live relay's server was touched")
			}
		})
	}
}

func TestReleaseOneAddress_FailuresAreReleaseFailed(t *testing.T) {
	f := newFake()
	f.failFloatingIPList = errors.New("503")
	if o := New(f).ReleaseOneAddress(context.Background(), recordFor(pubKeyA, "fsn1", "10"), "fip-x"); o.Code != provider.AddrReleaseFailed || o.Released {
		t.Fatalf("unreadable list: %+v", o)
	}
	f = newFake()
	f.seedFIP("fip-left", "198.51.100.20", "fsn1", "", ownedLabels(relayA()))
	f.failFloatingIPDelete = errors.New("delete refused by the cloud")
	o := New(f).ReleaseOneAddress(context.Background(), recordFor(pubKeyA, "fsn1", "10"), "fip-left")
	if o.Code != provider.AddrReleaseFailed || o.Released || o.Error == "" || o.IP != "198.51.100.20" {
		t.Fatalf("failed delete: %+v", o)
	}
}

// --- PA-3: teardown by id double-checks the derived name ---

func TestDecommission_IDGoneButALabelledServerKeepsTheName(t *testing.T) {
	f := newFake()
	// The recorded id "10" was removed in the console; a new server
	// carrying the derived name and both labels was made outside the
	// record as "11".
	f.seedServer("11", relayA(), "fsn1", ownedLabels(relayA()))
	rep, err := New(f).Decommission(context.Background(), recordFor(pubKeyA, "fsn1", "10"))
	if !errors.Is(err, provider.ErrNamedServerRemains) {
		t.Fatalf("err = %v, want ErrNamedServerRemains", err)
	}
	if rep.ServerDeleted {
		t.Error("server_deleted:true while a server with this relay's name still bills")
	}
	if rep.NamedServer == nil || rep.NamedServer.ID != "11" || rep.NamedServer.Name != relayA() {
		t.Errorf("named_server = %+v", rep.NamedServer)
	}
	if _, ok := f.servers["11"]; !ok {
		t.Error("the named server was deleted")
	}
	found := false
	for _, p := range rep.Preserved {
		if p == "server:11" {
			found = true
		}
	}
	if !found {
		t.Errorf("preserved = %v, want server:11", rep.Preserved)
	}
	for _, w := range rep.Warnings {
		if containsAny(w, "daal-deploy ", "`", "curl") {
			t.Errorf("warning carries a command line: %q", w)
		}
	}
}

func TestDecommission_IDGoneAndTheNameLookupFails(t *testing.T) {
	f := newFake()
	f.failServerByName = errors.New("503")
	rep, err := New(f).Decommission(context.Background(), recordFor(pubKeyA, "fsn1", "10"))
	if err == nil || errors.Is(err, provider.ErrNamedServerRemains) {
		t.Fatalf("err = %v, want a plain lookup error", err)
	}
	if rep.ServerDeleted || rep.NamedServer != nil {
		t.Errorf("report = %+v", rep)
	}
}

func TestDecommission_IDGoneAndTheNamedServerIsNotDaals(t *testing.T) {
	f := newFake()
	f.seedServer("11", relayA(), "fsn1", map[string]string{"owner": "someone"})
	rep, err := New(f).Decommission(context.Background(), recordFor(pubKeyA, "fsn1", "10"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !rep.ServerDeleted || rep.NamedServer != nil {
		t.Errorf("report = %+v, want today's server_deleted:true", rep)
	}
	if _, ok := f.servers["11"]; !ok {
		t.Error("a server without Daal's labels was deleted")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
