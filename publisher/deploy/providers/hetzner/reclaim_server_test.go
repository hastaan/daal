package hetzner

import (
	"context"
	"errors"
	"testing"

	"daal/publisher/deploy/provider"
)

// seedUnclaimedRelay plants a labelled server for relayA with its
// firewall, a stale one-shot key and an unattached reserved address —
// what a setup finished on another phone (or a lost record) leaves.
func seedUnclaimedRelay(f *fakeClient) {
	f.seedServer("10", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedFirewall("10", nil)
	f.seedSSHKey(relayA()+"-ephemeral-0badc0de", ownedLabels(relayA()))
	f.seedFIP("fip-1", "198.51.100.9", "fsn1", "", ownedLabels(relayA()))
}

func serverRef(id string) []provider.ResourceRef {
	return []provider.ResourceRef{{Kind: provider.KindServer, ID: id}}
}

func TestReclaimServer_DeletesANamedUnclaimedDaalServerAndEverythingWithIt(t *testing.T) {
	f := newFake()
	seedUnclaimedRelay(f)
	rep, err := New(f).ReclaimOrphansWithOpts(context.Background(), nil, serverRef("10"),
		provider.ReclaimOpts{IncludeUnclaimedServers: true})
	if err != nil {
		t.Fatal(err)
	}
	if o := outcomeFor(t, rep, provider.KindServer, "10"); !o.Deleted || o.Code != provider.ReclaimDeleted {
		t.Fatalf("server outcome = %+v", o)
	}
	if len(f.servers) != 0 {
		t.Fatal("the server is still billing")
	}
	if len(f.ensuredFirewalls) != 0 {
		t.Error("its firewall was left behind")
	}
	if len(f.sshKeys) != 0 {
		t.Error("its one-shot key was left behind")
	}
	if _, ok := f.fips["fip-1"]; ok {
		t.Error("its reserved address is still billing")
	}
	if o := outcomeFor(t, rep, provider.KindFloatingIP, "fip-1"); o.Code != provider.ReclaimReleased {
		t.Errorf("address outcome = %+v", o)
	}
}

func TestReclaimServer_NeverWithoutTheFlagOrWithoutNamingIt(t *testing.T) {
	cases := []struct {
		name string
		only []provider.ResourceRef
		opts provider.ReclaimOpts
	}{
		{"named but no flag", serverRef("10"), provider.ReclaimOpts{}},
		{"flag but the server is not named", []provider.ResourceRef{{Kind: provider.KindFloatingIP, ID: "fip-1"}}, provider.ReclaimOpts{IncludeUnclaimedServers: true}},
		{"flag and no --only at all", nil, provider.ReclaimOpts{IncludeUnclaimedServers: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			seedUnclaimedRelay(f)
			if _, err := New(f).ReclaimOrphansWithOpts(context.Background(), nil, tc.only, tc.opts); err != nil {
				t.Fatal(err)
			}
			if _, alive := f.servers["10"]; !alive {
				t.Fatal("a server was deleted without being named with the flag")
			}
		})
	}
}

func TestReclaimServer_RefusesWhatItCannotProve(t *testing.T) {
	t.Run("a record claims the server id", func(t *testing.T) {
		f := newFake()
		seedUnclaimedRelay(f)
		rec := recordFor(pubKeyB, "hel1", "10") // another relay's record naming id 10
		rep, err := New(f).ReclaimOrphansWithOpts(context.Background(), []*provider.OperatorRecord{rec}, serverRef("10"),
			provider.ReclaimOpts{IncludeUnclaimedServers: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, alive := f.servers["10"]; !alive {
			t.Fatal("deleted a server a record claims")
		}
		if o := outcomeFor(t, rep, provider.KindServer, "10"); o.Deleted || o.Code == provider.ReclaimDeleted {
			t.Fatalf("outcome = %+v", o)
		}
	})
	t.Run("unlabelled server named like a relay", func(t *testing.T) {
		f := newFake()
		f.seedServer("10", relayA(), "fsn1", nil)
		rep, err := New(f).ReclaimOrphansWithOpts(context.Background(), nil, serverRef("10"),
			provider.ReclaimOpts{IncludeUnclaimedServers: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, alive := f.servers["10"]; !alive {
			t.Fatal("deleted an unlabelled server")
		}
		if o := outcomeFor(t, rep, provider.KindServer, "10"); o.Code != provider.ReclaimKeptUnproven {
			t.Fatalf("outcome = %+v, want kept_unproven", o)
		}
	})
	t.Run("labels name a different relay than the server's name", func(t *testing.T) {
		f := newFake()
		f.seedServer("10", relayA(), "fsn1", ownedLabels(relayB()))
		rep, _ := New(f).ReclaimOrphansWithOpts(context.Background(), nil, serverRef("10"),
			provider.ReclaimOpts{IncludeUnclaimedServers: true})
		if _, alive := f.servers["10"]; !alive {
			t.Fatal("deleted a server whose labels do not match its name")
		}
		if o := outcomeFor(t, rep, provider.KindServer, "10"); o.Code != provider.ReclaimKeptNotDaal {
			t.Fatalf("outcome = %+v, want kept_not_daal", o)
		}
	})
	t.Run("server list unreadable", func(t *testing.T) {
		f := newFake()
		seedUnclaimedRelay(f)
		f.failServerList = errors.New("503")
		rep, err := New(f).ReclaimOrphansWithOpts(context.Background(), nil, serverRef("10"),
			provider.ReclaimOpts{IncludeUnclaimedServers: true})
		if err == nil {
			t.Fatal("reclaim ran on an incomplete server list")
		}
		if _, alive := f.servers["10"]; !alive {
			t.Fatal("deleted a server while the list was unreadable")
		}
		if o := outcomeFor(t, rep, provider.KindServer, "10"); o.Code != provider.ReclaimKeptListUnreadable {
			t.Fatalf("outcome = %+v, want kept_list_unreadable", o)
		}
	})
}

// The two-servers case: a record claims the relay but names another
// server id. The second server is deletable; the record's own is not,
// and the relay's address the record names is kept.
func TestReclaimServer_SecondServerForARelayIsDeletableTheRecordedOneIsNot(t *testing.T) {
	f := newFake()
	f.seedServer("10", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedFIP("fip-1", "198.51.100.9", "fsn1", "", ownedLabels(relayA()))
	rec := recordFor(pubKeyA, "fsn1", "77")
	rec.FloatingIPID = "fip-1"
	rep, err := New(f).ReclaimOrphansWithOpts(context.Background(), []*provider.OperatorRecord{rec}, serverRef("10"),
		provider.ReclaimOpts{IncludeUnclaimedServers: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, alive := f.servers["10"]; alive {
		t.Fatalf("second server survived: %+v", rep.Outcomes)
	}
	if _, ok := f.fips["fip-1"]; !ok {
		t.Fatal("released an address a record still names")
	}
	if o := outcomeFor(t, rep, provider.KindFloatingIP, "fip-1"); o.Code != provider.ReclaimKeptClaimed {
		t.Fatalf("address outcome = %+v, want kept_claimed", o)
	}
}

func TestAudit_ReportsRecordIndexAndAddresses(t *testing.T) {
	f := newFake()
	f.seedServer("10", relayB(), "hel1", ownedLabels(relayB()))
	f.seedFIP("fip-1", "198.51.100.9", "hel1", "", ownedLabels(relayB()))
	recs := []*provider.OperatorRecord{recordFor(pubKeyA, "fsn1", ""), recordFor(pubKeyB, "hel1", "10")}
	a, err := New(f).AuditAccount(context.Background(), recs)
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for _, k := range a.Known {
		idx[k.Relay] = k.RecordIndex
	}
	if idx[relayA()] != 0 || idx[relayB()] != 1 {
		t.Fatalf("record_index = %v, want relayA:0 relayB:1", idx)
	}
	if got := find(t, a, provider.KindServer, "10").Address; got != "5.75.0.10" {
		t.Errorf("server address = %q", got)
	}
	if got := find(t, a, provider.KindFloatingIP, "fip-1").Address; got != "198.51.100.9" {
		t.Errorf("address = %q", got)
	}
}
