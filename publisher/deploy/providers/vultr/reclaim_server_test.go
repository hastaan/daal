package vultr

import (
	"context"
	"testing"

	"daal/publisher/deploy/provider"
)

func TestReclaimServer_VultrDeletesANamedUnclaimedInstanceAndItsLeftovers(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	f.rips["rip-x"] = &wireReservedIP{ID: "rip-x", Region: testRegion, IPType: "v4", Subnet: "95.179.20.9",
		SubnetSize: 32, Label: ownershipMark(relayLabel(), "fip-1")}
	only := []provider.ResourceRef{{Kind: provider.KindServer, ID: rec.ServerID}}

	// Without the flag: kept.
	rep, err := p.ReclaimOrphansWithOpts(context.Background(), nil, only, provider.ReclaimOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.instances) != 1 {
		t.Fatal("deleted an instance without --include-unclaimed-servers")
	}
	if rep.Outcomes[0].Code != provider.ReclaimKeptUnsupported {
		t.Fatalf("outcome = %+v, want kept_unsupported", rep.Outcomes[0])
	}

	rep, err = p.ReclaimOrphansWithOpts(context.Background(), nil, only, provider.ReclaimOpts{IncludeUnclaimedServers: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.instances) != 0 {
		t.Fatalf("instance survived: %+v", rep.Outcomes)
	}
	if _, ok := f.rips["rip-x"]; ok {
		t.Fatal("its reserved IP is still billing")
	}
	if len(f.groups) != 0 {
		t.Errorf("its firewall group was left behind: %+v", rep.Outcomes)
	}
}

func TestReclaimServer_VultrRefusesAnInstanceARecordClaims(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	other := *rec
	other.PublisherPubKey = make([]byte, 32) // a different relay's record naming this id
	only := []provider.ResourceRef{{Kind: provider.KindServer, ID: rec.ServerID}}
	if _, err := p.ReclaimOrphansWithOpts(context.Background(), []*provider.OperatorRecord{&other}, only,
		provider.ReclaimOpts{IncludeUnclaimedServers: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.instances) != 1 {
		t.Fatal("deleted an instance a record names")
	}
}
