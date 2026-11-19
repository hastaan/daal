package vultr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// --- PA-1: release ONE address left reserved for a live relay ---

func TestReleaseOneAddress_VultrEveryCode(t *testing.T) {
	mark := func(n string) string { return ownershipMark(relayLabel(), n) }
	cases := []struct {
		name     string
		rip      *wireReservedIP
		recFIP   string
		recIP    string
		ask      string
		want     string
		released bool
		gone     bool
	}{
		{name: "by id", ask: "rip-left", want: provider.AddrReleased, released: true, gone: true,
			rip: &wireReservedIP{ID: "rip-left", Region: testRegion, IPType: "v4", Subnet: "95.179.20.30", SubnetSize: 32, Label: mark("a")}},
		{name: "by IP", ask: "95.179.20.30", want: provider.AddrReleased, released: true, gone: true,
			rip: &wireReservedIP{ID: "rip-left", Region: testRegion, IPType: "v4", Subnet: "95.179.20.30", SubnetSize: 32, Label: mark("a")}},
		{name: "already gone", ask: "rip-nothere", want: provider.AddrReleased, released: true},
		{name: "recorded address", ask: "rip-live", recFIP: "rip-live", want: provider.AddrInUse,
			rip: &wireReservedIP{ID: "rip-live", Region: testRegion, IPType: "v4", Subnet: "95.179.20.31", SubnetSize: 32, Label: mark("b")}},
		{name: "relay's public IP", ask: "95.179.20.32", recIP: "95.179.20.32", want: provider.AddrInUse,
			rip: &wireReservedIP{ID: "rip-pub", Region: testRegion, IPType: "v4", Subnet: "95.179.20.32", SubnetSize: 32, Label: mark("c")}},
		{name: "not Daal's", ask: "rip-mine", want: provider.AddrNotDaal,
			rip: &wireReservedIP{ID: "rip-mine", Region: testRegion, IPType: "v4", Subnet: "95.179.20.33", SubnetSize: 32, Label: "my own address"}},
		{name: "attached", ask: "rip-att", want: provider.AddrStillAttached,
			rip: &wireReservedIP{ID: "rip-att", Region: testRegion, IPType: "v4", Subnet: "95.179.20.34", SubnetSize: 32, Label: mark("d"), InstanceID: "somewhere"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeVultr(t)
			p, rec := mustProvision(t, f, mkOpts())
			if c.rip != nil {
				f.rips[c.rip.ID] = c.rip
			}
			rec.FloatingIPID = c.recFIP
			if c.recIP != "" {
				rec.PublicIP = net.ParseIP(c.recIP)
			}
			o := p.ReleaseOneAddress(context.Background(), rec, c.ask)
			if o.Code != c.want || o.Released != c.released {
				t.Fatalf("outcome %+v, want %s released %v", o, c.want, c.released)
			}
			if c.rip != nil {
				_, still := f.rips[c.rip.ID]
				if c.gone && still {
					t.Error("the address is still reserved")
				}
				if !c.gone && !still {
					t.Errorf("the address was deleted but must be kept (%s)", c.want)
				}
			}
			if _, ok := f.instances[rec.ServerID]; !ok {
				t.Error("the live relay's instance was touched")
			}
		})
	}
}

func TestReleaseOneAddress_VultrFailures(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	f.rips["rip-left"] = &wireReservedIP{ID: "rip-left", Region: testRegion, IPType: "v4", Subnet: "95.179.20.30",
		SubnetSize: 32, Label: ownershipMark(relayLabel(), "a")}
	f.failOn = func(method, path string) (int, bool) {
		return http.StatusInternalServerError, method == http.MethodDelete && strings.HasPrefix(path, "/reserved-ips/")
	}
	if o := p.ReleaseOneAddress(context.Background(), rec, "rip-left"); o.Code != provider.AddrReleaseFailed || o.Released || o.Error == "" {
		t.Fatalf("failed delete: %+v", o)
	}
	f.failOn = failPath(http.MethodGet, "/reserved-ips")
	if o := p.ReleaseOneAddress(context.Background(), rec, "rip-left"); o.Code != provider.AddrReleaseFailed {
		t.Fatalf("unreadable list: %+v", o)
	}
}

// --- PA-3: teardown by id double-checks the derived label ---

// moveInstance makes the recorded id gone while an instance with the
// same label (and the given tags) lives on under a new id.
func moveInstance(f *fakeVultr, oldID, newID string, tags []string) {
	inst := f.instances[oldID]
	delete(f.instances, oldID)
	cp := *inst
	cp.ID = newID
	if tags != nil {
		cp.Tags = tags
	}
	f.instances[newID] = &cp
}

func TestDecommission_VultrIDGoneButALabelledInstanceRemains(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	moveInstance(f, rec.ServerID, "inst-new", nil)
	rep, err := p.Decommission(context.Background(), rec)
	if !errors.Is(err, provider.ErrNamedServerRemains) {
		t.Fatalf("err = %v", err)
	}
	if rep.ServerDeleted || rep.NamedServer == nil || rep.NamedServer.ID != "inst-new" || rep.NamedServer.Name != relayLabel() {
		t.Fatalf("report = %+v named=%+v", rep, rep.NamedServer)
	}
	if _, ok := f.instances["inst-new"]; !ok {
		t.Error("the named instance was deleted")
	}
	if len(f.groups) == 0 {
		t.Error("the firewall of a live instance was removed")
	}
	if !containsSubstr(rep.Preserved, "server:inst-new") {
		t.Errorf("preserved = %v", rep.Preserved)
	}
	for _, w := range rep.Warnings {
		if strings.Contains(w, "curl") || strings.Contains(w, "daal-deploy ") || strings.Contains(w, "`") {
			t.Errorf("warning carries a command line: %q", w)
		}
	}
}

func TestDecommission_VultrIDGoneAndTheLabelLookupFails(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	delete(f.instances, rec.ServerID)
	f.failOn = failPath(http.MethodGet, "/instances")
	rep, err := p.Decommission(context.Background(), rec)
	if err == nil || errors.Is(err, provider.ErrNamedServerRemains) {
		t.Fatalf("err = %v, want a lookup error", err)
	}
	if rep.ServerDeleted || rep.NamedServer != nil {
		t.Fatalf("report = %+v", rep)
	}
}

func TestDecommission_VultrIDGoneAndTheLabelledInstanceIsNotDaals(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	moveInstance(f, rec.ServerID, "inst-foreign", []string{"managed-by:someone-else"})
	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !rep.ServerDeleted || rep.NamedServer != nil {
		t.Fatalf("report = %+v, want today's server_deleted:true", rep)
	}
	if _, ok := f.instances["inst-foreign"]; !ok {
		t.Error("an instance without Daal's tags was deleted")
	}
}
