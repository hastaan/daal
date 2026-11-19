package vultr

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

func TestReleaseRelayAddresses_VultrReleasesMarkedKeepsTheRest(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	f.rips["rip-a"] = &wireReservedIP{ID: "rip-a", Region: testRegion, IPType: "v4", Subnet: "95.179.20.9",
		SubnetSize: 32, Label: ownershipMark(relayLabel(), "fip-a")}
	f.rips["rip-attached"] = &wireReservedIP{ID: "rip-attached", Region: testRegion, IPType: "v4", Subnet: "95.179.20.10",
		SubnetSize: 32, Label: ownershipMark(relayLabel(), "fip-b"), InstanceID: "someone-else"}
	f.rips["rip-mine"] = &wireReservedIP{ID: "rip-mine", Region: testRegion, IPType: "v4", Subnet: "95.179.20.11",
		SubnetSize: 32, Label: "my own address"}
	rec.FloatingIPID = "rip-mine"
	delete(f.instances, rec.ServerID) // the server is gone

	out := p.ReleaseRelayAddresses(context.Background(), rec, rec.ServerID)
	codes := map[string]string{}
	for _, a := range out {
		codes[a.ID] = a.Code
	}
	if codes["rip-a"] != provider.AddrReleased || codes["rip-attached"] != provider.AddrStillAttached || codes["rip-mine"] != provider.AddrNotDaal {
		t.Fatalf("codes = %v", codes)
	}
	if _, ok := f.rips["rip-a"]; ok {
		t.Error("the relay's reserved IP is still billing")
	}
	if _, ok := f.rips["rip-mine"]; !ok {
		t.Error("released the person's own address")
	}
	if _, ok := f.rips["rip-attached"]; !ok {
		t.Error("released an address attached to another instance")
	}

	f.rips["rip-c"] = &wireReservedIP{ID: "rip-c", Region: testRegion, IPType: "v4", Subnet: "95.179.20.12",
		SubnetSize: 32, Label: ownershipMark(relayLabel(), "fip-c")}
	f.failOn = func(method, path string) (int, bool) {
		return http.StatusInternalServerError, method == http.MethodDelete && strings.HasPrefix(path, "/reserved-ips/")
	}
	rec.FloatingIPID = ""
	out = p.ReleaseRelayAddresses(context.Background(), rec, rec.ServerID)
	for _, a := range out {
		if a.ID == "rip-c" && a.Code != provider.AddrReleaseFailed {
			t.Fatalf("failed release reported as %+v", a)
		}
	}
}

func TestServerState_Vultr(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	cases := []struct {
		status, server, power, want string
	}{
		{"active", "ok", "running", provider.ServerRunning},
		{"active", "ok", "", provider.ServerRunning},
		{"active", "ok", "stopped", provider.ServerStopped},
		{"pending", "none", "running", provider.ServerStarting},
		{"active", "installingbooting", "running", provider.ServerStarting},
		{"suspended", "ok", "running", provider.ServerStopped},
	}
	for _, c := range cases {
		inst := f.instances[rec.ServerID]
		inst.Status, inst.ServerStatus, inst.PowerStatus = c.status, c.server, c.power
		got, err := p.ServerState(context.Background(), rec)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %q, %v", c, got, err)
		}
	}
	delete(f.instances, rec.ServerID)
	if got, err := p.ServerState(context.Background(), rec); err != nil || got != provider.ServerMissing {
		t.Errorf("gone: %q, %v", got, err)
	}
}
