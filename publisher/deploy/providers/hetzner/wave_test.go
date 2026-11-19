package hetzner

import (
	"context"
	"errors"
	"testing"

	"daal/publisher/deploy/provider"
)

// --- D4: decommission releases every address Daal reserved ---

func addrFor(t *testing.T, out []provider.AddressOutcome, id string) provider.AddressOutcome {
	t.Helper()
	for _, a := range out {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no outcome for address %s: %+v", id, out)
	return provider.AddressOutcome{}
}

func TestReleaseRelayAddresses_ReleasesDaalsKeepsTheRest(t *testing.T) {
	f := newFake()
	// The record's own address, labelled for this relay.
	f.seedFIP("fip-rec", "198.51.100.1", "fsn1", "", ownedLabels(relayA()))
	// A second labelled address the record does not name (an L3 swap
	// that never got written back).
	f.seedFIP("fip-extra", "198.51.100.2", "fsn1", "", ownedLabels(relayA()))
	// Labelled for this relay but attached to some other server.
	f.seedFIP("fip-other", "198.51.100.3", "fsn1", "99", ownedLabels(relayA()))
	// The person's own address, named by the record but unlabelled.
	f.seedFIP("fip-mine", "198.51.100.4", "fsn1", "", nil)
	// Another relay's address: never touched, never mentioned.
	f.seedFIP("fip-b", "198.51.100.5", "hel1", "", ownedLabels(relayB()))

	rec := recordFor(pubKeyA, "fsn1", "10")
	rec.FloatingIPID = "fip-rec"
	out := New(f).ReleaseRelayAddresses(context.Background(), rec, "10")

	if a := addrFor(t, out, "fip-rec"); !a.Released || a.Code != provider.AddrReleased || a.IP != "198.51.100.1" {
		t.Errorf("record's address: %+v", a)
	}
	if a := addrFor(t, out, "fip-extra"); a.Code != provider.AddrReleased {
		t.Errorf("unrecorded labelled address: %+v", a)
	}
	if a := addrFor(t, out, "fip-other"); a.Released || a.Code != provider.AddrStillAttached {
		t.Errorf("address on another server: %+v", a)
	}
	for _, id := range []string{"fip-rec", "fip-extra"} {
		if _, ok := f.fips[id]; ok {
			t.Errorf("%s still reserved", id)
		}
	}
	for _, id := range []string{"fip-other", "fip-b"} {
		if _, ok := f.fips[id]; !ok {
			t.Errorf("%s was released but is not this relay's to release", id)
		}
	}
	for _, a := range out {
		if a.ID == "fip-b" {
			t.Errorf("another relay's address appears in the report: %+v", a)
		}
	}

	// The person's own address named by the record: kept, said so.
	rec.FloatingIPID = "fip-mine"
	out = New(f).ReleaseRelayAddresses(context.Background(), rec, "10")
	if a := addrFor(t, out, "fip-mine"); a.Released || a.Code != provider.AddrNotDaal {
		t.Errorf("person's own address: %+v", a)
	}
	if _, ok := f.fips["fip-mine"]; !ok {
		t.Error("released an address Daal did not reserve")
	}
}

func TestReleaseRelayAddresses_AFailedReleaseIsReported(t *testing.T) {
	f := newFake()
	f.seedFIP("fip-rec", "198.51.100.1", "fsn1", "", ownedLabels(relayA()))
	f.failFloatingIPDelete = errors.New("503 from the cloud")
	rec := recordFor(pubKeyA, "fsn1", "10")
	rec.FloatingIPID = "fip-rec"
	out := New(f).ReleaseRelayAddresses(context.Background(), rec, "10")
	if a := addrFor(t, out, "fip-rec"); a.Released || a.Code != provider.AddrReleaseFailed || a.Error == "" {
		t.Fatalf("failed release reported as %+v", a)
	}
}

func TestReleaseRelayAddresses_AnUnreadableListIsAFailureNotSilence(t *testing.T) {
	f := newFake()
	f.failFloatingIPList = errors.New("503")
	out := New(f).ReleaseRelayAddresses(context.Background(), recordFor(pubKeyA, "fsn1", "10"), "10")
	if len(out) != 1 || out[0].Code != provider.AddrReleaseFailed {
		t.Fatalf("an unreadable address list must be release_failed (something may still bill): %+v", out)
	}
}

// A retried teardown: the first attempt deleted the server, then the
// API errors on the second delete. The server is provably gone, so it
// counts as deleted (contract D1-GO decommission).
func TestDecommission_AServerThatIsAlreadyGoneCountsAsDeleted(t *testing.T) {
	f := newFake()
	f.failServerDelete = errors.New("404-ish: server not found")
	rep, err := New(f).Decommission(context.Background(), recordFor(pubKeyA, "fsn1", "10"))
	if err != nil {
		t.Fatalf("a missing server failed the teardown: %v (%+v)", err, rep)
	}
	if !rep.ServerDeleted {
		t.Fatalf("server_deleted=false for a server that does not exist: %+v", rep)
	}
	// And a server that IS still there with a failing delete is not.
	f.seedServer("10", relayA(), "fsn1", ownedLabels(relayA()))
	rep, err = New(f).Decommission(context.Background(), recordFor(pubKeyA, "fsn1", "10"))
	if err == nil || rep.ServerDeleted {
		t.Fatalf("a surviving server was reported deleted: %+v %v", rep, err)
	}
}

// --- D3: server state ---

func TestServerState_MapsHetznerStatuses(t *testing.T) {
	f := newFake()
	p := New(f)
	for status, want := range map[string]string{
		"running": provider.ServerRunning, "off": provider.ServerStopped, "stopping": provider.ServerStopped,
		"initializing": provider.ServerStarting, "starting": provider.ServerStarting, "rebuilding": provider.ServerStarting,
	} {
		s := f.seedServer("10", relayA(), "fsn1", ownedLabels(relayA()))
		s.Status = status
		got, err := p.ServerState(context.Background(), recordFor(pubKeyA, "fsn1", "10"))
		if err != nil || got != want {
			t.Errorf("status %q: got %q, %v; want %q", status, got, err, want)
		}
	}
	delete(f.servers, "10")
	if got, err := p.ServerState(context.Background(), recordFor(pubKeyA, "fsn1", "10")); err != nil || got != provider.ServerMissing {
		t.Errorf("gone server: %q, %v", got, err)
	}
	// No id on the record: found by the derived name.
	f.seedServer("11", relayA(), "fsn1", ownedLabels(relayA()))
	if got, err := p.ServerState(context.Background(), recordFor(pubKeyA, "fsn1", "")); err != nil || got != provider.ServerRunning {
		t.Errorf("by derived name: %q, %v", got, err)
	}
}
