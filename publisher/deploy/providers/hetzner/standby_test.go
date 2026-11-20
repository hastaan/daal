package hetzner

import (
	"context"
	"errors"
	"net"
	"testing"

	"daal/publisher/deploy/provider"
)

func seedStandby(f *fakeClient, id, addr, serverID string) {
	fip := f.seedFloatingIP(id, addr, "fsn1", true)
	f.mu.Lock()
	fip.Labels[labelRole] = labelRoleStandby
	fip.ServerID = serverID
	if serverID != "" {
		f.floating[id] = serverID
	}
	f.mu.Unlock()
}

// Renting: labelled for this relay AND as a standby, homed in the
// relay's location, assigned to its server — and NOT adopted: the
// record still dials its own address.
func TestEnsureStandby_RentsAssignsAndDoesNotAdopt(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := fipRecord()
	res, err := p.EnsureStandby(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Adopted || res.Standby.FloatingIPID == "" || res.Standby.IP.To4() == nil {
		t.Fatalf("res = %+v", res)
	}
	got := f.fips[res.Standby.FloatingIPID]
	if got.HomeLocation != "fsn1" || got.ServerID != "1" {
		t.Errorf("standby home=%s server=%s", got.HomeLocation, got.ServerID)
	}
	if got.Labels[labelRole] != labelRoleStandby || !ownsFloatingIP(got, rec) {
		t.Errorf("labels = %v", got.Labels)
	}
	if !rec.PublicIP.Equal(net.ParseIP("5.75.0.1")) || rec.FloatingIPID != "" || rec.Standby != nil {
		t.Errorf("EnsureStandby changed the record: %+v", rec)
	}
	if rec.Candidates[0].PublicRiskTags[0] != "public_ip:5.75.0.1" {
		t.Errorf("candidate tags moved: %v", rec.Candidates[0].PublicRiskTags)
	}
}

// THE KILLED-WIZARD RULE. A run killed after the rent left a labelled
// standby; the retry adopts it instead of renting a second one.
func TestEnsureStandby_RetryAdoptsWhatAKilledRunRented(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-left", "203.0.113.90", "")
	p := New(f)
	res, err := p.EnsureStandby(context.Background(), fipRecord())
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || !res.Adopted || res.Standby.FloatingIPID != "fip-left" {
		t.Fatalf("res = %+v, want fip-left adopted", res)
	}
	if len(f.fips) != 1 {
		t.Errorf("%d floating IPs on the account, want 1 (no second rent)", len(f.fips))
	}
	if f.fips["fip-left"].ServerID != "1" {
		t.Error("adopted standby was not assigned")
	}
}

// Two killed runs: one adopted, the other handed back as a stray for
// the caller to release.
func TestEnsureStandby_ReportsStrays(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-a", "203.0.113.91", "")
	seedStandby(f, "fip-b", "203.0.113.92", "1")
	res, err := New(f).EnsureStandby(context.Background(), fipRecord())
	if err != nil {
		t.Fatal(err)
	}
	if res.Standby.FloatingIPID != "fip-a" || len(res.Strays) != 1 || res.Strays[0].FloatingIPID != "fip-b" {
		t.Fatalf("res = %+v", res)
	}
}

// Not every Floating IP labelled for this relay is a standby: an L3
// swap's address carries the same two labels and no role. A sibling
// relay's standby is not ours either.
func TestEnsureStandby_LeavesOtherAddressesAlone(t *testing.T) {
	f := newFake()
	f.seedFloatingIP("fip-l3", "203.0.113.50", "fsn1", true) // no role
	sib := f.seedFloatingIP("fip-sib", "203.0.113.51", "fsn1", true)
	sib.Labels[labelRelay] = "daal-fsn1-someoneelse"
	sib.Labels[labelRole] = labelRoleStandby
	res, err := New(f).EnsureStandby(context.Background(), fipRecord())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || len(res.Strays) != 0 {
		t.Fatalf("res = %+v, want a fresh rent and no strays", res)
	}
	if f.fips["fip-l3"].ServerID != "" || f.fips["fip-sib"].ServerID != "" {
		t.Error("touched an address that is not this relay's standby")
	}
}

// The record already names its standby: re-ensuring keeps its salt (or
// every pack already out would stop matching the key).
func TestEnsureStandby_KeepsTheRecordsStandbyAndSalt(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-s", "203.0.113.93", "1")
	rec := fipRecord()
	rec.Standby = &provider.StandbyAddress{FloatingIPID: "fip-s", IP: net.ParseIP("203.0.113.93"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	res, err := New(f).EnsureStandby(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.Adopted || res.Standby.FloatingIPID != "fip-s" || res.Standby.Salt != "AAECAwQFBgcICQoL" {
		t.Fatalf("res = %+v", res)
	}
}

// GATE S-1's refusal is typed, so the app can say what it means.
func TestEnsureStandby_LimitIsTyped(t *testing.T) {
	f := newFake()
	f.failFloatingIPCreate = errors.New("hcloud: Floating IP limit exceeded (resource_limit_exceeded)")
	_, err := New(f).EnsureStandby(context.Background(), fipRecord())
	if !errors.Is(err, ErrStandbyLimit) {
		t.Fatalf("err = %v, want ErrStandbyLimit", err)
	}
	if len(f.fips) != 0 {
		t.Error("something was created")
	}
}

// A failed assign returns what was rented, so the caller's rollback
// can release it. EnsureStandby itself deletes nothing.
func TestEnsureStandby_AssignFailureReturnsWhatWasRented(t *testing.T) {
	f := newFake()
	f.failFloatingIPAssign = errors.New("locked")
	p := New(f)
	rec := fipRecord()
	res, err := p.EnsureStandby(context.Background(), rec)
	if err == nil || res == nil || !res.Created || res.Standby.FloatingIPID == "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, ok := f.fips[res.Standby.FloatingIPID]; !ok {
		t.Fatal("EnsureStandby deleted on its own; the caller's rollback owns that")
	}
	deleted, err := p.RemoveStandby(context.Background(), rec, res.Standby.FloatingIPID)
	if err != nil || !deleted || len(f.fips) != 0 {
		t.Fatalf("rollback release: deleted=%v err=%v left=%d", deleted, err, len(f.fips))
	}
}

func TestPromoteStandby_MovesEveryCopyOfTheAddress(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-s", "203.0.113.93", "1")
	rec := fipRecord()
	rec.Standby = &provider.StandbyAddress{FloatingIPID: "fip-s", IP: net.ParseIP("203.0.113.93"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	prior, priorIP, err := New(f).PromoteStandby(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if prior != "" || !priorIP.Equal(net.ParseIP("5.75.0.1")) {
		t.Errorf("prior = %q %v", prior, priorIP)
	}
	if rec.FloatingIPID != "fip-s" || !rec.PublicIP.Equal(net.ParseIP("203.0.113.93")) || rec.Standby != nil {
		t.Errorf("record = %+v", rec)
	}
	if rec.Candidates[0].PublicRiskTags[0] != "public_ip:203.0.113.93" {
		t.Errorf("tags = %v", rec.Candidates[0].PublicRiskTags)
	}
}

func TestPromoteStandby_RefusesAnUnroutedStandby(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-s", "203.0.113.93", "") // not attached
	rec := fipRecord()
	rec.Standby = &provider.StandbyAddress{FloatingIPID: "fip-s", IP: net.ParseIP("203.0.113.93"), Mode: "sealed", Salt: "AAECAwQFBgcICQoL"}
	if _, _, err := New(f).PromoteStandby(context.Background(), rec); err == nil {
		t.Fatal("promoted an address that is not routed to the relay")
	}
	if rec.Standby == nil || !rec.PublicIP.Equal(net.ParseIP("5.75.0.1")) {
		t.Error("a refused promote changed the record")
	}
}

func TestRemoveStandby_Rules(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-s", "203.0.113.93", "1")
	f.seedFloatingIP("fip-l3", "203.0.113.50", "fsn1", true)
	rec := fipRecord()
	rec.FloatingIPID = "fip-l3"
	p := New(f)
	ctx := context.Background()
	if _, err := p.RemoveStandby(ctx, rec, "fip-l3"); err == nil {
		t.Error("released the advertised address")
	}
	f.seedFloatingIP("fip-other", "203.0.113.51", "fsn1", true)
	if _, err := p.RemoveStandby(ctx, rec, "fip-other"); err == nil {
		t.Error("released an address that is neither the record's standby nor labelled as one")
	}
	rec.Standby = &provider.StandbyAddress{FloatingIPID: "fip-s", IP: net.ParseIP("203.0.113.93")}
	deleted, err := p.RemoveStandby(ctx, rec, "fip-s")
	if err != nil || !deleted || rec.Standby != nil {
		t.Fatalf("deleted=%v err=%v standby=%v", deleted, err, rec.Standby)
	}
	if _, ok := f.fips["fip-s"]; ok {
		t.Error("still on the account")
	}
	// Already gone is success.
	if deleted, err := p.RemoveStandby(ctx, rec, "fip-s"); err != nil || !deleted {
		t.Errorf("second remove: %v %v", deleted, err)
	}
}

// RELAY DELETE. Decommission's address release gives the standby back
// with the relay: it carries the relay's labels and its server is gone.
func TestReleaseRelayAddresses_ReleasesTheStandby(t *testing.T) {
	f := newFake()
	seedStandby(f, "fip-s", "203.0.113.93", "1")
	rec := fipRecord()
	rec.Standby = &provider.StandbyAddress{FloatingIPID: "fip-s", IP: net.ParseIP("203.0.113.93")}
	// Hetzner detaches a Floating IP when its server is deleted.
	f.fips["fip-s"].ServerID = ""
	out := New(f).ReleaseRelayAddresses(context.Background(), rec, "1")
	if len(out) != 1 || !out[0].Released || out[0].ID != "fip-s" {
		t.Fatalf("outcomes = %+v", out)
	}
	if len(f.fips) != 0 {
		t.Error("standby still billing after relay delete")
	}
}

type pricedFake struct {
	*fakeClient
	price StandbyPrice
}

func (p *pricedFake) FloatingIPMonthlyPrice(_ context.Context, loc string) (StandbyPrice, error) {
	out := p.price
	out.Location = loc
	return out, nil
}

func TestStandbyMonthlyPrice(t *testing.T) {
	if _, err := New(newFake()).StandbyMonthlyPrice(context.Background(), "fsn1"); !errors.Is(err, ErrNoStandbyPrice) {
		t.Errorf("err = %v, want ErrNoStandbyPrice", err)
	}
	pf := &pricedFake{fakeClient: newFake(), price: StandbyPrice{Currency: "EUR", VATRate: "19.00", MonthlyNet: "3.0000000000", MonthlyGross: "3.5700000000"}}
	got, err := New(pf).StandbyMonthlyPrice(context.Background(), "hel1")
	if err != nil || got.Location != "hel1" || got.MonthlyNet != "3.0000000000" {
		t.Fatalf("got %+v %v", got, err)
	}
}
