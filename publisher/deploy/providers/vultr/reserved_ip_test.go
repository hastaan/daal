package vultr

import (
	"context"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// The adapter really does satisfy the deploy contract. A compile-time
// assertion, because a Provider that is one method short is a provider
// the wizard cannot bind at all.
var _ provider.Provider = (*Provider)(nil)

// TestL3_AssignMovesEveryCopyOfTheAddress is THE L3 test. The bug this
// guards against is not hypothetical: this adapter used to set
// FloatingIPID — a field nothing on the wire reads — and leave
// rec.PublicIP and every candidate's public_ip:* tag naming the burned
// address, so the swap reported success and every recipient's pack kept
// pointing at the blocked address.
func TestL3_AssignMovesEveryCopyOfTheAddress(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, addr, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatalf("CreateFloatingIP: %v", err)
	}
	if addr.String() != "95.179.20.7" {
		t.Fatalf("reserved address = %v", addr)
	}
	// Homed in the relay's own region, and carrying BOTH ownership
	// facts in the one label field Vultr offers.
	rip := f.rips[fipID]
	if rip.Region != testRegion {
		t.Errorf("address homed in %q, not the relay's %q", rip.Region, testRegion)
	}
	if !markedFor(rip.Label, relayLabel()) {
		t.Errorf("reserved ip label does not carry both ownership facts: %q", rip.Label)
	}

	if err := p.AssignFloatingIP(ctx, rec, fipID); err != nil {
		t.Fatalf("AssignFloatingIP: %v", err)
	}
	if rec.FloatingIPID != fipID {
		t.Errorf("record does not name the address id")
	}
	if rec.PublicIP.String() != "95.179.20.7" {
		t.Errorf("rec.PublicIP still names the old address: %v", rec.PublicIP)
	}
	for _, c := range rec.Candidates {
		if !hasTag(c.PublicRiskTags, "public_ip:95.179.20.7") {
			t.Errorf("candidate %s still tagged with the old address: %v", c.Family, c.PublicRiskTags)
		}
		n := 0
		for _, tg := range c.PublicRiskTags {
			if strings.HasPrefix(tg, "public_ip:") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("candidate %s carries %d public_ip tags — it is simultaneously in and out of an address cooldown", c.Family, n)
		}
	}
}

// TestL3_AssignRefusesAnAddressHeldByAnotherRelay. Stealing it would
// black-hole whatever relay is answering on it right now; a rotation
// must never take a second relay down.
func TestL3_AssignRefusesAnAddressHeldByAnotherRelay(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	f.rips[fipID].InstanceID = "somebody-elses-instance"

	if err := p.AssignFloatingIP(ctx, rec, fipID); err == nil {
		t.Fatal("attached an address that another instance is answering on")
	}
	if rec.FloatingIPID != "" {
		t.Error("the record was mutated by a refused swap")
	}
}

// TestL3_AssignRefusesToClaimASwapItCannotSee. The attach call returns
// before the routing change is complete, so the adapter reads the object
// back — and the record it is about to re-sign a pack against is only
// worth as much as that confirmation.
func TestL3_AssignRefusesToClaimASwapItCannotSee(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	f.attachIsNoop = true // the API says 204 and nothing moves

	before := rec.PublicIP.String()
	if err := p.AssignFloatingIP(ctx, rec, fipID); err == nil {
		t.Fatal("claimed a swap the API never performed")
	}
	if rec.PublicIP.String() != before {
		t.Errorf("record moved onto an address that is not routed here: %v", rec.PublicIP)
	}
}

// TestL3_AssignRefusesAnAddressInTheWrongNeighbourhood. Wave 2: the
// (address, SNI) pair is free for a censor to read, so an address homed
// far from the cover host's neighbourhood is a self-inflicted signal.
func TestL3_AssignRefusesAnAddressInTheWrongNeighbourhood(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	f.rips[fipID].Region = "sgp" // APAC; the relay advertises a eu-central host

	err = p.AssignFloatingIP(ctx, rec, fipID)
	if err == nil {
		t.Fatal("attached an APAC address to a relay advertising a European cover host")
	}
	if !strings.Contains(err.Error(), "rotate the cover host") {
		t.Errorf("refusal does not tell the operator what to do instead: %v", err)
	}
}

// TestL3_ReleaseWillNotDestroyAnAddressItDidNotCreate. The operator's
// own reserved IP is their property; detaching is fine, binning it is
// not — and "detached but still reserved" is still on their bill, so
// the caller is told.
func TestL3_ReleaseWillNotDestroyAnAddressItDidNotCreate(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	f.rips[fipID].Label = "my own address" // no ownership mark

	deleted, err := p.ReleaseFloatingIP(ctx, rec, fipID)
	if err != nil {
		t.Fatalf("ReleaseFloatingIP: %v", err)
	}
	if deleted {
		t.Error("destroyed an address daal-deploy did not create")
	}
	if _, ok := f.rips[fipID]; !ok {
		t.Error("the address is gone from the account")
	}
}

// The managed-by half alone is NOT enough: in an account running two
// relays every sibling address carries it, which is exactly the case
// where deleting is wrong.
func TestL3_ReleaseNeedsBothOwnershipFacts(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	// A sibling relay's address: managed by daal, owned by another relay.
	f.rips[fipID].Label = ownershipMark("daal-fra-ffffffffffffffff", "fip-1")

	deleted, err := p.ReleaseFloatingIP(ctx, rec, fipID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Error("deleted a sibling relay's address on the managed-by mark alone")
	}
}

func TestL3_ReleaseRefusesAnAddressAttachedElsewhere(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	f.rips[fipID].InstanceID = "another-relay"

	if _, err := p.ReleaseFloatingIP(ctx, rec, fipID); err == nil {
		t.Fatal("released an address another relay is answering on")
	}
	if f.rips[fipID].InstanceID != "another-relay" {
		t.Error("the other relay was detached anyway")
	}
}

func TestL3_ReleaseOfAnAbsentAddressIsSuccess(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	deleted, err := p.ReleaseFloatingIP(context.Background(), rec, "rip-does-not-exist")
	if err != nil || !deleted {
		t.Fatalf("a retried rollback must not fail because the first attempt worked: %v, %v", deleted, err)
	}
}

// TestL3_UnassignPutsTheRecordBackOnARoutedAddress. Clearing the id
// while leaving rec.PublicIP naming the detached address leaves the
// record asserting a route that no longer exists.
func TestL3_UnassignPutsTheRecordBackOnARoutedAddress(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AssignFloatingIP(ctx, rec, fipID); err != nil {
		t.Fatal(err)
	}
	if err := p.UnassignFloatingIP(ctx, rec); err != nil {
		t.Fatalf("UnassignFloatingIP: %v", err)
	}
	if rec.FloatingIPID != "" {
		t.Error("record still names a detached address id")
	}
	if rec.PublicIP.String() != "78.141.10.5" {
		t.Errorf("record did not fall back to the instance's own address: %v", rec.PublicIP)
	}
	for _, c := range rec.Candidates {
		if !hasTag(c.PublicRiskTags, "public_ip:78.141.10.5") {
			t.Errorf("candidate %s was left on the detached address: %v", c.Family, c.PublicRiskTags)
		}
	}
}

// --- ephemeral mgmt-plane rules ---

func TestEphemeralRule_OpensAndClosesTheHole(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	rule, err := p.SetEphemeralFirewallRule(ctx, rec.ServerID, "203.0.113.9", rec.MgmtPort, 300)
	if err != nil {
		t.Fatalf("SetEphemeralFirewallRule: %v", err)
	}
	if want := testNow.Add(300 * time.Second); !rule.ExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want %v", rule.ExpiresAt, want)
	}
	rules := f.rulesFor(t, rec.ServerID)
	key := ruleKey("v4", "tcp", "203.0.113.9", 32, "20000")
	if !rules[key] {
		t.Fatalf("the hole was not opened: %v", keys(rules))
	}
	if err := p.RemoveEphemeralFirewallRule(ctx, rule); err != nil {
		t.Fatalf("RemoveEphemeralFirewallRule: %v", err)
	}
	if f.rulesFor(t, rec.ServerID)[key] {
		t.Error("the hole is still open after removal")
	}
	// Idempotent: removing twice is success.
	if err := p.RemoveEphemeralFirewallRule(ctx, rule); err != nil {
		t.Errorf("second removal: %v", err)
	}
}

// FRP-10 invariant 28: the (port, IP) tuple is the rule's full key.
func TestEphemeralRule_RefusesNonsense(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	for _, tc := range []struct {
		name              string
		server, ip        string
		port, durationSec int
	}{
		{"no server", "", "203.0.113.9", 20000, 300},
		{"no caller ip", rec.ServerID, "", 20000, 300},
		{"port zero", rec.ServerID, "203.0.113.9", 0, 300},
		{"port outside the mgmt range", rec.ServerID, "203.0.113.9", 22, 300},
		{"no duration", rec.ServerID, "203.0.113.9", 20000, 0},
	} {
		if _, err := p.SetEphemeralFirewallRule(ctx, tc.server, tc.ip, tc.port, tc.durationSec); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// TestEphemeralRule_SweepsHolesAnEarlierRotationLeftOpen. Vultr enforces
// no server-side TTL, so expiry is this adapter's job: a rotation that
// died before its Remove call left a hole, and the next touch of the
// group is where it closes.
func TestEphemeralRule_SweepsHolesAnEarlierRotationLeftOpen(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	// An abandoned hole from an hour ago.
	groupID := f.instances[rec.ServerID].FirewallGroupID
	stale, err := p.c.FirewallRuleAdd(ctx, groupID, FirewallRule{
		IPType: "v4", Protocol: "tcp", Subnet: "198.51.100.4", SubnetSize: 32, Port: "31000",
		Notes: ephemeralNote("198.51.100.4", 31000, testNow.Add(-1*time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// An operator's own rule, which must survive: this adapter does not
	// delete rules it did not write.
	if _, err := p.c.FirewallRuleAdd(ctx, groupID, FirewallRule{
		IPType: "v4", Protocol: "tcp", Subnet: "198.51.100.9", SubnetSize: 32, Port: "9090",
		Notes: "my monitoring box",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := p.SetEphemeralFirewallRule(ctx, rec.ServerID, "203.0.113.9", rec.MgmtPort, 300); err != nil {
		t.Fatal(err)
	}
	rules := f.rulesFor(t, rec.ServerID)
	if rules[ruleKey("v4", "tcp", "198.51.100.4", 32, "31000")] {
		t.Error("an expired mgmt-plane hole is still open")
	}
	if !rules[ruleKey("v4", "tcp", "198.51.100.9", 32, "9090")] {
		t.Error("the operator's own firewall rule was deleted")
	}
	_ = stale
}
