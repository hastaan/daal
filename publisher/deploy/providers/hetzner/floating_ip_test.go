package hetzner

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/sni"
)

func fipRecord() *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "1",
		Region:          "fsn1",
		PublicIP:        net.ParseIP("5.75.0.1"),
		PublisherPubKey: []byte("0123456789abcdef"),
		CoverSNI:        "mirror.xtom.de", // eu-central, like fsn1
		Candidates: []provider.CandidateMeta{
			{Family: "vless-reality", PublicRiskTags: []string{"public_ip:5.75.0.1", "public_port:tcp443"}},
		},
	}
}

// Before Step 9 there was no floating-IP creation anywhere in the repo,
// so the cheapest recovery rung required an address reserved by hand in
// the provider console plus its numeric id, for which no input existed.
func TestCreateFloatingIP_ReservesInTheRelaysOwnRegion(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := fipRecord()

	id, addr, err := p.CreateFloatingIP(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || addr == nil {
		t.Fatalf("CreateFloatingIP returned id=%q addr=%v", id, addr)
	}
	got := f.fips[id]
	if got.HomeLocation != "fsn1" {
		t.Errorf("home location = %q, want the relay's own fsn1 — an address homed elsewhere routes via that location and breaks the cover host's neighbourhood claim", got.HomeLocation)
	}
	if got.Labels[labelManagedBy] != labelManagedByValue {
		t.Errorf("labels = %v, want the daal ownership stamp (without it the address can never be safely deleted)", got.Labels)
	}
	if !strings.HasPrefix(got.Name, derivedServerName(rec.PublisherPubKey, rec.Region)) {
		t.Errorf("name %q does not identify the relay it belongs to", got.Name)
	}
}

// Hetzner enforces name uniqueness on floating IPs the same way it does
// on SSH keys, and a name that is a pure function of (publisher key,
// region) is what wedged accounts before. Two reservations for the same
// relay must both succeed.
func TestCreateFloatingIP_TwiceForTheSameRelay(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := fipRecord()

	first, _, err := p.CreateFloatingIP(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := p.CreateFloatingIP(context.Background(), rec)
	if err != nil {
		t.Fatalf("second reservation for the same relay failed — the name is not per-attempt unique: %v", err)
	}
	if first == second {
		t.Fatal("two reservations returned the same id")
	}
}

func TestCreateFloatingIP_NeedsARegion(t *testing.T) {
	p := New(newFake())
	rec := fipRecord()
	rec.Region = ""
	if _, _, err := p.CreateFloatingIP(context.Background(), rec); err == nil {
		t.Fatal("expected a refusal: an address with no home location cannot be placed")
	}
}

// An address daal-deploy created is deleted; one the operator reserved
// is only detached, and the caller is told, because it is still billing.
func TestReleaseFloatingIP_DeletesOnlyWhatWeCreated(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := fipRecord()
	f.seedFloatingIP("fip-ours", "203.0.113.1", "fsn1", true)
	f.seedFloatingIP("fip-theirs", "203.0.113.2", "fsn1", false)

	deleted, err := p.ReleaseFloatingIP(context.Background(), rec, "fip-ours")
	if err != nil || !deleted {
		t.Fatalf("releasing our own address: deleted=%v err=%v", deleted, err)
	}
	if _, still := f.fips["fip-ours"]; still {
		t.Error("our address survived the release")
	}

	deleted, err = p.ReleaseFloatingIP(context.Background(), rec, "fip-theirs")
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Error("deleted an address daal-deploy did not create — that address is the operator's property")
	}
	if _, still := f.fips["fip-theirs"]; !still {
		t.Error("the operator's address was destroyed")
	}
}

// THE SIBLING-RELAY CASE, which is the one that destroys something.
//
// An operator running two relays in one Hetzner account has two
// addresses both carrying managed-by=daal-deploy. A mistyped id — or
// one copied out of the provider console, which is exactly where an
// operator gets these numbers — used to be enough: the release path
// detached the address BEFORE any ownership check (taking the sibling
// relay off the air) and then deleted it on the managed-by label alone
// (making that permanent, with every distributed pack for that relay
// now dead). ownsEphemeralKey has required both labels and had a
// sibling test since FRP-4; the destructive verb had neither.
func TestReleaseFloatingIP_RefusesAnotherRelaysAddress(t *testing.T) {
	f := newFake()
	p := New(f)
	rec := fipRecord()

	// R2: same account, same daal-deploy, different relay, attached and
	// answering right now.
	sibling := f.seedFloatingIP("fip-sibling", "203.0.113.9", "fsn1", true)
	sibling.Labels[labelRelay] = "daal-relay-someone-else"
	sibling.ServerID = "999"

	deleted, err := p.ReleaseFloatingIP(context.Background(), rec, "fip-sibling")
	if err == nil {
		t.Fatal("released an address attached to a DIFFERENT server — that takes a live relay off the air permanently")
	}
	if deleted {
		t.Fatal("reported the sibling's address as deleted")
	}
	if _, still := f.fips["fip-sibling"]; !still {
		t.Fatal("the sibling relay's address was destroyed")
	}
	if got := f.fips["fip-sibling"].ServerID; got != "999" {
		t.Fatalf("the sibling was detached from its server (ServerID=%q) before the refusal", got)
	}

	// And detached-but-still-another-relay's: no error (nothing is
	// answering on it), but not ours to delete either.
	orphan := f.seedFloatingIP("fip-orphan", "203.0.113.10", "fsn1", true)
	orphan.Labels[labelRelay] = "daal-relay-someone-else"
	deleted, err = p.ReleaseFloatingIP(context.Background(), rec, "fip-orphan")
	if err != nil {
		t.Fatalf("unexpected error on a detached sibling address: %v", err)
	}
	if deleted {
		t.Fatal("deleted another relay's reserved address")
	}
	if _, still := f.fips["fip-orphan"]; !still {
		t.Fatal("another relay's reserved address was destroyed")
	}
}

// A rollback can run twice. An address that is already gone is success,
// not an error, or the second attempt turns a recovered rotation into a
// failed one.
func TestReleaseFloatingIP_AbsentIsSuccess(t *testing.T) {
	p := New(newFake())
	deleted, err := p.ReleaseFloatingIP(context.Background(), fipRecord(), "fip-nope")
	if err != nil || !deleted {
		t.Fatalf("deleted=%v err=%v, want true/nil", deleted, err)
	}
}

// THE WAVE-2 INTERACTION. A floating IP homed in a different location
// than the relay's cover host puts the (address, SNI) pair a censor sees
// back into the implausible state Wave 2 exists to remove. L3 must not
// silently re-pick the cover host (that is an L2, on the box, and
// capability-gated), so the only honest answer is to refuse.
func TestAssignFloatingIP_RefusesAnAddressOutsideTheCoverHostsZone(t *testing.T) {
	f := newFake()
	f.servers["1"] = &ServerInfo{ID: "1", PublicIP: net.ParseIP("5.75.0.1")}
	// mirror.xtom.de is eu-central; "sin" is apac.
	f.seedFloatingIP("fip-apac", "203.0.113.20", "sin", true)
	p := New(f)
	rec := fipRecord()

	err := p.AssignFloatingIP(context.Background(), rec, "fip-apac")
	if err == nil {
		t.Fatal("expected a refusal: the cover host is not plausible for an address in another neighbourhood")
	}
	if !strings.Contains(err.Error(), rec.CoverSNI) {
		t.Errorf("the error must name the cover host so the operator knows what to fix: %v", err)
	}
	if rec.PublicIP.String() != "5.75.0.1" {
		t.Errorf("record mutated by a refused assign: %s", rec.PublicIP)
	}
	if _, attached := f.floating["fip-apac"]; attached {
		t.Error("the address was attached despite the refusal")
	}
}

// Same zone is the normal case and must go through untouched — in
// particular the cover host must NOT move, because moving it means an
// on-box TLS rotation the operator did not ask for.
func TestAssignFloatingIP_SameZoneKeepsTheCoverHost(t *testing.T) {
	f := newFake()
	f.servers["1"] = &ServerInfo{ID: "1", PublicIP: net.ParseIP("5.75.0.1")}
	f.seedFloatingIP("fip-eu", "203.0.113.21", "nbg1", true) // also eu-central
	p := New(f)
	rec := fipRecord()
	before := rec.CoverSNI

	if err := p.AssignFloatingIP(context.Background(), rec, "fip-eu"); err != nil {
		t.Fatal(err)
	}
	if rec.CoverSNI != before {
		t.Errorf("cover host moved to %q; an L3 must not silently perform an L2 (the box's sing-box config still advertises %q)", rec.CoverSNI, before)
	}
	if rec.PublicIP.String() != "203.0.113.21" {
		t.Errorf("record.PublicIP = %s, want 203.0.113.21", rec.PublicIP)
	}
}

// Three cases where the zone question cannot be settled. All must pass:
// blocking them would break rotations that are fine.
func TestAssignFloatingIP_UnjudgeableZonesAreAllowed(t *testing.T) {
	cases := []struct {
		name     string
		coverSNI string
		home     string
	}{
		{"record predates Wave 2 and has no cover host", "", "sin"},
		{"cover host is not in the pool (operator override)", "mirror.example.invalid", "sin"},
		{"the address has no home location", "mirror.xtom.de", ""},
		{"legacy fleet-wide constant", sni.LegacyCoverSNI, "sin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.servers["1"] = &ServerInfo{ID: "1", PublicIP: net.ParseIP("5.75.0.1")}
			f.seedFloatingIP("fip-x", "203.0.113.30", tc.home, true)
			p := New(f)
			rec := fipRecord()
			rec.CoverSNI = tc.coverSNI
			if err := p.AssignFloatingIP(context.Background(), rec, "fip-x"); err != nil {
				t.Fatalf("assign refused on an unjudgeable pairing: %v", err)
			}
		})
	}
}

// The adapter reads the address back and refuses to claim an attachment
// it cannot see, rather than trusting the Assign call's action id.
func TestAssignFloatingIP_ReadBackFailureIsNotSuccess(t *testing.T) {
	f := newFake()
	f.servers["1"] = &ServerInfo{ID: "1", PublicIP: net.ParseIP("5.75.0.1")}
	f.seedFloatingIP("fip-rb", "203.0.113.40", "fsn1", true)
	rec := fipRecord()

	// Let the first read (address resolution) succeed, then break the
	// confirming read that follows the attach.
	calls := 0
	p := New(&readBackBreaker{fakeClient: f, breakAfter: 1, calls: &calls})

	if err := p.AssignFloatingIP(context.Background(), rec, "fip-rb"); err == nil {
		t.Fatal("expected the failed read-back to fail the assign")
	}
	if rec.PublicIP.String() != "5.75.0.1" {
		t.Errorf("record adopted an address the adapter could not confirm: %s", rec.PublicIP)
	}
}

// readBackBreaker fails FloatingIPByID after N successful calls.
type readBackBreaker struct {
	*fakeClient
	breakAfter int
	calls      *int
}

func (r *readBackBreaker) FloatingIPByID(ctx context.Context, id string) (*FloatingIPInfo, error) {
	*r.calls++
	if *r.calls > r.breakAfter {
		return nil, errors.New("api unavailable")
	}
	return r.fakeClient.FloatingIPByID(ctx, id)
}

// retagPublicIP is the mechanism behind "both copies move". Pin the
// three shapes a candidate's tag list can be in.
func TestRetagPublicIP(t *testing.T) {
	ip := net.ParseIP("203.0.113.77")

	got := retagPublicIP([]string{"public_ip:5.75.0.1", "public_port:tcp443"}, ip)
	if len(got) != 2 || got[0] != "public_ip:203.0.113.77" || got[1] != "public_port:tcp443" {
		t.Errorf("replace-in-place: %v", got)
	}

	got = retagPublicIP([]string{"public_port:tcp443"}, ip)
	if len(got) != 2 || got[1] != "public_ip:203.0.113.77" {
		t.Errorf("append-when-absent: %v", got)
	}

	// Two address tags on one candidate means it is simultaneously in
	// and out of any address cooldown. Collapse to one.
	got = retagPublicIP([]string{"public_ip:5.75.0.1", "public_ip:5.75.0.2", "sni:cover.example.com"}, ip)
	if len(got) != 2 || got[0] != "public_ip:203.0.113.77" || got[1] != "sni:cover.example.com" {
		t.Errorf("collapse-duplicates: %v", got)
	}
}
