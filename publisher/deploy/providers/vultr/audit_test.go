package vultr

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// TestAudit_FindsTheBoxNoRecordClaims is the L5 failure in miniature:
// a rotation onto Vultr built the instance and died before the record
// was written, so the operator is paying for a box nothing on their
// disk knows about — and they are looking at the OTHER provider's
// console.
func TestAudit_FindsTheBoxNoRecordClaims(t *testing.T) {
	f := newFakeVultr(t)
	p, _ := mustProvision(t, f, mkOpts())

	audit, err := p.AuditAccount(context.Background(), nil) // no records at all
	if err != nil {
		t.Fatalf("AuditAccount: %v", err)
	}
	if !audit.ServerListComplete {
		t.Fatal("the instance list was readable; the audit says otherwise")
	}
	srv := findKind(audit, provider.KindServer)
	if srv == nil {
		t.Fatal("the running instance is not in the report")
	}
	if srv.Verdict != provider.VerdictUnclaimed {
		t.Errorf("verdict = %q, want unclaimed", srv.Verdict)
	}
	if !srv.Billing {
		t.Error("a running instance is not marked as billing")
	}
	if srv.Reclaimable {
		t.Error("the audit offered to delete a server; a server IS the relay and only the operator can decide")
	}
	if !strings.Contains(srv.Hint, "decommission") || !strings.Contains(srv.Hint, srv.ID) {
		t.Errorf("hint does not tell the operator how to remove it: %q", srv.Hint)
	}
	if !audit.NeedsAttention() {
		t.Error("an unclaimed billing instance is not flagged as needing attention")
	}
}

// A record that claims the relay turns the same instance from
// "unclaimed" into "in-use".
func TestAudit_ARecordClaimsTheRelay(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())

	audit, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	srv := findKind(audit, provider.KindServer)
	if srv == nil || srv.Verdict != provider.VerdictInUse {
		t.Fatalf("claimed instance = %+v, want in-use", srv)
	}
	if audit.NeedsAttention() {
		t.Errorf("a fully-claimed account needs attention: %+v", audit.Resources)
	}
	if len(audit.Known) != 1 || audit.Known[0].LiveServerID != rec.ServerID {
		t.Errorf("the record/provider join is wrong: %+v", audit.Known)
	}
}

// The classic orphaned provision: a record with no instance id beside a
// live instance. The join has to name it, because that state is what
// this whole audit exists for.
func TestAudit_RecordWithNoIDBesideALiveInstance(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	rec.ServerID = ""

	audit, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.Known) != 1 {
		t.Fatalf("known relays = %+v", audit.Known)
	}
	if !strings.Contains(audit.Known[0].Note, "never completed") {
		t.Errorf("the join does not explain the disagreement: %q", audit.Known[0].Note)
	}
}

// TestAudit_ReclaimsTheAddressAndKeyOfARelayThatIsGone. The two
// resources that survive a destroyed relay: a reserved IP that keeps
// billing, and a one-shot key that blocks the next provision.
func TestAudit_ReclaimsTheAddressAndKeyOfARelayThatIsGone(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	f.sshKeys["leftover"] = ephemeralKeyPrefix(relayLabel()) + "deadbeef"
	// The relay itself is gone — a reprovision that never came back.
	delete(f.instances, rec.ServerID)

	audit, err := p.AuditAccount(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	fip := findKind(audit, provider.KindFloatingIP)
	if fip == nil || fip.Verdict != provider.VerdictOrphan || !fip.Reclaimable {
		t.Fatalf("reserved ip = %+v, want a reclaimable orphan", fip)
	}
	key := findKind(audit, provider.KindSSHKey)
	if key == nil || key.Verdict != provider.VerdictOrphan || !key.Reclaimable {
		t.Fatalf("ssh key = %+v, want a reclaimable orphan", key)
	}

	rep, err := p.ReclaimOrphans(ctx, nil, nil)
	if err != nil {
		t.Fatalf("ReclaimOrphans: %v", err)
	}
	if _, still := f.rips[fipID]; still {
		t.Error("the orphaned address is still reserved and still billing")
	}
	if len(f.sshKeys) != 0 {
		t.Errorf("the orphaned key survived: %v", f.sshKeys)
	}
	if rep.Deleted() < 2 {
		t.Errorf("reclaim report undercounts: %+v", rep.Outcomes)
	}
}

// TestAudit_WillNotReclaimAnAddressSomethingAnswersOn.
func TestAudit_WillNotReclaimAnAddressSomethingAnswersOn(t *testing.T) {
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
	audit, err := p.AuditAccount(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	fip := findKind(audit, provider.KindFloatingIP)
	if fip == nil || fip.Verdict != provider.VerdictInUse || fip.Reclaimable {
		t.Fatalf("attached address = %+v, want in-use and not reclaimable", fip)
	}
}

// TestAudit_ARaceBetweenReportAndConfirmationIsCaught. The reclaim
// re-reads: between the operator reading a report and confirming it, an
// address can be attached to a live relay.
func TestAudit_ARaceBetweenReportAndConfirmationIsCaught(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	instID := rec.ServerID
	delete(f.instances, instID) // relay gone: the address is an orphan

	audit, err := p.AuditAccount(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fip := findKind(audit, provider.KindFloatingIP); fip == nil || !fip.Reclaimable {
		t.Fatalf("precondition: the address should be reclaimable, got %+v", fip)
	}
	// ...and now something attaches it, after the human read the report.
	f.rips[fipID].InstanceID = "a-relay-that-came-back"

	rep, err := p.ReclaimOrphans(ctx, nil, []provider.ResourceRef{{Kind: provider.KindFloatingIP, ID: fipID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, gone := f.rips[fipID]; !gone {
		t.Fatal("the address was deleted while something was answering on it")
	}
	if len(rep.Outcomes) == 0 || rep.Outcomes[0].Deleted {
		t.Fatalf("reclaim claims it deleted the address: %+v", rep.Outcomes)
	}
	if !strings.Contains(rep.Outcomes[0].Reason, "refused") {
		t.Errorf("the refusal does not name itself: %q", rep.Outcomes[0].Reason)
	}
}

// TestAudit_UnreadableInstanceListProvesNothing. "Nothing is behind
// this resource" is a claim about the whole instance list. Without the
// list there is no such claim, and a sweep becomes a rake.
func TestAudit_UnreadableInstanceListProvesNothing(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()
	if _, _, err := p.CreateFloatingIP(ctx, rec); err != nil {
		t.Fatal(err)
	}
	f.failOn = func(method, path string) (int, bool) {
		if method == http.MethodGet && strings.HasPrefix(path, "/instances") && !strings.Contains(path, "/instances/") {
			return http.StatusInternalServerError, true
		}
		return 0, false
	}

	audit, err := p.AuditAccount(ctx, nil)
	if err != nil {
		t.Fatalf("AuditAccount: %v", err)
	}
	if audit.ServerListComplete {
		t.Fatal("the audit claims a complete instance list it could not read")
	}
	for _, r := range audit.Resources {
		if r.Reclaimable {
			t.Errorf("%s %s is reclaimable without a complete instance list", r.Kind, r.ID)
		}
	}
	if len(audit.Warnings) == 0 {
		t.Error("no warning about the unreadable list")
	}
	if _, err := p.ReclaimOrphans(ctx, nil, nil); err == nil {
		t.Fatal("reclaim ran without being able to prove anything is an orphan")
	}
}

// TestAudit_IgnoresResourcesThatAreNotOurs. The operator's own reserved
// IP is their property, and this tool has no opinion about it.
func TestAudit_IgnoresResourcesThatAreNotOurs(t *testing.T) {
	f := newFakeVultr(t)
	p, _ := mustProvision(t, f, mkOpts())
	f.rips["mine"] = &wireReservedIP{ID: "mine", Region: testRegion, IPType: "v4", Subnet: "203.0.113.77", Label: "my own address"}
	f.sshKeys["mine"] = "my laptop"

	audit, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range audit.Resources {
		if r.ID == "mine" {
			t.Errorf("the audit has an opinion about a resource daal-deploy did not create: %+v", r)
		}
	}
}

// The managed-by mark alone must not be enough to claim a sibling
// relay's address.
func TestAudit_NeedsBothOwnershipFacts(t *testing.T) {
	f := newFakeVultr(t)
	p, _ := mustProvision(t, f, mkOpts())
	f.rips["half"] = &wireReservedIP{
		ID: "half", Region: testRegion, IPType: "v4", Subnet: "203.0.113.78",
		Label: markManagedByKey + "=" + markManagedByValue, // no relay half
	}
	audit, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range audit.Resources {
		if r.ID == "half" {
			t.Errorf("a half-marked address was claimed: %+v", r)
		}
	}
}

func findKind(a *provider.AccountAudit, kind string) *provider.AuditedResource {
	for i := range a.Resources {
		if a.Resources[i].Kind == kind {
			return &a.Resources[i]
		}
	}
	return nil
}

// A record that names an address but has lost its publisher key still
// CLAIMS that address. Testing the map's value instead of its presence
// would classify it as an orphan and release an address a live relay
// may still be answering on.
func TestAudit_ARecordWithoutAPublisherKeyStillClaimsItsAddress(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	ctx := context.Background()

	fipID, _, err := p.CreateFloatingIP(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.instances, rec.ServerID)

	truncated := &provider.OperatorRecord{FloatingIPID: fipID} // no pubkey, no region
	audit, err := p.AuditAccount(ctx, []*provider.OperatorRecord{truncated})
	if err != nil {
		t.Fatal(err)
	}
	fip := findKind(audit, provider.KindFloatingIP)
	if fip == nil {
		t.Fatal("the address is not in the report")
	}
	if fip.Reclaimable {
		t.Errorf("an address a record still names was offered for deletion: %+v", fip)
	}
}
