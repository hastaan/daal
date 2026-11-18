package hetzner

// WHAT THE SWEEP CAN AND CANNOT PROVE.
//
// Every test here is one sentence of that answer. The two halves are
// not equally important: a missed orphan costs the operator money,
// and a wrongly-reclaimed resource costs every recipient of that relay
// their connection. So the refusals get more tests than the deletions,
// on purpose.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

// --- fixtures -------------------------------------------------------

// pubKeyA / pubKeyB are two different publishers, i.e. two relays that
// can legitimately share one Hetzner account. Nearly every guard in
// the audit exists because of that case.
var (
	pubKeyA = []byte("AAAAAAAAAAAAAAAA")
	pubKeyB = []byte("BBBBBBBBBBBBBBBB")
)

func relayA() string { return derivedServerName(pubKeyA, "fsn1") }
func relayB() string { return derivedServerName(pubKeyB, "hel1") }

func recordFor(pub []byte, region, serverID string) *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        serverID,
		Region:          region,
		PublisherPubKey: pub,
		PublicIP:        net.ParseIP("5.75.0.1"),
	}
}

// seedServer plants a running relay carrying the ownership labels
// Provision stamps.
func (f *fakeClient) seedServer(id, name, region string, labels map[string]string) *ServerInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &ServerInfo{ID: id, Name: name, Status: "running", Region: region,
		ServerType: "cx22", PublicIP: net.ParseIP("5.75.0." + id), Labels: labels}
	f.servers[id] = s
	return s
}

func ownedLabels(relay string) map[string]string {
	return map[string]string{labelManagedBy: labelManagedByValue, labelRelay: relay}
}

// seedFIP plants a reserved address. serverID == "" is unattached.
func (f *fakeClient) seedFIP(id, addr, home, serverID string, labels map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fips[id] = &FloatingIPInfo{
		ID: id, IP: net.ParseIP(addr), HomeLocation: home,
		ServerID: serverID, Name: "daal-fip-" + id, Labels: labels,
	}
}

// seedFirewall plants a per-server firewall with an explicit
// applied-to set. Empty appliedTo is a firewall protecting nothing.
func (f *fakeClient) seedFirewall(serverID string, appliedTo []string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "fw-" + serverID
	f.ensuredFirewalls[serverID] = id
	f.fwAppliedTo[id] = appliedTo
	return id
}

func find(t *testing.T, a *provider.AccountAudit, kind, id string) provider.AuditedResource {
	t.Helper()
	for _, r := range a.Resources {
		if r.Kind == kind && r.ID == id {
			return r
		}
	}
	t.Fatalf("audit does not mention %s:%s — a billing resource that is not reported is worse than no audit at all.\ngot: %+v", kind, id, a.Resources)
	return provider.AuditedResource{}
}

func absent(t *testing.T, a *provider.AccountAudit, kind, id string) {
	t.Helper()
	for _, r := range a.Resources {
		if r.Kind == kind && r.ID == id {
			t.Fatalf("audit reported %s:%s, which is not ours to have an opinion about: %+v", kind, id, r)
		}
	}
}

func outcomeFor(t *testing.T, rep *provider.ReclaimReport, kind, id string) provider.ReclaimOutcome {
	t.Helper()
	for _, o := range rep.Outcomes {
		if o.Kind == kind && o.ID == id {
			return o
		}
	}
	t.Fatalf("reclaim said nothing about %s:%s; a resource an operator asked about must never be silently skipped.\ngot: %+v", kind, id, rep.Outcomes)
	return provider.ReclaimOutcome{}
}

// --- the orphan the operator actually has ---------------------------

// Wave 5 left a floating IP stranded by a failed release: reserved,
// labelled ours, attached to nothing, and belonging to a relay that no
// longer exists. Nothing in the tool could see it, because every
// floating-IP call started from an id somebody still knew.
func TestAudit_StrandedAddressIsProvenOrphanedAndReclaimed(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayA()))
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFloatingIP, "77")
	if got.Verdict != provider.VerdictOrphan || !got.Reclaimable {
		t.Fatalf("stranded address = %+v, want a reclaimable orphan", got)
	}
	if !got.Billing {
		t.Error("a reserved address bills every hour; the report must say so")
	}
	if !strings.Contains(got.Reason, relayA()) {
		t.Errorf("reason does not name the relay it was reserved for: %q", got.Reason)
	}

	rep, err := p.ReclaimOrphans(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := outcomeFor(t, rep, provider.KindFloatingIP, "77"); !o.Deleted {
		t.Fatalf("reclaim did not release it: %+v", o)
	}
	if _, err := f.FloatingIPByID(context.Background(), "77"); !errors.Is(err, errFloatingIPNotFound) {
		t.Error("the address is still reserved after a reclaim that reported success")
	}
}

// The key that has already cost this operator a retry: an orphan
// blocks the next provision for the same publisher+region with a
// uniqueness_error, and it is removable only through the provider API.
func TestAudit_OrphanedOneShotKeyIsTheThingThatBlocksTheNextProvision(t *testing.T) {
	f := newFake()
	id := f.seedSSHKey(relayA()+"-ephemeral-deadbeef", ownedLabels(relayA()))
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindSSHKey, id)
	if got.Verdict != provider.VerdictOrphan || !got.Reclaimable {
		t.Fatalf("orphan key = %+v, want a reclaimable orphan", got)
	}
	if !strings.Contains(got.Reason, "uniqueness_error") {
		t.Errorf("reason does not say what it actually costs: %q", got.Reason)
	}

	rep, err := p.ReclaimOrphans(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := outcomeFor(t, rep, provider.KindSSHKey, id); !o.Deleted {
		t.Fatalf("reclaim left the blocking key in place: %+v", o)
	}
}

// A firewall from a relay deleted long ago: named for a server id that
// no longer resolves, protecting nothing.
func TestAudit_FirewallForADeletedServerIsOrphaned(t *testing.T) {
	f := newFake()
	fwID := f.seedFirewall("9001", nil)
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFirewall, fwID)
	if got.Verdict != provider.VerdictOrphan || !got.Reclaimable {
		t.Fatalf("orphan firewall = %+v, want a reclaimable orphan", got)
	}
	rep, err := p.ReclaimOrphans(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := outcomeFor(t, rep, provider.KindFirewall, fwID); !o.Deleted {
		t.Fatalf("reclaim left it: %+v", o)
	}
}

// --- the refusals ---------------------------------------------------

// GUARD 1, in audit form. An attached address is being served on right
// now. This is the case ReleaseFloatingIP's guard was added for, and
// the audit must not be the path that reopens it — note the record set
// is EMPTY here, so nothing but the attachment itself protects it.
func TestAudit_AnAttachedAddressIsNeverAnOrphan(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedFIP("77", "203.0.113.7", "fsn1", "1", ownedLabels(relayA()))
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFloatingIP, "77")
	if got.Verdict != provider.VerdictInUse || got.Reclaimable {
		t.Fatalf("attached address = %+v, want in-use and untouchable", got)
	}
}

// GUARD 2. managed-by alone is exactly what a SIBLING relay's address
// also carries. On a two-relay account that is the case in which
// deleting it is wrong, so a half-marked address is unproven — named,
// never binned.
func TestAudit_AddressWithoutTheRelayLabelIsUnprovenNotOrphaned(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", map[string]string{labelManagedBy: labelManagedByValue})
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFloatingIP, "77")
	if got.Verdict != provider.VerdictUnproven || got.Reclaimable {
		t.Fatalf("half-marked address = %+v, want unproven and untouchable", got)
	}
	if got.Hint == "" {
		t.Error("an unproven resource must say where to look; this one does not")
	}
}

// The two-relay account, end to end. The operator audits with relay
// A's record in hand. Relay B is a different publisher's live relay in
// the same account: its server, its address and its key must all come
// back untouchable, and the sweep must not offer to reclaim any of
// them.
func TestAudit_ASiblingRelaysResourcesAreNeverReclaimable(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedServer("2", relayB(), "hel1", ownedLabels(relayB()))
	f.seedFIP("77", "203.0.113.7", "hel1", "", ownedLabels(relayB())) // B's spare address
	bKey := f.seedSSHKey(relayB()+"-ephemeral-cafebabe", ownedLabels(relayB()))
	f.seedFirewall("2", []string{"2"})
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{recordFor(pubKeyA, "fsn1", "1")})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range a.Resources {
		if r.Relay == relayB() && r.Reclaimable {
			t.Errorf("offered to reclaim the sibling relay's %s: %+v", r.Kind, r)
		}
	}
	if got := find(t, a, provider.KindFloatingIP, "77"); got.Verdict != provider.VerdictInUse {
		t.Errorf("sibling's spare address = %+v, want in-use (its relay is running and may be mid-rotation)", got)
	}
	if got := find(t, a, provider.KindSSHKey, bKey); got.Verdict != provider.VerdictInUse {
		t.Errorf("sibling's provisioning key = %+v, want in-use", got)
	}
	if got := find(t, a, provider.KindServer, "2"); got.Reclaimable {
		t.Errorf("sibling's server is reclaimable: %+v", got)
	}
	// And a reclaim run with A's record must delete nothing at all.
	rep, err := p.ReclaimOrphans(context.Background(), []*provider.OperatorRecord{recordFor(pubKeyA, "fsn1", "1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Deleted() != 0 {
		t.Fatalf("a sweep run beside a healthy sibling relay deleted %d resources: %+v", rep.Deleted(), rep.Outcomes)
	}
}

// The liveness proof sweepEphemeralKeys already enforces, applied
// account-wide: a running relay's provisioning key is not ours to
// remove even though nothing on disk names it.
func TestAudit_ALiveRelaysKeyIsLeftAlone(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	id := f.seedSSHKey(relayA()+"-ephemeral-deadbeef", ownedLabels(relayA()))
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindSSHKey, id)
	if got.Verdict != provider.VerdictInUse || got.Reclaimable {
		t.Fatalf("live relay's key = %+v, want in-use and untouchable", got)
	}
}

// A firewall detached from a server that still EXISTS is not spare
// clutter — it is a live relay with an exposed mgmt port. Deleting it
// would make that worse and permanent.
func TestAudit_FirewallDetachedFromALiveServerIsNotAnOrphan(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	fwID := f.seedFirewall("1", nil)
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFirewall, fwID)
	if got.Verdict != provider.VerdictInUse || got.Reclaimable {
		t.Fatalf("detached firewall for a live server = %+v, want in-use", got)
	}
}

// A label-selector firewall protects whatever matches at any moment,
// including servers that do not exist yet, so "attached to nothing" is
// not a fact that can be read off it.
func TestAudit_LabelSelectorFirewallIsUnprovenNotOrphaned(t *testing.T) {
	f := newFake()
	fwID := f.seedFirewall("9001", nil)
	f.fwLabelSelectors = map[string][]string{fwID: {"managed-by=daal-deploy"}}
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFirewall, fwID)
	if got.Verdict != provider.VerdictUnproven || got.Reclaimable {
		t.Fatalf("label-selector firewall = %+v, want unproven and untouchable", got)
	}
}

// Addresses with no ownership mark at all are the operator's own
// property. The audit has no opinion about them and must not list
// them: a report padded with things it cannot act on is a report
// people stop reading.
func TestAudit_UnmarkedAddressesAreNotListedAtAll(t *testing.T) {
	f := newFake()
	f.seedFIP("500", "198.51.100.9", "fsn1", "", nil)
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	absent(t, a, provider.KindFloatingIP, "500")
}

// --- the rule that keeps continuity ---------------------------------

// Decommission deliberately leaves an address reserved so the next
// relay can stand up on it without stranding a single distributed
// pack. A record that still names one is the operator saying "I am
// keeping this", and a sweep that bins it has spent something no rerun
// gets back. Report it, price it, explain it — never reclaim it.
func TestAudit_AnAddressARecordStillNamesIsKeptNotReclaimed(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayA()))
	rec := recordFor(pubKeyA, "fsn1", "") // server long gone
	rec.FloatingIPID = "77"
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFloatingIP, "77")
	if got.Reclaimable {
		t.Fatalf("offered to reclaim an address the operator's own record still names: %+v", got)
	}
	if got.Verdict != provider.VerdictUnclaimed {
		t.Errorf("verdict = %q, want unclaimed (it bills, and the operator must decide)", got.Verdict)
	}
	if !strings.Contains(got.Hint, "floating-ip release") {
		t.Errorf("hint does not name the deliberate way to give it back: %q", got.Hint)
	}
	rep, err := p.ReclaimOrphans(context.Background(), []*provider.OperatorRecord{rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Deleted() != 0 {
		t.Fatalf("reclaim deleted %d resources: %+v", rep.Deleted(), rep.Outcomes)
	}
}

// --- servers: reported, never deleted -------------------------------

// The worst outcome this wave can produce: a destructive rung builds
// the new box, fails before the record is written, and the operator is
// paying for two servers with one relay's worth of use. The audit must
// name it. It must also refuse to pick which one dies — no label can
// distinguish the abandoned box from the one every pack in the field
// dials.
func TestAudit_TwoPaidServersForOneRelayAreNamedButNeverDeleted(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	rec := recordFor(pubKeyA, "fsn1", "999") // the record names the OTHER box
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindServer, "1")
	if got.Verdict != provider.VerdictUnclaimed {
		t.Fatalf("server = %+v, want unclaimed", got)
	}
	if got.Reclaimable {
		t.Fatal("the audit offered to delete a server; it must never do that")
	}
	if !got.Billing {
		t.Error("a running server bills; the report must say so")
	}
	var k provider.KnownRelay
	for _, kr := range a.Known {
		if kr.Relay == relayA() {
			k = kr
		}
	}
	if k.Note == "" || !strings.Contains(k.Note, "999") {
		t.Errorf("the record/reality disagreement is not spelled out: %+v", k)
	}

	// Even when asked for by name, explicitly.
	rep, err := p.ReclaimOrphans(context.Background(), []*provider.OperatorRecord{rec},
		[]provider.ResourceRef{{Kind: provider.KindServer, ID: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	o := outcomeFor(t, rep, provider.KindServer, "1")
	if o.Deleted {
		t.Fatal("reclaim deleted a server")
	}
	if !strings.Contains(o.Reason, "refused") {
		t.Errorf("the refusal does not read as one: %q", o.Reason)
	}
}

// A record whose provision died before ServerCreate returned leaves no
// server id at all. The join has to notice the live box anyway — that
// is the single most common way an orphan is born.
func TestAudit_ARecordWithNoServerIDStillFindsItsLiveBox(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{recordFor(pubKeyA, "fsn1", "")})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Known) != 1 || a.Known[0].LiveServerID != "1" {
		t.Fatalf("join did not find the live box: %+v", a.Known)
	}
	if !strings.Contains(a.Known[0].Note, "never completed") {
		t.Errorf("note does not explain the state: %q", a.Known[0].Note)
	}
}

// A server named like ours but carrying no managed-by label is
// reported and never claimed: `--existing-server-id` adopts boxes
// daal-deploy did not create, and any tool may pick any name.
func TestAudit_AServerNamedLikeOursButUnlabelledIsUnproven(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", nil)
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindServer, "1")
	if got.Verdict != provider.VerdictUnproven || got.Reclaimable {
		t.Fatalf("unlabelled look-alike = %+v, want unproven and untouchable", got)
	}
}

// --- the property that gates every orphan finding -------------------

// Orphanhood is a claim about the WHOLE server list: "no live server
// stands behind this". If the list cannot be read, that claim cannot
// be made about anything. Treating an unreadable list as an empty one
// turns one API hiccup into a sweep that deletes the account.
func TestAudit_AnUnreadableServerListProvesNothingAndReclaimRefuses(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayA()))
	f.seedSSHKey(relayA()+"-ephemeral-deadbeef", ownedLabels(relayA()))
	f.seedFirewall("9001", nil)
	f.failServerList = errors.New("503 service unavailable")
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.ServerListComplete {
		t.Fatal("audit claims a complete server list it never read")
	}
	for _, r := range a.Resources {
		if r.Verdict == provider.VerdictOrphan || r.Reclaimable {
			t.Errorf("proved an orphan without the server list: %+v", r)
		}
		if r.Verdict != provider.VerdictUnproven {
			t.Errorf("%s:%s = %q, want unproven", r.Kind, r.ID, r.Verdict)
		}
	}
	if len(a.Warnings) == 0 {
		t.Error("a failed list must be said out loud, not inferred from an empty report")
	}

	if _, err := p.ReclaimOrphans(context.Background(), nil, nil); err == nil {
		t.Fatal("reclaim ran against an account it could not enumerate")
	}
}

// A list call that fails does not silently shrink the report. The
// operator is told which console page to open instead.
func TestAudit_AFailedFloatingIPListIsAWarningNotSilence(t *testing.T) {
	f := newFake()
	f.failFloatingIPList = errors.New("429 too many requests")
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(a.Warnings, "\n")
	if !strings.Contains(joined, "Floating IPs") {
		t.Errorf("warning does not point at the console page to check: %q", joined)
	}
}

// --- reclaim re-verifies -------------------------------------------

// Between an operator reading a report and confirming it, an address
// can be attached. The audit the human approved describes the past;
// deleting against it is how a sweep eats a live relay.
func TestReclaim_ReVerifiesAgainstTheAccountNotTheReport(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayA()))
	p := New(f)

	a, err := p.AuditAccount(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, a, provider.KindFloatingIP, "77"); !got.Reclaimable {
		t.Fatalf("precondition: the address should start out reclaimable, got %+v", got)
	}

	// The world moves: a new relay is stood up on that address.
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedFIP("77", "203.0.113.7", "fsn1", "1", ownedLabels(relayA()))

	rep, err := p.ReclaimOrphans(context.Background(), nil, a.Reclaimable())
	if err != nil {
		t.Fatal(err)
	}
	o := outcomeFor(t, rep, provider.KindFloatingIP, "77")
	if o.Deleted {
		t.Fatal("reclaim released an address a live relay is answering on")
	}
	if !strings.Contains(o.Reason, "refused") {
		t.Errorf("refusal reason does not name the guard: %q", o.Reason)
	}
	if _, err := f.FloatingIPByID(context.Background(), "77"); err != nil {
		t.Fatalf("the address is gone: %v", err)
	}
}

// A ref the operator asked for that the audit never saw is reported as
// a refusal with a reason. Silence there reads as "done", and the
// operator stops looking for a resource that is still billing.
func TestReclaim_ARefTheAuditNeverSawIsRefusedOutLoud(t *testing.T) {
	f := newFake()
	p := New(f)
	rep, err := p.ReclaimOrphans(context.Background(), nil,
		[]provider.ResourceRef{{Kind: provider.KindFloatingIP, ID: "does-not-exist"}})
	if err != nil {
		t.Fatal(err)
	}
	o := outcomeFor(t, rep, provider.KindFloatingIP, "does-not-exist")
	if o.Deleted || !strings.Contains(o.Reason, "refused") {
		t.Fatalf("outcome = %+v, want an explicit refusal", o)
	}
}

// An --only filter must not widen into "everything". Asking for one
// orphan reclaims exactly that one.
func TestReclaim_OnlyFilterIsExact(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayA()))
	keyID := f.seedSSHKey(relayA()+"-ephemeral-deadbeef", ownedLabels(relayA()))
	p := New(f)

	rep, err := p.ReclaimOrphans(context.Background(), nil,
		[]provider.ResourceRef{{Kind: provider.KindFloatingIP, ID: "77"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Deleted() != 1 {
		t.Fatalf("deleted %d, want exactly the one that was asked for: %+v", rep.Deleted(), rep.Outcomes)
	}
	keys, _ := f.SSHKeyList(context.Background())
	for _, k := range keys {
		if k.ID == keyID {
			return
		}
	}
	t.Fatal("the SSH key was removed by a run that only asked about an address")
}

// Reclaim runs twice: the second is a clean success, not an error. A
// retried cleanup must not look like a new failure.
func TestReclaim_IsIdempotent(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayA()))
	p := New(f)

	if _, err := p.ReclaimOrphans(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := p.ReclaimOrphans(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("second run errored: %v", err)
	}
	if rep.Deleted() != 0 {
		t.Errorf("second run claims to have deleted %d resources", rep.Deleted())
	}
}

// --- reporting shape ------------------------------------------------

// Every resource carries a reason, including the ones left alone. A
// report that explains only its refusals teaches the operator nothing
// about why it believes the rest is safe.
func TestAudit_EveryResourceCarriesAReason(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedFIP("77", "203.0.113.7", "fsn1", "1", ownedLabels(relayA()))
	f.seedFIP("78", "203.0.113.8", "hel1", "", ownedLabels(relayB()))
	f.seedSSHKey(relayA()+"-ephemeral-deadbeef", ownedLabels(relayA()))
	f.seedFirewall("1", []string{"1"})
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{recordFor(pubKeyA, "fsn1", "1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Resources) == 0 {
		t.Fatal("nothing reported")
	}
	for _, r := range a.Resources {
		if r.Reason == "" {
			t.Errorf("%s:%s carries no reason", r.Kind, r.ID)
		}
		if r.Verdict == "" {
			t.Errorf("%s:%s carries no verdict", r.Kind, r.ID)
		}
	}
	if !a.NeedsAttention() {
		t.Error("an account with an orphaned address needs attention")
	}
}

// A healthy account produces a report that says so, so an operator can
// tell "nothing to do" from "the audit did not look".
func TestAudit_AHealthyAccountNeedsNoAttention(t *testing.T) {
	f := newFake()
	f.seedServer("1", relayA(), "fsn1", ownedLabels(relayA()))
	f.seedFIP("77", "203.0.113.7", "fsn1", "1", ownedLabels(relayA()))
	f.seedFirewall("1", []string{"1"})
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{recordFor(pubKeyA, "fsn1", "1")})
	if err != nil {
		t.Fatal(err)
	}
	if !a.ServerListComplete {
		t.Fatal("server list not read")
	}
	if a.NeedsAttention() {
		t.Fatalf("healthy account flagged: %+v / %v", a.Resources, a.Warnings)
	}
}

// The adapter satisfies the optional contract. Compile-time, because
// the CLI type-asserts and a silent failure there renders as "this
// provider cannot audit" against the one provider that can.
var _ provider.AccountAuditor = (*Provider)(nil)

// The relay-name parse is what lets the audit work with no record at
// all. Both key shapes ownsEphemeralKey accepts must round-trip, and
// nothing else may.
func TestRelayFromEphemeralKeyName(t *testing.T) {
	relay := relayA()
	for _, tc := range []struct {
		name string
		want string
		ok   bool
	}{
		{relay + "-ephemeral", relay, true},
		{relay + "-ephemeral-deadbeef", relay, true},
		{"my-laptop", "", false},
		{"-ephemeral", "", false},
		{relay + "-ephemeralish", "", false},
		{"backup-ephemeral", "", false}, // not a daal- name
	} {
		got, ok := relayFromEphemeralKeyName(tc.name)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%q -> (%q,%v), want (%q,%v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// --- the pointer that makes any of this reachable -------------------

// THE DISCOVERABILITY GAP, CLOSED WHERE IT OPENS.
//
// Every message the adapter emits about a surviving billing resource
// is emitted at the exact moment an OperatorRecord is about to be
// lost. After that moment no record-driven surface can find the
// resource: `decommission` needs a record and the record is what just
// went missing. The account audit needs none, so it is the only route
// left — and a route the operator is never told about is a route
// nobody takes.
func TestProvisionOrphan_TellsTheOperatorHowToFindWhatSurvived(t *testing.T) {
	f := newFake()
	p := New(f)
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("hetzner: health check timed out")
	})
	var messages []string
	opts := liveOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = false // the box survives
	opts.OnProgress = func(_, msg string) { messages = append(messages, msg) }

	if _, err := p.Provision(context.Background(), opts); err == nil {
		t.Fatal("expected the health failure to surface")
	}
	if !anyContains(messages, "account-audit") {
		t.Fatalf("a provision that left a billing server never named the one verb that can still find it "+
			"without a record:\n%v", messages)
	}
}

// The worst case: rollback itself failed. A box is billing, the record
// is about to be discarded, and a one-shot SSH key will refuse the
// next attempt. This is the message that has to carry the way out.
func TestFailedRollback_NamesTheAudit(t *testing.T) {
	f := newFake()
	f.failServerDelete = errors.New("423 locked")
	p := New(f)
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, *ServerInfo, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("hetzner: health check timed out")
	})
	var messages []string
	opts := liveOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true
	opts.OnProgress = func(_, msg string) { messages = append(messages, msg) }

	if _, err := p.Provision(context.Background(), opts); err == nil {
		t.Fatal("expected the failure to surface")
	}
	if len(f.servers) == 0 {
		t.Fatal("precondition: the server should have survived the failed rollback")
	}
	if !anyContains(messages, "account-audit") {
		t.Fatalf("a FAILED rollback — a billing box plus a key that blocks the retry — did not name the audit:\n%v", messages)
	}
}

// A teardown that could not prove what it left behind says where to
// look. The SSH key is the one that costs a retry rather than money,
// and it is invisible in every other surface.
func TestDecommission_UnprovableKeySweepNamesTheAudit(t *testing.T) {
	f := newFake()
	f.failSSHKeyList = errors.New("503 service unavailable")
	p := New(f)
	rec := recordFor(pubKeyA, "fsn1", "")
	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Warnings, "\n")
	if !strings.Contains(joined, "account-audit") {
		t.Fatalf("teardown could not prove the one-shot key was gone and did not say where to look:\n%s", joined)
	}
}

// A record and an ownership label that disagree about whose address
// this is: two relays, two answers, no way to tell which is stale.
// That is precisely what the per-relay label exists to prevent, so the
// audit refuses to pick rather than guessing.
func TestAudit_ARecordAndALabelThatDisagreeAreUnproven(t *testing.T) {
	f := newFake()
	f.seedFIP("77", "203.0.113.7", "fsn1", "", ownedLabels(relayB())) // labelled for B
	rec := recordFor(pubKeyA, "fsn1", "")                             // A's record claims it
	rec.FloatingIPID = "77"
	p := New(f)

	a, err := p.AuditAccount(context.Background(), []*provider.OperatorRecord{rec})
	if err != nil {
		t.Fatal(err)
	}
	got := find(t, a, provider.KindFloatingIP, "77")
	if got.Verdict != provider.VerdictUnproven || got.Reclaimable {
		t.Fatalf("contradictory address = %+v, want unproven and untouchable", got)
	}
	if !strings.Contains(got.Reason, relayA()) || !strings.Contains(got.Reason, relayB()) {
		t.Errorf("the reason does not name both sides of the disagreement: %q", got.Reason)
	}
}
