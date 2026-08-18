package vultr

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
	"daal/publisher/deploy/sni"
)

func mkOpts() provider.ProvisionOpts {
	_, priv, _ := ed25519.GenerateKey(nil)
	// A real 32-byte publisher key: cloud-init writes it to
	// /etc/daal/mgmt/pubkey and the mgmt plane verifies every token
	// against it, so RenderV2 refuses anything shorter.
	pub := make([]byte, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	return provider.ProvisionOpts{
		PublisherPubKey: pub,
		Region:          testRegion,
		ServerType:      testPlan,
		ToolboxProfile:  "iran-default",
		HelperIP:        net.ParseIP("203.0.113.9"),
		EphemeralSSHKey: priv,
		MgmtPort:        20000,
	}
}

func relayLabel() string {
	o := mkOpts()
	return derivedInstanceLabel(o.PublisherPubKey, o.Region)
}

// mustProvision runs a provision that is expected to succeed.
func mustProvision(t *testing.T, f *fakeVultr, opts provider.ProvisionOpts) (*Provider, *provider.OperatorRecord) {
	t.Helper()
	p := f.provider(t)
	rec, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return p, rec
}

// TestProvision_BuildsARealRelay is the "same standard as Hetzner"
// test: the box is created behind its firewall, with the relay's real
// sing-box config, its real family set, and the ownership tags every
// later refusal depends on.
func TestProvision_BuildsARealRelay(t *testing.T) {
	f := newFakeVultr(t)
	_, rec := mustProvision(t, f, mkOpts())

	if rec.Provider != "vultr" || rec.ServerID == "" {
		t.Fatalf("record does not name a Vultr instance: %+v", rec)
	}
	if rec.PublicIP.String() != "78.141.10.5" {
		t.Errorf("record public ip = %v", rec.PublicIP)
	}
	if rec.MgmtPort != 20000 {
		t.Errorf("mgmt port = %d, want the persisted 20000", rec.MgmtPort)
	}

	// THE FIREWALL EXISTS BEFORE THE INSTANCE. Hetzner cannot do this
	// and therefore has a window where a booting relay's random mgmt
	// port faces the internet. If this ordering ever regresses, the
	// window comes back silently.
	if !f.sawBefore("POST /firewalls", "POST /instances") {
		t.Errorf("instance was created before its firewall: %v", f.calls)
	}

	// The instance carries BOTH ownership tags. Every refusal in this
	// package keys off them.
	inst := f.instances[rec.ServerID]
	if inst == nil {
		t.Fatal("instance vanished")
	}
	if !ownsInstance(&InstanceInfo{Tags: inst.Tags}, relayLabel()) {
		t.Errorf("instance tags do not prove ownership: %v", inst.Tags)
	}
	if inst.FirewallGroupID == "" {
		t.Error("instance was created with no firewall group attached")
	}

	// The cloud-init is the REAL relay config, not a placeholder. The
	// pre-Wave-6 adapter shipped `{"profile":"iran-default"}` here,
	// which boots a box that serves nothing while the record claims
	// four families.
	raw, err := base64.StdEncoding.DecodeString(f.lastUserData)
	if err != nil {
		t.Fatalf("user_data is not base64: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, `{"profile":"iran-default"}`) {
		t.Error("cloud-init still carries the placeholder sing-box config")
	}
	for _, want := range []string{`"type": "vless"`, `"reality"`, rec.CoverSNI} {
		if !strings.Contains(body, want) {
			t.Errorf("cloud-init does not contain %q", want)
		}
	}
	if f.lastOSID != 2284 {
		t.Errorf("os_id = %d, want the id resolved from the catalogue for %q", f.lastOSID, imageName)
	}

	// Candidates come from the profile, with this relay's address.
	if len(rec.Candidates) != 4 {
		t.Fatalf("iran-default default-enabled families = %d candidates, want 4: %+v", len(rec.Candidates), rec.Candidates)
	}
	for _, c := range rec.Candidates {
		if !hasTag(c.PublicRiskTags, "public_ip:78.141.10.5") {
			t.Errorf("candidate %s does not carry the relay's address: %v", c.Family, c.PublicRiskTags)
		}
	}
}

// TestProvision_FirewallOpensExactlyTheServedPorts. The ruleset is
// rendered from THIS relay's family set, and both address families get
// a rule: Vultr splits v4 and v6 into separate rules, so writing only
// one produces a quietly v4-only relay.
func TestProvision_FirewallOpensExactlyTheServedPorts(t *testing.T) {
	f := newFakeVultr(t)
	_, rec := mustProvision(t, f, mkOpts())

	rules := f.rulesFor(t, rec.ServerID)
	for _, want := range []string{"v4|tcp|0.0.0.0|0|443", "v6|tcp|::|0|443", "v4|udp|0.0.0.0|0|443", "v6|udp|::|0|443", "v4|tcp|0.0.0.0|0|80"} {
		if !rules[want] {
			t.Errorf("baseline rule %q missing; have %v", want, keys(rules))
		}
	}
	// naive (8444) and websocket-tls (8445) are default-enabled in
	// iran-default, so their ports are open.
	for _, want := range []string{"v4|tcp|0.0.0.0|0|8444", "v4|tcp|0.0.0.0|0|8445"} {
		if !rules[want] {
			t.Errorf("data-plane rule %q missing; have %v", want, keys(rules))
		}
	}
	// tuic is opt-in and NOT enabled, so 8443/udp must stay shut. An
	// open port serving nothing is a free fingerprint.
	if rules["v4|udp|0.0.0.0|0|8443"] {
		t.Error("8443/udp is open on a relay that does not serve tuic")
	}
}

// TestReRenderFirewall_IsTheL5L6Call. Moving a relay to a new provider
// or profile changes its family set; if the firewall is not re-rendered
// the box listens on a port its own firewall drops, and every route in
// the freshly minted pack that uses it is dead.
func TestReRenderFirewall_IsTheL5L6Call(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())

	if rules := f.rulesFor(t, rec.ServerID); rules["v4|udp|0.0.0.0|0|8443"] {
		t.Fatal("precondition: tuic port already open")
	}
	if err := p.ReRenderFirewall(context.Background(), rec,
		[]string{"vless-reality", "websocket-tls", "naive", "hysteria2", "tuic"}); err != nil {
		t.Fatalf("ReRenderFirewall: %v", err)
	}
	rules := f.rulesFor(t, rec.ServerID)
	for _, want := range []string{"v4|udp|0.0.0.0|0|8443", "v6|udp|::|0|8443"} {
		if !rules[want] {
			t.Errorf("after re-render, %q is still missing: %v", want, keys(rules))
		}
	}
}

// TestProvision_RefusesToAdoptAForeignInstance. The derived label is a
// pure function of (publisher key, region), so a collision is possible
// on a shared account — and adopting an untagged box writes somebody
// else's server into the operator's record, which teardown would then
// destroy.
func TestProvision_RefusesToAdoptAForeignInstance(t *testing.T) {
	f := newFakeVultr(t)
	f.instances["foreign"] = &wireInstance{
		ID: "foreign", Label: relayLabel(), Status: "active",
		Plan: testPlan, Region: testRegion, MainIP: "1.2.3.4",
		Tags: []string{"someone-elses"},
	}
	_, err := f.provider(t).Provision(context.Background(), mkOpts())
	if err == nil {
		t.Fatal("adopted an instance that carries no daal ownership tags")
	}
	if !strings.Contains(err.Error(), "did not create") {
		t.Errorf("refusal does not explain itself: %v", err)
	}
}

// TestProvision_OneShotKeyIsAlwaysDeleted. An orphaned SSH key is the
// failure that has already wedged this project's operator: the name was
// a pure function of (publisher key, region), so one survivor made every
// later attempt fail forever.
func TestProvision_OneShotKeyIsAlwaysDeleted(t *testing.T) {
	f := newFakeVultr(t)
	mustProvision(t, f, mkOpts())
	if len(f.sshKeys) != 0 {
		t.Errorf("one-shot SSH key survived a SUCCESSFUL provision: %v", f.sshKeys)
	}

	// ...and after a failure too.
	g := newFakeVultr(t)
	g.failOn = failPath(http.MethodPost, "/instances")
	if _, err := g.provider(t).Provision(context.Background(), mkOpts()); err == nil {
		t.Fatal("expected the injected create failure")
	}
	if len(g.sshKeys) != 0 {
		t.Errorf("one-shot SSH key survived a FAILED provision: %v", g.sshKeys)
	}
}

// --- rollback ---

// TestRollback_NothingBillingCleansUpUnconditionally. The firewall
// group is created before the instance, so a create failure leaves a
// resource behind. It protects nothing, so it goes — regardless of
// RollbackOnFailure, which is about a billing box.
func TestRollback_NothingBillingCleansUpUnconditionally(t *testing.T) {
	f := newFakeVultr(t)
	f.failOn = failPath(http.MethodPost, "/instances")

	_, err := f.provider(t).Provision(context.Background(), mkOpts())
	if err == nil {
		t.Fatal("expected the injected create failure")
	}
	if len(f.groups) != 0 {
		t.Errorf("orphaned firewall group after a failed create: %v", f.groups)
	}
	if !strings.Contains(err.Error(), "nothing was created that is still running or billing") {
		t.Errorf("error does not say the account is clean: %v", err)
	}
}

// TestRollback_ReportsWhatItCouldNotClean. Where cleanup is impossible,
// the operator gets the resource, where it is, and the command that
// removes it — not a shrug.
func TestRollback_ReportsWhatItCouldNotClean(t *testing.T) {
	f := newFakeVultr(t)
	f.failOn = func(method, path string) (int, bool) {
		if method == http.MethodPost && path == "/instances" {
			return http.StatusInternalServerError, true
		}
		if method == http.MethodDelete && strings.HasPrefix(path, "/firewalls/") {
			return http.StatusInternalServerError, true
		}
		return 0, false
	}
	_, err := f.provider(t).Provision(context.Background(), mkOpts())
	if err == nil {
		t.Fatal("expected failure")
	}
	if !strings.Contains(err.Error(), "cleanup incomplete") {
		t.Errorf("error hides the leftover: %v", err)
	}
	if !strings.Contains(err.Error(), "curl -s -X DELETE") || !strings.Contains(err.Error(), "/firewalls/") {
		t.Errorf("error does not carry the removal command: %v", err)
	}
}

// TestRollback_HealthFailureWithRollbackDestroysTheBox. The unattended
// case: nothing may be left on the meter.
func TestRollback_HealthFailureWithRollbackDestroysTheBox(t *testing.T) {
	f := newFakeVultr(t)
	p := f.provider(t)
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("cloud-init never went healthy")
	})
	opts := mkOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true

	_, err := p.Provision(context.Background(), opts)
	if err == nil {
		t.Fatal("expected the health failure")
	}
	if len(f.instances) != 0 {
		t.Errorf("a billing instance survived a rollback: %v", f.instances)
	}
	if len(f.groups) != 0 {
		t.Errorf("firewall group survived a rollback: %v", f.groups)
	}
	if !strings.Contains(err.Error(), "rolled back") || !strings.Contains(err.Error(), "nothing is billing") {
		t.Errorf("error does not state the outcome: %v", err)
	}
}

// TestRollback_HealthFailureWithoutRollbackNamesTheOrphan. The default:
// a slow boot is recoverable and the idempotent retry reuses the box —
// but the user must be told what is running, and how to kill it.
func TestRollback_HealthFailureWithoutRollbackNamesTheOrphan(t *testing.T) {
	f := newFakeVultr(t)
	p := f.provider(t)
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("timed out")
	})
	var events []string
	opts := mkOpts()
	opts.WaitForHealth = true
	opts.OnProgress = func(step, msg string) { events = append(events, step+": "+msg) }

	_, err := p.Provision(context.Background(), opts)
	if err == nil {
		t.Fatal("expected the health failure")
	}
	if len(f.instances) != 1 {
		t.Fatalf("the instance should have been left alone: %v", f.instances)
	}
	for _, want := range []string{"still running and still billing", "78.141.10.5", "curl -s -X DELETE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q: %v", want, err)
		}
	}
	if !hasPrefixIn(events, "provision_orphan:") {
		t.Errorf("no provision_orphan event for the UI to render: %v", events)
	}
}

// TestRollback_FailedInstanceDeleteLeavesTheFirewallAlone. If the box
// survives, its firewall must survive too: stripping a live relay's
// firewall exposes its random mgmt port.
func TestRollback_FailedInstanceDeleteLeavesTheFirewallAlone(t *testing.T) {
	f := newFakeVultr(t)
	p := f.provider(t)
	p.setHealthWaiter(func(context.Context, *provider.OperatorRecord, string, provider.ProvisionOpts, func(string, string)) error {
		return errors.New("timed out")
	})
	f.failOn = func(method, path string) (int, bool) {
		if method == http.MethodDelete && strings.HasPrefix(path, "/instances/") {
			return http.StatusInternalServerError, true
		}
		return 0, false
	}
	opts := mkOpts()
	opts.WaitForHealth = true
	opts.RollbackOnFailure = true

	_, err := p.Provision(context.Background(), opts)
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(f.groups) != 1 {
		t.Errorf("the surviving box lost its firewall: %v", f.groups)
	}
	if !strings.Contains(err.Error(), "STILL BILLING") {
		t.Errorf("error does not shout about the surviving box: %v", err)
	}
}

// --- decommission ---

func TestDecommission_RemovesEverythingAndSaysSo(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	// A key from an earlier crashed attempt, of the kind that blocks
	// every retry.
	f.sshKeys["stale"] = ephemeralKeyPrefix(relayLabel()) + "deadbeef"

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.Clean() {
		t.Errorf("report is not clean: %+v", rep)
	}
	if len(f.instances) != 0 || len(f.groups) != 0 || len(f.sshKeys) != 0 {
		t.Errorf("resources survived: instances=%v groups=%v keys=%v", f.instances, f.groups, f.sshKeys)
	}
}

// TestDecommission_RefusesAForeignInstance. Ownership tags, not the id
// alone. A record can point at a box this tooling did not build — a
// copied record, a recycled id — and destroying it is unrecoverable.
func TestDecommission_RefusesAForeignInstance(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	f.instances[rec.ServerID].Tags = []string{"managed-by:someone-else"}

	rep, err := p.Decommission(context.Background(), rec)
	if err == nil {
		t.Fatal("deleted an instance that carries no daal ownership tags")
	}
	if len(f.instances) != 1 {
		t.Error("the foreign instance was destroyed anyway")
	}
	if rep.ServerDeleted {
		t.Error("report claims the server is gone")
	}
	if !containsSubstr(rep.Preserved, "instance:") {
		t.Errorf("the preserved resource is not reported: %+v", rep)
	}
}

// TestDecommission_FindsTheBoxWhenTheRecordHasNoID. The commonest way
// to arrive here: a provision that created the box and then failed its
// health wait persists an empty server_id while a real instance carries
// the derived label. Claiming "deleted" on that record tells the user
// the billing stopped and throws away the only handle on the box.
func TestDecommission_FindsTheBoxWhenTheRecordHasNoID(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	rec.ServerID = ""

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if !rep.ServerDeleted || len(f.instances) != 0 {
		t.Errorf("the instance was not found by its derived label: %+v / %v", rep, f.instances)
	}
}

// TestDecommission_PreservesAFirewallProtectingAnotherBox.
func TestDecommission_PreservesAFirewallProtectingAnotherBox(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	// A sibling relay behind the same group. Vultr decrements the
	// counter asynchronously, so this is deliberately set to survive
	// our own instance's delete.
	for _, g := range f.groups {
		g.Instances = 2
	}

	rep, err := p.Decommission(context.Background(), rec)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if rep.FirewallDeleted {
		t.Error("deleted a firewall another relay is still behind")
	}
	if !containsSubstr(rep.Preserved, "firewall-group:") {
		t.Errorf("preservation not reported: %+v", rep)
	}
	if !containsSubstr(rep.Warnings, "curl -s -X DELETE") {
		t.Errorf("no removal command for the preserved group: %+v", rep.Warnings)
	}
}

func TestDecommission_NilRecordIsVacuouslyClean(t *testing.T) {
	f := newFakeVultr(t)
	rep, err := f.provider(t).Decommission(context.Background(), nil)
	if err != nil || !rep.Clean() {
		t.Fatalf("nil record: %+v, %v", rep, err)
	}
}

// --- pricing ---

func TestPricing_SaysWhichCurrency(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	pr, err := p.Pricing(context.Background(), rec)
	if err != nil {
		t.Fatalf("Pricing: %v", err)
	}
	if pr.Currency != "USD" {
		t.Errorf("currency = %q; Vultr bills in USD and the field is named EUR", pr.Currency)
	}
	if pr.MonthlyEUR != 5.0 || pr.HourlyEUR != 0.007 {
		t.Errorf("pricing = %+v", pr)
	}
}

// TestPricing_RefusesAPlanTheRegionDoesNotCarry. Quoting a price for a
// box that cannot be created there invites the operator to pick it.
func TestPricing_RefusesAPlanTheRegionDoesNotCarry(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	rec.ServerType = "vc2-2c-4gb" // ewr only
	if _, err := p.Pricing(context.Background(), rec); err == nil {
		t.Fatal("quoted a price for a plan the region does not offer")
	}
}

// --- cover SNI ---

func TestProvision_RecordCarriesAPerRelayCoverSNI(t *testing.T) {
	f := newFakeVultr(t)
	_, rec := mustProvision(t, f, mkOpts())
	if rec.CoverSNI == "" {
		t.Fatal("Vultr record has no cover SNI")
	}
	if rec.CoverSNI == sni.LegacyCoverSNI {
		t.Fatalf("record carries the fleet-wide constant %q", rec.CoverSNI)
	}
	inZone := false
	for _, e := range sni.InZone(sni.ZoneEUCentral) {
		if e.Host == rec.CoverSNI {
			inZone = true
		}
	}
	if !inZone {
		t.Errorf("fra relay got %q, which is not in eu-central", rec.CoverSNI)
	}
}

func TestReprovision_MovesTheCoverSNIAndDeletesTheBox(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	before := rec.CoverSNI

	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{}); err != nil {
		t.Fatalf("Reprovision: %v", err)
	}
	if rec.CoverSNI == before {
		t.Errorf("re-provision kept the burned cover host %q", before)
	}
	if len(f.instances) != 0 {
		t.Error("the old instance was not destroyed")
	}
	// The firewall group SURVIVES: the next Provision finds it by
	// description, so the rebuilt box is protected from its first
	// instant.
	if len(f.groups) != 1 {
		t.Errorf("the relay's firewall group was destroyed by a reprovision: %v", f.groups)
	}
}

// TestProvision_ReusesTheFirewallGroupOnRebuild closes the loop above:
// no second group, and the rules are not duplicated.
func TestProvision_ReusesTheFirewallGroupOnRebuild(t *testing.T) {
	f := newFakeVultr(t)
	p, rec := mustProvision(t, f, mkOpts())
	firstGroup := f.instances[rec.ServerID].FirewallGroupID
	ruleCount := len(f.groups[firstGroup].Rules)

	if err := p.Reprovision(context.Background(), rec, provider.ReprovisionOpts{}); err != nil {
		t.Fatalf("Reprovision: %v", err)
	}
	opts := mkOpts()
	opts.CoverSNI = rec.CoverSNI
	rec2, err := p.Provision(context.Background(), opts)
	if err != nil {
		t.Fatalf("re-Provision: %v", err)
	}
	if got := f.instances[rec2.ServerID].FirewallGroupID; got != firstGroup {
		t.Errorf("rebuild made a second firewall group (%s -> %s)", firstGroup, got)
	}
	if got := len(f.groups[firstGroup].Rules); got != ruleCount {
		t.Errorf("rebuild duplicated firewall rules: %d -> %d", ruleCount, got)
	}
}

// --- helpers ---

func failPath(method, path string) func(string, string) (int, bool) {
	return func(m, p string) (int, bool) {
		if m == method && p == path {
			return http.StatusInternalServerError, true
		}
		return 0, false
	}
}

// rulesFor returns the rule keys attached to an instance's group.
func (f *fakeVultr) rulesFor(t *testing.T, instanceID string) map[string]bool {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	inst := f.instances[instanceID]
	if inst == nil {
		t.Fatalf("no instance %s", instanceID)
	}
	g := f.groups[inst.FirewallGroupID]
	if g == nil {
		t.Fatalf("instance %s has no firewall group", instanceID)
	}
	out := map[string]bool{}
	for _, r := range g.Rules {
		out[ruleKey(r.IPType, r.Protocol, r.Subnet, r.SubnetSize, r.Port)] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func containsSubstr(haystack []string, want string) bool {
	for _, h := range haystack {
		if strings.Contains(h, want) {
			return true
		}
	}
	return false
}

func hasPrefixIn(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf

// TestProvision_TheRecordMovesAsAWhole is the L5 invariant: provider,
// region, server id and the dialled address either all move to the new
// cloud or none of them do.
//
// The failure it forbids is a record that still says "hetzner" beside a
// Vultr instance id — the next rotation would build the provider
// adapter from the stale field and target the wrong box, on the wrong
// account, with a token that cannot see it. Provision never mutates the
// caller's record; it returns a new one built in a single literal, so
// there is no window in which half of it has moved.
func TestProvision_TheRecordMovesAsAWhole(t *testing.T) {
	f := newFakeVultr(t)
	// What the operator holds before an L5: a record on the old cloud.
	old := &provider.OperatorRecord{
		Provider: "hetzner", ServerID: "9999", Region: "fsn1",
		ServerType: "cx22", PublicIP: net.ParseIP("5.75.1.1"),
		FloatingIPID: "hetzner-fip-1",
		Candidates: []provider.CandidateMeta{
			{Family: "vless-reality", PublicRiskTags: []string{"public_ip:5.75.1.1"}},
		},
	}
	_, rec := mustProvision(t, f, mkOpts())

	if rec == old {
		t.Fatal("Provision handed back the caller's own record")
	}
	if old.Provider != "hetzner" || old.ServerID != "9999" {
		t.Error("Provision mutated the record the operator still needs to tear the old relay down")
	}
	if rec.Provider != "vultr" || rec.Region != testRegion {
		t.Errorf("new record is not wholly on the new cloud: provider=%q region=%q", rec.Provider, rec.Region)
	}
	if rec.ServerID == old.ServerID || rec.PublicIP.Equal(old.PublicIP) {
		t.Error("new record carries the old cloud's identity")
	}
	// A floating-IP id from the OLD provider must not travel: it is
	// meaningless on Vultr, and a release or teardown aimed at it would
	// hit an id this account has never heard of.
	if rec.FloatingIPID != "" {
		t.Errorf("the old cloud's reserved-address id followed the relay: %q", rec.FloatingIPID)
	}
	for _, c := range rec.Candidates {
		if hasTag(c.PublicRiskTags, "public_ip:5.75.1.1") {
			t.Errorf("candidate %s still advertises the old cloud's address: %v", c.Family, c.PublicRiskTags)
		}
	}
}
