package cli

// The CLI half of the account audit. Three things are worth a test
// here and nothing else is:
//
//   - the destructive verb does NOTHING without --yes,
//   - an adapter that cannot enumerate says so instead of reporting a
//     clean account, and
//   - a refusal reaches the operator's screen with its reason intact.
//
// The proving itself is tested where it lives, in
// providers/hetzner/audit_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/provider"
)

// fakeAuditProvider is a providerFace that also implements
// AccountAuditor, and counts reclaim calls so a dry run can be proven
// to be dry all the way down rather than merely quiet.
type fakeAuditProvider struct {
	providerFace // nil: any other method call panics, which is the point
	audit        *provider.AccountAudit
	auditErr     error
	reclaim      *provider.ReclaimReport
	reclaimErr   error
	reclaimCalls int
	lastOnly     []provider.ResourceRef
	lastRecords  int
}

func (f *fakeAuditProvider) AuditAccount(_ context.Context, recs []*provider.OperatorRecord) (*provider.AccountAudit, error) {
	f.lastRecords = len(recs)
	return f.audit, f.auditErr
}

func (f *fakeAuditProvider) ReclaimOrphans(_ context.Context, recs []*provider.OperatorRecord, only []provider.ResourceRef) (*provider.ReclaimReport, error) {
	f.reclaimCalls++
	f.lastOnly = only
	f.lastRecords = len(recs)
	return f.reclaim, f.reclaimErr
}

// fakeBlindProvider is an adapter that cannot enumerate an account —
// the shape vultr and stark are in today.
type fakeBlindProvider struct{ providerFace }

func auditWithOneOrphan() *provider.AccountAudit {
	a := provider.NewAccountAudit("hetzner", timeZero())
	a.ServerListComplete = true
	a.Add(provider.AuditedResource{
		Kind: provider.KindFloatingIP, ID: "77", Name: "daal-fip-77", Relay: "daal-fsn1-aaaa",
		Verdict: provider.VerdictOrphan, Reason: "attached to nothing and its relay is gone",
		Billing: true, Reclaimable: true,
	})
	a.Add(provider.AuditedResource{
		Kind: provider.KindServer, ID: "9", Name: "daal-fsn1-bbbb",
		Verdict: provider.VerdictUnclaimed, Reason: "built by daal-deploy, no record claims it",
		Billing: true, Hint: "run `daal-deploy decommission`",
	})
	return a
}

// timeZero is a fixed clock so a rendered report is byte-stable
// between runs; a diff between two audits should mean the account
// changed, not that time passed.
func timeZero() time.Time { return time.Unix(0, 0).UTC() }

func writeTestFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

func tokenFileFor(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := dir + "/token"
	if err := writeTestFile(p, "tok"); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- the property that matters most ---------------------------------

// A verb that deletes cloud resources must not delete anything on a
// bare invocation. The dry run is the DEFAULT, and it is proven by the
// reclaim call never being made — not by the absence of output, which
// a future refactor could restore while leaving the deletes in place.
func TestAccountReclaim_DoesNothingWithoutYes(t *testing.T) {
	f := &fakeAuditProvider{audit: auditWithOneOrphan()}
	withFakeProvider(t, f)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"account-reclaim", "--token-file", tokenFileFor(t)}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if f.reclaimCalls != 0 {
		t.Fatalf("the destructive path ran %d time(s) without --yes", f.reclaimCalls)
	}
	out := stdout.String()
	if !strings.Contains(out, "--yes") {
		t.Errorf("the plan does not tell the operator how to actually run it: %s", out)
	}
	if !strings.Contains(out, "77") {
		t.Errorf("the plan does not name what it would delete: %s", out)
	}
	if !strings.Contains(out, "Servers are never deleted") {
		t.Errorf("the plan does not state the limit that matters: %s", out)
	}
}

func TestAccountReclaim_WithYesRunsIt(t *testing.T) {
	rep := provider.NewReclaimReport("hetzner")
	rep.Add(provider.ReclaimOutcome{Kind: provider.KindFloatingIP, ID: "77", Deleted: true, Reason: "released"})
	f := &fakeAuditProvider{audit: auditWithOneOrphan(), reclaim: rep}
	withFakeProvider(t, f)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"account-reclaim", "--token-file", tokenFileFor(t), "--yes"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if f.reclaimCalls != 1 {
		t.Fatalf("reclaim ran %d times", f.reclaimCalls)
	}
	if !strings.Contains(stdout.String(), "1 deleted") {
		t.Errorf("output does not count what happened: %s", stdout.String())
	}
}

// A refusal must reach the screen with its reason. An operator who
// sees "0 deleted" and no explanation concludes the tool is broken and
// goes and deletes something by hand.
func TestAccountReclaim_RefusalsArePrintedWithTheirReason(t *testing.T) {
	rep := provider.NewReclaimReport("hetzner")
	rep.Add(provider.ReclaimOutcome{
		Kind: provider.KindFloatingIP, ID: "77", Deleted: false,
		Reason: "refused: it has been attached to server 1 since the audit ran",
	})
	f := &fakeAuditProvider{audit: auditWithOneOrphan(), reclaim: rep}
	withFakeProvider(t, f)
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"account-reclaim", "--token-file", tokenFileFor(t), "--yes"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(stdout.String(), "attached to server 1") {
		t.Errorf("the refusal's reason was swallowed: %s", stdout.String())
	}
}

// An account-wide refusal (the server list could not be read) is an
// error, and the report still prints so the operator can see that
// nothing was touched.
func TestAccountReclaim_AccountWideRefusalIsAnErrorThatStillExplains(t *testing.T) {
	f := &fakeAuditProvider{
		audit:      auditWithOneOrphan(),
		reclaim:    provider.NewReclaimReport("hetzner"),
		reclaimErr: errors.New("refusing to reclaim anything — the account's server list could not be read"),
	}
	withFakeProvider(t, f)
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"account-reclaim", "--token-file", tokenFileFor(t), "--yes"}, &stdout, &stderr); rc != 1 {
		t.Fatalf("rc=%d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "server list could not be read") {
		t.Errorf("stderr does not carry the reason: %s", stderr.String())
	}
}

// --only is exact and is passed through unwidened.
func TestAccountReclaim_OnlyIsParsedAndForwarded(t *testing.T) {
	f := &fakeAuditProvider{audit: auditWithOneOrphan(), reclaim: provider.NewReclaimReport("hetzner")}
	withFakeProvider(t, f)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"account-reclaim", "--token-file", tokenFileFor(t), "--yes",
		"--only", "floating-ip:77", "--only", "ssh-key:3"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	want := []provider.ResourceRef{{Kind: "floating-ip", ID: "77"}, {Kind: "ssh-key", ID: "3"}}
	if len(f.lastOnly) != 2 || f.lastOnly[0] != want[0] || f.lastOnly[1] != want[1] {
		t.Fatalf("only = %+v, want %+v", f.lastOnly, want)
	}
}

func TestAccountReclaim_MalformedOnlyIsAFlagError(t *testing.T) {
	withFakeProvider(t, &fakeAuditProvider{audit: auditWithOneOrphan()})
	for _, bad := range []string{"77", "widget:1", "floating-ip:", ":77"} {
		var stdout, stderr bytes.Buffer
		rc := Run([]string{"account-reclaim", "--token-file", tokenFileFor(t), "--yes", "--only", bad}, &stdout, &stderr)
		if rc != 2 {
			t.Errorf("--only %q gave rc=%d, want 2 (a bad selector must not reach the deleter)", bad, rc)
		}
	}
}

// --- the blind adapter ----------------------------------------------

// vultr and stark cannot enumerate an account today. Reporting
// "nothing found" from an adapter that cannot look would be a lie
// about resources that are still billing, which is the reason
// AccountAuditor is a separate, optional interface.
func TestAccountAudit_AnAdapterThatCannotEnumerateSaysSo(t *testing.T) {
	withFakeProvider(t, &fakeBlindProvider{})
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"account-audit", "--provider", "vultr", "--token-file", tokenFileFor(t)}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("rc=%d, want 1", rc)
	}
	if strings.Contains(stdout.String(), "nothing is orphaned") {
		t.Fatal("an adapter that cannot look reported a clean account")
	}
	for _, want := range []string{"cannot audit an account yet", "console by hand"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("refusal does not say %q: %s", want, stderr.String())
		}
	}
}

// The same refusal has to reach the destructive verb too — otherwise
// an operator learns the adapter is blind only after asking it to
// delete things.
func TestAccountReclaim_AnAdapterThatCannotEnumerateSaysSo(t *testing.T) {
	withFakeProvider(t, &fakeBlindProvider{})
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"account-reclaim", "--provider", "stark", "--token-file", tokenFileFor(t), "--yes"}, &stdout, &stderr)
	if rc != 1 || !strings.Contains(stderr.String(), "cannot audit an account yet") {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
}

// --- the read side ---------------------------------------------------

// The unproven section must survive rendering. It is the honest half:
// resources the tool cannot prove anything about, named so the
// operator can look them up.
func TestAccountAudit_PrintsWhatItCouldNotProveAndWhereToLook(t *testing.T) {
	a := provider.NewAccountAudit("hetzner", timeZero())
	a.ServerListComplete = true
	a.Add(provider.AuditedResource{
		Kind: provider.KindFloatingIP, ID: "88", Name: "daal-fip-88",
		Verdict: provider.VerdictUnproven, Billing: true,
		Reason: "carries managed-by=daal-deploy but no daal-relay label",
		Hint:   "Hetzner console -> Floating IPs -> daal-fip-88",
	})
	withFakeProvider(t, &fakeAuditProvider{audit: a})
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"account-audit", "--token-file", tokenFileFor(t)}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"COULD NOT BE PROVEN", "daal-fip-88", "no daal-relay label", "Hetzner console", "[billing]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

// An unreadable server list is stated at the top, above everything it
// invalidates, and the read-only verb still exits 0 so it can be run
// unconditionally before a provision.
func TestAccountAudit_AnIncompleteServerListIsStatedFirst(t *testing.T) {
	a := provider.NewAccountAudit("hetzner", timeZero())
	a.ServerListComplete = false
	a.Warnf("could not list servers (503)")
	withFakeProvider(t, &fakeAuditProvider{audit: a})
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"account-audit", "--token-file", tokenFileFor(t)}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "Nothing below is proven") {
		t.Errorf("the invalidation is not stated: %s", out)
	}
	if strings.Contains(out, "nothing is orphaned and nothing is unaccounted for") {
		t.Error("an audit that could not enumerate reported a clean account")
	}
}

// --json is the shape an operator diffs between runs and pastes into a
// ticket, so it has to actually be the report.
func TestAccountAudit_JSONIsTheWholeReport(t *testing.T) {
	withFakeProvider(t, &fakeAuditProvider{audit: auditWithOneOrphan()})
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"account-audit", "--token-file", tokenFileFor(t), "--json"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	var got provider.AccountAudit
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout.String())
	}
	if len(got.Resources) != 2 || got.Resources[0].ID != "77" {
		t.Fatalf("round-trip lost resources: %+v", got.Resources)
	}
	if got.Warnings == nil {
		t.Error("warnings must never be null on the wire")
	}
}

// Records are OPTIONAL. The orphan that costs the most is the one
// whose record was never written, so a bare invocation must work.
func TestAccountAudit_RunsWithNoRecordsAtAll(t *testing.T) {
	f := &fakeAuditProvider{audit: auditWithOneOrphan()}
	withFakeProvider(t, f)
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"account-audit", "--token-file", tokenFileFor(t)}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if f.lastRecords != 0 {
		t.Fatalf("invented %d records", f.lastRecords)
	}
}

// A record that will not parse is fatal, not skipped. Silently
// ignoring one of the operator's relays is how that relay's live
// resources get classified as unclaimed.
func TestAccountAudit_AnUnreadableRecordIsFatal(t *testing.T) {
	f := &fakeAuditProvider{audit: auditWithOneOrphan()}
	withFakeProvider(t, f)
	dir := t.TempDir()
	bad := dir + "/bad.json"
	if err := writeTestFile(bad, "{not json"); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"account-audit", "--token-file", tokenFileFor(t), "--record-file", bad}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("rc=%d, want 1", rc)
	}
	if f.lastRecords != 0 {
		t.Error("the audit ran despite a record it could not read")
	}
}

// --- wiring ----------------------------------------------------------

func TestAccountVerbs_AreDispatchedAndDocumented(t *testing.T) {
	for _, verb := range []string{"account-audit", "account-reclaim"} {
		var stdout, stderr bytes.Buffer
		if rc := Run([]string{verb}, &stdout, &stderr); rc != 2 {
			t.Errorf("%s with no flags gave rc=%d, want 2", verb, rc)
		}
		if !strings.Contains(stderr.String(), "--token-file") {
			t.Errorf("%s does not name its required flag: %s", verb, stderr.String())
		}
		if !strings.Contains(usage(), verb) {
			t.Errorf("usage() does not document %s", verb)
		}
	}
}

// A flag error must never build a provider — the same rule the rotate
// verbs pin, and here it also means a typo can never reach a deleter.
func TestAccountVerbs_FlagErrorsNeverBuildAProvider(t *testing.T) {
	prev := buildProviderFn
	built := 0
	buildProviderFn = func(string, string, bool) (providerFace, error) {
		built++
		return nil, errors.New("should not be reached")
	}
	t.Cleanup(func() { buildProviderFn = prev })
	for _, args := range [][]string{
		{"account-audit"},
		{"account-reclaim"},
		{"account-reclaim", "--token-file", "x", "--only", "nonsense"},
	} {
		var stdout, stderr bytes.Buffer
		Run(args, &stdout, &stderr)
	}
	if built != 0 {
		t.Fatalf("built a provider %d time(s) on a flag error", built)
	}
}
