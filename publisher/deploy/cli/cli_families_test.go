package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/cloudinit"
	"daal/publisher/deploy/provider"
)

// servePhrase is how the statement must open for a list that turns on an
// opt-in family: a promise only when the pinned relay release can keep
// it (cloudinit.PinnedMgmtServesOptInFamilies), a request otherwise.
func servePhrase() string {
	if cloudinit.PinnedMgmtServesOptInFamilies {
		return "will serve "
	}
	return "will be asked to serve "
}

// provisionDry runs `provision --dry-run` (no cloud call) and returns
// its exit status, stdout and stderr.
func provisionDry(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{
		"provision", "--provider", "hetzner", "--pubkey-file", pubFile,
		"--region", "fsn1", "--server-type", "cx22", "--helper-ip", "198.18.0.2", "--dry-run",
	}, extra...)
	var stdout, stderr bytes.Buffer
	rc := Run(args, &stdout, &stderr)
	return rc, stdout.String(), stderr.String()
}

func recordFamilies(t *testing.T, stdout string) []string {
	t.Helper()
	var rec provider.OperatorRecord
	if err := json.Unmarshal([]byte(stdout), &rec); err != nil {
		t.Fatalf("stdout is not an OperatorRecord: %v\n%s", err, stdout)
	}
	var out []string
	for _, c := range rec.Candidates {
		out = append(out, c.Family)
	}
	return out
}

// FAM-3, first half: a misspelt family used to be dropped without a
// word as long as one other name matched — exit 0, a rented server, and
// a relay without the family the operator asked for.
func TestProvision_FamiliesTypoIsAnErrorNamingTheValueAndTheValidSet(t *testing.T) {
	rc, stdout, stderr := provisionDry(t, "--toolbox-profile", "iran-default", "--families", "vless-reality,tiuc")
	if rc == 0 {
		t.Fatalf("rc = 0 for --families vless-reality,tiuc; record: %s", stdout)
	}
	if rc != 2 {
		t.Errorf("rc = %d, want 2 (a usage error, before anything is created)", rc)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("an OperatorRecord was written for a refused family list:\n%s", stdout)
	}
	if !strings.Contains(stderr, `"tiuc"`) {
		t.Errorf("the error does not name the bad value:\n%s", stderr)
	}
	for _, valid := range []string{"vless-reality", "websocket-tls", "naive", "hysteria2", "shadowsocks", "anytls", "tuic"} {
		if !strings.Contains(stderr, valid) {
			t.Errorf("the error does not list %q in the valid set:\n%s", valid, stderr)
		}
	}
	// Several bad names: all of them, not the first.
	_, _, stderr = provisionDry(t, "--toolbox-profile", "iran-default", "--families", "tiuc,naive,anytsl")
	if !strings.Contains(stderr, `"tiuc"`) || !strings.Contains(stderr, `"anytsl"`) {
		t.Errorf("not every bad value is named:\n%s", stderr)
	}
}

// A real family the CHOSEN profile does not offer is the same failure
// for the operator — the relay will not serve it — and is told apart
// from a typo in the text.
func TestProvision_FamilyNotOfferedByTheProfileIsAnError(t *testing.T) {
	rc, stdout, stderr := provisionDry(t, "--toolbox-profile", "iran-tcp443", "--families", "vless-reality,tuic")
	if rc != 2 {
		t.Fatalf("rc = %d, want 2; stdout=%s stderr=%s", rc, stdout, stderr)
	}
	if !strings.Contains(stderr, `"tuic"`) || !strings.Contains(stderr, `"iran-default"`) {
		t.Errorf("the error should name tuic and the profile that does offer it:\n%s", stderr)
	}
	if strings.Contains(stderr, "hysteria2,") || strings.Contains(stderr, ", hysteria2") {
		t.Errorf("the valid set for iran-tcp443 lists a family that profile does not offer:\n%s", stderr)
	}
}

// FAM-3, second half: the list REPLACES the defaults. `--families tuic`
// is a tuic-only relay; that is allowed, and it must be said.
func TestProvision_ShortFamilyListSaysWhatItDrops(t *testing.T) {
	rc, stdout, stderr := provisionDry(t, "--toolbox-profile", "iran-default", "--families", "tuic")
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, stderr)
	}
	if got := strings.Join(recordFamilies(t, stdout), ","); got != "tuic" {
		t.Errorf("record families = %s, want tuic", got)
	}
	for _, want := range []string{"REPLACES", servePhrase() + "tuic", "will NOT serve vless-reality, websocket-tls, naive, hysteria2"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q:\n%s", want, stderr)
		}
	}

	// With --progress-json the same statement is one machine-readable
	// event, and stderr stays one JSON object per line.
	rc, _, stderr = provisionDry(t, "--toolbox-profile", "iran-default", "--families", "shadowsocks,anytls", "--progress-json")
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, stderr)
	}
	var ev map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("--progress-json stderr line is not JSON: %q", line)
		}
		if m["step"] == "provision_families" {
			ev = m
		}
	}
	if ev == nil {
		t.Fatalf("no provision_families progress event:\n%s", stderr)
	}
	join := func(v any) string {
		var parts []string
		for _, x := range v.([]any) {
			parts = append(parts, x.(string))
		}
		return strings.Join(parts, ",")
	}
	if got := join(ev["families"]); got != "shadowsocks,anytls" {
		t.Errorf("event families = %s", got)
	}
	if got := join(ev["dropped_defaults"]); got != "vless-reality,websocket-tls,naive,hysteria2" {
		t.Errorf("event dropped_defaults = %s", got)
	}
	if got := join(ev["added_opt_in"]); got != "shadowsocks,anytls" {
		t.Errorf("event added_opt_in = %s", got)
	}
	// What the pinned relay release cannot serve is in the event too, so
	// a front end can say it without parsing the sentence.
	wantUnserved := strings.Join(cloudinit.NotServedByPinnedMgmt([]string{"shadowsocks", "anytls"}), ",")
	if _, ok := ev["unserved_by_release"]; !ok {
		t.Fatalf("event has no unserved_by_release: %v", ev)
	}
	if got := join(ev["unserved_by_release"]); got != wantUnserved {
		t.Errorf("event unserved_by_release = %q, want %q", got, wantUnserved)
	}
}

// No --families: the profile's defaults, and nothing to announce.
func TestProvision_NoFamiliesFlagIsQuiet(t *testing.T) {
	rc, stdout, stderr := provisionDry(t, "--toolbox-profile", "iran-default")
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, stderr)
	}
	if strings.Contains(stderr, "REPLACES") {
		t.Errorf("a notice was printed although --families was not given:\n%s", stderr)
	}
	if n := len(recordFamilies(t, stdout)); n != 4 {
		t.Errorf("default relay has %d families, want 4", n)
	}
	// The defaults plus an opt-in: nothing dropped, and it says so by
	// not saying "will NOT serve".
	rc, stdout, stderr = provisionDry(t, "--toolbox-profile", "iran-default",
		"--families", "vless-reality,websocket-tls,naive,hysteria2,tuic,tuic")
	if rc != 0 {
		t.Fatalf("rc = %d: %s", rc, stderr)
	}
	if strings.Contains(stderr, "will NOT serve") {
		t.Errorf("nothing was dropped, yet:\n%s", stderr)
	}
	if !strings.Contains(stderr, "tuic: off by default, turned on by this list") {
		t.Errorf("the opt-in family is not called out:\n%s", stderr)
	}
	if n := len(recordFamilies(t, stdout)); n != 5 {
		t.Errorf("relay has %d families, want 5 (a repeated name must not repeat a candidate)", n)
	}
}

// L6 keeps working. The rung moves a relay to another toolbox profile:
// `reprovision` (delete) then `provision --families <the record's
// families>` on the new profile, and it relied on `provision` dropping
// what the new profile does not offer. `provision` no longer drops in
// silence, so `reprovision` narrows the record it hands on.
func TestReprovision_NarrowsTheRecordSoTheL6RebuildStillProvisions(t *testing.T) {
	rec := &provider.OperatorRecord{Candidates: []provider.CandidateMeta{
		{Family: "vless-reality"}, {Family: "hysteria2"}, {Family: "naive"}, {Family: "tuic"},
	}}
	recordList := func() string {
		var out []string
		for _, c := range rec.Candidates {
			out = append(out, c.Family)
		}
		return strings.Join(out, ",")
	}

	// Without the narrowing, the second half of an L6 onto the no-UDP
	// profile would now be refused — after the old server was deleted.
	if rc, _, _ := provisionDry(t, "--toolbox-profile", "iran-tcp443", "--families", recordList()); rc == 0 {
		t.Fatal("precondition: the un-narrowed list should be refused by the stricter provision")
	}

	dropped := narrowRecordToProfile(rec, "iran-tcp443")
	if strings.Join(dropped, ",") != "hysteria2,tuic" {
		t.Errorf("dropped = %v, want hysteria2 and tuic (the UDP families iran-tcp443 does not offer)", dropped)
	}
	if recordList() != "vless-reality,naive" {
		t.Errorf("record after narrowing = %s, want vless-reality,naive", recordList())
	}
	rc, stdout, stderr := provisionDry(t, "--toolbox-profile", "iran-tcp443", "--families", recordList())
	if rc != 0 {
		t.Fatalf("the L6 rebuild's provision was refused: rc=%d %s", rc, stderr)
	}
	if got := strings.Join(recordFamilies(t, stdout), ","); got != "vless-reality,naive" {
		t.Errorf("rebuilt relay families = %s, want vless-reality,naive", got)
	}

	// Same profile, no profile, unknown profile: nothing is touched.
	for _, prof := range []string{"", "iran-tcp443", "no-such-profile"} {
		before := recordList()
		if d := narrowRecordToProfile(rec, prof); len(d) != 0 || recordList() != before {
			t.Errorf("narrowRecordToProfile(%q) changed an already-valid record: dropped %v, now %s", prof, d, recordList())
		}
	}
	if d := narrowRecordToProfile(nil, "iran-tcp443"); d != nil {
		t.Errorf("nil record: %v", d)
	}
}

// Review finding on FAM-2/FAM-3 (F-002 still open): the line printed
// before the cloud is called said "this relay will serve …, anytls"
// while the only daal-relay-mgmt a new relay downloads serves no anytls
// at all. Whatever the pin is today, a plan that names a family the
// release cannot serve must not read as a promise, and must say what the
// operator gets instead.
func TestFamilySummary_DoesNotPromiseWhatTheReleaseCannotServe(t *testing.T) {
	plan := &familyPlan{
		Profile:           "iran-default",
		Explicit:          true,
		Served:            []string{"vless-reality", "websocket-tls", "naive", "hysteria2", "anytls"},
		AddedOptIn:        []string{"anytls"},
		UnservedByRelease: []string{"anytls"},
	}
	got := plan.summary()
	if strings.Contains(got, "will serve") {
		t.Errorf("the statement promises families the released relay software cannot serve:\n%s", got)
	}
	for _, want := range []string{
		"will be asked to serve vless-reality, websocket-tls, naive, hysteria2, anytls",
		"NOT SERVED YET",
		"predates anytls",
		"no connection file will carry a route for anytls",
		"older Daal apps cannot open at all",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the statement does not say %q:\n%s", want, got)
		}
	}

	// tuic alone: unserved, but it does not change the file format, so
	// the older-app sentence would be a false alarm.
	plan.Served = []string{"tuic"}
	plan.AddedOptIn = []string{"tuic"}
	plan.UnservedByRelease = []string{"tuic"}
	if got := plan.summary(); strings.Contains(got, "older Daal apps") || !strings.Contains(got, "NOT SERVED YET") {
		t.Errorf("tuic-only statement is wrong:\n%s", got)
	}

	// Once the release serves them, it is a plain promise again.
	plan.UnservedByRelease = nil
	got = plan.summary()
	if !strings.Contains(got, "will serve tuic") || strings.Contains(got, "asked") || strings.Contains(got, "NOT SERVED YET") {
		t.Errorf("with nothing unserved the statement should be the plain one:\n%s", got)
	}
}

// The plan takes "unserved" from the constant next to the pin and from
// nowhere else, and a list of default families never trips it.
func TestResolveFamilies_UnservedComesFromThePin(t *testing.T) {
	plan, err := resolveFamilies("iran-default", []string{"vless-reality", "shadowsocks", "anytls", "tuic"})
	if err != nil {
		t.Fatal(err)
	}
	want := cloudinit.NotServedByPinnedMgmt(plan.Served)
	if strings.Join(plan.UnservedByRelease, ",") != strings.Join(want, ",") {
		t.Errorf("UnservedByRelease = %v, want %v", plan.UnservedByRelease, want)
	}
	if !cloudinit.PinnedMgmtServesOptInFamilies && len(plan.UnservedByRelease) != 3 {
		t.Errorf("the pinned release serves none of the three opt-in families; UnservedByRelease = %v", plan.UnservedByRelease)
	}
	plan, err = resolveFamilies("iran-default", []string{"vless-reality", "naive"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.UnservedByRelease) != 0 {
		t.Errorf("default families reported as unserved: %v", plan.UnservedByRelease)
	}
	if got := plan.summary(); !strings.Contains(got, "will serve vless-reality, naive") {
		t.Errorf("a list of default families should stay a plain promise:\n%s", got)
	}
}
