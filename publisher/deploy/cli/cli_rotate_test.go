package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

func writeRotateRecord(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	rec := provider.OperatorRecord{
		Provider:   "hetzner",
		ServerID:   "srv-1",
		ServerType: "cpx21",
		Region:     "fsn1",
		CoverSNI:   "mirror.init7.net",
	}
	body, _ := json.Marshal(rec)
	path := filepath.Join(tmp, "rec.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- dispatch ---

// The verbs exist on the Run() switch. Before Step 7 the box endpoints,
// the client methods and the token allow-list all existed with zero
// callers; the switch case is the thing that was missing, so it gets
// its own assertion.
func TestRun_DispatchesRotateVerbs(t *testing.T) {
	for _, sub := range []string{"rotate-credentials", "rotate-tls"} {
		var stdout, stderr bytes.Buffer
		rc := Run([]string{sub}, &stdout, &stderr)
		if rc != 2 {
			t.Errorf("%s: rc = %d, want 2 (missing flags)", sub, rc)
		}
		if strings.Contains(stderr.String(), "unknown subcommand") {
			t.Errorf("%s is not wired into the subcommand switch", sub)
		}
		if !strings.Contains(stderr.String(), "--record-file") {
			t.Errorf("%s: expected the missing-flag list; got %s", sub, stderr.String())
		}
	}
}

func TestUsage_DocumentsRotateVerbs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{"--help"}, &stdout, &stderr); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	for _, want := range []string{"rotate-credentials", "rotate-tls"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("usage does not mention %s", want)
		}
	}
}

// --- flag validation ---

// --name is required and there is no rotate-all spelling. This is the
// interlock, not a nicety: on a relay that predates the split, a
// nameless rotate-credentials rotates the box-wide REALITY keypair and
// invalidates every pack in the field.
func TestRotateCredentials_RequiresName(t *testing.T) {
	recFile := writeRotateRecord(t)
	var stdout, stderr bytes.Buffer
	rc := runRotateCredentials(t.Context(), []string{
		"--record-file", recFile,
		"--priv-key", "-",
		"--helper-ip", "1.2.3.4",
	}, bytes.NewBuffer(nil), &stdout, &stderr)
	if rc != 2 {
		t.Fatalf("rc = %d, want 2; stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--name") {
		t.Errorf("expected --name in the missing-flag list; got %s", stderr.String())
	}
}

func TestRotateCredentials_RequiresRecordPrivKeyAndHelperIP(t *testing.T) {
	recFile := writeRotateRecord(t)
	cases := map[string][]string{
		"--record-file": {"--priv-key", "-", "--helper-ip", "1.2.3.4", "--name", "r1"},
		"--priv-key":    {"--record-file", recFile, "--helper-ip", "1.2.3.4", "--name", "r1"},
		"--helper-ip":   {"--record-file", recFile, "--priv-key", "-", "--name", "r1"},
	}
	for missing, args := range cases {
		var stdout, stderr bytes.Buffer
		rc := runRotateCredentials(t.Context(), args, bytes.NewBuffer(nil), &stdout, &stderr)
		if rc != 2 {
			t.Errorf("omitting %s: rc = %d, want 2", missing, rc)
		}
		if !strings.Contains(stderr.String(), missing) {
			t.Errorf("omitting %s: stderr = %s", missing, stderr.String())
		}
	}
}

// rotate-tls takes no --name: it is relay-wide by construction. The
// per-recipient scope belongs to the other verb, and conflating the two
// is the exact bug Step 7 exists to undo.
func TestRotateTLS_HasNoRecipientScope(t *testing.T) {
	recFile := writeRotateRecord(t)
	var stdout, stderr bytes.Buffer
	rc := runRotateTLS(t.Context(), []string{
		"--record-file", recFile,
		"--priv-key", "-",
		"--helper-ip", "1.2.3.4",
		"--name", "r1",
	}, bytes.NewBuffer(nil), &stdout, &stderr)
	if rc == 0 {
		t.Fatal("rotate-tls accepted --name")
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Errorf("expected an unknown-flag error; got %s", stderr.String())
	}
}

func TestRotateTLS_RequiresRecordPrivKeyAndHelperIP(t *testing.T) {
	recFile := writeRotateRecord(t)
	cases := map[string][]string{
		"--record-file": {"--priv-key", "-", "--helper-ip", "1.2.3.4"},
		"--priv-key":    {"--record-file", recFile, "--helper-ip", "1.2.3.4"},
		"--helper-ip":   {"--record-file", recFile, "--priv-key", "-"},
	}
	for missing, args := range cases {
		var stdout, stderr bytes.Buffer
		rc := runRotateTLS(t.Context(), args, bytes.NewBuffer(nil), &stdout, &stderr)
		if rc != 2 {
			t.Errorf("omitting %s: rc = %d, want 2", missing, rc)
		}
		if !strings.Contains(stderr.String(), missing) {
			t.Errorf("omitting %s: stderr = %s", missing, stderr.String())
		}
	}
}

// A flag error must never reach the network or the cloud API. Both
// verbs validate before they build a provider, so a malformed
// invocation cannot open a firewall window.
func TestRotateVerbs_FlagErrorsNeverBuildAProvider(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := runRotateCredentials(t.Context(), []string{"--nonsense"}, bytes.NewBuffer(nil), &stdout, &stderr); rc == 0 {
		t.Error("rotate-credentials accepted an unknown flag")
	}
	stdout.Reset()
	stderr.Reset()
	if rc := runRotateTLS(t.Context(), []string{"--nonsense"}, bytes.NewBuffer(nil), &stdout, &stderr); rc == 0 {
		t.Error("rotate-tls accepted an unknown flag")
	}
}

// --- rotate-recommend, capability-aware ---

// Omitting --relay-capabilities means "not probed", and the emitted
// action must say so rather than promise a one-tap rotation that may
// not exist on this relay.
func TestRotateRecommend_UnprobedRelayReportsUnknownAvailability(t *testing.T) {
	recFile := writeRotateRecord(t)
	var stdout, stderr bytes.Buffer
	rc := runRotateRecommend([]string{
		"--record-file", recFile,
		"--context-only",
		"--classification", "sni_rst",
	}, bytes.NewBuffer(nil), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"kind": "rotate-tls"`) {
		t.Errorf("L2 did not name the rotate-tls verb; got %s", out)
	}
	if !strings.Contains(out, `"availability": "unknown"`) {
		t.Errorf("unprobed relay did not report unknown availability; got %s", out)
	}
}

// Probed and capable: the recommendation names an action the publisher
// can actually run, in place, right now.
func TestRotateRecommend_CapableRelayNamesTheInPlaceVerb(t *testing.T) {
	recFile := writeRotateRecord(t)
	var stdout, stderr bytes.Buffer
	rc := runRotateRecommend([]string{
		"--record-file", recFile,
		"--context-only",
		"--credential-leak",
		"--relay-capabilities", "rotate-credentials,rotate-tls",
	}, bytes.NewBuffer(nil), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		`"level": "L1"`,
		`"kind": "rotate-credentials"`,
		`"availability": "ready"`,
		`"in_place": true`,
		`"needs_recipient_name": true`,
		`"est_wallclock": "~90s"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
}

// Probed and NOT capable: the flag was passed with an empty value, i.e.
// "we asked, and it can do neither". The recommendation degrades to the
// reprovision fallback and stops quoting the in-place wall clock.
func TestRotateRecommend_OldRelayDegradesToReprovision(t *testing.T) {
	recFile := writeRotateRecord(t)
	var stdout, stderr bytes.Buffer
	rc := runRotateRecommend([]string{
		"--record-file", recFile,
		"--context-only",
		"--credential-leak",
		"--relay-capabilities", "",
	}, bytes.NewBuffer(nil), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"level": "L1"`) {
		t.Errorf("level changed; got %s", out)
	}
	if !strings.Contains(out, `"kind": "reprovision"`) {
		t.Errorf("old relay did not fall back to reprovision; got %s", out)
	}
	if !strings.Contains(out, `"availability": "unsupported"`) {
		t.Errorf("old relay did not report unsupported; got %s", out)
	}
	if !strings.Contains(out, `"destroys_server": true`) {
		t.Errorf("fallback did not admit it destroys the server; got %s", out)
	}
	if strings.Contains(out, `"est_wallclock": "~90s"`) {
		t.Errorf("quoted the in-place wall clock for a destroy-and-rebuild; got %s", out)
	}
	if !strings.Contains(out, "re-release") {
		t.Errorf("no remediation for the operator; got %s", out)
	}
}
