package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

func TestRun_NoArgsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run(nil, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d want 2", rc)
	}
	if !strings.Contains(stderr.String(), "Usage") {
		t.Errorf("expected usage on stderr; got: %s", stderr.String())
	}
}

func TestRun_HelpExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"--help"}, &stdout, &stderr)
	if rc != 0 {
		t.Errorf("rc = %d want 0", rc)
	}
	if !strings.Contains(stdout.String(), "Subcommands") {
		t.Errorf("expected help on stdout")
	}
}

func TestRun_VersionExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"version"}, &stdout, &stderr)
	if rc != 0 {
		t.Errorf("rc = %d want 0", rc)
	}
	if !strings.Contains(stdout.String(), "daal-deploy") {
		t.Errorf("expected version on stdout; got %q", stdout.String())
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"foo"}, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc = %d want 2", rc)
	}
}

func TestProvision_DryRunEmitsRecord(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--provider", "hetzner",
		"--pubkey", pubFile,
		"--region", "fsn1",
		"--server-type", "cx22",
		"--toolbox", "iran-default",
		"--families", "vless-reality,hysteria2",
		"--helper-ip", "1.2.3.4",
		"--dry-run",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	var rec provider.OperatorRecord
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatalf("unmarshal: %v\nstdout: %s", err, stdout.String())
	}
	if rec.Provider != "hetzner" {
		t.Errorf("Provider = %q want hetzner", rec.Provider)
	}
	if rec.Region != "fsn1" {
		t.Errorf("Region = %q want fsn1", rec.Region)
	}
	if !strings.HasPrefix(rec.ServerID, "dry-run-") {
		t.Errorf("ServerID = %q; want dry-run-*", rec.ServerID)
	}
	if len(rec.Candidates) == 0 {
		t.Errorf("Candidates empty")
	}
	if len(rec.Candidates) != 2 {
		t.Errorf("Candidates = %d want 2 from --families filter", len(rec.Candidates))
	}
}

func TestProvision_RejectsBadPubkeyLength(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	if err := os.WriteFile(pubFile, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--helper-ip", "1.2.3.4",
		"--dry-run",
	}, &stdout, &stderr)
	if rc != 1 {
		t.Errorf("rc=%d want 1", rc)
	}
	if !strings.Contains(stderr.String(), "want 32 bytes") {
		t.Errorf("expected size error; got: %s", stderr.String())
	}
}

func TestProvision_RejectsBadHelperIP(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = os.WriteFile(pubFile, pub, 0o600)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--helper-ip", "not-an-ip",
		"--dry-run",
	}, &stdout, &stderr)
	if rc != 1 {
		t.Errorf("rc=%d want 1", rc)
	}
	if !strings.Contains(stderr.String(), "invalid --helper-ip") {
		t.Errorf("expected helper-ip error; got: %s", stderr.String())
	}
}

func TestProvision_OWritesFileNotStdout(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	outFile := filepath.Join(tmp, "rec.json")
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = os.WriteFile(pubFile, pub, 0o600)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--helper-ip", "1.2.3.4",
		"--dry-run",
		"-o", outFile,
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty when -o is set; got %s", stdout.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not written: %v", err)
	}
}

func TestProvision_RequiresTokenWhenLive(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = os.WriteFile(pubFile, pub, 0o600)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--helper-ip", "1.2.3.4",
		// no --dry-run, no --token-file
	}, &stdout, &stderr)
	if rc != 1 {
		t.Errorf("rc=%d want 1", rc)
	}
	if !strings.Contains(stderr.String(), "--token-file required") {
		t.Errorf("expected token-required error; got: %s", stderr.String())
	}
}

func TestPricing_AcceptsRegionServerTypeShape(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"pricing",
		"--provider", "hetzner",
		"--region", "fsn1",
		"--server-type", "cx22",
		// no token: this test pins flag shape only; FRP-5 supplies token live.
	}, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc=%d want 2 for missing token", rc)
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Errorf("pricing FRP-5 flag shape not accepted: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--token-file") {
		t.Errorf("expected token-required error; got: %s", stderr.String())
	}
}

func TestVerify_AcceptsDryRunRecord(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	recFile := filepath.Join(tmp, "rec.json")
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = os.WriteFile(pubFile, pub, 0o600)

	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--helper-ip", "1.2.3.4",
		"--dry-run",
		"-o", recFile,
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("provision rc=%d stderr=%s", rc, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	rc = Run([]string{"verify", "--record-file", recFile}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("verify rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"ok":true`) {
		t.Errorf("verify output = %q", stdout.String())
	}
}

// FRP-7: rotate-recommend driven from a stub OperatorRecord +
// stdin Explanation JSON. Asserts the command emits a JSON
// recommendation with the expected level + V1.5 wallclock.
func TestRotateRecommend_FromExplanation_TCPReset_L3(t *testing.T) {
	tmp := t.TempDir()
	rec := provider.OperatorRecord{
		Provider:     "hetzner",
		ServerID:     "srv-1",
		ServerType:   "cpx21",
		Region:       "fsn1",
		FloatingIPID: "fip-1",
	}
	body, _ := json.Marshal(rec)
	recFile := filepath.Join(tmp, "rec.json")
	_ = os.WriteFile(recFile, body, 0o600)

	stdin := bytes.NewBufferString(`{
        "pick": {"exposure_mode":"direct_vps"},
        "failures":[{"classification":"tcp_reset","tag":"public_ip:198.51.100.10"}],
        "active_cooldowns":[{"tag":"public_ip:198.51.100.10","reason":"tcp_reset"}],
        "phase":"V1.5"
    }`)
	var stdout, stderr bytes.Buffer
	rc := runRotateRecommend([]string{"--record-file", recFile}, stdin, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rotate-recommend rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"level": "L3"`) {
		t.Errorf("expected L3; got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"est_wallclock": "~10s"`) {
		t.Errorf("expected ~10s wallclock; got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"confidence": "high"`) {
		t.Errorf("expected high confidence (Explanation source); got %s", stdout.String())
	}
}

func TestRotateRecommend_ContextOnly_CapsAtMedium(t *testing.T) {
	tmp := t.TempDir()
	rec := provider.OperatorRecord{
		Provider:   "hetzner",
		ServerID:   "srv-1",
		ServerType: "cpx21",
		Region:     "fsn1",
	}
	body, _ := json.Marshal(rec)
	recFile := filepath.Join(tmp, "rec.json")
	_ = os.WriteFile(recFile, body, 0o600)

	var stdout, stderr bytes.Buffer
	rc := runRotateRecommend([]string{
		"--record-file", recFile,
		"--context-only",
		"--classification", "sni_rst",
	}, bytes.NewBuffer(nil), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rotate-recommend ctx rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"level": "L2"`) {
		t.Errorf("expected L2 from sni_rst; got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"confidence": "medium"`) {
		t.Errorf("expected medium (context cap); got %s", stdout.String())
	}
}

func TestRotateRecommend_Run_DispatchesSubcommand(t *testing.T) {
	// Smoke: the Run() entry point dispatches "rotate-recommend"
	// to runRotateRecommend (covers the switch case wiring).
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"rotate-recommend"}, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("expected rc=2 for missing --record-file; got %d", rc)
	}
	if !strings.Contains(stderr.String(), "--record-file") {
		t.Errorf("expected --record-file required error; got %s", stderr.String())
	}
}

// --- decommission: the JSON contract the wizard's DestroyReport
// --- deserialises. Field names and the always-present `warnings`
// --- array are load-bearing; changing them breaks the Rust shim.

// fakeTeardownProvider is a providerFace whose only interesting
// method is Decommission. Injected through buildProviderFn so the
// contract can be asserted without a live cloud token.
type fakeTeardownProvider struct {
	providerFace // nil: any other method call panics, which is the point
	report       *provider.DecommissionReport
	err          error
}

func (f *fakeTeardownProvider) Decommission(_ context.Context, _ *provider.OperatorRecord) (*provider.DecommissionReport, error) {
	return f.report, f.err
}

func withFakeProvider(t *testing.T, p providerFace) {
	t.Helper()
	prev := buildProviderFn
	buildProviderFn = func(string, string, bool) (providerFace, error) { return p, nil }
	t.Cleanup(func() { buildProviderFn = prev })
}

func writeDecommissionFixture(t *testing.T) (recordFile, tokenFile string) {
	t.Helper()
	tmp := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	rec := provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "12345",
		ServerType:      "cx22",
		Region:          "fsn1",
		PublisherPubKey: pub,
	}
	body, _ := json.Marshal(rec)
	recordFile = filepath.Join(tmp, "rec.json")
	tokenFile = filepath.Join(tmp, "tok")
	if err := os.WriteFile(recordFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("dummy-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return recordFile, tokenFile
}

func TestDecommission_EmitsPerResourceJSONReport(t *testing.T) {
	rep := provider.NewDecommissionReport("hetzner", "12345")
	rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
	rep.DeletedSSHKeyIDs = []string{"678"}
	rep.FirewallID = "910"
	withFakeProvider(t, &fakeTeardownProvider{report: rep})

	recordFile, tokenFile := writeDecommissionFixture(t)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}

	// Assert on the raw keys, not the round-tripped struct: the Rust
	// side reads these names.
	var wire map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	for _, k := range []string{"server_deleted", "ssh_key_deleted", "firewall_deleted", "warnings"} {
		if _, ok := wire[k]; !ok {
			t.Errorf("missing required field %q in %s", k, stdout.String())
		}
	}
	if wire["server_deleted"] != true || wire["ssh_key_deleted"] != true || wire["firewall_deleted"] != true {
		t.Errorf("booleans wrong: %s", stdout.String())
	}
	if w, ok := wire["warnings"].([]any); !ok || len(w) != 0 {
		t.Errorf("warnings must be an empty array, never null: %s", stdout.String())
	}
	if wire["server_id"] != "12345" {
		t.Errorf("server_id = %v", wire["server_id"])
	}
}

// The Rust bridge (cli_bridge.rs `run_decommission`) sends `--json` on
// the first attempt and only retries without it when the binary exits 2
// on a flag-parse failure. If this flag is ever dropped, that retry
// becomes the normal path: every teardown runs the verb twice and the
// second run is read through the legacy branch, which reports the SSH
// key and the firewall as unconfirmed even when they were deleted.
// Nothing else would fail, which is exactly why this needs a test.
func TestDecommission_AcceptsJSONFlag(t *testing.T) {
	rep := provider.NewDecommissionReport("hetzner", "12345")
	rep.ServerDeleted, rep.SSHKeyDeleted, rep.FirewallDeleted = true, true, true
	withFakeProvider(t, &fakeTeardownProvider{report: rep})

	recordFile, tokenFile := writeDecommissionFixture(t)
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile, "--json"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("--json must be accepted, got rc=%d stderr=%s", rc, stderr.String())
	}
	var wire map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if wire["server_deleted"] != true {
		t.Errorf("server_deleted = %v", wire["server_deleted"])
	}
}

func TestDecommission_PartialTeardownIsStillReported(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*provider.DecommissionReport)
		err        error
		wantRC     int
		wantServer bool
	}{
		{
			name: "warnings only: exit 0, resources named",
			mutate: func(r *provider.DecommissionReport) {
				r.ServerDeleted, r.FirewallDeleted = true, true
				r.Warnf("could not delete SSH key %q: 503", "daal-fsn1-aa-ephemeral")
				r.Preserve("ssh-key:daal-fsn1-aa-ephemeral")
			},
			wantRC:     0,
			wantServer: true,
		},
		{
			name: "server survived: exit 1, report still on stdout",
			mutate: func(r *provider.DecommissionReport) {
				r.Warnf("could not delete server 12345: 503")
				r.Preserve("server:12345")
			},
			err:        errors.New("hetzner: delete server 12345: 503"),
			wantRC:     1,
			wantServer: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := provider.NewDecommissionReport("hetzner", "12345")
			tc.mutate(rep)
			withFakeProvider(t, &fakeTeardownProvider{report: rep, err: tc.err})

			recordFile, tokenFile := writeDecommissionFixture(t)
			var stdout, stderr bytes.Buffer
			rc := Run([]string{"decommission", "--record-file", recordFile, "--token-file", tokenFile}, &stdout, &stderr)
			if rc != tc.wantRC {
				t.Fatalf("rc=%d want %d; stderr=%s", rc, tc.wantRC, stderr.String())
			}
			var wire map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil {
				t.Fatalf("a partial teardown must still print its report: %v\n%s", err, stdout.String())
			}
			if wire["server_deleted"] != tc.wantServer {
				t.Errorf("server_deleted = %v want %v", wire["server_deleted"], tc.wantServer)
			}
			if w, _ := wire["warnings"].([]any); len(w) == 0 {
				t.Errorf("a partial teardown must carry warnings: %s", stdout.String())
			}
			if p, _ := wire["preserved"].([]any); len(p) == 0 {
				t.Errorf("a survivor must be listed in preserved: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), "decommission") {
				t.Errorf("stderr should explain the partial teardown; got %q", stderr.String())
			}
		})
	}
}

func TestDecommission_RequiresRecordAndToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{"decommission"}, &stdout, &stderr)
	if rc != 2 {
		t.Errorf("rc=%d want 2 for missing flags", rc)
	}
	for _, want := range []string{"--record-file", "--token-file"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("expected %s in %q", want, stderr.String())
		}
	}
}

func TestProvision_AcceptsRollbackOnFailureFlag(t *testing.T) {
	tmp := t.TempDir()
	pubFile := filepath.Join(tmp, "pub")
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--helper-ip", "1.2.3.4",
		"--rollback-on-failure",
		"--dry-run",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Errorf("--rollback-on-failure not accepted: %s", stderr.String())
	}
}
