package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"daal/publisher/deploy/health"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/phase"
	"daal/publisher/deploy/mgmt"
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
        "phase":"` + string(phase.Current) + `"
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
		// The L3 verbs need an address the relay currently ANSWERS on:
		// the bind request has to travel over it, since the address it
		// is bringing up is by definition not yet answering. A fixture
		// without one exercised a path no real record can be in.
		PublicIP:           net.ParseIP("198.51.100.7"),
		MgmtPort:           8443,
		MgmtTLSFingerprint: strings.Repeat("ab", 32),
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

// --- floating-ip: the L3 rung's CLI surface ------------------------

// fakeFIPProvider is a providerFace that also reserves and releases
// addresses, i.e. the post-Step-9 Hetzner shape.
type fakeFIPProvider struct {
	providerFace // nil: any other method call panics, which is the point
	assigned     []string
	created      int
	released     []string
	releaseOwned bool
	assignErr    error
	newIP        string
	idOnly       bool

	// box, when set, makes this provider log its calls into the SAME
	// sequence the box stubs use. The L3 ordering assertions are about
	// cloud calls and box calls interleaved — "attach before bind",
	// "unbind before release" — and two separate lists cannot express
	// that.
	box *fakeBox
}

func (f *fakeFIPProvider) log(s string) {
	if f.box != nil {
		f.box.calls = append(f.box.calls, s)
	}
}

func (f *fakeFIPProvider) AssignFloatingIP(_ context.Context, rec *provider.OperatorRecord, fipID string) error {
	f.log("attach " + fipID)
	f.assigned = append(f.assigned, fipID)
	if f.assignErr != nil {
		return f.assignErr
	}
	rec.FloatingIPID = fipID
	// idOnly models the Vultr and Stark adapters, which record the id
	// and stop. It is not a hypothetical: both ship that way today.
	if f.idOnly {
		return nil
	}
	rec.PublicIP = net.ParseIP(f.newIP)
	for i := range rec.Candidates {
		tags := rec.Candidates[i].PublicRiskTags
		for j, tg := range tags {
			if strings.HasPrefix(tg, "public_ip:") {
				tags[j] = "public_ip:" + f.newIP
			}
		}
		rec.Candidates[i].PublicRiskTags = tags
	}
	return nil
}

func (f *fakeFIPProvider) UnassignFloatingIP(_ context.Context, rec *provider.OperatorRecord) error {
	f.log("detach")
	rec.FloatingIPID = ""
	// A real adapter puts the record back on the server's own primary
	// address; without that the unbind below would have no working
	// address to travel over.
	rec.PublicIP = net.ParseIP("198.51.100.7")
	return nil
}

func (f *fakeFIPProvider) CreateFloatingIP(_ context.Context, _ *provider.OperatorRecord) (string, net.IP, error) {
	f.log("reserve")
	f.created++
	return "fip-reserved", net.ParseIP(f.newIP), nil
}

func (f *fakeFIPProvider) ReleaseFloatingIP(_ context.Context, _ *provider.OperatorRecord, id string) (bool, error) {
	f.log("release " + id)
	f.released = append(f.released, id)
	return f.releaseOwned, nil
}

// --fip-id used to be mandatory, which put the whole L3 rung behind an
// address the operator had to reserve by hand in the provider console
// plus a numeric id no screen asks for.
func TestAssignFIP_WithoutAnIDReservesOne(t *testing.T) {
	withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if f.created != 1 {
		t.Errorf("CreateFloatingIP calls = %d, want 1", f.created)
	}
	if len(f.assigned) != 1 || f.assigned[0] != "fip-reserved" {
		t.Errorf("assigned = %v, want [fip-reserved]", f.assigned)
	}
	// The written-back record must carry the NEW address, or the pack
	// signed from it points straight back at the burned one.
	body, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("record is not JSON: %v\n%s", err, body)
	}
	if wire["public_ip"] != "203.0.113.5" {
		t.Errorf("record public_ip = %v, want 203.0.113.5 — the swap left the burned address in the record", wire["public_ip"])
	}
	if wire["floating_ip_id"] != "fip-reserved" {
		t.Errorf("record floating_ip_id = %v, want fip-reserved", wire["floating_ip_id"])
	}
}

// An address minted seconds ago that could not be attached is a billing
// resource with no purpose — the same leak class as an orphaned server.
func TestAssignFIP_ReservedAddressIsReturnedWhenTheAttachFails(t *testing.T) {
	withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, assignErr: errors.New("cloud says no")}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("a failed attach must not exit 0")
	}
	if len(f.released) != 1 || f.released[0] != "fip-reserved" {
		t.Errorf("released = %v, want the reserved address handed back", f.released)
	}
}

// `unassign` detaches; the address stays reserved and keeps billing.
// `release` gives it back — but only when daal-deploy created it, and
// it says so out loud when it did not.
func TestFloatingIPRelease_ReportsAnAddressItMayNotDelete(t *testing.T) {
	withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: false}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	// --fip-address is how an id the record does not name is resolved to
	// something the BOX understands. Without it the release refuses (see
	// TestFloatingIPRelease_RefusesWhenTheAddressCannotBeResolved),
	// because releasing an address a live relay may still hold is how a
	// stranger is issued an address this box still answers on.
	rc := Run([]string{"floating-ip", "release", "--record-file", recordFile, "--token-file", tokenFile,
		"--priv-key", keyFile, "--helper-ip", "1.2.3.4", "--fip-id", "fip-theirs",
		"--fip-address", "203.0.113.77"}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "still billing") {
		t.Errorf("an address left reserved must be reported, not passed over: %q", stderr.String())
	}
}

// THE POST-CONDITION, ON THE SEAM THAT ACTUALLY SHIPS.
//
// The live rotation path is the wizard's rotate_execute, whose ONLY
// provider mutation for L3 is this subprocess. A guard that is not here
// is on no path a user can reach — which is why, when Wave 6 deleted
// the caller-less Go executor that also carried this check, the check
// itself stayed (rotation.CheckAddressMoved) and this test with it.
//
// The failure it catches is the one Step 9 exists to end. An adapter
// that records the floating-IP id and stops — Vultr and Stark, by their
// own comments — leaves rec.PublicIP naming the burned address, so the
// verb used to exit 0, the wizard persisted the record, re-signed a
// pack aimed at the address the operator was rotating AWAY from,
// published a freshness document about it, and reported success.
func TestAssignFIP_RefusesWhenTheAddressDidNotMove(t *testing.T) {
	withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, idOnly: true}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)
	before, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc := Run(assignArgs(recordFile, tokenFile, keyFile, "--fip-id", "fip-42"), &stdout, &stderr)
	if rc == 0 {
		t.Fatal("an adapter that attaches the address without moving the record onto it exited 0; " +
			"the caller would now re-sign a pack pointing at the burned address")
	}
	if !strings.Contains(stderr.String(), "without moving the record") {
		t.Errorf("the refusal does not name the problem: %q", stderr.String())
	}
	// Nothing is written back on the failing path, so nothing
	// downstream can persist or sign a half-applied swap.
	after, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the record was rewritten despite the refusal")
	}
}

// An address minted for a swap that then fails its post-condition is
// the same leak as one that failed to attach: give it back.
func TestAssignFIP_ReservedAddressIsReturnedWhenThePostConditionFails(t *testing.T) {
	withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true, idOnly: true}
	withFakeProvider(t, f)
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	if rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr); rc == 0 {
		t.Fatal("expected a refusal")
	}
	if len(f.released) != 1 || f.released[0] != "fip-reserved" {
		t.Errorf("released = %v, want the address we had just reserved", f.released)
	}
}

// withReachableL3Address stubs the post-swap reachability probe. The fakes
// hand back documentation addresses (203.0.113.0/24) that nothing answers
// on, so without this every assign-fip test would sit through a real dial
// timeout and then correctly fail. Tests that care about the UNREACHABLE
// path stub it the other way — see TestAssignFIP_RefusesAnAddressThatDoesNotServe.
func withReachableL3Address(t *testing.T) {
	t.Helper()
	prev := l3AddressServes
	l3AddressServes = func(net.IP, int, time.Duration) error { return nil }
	t.Cleanup(func() { l3AddressServes = prev })
}

// --- the box half of an L3 swap -----------------------------------
//
// Since the guest-OS fix, assign-fip is not a pure cloud-API verb: it
// probes what the relay can do, then tells it to configure the address
// on its interface. Both calls open a cloud firewall window and dial a
// TLS-pinned box, so every test stubs them — and the ordering they
// record is what the new tests assert on.

// fakeBox records what the CLI asked the relay to do, in order.
type fakeBox struct {
	caps      *mgmt.BoxCapabilities
	capsErr   error
	bindErr   error
	unbindErr error

	// calls is the sequence of box+probe operations, appended in the
	// order the CLI performed them. "bind 203.0.113.5" etc.
	calls []string
	// bound/unbound are the (control, target) pairs, so a test can
	// prove the request travelled over an address the box answers on.
	bound   [][2]string
	unbound [][2]string
}

func newFakeBox() *fakeBox {
	return &fakeBox{caps: &mgmt.BoxCapabilities{
		OK:             true,
		MgmtAPIVersion: mgmt.MgmtAPIVersionAddressBinding,
		Capabilities:   []string{mgmt.CapRotateCredentialsScoped, mgmt.CapRotateTLSScoped, mgmt.CapBindAddress},
	}}
}

// withFakeBox installs the box stubs and returns the recorder. The
// reachability probe is recorded through the same list so "bind before
// probe" is one assertion on one slice rather than two clocks.
func withFakeBox(t *testing.T, b *fakeBox) *fakeBox {
	t.Helper()
	prevCaps, prevBind, prevUnbind, prevServes := l3BoxCapabilities, l3BindAddress, l3UnbindAddress, l3AddressServes
	l3BoxCapabilities = func(_ context.Context, _ provider.Provider, _ *provider.OperatorRecord, _ string) (*mgmt.BoxCapabilities, error) {
		b.calls = append(b.calls, "capabilities")
		return b.caps, b.capsErr
	}
	l3BindAddress = func(_ context.Context, _ provider.Provider, _ *provider.OperatorRecord, _ ed25519.PrivateKey, _ string, controlIP, target net.IP) (*mgmt.BindAddressResp, error) {
		b.calls = append(b.calls, "bind "+target.String())
		b.bound = append(b.bound, [2]string{controlIP.String(), target.String()})
		if b.bindErr != nil {
			return nil, b.bindErr
		}
		return &mgmt.BindAddressResp{IP: target.String(), Persisted: true, Interface: "eth0"}, nil
	}
	l3UnbindAddress = func(_ context.Context, _ provider.Provider, _ *provider.OperatorRecord, _ ed25519.PrivateKey, _ string, controlIP, target net.IP) (*mgmt.UnbindAddressResp, error) {
		b.calls = append(b.calls, "unbind "+target.String())
		b.unbound = append(b.unbound, [2]string{controlIP.String(), target.String()})
		if b.unbindErr != nil {
			return nil, b.unbindErr
		}
		return &mgmt.UnbindAddressResp{IP: target.String(), WasBound: true, Removed: true, PersistenceRemoved: true}, nil
	}
	l3AddressServes = func(ip net.IP, _ int, _ time.Duration) error {
		b.calls = append(b.calls, "probe "+ip.String())
		return nil
	}
	t.Cleanup(func() {
		l3BoxCapabilities, l3BindAddress, l3UnbindAddress, l3AddressServes = prevCaps, prevBind, prevUnbind, prevServes
	})
	return b
}

// writePrivKeyFile drops a publisher private key next to the fixture.
func writePrivKeyFile(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "priv.key")
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// l3Fixture is writeDecommissionFixture plus the signing key the box
// half needs.
func l3Fixture(t *testing.T) (recordFile, tokenFile, keyFile string) {
	t.Helper()
	recordFile, tokenFile = writeDecommissionFixture(t)
	return recordFile, tokenFile, writePrivKeyFile(t, filepath.Dir(recordFile))
}

// assignArgs is the flag set every assign-fip call now needs.
func assignArgs(recordFile, tokenFile, keyFile string, extra ...string) []string {
	return append([]string{"floating-ip", "assign",
		"--record-file", recordFile,
		"--token-file", tokenFile,
		"--priv-key", keyFile,
		"--helper-ip", "1.2.3.4",
	}, extra...)
}

// The 2026-08-17 hardware finding: the provider reports the address
// attached and the guest OS never answers on it. The swap must not be
// committed in that state.
func TestAssignFIP_RefusesAnAddressThatDoesNotServe(t *testing.T) {
	box := withFakeBox(t, newFakeBox())
	f := &fakeFIPProvider{newIP: "203.0.113.5", releaseOwned: true}
	withFakeProvider(t, f)
	prev := l3AddressServes
	l3AddressServes = func(ip net.IP, _ int, _ time.Duration) error {
		box.calls = append(box.calls, "probe "+ip.String())
		return fmt.Errorf("%w: %s is dead", health.ErrAddressUnreachable, ip)
	}
	t.Cleanup(func() { l3AddressServes = prev })
	recordFile, tokenFile, keyFile := l3Fixture(t)

	var stdout, stderr bytes.Buffer
	rc := Run(assignArgs(recordFile, tokenFile, keyFile), &stdout, &stderr)
	if rc == 0 {
		t.Fatalf("an unreachable address must not be committed; rc=0 stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not serve") {
		t.Errorf("stderr should name the reachability failure, got %q", stderr.String())
	}
}
