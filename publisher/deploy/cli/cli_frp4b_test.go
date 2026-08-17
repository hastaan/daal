package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/phase"
	bundlepublisher "daal/bundle-go/publisher"
)

// testPhase is the phase these CLI invocations pass to
// `bind-and-sign`. It is the SHIPPED phase, not a pinned literal: the
// whole class of bug this constant exists to prevent is a test that
// proves the CLI works at a phase production does not use.
var testPhase = string(phase.Current)

// helper: provision a synthetic OperatorRecord on disk plus the
// matching ed25519 keypair (pub-bytes match rec.PublisherPubKey).
func mkBindFixture(t *testing.T) (recPath, privPath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	tmp := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pubFile := filepath.Join(tmp, "pub")
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}

	privPath = filepath.Join(tmp, "priv")
	if err := os.WriteFile(privPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}

	recPath = filepath.Join(tmp, "rec.json")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"provision",
		"--pubkey-file", pubFile,
		"--region", "fsn1",
		"--toolbox-profile", "iran-default",
		"--families", "vless-reality,hysteria2",
		"--helper-ip", "1.2.3.4",
		"--dry-run",
		"-o", recPath,
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("provision rc=%d stderr=%s", rc, stderr.String())
	}
	return
}

// 1. bind-and-sign happy-path: produces .sbp on disk + summary on stdout.
func TestBindAndSign_HappyPath(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	out := filepath.Join(t.TempDir(), "rp.sbp")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"bind-and-sign",
		"--operator-record", recPath,
		"--priv-key", privPath,
		"--output", out,
		"--phase", testPhase,
		"--now-unix", "1746115200",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if st.Size() == 0 {
		t.Fatalf("output .sbp is empty")
	}
	// Stdout JSON must include sbp_sha256 (hex) + relay_pack_id (rp-...)
	var summary map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("stdout not JSON: %v\n%s", err, stdout.String())
	}
	sha, _ := summary["sbp_sha256"].(string)
	if len(sha) != 64 {
		t.Fatalf("sbp_sha256 wrong length: %q", sha)
	}
	if _, err := hex.DecodeString(sha); err != nil {
		t.Fatalf("sbp_sha256 not hex: %v", err)
	}
	rpid, _ := summary["relay_pack_id"].(string)
	if !strings.HasPrefix(rpid, "rp-") {
		t.Fatalf("relay_pack_id missing rp- prefix: %q", rpid)
	}
}

// 2. bind-and-sign deterministic across two runs given --now-unix.
func TestBindAndSign_DeterministicWithNowUnix(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	out1 := filepath.Join(t.TempDir(), "rp1.sbp")
	out2 := filepath.Join(t.TempDir(), "rp2.sbp")
	args := func(out string) []string {
		return []string{
			"bind-and-sign",
			"--operator-record", recPath,
			"--priv-key", privPath,
			"--output", out,
			"--phase", testPhase,
			"--now-unix", "1746115200",
		}
	}
	var so1, se1, so2, se2 bytes.Buffer
	if rc := Run(args(out1), &so1, &se1); rc != 0 {
		t.Fatalf("run1 rc=%d %s", rc, se1.String())
	}
	if rc := Run(args(out2), &so2, &se2); rc != 0 {
		t.Fatalf("run2 rc=%d %s", rc, se2.String())
	}
	a, _ := os.ReadFile(out1)
	b, _ := os.ReadFile(out2)
	if !bytes.Equal(a, b) {
		t.Fatalf("CLI bind-and-sign not deterministic with --now-unix")
	}
}

// 3. bind-and-sign reads privkey from stdin when --priv-key=-.
func TestBindAndSign_PrivKeyFromStdin(t *testing.T) {
	recPath, _, _, priv := mkBindFixture(t)
	out := filepath.Join(t.TempDir(), "rp.sbp")
	var stdout, stderr bytes.Buffer
	// Run() reads stdin from os.Stdin; for bind-and-sign we
	// use the dispatcher path so we exercise the same code path.
	// We simulate stdin by replacing os.Stdin temporarily.
	r, w, _ := os.Pipe()
	go func() {
		defer w.Close()
		_, _ = w.Write(priv)
	}()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()

	rc := Run([]string{
		"bind-and-sign",
		"--operator-record", recPath,
		"--priv-key", "-",
		"--output", out,
		"--phase", testPhase,
		"--now-unix", "1746115200",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	if st, err := os.Stat(out); err != nil || st.Size() == 0 {
		t.Fatalf("output missing/empty: err=%v", err)
	}
}

func TestBindAndSign_SubkeyCertFlag(t *testing.T) {
	recPath, rootPrivPath, _, _ := mkBindFixture(t)
	tmp := t.TempDir()
	sub, err := bundlepublisher.Subkey(bundlepublisher.SubkeyOptions{
		RootPrivPath: rootPrivPath,
		OutDir:       tmp,
		Validity:     90 * 24 * time.Hour,
		Label:        "cli-test-subkey",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "subkey-rp.sbp")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"bind-and-sign",
		"--operator-record", recPath,
		"--priv-key", sub.SubkeyPrivPath,
		"--subkey-cert", sub.SubkeyCertPath,
		"--output", out,
		"--phase", testPhase,
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if parsed.Manifest.SpecVersion != 4 {
		t.Fatalf("spec_version = %d, want 4", parsed.Manifest.SpecVersion)
	}
	if len(parsed.SubkeyCertJSON) == 0 {
		t.Fatal("sub-key bundle missing trust/subkey-cert.json")
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

// 4. bind-and-sign rejects wrong-size privkey from disk.
func TestBindAndSign_RejectsBadPrivKey(t *testing.T) {
	recPath, _, _, _ := mkBindFixture(t)
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad")
	if err := os.WriteFile(bad, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "rp.sbp")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"bind-and-sign",
		"--operator-record", recPath,
		"--priv-key", bad,
		"--output", out,
		"--phase", testPhase,
	}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("rc=%d want 1 stderr=%s", rc, stderr.String())
	}
	if !strings.Contains(stderr.String(), "want 64 bytes") {
		t.Fatalf("expected size error; got %s", stderr.String())
	}
}

// 5. qr-fountain emits N JSON-line frames with valid base64url payloads.
func TestQRFountain_StreamsFrames(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	out := filepath.Join(t.TempDir(), "rp.sbp")
	var stdout, stderr bytes.Buffer
	if rc := Run([]string{
		"bind-and-sign",
		"--operator-record", recPath, "--priv-key", privPath,
		"--output", out, "--phase", testPhase, "--now-unix", "1746115200",
	}, &stdout, &stderr); rc != 0 {
		t.Fatalf("bind-and-sign rc=%d %s", rc, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	rc := Run([]string{
		"qr-fountain", "--sbp", out, "--frames", "5", "--seed", "7",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("qr-fountain rc=%d %s", rc, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("want 5 frames, got %d", len(lines))
	}
	for i, line := range lines {
		var frame map[string]any
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			t.Fatalf("frame %d not JSON: %v", i, err)
		}
		b64, _ := frame["frame_b64"].(string)
		if b64 == "" {
			t.Fatalf("frame %d missing frame_b64", i)
		}
		if _, err := base64.RawURLEncoding.DecodeString(b64); err != nil {
			t.Fatalf("frame %d frame_b64 not valid base64url: %v", i, err)
		}
	}
}

func TestFRP4bSubcommandHelpExitsZero(t *testing.T) {
	for _, sub := range []string{"bind-and-sign", "qr-fountain"} {
		var stdout, stderr bytes.Buffer
		rc := Run([]string{sub, "--help"}, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("%s --help rc=%d stderr=%s", sub, rc, stderr.String())
		}
		if !strings.Contains(stderr.String(), "Usage of "+sub) {
			t.Fatalf("%s --help missing usage text: %s", sub, stderr.String())
		}
	}
}

// 6. provision --progress-json emits step events on stderr.
func TestProvision_ProgressJSONEmitsSteps(t *testing.T) {
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
		"--dry-run",
		"--progress-json",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	// Each line of stderr is a JSON event. We expect at least
	// provision_start, provision_cloud_call, provision_done.
	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // some lines may be human prose; tolerate.
		}
		if step, ok := ev["step"].(string); ok {
			got[step] = true
		}
	}
	for _, want := range []string{"provision_start", "provision_cloud_call", "provision_done"} {
		if !got[want] {
			t.Errorf("missing progress step %q in stderr:\n%s", want, stderr.String())
		}
	}
}
