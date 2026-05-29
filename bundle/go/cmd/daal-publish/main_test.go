package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSubkeyRotateCLI is a smoke test for the FRP-7.5
// `daal-publish subkey rotate` subcommand. It captures stdout
// from the JSON form and asserts the wizard-facing contract:
//
//   - Exit 0 when --root-priv + --out-dir are valid.
//   - JSON line carries every keystore-path field +
//     valid_from/valid_until + root + sub-key fingerprints.
func TestSubkeyRotateCLI(t *testing.T) {
	dir := t.TempDir()
	// Bootstrap a root keypair via cmdKeygen.
	if rc := cmdKeygen([]string{"--out-dir", dir, "--label", "test"}); rc != 0 {
		t.Fatalf("keygen exited %d", rc)
	}
	rootPriv := filepath.Join(dir, "publisher.priv")

	// Capture stdout.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = pipeW
	rc := cmdSubkey([]string{
		"rotate",
		"--root-priv", rootPriv,
		"--out-dir", dir,
		"--validity", "30d",
		"--label", "smoke",
		"--json",
	})
	pipeW.Close()
	os.Stdout = origStdout
	if rc != 0 {
		t.Fatalf("subkey rotate exited %d", rc)
	}
	body, err := os.ReadFile("/proc/self/fd/0") // not used; we read pipeR
	_ = body
	_ = err

	buf := make([]byte, 4096)
	n, _ := pipeR.Read(buf)
	out := string(buf[:n])

	if !strings.HasPrefix(out, "{") {
		t.Fatalf("expected JSON output, got: %q", out)
	}
	var result struct {
		SubkeyDir      string `json:"subkey_dir"`
		SubkeyPubPath  string `json:"subkey_pub_path"`
		SubkeyPrivPath string `json:"subkey_priv_path"`
		SubkeyCertPath string `json:"subkey_cert_path"`
		SubkeyMetaPath string `json:"subkey_meta_path"`
		ValidFrom      string `json:"valid_from"`
		ValidUntil     string `json:"valid_until"`
		Label          string `json:"label"`
		RootFP         string `json:"root_fingerprint_hex"`
		SubkeyFP       string `json:"subkey_fingerprint_hex"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, out)
	}
	if result.Label != "smoke" {
		t.Errorf("label = %q, want %q", result.Label, "smoke")
	}
	if result.RootFP == "" || len(result.RootFP) != 64 {
		t.Errorf("root_fingerprint_hex bad: %q", result.RootFP)
	}
	if result.SubkeyFP == "" || len(result.SubkeyFP) != 64 {
		t.Errorf("subkey_fingerprint_hex bad: %q", result.SubkeyFP)
	}
	if result.ValidUntil == "" {
		t.Error("valid_until missing")
	}
	// Files must actually exist on disk.
	for _, p := range []string{result.SubkeyPubPath, result.SubkeyPrivPath, result.SubkeyCertPath, result.SubkeyMetaPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file at %s: %v", p, err)
		}
	}
}

// TestSubkeyRotateCLIRequiresFlags asserts the missing-flag
// guard returns the documented exit code.
func TestSubkeyRotateCLIRequiresFlags(t *testing.T) {
	rc := cmdSubkey([]string{"rotate"})
	if rc != 2 {
		t.Errorf("expected exit 2 for missing flags, got %d", rc)
	}
}

// TestSubkeyDefaultDispatchToIssue asserts that
// `daal-publish subkey ...` (no `rotate`) still routes to the
// 1A issue form (regression guard).
func TestSubkeyDefaultDispatchToIssue(t *testing.T) {
	dir := t.TempDir()
	if rc := cmdKeygen([]string{"--out-dir", dir}); rc != 0 {
		t.Fatalf("keygen exited %d", rc)
	}
	rc := cmdSubkey([]string{
		"--root-priv", filepath.Join(dir, "publisher.priv"),
		"--out-dir", dir,
		"--validity", "7d",
		"--label", "issue-form",
	})
	if rc != 0 {
		t.Errorf("issue-form dispatch exited %d, want 0", rc)
	}
	// Find the new subkey dir under dir/subkeys/<fp>/.
	entries, err := os.ReadDir(filepath.Join(dir, "subkeys"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one subkey dir under issue form")
	}
}
