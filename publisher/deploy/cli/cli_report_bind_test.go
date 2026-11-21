package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"daal/bundle-go/bundle"
	"daal/bundle-go/fieldreport"
)

// The app marks a relay as the Test relay by signing with
// `--report-to`: every route of the pack then carries `_report_to`.
func TestBindAndSign_ReportToFlag(t *testing.T) {
	recPath, privPath, _, _ := mkBindFixture(t)
	var pub [32]byte
	pub[31] = 9
	addr := fieldreport.EncodeAddress(pub)
	out := filepath.Join(t.TempDir(), "rp.sbp")
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"bind-and-sign",
		"--operator-record", recPath,
		"--priv-key", privPath,
		"--output", out,
		"--phase", testPhase,
		"--now-unix", "1746115200",
		"--report-to", addr,
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("ParseSBP: %v", err)
	}
	if len(b.Manifest.Routes) == 0 {
		t.Fatal("no routes")
	}
	for _, r := range b.Manifest.Routes {
		var fc map[string]any
		if err := json.Unmarshal(r.FamilySpecificConfig, &fc); err != nil {
			t.Fatal(err)
		}
		if fc["_report_to"] != addr {
			t.Fatalf("route %s: _report_to = %v", r.ID, fc["_report_to"])
		}
	}

	// A malformed address is refused, not signed.
	stdout.Reset()
	stderr.Reset()
	rc = Run([]string{
		"bind-and-sign",
		"--operator-record", recPath,
		"--priv-key", privPath,
		"--output", filepath.Join(t.TempDir(), "bad.sbp"),
		"--phase", testPhase,
		"--now-unix", "1746115200",
		"--report-to", "daal1nope",
	}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("a bad --report-to was signed")
	}
}
