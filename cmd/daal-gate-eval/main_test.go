package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gateTemplate mirrors the real FRP-13 gate shape: the closed six
// supplement §17.2 conditions plus the closed five supplement §22.4
// thresholds. Tests intentionally avoid reduced dummy specs so the
// parser cannot regress into accepting underspecified gates.
const gateTemplate = `
gate_id: daal-public-directory-gate-v1
prerequisite:
  cell_closure_doc: SUBSTITUTE_CLOSURE_PATH
  required_status:  SHIPPED
conditions:
  - id: sybil_spam_absent
    statement: "Sybil spam absent or trivially recoverable across at least 90 days of cell-only operation."
    evidence_required: "operational log"
    status: %SYBIL_STATUS%
    evidence: %SYBIL_EVIDENCE%
  - id: poisoned_relaypack_mttr_under_24h
    statement: "Poisoned-RelayPack incidents detected and revoked in <24 hours."
    evidence_required: "incident log"
    status: %POISON_STATUS%
    evidence: %POISON_EVIDENCE%
  - id: cloud_provider_takedown_survived
    statement: "Cloud-provider takedowns survived without user-side outage."
    evidence_required: "incident reports"
    status: %TAKEDOWN_STATUS%
    evidence: %TAKEDOWN_EVIDENCE%
  - id: social_engineering_caught
    statement: "Social-engineering attempts on cell admins caught."
    evidence_required: "red-team reports"
    status: %SOCIAL_STATUS%
    evidence: %SOCIAL_EVIDENCE%
  - id: fake_helper_malware_closed
    statement: "Fake-helper malware vector closed via reproducible-build + signature-verification UX."
    evidence_required: "external audit"
    status: %MALWARE_STATUS%
    evidence: %MALWARE_EVIDENCE%
  - id: metadata_leak_audit_clean
    statement: "Metadata-leakage audit shows no per-recipient identifiable data."
    evidence_required: "external audit"
    status: %METADATA_STATUS%
    evidence: %METADATA_EVIDENCE%
success_metric:
  blackout_documented_by: ["OONI"]
  thresholds:
    - id: active_frps
      statement: "At least 1,000 active FRPs."
      threshold: 1000
      observed: %ACTIVE_FRPS_OBS%
      status: %ACTIVE_FRPS_STATUS%
    - id: frps_in_cells_pct
      statement: "At least 30% of FRPs are in cells."
      threshold_pct: 30
      observed_pct: %FRPS_IN_CELLS_OBS%
      status: %FRPS_IN_CELLS_STATUS%
    - id: cells_in_directory_pct
      statement: "At least 10% of cells are opted into the public directory."
      threshold_pct: 10
      observed_pct: %CELLS_IN_DIRECTORY_OBS%
      status: %CELLS_IN_DIRECTORY_STATUS%
    - id: avg_relaypack_burn_days
      statement: "Directory's average per-RelayPack burn lifetime is at least 7 days."
      threshold_days: 7
      observed_days: %BURN_DAYS_OBS%
      status: %BURN_DAYS_STATUS%
    - id: directory_key_transparency_log
      statement: "Project directory-key signing operations are auditable in a public log."
      threshold: "non-empty transparency_log_url field on every signing operation"
      observed_url: %TRANSPARENCY_URL%
      status: %TRANSPARENCY_STATUS%
`

// writeGate writes a gate spec markdown file to dir, substituting
// the supplied placeholders.
func writeGate(t *testing.T, dir string, vals map[string]string) string {
	t.Helper()
	body := gateTemplate
	for k, v := range vals {
		body = strings.ReplaceAll(body, k, v)
	}
	return writeRawGate(t, dir, body)
}

func writeRawGate(t *testing.T, dir string, yamlBody string) string {
	t.Helper()
	full := "# gate\n```yaml\n" + yamlBody + "\n```\n"
	path := filepath.Join(dir, "gate.md")
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatalf("write gate: %v", err)
	}
	return path
}

// writeClosure writes a cell-closure markdown file to dir with the
// supplied status token.
func writeClosure(t *testing.T, dir string, status string) string {
	t.Helper()
	body := fmt.Sprintf("# Cell closure\n\n**Status**: %s. Pending pilot.\n", status)
	path := filepath.Join(dir, "closure.md")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write closure: %v", err)
	}
	return path
}

// runCLI invokes run() with --gate / --closure overrides and
// returns the exit code + captured stdout.
func runCLI(t *testing.T, gatePath, closurePath string, extraArgs ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"--gate", gatePath,
		"--closure", closurePath,
	}, extraArgs...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run(args, stdout, stderr)
	return code, stdout.String(), stderr.String()
}

// vals constructs the substitution map with all-HOLD defaults that
// individual tests override.
func vals() map[string]string {
	return map[string]string{
		"%SYBIL_STATUS%":              "HOLD",
		"%SYBIL_EVIDENCE%":            "TBD",
		"%POISON_STATUS%":             "HOLD",
		"%POISON_EVIDENCE%":           "TBD",
		"%TAKEDOWN_STATUS%":           "HOLD",
		"%TAKEDOWN_EVIDENCE%":         "TBD",
		"%SOCIAL_STATUS%":             "HOLD",
		"%SOCIAL_EVIDENCE%":           "TBD",
		"%MALWARE_STATUS%":            "HOLD",
		"%MALWARE_EVIDENCE%":          "TBD",
		"%METADATA_STATUS%":           "HOLD",
		"%METADATA_EVIDENCE%":         "TBD",
		"%ACTIVE_FRPS_OBS%":           "null",
		"%ACTIVE_FRPS_STATUS%":        "HOLD",
		"%FRPS_IN_CELLS_OBS%":         "null",
		"%FRPS_IN_CELLS_STATUS%":      "HOLD",
		"%CELLS_IN_DIRECTORY_OBS%":    "null",
		"%CELLS_IN_DIRECTORY_STATUS%": "HOLD",
		"%BURN_DAYS_OBS%":             "null",
		"%BURN_DAYS_STATUS%":          "HOLD",
		"%TRANSPARENCY_URL%":          "null",
		"%TRANSPARENCY_STATUS%":       "HOLD",
	}
}

func allPassVals() map[string]string {
	v := vals()
	for _, key := range []string{
		"%SYBIL_STATUS%",
		"%POISON_STATUS%",
		"%TAKEDOWN_STATUS%",
		"%SOCIAL_STATUS%",
		"%MALWARE_STATUS%",
		"%METADATA_STATUS%",
		"%ACTIVE_FRPS_STATUS%",
		"%FRPS_IN_CELLS_STATUS%",
		"%CELLS_IN_DIRECTORY_STATUS%",
		"%BURN_DAYS_STATUS%",
		"%TRANSPARENCY_STATUS%",
	} {
		v[key] = "PASS"
	}
	for _, key := range []string{
		"%SYBIL_EVIDENCE%",
		"%POISON_EVIDENCE%",
		"%TAKEDOWN_EVIDENCE%",
		"%SOCIAL_EVIDENCE%",
		"%MALWARE_EVIDENCE%",
		"%METADATA_EVIDENCE%",
	} {
		v[key] = `"https://audit.example/evidence.md"`
	}
	v["%ACTIVE_FRPS_OBS%"] = "1500"
	v["%FRPS_IN_CELLS_OBS%"] = "42"
	v["%CELLS_IN_DIRECTORY_OBS%"] = "12"
	v["%BURN_DAYS_OBS%"] = "8"
	v["%TRANSPARENCY_URL%"] = `"https://transparency.example/log.json"`
	return v
}

func TestParse_GateSpecLoadsCorrectly(t *testing.T) {
	dir := t.TempDir()
	gp := writeGate(t, dir, vals())
	g, err := loadGateSpec(gp)
	if err != nil {
		t.Fatalf("loadGateSpec: %v", err)
	}
	if g.GateID != "daal-public-directory-gate-v1" {
		t.Errorf("gate_id = %q", g.GateID)
	}
	if len(g.Conditions) != 6 {
		t.Errorf("conditions len = %d", len(g.Conditions))
	}
	if len(g.SuccessMetric.Thresholds) != 5 {
		t.Errorf("thresholds len = %d", len(g.SuccessMetric.Thresholds))
	}
}

func TestParse_MissingRequiredConditionRejected(t *testing.T) {
	dir := t.TempDir()
	raw := `
gate_id: daal-public-directory-gate-v1
prerequisite:
  cell_closure_doc: specs/cell-closure-v1.md
  required_status: SHIPPED
conditions:
  - id: sybil_spam_absent
    statement: "A"
    evidence_required: "x"
    status: HOLD
    evidence: TBD
success_metric:
  thresholds:
    - id: active_frps
      threshold: 1000
      observed: null
      status: HOLD
    - id: frps_in_cells_pct
      threshold_pct: 30
      observed_pct: null
      status: HOLD
    - id: cells_in_directory_pct
      threshold_pct: 10
      observed_pct: null
      status: HOLD
    - id: avg_relaypack_burn_days
      threshold_days: 7
      observed_days: null
      status: HOLD
    - id: directory_key_transparency_log
      threshold: "non-empty"
      observed_url: null
      status: HOLD
`
	gp := writeRawGate(t, dir, raw)
	if _, err := loadGateSpec(gp); err == nil || !strings.Contains(err.Error(), "missing required §17.2 condition") {
		t.Fatalf("loadGateSpec err = %v, want missing required condition", err)
	}
}

func TestParse_InvalidStatusRejected(t *testing.T) {
	dir := t.TempDir()
	v := vals()
	v["%SYBIL_STATUS%"] = "PAS"
	gp := writeGate(t, dir, v)
	if _, err := loadGateSpec(gp); err == nil || !strings.Contains(err.Error(), "invalid status") {
		t.Fatalf("loadGateSpec err = %v, want invalid status", err)
	}
}

func TestParse_MalformedThresholdDefinitionRejected(t *testing.T) {
	dir := t.TempDir()
	v := vals()
	v["%ACTIVE_FRPS_OBS%"] = "1500"
	// The observed value alone is not enough. The gate spec must
	// carry the locked numeric threshold definition too.
	raw := strings.ReplaceAll(gateTemplate, "      threshold: 1000\n      observed: %ACTIVE_FRPS_OBS%", "      observed: %ACTIVE_FRPS_OBS%")
	for k, val := range v {
		raw = strings.ReplaceAll(raw, k, val)
	}
	gp := writeRawGate(t, dir, raw)
	if _, err := loadGateSpec(gp); err == nil || !strings.Contains(err.Error(), "threshold active_frps malformed") {
		t.Fatalf("loadGateSpec err = %v, want malformed threshold", err)
	}
}

func TestVerdict_AllHoldExits1(t *testing.T) {
	dir := t.TempDir()
	gp := writeGate(t, dir, vals())
	cp := writeClosure(t, dir, "HOLD")
	code, out, _ := runCLI(t, gp, cp)
	if code != 1 {
		t.Errorf("exit=%d, want 1; out=%s", code, out)
	}
	if !strings.Contains(out, "Gate verdict: HOLD") {
		t.Errorf("expected HOLD verdict in output, got %s", out)
	}
}

func TestVerdict_AllPassExits0(t *testing.T) {
	dir := t.TempDir()
	gp := writeGate(t, dir, allPassVals())
	cp := writeClosure(t, dir, "SHIPPED")
	code, out, _ := runCLI(t, gp, cp)
	if code != 0 {
		t.Errorf("exit=%d, want 0; out=%s", code, out)
	}
	if !strings.Contains(out, "Gate verdict: PASS") {
		t.Errorf("expected PASS verdict, got %s", out)
	}
}

func TestVerdict_MixedHoldExits1WithReason(t *testing.T) {
	dir := t.TempDir()
	v := vals()
	v["%SYBIL_STATUS%"] = "PASS"
	v["%SYBIL_EVIDENCE%"] = `"https://audit.example/sybil.md"`
	// poisoned_relaypack_mttr_under_24h stays HOLD; the rest stays HOLD.
	gp := writeGate(t, dir, v)
	cp := writeClosure(t, dir, "SHIPPED")
	code, out, _ := runCLI(t, gp, cp)
	if code != 1 {
		t.Errorf("exit=%d, want 1; out=%s", code, out)
	}
	if !strings.Contains(out, "Gate verdict: HOLD") {
		t.Errorf("verdict want HOLD, got %s", out)
	}
	if !strings.Contains(out, "poisoned_relaypack_mttr_under_24h") {
		t.Errorf("expected poisoned_relaypack_mttr_under_24h mentioned in output: %s", out)
	}
}

func TestVerdict_CellClosureHoldOverridesAllPass(t *testing.T) {
	dir := t.TempDir()
	gp := writeGate(t, dir, allPassVals())
	// Closure HOLD should pull verdict back to HOLD even though
	// every §17.2 + §22.4 row is PASS.
	cp := writeClosure(t, dir, "HOLD")
	code, out, _ := runCLI(t, gp, cp)
	if code != 1 {
		t.Errorf("exit=%d, want 1; out=%s", code, out)
	}
	if !strings.Contains(out, "Gate verdict: HOLD") {
		t.Errorf("verdict want HOLD due to closure, got %s", out)
	}
}

func TestVerdict_ThresholdBelowRequiredFails(t *testing.T) {
	dir := t.TempDir()
	v := allPassVals()
	v["%ACTIVE_FRPS_OBS%"] = "999"
	gp := writeGate(t, dir, v)
	cp := writeClosure(t, dir, "SHIPPED")
	code, out, _ := runCLI(t, gp, cp)
	if code != 2 {
		t.Errorf("exit=%d, want 2; out=%s", code, out)
	}
	if !strings.Contains(out, "active_frps") || !strings.Contains(out, "below") {
		t.Errorf("expected active_frps below-threshold failure, got %s", out)
	}
}

func TestVerdict_TransparencyURLRequired(t *testing.T) {
	dir := t.TempDir()
	v := allPassVals()
	v["%TRANSPARENCY_URL%"] = "null"
	gp := writeGate(t, dir, v)
	cp := writeClosure(t, dir, "SHIPPED")
	code, out, _ := runCLI(t, gp, cp)
	if code != 2 {
		t.Errorf("exit=%d, want 2; out=%s", code, out)
	}
	if !strings.Contains(out, "directory_key_transparency_log") || !strings.Contains(out, "observed") {
		t.Errorf("expected transparency URL failure, got %s", out)
	}
}

func TestJSONOutput_IsValidAndContainsVerdict(t *testing.T) {
	dir := t.TempDir()
	gp := writeGate(t, dir, vals())
	cp := writeClosure(t, dir, "HOLD")
	code, out, _ := runCLI(t, gp, cp, "--json")
	if code != 1 {
		t.Errorf("exit=%d, want 1", code)
	}
	var rep Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("json invalid: %v\nbody=%s", err, out)
	}
	if rep.Verdict != VerdictHOLD {
		t.Errorf("rep.Verdict = %q, want HOLD", rep.Verdict)
	}
	if len(rep.Conditions) != 6 {
		t.Errorf("rep.Conditions len = %d", len(rep.Conditions))
	}
	if len(rep.Thresholds) != 5 {
		t.Errorf("rep.Thresholds len = %d", len(rep.Thresholds))
	}
}

// TestEvidence_PASSWithoutEvidenceDowngradesToFail covers locked
// invariant 50's anti-vibe enforcement: a status=PASS with empty /
// TBD / null evidence is rejected as FAIL by the CLI.
func TestEvidence_PASSWithoutEvidenceDowngradesToFail(t *testing.T) {
	dir := t.TempDir()
	v := allPassVals()
	v["%SYBIL_EVIDENCE%"] = "TBD" // <-- the anti-vibe trap
	gp := writeGate(t, dir, v)
	cp := writeClosure(t, dir, "SHIPPED")
	code, out, _ := runCLI(t, gp, cp)
	if code != 2 {
		t.Errorf("exit=%d, want 2 (FAIL); out=%s", code, out)
	}
	if !strings.Contains(out, "Gate verdict: FAIL") {
		t.Errorf("verdict want FAIL; got %s", out)
	}
	if !strings.Contains(out, "evidence missing or TBD") {
		t.Errorf("expected evidence-missing reason in output: %s", out)
	}
}
