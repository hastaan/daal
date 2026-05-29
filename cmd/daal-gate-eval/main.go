// Command daal-gate-eval reads specs/public-directory-gate-v1.md
// and specs/cell-closure-v1.md, prints a per-condition status
// table, and exits with one of:
//
//	exit 0 — gate verdict PASS (all six §17.2 conditions PASS, all
//	         five §22.4 thresholds PASS, prerequisite cell closure
//	         SHIPPED, transparency-log URL non-empty).
//	exit 1 — gate verdict HOLD (any condition / threshold HOLD; or
//	         cell-closure HOLD).
//	exit 2 — gate verdict FAIL (any condition / threshold FAIL).
//
// FRP-13 ships this CLI alongside the gate spec. At FRP-13 ship
// every condition reads HOLD, so the CLI exits 1.
//
// Locked invariants (per phase doc 43 + supplement §17.6):
//
//  48. GATED start preserved.
//  49. Acceptable outcome: never ship.
//
// The CLI is the executable enforcement vector: gate verdict is a
// falsifiable yes/no answer instead of a vibe.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// gateSpec mirrors the YAML block in specs/public-directory-gate-v1.md
// §3 exactly. Field tags use yaml v3 conventions.
type gateSpec struct {
	GateID       string `yaml:"gate_id"`
	Prerequisite struct {
		CellClosureDoc string `yaml:"cell_closure_doc"`
		RequiredStatus string `yaml:"required_status"`
	} `yaml:"prerequisite"`
	Conditions    []condition `yaml:"conditions"`
	SuccessMetric struct {
		BlackoutDocumentedBy []string    `yaml:"blackout_documented_by"`
		Thresholds           []threshold `yaml:"thresholds"`
	} `yaml:"success_metric"`
}

type condition struct {
	ID               string `yaml:"id"`
	Statement        string `yaml:"statement"`
	EvidenceRequired string `yaml:"evidence_required"`
	Status           string `yaml:"status"`
	Evidence         string `yaml:"evidence"`
}

// threshold uses an interface-typed Observed because §22.4 mixes
// integer counts, percentages, day-counts, and URL strings.
type threshold struct {
	ID            string      `yaml:"id"`
	Statement     string      `yaml:"statement"`
	Threshold     interface{} `yaml:"threshold,omitempty"`
	ThresholdPct  interface{} `yaml:"threshold_pct,omitempty"`
	ThresholdDays interface{} `yaml:"threshold_days,omitempty"`
	Observed      interface{} `yaml:"observed,omitempty"`
	ObservedPct   interface{} `yaml:"observed_pct,omitempty"`
	ObservedDays  interface{} `yaml:"observed_days,omitempty"`
	ObservedURL   interface{} `yaml:"observed_url,omitempty"`
	Status        string      `yaml:"status"`
}

// closureDoc is the YAML frontmatter shape we read out of
// specs/cell-closure-v1.md. The closure file is markdown with an
// embedded YAML code block; we extract the first ```yaml fenced
// block, fall back to scanning the file body for a "status:" line
// at column 0 (current cell-closure-v1.md uses prose `**Status**`
// rather than YAML — the prose form is matched too).
type closureDoc struct {
	Status string `yaml:"status"`
}

// Verdict is the gate verdict returned to the user.
type Verdict string

const (
	VerdictPASS Verdict = "PASS"
	VerdictHOLD Verdict = "HOLD"
	VerdictFAIL Verdict = "FAIL"
)

var requiredConditionIDs = []string{
	"sybil_spam_absent",
	"poisoned_relaypack_mttr_under_24h",
	"cloud_provider_takedown_survived",
	"social_engineering_caught",
	"fake_helper_malware_closed",
	"metadata_leak_audit_clean",
}

var requiredThresholdIDs = []string{
	"active_frps",
	"frps_in_cells_pct",
	"cells_in_directory_pct",
	"avg_relaypack_burn_days",
	"directory_key_transparency_log",
}

// run is main without os.Exit so tests can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daal-gate-eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoRoot := fs.String("repo", findRepoRoot(), "absolute path to repo root")
	gatePath := fs.String("gate", "", "override gate spec path (default: <repo>/specs/public-directory-gate-v1.md)")
	closurePath := fs.String("closure", "", "override cell-closure path (default: <repo>/specs/cell-closure-v1.md)")
	jsonOut := fs.Bool("json", false, "emit JSON report instead of text table")
	strict := fs.Bool("strict", false, "exit non-zero on FAIL or HOLD (default true; preserved for forward compatibility)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_ = strict // current behaviour is always strict; flag preserved.

	if *gatePath == "" {
		*gatePath = filepath.Join(*repoRoot, "specs", "public-directory-gate-v1.md")
	}
	if *closurePath == "" {
		*closurePath = filepath.Join(*repoRoot, "specs", "cell-closure-v1.md")
	}

	gate, gateErr := loadGateSpec(*gatePath)
	if gateErr != nil {
		fmt.Fprintf(stderr, "error: load gate spec: %v\n", gateErr)
		return 2
	}
	closure, closureErr := loadClosureDoc(*closurePath)
	if closureErr != nil {
		fmt.Fprintf(stderr, "error: load cell-closure: %v\n", closureErr)
		return 2
	}

	report := evaluate(gate, closure)

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		writeText(stdout, report)
	}

	switch report.Verdict {
	case VerdictPASS:
		return 0
	case VerdictFAIL:
		return 2
	default: // HOLD
		return 1
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// findRepoRoot walks up from the current working directory looking
// for the directory containing both `specs/` and `phases of
// development/`. Returns the cwd if nothing matches; the caller can
// override with --repo.
func findRepoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for i := 0; i < 8; i++ {
		if dirExists(filepath.Join(cwd, "specs")) && dirExists(filepath.Join(cwd, "phases of development")) {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			break
		}
		cwd = parent
	}
	c, _ := os.Getwd()
	return c
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// loadGateSpec reads the markdown file, extracts the first ```yaml
// fenced block, and unmarshals it.
func loadGateSpec(path string) (*gateSpec, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	yamlBlock, err := extractFencedYAML(string(body))
	if err != nil {
		return nil, fmt.Errorf("extract yaml block from %s: %w", path, err)
	}
	var spec gateSpec
	if err := yaml.Unmarshal([]byte(yamlBlock), &spec); err != nil {
		return nil, fmt.Errorf("unmarshal yaml in %s: %w", path, err)
	}
	if spec.GateID == "" {
		return nil, fmt.Errorf("gate spec missing gate_id field")
	}
	if spec.GateID != "daal-public-directory-gate-v1" {
		return nil, fmt.Errorf("unexpected gate_id %q", spec.GateID)
	}
	if err := validateGateSpec(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateGateSpec(spec *gateSpec) error {
	if strings.TrimSpace(spec.Prerequisite.CellClosureDoc) == "" {
		return errors.New("gate spec prerequisite.cell_closure_doc is required")
	}
	if !strings.EqualFold(spec.Prerequisite.RequiredStatus, "SHIPPED") {
		return fmt.Errorf("gate spec prerequisite.required_status = %q, want SHIPPED", spec.Prerequisite.RequiredStatus)
	}
	if err := validateConditions(spec.Conditions); err != nil {
		return err
	}
	if err := validateThresholds(spec.SuccessMetric.Thresholds); err != nil {
		return err
	}
	return nil
}

func validateConditions(rows []condition) error {
	seen := map[string]bool{}
	for _, row := range rows {
		if !containsID(requiredConditionIDs, row.ID) {
			return fmt.Errorf("unknown §17.2 condition id %q", row.ID)
		}
		if seen[row.ID] {
			return fmt.Errorf("duplicate §17.2 condition id %q", row.ID)
		}
		seen[row.ID] = true
		if !validGateStatus(row.Status) {
			return fmt.Errorf("condition %s has invalid status %q", row.ID, row.Status)
		}
		if strings.TrimSpace(row.Statement) == "" {
			return fmt.Errorf("condition %s missing statement", row.ID)
		}
		if strings.TrimSpace(row.EvidenceRequired) == "" {
			return fmt.Errorf("condition %s missing evidence_required", row.ID)
		}
	}
	for _, id := range requiredConditionIDs {
		if !seen[id] {
			return fmt.Errorf("missing required §17.2 condition id %q", id)
		}
	}
	return nil
}

func validateThresholds(rows []threshold) error {
	seen := map[string]bool{}
	for _, row := range rows {
		if !containsID(requiredThresholdIDs, row.ID) {
			return fmt.Errorf("unknown §22.4 threshold id %q", row.ID)
		}
		if seen[row.ID] {
			return fmt.Errorf("duplicate §22.4 threshold id %q", row.ID)
		}
		seen[row.ID] = true
		if !validGateStatus(row.Status) {
			return fmt.Errorf("threshold %s has invalid status %q", row.ID, row.Status)
		}
		if note := thresholdDefinitionNote(row); note != "" {
			return fmt.Errorf("threshold %s malformed: %s", row.ID, note)
		}
	}
	for _, id := range requiredThresholdIDs {
		if !seen[id] {
			return fmt.Errorf("missing required §22.4 threshold id %q", id)
		}
	}
	return nil
}

func thresholdDefinitionNote(t threshold) string {
	switch t.ID {
	case "active_frps":
		if _, ok := numberValue(t.Threshold); !ok {
			return "threshold missing or non-numeric"
		}
	case "frps_in_cells_pct", "cells_in_directory_pct":
		if _, ok := numberValue(t.ThresholdPct); !ok {
			return "threshold_pct missing or non-numeric"
		}
	case "avg_relaypack_burn_days":
		if _, ok := numberValue(t.ThresholdDays); !ok {
			return "threshold_days missing or non-numeric"
		}
	case "directory_key_transparency_log":
		if _, ok := nonEmptyString(t.Threshold); !ok {
			return "threshold missing or empty"
		}
	}
	return ""
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func validGateStatus(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HOLD", "PASS", "FAIL":
		return true
	default:
		return false
	}
}

// loadClosureDoc reads the cell-closure markdown file. It scans
// for a prose `**Status**: <value>` line first (the canonical real
// status), falling back to a ```yaml fence if no prose line is
// found. The prose-first ordering matters because cell-closure-v1.md
// embeds an aspirational YAML template at §2 showing what a future
// SHIPPED record would look like; the real status sits in the
// prose preamble at the top.
func loadClosureDoc(path string) (*closureDoc, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		trim := strings.TrimSpace(line)
		var lhs, rhs string
		switch {
		case strings.HasPrefix(trim, "**Status**:"):
			rhs = strings.TrimSpace(strings.TrimPrefix(trim, "**Status**:"))
			lhs = "**Status**"
		case strings.HasPrefix(trim, "**status**:"):
			rhs = strings.TrimSpace(strings.TrimPrefix(trim, "**status**:"))
			lhs = "**status**"
		case strings.HasPrefix(trim, "Status:"):
			rhs = strings.TrimSpace(strings.TrimPrefix(trim, "Status:"))
			lhs = "Status"
		case strings.HasPrefix(trim, "status:"):
			rhs = strings.TrimSpace(strings.TrimPrefix(trim, "status:"))
			lhs = "status"
		}
		if lhs == "" {
			continue
		}
		// Take the first whitespace-separated word as the status
		// token; drops trailing prose like "HOLD. Pending V2 cell
		// alpha pilot." -> "HOLD".
		rhs = strings.TrimSuffix(rhs, ".")
		fields := strings.Fields(rhs)
		if len(fields) == 0 {
			continue
		}
		token := strings.TrimSuffix(fields[0], ".")
		token = strings.Trim(token, "`")
		token = strings.ToUpper(token)
		switch token {
		case "SHIPPED", "HOLD", "FAIL", "PASS", "PENDING":
			return &closureDoc{Status: token}, nil
		}
	}
	// Prose status not found; fall back to the embedded YAML
	// template (some closure docs may use only the YAML form).
	if yamlBlock, err := extractFencedYAML(string(body)); err == nil {
		var doc closureDoc
		if err := yaml.Unmarshal([]byte(yamlBlock), &doc); err == nil && doc.Status != "" {
			return &doc, nil
		}
	}
	return nil, errors.New("could not locate Status field in closure doc")
}

// extractFencedYAML returns the contents of the first ```yaml fenced
// code block in body. Returns an error if no such block exists.
func extractFencedYAML(body string) (string, error) {
	const fence = "```yaml"
	start := strings.Index(body, fence)
	if start < 0 {
		return "", errors.New("no ```yaml fence found")
	}
	rest := body[start+len(fence):]
	// Trim leading newline.
	rest = strings.TrimLeft(rest, "\r\n")
	end := strings.Index(rest, "\n```")
	if end < 0 {
		return "", errors.New("```yaml fence is not closed")
	}
	return rest[:end], nil
}

// Report is the structured form rendered by writeText / json.
type Report struct {
	Prerequisite struct {
		Path     string `json:"path"`
		Status   string `json:"status"`
		Required string `json:"required"`
		Met      bool   `json:"met"`
	} `json:"prerequisite"`
	Conditions  []ItemReport `json:"conditions"`
	Thresholds  []ItemReport `json:"thresholds"`
	Verdict     Verdict      `json:"verdict"`
	HoldReasons []string     `json:"hold_reasons,omitempty"`
	FailReasons []string     `json:"fail_reasons,omitempty"`
}

// ItemReport is one row in the printed table.
type ItemReport struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Status    string `json:"status"`
	Note      string `json:"note,omitempty"`
}

func evaluate(gate *gateSpec, closure *closureDoc) Report {
	r := Report{}
	r.Prerequisite.Path = gate.Prerequisite.CellClosureDoc
	r.Prerequisite.Required = gate.Prerequisite.RequiredStatus
	r.Prerequisite.Status = closure.Status
	r.Prerequisite.Met = strings.EqualFold(closure.Status, gate.Prerequisite.RequiredStatus)

	for _, c := range gate.Conditions {
		ir := ItemReport{
			ID:        c.ID,
			Statement: c.Statement,
			Status:    strings.ToUpper(strings.TrimSpace(c.Status)),
		}
		// PASS records require non-empty, non-TBD evidence (locked
		// invariant 48 enforcement; matches §5 of the gate spec).
		if ir.Status == "PASS" && evidenceMissing(c.Evidence) {
			ir.Status = "FAIL"
			ir.Note = "PASS rejected: evidence missing or TBD"
		}
		r.Conditions = append(r.Conditions, ir)
	}

	for _, t := range gate.SuccessMetric.Thresholds {
		ir := ItemReport{
			ID:        t.ID,
			Statement: t.Statement,
			Status:    strings.ToUpper(strings.TrimSpace(t.Status)),
		}
		// Threshold PASS records require an observed value or URL.
		if ir.Status == "PASS" && allObservedNil(t) {
			ir.Status = "FAIL"
			ir.Note = "PASS rejected: no observed value recorded"
		}
		if ir.Status == "PASS" {
			if note := thresholdFailureNote(t); note != "" {
				ir.Status = "FAIL"
				ir.Note = note
			}
		}
		r.Thresholds = append(r.Thresholds, ir)
	}

	// Verdict combinator.
	failReasons := []string{}
	holdReasons := []string{}
	if !r.Prerequisite.Met {
		holdReasons = append(holdReasons, fmt.Sprintf("prerequisite %s requires %s, observed %s",
			r.Prerequisite.Path, r.Prerequisite.Required, r.Prerequisite.Status))
	}
	for _, ir := range r.Conditions {
		switch ir.Status {
		case "FAIL":
			failReasons = append(failReasons, ir.ID+": "+ir.Note)
		case "HOLD":
			holdReasons = append(holdReasons, ir.ID+": HOLD")
		}
	}
	for _, ir := range r.Thresholds {
		switch ir.Status {
		case "FAIL":
			failReasons = append(failReasons, ir.ID+": "+ir.Note)
		case "HOLD":
			holdReasons = append(holdReasons, ir.ID+": HOLD")
		}
	}
	r.HoldReasons = holdReasons
	r.FailReasons = failReasons
	switch {
	case len(failReasons) > 0:
		r.Verdict = VerdictFAIL
	case len(holdReasons) > 0:
		r.Verdict = VerdictHOLD
	default:
		r.Verdict = VerdictPASS
	}
	return r
}

func evidenceMissing(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return true
	}
	if strings.EqualFold(t, "tbd") {
		return true
	}
	if strings.EqualFold(t, "null") {
		return true
	}
	return false
}

// allObservedNil returns true iff every observed_* field on the
// threshold is nil / empty.
func allObservedNil(t threshold) bool {
	if t.Observed != nil {
		return false
	}
	if t.ObservedPct != nil {
		return false
	}
	if t.ObservedDays != nil {
		return false
	}
	if t.ObservedURL != nil {
		if s, ok := t.ObservedURL.(string); ok && strings.TrimSpace(s) != "" {
			return false
		}
	}
	return true
}

func thresholdFailureNote(t threshold) string {
	switch t.ID {
	case "active_frps":
		return compareAtLeast("observed", t.Observed, "threshold", t.Threshold)
	case "frps_in_cells_pct", "cells_in_directory_pct":
		return compareAtLeast("observed_pct", t.ObservedPct, "threshold_pct", t.ThresholdPct)
	case "avg_relaypack_burn_days":
		return compareAtLeast("observed_days", t.ObservedDays, "threshold_days", t.ThresholdDays)
	case "directory_key_transparency_log":
		if s, ok := nonEmptyString(t.ObservedURL); !ok || s == "" {
			return "PASS rejected: observed_url missing or empty"
		}
		return ""
	default:
		return fmt.Sprintf("PASS rejected: unknown threshold id %q", t.ID)
	}
}

func compareAtLeast(observedName string, observed interface{}, thresholdName string, threshold interface{}) string {
	obs, ok := numberValue(observed)
	if !ok {
		return fmt.Sprintf("PASS rejected: %s missing or non-numeric", observedName)
	}
	thr, ok := numberValue(threshold)
	if !ok {
		return fmt.Sprintf("PASS rejected: %s missing or non-numeric", thresholdName)
	}
	if obs < thr {
		return fmt.Sprintf("PASS rejected: %s %.2f below %s %.2f", observedName, obs, thresholdName, thr)
	}
	return ""
}

func numberValue(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float64:
		return x, true
	case string:
		s := strings.TrimSpace(x)
		if s == "" || strings.EqualFold(s, "null") || strings.EqualFold(s, "tbd") {
			return 0, false
		}
		n, err := strconv.ParseFloat(s, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func nonEmptyString(v interface{}) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "null") || strings.EqualFold(s, "tbd") {
		return "", false
	}
	return s, true
}

func writeText(w io.Writer, r Report) {
	fmt.Fprintln(w, "FRP-13 Public-Directory Gate Status")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Prerequisite (cell closure):")
	prereqMark := "HOLD"
	if r.Prerequisite.Met {
		prereqMark = "PASS"
	}
	fmt.Fprintf(w, "  %-32s %-6s (need %s, got %s)\n",
		r.Prerequisite.Path, prereqMark, r.Prerequisite.Required, r.Prerequisite.Status)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "§17.2 Conditions:")
	for _, ir := range r.Conditions {
		extra := ""
		if ir.Note != "" {
			extra = " (" + ir.Note + ")"
		}
		fmt.Fprintf(w, "  %-44s %s%s\n", ir.ID, ir.Status, extra)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "§22.4 V3 success metric:")
	for _, ir := range r.Thresholds {
		extra := ""
		if ir.Note != "" {
			extra = " (" + ir.Note + ")"
		}
		fmt.Fprintf(w, "  %-44s %s%s\n", ir.ID, ir.Status, extra)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Gate verdict: %s\n", r.Verdict)
}
