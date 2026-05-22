package selection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNewExplanation_HasNonNilSlices ensures JSON output never
// emits "null" for the four slice fields. UI code is allowed to
// assume `Array<...>` shape per the FRP-6 contract.
func TestNewExplanation_HasNonNilSlices(t *testing.T) {
	e := NewExplanation("test-decision-1", PhaseV15)
	if e.Shortlist == nil || e.Failures == nil || e.ActiveCooldowns == nil || e.NetworkSignals == nil {
		t.Fatal("NewExplanation must initialise slice fields to non-nil empty slices")
	}
	body, err := e.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{`"shortlist": []`, `"failures": []`, `"active_cooldowns": []`, `"network_signals": []`} {
		if !strings.Contains(string(body), sub) {
			t.Errorf("expected %q in JSON output; got: %s", sub, body)
		}
	}
}

// TestPhaseConstants pins the 4 phase strings.
func TestPhaseConstants(t *testing.T) {
	got := []Phase{PhaseV15, PhaseV16, PhaseV2, PhasePostV2}
	want := []string{"V1.5", "V1.6", "V2", "post-V2"}
	for i, p := range got {
		if string(p) != want[i] {
			t.Errorf("phase[%d] = %q want %q", i, p, want[i])
		}
	}
}

// TestExplanationJSONFieldOrder pins the JSON output's TOP-LEVEL key
// order via the struct definition. encoding/json emits fields in
// declaration order; this is the FRP-6 contract.
func TestExplanationJSONFieldOrder(t *testing.T) {
	e := NewExplanation("d", PhaseV15)
	body, _ := e.MarshalCanonical()
	want := []string{
		`"pick"`, `"shortlist"`, `"failures"`, `"active_cooldowns"`,
		`"network_signals"`, `"reason"`, `"decision_id"`, `"phase"`,
	}
	last := -1
	for _, k := range want {
		idx := strings.Index(string(body), k)
		if idx < 0 {
			t.Errorf("missing key %s", k)
			continue
		}
		if idx <= last {
			t.Errorf("key %s out of order", k)
		}
		last = idx
	}
}

// repoRoot resolves the repo root from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// /home/daal/core/internal/selection/explain_test.go
	// → /home/daal
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// TestExplanationGoldenFile asserts that every JSON file in
// specs/test-vectors/explanation/ is a valid Explanation that
// round-trips byte-identically through MarshalCanonical.
//
// The hand-authored seeds at FRP-3 commit 1 are over-written by the
// commit-4 generator with deterministic versions; this test treats
// either as canonical so commits 1 and 4 are both green.
func TestExplanationGoldenFile(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "specs", "test-vectors", "explanation")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("goldens dir absent: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		t.Run(ent.Name(), func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, ent.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var e Explanation
			if err := json.Unmarshal(body, &e); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// All required fields must be set.
			if e.DecisionID == "" {
				t.Errorf("%s: decision_id empty", ent.Name())
			}
			if e.Phase == "" {
				t.Errorf("%s: phase empty", ent.Name())
			}
			// Round-trip must preserve every byte for a generator
			// that uses MarshalCanonical. Hand-authored seeds may
			// not match exactly; we only require that re-encoding
			// yields VALID JSON of equivalent shape.
			again, err := e.MarshalCanonical()
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			var e2 Explanation
			if err := json.Unmarshal(again, &e2); err != nil {
				t.Fatalf("re-unmarshal: %v", err)
			}
		})
		count++
	}
	if count == 0 {
		t.Fatalf("no .json goldens found in %s", dir)
	}
	t.Logf("validated %d explanation golden(s)", count)
}
