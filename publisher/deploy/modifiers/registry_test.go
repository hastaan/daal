package modifiers

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestRegistry_KnownKinds checks the build-time registry contains
// the two FRP-12 reserved-slot kinds.
func TestRegistry_KnownKinds(t *testing.T) {
	got := AllKinds()
	want := []string{"client_desync", "tls_fragment"}
	if len(got) != len(want) {
		t.Fatalf("AllKinds() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllKinds()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRegistry_LookupReservedSlots verifies the two PENDING kinds
// load with their declared MinPhase + Platforms.
func TestRegistry_LookupReservedSlots(t *testing.T) {
	cd, err := Lookup("client_desync")
	if err != nil {
		t.Fatalf("Lookup(client_desync): %v", err)
	}
	if cd.Status != StatusPending {
		t.Errorf("client_desync.Status = %q, want PENDING", cd.Status)
	}
	if cd.MinPhase != PhasePostV2 {
		t.Errorf("client_desync.MinPhase = %q, want PostV2", cd.MinPhase)
	}
	if len(cd.Platforms) != 1 || cd.Platforms[0] != PlatformLinuxDesktop {
		t.Errorf("client_desync.Platforms = %v, want [linux-desktop]", cd.Platforms)
	}

	tf, err := Lookup("tls_fragment")
	if err != nil {
		t.Fatalf("Lookup(tls_fragment): %v", err)
	}
	if tf.Status != StatusPending {
		t.Errorf("tls_fragment.Status = %q, want PENDING", tf.Status)
	}
	if len(tf.Platforms) != 0 {
		t.Errorf("tls_fragment.Platforms = %v, want empty", tf.Platforms)
	}
}

func TestRegistry_LookupUnknown(t *testing.T) {
	_, err := Lookup("nope")
	if !errors.Is(err, ErrUnknownKind) {
		t.Errorf("Lookup(nope) error = %v, want ErrUnknownKind", err)
	}
}

// TestRegistry_AllowedKindsAtIsEmpty verifies locked invariant 37:
// at FRP-12 ship the registry has zero PASS records, so
// AllowedKindsAt at every phase MUST return an empty map.
func TestRegistry_AllowedKindsAtIsEmpty(t *testing.T) {
	for _, p := range []Phase{PhaseV15, PhaseV16, PhasePostV2} {
		got := AllowedKindsAt(p)
		if len(got) != 0 {
			t.Errorf("AllowedKindsAt(%s) = %v, want empty (locked invariant 37)", p, got)
		}
	}
}

func TestRegistry_AllowedKindsAtUnknownPhase(t *testing.T) {
	got := AllowedKindsAt(Phase("V99"))
	if len(got) != 0 {
		t.Errorf("AllowedKindsAt(V99) should be empty, got %v", got)
	}
}

func TestRegistry_HasPassAtFalseForReservedSlots(t *testing.T) {
	for _, k := range AllKinds() {
		if HasPassAt(k, PhasePostV2) {
			t.Errorf("HasPassAt(%s, PostV2) = true; should be false at FRP-12 ship", k)
		}
	}
}

// TestRegistry_ZeroPASSRecordsInSpecs is the on-disk verification
// grep equivalent: walk specs/modifiers/*.md (excluding _template.md
// and README.md) and assert that no file body contains a
// pass_record.status=PASS line. Locked invariant 37; this test
// MUST pass at every commit through 11/11.
func TestRegistry_ZeroPASSRecordsInSpecs(t *testing.T) {
	dir := specsModifiersDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".md") {
			continue
		}
		if ent.Name() == "_template.md" || ent.Name() == "README.md" {
			continue
		}
		full := filepath.Join(dir, ent.Name())
		body, err := os.ReadFile(full)
		if err != nil {
			t.Fatalf("read %s: %v", full, err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			low := strings.ToLower(line)
			if !strings.Contains(low, "status") {
				continue
			}
			if strings.Contains(line, "PASS") &&
				!strings.Contains(line, "PENDING") &&
				!strings.Contains(line, "REJECTED") &&
				!strings.Contains(line, "DEPRECATED") {
				// Allow the legend bullet in spec text only if it
				// also enumerates other statuses (the template
				// pattern: "PENDING | PASS | REJECTED |
				// DEPRECATED" — guarded above).
				if strings.Contains(line, "**status**") &&
					!isLegendListing(line) {
					t.Errorf("%s line %q carries a non-PENDING status; locked invariant 37 violated", full, line)
				}
			}
		}
	}
}

// isLegendListing returns true iff the line enumerates more than
// one status value (the template's "**status**: PENDING | PASS |
// REJECTED | DEPRECATED" line, which we never expect to encounter
// in real per-modifier files but defend against here).
func isLegendListing(line string) bool {
	count := 0
	for _, s := range []string{"PENDING", "PASS", "REJECTED", "DEPRECATED"} {
		if strings.Contains(line, s) {
			count++
		}
	}
	return count >= 2
}

// specsModifiersDir locates specs/modifiers/ relative to the test
// binary's working directory (the package directory under
// publisher/deploy/modifiers).
func specsModifiersDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../publisher/deploy/modifiers/registry_test.go
	dir := filepath.Dir(thisFile)
	// Walk up to the repo root (look for go.mod under publisher).
	for i := 0; i < 6; i++ {
		dir = filepath.Dir(dir)
		candidate := filepath.Join(dir, "specs", "modifiers")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
	}
	t.Fatal("could not locate specs/modifiers/ relative to test file")
	return ""
}

// TestRegistry_DeterministicOrder verifies AllKinds returns kinds
// in a stable alphabetical order across calls.
func TestRegistry_DeterministicOrder(t *testing.T) {
	a := AllKinds()
	b := AllKinds()
	if len(a) != len(b) {
		t.Fatalf("len mismatch %d vs %d", len(a), len(b))
	}
	c := append([]string{}, a...)
	sort.Strings(c)
	for i := range a {
		if a[i] != b[i] || a[i] != c[i] {
			t.Errorf("non-deterministic / non-sorted ordering at %d", i)
		}
	}
}
