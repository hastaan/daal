package censor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllScenarios(t *testing.T) {
	// The driver lives at .../soak-driver; the scenarios directory is
	// two levels up.
	dir := filepath.Join("..", "..", "..", "scenarios")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("scenarios dir %s missing: %v", dir, err)
	}
	scs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scs) < 5 {
		t.Fatalf("expected ≥5 scenarios, got %d", len(scs))
	}
	// Expect the new publisher-revocation-url-unreachable scenario.
	var found bool
	for _, s := range scs {
		if s.ID == "publisher-revocation-url-unreachable" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("publisher-revocation-url-unreachable scenario missing")
	}
}
