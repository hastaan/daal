package trust_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"daal/bundle-go/importer"
	"daal/core/trust"
)

// rotationWindowNow derives a deterministic "now" that sits inside the
// sample rotation chain's transition window. The samples are generated
// with real timestamps, so tests anchored to time.Now() start failing
// the day the window closes; anchoring to the fixture keeps the tests
// asserting rotation semantics, not fixture freshness.
func rotationWindowNow(t *testing.T) time.Time {
	t.Helper()
	raw := mustReadFile(t, filepath.Join(samplesDir, "rotation-A-to-B.json"))
	var doc struct {
		TransitionStartsAt string `json:"transition_starts_at"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse rotation sample: %v", err)
	}
	from, err := time.Parse(time.RFC3339, doc.TransitionStartsAt)
	if err != nil {
		t.Fatalf("parse transition_starts_at: %v", err)
	}
	return from.Add(time.Hour).UTC()
}

func TestValidRotationAcceptedWhenOldPubPinned(t *testing.T) {
	s := openStore(t)
	a := &trust.StoreAdapter{S: s}
	now := rotationWindowNow(t)

	// Pin publisher A by importing signed-A and trusting it.
	signedA := mustReadFile(t, filepath.Join(samplesDir, "signed-A.sbp"))
	if _, err := importer.AcceptTrustPrompt("trust", signedA, a, wordlists(), now); err != nil {
		t.Fatal(err)
	}

	// Now import the B-signed bundle with rotation chain A -> B.
	rotation := mustReadFile(t, filepath.Join(samplesDir, "valid-rotation-B.sbp"))
	v, err := importer.ImportBytes(rotation, a, wordlists(), now)
	if err != nil {
		t.Fatalf("rotation import error: %v (verdict %+v)", err, v)
	}
	if v.Kind != importer.VerdictRotationAccepted {
		t.Fatalf("expected rotation accepted, got %v reason=%q", v.Kind, v.Reason)
	}
}

func TestRotationRejectedWhenOldPubNotPinned(t *testing.T) {
	s := openStore(t)
	a := &trust.StoreAdapter{S: s}
	// In-window on purpose: outside the window the import is rejected
	// for the wrong reason and the unpinned-publisher assertion below
	// would pass vacuously.
	now := rotationWindowNow(t)

	// No prior pin for A. Rotation must NOT silently install B.
	rotation := mustReadFile(t, filepath.Join(samplesDir, "valid-rotation-B.sbp"))
	v, _ := importer.ImportBytes(rotation, a, wordlists(), now)
	if v.Kind == importer.VerdictRotationAccepted || v.Kind == importer.VerdictImported {
		t.Fatalf("rotation must be rejected when old pub unpinned, got %v", v.Kind)
	}
}
