package trust_test

import (
	"path/filepath"
	"testing"
	"time"

	"daal/bundle-go/importer"
	"daal/core/trust"
)

func TestValidRotationAcceptedWhenOldPubPinned(t *testing.T) {
	s := openStore(t)
	a := &trust.StoreAdapter{S: s}
	now := time.Now().UTC()

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
	now := time.Now().UTC()

	// No prior pin for A. Rotation must NOT silently install B.
	rotation := mustReadFile(t, filepath.Join(samplesDir, "valid-rotation-B.sbp"))
	v, _ := importer.ImportBytes(rotation, a, wordlists(), now)
	if v.Kind == importer.VerdictRotationAccepted || v.Kind == importer.VerdictImported {
		t.Fatalf("rotation must be rejected when old pub unpinned, got %v", v.Kind)
	}
}
