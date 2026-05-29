package publisher

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

func TestRevocationVerifies(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	pub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	out := filepath.Join(dir, "rev.json")
	if _, err := Revoke(RevokeOptions{
		RootPrivPath:          filepath.Join(dir, "publisher.priv"),
		RouteIDs:              []string{"r-1", "r-2"},
		PublisherFingerprints: []string{},
		Reason:                "compromised endpoint",
		Out:                   out,
	}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(out, pub); err != nil {
		t.Fatalf("verify revocation: %v", err)
	}
}

func TestRotationChainVerifies(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir}); err != nil {
		t.Fatal(err)
	}
	oldPub, _ := LoadPub(filepath.Join(dir, "publisher.pub"))
	// Generate a new root.
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPubPath := filepath.Join(dir, "new-root.pub")
	if err := writeFileAtomic(newPubPath, newPub, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "rotation.json")
	chain, err := Rotate(RotateOptions{
		OldRootPrivPath:  filepath.Join(dir, "publisher.priv"),
		NewRootPubPath:   newPubPath,
		TransitionWindow: 14 * 24 * time.Hour,
		Out:              out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRotationChain(*chain, oldPub, newPub, time.Now()); err != nil {
		t.Fatalf("verify rotation chain: %v", err)
	}
	// Outside window.
	future := time.Now().Add(60 * 24 * time.Hour)
	if err := VerifyRotationChain(*chain, oldPub, newPub, future); err == nil {
		t.Fatal("rotation chain outside window should fail")
	}
}
