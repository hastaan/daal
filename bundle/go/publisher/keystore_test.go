package publisher

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestKeygenWritesFilesWithCorrectModes(t *testing.T) {
	dir := t.TempDir()
	meta, err := Keygen(KeygenOptions{OutDir: dir, Label: "test"})
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if meta.KeyFingerprintHex == "" {
		t.Fatal("missing fingerprint")
	}
	if meta.KeyFingerprintEN == "" {
		t.Fatal("missing english fingerprint")
	}
	if meta.KeyFingerprintFA == "" {
		t.Fatal("missing persian fingerprint")
	}

	if runtime.GOOS != "windows" {
		// Permissions are POSIX-meaningful only.
		st, err := os.Stat(filepath.Join(dir, "publisher.priv"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("publisher.priv mode = %o, want 0600", st.Mode().Perm())
		}
		st, err = os.Stat(filepath.Join(dir, "publisher.pub"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o644 {
			t.Fatalf("publisher.pub mode = %o, want 0644", st.Mode().Perm())
		}
		st, err = os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Fatalf("keystore dir mode = %o, want 0700", st.Mode().Perm())
		}
	}

	// Refuse overwrite without --force.
	_, err = Keygen(KeygenOptions{OutDir: dir, Label: "test"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected refusal to overwrite, got %v", err)
	}
}

func TestSubkeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := Keygen(KeygenOptions{OutDir: dir, Label: "root"}); err != nil {
		t.Fatal(err)
	}
	rootPub, err := LoadPub(filepath.Join(dir, "publisher.pub"))
	if err != nil {
		t.Fatal(err)
	}
	art, err := Subkey(SubkeyOptions{
		RootPrivPath: filepath.Join(dir, "publisher.priv"),
		OutDir:       dir,
		Validity:     14 * 24 * time.Hour,
		Label:        "test-sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySubkeyCert(art.Cert, rootPub, time.Now()); err != nil {
		t.Fatalf("verify subkey cert: %v", err)
	}

	// Tampering breaks verification.
	bad := art.Cert
	bad.SubkeyPubHex = strings.Repeat("0", ed25519.PublicKeySize*2)
	if err := VerifySubkeyCert(bad, rootPub, time.Now()); err == nil {
		t.Fatal("tampered cert should fail verification")
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"14d":  14 * 24 * time.Hour,
		"2w":   2 * 7 * 24 * time.Hour,
		"336h": 336 * time.Hour,
		"30m":  30 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Fatalf("%s: got %v want %v", in, got, want)
		}
	}
}
