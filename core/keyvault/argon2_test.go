package keyvault

import (
	"bytes"
	"strings"
	"testing"
)

// TestDeriveDeterministic asserts the same (pin, salt) yields the
// same 32-byte key. This is the bedrock invariant a vault relies on
// — wrong derivation = lost data.
func TestDeriveDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, V1SaltLen)
	a, err := Derive("correct-horse-battery-staple", salt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive("correct-horse-battery-staple", salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Derive is non-deterministic on identical inputs")
	}
	if len(a) != int(V1OutLen) {
		t.Errorf("output length = %d, want %d", len(a), V1OutLen)
	}
}

// TestDeriveDiffersOnPIN — different PINs must produce different keys.
func TestDeriveDiffersOnPIN(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, V1SaltLen)
	a, _ := Derive("hunter2", salt)
	b, _ := Derive("hunter3", salt)
	if bytes.Equal(a, b) {
		t.Fatal("Derive collided on different PINs")
	}
}

// TestDeriveDiffersOnSalt — different salts must produce different keys.
func TestDeriveDiffersOnSalt(t *testing.T) {
	a, _ := Derive("hunter2", bytes.Repeat([]byte{0x01}, V1SaltLen))
	b, _ := Derive("hunter2", bytes.Repeat([]byte{0x02}, V1SaltLen))
	if bytes.Equal(a, b) {
		t.Fatal("Derive collided on different salts")
	}
}

// TestDeriveRejectsEmptyPIN — V0.1 vault profile refuses an empty PIN.
func TestDeriveRejectsEmptyPIN(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, V1SaltLen)
	if _, err := Derive("", salt); err != ErrEmptyPIN {
		t.Fatalf("Derive(\"\") = %v, want ErrEmptyPIN", err)
	}
}

// TestDeriveRejectsBadSalt — a salt of the wrong length is rejected.
func TestDeriveRejectsBadSalt(t *testing.T) {
	if _, err := Derive("hunter2", []byte{1, 2, 3}); err == nil {
		t.Fatal("Derive accepted a too-short salt")
	}
}

// TestNewSaltUnique — successive NewSalt calls produce different
// salts. 16 random bytes colliding is astronomical; this test is a
// sanity check on the rng wiring.
func TestNewSaltUnique(t *testing.T) {
	a, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("NewSalt collision on fresh draws")
	}
	if len(a) != V1SaltLen {
		t.Errorf("salt length = %d, want %d", len(a), V1SaltLen)
	}
}

// TestParametersLocked — locks the v1 parameter set. Bumping any of
// these without a v2 spec is a roadmap-level decision.
func TestParametersLocked(t *testing.T) {
	want := struct {
		t, m uint32
		p    uint8
		s    int
		o    uint32
	}{
		t: 3,
		m: 64 * 1024,
		p: 4,
		s: 16,
		o: 32,
	}
	if V1Time != want.t || V1MemoryKiB != want.m || V1Parallel != want.p ||
		V1SaltLen != want.s || V1OutLen != want.o {
		t.Errorf("v1 parameters drifted")
	}
	// Self-document the lock by formatting the value set.
	tag := strings.Join([]string{"t=3", "m=65536KiB", "p=4", "s=16", "o=32"}, " ")
	if tag == "" {
		t.Fatal("unreachable")
	}
}
