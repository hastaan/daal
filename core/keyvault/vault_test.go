package keyvault

import (
	"bytes"
	"strings"
	"testing"
)

// TestSealOpenRoundTrip — the canonical happy path.
func TestSealOpenRoundTrip(t *testing.T) {
	pt := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	blob, err := Seal(pt, "hunter2")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	out, err := Open(blob, "hunter2")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Errorf("round-trip mismatch: %q vs %q", out, pt)
	}
}

// TestOpenWrongPINReturnsErrWrongPIN — the user-facing failure mode.
func TestOpenWrongPINReturnsErrWrongPIN(t *testing.T) {
	pt := []byte("secret")
	blob, _ := Seal(pt, "right")
	if _, err := Open(blob, "wrong"); err != ErrWrongPIN {
		t.Fatalf("Open(wrong) = %v, want ErrWrongPIN", err)
	}
}

// TestOpenRejectsBadVersion — a blob with an unknown version byte
// is rejected with a clean error.
func TestOpenRejectsBadVersion(t *testing.T) {
	pt := []byte("x")
	blob, _ := Seal(pt, "p")
	blob[0] = 0xff
	if _, err := Open(blob, "p"); err == nil {
		t.Fatal("expected error on bad version")
	}
}

// TestOpenRejectsTruncatedBlob — defensive parsing.
func TestOpenRejectsTruncatedBlob(t *testing.T) {
	pt := []byte("x")
	blob, _ := Seal(pt, "p")
	if _, err := Open(blob[:10], "p"); err == nil {
		t.Fatal("expected error on truncated blob")
	}
}

// TestSealNonDeterministic — two seals of the same plaintext under
// the same PIN must NOT produce identical blobs (fresh salt + fresh
// nonce on every call).
func TestSealNonDeterministic(t *testing.T) {
	pt := []byte("data")
	a, _ := Seal(pt, "p")
	b, _ := Seal(pt, "p")
	if bytes.Equal(a, b) {
		t.Error("Seal is deterministic — salt/nonce reuse hazard")
	}
}

// TestSealRejectsEmptyPIN — V0.1 invariant.
func TestSealRejectsEmptyPIN(t *testing.T) {
	if _, err := Seal([]byte("x"), ""); err != ErrEmptyPIN {
		t.Errorf("Seal(\"\") = %v, want ErrEmptyPIN", err)
	}
	if _, err := Open([]byte("x"), ""); err != ErrEmptyPIN {
		t.Errorf("Open(\"\") = %v, want ErrEmptyPIN", err)
	}
}

// TestPINNotEmbeddedInBlob — a sealed blob must not contain the
// PIN string anywhere. This is a regression test for the V0.1 +
// CC.6 privacy posture, mirrored at the ABI layer by
// TestPINDoesNotLeakIntoDiagnostics.
func TestPINNotEmbeddedInBlob(t *testing.T) {
	pin := "correct-horse-battery-staple"
	blob, _ := Seal([]byte("payload"), pin)
	if strings.Contains(string(blob), pin) {
		t.Fatal("PIN appears in sealed blob")
	}
}
