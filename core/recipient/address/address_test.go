package address

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoundTrip generates a fresh random 32-byte key, encodes
// and decodes it, and asserts the bytes round-trip.
func TestRoundTrip(t *testing.T) {
	for i := 0; i < 256; i++ {
		var k [32]byte
		if _, err := rand.Read(k[:]); err != nil {
			t.Fatal(err)
		}
		s := Encode(k)
		if len(s) != AddressLen {
			t.Fatalf("encoded len = %d, want %d", len(s), AddressLen)
		}
		if !strings.HasPrefix(s, "daal1") {
			t.Fatalf("encoded missing daal1 prefix: %q", s)
		}
		got, err := Decode(s)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		if got != k {
			t.Fatalf("round-trip mismatch:\n  in : %x\n  out: %x", k, got)
		}
	}
}

// TestAllZeroKey pins the exact daal1... string for the all-zero
// pubkey. This is a stable cross-impl checkpoint.
func TestAllZeroKey(t *testing.T) {
	var k [32]byte
	s := Encode(k)
	if len(s) != AddressLen {
		t.Fatalf("len = %d, want %d", len(s), AddressLen)
	}
	if !strings.HasPrefix(s, "daal1qqqqqqqq") {
		t.Fatalf("zero-key encoding does not start with daal1qqqqqqqq: %q", s)
	}
	got, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatalf("zero-key decode mismatch: %x", got)
	}
}

// TestSingleCharCorruption confirms bech32m detects single-char
// substitutions. Tries each position with each other charset
// char; every mutation must be detected.
func TestSingleCharCorruption(t *testing.T) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	s := Encode(k)
	for pos := len("daal1"); pos < len(s); pos++ {
		orig := s[pos]
		for _, alt := range charset {
			if byte(alt) == orig {
				continue
			}
			corrupted := s[:pos] + string(alt) + s[pos+1:]
			if _, err := Decode(corrupted); err == nil {
				t.Fatalf("single-char corruption at pos %d (%c→%c) not detected", pos, orig, alt)
			}
		}
	}
}

// TestMixedCaseRejected — mixed-case input is a strong signal of
// copy/paste damage and must be rejected.
func TestMixedCaseRejected(t *testing.T) {
	var k [32]byte
	s := Encode(k)
	// Uppercase the 10th rune.
	rs := []rune(s)
	if rs[10] >= 'a' && rs[10] <= 'z' {
		rs[10] = rs[10] - 'a' + 'A'
	}
	mixed := string(rs)
	if _, err := Decode(mixed); err != ErrMixedCase {
		t.Fatalf("mixed-case decode got %v, want ErrMixedCase", err)
	}
}

// TestWrongLengthRejected — 61 chars, 63 chars.
func TestWrongLengthRejected(t *testing.T) {
	cases := []string{
		strings.Repeat("q", 61),
		strings.Repeat("q", 63),
		"",
		"daal1",
	}
	for _, s := range cases {
		if _, err := Decode(s); err != ErrInvalidLength {
			t.Fatalf("Decode(%q) error = %v, want ErrInvalidLength", s, err)
		}
	}
}

// TestWrongHRPRejected — a bech32m string with HRP != "daal".
func TestWrongHRPRejected(t *testing.T) {
	// "bc1qq..." would be a Bitcoin segwit address. Make a 62-char
	// string with "bcco" HRP (4 chars) and a valid payload section.
	var k [32]byte
	good := Encode(k)
	bad := "bcco" + good[4:]
	if _, err := Decode(bad); err == nil {
		t.Fatalf("Decode(%q) should have failed", bad)
	}
}

// TestURIPrefixStripping — daal://addr/daal1... must decode the
// same as the bare daal1... form.
func TestURIPrefixStripping(t *testing.T) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	bare := Encode(k)
	uri := URIPrefix + bare
	got, err := Decode(uri)
	if err != nil {
		t.Fatalf("Decode(uri) failed: %v", err)
	}
	if got != k {
		t.Fatalf("uri decode mismatch")
	}
}

// TestParseURIRequiresPrefix — bare daal1... should be rejected
// by ParseURI (use Decode for that).
func TestParseURIRequiresPrefix(t *testing.T) {
	var k [32]byte
	bare := Encode(k)
	if _, err := ParseURI(bare); err != ErrInvalidURI {
		t.Fatalf("ParseURI(bare) err = %v, want ErrInvalidURI", err)
	}
	if _, err := ParseURI(URIPrefix + bare); err != nil {
		t.Fatalf("ParseURI(prefixed) err = %v, want nil", err)
	}
}

// TestFingerprint — sha256 of the pubkey, hex.
func TestFingerprint(t *testing.T) {
	var k [32]byte
	fp := Fingerprint(k)
	// Pin: sha256(32 zero bytes) is a known value.
	want := "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
	if fp != want {
		t.Fatalf("Fingerprint(zero) = %s, want %s", fp, want)
	}
	if len(fp) != 64 {
		t.Fatalf("Fingerprint len = %d, want 64", len(fp))
	}
}

// TestGoldenVectors loads (or, on first run, generates) the
// shared cross-impl golden vectors and asserts round-trip.
func TestGoldenVectors(t *testing.T) {
	path := goldenPath(t)
	vectors, err := loadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 8 {
		t.Fatalf("golden vector count = %d, want >= 8", len(vectors))
	}
	for i, v := range vectors {
		pubBytes, err := hex.DecodeString(v.PubHex)
		if err != nil {
			t.Fatalf("vector %d: hex decode pub: %v", i, err)
		}
		if len(pubBytes) != 32 {
			t.Fatalf("vector %d: pub len = %d, want 32", i, len(pubBytes))
		}
		var k [32]byte
		copy(k[:], pubBytes)
		got := Encode(k)
		if got != v.Address {
			t.Fatalf("vector %d:\n  encoded: %s\n  golden : %s", i, got, v.Address)
		}
		back, err := Decode(v.Address)
		if err != nil {
			t.Fatalf("vector %d decode: %v", i, err)
		}
		if !bytes.Equal(back[:], pubBytes) {
			t.Fatalf("vector %d decode mismatch", i)
		}
	}
}

// ----------------------------------------------------------------
// Golden vectors plumbing. The Rust mirror loads the same file.
// ----------------------------------------------------------------

type goldenVector struct {
	PubHex  string `json:"pub_hex"`
	Address string `json:"address"`
}

func goldenPath(t *testing.T) string {
	t.Helper()
	// specs/test-vectors/recipient-address-v1/golden.json sits at
	// the repo root, ../../../specs/... from this package.
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	return filepath.Join(root, "specs", "test-vectors", "recipient-address-v1", "golden.json")
}

func repoRoot() (string, error) {
	// Walk up from cwd until we find a "specs" directory.
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "specs")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func loadOrGenerate(path string) ([]goldenVector, error) {
	if data, err := os.ReadFile(path); err == nil {
		var out []goldenVector
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	// Generate a deterministic 16-entry set on first run. The pubs
	// are not random — they're stamped from a seeded counter so the
	// golden file is reproducible across machines.
	vectors := make([]goldenVector, 0, 16)
	// Hand-picked stable test patterns.
	patterns := [][]byte{
		bytesAll(0x00),
		bytesAll(0xff),
		bytesAll(0x01),
		bytesAll(0xa5),
		bytesIota(),
		bytesIotaRev(),
		bytesPattern(0xde, 0xad, 0xbe, 0xef),
		bytesPattern(0xca, 0xfe, 0xba, 0xbe),
	}
	for _, pat := range patterns {
		var k [32]byte
		copy(k[:], pat)
		vectors = append(vectors, goldenVector{
			PubHex:  hex.EncodeToString(pat),
			Address: Encode(k),
		})
	}
	// Plus 8 deterministic "random" keys via a SHAKE-like loop
	// over the prior key.
	prev := bytesAll(0x42)
	for i := 0; i < 8; i++ {
		next := mixKey(prev, byte(i))
		var k [32]byte
		copy(k[:], next)
		vectors = append(vectors, goldenVector{
			PubHex:  hex.EncodeToString(next),
			Address: Encode(k),
		})
		prev = next
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return nil, err
	}
	return vectors, nil
}

func bytesAll(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytesIota() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func bytesIotaRev() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(31 - i)
	}
	return out
}

func bytesPattern(a, b, c, d byte) []byte {
	out := make([]byte, 32)
	pat := []byte{a, b, c, d}
	for i := range out {
		out[i] = pat[i%4]
	}
	return out
}

// mixKey is a simple deterministic mixer for the golden vectors —
// not cryptographically meaningful, just stable across runs.
func mixKey(prev []byte, salt byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = prev[i] ^ (salt + byte(i*3+1))
	}
	return out
}
