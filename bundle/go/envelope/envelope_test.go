package envelope

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/age"
)

// genIdentity returns a fresh X25519 keypair as raw 32-byte arrays.
func genIdentity(t *testing.T) (pub [32]byte, priv [32]byte) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// Re-encode the recipient string and re-extract the raw point
	// via our local bech32 decoder. Faster: just store the raw bytes
	// by round-tripping through our encoders.
	// age provides String() but not raw accessors; instead we
	// generate via raw bytes ourselves.
	_ = id
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	// Curve25519 clamping is applied internally by age; we just feed
	// raw 32 bytes and age handles clamping (it does NOT clamp again
	// for raw scalars, but the X25519 op is consistent).
	derivePub(t, priv, &pub)
	return pub, priv
}

func derivePub(t *testing.T, priv [32]byte, out *[32]byte) {
	t.Helper()
	// Round-trip via age to derive the corresponding pub: build
	// identity from priv, ask for its recipient, decode that string.
	id, err := newX25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}
	recip := id.Recipient().String() // age1...
	pubBytes, err := decodeAgeBech32(recip)
	if err != nil {
		t.Fatal(err)
	}
	copy(out[:], pubBytes)
}

func decodeAgeBech32(s string) ([]byte, error) {
	// Strip the HRP + separator; decode the 5-bit data; chop the
	// last 6 chars (checksum); ageConvertBits 5→8 without padding.
	sep := -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '1' {
			sep = i
			break
		}
	}
	if sep < 0 {
		return nil, age.ErrIncorrectIdentity
	}
	dataPart := s[sep+1:]
	data := make([]byte, 0, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		idx := bytesIndex([]byte(ageBech32Charset), dataPart[i])
		if idx < 0 {
			return nil, age.ErrIncorrectIdentity
		}
		data = append(data, byte(idx))
	}
	payload := data[:len(data)-6]
	return ageConvertBits(payload, 5, 8, false)
}

func bytesIndex(set []byte, c byte) int {
	for i, b := range set {
		if b == c {
			return i
		}
	}
	return -1
}

func TestSniffMagic(t *testing.T) {
	if !SniffMagic(Magic) {
		t.Fatal("SniffMagic(Magic) = false")
	}
	if !SniffMagic(append(Magic, 0xff, 0xff)) {
		t.Fatal("SniffMagic on prefixed bytes = false")
	}
	if SniffMagic([]byte("DSBP\x00\x02foo")) {
		t.Fatal("SniffMagic on wrong version = true")
	}
	if SniffMagic([]byte("hello world")) {
		t.Fatal("SniffMagic on non-magic = true")
	}
	if SniffMagic([]byte{}) {
		t.Fatal("SniffMagic on empty = true")
	}
}

func TestRoundTrip(t *testing.T) {
	pub, priv := genIdentity(t)
	plaintext := []byte("hello daal world: " + string(make([]byte, 1024)))
	for i := range plaintext[19:] {
		plaintext[19+i] = byte(i % 251)
	}
	ct, err := EncryptForRecipient(plaintext, pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !SniffMagic(ct) {
		t.Fatal("ciphertext missing magic")
	}
	pt, err := Decrypt(ct, priv)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(pt), len(plaintext))
	}
}

func TestWrongKeyFailsDecrypt(t *testing.T) {
	pubA, _ := genIdentity(t)
	_, privB := genIdentity(t)
	ct, err := EncryptForRecipient([]byte("secret"), pubA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(ct, privB); err == nil {
		t.Fatal("Decrypt with wrong key succeeded")
	}
}

func TestBadMagicRejected(t *testing.T) {
	_, priv := genIdentity(t)
	bad := []byte("XXXX\x00\x01rest of age stream")
	if _, err := Decrypt(bad, priv); err != ErrBadMagic {
		t.Fatalf("got %v, want ErrBadMagic", err)
	}
}

func TestTamperedMagicRejected(t *testing.T) {
	pub, priv := genIdentity(t)
	ct, _ := EncryptForRecipient([]byte("x"), pub)
	ct[5] = 0x02 // bump version byte
	if _, err := Decrypt(ct, priv); err != ErrBadMagic {
		t.Fatalf("got %v, want ErrBadMagic on version bump", err)
	}
}

func TestTruncatedBody(t *testing.T) {
	pub, priv := genIdentity(t)
	ct, _ := EncryptForRecipient(bytes.Repeat([]byte("z"), 200), pub)
	truncated := ct[:len(ct)-20]
	if _, err := Decrypt(truncated, priv); err == nil {
		t.Fatal("decrypt of truncated ciphertext succeeded")
	}
}

func TestOversizedCiphertextRejected(t *testing.T) {
	_, priv := genIdentity(t)
	huge := make([]byte, MaxCiphertextBytes+1)
	copy(huge, Magic)
	if _, err := Decrypt(huge, priv); err != ErrCiphertextTooLarge {
		t.Fatalf("got %v, want ErrCiphertextTooLarge", err)
	}
}

func TestFuzzRoundTrip(t *testing.T) {
	for i := 0; i < 32; i++ {
		pub, priv := genIdentity(t)
		n := 1 + i*128
		plain := make([]byte, n)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		ct, err := EncryptForRecipient(plain, pub)
		if err != nil {
			t.Fatal(err)
		}
		out, err := Decrypt(ct, priv)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("fuzz round-trip mismatch at i=%d, n=%d", i, n)
		}
	}
}
