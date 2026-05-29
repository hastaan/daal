// Package envelope wraps a signed .sbp in an age v1 ciphertext
// addressed to one X25519 recipient. The on-disk file is the
// `.sbpx` envelope: a 6-byte magic prefix `DSBP\x00\x01` followed
// by the standard age v1 wire format (ASCII header + binary body).
//
// Spec: specs/sbpx-envelope-v1.md.
//
// The envelope provides confidentiality for the inner relay pack
// (no IP/SNI/credentials leak to a passive observer of the file).
// Authenticity is provided by the inner SBP's Ed25519 signature,
// which is verified after age-decryption — see VerifyBundle.
package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// Magic is the 6-byte prefix that distinguishes a .sbpx file from
// a bare age stream. The trailing 0x01 is the envelope version;
// future versions bump this byte.
var Magic = []byte{'D', 'S', 'B', 'P', 0x00, 0x01}

// MaxCiphertextBytes caps the size of a .sbpx the recipient
// importer will read into memory. Plain .sbp files are typically
// 12-20 KB; we allow a generous 4 MiB ceiling that still rules out
// runaway inputs.
const MaxCiphertextBytes = 4 * 1024 * 1024

var (
	// ErrBadMagic is returned by Decrypt / SniffMagic when the input
	// does not start with the .sbpx magic prefix.
	ErrBadMagic = errors.New("envelope: bad magic; not a .sbpx file")

	// ErrAgeHeader is returned when the age header cannot be parsed
	// or specifies a recipient type Daal does not support.
	ErrAgeHeader = errors.New("envelope: malformed or unsupported age header")

	// ErrDecrypt is the canonical decrypt-failure error: wrong key,
	// tampered ciphertext, truncated body.
	ErrDecrypt = errors.New("envelope: decryption failed")

	// ErrCiphertextTooLarge guards the 4-MiB read cap.
	ErrCiphertextTooLarge = errors.New("envelope: ciphertext exceeds 4 MiB cap")
)

// SniffMagic reports whether the leading 6 bytes of `head` match
// the v1 magic. Used by import dispatchers to choose the .sbp vs
// .sbpx branch.
func SniffMagic(head []byte) bool {
	return len(head) >= len(Magic) && bytes.Equal(head[:len(Magic)], Magic)
}

// EncryptForRecipient wraps signed .sbp plaintext for one X25519
// recipient (the 32-byte public key part of an `age` identity).
// Returns the full .sbpx bytes (magic + age stream).
//
// The recipient key is the raw 32-byte X25519 pub the
// `core/recipient/address` codec produces; we wrap it as an age
// X25519 recipient here.
func EncryptForRecipient(plaintext []byte, recipient [32]byte) ([]byte, error) {
	r, err := newX25519Recipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("envelope: build recipient: %w", err)
	}
	var ageBuf bytes.Buffer
	w, err := age.Encrypt(&ageBuf, r)
	if err != nil {
		return nil, fmt.Errorf("envelope: age.Encrypt init: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("envelope: write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("envelope: close age stream: %w", err)
	}
	out := make([]byte, 0, len(Magic)+ageBuf.Len())
	out = append(out, Magic...)
	out = append(out, ageBuf.Bytes()...)
	return out, nil
}

// Decrypt opens a .sbpx envelope using the recipient's X25519
// private key (the 32-byte raw scalar). Returns the inner .sbp
// plaintext.
func Decrypt(ciphertext []byte, priv [32]byte) ([]byte, error) {
	if len(ciphertext) > MaxCiphertextBytes {
		return nil, ErrCiphertextTooLarge
	}
	if !SniffMagic(ciphertext) {
		return nil, ErrBadMagic
	}
	body := ciphertext[len(Magic):]
	id, err := newX25519Identity(priv)
	if err != nil {
		return nil, fmt.Errorf("envelope: build identity: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(body), id)
	if err != nil {
		// age returns a variety of error types; we collapse them
		// into the single ErrDecrypt sentinel so the recipient-app
		// UI can show one consistent message.
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	out, err := io.ReadAll(io.LimitReader(r, MaxCiphertextBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrDecrypt, err)
	}
	if int64(len(out)) > MaxCiphertextBytes {
		return nil, ErrCiphertextTooLarge
	}
	return out, nil
}
