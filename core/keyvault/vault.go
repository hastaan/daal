package keyvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// SealedBlob is the on-disk format of a vault-sealed secret. Stable
// at v1; widening fields requires a spec bump (and a v2 vault).
//
// Layout (little-endian where multi-byte):
//
//	[0]      version byte (0x01)
//	[1..16]  salt (V1SaltLen bytes)
//	[17..28] AES-GCM nonce (12 bytes)
//	[29..32] ciphertext length (uint32 LE)
//	[33..]   ciphertext (includes 16-byte AES-GCM tag at tail)
//
// The plaintext under the cipher is the age identity (or whatever
// the caller wants to seal — the vault is content-agnostic). The
// authenticated-data field is the constant string "daal-keyvault-v1"
// so a misaligned implementation rejects the blob immediately.
const (
	v1Version  byte = 0x01
	v1NonceLen      = 12
	v1AAD           = "daal-keyvault-v1"
)

// Seal encrypts plaintext under a PIN-derived key. Generates a fresh
// salt and a fresh nonce on every call, so identical plaintexts
// produce different ciphertexts (good — the vault is not a
// deterministic primitive).
func Seal(plaintext []byte, pin string) ([]byte, error) {
	if pin == "" {
		return nil, ErrEmptyPIN
	}
	salt, err := NewSalt()
	if err != nil {
		return nil, fmt.Errorf("keyvault: salt: %w", err)
	}
	key, err := Derive(pin, salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, v1NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(v1AAD))

	out := make([]byte, 0, 1+V1SaltLen+v1NonceLen+4+len(ciphertext))
	out = append(out, v1Version)
	out = append(out, salt...)
	out = append(out, nonce...)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
	out = append(out, lenBuf[:]...)
	out = append(out, ciphertext...)
	return out, nil
}

// Open is the inverse of Seal. Returns ErrWrongPIN if the AEAD tag
// fails to verify (which is the expected failure mode for a wrong
// PIN). Other errors reflect malformed input.
var ErrWrongPIN = errors.New("keyvault: wrong PIN")

func Open(blob []byte, pin string) ([]byte, error) {
	if pin == "" {
		return nil, ErrEmptyPIN
	}
	if len(blob) < 1+V1SaltLen+v1NonceLen+4 {
		return nil, errors.New("keyvault: blob too short")
	}
	if blob[0] != v1Version {
		return nil, fmt.Errorf("keyvault: unsupported version %d", blob[0])
	}
	salt := blob[1 : 1+V1SaltLen]
	nonceStart := 1 + V1SaltLen
	nonce := blob[nonceStart : nonceStart+v1NonceLen]
	lenStart := nonceStart + v1NonceLen
	ctLen := binary.LittleEndian.Uint32(blob[lenStart : lenStart+4])
	ctStart := lenStart + 4
	if uint32(len(blob)-ctStart) != ctLen {
		return nil, errors.New("keyvault: ciphertext length mismatch")
	}
	ciphertext := blob[ctStart:]

	key, err := Derive(pin, salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(v1AAD))
	if err != nil {
		return nil, ErrWrongPIN
	}
	return plaintext, nil
}

// wipe zeroes a key buffer best-effort. Go does not guarantee that
// the memory isn't paged or copied (it almost certainly is); this
// is a defense-in-depth measure that mirrors the secret-handling
// hygiene already in routestore's age identity loader.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
