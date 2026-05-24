package keyvault

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

// V1 Argon2id parameters. Locked. See doc.go for rationale.
const (
	V1Time      uint32 = 3
	V1MemoryKiB uint32 = 64 * 1024 // 64 MiB
	V1Parallel  uint8  = 4
	V1SaltLen          = 16
	V1OutLen    uint32 = 32
)

// ErrEmptyPIN is returned by Derive when called with an empty PIN.
// We deliberately refuse the empty case to prevent silent
// derivation collisions across users.
var ErrEmptyPIN = errors.New("keyvault: empty PIN")

// NewSalt returns a fresh V1SaltLen-byte salt drawn from
// crypto/rand. The salt is non-secret; persist it next to the
// sealed blob.
func NewSalt() ([]byte, error) {
	s := make([]byte, V1SaltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Derive runs Argon2id over (pin, salt) with the v1 parameters and
// returns a 32-byte key. The pin string is NOT mutated by this
// function; the caller is responsible for any zeroing it can
// arrange (Go strings are immutable so true zeroing is best-effort
// at the byte-slice level, see secrets.go for the wipe pattern).
func Derive(pin string, salt []byte) ([]byte, error) {
	if pin == "" {
		return nil, ErrEmptyPIN
	}
	if len(salt) != V1SaltLen {
		return nil, errors.New("keyvault: bad salt length")
	}
	return argon2.IDKey([]byte(pin), salt, V1Time, V1MemoryKiB, V1Parallel, V1OutLen), nil
}
