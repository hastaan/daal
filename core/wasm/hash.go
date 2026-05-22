// Phase 3E. Shared hash helper used by both the default and
// `-tags no_wasm` builds; lives in its own file so a no-build-
// tag declaration is visible to both. Stdlib only.

package wasm

import (
	"crypto/sha256"
	"encoding/hex"
)

func verifyHashImpl(body []byte, wantHex string) error {
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != wantHex {
		return ErrHashMismatch
	}
	return nil
}
