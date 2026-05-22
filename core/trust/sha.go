package trust

import (
	"crypto/sha256"
	"encoding/hex"
)

// shaHex returns the lowercase-hex SHA-256 digest of b. This must match
// bundle.PublisherFingerprint exactly so trust pins keyed by hex compare
// across packages.
func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
