package share

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// DeriveBearerToken derives a session bearer token from the human-readable
// PIN and the session ID using HKDF-style expansion (HMAC-SHA256). The
// token is what the receiver presents in Authorization. Crucially, the PIN
// alone is not enough: an attacker who guesses 000000..999999 still needs
// to know the session ID we publish via mDNS / QR.
func DeriveBearerToken(pin, sessionID string) string {
	mac := hmac.New(sha256.New, []byte("daal-share/v1"))
	mac.Write([]byte(pin))
	mac.Write([]byte{0})
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
