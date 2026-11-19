package health

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// The provisioning bootstrap, and why it is authenticated.
//
// The health endpoint is plain HTTP on a fresh address: there is no
// certificate to verify yet, because the reply is where the publisher
// LEARNS the certificate — the management-plane TLS fingerprint it
// pins for the life of the relay (OperatorRecord.MgmtTLSFingerprint).
// Everything the relay later says about itself, including the keys the
// publisher signs into a pack, is believed because of that pin. So the
// pin must not be something a machine on the path can choose.
//
// What the two ends share that the path does not have is the health
// token: the publisher generates it, and it reaches the box inside
// cloud-init user-data, over the cloud provider's HTTPS API. It is
// therefore never sent. Two values are derived from it, with distinct
// labels so neither can stand in for the other:
//
//	path token  = hex(HMAC-SHA256(token, "daal-health-path-v1"))
//	fingerprint = hex(HMAC-SHA256(HMAC-SHA256(token, "daal-mgmt-fpr-v1"), fingerprint))
//
// The path token rides in the URL, so anyone on the path reads it — and
// learns nothing that makes a fingerprint MAC. The box returns the MAC
// beside the fingerprint; the poller refuses a fingerprint whose MAC
// does not verify. There is no unauthenticated fallback: a box whose
// health binary predates this cannot be provisioned by this publisher.
const (
	pathTokenLabel      = "daal-health-path-v1"
	fingerprintMACLabel = "daal-mgmt-fpr-v1"
)

// ErrFingerprintUnauthenticated means a health reply carried a
// management-TLS fingerprint without a valid MAC: something other than
// the box wrote it, or the box's health binary predates the MAC. The
// fingerprint is never returned to the caller.
var ErrFingerprintUnauthenticated = errors.New("health: mgmt_tls_fingerprint is not authenticated by the provisioning secret — refusing to pin it")

// ErrBootstrapRefused means a health endpoint answered 404 to the
// derived path token: it does not hold this provisioning secret, or it
// is a health binary from before the path token was derived (which
// expects the raw secret in the URL — something this publisher will
// not send).
var ErrBootstrapRefused = errors.New("health: the relay's health endpoint does not recognise this provisioning secret (status 404) — its software may predate the authenticated bootstrap")

func derive(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// PathToken is what goes in the URL in place of the health token.
func PathToken(token string) string {
	return hex.EncodeToString(derive([]byte(token), pathTokenLabel))
}

func canonicalFingerprint(fp string) string {
	return strings.ToLower(strings.TrimSpace(fp))
}

// FingerprintMAC authenticates a management-TLS fingerprint under the
// health token. The box computes it; the poller verifies it.
func FingerprintMAC(token, fingerprint string) string {
	key := derive([]byte(token), fingerprintMACLabel)
	return hex.EncodeToString(derive(key, canonicalFingerprint(fingerprint)))
}

// VerifyFingerprintMAC reports whether mac is FingerprintMAC(token,
// fingerprint), in constant time.
func VerifyFingerprintMAC(token, fingerprint, mac string) bool {
	got, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(mac)))
	if err != nil || len(got) != sha256.Size || token == "" {
		return false
	}
	want, _ := hex.DecodeString(FingerprintMAC(token, fingerprint))
	return hmac.Equal(got, want)
}
