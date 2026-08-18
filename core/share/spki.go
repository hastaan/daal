package share

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrNoPin is returned when a receiver-side pull was asked to connect
// without an expected SPKI hash. This is deliberately NOT a warning that
// downgrades to an unpinned connection: an unpinned LAN pull is the
// whole vulnerability (anyone on the same Wi-Fi can answer the mDNS
// query and present their own cert), so "no pin supplied" MUST refuse.
var ErrNoPin = errors.New("share: refusing TLS without an expected SPKI pin")

// ErrPinMismatch is returned when the presented leaf certificate's SPKI
// hash is not the one the sender published.
var ErrPinMismatch = errors.New("share: TLS certificate SPKI does not match the published pin")

// spkiHashLen is the length of a SHA-256 digest. Any decoded pin of a
// different length is rejected outright rather than compared, so a
// truncated pin cannot be made to match by accident.
const spkiHashLen = sha256.Size

// SPKIHashFromDER computes base64url(sha256(RawSubjectPublicKeyInfo)) for
// a DER-encoded certificate. This is the exact value the sender publishes
// in the mDNS TXT `spki=` field and in the QR fallback URL, and the exact
// value the receiver pins. Sender and receiver MUST agree on this
// function; there is only one copy of it.
func SPKIHashFromDER(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return SPKIHashFromCert(cert), nil
}

// SPKIHashFromCert is SPKIHashFromDER for an already-parsed certificate.
func SPKIHashFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// decodePin turns the published base64url pin into raw bytes, refusing
// anything that is not exactly one SHA-256 digest. Both the standard and
// raw (unpadded) base64url alphabets are accepted because QR encoders and
// mDNS TXT writers in the wild disagree about padding; the DECODED value
// is what we compare, so accepting both spellings widens nothing.
func decodePin(pin string) ([]byte, error) {
	if pin == "" {
		return nil, ErrNoPin
	}
	raw, err := base64.RawURLEncoding.DecodeString(pin)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(pin)
	}
	if err != nil {
		return nil, fmt.Errorf("share: malformed SPKI pin: %w", err)
	}
	if len(raw) != spkiHashLen {
		return nil, fmt.Errorf("share: SPKI pin is %d bytes, want %d", len(raw), spkiHashLen)
	}
	return raw, nil
}

// pinnedVerifier builds the tls.Config.VerifyPeerCertificate callback that
// enforces the pin the spec has always promised.
//
// Why a callback and not the normal chain verification: the sender's cert
// is self-signed and generated fresh per session, so there is no CA to
// chain to and no stable name to match — chain verification would have to
// be disabled no matter what. InsecureSkipVerify therefore stays true,
// but it now means "we do our own verification", not "we do none". The
// callback runs during the handshake and its error aborts the handshake,
// so no request bytes (including the bearer token) are ever written to an
// unverified peer.
func pinnedVerifier(expectedPin string) (func(rawCerts [][]byte, _ [][]*x509.Certificate) error, error) {
	want, err := decodePin(expectedPin)
	if err != nil {
		return nil, err
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrPinMismatch
		}
		// rawCerts[0] is the leaf, per crypto/tls. We pin the leaf and
		// ignore the rest of the presented chain entirely: a self-signed
		// per-session cert has no chain worth inspecting, and an attacker
		// controls what they append to theirs.
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return ErrPinMismatch
		}
		got := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return ErrPinMismatch
		}
		return nil
	}, nil
}

// pinnedTLSConfig is the only tls.Config any receiver-side dial in this
// package may use. It refuses to exist without a usable pin, which is how
// "forgot to pass the pin" becomes a compile-adjacent error instead of a
// silent downgrade to trust-anything.
func pinnedTLSConfig(expectedPin string) (*tls.Config, error) {
	verify, err := pinnedVerifier(expectedPin)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		// Chain/name verification is off because the peer is a
		// self-signed per-session cert; VerifyPeerCertificate below is
		// the actual trust decision and it fails closed.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verify,
		MinVersion:            tls.VersionTLS12,
	}, nil
}
