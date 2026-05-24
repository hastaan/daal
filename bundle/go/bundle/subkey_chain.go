package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

// FRP-7.5: sub-key cert chain verifier.
//
// This file is the bundle-side counterpart of
// `publisher/subkey.go::SubkeyCert` + `VerifySubkeyCert`. The
// duplication is unavoidable: the bundle module is its own
// go.mod and cannot import the publisher package. A regression
// test in `bundle/go/bundle/sbp_subkey_test.go` round-trips the
// shape against a publisher-side cert, locking the wire format
// across both modules.
//
// The on-disk shape is the canonical JSON produced by
// `publisher.SubkeyCert`:
//
//	{
//	  "v": 1,
//	  "kind": "subkey_cert",
//	  "root_fingerprint_hex": "<hex>",
//	  "subkey_pub_hex": "<hex>",
//	  "valid_from": "<RFC3339>",
//	  "valid_until": "<RFC3339>",
//	  "label": "<string>",
//	  "signature_hex": "<hex>"
//	}
//
// The signature covers the canonical-JSON of the cert with
// `signature_hex` stripped, signed by the root publisher key.

// subkeyCertWire is the on-disk shape; field names mirror
// `publisher.SubkeyCert` exactly.
type subkeyCertWire struct {
	V                  int    `json:"v"`
	Kind               string `json:"kind"`
	RootFingerprintHex string `json:"root_fingerprint_hex"`
	SubkeyPubHex       string `json:"subkey_pub_hex"`
	ValidFrom          string `json:"valid_from"`
	ValidUntil         string `json:"valid_until"`
	Label              string `json:"label"`
	SignatureHex       string `json:"signature_hex"`
}

// resolveManifestSigningKey walks the cert chain (when present)
// and returns the public key the manifest signature MUST verify
// against, or an error.
//
//   - If subkeyCertJSON is empty, returns publisherPub directly
//     (the 1A path; unchanged).
//   - Otherwise parses + verifies the cert against publisherPub,
//     enforces the validity window with `now`, and returns the
//     cert's subject sub-key.
func resolveManifestSigningKey(
	subkeyCertJSON []byte,
	publisherPub ed25519.PublicKey,
	now time.Time,
) (ed25519.PublicKey, error) {
	if len(subkeyCertJSON) == 0 {
		return publisherPub, nil
	}
	var cert subkeyCertWire
	if err := json.Unmarshal(subkeyCertJSON, &cert); err != nil {
		return nil, ErrSubkeyCertMalformed
	}
	if cert.V != 1 || cert.Kind != "subkey_cert" {
		return nil, ErrSubkeyCertMalformed
	}
	subPub, err := hex.DecodeString(cert.SubkeyPubHex)
	if err != nil || len(subPub) != ed25519.PublicKeySize {
		return nil, ErrSubkeyCertMalformed
	}
	rootFP := PublisherFingerprint(publisherPub).Hex
	if cert.RootFingerprintHex != rootFP {
		return nil, ErrSubkeyCertRootMismatch
	}
	from, err1 := time.Parse(time.RFC3339, cert.ValidFrom)
	until, err2 := time.Parse(time.RFC3339, cert.ValidUntil)
	if err1 != nil || err2 != nil {
		return nil, ErrSubkeyCertMalformed
	}
	if now.Before(from) || !now.Before(until) {
		return nil, ErrSubkeyCertOutOfWindow
	}
	if err := verifyCertSignatureCanonical(cert, publisherPub); err != nil {
		return nil, ErrSubkeyCertBadSignature
	}
	return ed25519.PublicKey(subPub), nil
}

// verifyCertSignatureCanonical re-canonicalises the cert with
// `signature_hex` stripped and verifies the on-disk signature
// against publisherPub. Mirrors the publisher-side
// `verifyCanonical(cert, "signature_hex", ..., rootPub)` exactly.
func verifyCertSignatureCanonical(cert subkeyCertWire, publisherPub ed25519.PublicKey) error {
	sig, err := hex.DecodeString(cert.SignatureHex)
	if err != nil {
		return ErrSubkeyCertBadSignature
	}
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		return ErrSubkeyCertMalformed
	}
	if !ed25519.Verify(publisherPub, body, sig) {
		return ErrSubkeyCertBadSignature
	}
	return nil
}

// canonicalCertBytesExcludingSignature emits the canonical JSON
// of cert with the `signature_hex` field stripped — the same
// payload the publisher signed. The implementation mirrors
// `publisher.canonicalJSONExcluding` byte-for-byte (locked across
// modules; a regression test exercises a publisher-signed cert).
func canonicalCertBytesExcludingSignature(cert subkeyCertWire) ([]byte, error) {
	raw, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if obj, ok := doc.(map[string]any); ok {
		delete(obj, "signature_hex")
	}
	var buf bytes.Buffer
	if err := writeCanonicalCert(&buf, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonicalCert is the local mirror of publisher's
// writeCanonical. Kept private to avoid widening this module's
// public surface.
func writeCanonicalCert(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		if v == float64(int64(v)) {
			buf.WriteString(strconv.FormatInt(int64(v), 10))
		} else {
			buf.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalCert(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := writeCanonicalCert(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return ErrSubkeyCertMalformed
	}
	return nil
}
