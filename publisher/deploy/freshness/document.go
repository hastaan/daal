package freshness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// Document is the in-memory representation of one freshness
// statement. The on-wire format is the canonical JSON of this
// struct with field names lowered to snake_case.
type Document struct {
	Kind                string          `json:"kind"`
	RelayPackID         string          `json:"relay_pack_id"`
	CurrentBundleSHA256 string          `json:"current_bundle_sha256"`
	CurrentSignedURL    string          `json:"current_signed_url"`
	LastModified        string          `json:"last_modified"`
	PublisherPubHex     string          `json:"publisher_pub_hex"`
	SubkeyCert          json.RawMessage `json:"subkey_cert,omitempty"`
	SignatureHex        string          `json:"signature_hex"`
}

// BuildOpts feeds Build / BuildAndSign.
type BuildOpts struct {
	// RelayPackID is the bundle's Manifest.RelayPack.RelayPackID.
	RelayPackID string

	// BundleBytes is the signed .sbp body currently published at
	// CurrentSignedURL. If set, Build hashes these bytes into
	// CurrentBundleSHA256.
	BundleBytes []byte

	// CurrentBundleSHA256 is the SHA-256 hex digest of the signed
	// .sbp body. Required when BundleBytes is empty.
	CurrentBundleSHA256 string

	// CurrentSignedURL is the recipient-fetchable signed .sbp URL.
	CurrentSignedURL string

	// PublisherPubHex is the publisher root public key in hex.
	PublisherPubHex string

	// LastModified is the document's freshness timestamp; defaults
	// to now.
	LastModified time.Time
}

// Build emits an unsigned Document. The caller signs with Sign or
// SignWithSubkey.
func Build(opts BuildOpts) (*Document, error) {
	if opts.RelayPackID == "" {
		return nil, errors.New("freshness: RelayPackID required")
	}
	if opts.CurrentSignedURL == "" {
		return nil, errors.New("freshness: CurrentSignedURL required")
	}
	u, err := url.Parse(opts.CurrentSignedURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("freshness: CurrentSignedURL must be https")
	}
	if opts.PublisherPubHex == "" {
		return nil, errors.New("freshness: PublisherPubHex required")
	}
	shaHex := opts.CurrentBundleSHA256
	if len(opts.BundleBytes) > 0 {
		sum := sha256.Sum256(opts.BundleBytes)
		shaHex = hex.EncodeToString(sum[:])
	}
	if !isSHA256Hex(shaHex) {
		return nil, errors.New("freshness: CurrentBundleSHA256 required")
	}
	if _, err := hex.DecodeString(opts.PublisherPubHex); err != nil {
		return nil, errors.New("freshness: PublisherPubHex must be hex")
	}
	modified := opts.LastModified
	if modified.IsZero() {
		modified = time.Now().UTC()
	}
	modified = modified.UTC()
	return &Document{
		Kind:                "daal/freshness-v1",
		RelayPackID:         opts.RelayPackID,
		CurrentBundleSHA256: shaHex,
		CurrentSignedURL:    opts.CurrentSignedURL,
		LastModified:        modified.Format(time.RFC3339),
		PublisherPubHex:     opts.PublisherPubHex,
	}, nil
}

// Sign signs the supplied unsigned Document with the publisher
// root key. Use this when the FRP has no active sub-key.
func Sign(doc *Document, rootPriv ed25519.PrivateKey) ([]byte, error) {
	if doc == nil {
		return nil, errors.New("freshness: nil document")
	}
	if len(rootPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("freshness: invalid root private key")
	}
	doc.SubkeyCert = nil
	pub := rootPriv.Public().(ed25519.PublicKey)
	if doc.PublisherPubHex == "" {
		doc.PublisherPubHex = hex.EncodeToString(pub)
	}
	body, err := canonicalBytesExcludingSignature(doc)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(rootPriv, body)
	doc.SignatureHex = hex.EncodeToString(sig)
	return canonicalBytes(doc)
}

// SignWithSubkey signs with an active sub-key. The supplied
// subkeyCertJSON is the publisher-side SubkeyCert JSON the
// recipient walks to validate the chain. The cert is embedded as
// the structured `subkey_cert` object in the document.
func SignWithSubkey(doc *Document, subkeyPriv ed25519.PrivateKey, subkeyCertJSON []byte) ([]byte, error) {
	if doc == nil {
		return nil, errors.New("freshness: nil document")
	}
	if len(subkeyPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("freshness: invalid sub-key private key")
	}
	if len(subkeyCertJSON) == 0 {
		return nil, errors.New("freshness: SubkeyCertJSON required when signing with sub-key")
	}
	canonCert, err := canonicalRawJSON(subkeyCertJSON)
	if err != nil {
		return nil, fmt.Errorf("freshness: canonical subkey cert: %w", err)
	}
	doc.SubkeyCert = canonCert
	body, err := canonicalBytesExcludingSignature(doc)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(subkeyPriv, body)
	doc.SignatureHex = hex.EncodeToString(sig)
	return canonicalBytes(doc)
}

// VerifyOpts feeds Verify.
type VerifyOpts struct {
	// PublisherRootPub is the bundle's publisher root key.
	// Required.
	PublisherRootPub ed25519.PublicKey

	// Now is the wall-clock used for cert-chain window checks
	// (when the document carries a SubkeyCertJSON). Defaults
	// to time.Now().
	Now time.Time
}

// Verify parses the document, walks the cert chain when
// present, and verifies the signature. Returns the parsed
// document on success. Used by the recipient-side core/refresh/
// path AND by publisher-side tests; the recipient module pulls
// the same logic via a small adapter (commit 5/8).
func Verify(docBytes []byte, opts VerifyOpts) (*Document, error) {
	if len(opts.PublisherRootPub) != ed25519.PublicKeySize {
		return nil, errors.New("freshness: PublisherRootPub required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var doc Document
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("freshness: malformed document: %w", err)
	}
	if doc.Kind != "daal/freshness-v1" {
		return nil, errors.New("freshness: unsupported document kind/version")
	}
	if doc.RelayPackID == "" || !isSHA256Hex(doc.CurrentBundleSHA256) || doc.CurrentSignedURL == "" || doc.PublisherPubHex == "" {
		return nil, errors.New("freshness: required fields missing")
	}
	u, err := url.Parse(doc.CurrentSignedURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("freshness: current_signed_url must be https")
	}
	if _, err := time.Parse(time.RFC3339, doc.LastModified); err != nil {
		return nil, fmt.Errorf("freshness: malformed last_modified: %w", err)
	}
	pubHex := hex.EncodeToString(opts.PublisherRootPub)
	if !equalHex(pubHex, doc.PublisherPubHex) {
		return nil, errors.New("freshness: publisher_pub_hex mismatch")
	}
	signingPub := ed25519.PublicKey(opts.PublisherRootPub)
	if len(doc.SubkeyCert) > 0 {
		// Walk the FRP-7.5 chain: cert is signed by root; sub-key
		// is the cert's subject. Cert's validity window enforced
		// by walkSubkeyCert.
		sub, err := walkSubkeyCert(doc.SubkeyCert, opts.PublisherRootPub, now)
		if err != nil {
			return nil, fmt.Errorf("freshness: subkey cert: %w", err)
		}
		signingPub = sub
	}
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("freshness: malformed signature_hex")
	}
	body, err := canonicalBytesExcludingSignature(&doc)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signingPub, body, sig) {
		return nil, errors.New("freshness: signature invalid")
	}
	return &doc, nil
}

// canonicalBytes emits the canonical JSON of doc with all fields,
// including signature_hex. canonicalBytesExcludingSignature emits
// the same with signature_hex stripped — the bytes the signer
// signs.
//
// The implementation mirrors publisher.canonicalJSONExcluding +
// bundle.subkey_chain.go::writeCanonicalCert byte-for-byte so the
// freshness signer round-trips against the bundle's sub-key
// resolver and the publisher-side cert canonicaliser.
func canonicalBytes(doc *Document) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var any any
	if err := json.Unmarshal(raw, &any); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, any); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalBytesExcludingSignature(doc *Document) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var any any
	if err := json.Unmarshal(raw, &any); err != nil {
		return nil, err
	}
	if obj, ok := any.(map[string]interface{}); ok {
		delete(obj, "signature_hex")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, any); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalRawJSON(raw []byte) (json.RawMessage, error) {
	var any any
	if err := json.Unmarshal(raw, &any); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, any); err != nil {
		return nil, err
	}
	return json.RawMessage(buf.Bytes()), nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func writeCanonical(buf *bytes.Buffer, value any) error {
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
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("freshness: unsupported value type %T", v)
	}
	return nil
}
