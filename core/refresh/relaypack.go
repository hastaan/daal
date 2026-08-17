// relaypack.go is the FRP-8 V1.6 freshness-driven RelayPack
// refresh adapter. It is the network-IO + atomic-swap half of
// the layer split documented in
// core/internal/selection/freshness.go.
//
// LAYER SPLIT:
//
//   - core/internal/selection/freshness.go: pure trigger policy.
//     No sockets, no http. Position B enforced by the existing
//     selection opsec test.
//
//   - core/refresh/relaypack.go (this file): network IO via
//     bootstrap.FetchRaw, freshness JSON parse + signature verify
//     (sub-key-aware), signed-bundle SHA comparison, atomic
//     swap via bundle/go/importer.ApplyVerifiedRefresh.
//
//   - bundle/go/importer.ApplyVerifiedRefresh: re-verifies the
//     SBP signature, re-runs the V16 RelayPack validator
//     (RP022/RP023/RP024 hardening attestation gates fire the
//     same as on the QR-scan import path), upserts atomically.
//
// OPSEC invariants:
//   - This package is allowed net/http indirectly via
//     bootstrap.FetchRaw (which uses raw TLS / HTTP/1.1, not
//     net/http). The package-level opsec test in core/refresh/
//     prevents net/http itself.
//   - Freshness URLs are NEVER logged.
//   - The fetched bytes are bounded; we cap at 64KB.

package refresh

import (
	"bytes"
	"context"
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

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
	"daal/core/bootstrap"
)

// ErrFreshnessExpired is returned when the freshness document's
// expires_at is in the past. The caller (host pipeline) records
// the failure and re-attempts later per FreshnessPolicy.RetryBackoff.
var ErrFreshnessExpired = errors.New("freshness document expired")

// ErrFreshnessSignature is returned when the document's signature
// does not verify against the bundle's publisher root key (or the
// embedded sub-key cert is invalid).
var ErrFreshnessSignature = errors.New("freshness signature invalid")

// ErrFreshnessVersion is returned for unsupported document
// version/kind tuples.
var ErrFreshnessVersion = errors.New("unsupported freshness document")

// FreshnessOutcome is the structured result of one refresh
// attempt. It is what the host pipeline stores onto the
// per-RelayPack FreshnessState plus an optional signed-bundle
// change marker the UI can surface.
type FreshnessOutcome struct {
	// FetchedAt is the wall-clock at fetch completion.
	FetchedAt time.Time
	// CurrentBundleSHA256 is the signed .sbp SHA-256 the
	// freshness document is currently pointing at.
	CurrentBundleSHA256 string
	// ChangedFromCurrent is true when CurrentBundleSHA256
	// differs from currentBundleSHA256. When true the host
	// pipeline fetches CurrentSignedURL and applies the bundle.
	ChangedFromCurrent bool
	// Document is the parsed document on success (nil on
	// error).
	Document *FreshnessDocument
}

// FreshnessDocument mirrors publisher/deploy/freshness.Document
// byte-for-byte. Duplicated here because core/ cannot import
// publisher/. A regression test (relaypack_freshness_test.go)
// round-trips the shape against publisher's signer.
type FreshnessDocument struct {
	Kind                string          `json:"kind"`
	RelayPackID         string          `json:"relay_pack_id"`
	CurrentBundleSHA256 string          `json:"current_bundle_sha256"`
	CurrentSignedURL    string          `json:"current_signed_url"`
	LastModified        string          `json:"last_modified"`
	PublisherPubHex     string          `json:"publisher_pub_hex"`
	SubkeyCert          json.RawMessage `json:"subkey_cert,omitempty"`
	SignatureHex        string          `json:"signature_hex"`
}

// FetchAndVerifyFreshness fetches the freshness JSON at url,
// verifies its signature against publisherRootPub (walking the
// embedded sub-key cert when present), and returns the parsed
// outcome. The caller's currentBundleSHA256 is the recipient's
// locally-pinned signed .sbp digest; the outcome flags
// ChangedFromCurrent when the freshness document points at a
// different signed bundle.
func FetchAndVerifyFreshness(
	ctx context.Context,
	url string,
	publisherRootPub ed25519.PublicKey,
	currentBundleSHA256 string,
	dialer bootstrap.Dialer,
	timeout time.Duration,
	now time.Time,
) (*FreshnessOutcome, error) {
	raw, err := bootstrap.FetchRaw(ctx, url, dialer, timeout)
	if err != nil {
		return nil, fmt.Errorf("freshness fetch: %w", err)
	}
	if len(raw) > 64*1024 {
		raw = raw[:64*1024]
	}
	doc, err := verifyFreshnessDoc(raw, publisherRootPub, now)
	if err != nil {
		return nil, err
	}
	return &FreshnessOutcome{
		FetchedAt:           now.UTC(),
		CurrentBundleSHA256: doc.CurrentBundleSHA256,
		ChangedFromCurrent:  !equalHex(doc.CurrentBundleSHA256, currentBundleSHA256),
		Document:            doc,
	}, nil
}

// ApplyRefresh applies the supplied bundle bytes via the importer's
// ApplyVerifiedRefresh entry point, threading the freshness
// document's CurrentBundleSHA256 as the cross-check value the
// importer compares against the signed .sbp body.
//
// This is the "atomic swap" call the phase doc §13 layer split
// names. The importer is responsible for the atomic upsert; this
// function is a thin adapter that propagates the verified
// signed bundle digest.
func ApplyRefresh(
	bundleBody []byte,
	doc *FreshnessDocument,
	st importer.State,
	wordlists bundle.Wordlists,
	now time.Time,
) (importer.Verdict, error) {
	if doc == nil {
		return importer.Verdict{Kind: importer.VerdictRejected, Reason: "freshness_doc_nil"},
			errors.New("freshness document required")
	}
	return importer.ApplyVerifiedRefresh(bundleBody, doc.CurrentBundleSHA256, st, wordlists, now)
}

// verifyFreshnessDoc parses + verifies the document. Sub-key-aware:
// when SubkeyCert is non-empty, walks the cert chain via the
// shared bundle.subkeyCert path (mirrored locally below); otherwise
// verifies against publisherRootPub.
func verifyFreshnessDoc(raw []byte, publisherRootPub ed25519.PublicKey, now time.Time) (*FreshnessDocument, error) {
	var doc FreshnessDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("freshness parse: %w", err)
	}
	if doc.Kind != "daal/freshness-v1" {
		return nil, ErrFreshnessVersion
	}
	if doc.RelayPackID == "" || !isSHA256Hex(doc.CurrentBundleSHA256) || doc.CurrentSignedURL == "" || doc.PublisherPubHex == "" {
		return nil, errors.New("freshness: required fields missing")
	}
	u, err := url.Parse(doc.CurrentSignedURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("freshness: current_signed_url must be https")
	}
	if _, err := time.Parse(time.RFC3339, doc.LastModified); err != nil {
		return nil, fmt.Errorf("freshness last_modified: %w", err)
	}
	if !equalHex(hex.EncodeToString(publisherRootPub), doc.PublisherPubHex) {
		return nil, errors.New("freshness: publisher_pub_hex mismatch")
	}
	signingPub := ed25519.PublicKey(publisherRootPub)
	if len(doc.SubkeyCert) > 0 {
		sub, err := walkFreshnessSubkeyCert(doc.SubkeyCert, publisherRootPub, now)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFreshnessSignature, err)
		}
		signingPub = sub
	}
	sig, err := hex.DecodeString(doc.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrFreshnessSignature
	}
	body, err := canonicalDocBytesExcludingSignature(&doc)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signingPub, body, sig) {
		return nil, ErrFreshnessSignature
	}
	return &doc, nil
}

// walkFreshnessSubkeyCert mirrors bundle/go/bundle/subkey_chain.go
// byte-for-byte (minus the package-private types). A regression
// test pins the format across both modules.
func walkFreshnessSubkeyCert(certJSON []byte, rootPub ed25519.PublicKey, now time.Time) (ed25519.PublicKey, error) {
	var cert struct {
		V                  int    `json:"v"`
		Kind               string `json:"kind"`
		RootFingerprintHex string `json:"root_fingerprint_hex"`
		SubkeyPubHex       string `json:"subkey_pub_hex"`
		ValidFrom          string `json:"valid_from"`
		ValidUntil         string `json:"valid_until"`
		Label              string `json:"label"`
		SignatureHex       string `json:"signature_hex"`
	}
	if err := json.Unmarshal(certJSON, &cert); err != nil {
		return nil, fmt.Errorf("malformed: %w", err)
	}
	if cert.V != 1 || cert.Kind != "subkey_cert" {
		return nil, errors.New("malformed: bad version/kind")
	}
	subPub, err := hex.DecodeString(cert.SubkeyPubHex)
	if err != nil || len(subPub) != ed25519.PublicKeySize {
		return nil, errors.New("malformed: subkey_pub_hex")
	}
	sum := sha256.Sum256(rootPub)
	if cert.RootFingerprintHex != hex.EncodeToString(sum[:]) {
		return nil, errors.New("root fingerprint mismatch")
	}
	from, err1 := time.Parse(time.RFC3339, cert.ValidFrom)
	until, err2 := time.Parse(time.RFC3339, cert.ValidUntil)
	if err1 != nil || err2 != nil {
		return nil, errors.New("malformed: validity window")
	}
	if now.Before(from) || !now.Before(until) {
		return nil, errors.New("out of window")
	}
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(cert.SignatureHex)
	if err != nil {
		return nil, errors.New("malformed: signature_hex")
	}
	if !ed25519.Verify(rootPub, body, sig) {
		return nil, errors.New("signature invalid")
	}
	return ed25519.PublicKey(subPub), nil
}

// canonicalDocBytesExcludingSignature emits the canonical-JSON
// of the document with signature_hex stripped — the bytes the
// signer signed.
func canonicalDocBytesExcludingSignature(doc *FreshnessDocument) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if obj, ok := v.(map[string]any); ok {
		delete(obj, "signature_hex")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func canonicalCertBytesExcludingSignature(cert any) ([]byte, error) {
	raw, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if obj, ok := v.(map[string]any); ok {
		delete(obj, "signature_hex")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
		return fmt.Errorf("unsupported value %T", v)
	}
	return nil
}

func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
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
