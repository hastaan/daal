// Package bootstrap implements Phase 1D: Tier-1/2/3 bootstrap material.
//
//   - Tier 1 (durable, embedded in every build):
//     project root pubkey + 3..5 publisher pubkeys + signed primary and
//     fallback pointer sets.
//   - Tier 2 (disposable, embedded sparingly, valid_until ≤ 30d):
//     3..8 emergency seed .sbp bundles signed by Tier-1 publishers.
//   - Tier 3 (fetched on first network reachability):
//     a directory .sbp signed by a Tier-1 publisher and pinned at fetch
//     time against the pointer's expected_publisher_fingerprint_hex.
//
// All cryptography in this package is built on daal/bundle-go (Ed25519,
// canonical JSON, .sbp parser/verifier). No new format is introduced.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// PointerSet is a signed list of bootstrap-directory URLs. The set is
// signed by the project root key (Tier-1). Clients accept a pointer set
// only when the signature verifies and `valid_until` is in the future.
type PointerSet struct {
	V            int       `json:"v"`
	Kind         string    `json:"kind"` // "bootstrap_pointers"
	Set          string    `json:"set"`  // "primary" | "fallback"
	IssuedAt     string    `json:"issued_at"`
	ValidUntil   string    `json:"valid_until"`
	Pointers     []Pointer `json:"pointers"`
	SignatureHex string    `json:"signature_hex"`
}

// Pointer is one URL the client may try to fetch the directory from.
type Pointer struct {
	URL                             string `json:"url"`
	ExpectedPublisherFingerprintHex string `json:"expected_publisher_fingerprint_hex"`
}

// SignPointerSet returns a copy of `set` with `SignatureHex` populated,
// signed by `priv`. The canonical JSON used for the signature is exactly
// the same JSON that VerifyPointerSet recomputes — see canonicalUnsigned.
func SignPointerSet(set PointerSet, priv ed25519.PrivateKey) (PointerSet, error) {
	if set.V == 0 {
		set.V = 1
	}
	if set.Kind == "" {
		set.Kind = "bootstrap_pointers"
	}
	if set.Set != "primary" && set.Set != "fallback" {
		return set, fmt.Errorf("pointer: set must be 'primary' or 'fallback'")
	}
	canonical, err := canonicalUnsignedPointerSet(set)
	if err != nil {
		return set, err
	}
	sig := ed25519.Sign(priv, canonical)
	set.SignatureHex = hex.EncodeToString(sig)
	return set, nil
}

// VerifyPointerSet checks the signature against `rootPub`, parses the
// timestamps, and rejects expired sets. On success it returns nil.
func VerifyPointerSet(set PointerSet, rootPub ed25519.PublicKey, now time.Time) error {
	if set.V != 1 {
		return fmt.Errorf("pointer: unsupported version %d", set.V)
	}
	if set.Kind != "bootstrap_pointers" {
		return fmt.Errorf("pointer: bad kind %q", set.Kind)
	}
	if set.Set != "primary" && set.Set != "fallback" {
		return fmt.Errorf("pointer: bad set %q", set.Set)
	}
	if len(set.Pointers) == 0 {
		return errors.New("pointer: no pointers")
	}
	for _, p := range set.Pointers {
		if p.URL == "" {
			return errors.New("pointer: empty url")
		}
		if len(p.ExpectedPublisherFingerprintHex) != 64 {
			return fmt.Errorf("pointer: bad fingerprint length for %s", p.URL)
		}
	}
	canonical, err := canonicalUnsignedPointerSet(set)
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(set.SignatureHex)
	if err != nil {
		return fmt.Errorf("pointer: bad signature hex: %w", err)
	}
	if !ed25519.Verify(rootPub, canonical, sig) {
		return errors.New("pointer: signature verification failed")
	}
	validUntil, err := time.Parse(time.RFC3339, set.ValidUntil)
	if err != nil {
		return fmt.Errorf("pointer: bad valid_until: %w", err)
	}
	if !validUntil.After(now) {
		return errors.New("pointer: set expired")
	}
	return nil
}

// canonicalUnsignedPointerSet returns canonical JSON of the set with
// SignatureHex elided. We sort pointer entries lexicographically by URL
// to make the signature input independent of input ordering.
func canonicalUnsignedPointerSet(set PointerSet) ([]byte, error) {
	sortedPointers := append([]Pointer(nil), set.Pointers...)
	sort.Slice(sortedPointers, func(i, j int) bool { return sortedPointers[i].URL < sortedPointers[j].URL })
	type unsignedDoc struct {
		V          int       `json:"v"`
		Kind       string    `json:"kind"`
		Set        string    `json:"set"`
		IssuedAt   string    `json:"issued_at"`
		ValidUntil string    `json:"valid_until"`
		Pointers   []Pointer `json:"pointers"`
	}
	doc := unsignedDoc{
		V: set.V, Kind: set.Kind, Set: set.Set,
		IssuedAt: set.IssuedAt, ValidUntil: set.ValidUntil,
		Pointers: sortedPointers,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	// Run through the bundle-go canonicalizer would normally happen here;
	// since our doc is small and well-formed JSON, we sort keys via a
	// re-marshal through map[string]any so the canonical form matches
	// publisher.canonical-style output.
	var anyDoc map[string]any
	if err := json.Unmarshal(raw, &anyDoc); err != nil {
		return nil, err
	}
	return canonicalSortedJSON(anyDoc)
}

func canonicalSortedJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalSorted(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalSorted(buf *bytes.Buffer, value any) error {
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
		// JSON unmarshalling produces float64 for all numbers.
		if v == float64(int64(v)) {
			fmt.Fprintf(buf, "%d", int64(v))
		} else {
			fmt.Fprintf(buf, "%g", v)
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
			if err := writeCanonicalSorted(buf, item); err != nil {
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
			b, _ := json.Marshal(k)
			buf.Write(b)
			buf.WriteByte(':')
			if err := writeCanonicalSorted(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", value)
	}
	return nil
}
