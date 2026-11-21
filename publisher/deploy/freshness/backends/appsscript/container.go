package appsscript

// The daal-refresh-v1 container (specs/relaypack-v1.md, "The
// daal-refresh-v1 container") and the MAC of the update that carries
// it to the script.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"daal/bundle-go/bundle"
)

// ContainerKind is the container's kind discriminator.
const ContainerKind = "daal-refresh-v1"

// Limits, all from the spec.
const (
	MaxContainer = 65536     // the whole UTF-8 JSON
	MaxFreshness = 16 << 10  // the freshness document, decoded
	MaxPack      = 48 << 10  // the signed credential-less pack, decoded
	maxSeq       = 1<<53 - 1 // what the script's Number.isSafeInteger accepts
)

// standbyKeyRe: 26 symbols of Crockford's base32, canonical upper case.
var standbyKeyRe = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// wire is the container as it travels.
type wire struct {
	Kind       string `json:"kind"`
	Freshness  string `json:"freshness,omitempty"`
	Pack       string `json:"pack,omitempty"`
	StandbyKey string `json:"standby_key,omitempty"`
}

// Parts are a parsed container. Nothing in it is trusted because of
// where it came from: each part authenticates itself downstream.
type Parts struct {
	// Freshness is the document's exact bytes; nil in the empty
	// container a removed channel serves.
	Freshness  []byte
	Pack       []byte
	StandbyKey string
}

// Empty is the container a removed channel serves: "nothing new".
func Empty() []byte { return []byte(`{"kind":"` + ContainerKind + `"}`) }

// docRef is what Build reads of the freshness document: enough to
// refuse a pack the document does not name, and the sequence the
// update is numbered with.
type docRef struct {
	Kind                string `json:"kind"`
	Sequence            uint64 `json:"sequence"`
	CurrentBundleSHA256 string `json:"current_bundle_sha256"`
}

func readDoc(doc []byte) (docRef, error) {
	var d docRef
	if err := json.Unmarshal(doc, &d); err != nil {
		return d, fmt.Errorf("appsscript: the freshness document is not JSON: %w", err)
	}
	if d.Sequence == 0 {
		return d, errors.New("appsscript: the freshness document has no sequence")
	}
	return d, nil
}

// DocSequence is the freshness document's own sequence. The update to
// the script is numbered with it, so the script's high-water mark moves
// with the document's.
func DocSequence(doc []byte) (uint64, error) {
	d, err := readDoc(doc)
	return d.Sequence, err
}

// Build makes a container from the document, optionally the pack it
// names and a standby key. The pack must be the one the document names
// (its SHA-256 is the document's current_bundle_sha256): a container
// carrying another file would be refused by every recipient while the
// publisher saw a green publish.
func Build(freshnessDoc, pack []byte, standbyKey string) ([]byte, error) {
	if len(freshnessDoc) == 0 {
		return nil, errors.New("appsscript: a container needs the freshness document")
	}
	if len(freshnessDoc) > MaxFreshness {
		return nil, fmt.Errorf("appsscript: freshness document is %d bytes, at most %d", len(freshnessDoc), MaxFreshness)
	}
	d, err := readDoc(freshnessDoc)
	if err != nil {
		return nil, err
	}
	w := wire{Kind: ContainerKind, Freshness: base64.StdEncoding.EncodeToString(freshnessDoc)}
	if len(pack) > 0 {
		if len(pack) > MaxPack {
			return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrPackTooLarge, len(pack), MaxPack)
		}
		sum := sha256.Sum256(pack)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(d.CurrentBundleSHA256)) {
			return nil, errors.New("appsscript: the pack is not the one the freshness document names")
		}
		w.Pack = base64.StdEncoding.EncodeToString(pack)
	}
	if strings.TrimSpace(standbyKey) != "" {
		// The key as the publisher holds it: `standby promote` prints it
		// in groups (bundle.StandbyKeyBytes.Text). Read it the way the
		// engine reads a typed key (spaces and '-' ignored, case folded,
		// O/I/L read as digits, trailing bits zero) and carry the one
		// canonical form, 26 symbols run together, which is all a
		// recipient's container reader accepts.
		k, err := bundle.ParseStandbyKeyText(standbyKey)
		if err != nil {
			return nil, fmt.Errorf("appsscript: standby key: %w", err)
		}
		w.StandbyKey = strings.ReplaceAll(k.Text(), " ", "")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	if len(out) > MaxContainer {
		return nil, fmt.Errorf("%w: container is %d bytes, at most %d", ErrPackTooLarge, len(out), MaxContainer)
	}
	return out, nil
}

// ErrPackTooLarge: the pack does not fit; the container can still go
// without it (recipients then fetch the pack from current_signed_url).
var ErrPackTooLarge = errors.New("appsscript: the pack does not fit in the container")

// Parse reads a container with the spec's limits. It checks shape
// only; the caller verifies each part.
func Parse(body []byte) (*Parts, error) {
	if len(body) > MaxContainer {
		return nil, fmt.Errorf("appsscript: container is %d bytes, at most %d", len(body), MaxContainer)
	}
	var w wire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("appsscript: container is not JSON: %w", err)
	}
	if w.Kind != ContainerKind {
		return nil, errors.New("appsscript: not a daal-refresh-v1 container")
	}
	p := &Parts{}
	if w.Freshness == "" {
		if w.Pack != "" || w.StandbyKey != "" {
			return nil, errors.New("appsscript: container parts without a freshness document")
		}
		return p, nil
	}
	f, err := decodeLimited(w.Freshness, MaxFreshness)
	if err != nil {
		return nil, fmt.Errorf("appsscript: freshness: %w", err)
	}
	p.Freshness = f
	if w.Pack != "" {
		pk, err := decodeLimited(w.Pack, MaxPack)
		if err != nil {
			return nil, fmt.Errorf("appsscript: pack: %w", err)
		}
		p.Pack = pk
	}
	if w.StandbyKey != "" {
		if !standbyKeyRe.MatchString(w.StandbyKey) {
			return nil, errors.New("appsscript: malformed standby key")
		}
		p.StandbyKey = w.StandbyKey
	}
	return p, nil
}

func decodeLimited(s string, max int) ([]byte, error) {
	if base64.StdEncoding.DecodedLen(len(s)) > max+2 {
		return nil, fmt.Errorf("more than %d bytes", max)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("not base64")
	}
	if len(b) > max {
		return nil, fmt.Errorf("more than %d bytes", max)
	}
	return b, nil
}

// MAC is the update's authenticator, as 64 lower-case hex characters:
// HMAC-SHA256(write key, ASCII decimal seq ‖ 0x0A ‖ blob).
func MAC(writeKey []byte, seq uint64, blob []byte) string {
	m := hmac.New(sha256.New, writeKey)
	m.Write([]byte(strconv.FormatUint(seq, 10)))
	m.Write([]byte{'\n'})
	m.Write(blob)
	return hex.EncodeToString(m.Sum(nil))
}

// update is the body POSTed to the script.
type update struct {
	Seq  uint64 `json:"seq"`
	Blob string `json:"blob"`
	MAC  string `json:"mac"`
}

// UpdateBody is the JSON the publisher POSTs for one container.
func UpdateBody(writeKey []byte, seq uint64, blob []byte) ([]byte, error) {
	if len(writeKey) != WriteKeySize {
		return nil, errors.New("appsscript: write key must be 32 bytes")
	}
	if seq == 0 || seq > maxSeq {
		return nil, fmt.Errorf("appsscript: update number %d is out of range", seq)
	}
	if len(blob) > MaxContainer {
		return nil, errors.New("appsscript: container too large")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(update{Seq: seq, Blob: string(blob), MAC: MAC(writeKey, seq, blob)}); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
