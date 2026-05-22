//go:build !no_wasm

package wasm

// Phase 3E. WASM kill-switch verifier + secrets_kv cache + delta
// refresh hook.
//
// Locked at 3E (`specs/wasm-kill-switch-v1.md`):
//
//   - One project-controlled signing key custodied per CC.4
//     (hardware-token). Distinct from the bootstrap-directory
//     signing key. Loaded into the engine at init time as a
//     32-byte Ed25519 public key; surfaced over the ABI by
//     `engine_wasm_kill_switch_pubkey()`.
//   - Each delta entry binds (slug, sha256, generation) and
//     carries an Ed25519 signature over the canonical JSON
//     payload. Generations are monotonically increasing.
//   - Deltas are append-only within a generation: the engine
//     accepts a new generation only when its number is strictly
//     greater than the last accepted generation in the
//     secrets_kv cache. Rescinds are NOT supported at v1 (a
//     kill-switch is a one-way safety valve).
//   - The verifier is consulted on the existing pointer-rotation
//     refresh path; on success it inserts each (sha256) into the
//     Loader's killed set and persists `wasm_killed:<sha256>`
//     under the secrets_kv namespace.
//
// The kill-switch verifier is intentionally tiny: stdlib +
// crypto/ed25519 only. It does NOT touch the family registry, the
// path manager, or the bundle parser; the WASM family handler
// gates module load on `Loader.IsKilled` and does the right
// thing when a previously-loaded module is killed mid-session
// (the engine refuses on next-session load — by-design, no
// hot-replace at 3E).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Sentinel errors for kill-switch verification.
var (
	ErrKillSwitchPubkeyMissing  = errors.New("wasm: kill-switch pubkey not configured")
	ErrKillSwitchSignature      = errors.New("wasm: kill-switch signature invalid")
	ErrKillSwitchEntryMalformed = errors.New("wasm: kill-switch entry malformed")
	ErrKillSwitchGenerationGoes = errors.New("wasm: kill-switch generation must increase")
)

// KillSwitchEntry is the on-the-wire shape of a single kill-
// switch delta. The signature covers a deterministic JSON
// rendering of (slug, sha256_hex, generation) — exact bytes
// emitted by `canonicalEntryBytes`.
type KillSwitchEntry struct {
	Slug         string `json:"slug"`
	SHA256Hex    string `json:"sha256"`
	Generation   uint64 `json:"generation"`
	SignatureB64 string `json:"signature"`
}

// SecretsKV is the minimal subset of routestore.Store the kill-
// switch verifier needs. The interface keeps the wasm package
// free of a routestore import (the existing layering rule:
// wasm depends on bundle types if anything; routestore depends
// on wasm only via the family-string indirection).
type SecretsKV interface {
	PutSecret(key string, plaintext []byte) error
	GetSecret(key string) ([]byte, error)
	ListSecretKeys(prefix string) ([]string, error)
}

// KillSwitchVerifier is the engine-side coordinator. It owns:
//
//   - the project-controlled Ed25519 pubkey (immutable for the
//     session; the engine refuses to swap it at runtime),
//   - a generation watermark in secrets_kv under
//     `wasm_killed:_generation`,
//   - one secrets_kv entry per killed sha256 under
//     `wasm_killed:<sha256>`.
//
// Verifier is safe for concurrent use; the refresh-hook caller
// (the existing pointer-rotation loop) holds the mutex while
// applying a delta batch.
type KillSwitchVerifier struct {
	mu     sync.Mutex
	pub    ed25519.PublicKey
	loader *Loader
	kv     SecretsKV
}

// NewKillSwitchVerifier returns a verifier that mutates `loader`
// and persists into `kv`. `pub` is the 32-byte Ed25519 pubkey
// the project signs deltas with; passing nil makes every
// subsequent Apply call return ErrKillSwitchPubkeyMissing.
func NewKillSwitchVerifier(pub ed25519.PublicKey, loader *Loader, kv SecretsKV) *KillSwitchVerifier {
	return &KillSwitchVerifier{pub: pub, loader: loader, kv: kv}
}

// PubkeyHex returns the configured kill-switch pubkey as
// uppercase hex, or "" if unconfigured. Surfaced over the ABI
// by `engine_wasm_kill_switch_pubkey`.
func (v *KillSwitchVerifier) PubkeyHex() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.pub) == 0 {
		return ""
	}
	return hex.EncodeToString(v.pub)
}

// canonicalEntryBytes returns the deterministic JSON payload an
// entry's signature is over. Locked at 3E.
//
// Layout: `{"slug":"…","sha256":"…","generation":N}` with no
// whitespace and the keys in the literal order shown — Go's
// `encoding/json` does NOT guarantee key order on its own.
func canonicalEntryBytes(slug, sha256Hex string, gen uint64) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"slug":`)
	slugJSON, _ := json.Marshal(slug)
	buf.Write(slugJSON)
	buf.WriteString(`,"sha256":`)
	sumJSON, _ := json.Marshal(sha256Hex)
	buf.Write(sumJSON)
	fmt.Fprintf(&buf, `,"generation":%d}`, gen)
	return buf.Bytes()
}

// VerifyEntry checks the signature on a single entry. Public so
// the publisher CLI can self-verify a freshly-signed delta
// before publishing.
func VerifyEntry(pub ed25519.PublicKey, e KillSwitchEntry) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrKillSwitchPubkeyMissing
	}
	if e.Slug == "" || e.SHA256Hex == "" || len(e.SHA256Hex) != 64 {
		return ErrKillSwitchEntryMalformed
	}
	sig, err := decodeSig(e.SignatureB64)
	if err != nil {
		return ErrKillSwitchEntryMalformed
	}
	payload := canonicalEntryBytes(e.Slug, e.SHA256Hex, e.Generation)
	if !ed25519.Verify(pub, payload, sig) {
		return ErrKillSwitchSignature
	}
	return nil
}

// Apply ingests a batch of entries. Signature is verified on
// each entry; entries that fail verification are dropped (a
// single bad signature is not allowed to taint the rest of the
// batch — the publisher might be staging a new delta and a
// stale entry could be in flight). The first return is the
// count of newly-killed sha256 strings; the second is the count
// of entries skipped due to signature/format failures.
func (v *KillSwitchVerifier) Apply(entries []KillSwitchEntry) (newlyKilled, skipped int, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.pub) == 0 {
		return 0, len(entries), ErrKillSwitchPubkeyMissing
	}

	last, err := v.lastGeneration()
	if err != nil {
		return 0, 0, err
	}

	// Sort by generation ascending so monotonicity is
	// preserved when the publisher batches multiple
	// generations into a single delta.
	sorted := append([]KillSwitchEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Generation < sorted[j].Generation
	})

	highest := last
	for _, e := range sorted {
		if err := VerifyEntry(v.pub, e); err != nil {
			skipped++
			continue
		}
		if e.Generation <= last {
			// Already incorporated in a previous Apply; idempotent skip.
			skipped++
			continue
		}
		key := "wasm_killed:" + e.SHA256Hex
		if _, getErr := v.kv.GetSecret(key); getErr == nil {
			// Already present; bump generation only.
			if e.Generation > highest {
				highest = e.Generation
			}
			continue
		}
		entryJSON, _ := json.Marshal(e)
		if perr := v.kv.PutSecret(key, entryJSON); perr != nil {
			return newlyKilled, skipped, perr
		}
		v.loader.MarkKilled(e.SHA256Hex)
		newlyKilled++
		if e.Generation > highest {
			highest = e.Generation
		}
	}

	if highest > last {
		genBuf := []byte(fmt.Sprintf("%d", highest))
		if perr := v.kv.PutSecret("wasm_killed:_generation", genBuf); perr != nil {
			return newlyKilled, skipped, perr
		}
	}
	return newlyKilled, skipped, nil
}

// DaalteFromKV repopulates the loader's killed set from the
// secrets_kv namespace at engine boot. Returns the count of
// (sha256) keys daalted.
func (v *KillSwitchVerifier) DaalteFromKV() (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	keys, err := v.kv.ListSecretKeys("wasm_killed:")
	if err != nil {
		return 0, err
	}
	daalted := 0
	for _, k := range keys {
		if k == "wasm_killed:_generation" {
			continue
		}
		// Strip the prefix; the suffix IS the sha256 hex.
		const prefix = "wasm_killed:"
		if len(k) <= len(prefix) {
			continue
		}
		sha := k[len(prefix):]
		v.loader.MarkKilled(sha)
		daalted++
	}
	return daalted, nil
}

// KillSwitchedCount returns the count of distinct sha256 entries
// currently on the kill-list. Surfaced as the
// `wasm_kill_switched_count` diagnostic.
func (v *KillSwitchVerifier) KillSwitchedCount() (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	keys, err := v.kv.ListSecretKeys("wasm_killed:")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, k := range keys {
		if k == "wasm_killed:_generation" {
			continue
		}
		count++
	}
	return count, nil
}

// lastGeneration reads the watermark; absent ⇒ 0.
func (v *KillSwitchVerifier) lastGeneration() (uint64, error) {
	body, err := v.kv.GetSecret("wasm_killed:_generation")
	if err != nil {
		// Treat any error as absent. Storage errors surface
		// at the next Put.
		return 0, nil
	}
	var n uint64
	for _, c := range body {
		if c < '0' || c > '9' {
			return 0, nil
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

// decodeSig accepts the standard and URL-safe base64 encodings,
// with or without padding. The publisher CLI emits std-no-pad
// to match the rest of the bundle ecosystem; the verifier is
// permissive on input.
func decodeSig(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding,
		base64.RawURLEncoding, base64.URLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("wasm: signature not base64")
}
