# bundle-rs v1

## Status

**Phase 1.5B.** Implemented in `client-desktop/bundle-rs/`. Pure Rust,
verify-only. Forbids `unsafe_code`. No file I/O, no network, no
logging.

## Scope

`bundle-rs` is the desktop GUI's **fast local verifier** for `.sbp`
files. It exists so the trust prompt (publisher fingerprint, route
list, expiry) can render before the user commits to importing — without
crossing the C ABI for read-only verification.

In-scope (1.5B):

- `parse_manifest` / `verify_manifest` — manifest JSON + ed25519
  detached signature, with the same canonical-JSON serialization the
  Go side uses.
- `parse_sbp` — `.sbp` zip walk, `unsafe_path` rejection.
- `verify_bundle` — full `bundle.VerifyBundle` parity (spec_version 1
  OR 2 accepted; v3+ rejected with `Error::UnsupportedSpec`).
- `render_fingerprint` — hex + EN words + FA words + visual SVG
  data-URI, byte-identical to the Go renderer.
- `verify_rotation_envelope` / `verify_rotation_chain` — rotation
  envelopes signed by the OLD root.
- `parse_revocation` (in-archive `revocation.json`).
- `verify_revocation` — `publisher.SignedRevocation` (v=1) signed by a
  pinned ed25519 key.

Out of scope:

- Bundle authoring / signing. The publisher CLI stays Go-only.
- Persistent state. `bundle-rs` writes nothing to disk.
- Localized error rendering. Errors carry stable string codes
  (`Error::code()` returns `"ErrInvalidSignature"` etc.); the UI maps
  codes to translations.

## Public API

```rust
// Top-level
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Error>;
pub fn verify_manifest(m: &Manifest, sig: &[u8], pub_key: &[u8]) -> Result<(), Error>;
pub fn parse_sbp(bytes: &[u8]) -> Result<Sbp, Error>;
pub fn verify_bundle(b: &Sbp) -> Result<(), Error>;
pub fn publisher_fingerprint(pub_key: &[u8]) -> Fingerprint;
pub fn render_fingerprint(fp: &Fingerprint, en: &[&str], fa: &[&str]) -> RenderedFingerprint;

// Rotation
pub fn verify_rotation_envelope(chain: &RotationEnvelope, old_pub: &[u8],
                                new_pub: &[u8], now: time::OffsetDateTime) -> Result<(), Error>;
pub fn verify_rotation_chain(envelopes: &[RotationEnvelope], root_pub: &[u8],
                             now: time::OffsetDateTime) -> Result<Vec<u8>, Error>;

// Revocation
pub fn parse_revocation(bytes: &[u8]) -> Result<RevocationList, Error>;
pub fn verify_revocation(body: &[u8], signing_pub: &[u8]) -> Result<RevocationSet, Error>;
```

Every error variant carries a stable `code()` string matching the Go
`bundle/...` error variant name (e.g., `ErrInvalidSignature`,
`ErrFingerprintMismatch`, `ErrUnsupportedSpec`).

## Parity guarantee

The crate ships an integration test (`tests/parity_with_go.rs`) that
loads the corpus produced by
`bundle/go/cmd/bundle-rs-fixtures` and asserts the Rust verdict
matches the Go-supplied oracle for every fixture. Fixtures cover:

- spec v1 (legacy)
- spec v2 (current)
- spec v3 (rejected)
- corrupted signature
- expired bundle / route
- unknown transport / scarcity enum
- missing profile referenced by manifest
- declared-fingerprint mismatch
- v2 directory bundle with `pointer_rotation_ref`
- valid signed revocation (v=1)
- tampered signed revocation

CI runs both the Go test suite and the Rust parity suite. A new
fixture lands in `client-desktop/bundle-rs/tests/fixtures/` (and the
generator that produces it lives at
`bundle/go/cmd/bundle-rs-fixtures`) when either side discovers an
edge case.

## Dependencies

All pure-Rust:

- `ed25519-dalek` (verify-only)
- `serde` + `serde_json`
- `sha2`
- `zip` (read-only)
- `hex`, `base64`
- `time` (RFC3339 parse only; no clock side-effects in unit tests)
- `thiserror`

No `tokio`, no `reqwest`, no `tracing`, no any networking crate.

## Privacy invariants

- No function in this crate touches the network, a filesystem, or the
  clock for purposes other than RFC3339 expiry comparison.
- No logging at all.
- Errors carry stable codes (above) but never the input bytes,
  publisher names, or URLs.

## Future work

- Property-based tests via `proptest` (random bytes → never panic).
- Formal verification of the parser per CC.4 (V4 candidate workstream).
- Streaming `parse_sbp` for very large archives (V2; current ceiling
  is the in-memory ZipArchive).
