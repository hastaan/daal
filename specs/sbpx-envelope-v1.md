# `.sbpx` encrypted relay-pack envelope — v1

**Status:** locked at FRP-14. **Spec version:** 1.
**Owner package:** `bundle/go/envelope/` (Go); recipient-side
decryption lives in the Tauri Rust shell.

This document specifies the on-disk envelope that wraps a signed
`.sbp` so its contents are readable only by the targeted recipient.
It is a thin layer over the [age](https://age-encryption.org) v1
format — Daal does not invent any crypto here; the envelope merely
adds a magic prefix for sniff-based file-type detection and pins the
permitted recipient/identity types.

## 1. Threat model

The `.sbp` plaintext contains:

* The server's public IP address (under `direct_vps`).
* The TLS SNI, Reality public key, short_id, VLESS UUID, Hysteria2
  password, Naive password, and WebSocket path for the recipient's
  per-user credentials slot.

Any party who reads a `.sbp` can either (a) blocklist the IP or
(b) impersonate the recipient against the server (since the user-bound
credentials authenticate by possession, not signature).

The envelope's job is **confidentiality**: only a holder of the
correct X25519 private key can recover the inner `.sbp`. It is **not**
the job of the envelope to provide:

* Authenticity of the publisher (the inner `.sbp` carries an Ed25519
  signature; the envelope adds no new authentication).
* Forward secrecy for past packs (each pack is a fresh ephemeral
  encryption, but the recipient's long-term X25519 priv compromises
  every past pack signed to that address — known limitation of
  static-recipient PKE; mitigated by recipient-side key rotation, see
  §6).
* Cover-traffic / metadata privacy of the *file's existence*. An
  observer of the share channel still learns "a Daal relay pack was
  shared" even if they cannot read its contents.

## 2. File format

```
+--------+--------+--------+--------+--------+--------+
|  'D'   |  'S'   |  'B'   |  'P'   |  0x00  |  0x01  |
+--------+--------+--------+--------+--------+--------+
| age v1 header (ASCII, length-prefixed by literal newline)         |
+-------------------------------------------------------------------+
| age v1 body (ChaCha20-Poly1305 chunks, 64 KiB each)               |
+-------------------------------------------------------------------+
```

* **Magic:** the 6 bytes `D S B P 0x00 0x01`. Distinguishes `.sbpx`
  from a raw age stream, lets the recipient app dispatch correctly,
  and provides forward room for an envelope-version bump (the `0x01`
  byte). Parsers MUST reject any file whose first 6 bytes do not
  exactly match this prefix.
* **age v1 header + body:** the standard age wire format, unmodified.
  The header opens with `age-encryption.org/v1` and ends with a
  literal `---` line followed by a base64 MAC; the body is the
  CC20P1305 stream. See https://age-encryption.org/v1 for the
  authoritative spec.

A future envelope version would replace the `0x01` byte. v1 parsers
MUST refuse other version bytes.

## 3. Permitted recipient types

V1.6 supports exactly one recipient type:

* **X25519** — the recipient is named by a Daal address (`daal1...`,
  see `specs/recipient-address-v1.md`), which decodes to a 32-byte
  X25519 pubkey. Maps to `age.X25519Recipient`.

Other age recipient types (`ssh-rsa`, `ssh-ed25519`, passphrase) are
not used by Daal at V1.6 and MUST be rejected at encrypt time. The
recipient app's decrypt path only knows X25519, so an ssh-style age
file would be silently undecryptable; we fail loudly at the publisher
side instead.

V2 (FRP-11) widens to multi-recipient by adding additional X25519
stanzas to the same envelope — same wire format, multiple wrapped
file-keys.

## 4. Cross-binding to inner SBP

The envelope alone provides confidentiality but not "this pack is for
me." A malicious publisher could:

* Take a legitimate `.sbpx` intended for recipient A.
* Re-encrypt the inner bytes to recipient B's pubkey.
* Send it to B.

If B's app accepts any pack it can decrypt, B is now using A's
credentials. The on-box server cannot distinguish them, so B's
traffic looks like A's, defeating per-recipient revocation.

**Fix:** the inner `.sbp` manifest gets a new field at FRP-14:

```jsonc
"bundle": {
  ...,
  "recipient_fp_hex": "<sha256 of recipient X25519 pub, 64 hex chars>"
}
```

The signed manifest binds the pack to a specific recipient identity.
The recipient app's `VerifyBundle` cross-checks:

```go
expected := sha256(recipientIdentity.PubBytes())
if hex(expected) != manifest.Bundle.RecipientFPHex {
    return ErrRecipientMismatch
}
```

Mismatch returns `ErrRecipientMismatch` with a user-readable error
("This relay pack wasn't for you").

This field is empty / omitted on V1.5 `.sbp` files; the validator
treats empty as "no binding" (for backwards compat with pre-FRP-14
packs); non-empty MUST match.

## 5. Public API

### 5.1. Go side — `bundle/go/envelope/`

```go
// EncryptForRecipient wraps signed .sbp plaintext for one X25519
// recipient. Returns the .sbpx bytes.
func EncryptForRecipient(plaintext []byte, recipient [32]byte) ([]byte, error)

// Decrypt opens an .sbpx envelope using the recipient's X25519
// private key. Returns the inner .sbp plaintext.
func Decrypt(ciphertext []byte, priv [32]byte) ([]byte, error)

// SniffMagic reports whether the leading bytes match the v1 magic
// prefix. Used by import dispatchers to choose .sbp vs .sbpx branch.
func SniffMagic(head []byte) bool
```

Errors:

| Error | Meaning |
|---|---|
| `ErrBadMagic` | head bytes do not match `DSBP\x00\x01` |
| `ErrAgeHeader` | age header malformed or unsupported (e.g. ssh recipient) |
| `ErrDecrypt` | age decryption failed (wrong key, tampering, truncation) |

### 5.2. Rust side

The recipient app's import path lives in the existing
`client-shell/tauri/src-tauri/src/recipient.rs`. New module
`envelope.rs` mirrors the Go API:

```rust
pub fn sniff_magic(head: &[u8]) -> bool;
pub fn decrypt(ciphertext: &[u8], priv_key: &[u8; 32]) -> Result<Vec<u8>, EnvelopeError>;
```

The publisher app does its encryption in Go via the wizard's CLI
bridge (`daal-deploy bind-and-sign-and-encrypt`); the Rust side of
the publisher does not need to import the age crate. Reason: the
Tauri shell already calls into Go for signing, so layering encryption
on top is a one-line addition rather than a parallel crypto stack.

## 6. Recipient key lifecycle

* X25519 keypair generated at first launch of the recipient app.
* Priv stored via `custody.put(alias, …)` (Device Custody v1), alias
  `daal.recipient.identity.priv`. There is no PIN; `Keystore::seal`
  survives only as the legacy reader for the one-time migration.
* Pub persisted in plaintext under alias `daal.recipient.identity.pub`.
* No automatic rotation at V1.6. Rotation requires:
  - Generate new keypair.
  - Display new address.
  - Publisher must re-add the new address and re-issue all packs.
  - Old packs become un-decryptable on the new identity.

Rotation UX is deferred to a post-V2 spec.

## 7. Test surface

| File | Tests |
|---|---|
| `bundle/go/envelope/envelope_test.go` | encrypt+decrypt round-trip, sniff_magic on bare age stream (false), sniff_magic on .sbpx (true), wrong-key decrypt fails, truncated envelope fails, magic-byte tamper fails |
| `bundle/go/envelope/fuzz_test.go` | 256 random plaintexts × 256 random keypairs round-trip |
| Recipient app | `client-shell/tauri/src-tauri/tests/sbpx_import_test.rs`: full import flow with correct key, wrong key (`ErrDecrypt`), correct key but wrong `recipient_fp_hex` (`ErrRecipientMismatch`) |

## 8. Performance notes

* Typical `.sbp` is 12–18 KB (4 transport families × 2–4 KB
  sing-box profile each + manifest). age overhead is one header
  (~250 B) + one tag per 64 KiB chunk (16 B). A 20 KB pack becomes a
  20.25 KB `.sbpx`. Negligible.
* Encryption is single-pass streaming and runs in <5 ms on a
  mid-range desktop; not on the wizard's critical path even on
  low-end Android.

## 9. Carry-overs

* Multi-recipient (one `.sbpx` decryptable by mom and cousin) is V2
  / FRP-11 — same wire format, additional X25519 stanzas in the age
  header.
* Streaming decrypt to disk is not exposed at V1.6; the recipient app
  reads the whole `.sbpx` into memory (<256 KB hard cap on import).
