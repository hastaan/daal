# sbpx-import-v1 — recipient-side `.sbpx` ingest

> **Status:** v1 — landed in Daal v0.1.0 release branch, FRP-14 Layer 3d.
> **Owners:** recipient-app team.
> **Cross-refs:**
>   * `sbpx-envelope-v1.md` — wire format (age v1, `DSBP\x00\x01` magic).
>   * `recipient-identity-v1.md` — the priv-key used to decrypt.
>   * `relaypack-v1.md` — the `.sbp` payload after decryption,
>     including the `manifest.Bundle.RecipientFPHex` binding.
>   * `bundle-rs-v1.md` — the existing importer this lane funnels into.

## 1. Goal

After Layer 3c the recipient owns a `daal1…` address. After
Layer 3d the recipient app accepts a `.sbpx` file (encrypted relay
pack) and, on success, behaves exactly as if it had received the
old `.sbp` — i.e. the existing trust-prompt UX is unchanged
downstream.

The lane is a **branch added on top of the existing import**, not
a replacement. Plain `.sbp` continues to work — it just emits a
warning that the channel was unencrypted (see §6).

## 2. Pipeline

```
file path
   │
   ▼
read first 6 bytes
   │
   ├─ magic = "DSBP\x00\x01"     ──► sbpx lane
   │        │
   │        ▼ envelope.Decrypt(ciphertext, priv)
   │        │
   │        ▼ tmpfile.write(plaintext .sbp bytes)
   │        │
   │        ▼ contract.previewBundle(tmpfile)
   │        │
   │        ▼ verify manifest.Bundle.RecipientFPHex == identity.fp
   │        │
   │        ▼ contract.importSbp(tmpfile)
   │
   └─ else                       ──► legacy sbp lane (unchanged)
            │
            ▼ warning toast "channel was unencrypted"
            │
            ▼ contract.previewBundle + importSbp
```

## 3. Wire-level sniff

A `.sbpx` file starts with the 6-byte magic `DSBP\x00\x01`.
We sniff by **opening the file and reading the first 6 bytes**
(not by extension), because:

* Some share apps (Telegram, WhatsApp) drop or replace the
  extension.
* The wizard's stored relay-pack path on the publisher side may
  still emit `.sbp` during the dual-write window (see
  `sbpx-envelope-v1.md` §10).

The sniff matches `envelope.SniffMagic([u8; 6])` exactly so that
the publisher-side write and the recipient-side read share one
definition.

## 4. Rust API (`daal-desktop-tauri::recipient`)

```rust
/// Returns Ok(true) if the head is the 6-byte sbpx magic.
fn is_sbpx(head: &[u8]) -> bool;

/// One-shot decrypt of an sbpx file: opens identity, reads the
/// ciphertext, age-decrypts in memory, writes plaintext .sbp to
/// a mode-0600 tempfile under the app cache, returns that path.
///
/// Caller must delete the tempfile when import_sbp returns (the
/// existing import flow already does this for plain .sbp via the
/// "staging" cache).
pub fn recipient_decrypt_sbpx(
    sbpx_path: &Path,
    db: &OperatorDb,
    ks: &Keystore,
    pin: &str,
) -> Result<PathBuf, SbpxImportError>;
```

`SbpxImportError` variants:

* `NotEncryptedToYou` — fingerprint mismatch (manifest's
  `recipient_fp_hex != fingerprint(my_pub)`). UI string:
  *“This relay pack was sent to a different phone.”*
* `EnvelopeCorrupt` — age-decrypt failed (mac, format,
  truncated). UI string: *“The file is damaged or was not made
  by Daal.”*
* `WrongPin` — keystore wouldn't open.
* `Io(_)`, `Db(_)` — wrap underlying errors.
* `IdentityMissing` — no identity row in DB; UI prompts the user
  to set up their address first.

## 5. Tauri command + UI hook

```
recipient_import_sbpx(path: string, pin: string)
    -> { plaintext_path: string }
```

The React import modal:

1. Sniffs the head client-side (the Tauri FS plugin exposes
   `readBinaryFile` with byte-length cap).
2. If sbpx: prompts for PIN (same modal pattern as
   `recipient.address.title`), invokes
   `recipient_import_sbpx(path, pin)`, then routes the returned
   plaintext path through the **existing** `contract.previewBundle`
   + `contract.importSbp` flow. The trust prompt then takes over
   unchanged.
3. If plain `.sbp`: existing path, **plus** a yellow toast at
   the top of the trust prompt with key
   `recipient.import.legacy_warning`: *“This pack was not
   encrypted. Anyone who could read the file in transit could see
   the credentials inside. Ask the publisher for a `.sbpx` next
   time.”*

The plaintext tempfile is unlinked when the trust prompt closes
(accept or reject) — the existing import flow's
`finally { fs.removeFile(staging) }` already covers this; the
sbpx tempfile is staged into the same staging dir.

## 6. Plain-`.sbp` deprecation policy

This recipient app accepts plain `.sbp` for the entire v0.1.x
line. The warning toast is the only behavioural change. v1.6
will **stop emitting** plain `.sbp` on the publisher side
(`sbpx-envelope-v1.md` §10); v2.0 will reject plain `.sbp` on
import with a hard error pointing the user at the publisher for
a re-share.

That deprecation timeline is intentional: it gives the recipient
population an upgrade window without breaking anyone in the
middle of a censorship event.

## 7. Trust-prompt copy changes

The existing trust prompt shows server fingerprint + provenance.
For `.sbpx` we add one extra row at the bottom: *“Encrypted to
this phone ✓”* (green check). The corresponding plain-`.sbp`
row reads *“Channel was unencrypted ⚠”* (yellow warning).

i18n keys:

```
recipient.trust.sbpx_ok      "Encrypted to this phone ✓"
recipient.trust.sbp_legacy   "Channel was unencrypted ⚠"
recipient.import.legacy_warning  "This pack was not encrypted. …"
recipient.import.not_yours   "This relay pack was sent to a different phone."
recipient.import.corrupt     "The file is damaged or was not made by Daal."
recipient.import.identity_missing
                             "Set up your Daal address first, then ask the
                              publisher to send the pack again."
```

## 8. Security properties

* **Confidentiality (network):** an attacker who captured the
  `.sbpx` in transit learns nothing about the inbound credentials
  or server IP. age v1 over X25519 + ChaCha20-Poly1305 (the
  default age recipe) handles this.
* **Confidentiality (at rest):** the tempfile under app cache
  contains the *plaintext* `.sbp` for the duration of the trust
  prompt. This is acceptable because the existing `.sbp` import
  has the same property and the file is in the app's
  data-protection-class storage. We do not raise the bar in this
  layer.
* **Authenticity:** the inner `.sbp` is already Ed25519-signed by
  the publisher (`relaypack-v1.md`). The envelope adds *to-this-
  phone* confidentiality, not extra authenticity.
* **Replay:** an attacker who captures the same `.sbpx` twice
  cannot do anything new — the inner `.sbp` is identical and the
  importer's de-dup (Manifest sha-256 ledger from
  `30-phase-frp-2-import-store-preservation.md`) drops the
  second import.

## 9. Tests

* `is_sbpx` recognises the magic, rejects 6-byte heads that
  differ in any byte, and returns false for any head shorter than
  6 bytes (no panic).
* `recipient_decrypt_sbpx` round-trips a publisher-produced sbpx
  (golden file in `specs/test-vectors/sbpx/`) into the same
  plaintext bytes as the source `.sbp`.
* `recipient_decrypt_sbpx` returns `NotEncryptedToYou` when the
  manifest's `recipient_fp_hex` mismatches the local identity.
* `recipient_decrypt_sbpx` returns `EnvelopeCorrupt` when the
  ciphertext's last byte is flipped.
* `recipient_decrypt_sbpx` returns `IdentityMissing` when the DB
  has no identity row.
* End-to-end Tauri integration test: produce a `.sbpx` with the
  publisher's `envelope.EncryptForRecipient` API in a fixture,
  drive `recipient_import_sbpx` against an in-memory DB seeded
  with a matching identity, assert the plaintext path the call
  returns matches the original `.sbp` bytes.

## 10. Tempfile hygiene

* Path: `<app_cache>/staging/sbpx/<random16hex>.sbp`
* Mode: 0600 (umask-tolerant — explicit chmod after create on
  Unix; no-op on Android because Tauri's `app_cache_dir` is
  already app-private).
* TTL: deleted by the existing import flow's `finally` block.
* On crash: a sweep at next launch (`recipient_decrypt_sbpx`
  start) deletes anything older than 10 minutes in the
  `staging/sbpx/` dir.

## 11. Out-of-scope (deferred)

* Streaming decrypt (everything fits in 4 MiB; see envelope cap).
* Multi-recipient envelopes (one envelope, multiple `daal1…`
  receivers). The publisher will emit one `.sbpx` per recipient.
* `.sbpx` over QR fountain — Layer 3d ships file-only; QR support
  will follow when QR fountain itself ships in V1.6.
