# recipient-identity-v1 — recipient app per-device X25519 identity

> **Status:** v1 — landed in Daal v0.1.0 release branch, FRP-14 Layer 3c.
> **Owners:** recipient-app team.
> **Cross-refs:**
>   * `recipient-address-v1.md` — `daal1…` bech32m address codec (Go + Rust).
>   * `sbpx-envelope-v1.md` — age v1 envelope this identity decrypts.
>   * `per-recipient-credentials-v1.md` — how the publisher uses the
>     fingerprint of this pubkey when provisioning per-recipient users.
>   * `key-vault-v1.md` — outer keystore the priv-key is wrapped in.

## 1. Motivation

For pack-to-person (FRP-14) the publisher must encrypt the relay
pack to a *specific* recipient. The recipient must therefore own a
long-lived Curve25519 (X25519) keypair the publisher can address.
This spec defines how that keypair is generated, persisted,
displayed to the user, and exported as a `daal1…` address.

One identity per **install** (per app data directory). Multi-device
key portability is intentionally **out of scope** for v1 — losing
the phone means losing the identity and needing a fresh address.

## 2. Properties

* **Singleton per app data dir.** A single `recipient_identity`
  row in the operator/recipient DB. CHECK constraint enforces `id = 1`.
* **Custody-wrapped at rest.** The private key never touches disk in
  cleartext. It is stored through the same Device Custody layer the
  publisher keys use, under a dedicated alias `recipient_priv_x25519`.
  See the amendment note below — this is **not** PIN-derived any more.
* **Lazy creation.** Identity is **not** created until the user
  enters the “My Daal address” screen. We do not silently mint keys at
  first launch. On a hardware / OS-keystore device the mint needs no
  user secret at all; on a session-passphrase device the user is
  prompted for the session passphrase once, which unlocks custody.
* **Idempotent.** Re-entering the screen re-derives nothing — it reads
  the cached pub from the DB. The
  priv is only opened on demand (e.g. when decrypting an
  `.sbpx`).
* **No rotation in v1.** Once created the keypair is immutable.
  A future v2 may add rotation via a `revoked_at_unix` column and
  per-publisher rebind, but v1 ships without it.

## 3. Cryptography

* **Curve:** Curve25519 (X25519 ECDH).
* **Key generation:** 32 bytes from OS RNG (`getrandom`), then
  `x25519::x25519(scalar, X25519_BASEPOINT_BYTES)` to derive the
  pubkey. The scalar is **not** pre-clamped; age does its own
  clamping inside `derive_public` so the on-the-wire pub matches.
* **Storage format:**
  - `priv_x25519`: raw 32 bytes, sealed with `Keystore::seal` under
    alias `recipient_priv_x25519`.
  - `pub_x25519`: raw 32 bytes, plaintext column in DB
    (also derivable from the address but cached for cheap reads).
  - `created_at_unix`: i64 wall-clock seconds.
* **Fingerprint:** `hex(SHA-256(pub_x25519))` — 64 lowercase hex
  chars (matches `daal-recipient-addr::fingerprint` and the
  publisher-side `RecipientFingerprint`). Used as
  `manifest.Bundle.RecipientFPHex`. v1 stores the full digest; any
  display-side truncation is the UI's choice.
* **Address:** `daal-recipient-addr::encode(pub_x25519)` →
  `daal1…` (63 chars). The URI form `daal://daal1…` is what the
  user copies/QR-shares to publishers.

## 4. Storage layout

### 4.1 Keystore alias

```
service   = "daal"
user      = "recipient_priv_x25519"
value     = base64(nonce[12] || ciphertext || tag[16])     (AES-256-GCM)
```

Wrapped per `key-vault-v1.md`. Same Argon2id parameters
(m=65 536 KiB, t=3, p=4) as every other Daal PIN-wrap.

### 4.2 SQLite migration `V010__recipient_identity.sql`

```sql
CREATE TABLE recipient_identity (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    pubkey_x25519   BLOB    NOT NULL,
    keystore_alias  TEXT    NOT NULL DEFAULT 'recipient_priv_x25519',
    address_str     TEXT    NOT NULL,   -- cached daal1…
    fingerprint_hex TEXT    NOT NULL,   -- 64 hex chars (hex sha256)
    created_at_unix INTEGER NOT NULL
);

-- One-and-only-one row enforced by the CHECK above; no UNIQUE
-- index needed.
```

The migration lives in `client-shell/tauri/daal-wizard/migrations/`
because the recipient app shares the `daal-wizard` crate’s DB layer
in this build (operator DB doubles as the recipient DB on the same
device — see `desktop-architecture-v1.md` for the unified-app
rationale).

## 5. Rust API (`daal-wizard::recipient_identity`)

```rust
pub struct RecipientIdentitySummary {
    pub address: String,         // daal1…
    pub fingerprint_hex: String, // 64 lowercase hex chars (hex sha256)
    pub created_at_unix: i64,
}

/// First call: generate fresh X25519 keypair, seal priv into
/// keystore under `recipient_priv_x25519`, insert row id=1.
/// Subsequent calls: read row id=1 and return the summary without
/// touching the keystore.
///
/// Errors:
///   * `RecipientIdentityError::WrongPin` if the keystore is non-empty
///     but the PIN does not decrypt it (paranoia check: we re-open
///     the priv on first-create-after-restart to confirm round-trip).
///   * `RecipientIdentityError::KeystoreUnavailable` if the OS
///     keychain is not reachable.
///   * `RecipientIdentityError::Db(_)` for any sqlx error.
pub fn get_or_create(
    db: &OperatorDb,
    ks: &Keystore,
    pin: &str,
) -> Result<RecipientIdentitySummary, RecipientIdentityError>;

/// Read-only path used by .sbpx import (Layer 3d): returns the
/// raw 32-byte priv-key. Caller is responsible for zeroizing.
pub fn open_priv(
    db: &OperatorDb,
    ks: &Keystore,
    pin: &str,
) -> Result<[u8; 32], RecipientIdentityError>;

/// Read-only summary; errors if identity not yet created. No
/// keystore I/O.
pub fn get_summary(db: &OperatorDb) -> Result<Option<RecipientIdentitySummary>, RecipientIdentityError>;
```

### 5.1 OperatorDb additions

```rust
impl OperatorDb {
    pub async fn upsert_recipient_identity(
        &self,
        pubkey: &[u8; 32],
        address: &str,
        fingerprint_hex: &str,
        created_at_unix: i64,
    ) -> sqlx::Result<()>;

    pub async fn get_recipient_identity(
        &self,
    ) -> sqlx::Result<Option<RecipientIdentityRow>>;
}
```

`upsert_recipient_identity` uses `INSERT … ON CONFLICT(id) DO NOTHING`
— v1 forbids rewriting the row. Returns `Ok(())` even when the row
already exists; callers detect this via `get_recipient_identity`
beforehand.

## 6. Tauri commands

```
recipient_identity_get_or_create(pin: string)
    -> { address: string, fingerprint_hex: string, created_at_unix: i64 }

recipient_identity_get()
    -> { address, fingerprint_hex, created_at_unix } | null
```

`recipient_identity_get` returns `null` (not an error) when no
identity exists yet — the React layer uses this to decide whether
to render the “Create your address” CTA or the address itself.

## 7. UI: “My Daal address” screen

Path: `client-ui/src/recipient/MyAddress.tsx`.

Sections (top to bottom):

1. **Eyebrow + title** — `recipient.address.title` /
   `recipient.address.eyebrow`.
2. **Explainer** — `recipient.address.explain`. Two short
   sentences; emphasises that anybody with the address can give
   you a route, that the address is *not* a secret on its own.
3. **Address card** —
   - Monospace `daal1…` (line-wrapped 4-char groups, like SSH
     fingerprints).
   - “Copy address” button (`@tauri-apps/plugin-clipboard-manager`).
   - “Show as QR” toggle that renders the URI form
     (`daal://daal1…`) via the existing QR component used elsewhere
     in the app (planned for 3c.5 — initial 3c ships the
     monospace + copy only).
4. **First-time CTA** — when `recipient_identity_get()` returns
   `null`: PIN field + “Create my Daal address” button. On
   success, swap to the address card view in-place.
5. **Footer note** — `recipient.address.footer`: “This address
   identifies your phone to publishers. Losing the phone means
   losing this address — get a new one from the publisher after
   reinstalling.”

The first-time CTA shows a passphrase field **only** when custody
reports the `session_passphrase` level; on hardware / OS-keystore
devices the key is minted with no prompt (`client-ui/src/recipient/MyAddress.tsx`).
`Wizard.validatePin` no longer exists.

**Amended 2026-08-17 — Device Custody v1 replaced the PIN model.**
`pin_lockout.rs` was deleted in `d80c638`; `Wizard.validatePin` no
longer exists; `daal-wizard/src/lib.rs:11` states "There is no PIN
anywhere in that flow". Recipient identity keys are stored through
`ctx.custody.get()` / `ctx.custody.put()`
(`daal-wizard/src/recipient_identity.rs:110,137,192`), backed by
`device_custody.rs`.

The model is: on a platform with a hardware/OS keystore (Android
Keystore, iOS/macOS Keychain, Windows DPAPI, Linux libsecret) the key
is wrapped by a per-app **Device Wrap Key** held in that keystore and
**there is no PIN**; where no keystore exists the fallback is a
**session passphrase** (Argon2id) set once per session. The wrap key
always mixes in a machine-id binding, so lifting the blob to another
machine fails even with the DWK alias. The UI labels the active level
("Hardware" / "OS Keystore" / "Session passphrase") honestly.

Note that `specs/key-vault-v1.md` is **still accurate and still
PIN-based** — it describes `core/keyvault`, the *engine* vault, which
is a different subsystem from wizard-side key custody. Do not
"fix" it to match this note.



### 7.1 Navigation

For v1 the screen is reachable from the Sources page “Add” modal:
add a fifth tab “My address” next to Paste / Scan / LAN / File.
This keeps the surface small and avoids adding a top-level nav
entry until the recipient flow is exercised in real usage.

A future polish ticket will promote it to a first-class sidebar
entry once we know what users actually do with the address.

## 8. i18n keys (en + fa)

```
recipient.address.title         "My Daal address"
recipient.address.eyebrow       "Receive relay packs"
recipient.address.explain       "Share this address with someone who's
                                 running a Daal server. They'll use it
                                 to send you a relay pack only your
                                 phone can open."
recipient.address.create_cta    "Create my Daal address"
recipient.address.creating      "Creating…"
recipient.address.copy          "Copy address"
recipient.address.copied        "Copied!"
recipient.address.show_qr       "Show as QR"
recipient.address.footer        "This address identifies this phone.
                                 Reinstalling makes a new address; ask
                                 the publisher for a fresh pack."
recipient.address.error.pin     "PIN is wrong. Try again."
recipient.address.error.create  "Could not create address: {msg}"
```

Persian translations are provided in `i18n/fa.json` at the same
keys, following the existing translation style (no transliteration
of `daal1`).

## 9. Privacy / threat model

* **Public address is not a tracking identifier in v1.** No
  rendezvous, no subscription, no analytics. The publisher learns
  the address only because the recipient hands it to them.
* **Loss of phone = loss of identity.** This is intentional — the
  v1 product story is “anyone can get back online by asking the
  publisher for a new pack”. Identity portability is a v2
  problem.
* **Wrong-PIN attempts are not rate-limited at this layer.**
  The keystore inherits whatever rate-limit the OS keychain
  enforces. The Daal layer trusts that.

## 10. Tests (must pass before Layer 3d starts)

* `recipient_identity::get_or_create` first call creates row,
  seals priv, returns summary; second call returns identical
  summary without touching the keystore (verified by counting
  keystore-call hits on a mock backend).
* `recipient_identity::open_priv` round-trips the 32-byte key on
  a freshly created identity.
* `recipient_identity::open_priv` errors `WrongPin` on bad PIN.
* `OperatorDb::upsert_recipient_identity` is idempotent: second
  call with different bytes does **not** overwrite.
* Fingerprint matches `daal-recipient-addr::fingerprint(pub)` for
  every entry in the shared golden-vector file.
* Address round-trip: `decode(get_or_create().address).0 == pub`.

Coverage target ≥ 80 % on the new module.

## 11. Out-of-scope (deferred to v2)

* Multi-device key sync.
* Key rotation / revocation by the recipient.
* Recipient-side rendezvous tied to this pubkey.
* Encrypting the cached `pub_x25519` column in the DB (low-value
  — the address it derives is already public).
