# FRP-5 Handover — Desktop Wizard + Key/OperatorRecord Model

**Status**: SHIPPED (5 commits + readiness correction)
**Engine**: `daal-core 0.9.0+v3-share`, ABI=48 (untouched — wizard is Helper-side only)
**Phase doc**: `phases of development/33-phase-frp-5-desktop-wizard.md`
**Position B**: preserved — no telemetry, no third-party endpoints from the wizard itself; only the live `daal-deploy pricing` subcommand reaches Hetzner.

## What FRP-5 Ships

The Tauri 2 desktop wizard the Diaspora Helper uses to (a) custody a cloud-provider API token under PIN-derived AES-GCM, (b) generate or import an Ed25519 publisher keypair, (c) author the pre-provision `OperatorRecord` skeleton FRP-4b's binder will read, and (d) preview the provisioning / signing / hand-off flows as disabled-shell static layouts so the visual flow is reviewable end-to-end. The four screens 0–3 are wired live; screens 4–6 are static layouts pending FRP-4b.

What FRP-5 does NOT ship: live provisioning, live RelayPack signing, live QR emission. Those live in FRP-4b per the `4a → 5 → 4b` track ordering.

## Source Map

```
client-desktop/daal-wizard/                # workspace crate (NOT inside tauri/src-tauri)
├── Cargo.toml                              # keyring 3.6, argon2 0.5, aes-gcm 0.10,
│                                           # zeroize 1.8, rusqlite 0.32 (bundled),
│                                           # ed25519-dalek 2.2, sha2, tempfile
├── migrations/V001__operators.sql          # operators(...) + pin_attempts(...)
├── src/lib.rs
├── src/operator_db.rs                      # SQLite wrapper + migrations runner
├── src/keystore.rs                         # OS-keystore + Argon2id + AES-256-GCM
├── src/pin_lockout.rs                      # 5/60s → 60s lockout, doubling, cap 1h
├── src/publisher_key.rs                    # ed25519-dalek + 16-word fingerprint
├── src/cli_bridge.rs                       # subprocess → daal-deploy pricing
├── src/staging.rs                          # PreProvisionRecord JSON writer
├── src/commands.rs                         # high-level WizardCtx surface
├── tests/frp5-schema-snapshot.json         # pinned FRP-4a / FRP-5 key set
├── tests/schema_xref.rs                    # OperatorRecord JSON-key drift detector
└── tests/key_opsec.rs                      # OPSEC regressions

client-desktop/tauri/src/wizard/
├── types.ts                                # PreProvisionRecord/Pricing/Fingerprint TS twins
├── state.ts                                # wizardReducer
├── bridge.ts                               # @tauri-apps/api invoke wrappers
├── i18n.ts + i18n/wizard.{en,fa}.json      # ~70 strings each
├── WizardShell.tsx                         # router + progress indicator + cancel modal
└── screens/Screen{0..6}*.tsx               # 0-3 LIVE, 4-6 disabled shells

client-desktop/tauri/src-tauri/src/lib.rs   # registers eight #[tauri::command] shims
                                            # + WizardStateMgr managed state
client-desktop/tauri/src-tauri/icons/       # tracked RGBA icon for Tauri context generation
client-desktop/tauri/src-tauri/resources/   # tracked bundle-resource dir; libdaalcore.so may be staged here
```

## Key Custody — Two-Layer Design

**Layer 1 (OS keystore).** The AES-GCM ciphertext is stored via the `keyring` crate (Linux Secret Service, macOS Keychain, Windows Credential Manager). The build feature `dev-no-keystore` swaps this for an in-memory backend for local dev only; release builds reject it via `compile_error!`.

**Layer 2 (PIN-derived AES-GCM).** A 16-byte random salt per install, persisted at `~/.config/daal/keystore_salt` (mode 0o600). On every `seal` / `open` call we run Argon2id with parameters `m=65536 KiB, t=3, p=4` (OWASP 2024 minimum) over the user's PIN to derive a 32-byte AES key, then AES-256-GCM with a fresh 12-byte random nonce per write. Wrong PIN returns `KeystoreError::WrongPin`; `pin_lockout` is consulted before each PIN-bearing command and counts failures over a sliding 60-s window: 5 failures lock for 60s; consecutive bursts double the lockout; cap is 3600s.

PIN format at FRP-5: 6–12 ASCII digits. The UI recommends a 6-digit minimum; longer numeric PINs are accepted.

## Wizard Command Surface

All commands take a `WizardCtx { db, keystore, staging_dir, cli, clock }` so unit tests can substitute mocks. The Tauri shell builds one on app startup and passes it via `#[tauri::command]` State.

| Command | Live at FRP-5? | Notes |
|---|---|---|
| `wizard_store_cloud_token` | yes | seals token under PIN; inserts pre-provision row |
| `wizard_pricing_lookup` | yes | shells out to FRP-4a `daal-deploy pricing` (read-only) |
| `wizard_select_profile` | yes | persists region/type/profile/families to record JSON |
| `wizard_publisher_keygen` | yes | verifies the cloud-token PIN, then generates Ed25519 keypair and seals priv under the same PIN |
| `wizard_publisher_keyimport` | yes | verifies the cloud-token PIN, then imports 32-byte seed or 64-byte expanded form |
| `wizard_finalize_pre_provision` | yes | writes `<staging>/{id}.pre-provision.json` (mode 0o600) |
| `wizard_list_operators` | yes | lightweight summary list |
| `wizard_cancel_and_cleanup` | yes | erases keystore aliases + DB row + staging file |

`provision_run`, `sign_relaypack`, and `qr_render` are intentionally absent — those are FRP-4b's. The OPSEC test `tests/key_opsec.rs::no_frp4b_command_names_in_wizard_sources` greps the wizard sources to make sure they stay absent.

## Pre-Provision Record Schema

`PreProvisionRecord` mirrors the FRP-4a Go `provider.OperatorRecord` field-for-field, plus two FRP-5 wizard-extras:

```text
provider, server_id, server_type, region,
public_ip, public_ipv6 (omitempty), floating_ip_id (omitempty),
toolbox_profile, publisher_pub_key, candidates,
provisioned_at,
enabled_families,             # FRP-5 wizard-extra; FRP-4b reads as ProvisionOpts
freshness_url                 # FRP-5 wizard-extra; "" at V1.5; FRP-8 populates
```

Drift on either side fails `tests/schema_xref.rs::pre_provision_keys_equal_snapshot_union` with a helpful diff. The pinned snapshot is `tests/frp5-schema-snapshot.json`. **Maintainer rule**: when FRP-4a or FRP-8 mutates the OperatorRecord shape, update both the Go side and the snapshot in one commit.

At FRP-5 ship `freshness_url` is empty string. RelayPack canonicalisation already round-trips an empty string deterministically through `bundle/go/bundle/canonical.go` (verified by the FRP-1 corpus and `RP021`).

## Frontend Wizard Layout

```
Screen 0  Welcome / explainer                                   LIVE
Screen 1  Cloud token + 6-12 digit PIN + confirm-PIN            LIVE
              → wizard_store_cloud_token + pricing_lookup
              (the latter doubles as a token-validity check)
Screen 2  Region + server-type + toolbox profile + families     LIVE
              CDN-fronted V1.6 line greyed-out per supplement §21.1
Screen 3  Publisher key — create-new (default) or import        LIVE
              → fingerprint render (hex / EN words / FA words)
              → wizard_finalize_pre_provision (writes staging)
Screen 4  Provisioning progress (5 steps)                       DISABLED SHELL
Screen 5  Signing the RelayPack                                 DISABLED SHELL
Screen 6  Hand-off (QR placeholder + Send-via-Signal +          DISABLED SHELL
              Print + Rotate-disabled)
```

Cancel-and-cleanup flow: from any screen ≥1, the top-right "Cancel" button raises a confirmation modal; on confirm the wizard erases the keystore aliases, deletes the DB row, removes the staging file, then returns to the Home tab.

i18n: EN + FA, ~70 strings each in `i18n/wizard.{en,fa}.json`. The Persian translations are placeholders and need a native-speaker review pass before external pilot use. FRP-5 ships the structure; FRP-4b is not blocked because it wires deployment/signing, not copy.

## Hand-off to FRP-4b

FRP-4b ("Direct-Mode Deploy Integration") will:

1. **Read** the pre-provision JSON from `<staging>/<id>.pre-provision.json`.
2. **Drive** the FRP-4a `daal-deploy provision` subcommand with the staging fields, the user-PIN-decrypted cloud token, and the user-PIN-decrypted publisher private key.
3. **Update** the operator row to `status='provisioned'` and rewrite the JSON with the `server_id` / `public_ip` / `candidates` / `provisioned_at` populated by Hetzner.
4. **Bind** a `RelayPack` (FRP-2 binder) and **sign** it with the publisher key.
5. **Render** the `.sbp` as a QR fountain (`specs/qr-fountain-v1.md`), showing it on screen 6 with a Send-via-Signal hand-off button.

The wizard does not yet have command shims for any of these. FRP-4b adds three: `wizard_provision_run`, `wizard_sign_relaypack`, `wizard_qr_render`. The OPSEC grep test (the one currently asserting these are absent) flips polarity at FRP-4b.

## Handover to FRP-7.5 / FRP-8

- **FRP-7.5 (BIP-39 wordlists)**: replace the 16-word EN+FA placeholders in `bundle/go/publisher/keystore.go::defaultWordlists` and `client-desktop/daal-wizard/src/publisher_key.rs::{EN_WORDLIST,FA_WORDLIST}` together. Bump the fingerprint algorithm version field (currently implicit; lift to explicit at the same change).
- **FRP-8 (CDN-fronted candidates)**: populate the `freshness_url` field from the publisher's freshness endpoint; flip the V1.6 grey-out checkbox on screen 2 to active; lift the `RP021` rejection in the validator at the matching version bump.

## Build Matrix at Ship

```
$ cd client-desktop && cargo test -p daal-wizard
   Compiling daal-wizard v0.1.0
    Finished test profile
   Running 41 lib tests, 2 integration (schema_xref), 4 integration (key_opsec)
   test result: ok. 47 passed.
$ cd client-desktop && cargo build --workspace
    Finished dev profile [unoptimized + debuginfo]
$ # Tauri shell (requires Debian GTK/WebKit dev packages locally; CI installs them):
$ cd client-desktop/tauri/src-tauri && cargo build
$ cd client-desktop/tauri/src-tauri && cargo build --release
$ cd client-desktop/tauri/src-tauri && cargo test
$ cd client-desktop/tauri && npm run build
$ cd client-desktop/tauri && npm audit --audit-level=moderate
```

The Tauri shell is intentionally out-of-tree from the workspace because pulling in `tauri-build` + the GTK toolchain slows `cargo test -p bundle-rs` significantly. Local review installed the Debian GTK/WebKit dev packages and verified both debug and release Rust shell builds after fixing the FRP-5 shim API names, the missing icon asset, and the empty `resources/*` bundle glob. Frontend build is also green under npm with a tracked `package-lock.json`; Vite was moved to `^6.4.2` so `npm audit --audit-level=moderate` reports 0 vulnerabilities on Node 18.

## OPSEC Notes for Reviewers

- `GeneratedKey` does not derive `Debug` — `dbg!()` cannot leak its private bytes (compile error). Asserted by `tests/key_opsec.rs::generated_key_does_not_derive_debug`.
- The pre-provision JSON file is mode 0o600 on unix. Asserted by `tests/key_opsec.rs::pre_provision_file_is_mode_0o600`.
- No analytics-vendor symbols appear anywhere in the wizard crate or wizard frontend. Asserted by `tests/key_opsec.rs::no_analytics_vendor_symbols_in_wizard_sources`.
- The cloud token is written to a tempfile with mode 0o600 before being passed to `daal-deploy`; subprocess invoked with `env_clear()` + PATH passthrough only.

## Pending Items (for the Pilot Window)

- Native-speaker FA copy review before external pilot use.
- Full BIP-39 wordlist swap (FRP-7.5).
- The "Run a Family Relay" entry button label may need a UX-copy review pass — phase doc says it lives on the Home tab but we currently surface it as a top-nav button. The reducer is screen-zero-resilient either way.
