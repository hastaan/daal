# Key Vault V1 — Argon2id PIN-derived AES-GCM seal

**Status:** Locked at Phase 2D.

**Implementation:** `core/keyvault/`.

**Related:** `routestore-v1.md`, `engine-abi-v1.md`,
`network-memory-v1.md`, `lifeline-mode-v1.md`.

## Threat model

A device-in-hand adversary attempts offline PIN-guessing against
the routestore's age identity. The vault must:

1. Make each guess pay measurable CPU + memory (Argon2id at
   moderate-resource params).
2. Authenticate the ciphertext (AES-GCM) so wrong-PIN derivations
   reject cleanly with a typed error rather than yielding
   plausibly-decrypted nonsense.
3. Never persist, transmit, or surface the PIN — the PIN crosses
   exactly one ABI surface (`engine_unlock_secrets`) and is wiped
   from the derived-key buffer immediately after Argon2id returns.

## Storage profiles

The engine selects one of two profiles at `engine_init`:

| Profile     | Selection mechanism                       | Behaviour                                                                                                |
| ----------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `keystore`  | Default (no `.use_vault` file)           | Platform keystore handles unlock at process-start (Android Keystore / Keychain / DPAPI / libsecret).     |
| `vault`     | `state/.use_vault` empty marker present   | `engine_unlock_secrets(pin)` decrypts the on-disk identity blob via this spec's primitive.               |

Both labels are **behavioural**, never group-based. Compliance is
enforced by `core/opsec_test.go::TestNoGroupBasedLabels`.

## Argon2id parameters (locked)

| Parameter   | Value     | Constant in `core/keyvault/argon2.go` |
| ----------- | --------- | ------------------------------------- |
| time        | 3         | `V1Time`                              |
| memory      | 64 MiB    | `V1MemoryKiB = 64 * 1024`             |
| parallelism | 4         | `V1Parallel`                          |
| salt length | 16 bytes  | `V1SaltLen`                           |
| output len  | 32 bytes  | `V1OutLen`                            |

These are the OWASP 2024 Argon2id "moderate-resource" defaults. A
typical mobile/desktop PIN guess pays roughly 100 ms of CPU + 64
MiB of RAM. Adjusting any value is a v2 spec bump; the
`TestParametersLocked` regression in
`core/keyvault/argon2_test.go` is the canonical guard.

## Sealed-blob format

Layout (little-endian where multi-byte):

```
[0]      version byte (0x01)
[1..16]  salt          (16 bytes)
[17..28] AES-GCM nonce (12 bytes)
[29..32] ciphertext length (uint32 LE)
[33..]   ciphertext (includes 16-byte AES-GCM tag at tail)
```

- **AAD:** the constant string `"daal-keyvault-v1"`. A
  misaligned implementation rejects the blob immediately because
  the GCM tag fails to verify.
- **Salt:** fresh on every `Seal` call; non-secret; persisted in
  the blob.
- **Nonce:** fresh on every `Seal` call; never reused. Two seals
  of the same plaintext under the same PIN MUST produce
  different blobs (regression: `TestSealNonDeterministic`).

## API

```go
func NewSalt() ([]byte, error)
func Derive(pin string, salt []byte) ([]byte, error)
func Seal(plaintext []byte, pin string) ([]byte, error)
func Open(blob []byte, pin string) ([]byte, error)

var ErrEmptyPIN = errors.New("keyvault: empty PIN")
var ErrWrongPIN = errors.New("keyvault: wrong PIN")
```

`Derive` and `Seal` reject empty PIN with `ErrEmptyPIN`. `Open`
returns `ErrWrongPIN` whenever AES-GCM tag verification fails;
this is the user-facing wrong-PIN signal. Other parsing errors
(bad version byte, truncated blob, length mismatch) are surfaced
as plain errors — they indicate corruption, not a wrong PIN.

## PIN handling

- The PIN string is held in a single function frame on the call
  stack and passed by value to `Derive`. Go strings are
  immutable, so true zeroing of the PIN bytes is not possible;
  the implementation zeroes the **derived key** buffer in a
  `defer wipe(key)` after every `Seal` and `Open` (defense in
  depth).
- The PIN is **never** persisted, **never** logged, and **never**
  appears in `engine_export_diagnostics`. The latter is regressed
  by:
  - `core/abi/secrets_test.go::TestPINDoesNotLeakIntoDiagnostics`
  - `core/keyvault/vault_test.go::TestPINNotEmbeddedInBlob`
  - `test-rigs/.../invariants.go::ruleNoPINLeakInDiagnostics`

## ABI

`engine_unlock_secrets(pin *C.char) -> C.int` (release ABI).
Return semantics:

- `0` — unlocked.
- `-1` — wrong PIN, empty PIN, or I/O failure.
- `-2` — engine is running under the keystore profile (no PIN
  gate is required; the desktop translates this to "proceed").

The companion symbol `engine_set_allow_bulk_capable(int) -> int`
controls the lifeline-strict bulk-capable session opt-in flag;
see `lifeline-mode-v1.md`.

## Persisted file

`stateDir/.age_identity.vault` is the on-disk sealed blob. File
permissions: `0600`. The presence of the empty marker file
`stateDir/.use_vault` selects the vault profile at Init.

## Phase 2E carry-over (iOS host-app vs extension)

The iOS Network Extension has a documented ~50 MiB memory
ceiling. The Argon2id v1 peak of 64 MiB does NOT fit inside the
extension's budget. Resolution at 2E: **the host app runs unlock**.

```
[host app]                                    [extension]
  user enters PIN                                |
  engine_unlock_secrets(pin) — 64 MiB peak       |
  unsealed identity → App Group secrets KV       |
                                                 v
                                           extension reads
                                           unsealed identity
                                           at tunnel start
```

The PIN itself NEVER crosses the App Group boundary — only the
RESULT of unlock does. The unsealed identity persists in the App
Group secrets KV under the iOS Data Protection class
`NSFileProtectionCompleteUntilFirstUserAuthentication`; on the
next launch after a reboot the user re-unlocks before the
extension can start the tunnel.

The engine-side `engine_unlock_secrets` ABI surface is unchanged.
The host-app-vs-extension split is purely a 2E platform
integration decision; the engine treats it identically to the
desktop's single-process unlock.

## v2 considerations (not implemented)

- Larger memory params (128 MiB) with capability-detection.
- Hardware-token gating (TPM / Secure Enclave) as a third profile
  (`hwbacked`).
- Re-keying without a full rewrite (key-encryption-key over a
  per-record DEK).

These are explicitly out of scope at v1.
