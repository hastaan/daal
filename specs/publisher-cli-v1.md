# Publisher CLI v1 (`daal-publish`)

## Status

Draft for V1.6 implementation. **Phase 3A adds the
`webtunnel-bridge` subcommand for V3.1.** **Phase 3B adds the
`snowflake-rendezvous-hint` subcommand for V3.2.**

## Purpose

`daal-publish` is the operator-facing command-line tool that turns the bundle/trust core into produced, signed, verifiable `.sbp` artifacts. It is the only supported way to produce production bundles, sub-keys, revocation lists, and root-key rotation chains.

## Non-Goals

- No web admin / publisher portal.
- No HSM/YubiHSM integration in this version (`--hsm` flag is reserved and rejected with a clear "not yet implemented" message).
- No bootstrap-directory builder.
- No telemetry, no auto-uploads, no remote calls of any kind. `daal-publish` and the `publisher/` package never open a network socket.

## Commands

```text
daal-publish keygen      --out-dir <dir> [--label <name>] [--force]
daal-publish subkey      --root-priv <file> --out-dir <dir>
                          --validity <duration> [--label <name>]
daal-publish bundle      --manifest <json> --profiles-dir <dir>
                          --signing-priv <file> --publisher-pub <file>
                          [--rotation-chain <file>] [--revocation <file>]
                          --out <file.sbp>
                          [--lint-strict] [--unsafe-unsigned]
daal-publish verify      <file.sbp>
                          [--require-trust-class <c>] [--max-route-count <n>]
                          [--reject-on-warn]
daal-publish revoke      --root-priv <file>
                          [--bundle-id <uuid>]... [--route-id <uuid>]...
                          [--publisher-fingerprint <hex>]...
                          --reason <free-text> --out <revocation.json>
daal-publish rotate-key  --old-root-priv <file> --new-root-pub <file>
                          --transition-window <duration>
                          --out <rotation.json>
daal-publish fingerprint <publisher.pub>
daal-publish version
daal-publish webtunnel-bridge   --hostname <host> --port <int>
                                 --bridge-fingerprint <hex-sha1>
                                 --secret-path-bytes <int>
                                 [--scarcity-class <c>]
                                 [--sni <hostname>]
                                 [--alpn <proto>]...
                                 --output <route.json>
daal-publish snowflake-rendezvous-hint
                                 --channel <channel-id>
                                 [--broker-url <url>]
                                 [--sqs-queue-url <url>]
                                 [--amp-cache-url <url>]
                                 [--push-registry-url <url>]
                                 [--push-topic <name>]
                                 --signing-priv <file>
                                 --validity <duration>
                                 --output <hint.json>
```

`<duration>` accepts Go duration syntax extended with `d` (days) and `w` (weeks).

## Keystore Layout

```text
<keystore>/
  publisher.pub                    32 bytes, mode 0644
  publisher.priv                   64 bytes, mode 0600
  publisher.meta.json              label, created_at, fingerprint hex/EN/FA
  subkeys/<fingerprint>/
    subkey.pub                     mode 0644
    subkey.priv                    mode 0600
    subkey.meta.json
    subkey.cert                    canonical-JSON cert signed by root
```

- Private files MUST be created with mode `0600` and the key directory with `0700`.
- The CLI refuses to overwrite an existing `publisher.priv` without `--force`.
- The CLI never prints private bytes. Errors that would echo private buffers are sanitized.

## Sub-Key Cert

```jsonc
{
  "v": 1,
  "kind": "subkey_cert",
  "root_fingerprint_hex": "...",
  "subkey_pub_hex": "...",
  "valid_from": "RFC3339",
  "valid_until": "RFC3339",
  "label": "operator-laptop-2026-04",
  "signature_hex": "..."
}
```

When a sub-key is used to sign a bundle, the cert is embedded under
`trust/subkey-cert.json` so verifiers can cross-check the signing chain.

## Rotation Chain

```jsonc
{
  "v": 1,
  "kind": "root_rotation",
  "old_root_fingerprint_hex": "...",
  "new_root_pub_hex": "...",
  "transition_starts_at": "RFC3339",
  "transition_ends_at": "RFC3339",
  "signature_hex": "..."
}
```

Signed by the **old** root key. Embedded under `trust/rotation.json` in the
first bundle signed by the new root.

## Revocation

```jsonc
{
  "v": 1,
  "issued_at": "RFC3339",
  "revoked_publishers": ["fp-hex"],
  "revoked_routes": ["route-id"],
  "reason": "compromised endpoint",
  "signature_hex": "..."
}
```

Signature is over canonical JSON of every field except `signature_hex`.

## Safety Rules (enforced by the CLI)

- Refuse production output without a signing key. Bundles without
  `manifest.sig` require `--unsafe-unsigned` and the output filename is forced
  to end in `.UNSIGNED.sbp`.
- `bundle.expires_at` is required and must be in the future at build time.
- Each `routes[].valid_until` must be ≤ `bundle.expires_at + 7 days`.
- Default route-count cap = 100. Warn at 30 (friend-share) / 50 (provider).
- Reject `bundle.type` values not in the spec enum.
- Reject manifest fingerprint that does not match `publisher.pub`.
- Never log or echo bytes from `*.priv` files.
- All file outputs are atomic (`*.tmp` then rename).

## Lint Codes

| Code | Level | Trigger |
|---|---|---|
| `REALITY_COVER_SNI_IMPLAUSIBLE` | warn | metadata-only ASN/SNI mismatch heuristic. |
| `PUBLISHER_KEY_REUSE` | warn | same publisher signs many routes sharing IP/SNI prefix. |
| `EXPIRY_TOO_LONG_BOOTSTRAP` | warn | `valid_until` > 30d for `scarcity_class: emergency`. |
| `EXPIRY_TOO_LONG_FRIEND_SHARE` | warn | `valid_until` > 60d for `bundle.type: friend_share`. |
| `UDP_ONLY_NO_TCP_FALLBACK` | warn | bundle has only UDP-gated transports. |
| `UDP_GATED_NOT_MARKED` | block | UDP-first transport missing `udp_gated: true`. |
| `EMPTY_PROFILES` | block | route's `config_path` missing/empty in `--profiles-dir`. |
| `PROFILE_OUTSIDE_DIR` | block | `config_path` resolves outside `profiles/`. |
| `BUNDLE_TYPE_MISMATCH_SCARCITY` | warn | `bundle.type: emergency` with no emergency route. |
| `MANIFEST_TIME_SKEW` | warn | `created_at` >24h future or >90d past. |

`--lint-strict` promotes every `warn` to a `block`.

## Exit Codes

- `0` — ok.
- `1` — operational error (file I/O, bad flags).
- `2` — bundle invalid / verification failed.
- `3` — lint warnings, only with `--reject-on-warn`.

## Determinism

`daal-publish bundle` produces byte-identical archives for identical inputs.
This is enforced by `bundle.BuildSignedBundleDeterministic` (sorted entries,
zeroed mtimes, Store method).

## Operator UX

- Output is plain text on stdout; structured JSON only with `--json`.
- Warnings go to stderr; never stdout.
- Every lint warning includes a remediation hint and a doc anchor.
- Successful `bundle` prints publisher fingerprint in hex, English four words,
  and Persian four words.
- Verify summary prints publisher fingerprint, route count by family, expiry;
  never private or signature material.

## Phase 3A `webtunnel-bridge` subcommand

Generates a `routes[]` JSON object ready to be embedded in an
`.sbp` manifest under `transport_family: "webtunnel"`. See
`specs/webtunnel-route-v1.md` for the wire shape.

- `--hostname` (required) — the bridge's public hostname.
- `--port` (default 443) — the bridge's TCP port.
- `--bridge-fingerprint` (required) — hex SHA-1 of the
  bridge's certificate, used in the WebTunnel client's TLS
  pinning clause.
- `--secret-path-bytes` (default 16) — generates a URL-safe
  random path of the requested byte length.
- `--scarcity-class` (default `experimental`) — the route's
  scarcity tag. The CLI rejects `bulk-capable` for WebTunnel
  routes at parse time (mirroring the SBP-v1 parser rule).
- `--sni` (optional) — overrides the SNI; defaults to
  `--hostname`.
- `--alpn` (repeatable, optional) — ALPN list; defaults to
  `["http/1.1"]`.
- `--output` (required) — output file path.

The subcommand never opens a network socket (existing OPSEC
invariant). The generated path is produced by `crypto/rand`;
the CLI refuses to run on a system whose RNG read fails.

## Phase 3B `snowflake-rendezvous-hint` subcommand

Generates a single `rendezvous_hints[]` entry signed by the
publisher key, ready to splice into a manifest's top-level
`rendezvous_hints[]` slot. See `specs/rendezvous-channels-v1.md`
and `specs/snowflake-route-v1.md`.

- `--channel` (required) — one of `domain_fronted_broker`,
  `sqs`, `amp_cache`, `push`, `offline_hint`. Unknown values
  rejected.
- `--broker-url` — required for `domain_fronted_broker`.
  HTTPS only.
- `--sqs-queue-url` — required for `sqs`. HTTPS only.
- `--amp-cache-url` — required for `amp_cache`. HTTPS only.
- `--push-registry-url` — required for `push`. HTTPS only.
- `--push-topic` — required for `push`. Free-form string.
- `--signing-priv` (required) — publisher private key path.
- `--validity` (required) — duration the hint is good for.
- `--output` (required) — output file path.

The subcommand never opens a network socket (existing OPSEC
invariant). The signature is over canonical-JSON-encoded
`{channel_id, payload}` per `specs/sbp-v1.md`'s 3B field
semantics. The CLI refuses `push`-channel hints whose
`--push-registry-url` is not HTTPS.

## Phase 3C `masque-bridge` subcommand

Generates a single `routes[]` entry stub for a MASQUE upstream
endpoint, ready to splice into a manifest's `routes[]` array.
See `specs/masque-ladder-v1.md`.

- `--endpoint` (required) — `https://host[:port]/path`. MUST
  be `https://`; the path MUST be non-empty (`/` alone is
  rejected). The host portion drives the default route ID.
- `--route-id` (optional) — defaults to `mq-<sanitised-host>`.
- `--validity` (optional) — defaults to `7d`. Accepts the
  same duration grammar (`Nd`, `Nh`, `Nm`) as the 3A
  `webtunnel-bridge` subcommand.
- `--caveat-fa-ir` (optional) — Persian caveat override
  (defaults to empty; the family default applies).
- `--experimental-min-engine-version` (optional) — semver pin
  (defaults to empty; no minimum).
- `--out` (required) — output file path.

The emitted route stub carries:

- `transport_family: "masque"`.
- `scarcity_class: "experimental"` (locked at 3C; the
  routestore family table is the gatekeeper).
- `masque_endpoint: <URL>` (the new 3C field).
- `family_specific_config: {}` (empty object; reserved for
  future per-route knobs at the H2 / H3 rung).

The subcommand never opens a network socket (existing OPSEC
invariant).

## Phase 3D `psiphon-bundle` subcommand

Wraps an upstream Psiphon publisher bundle (produced
out-of-band by Psiphon Inc.'s tooling) into a Daal `routes[]`
entry stub. See `specs/psiphon-route-v1.md`.

- `--psiphon-blob` (required) — path to the raw upstream
  bundle bytes. Size MUST be in `[256, 65536]` bytes.
- `--route-id` (optional) — defaults to
  `ps-<8-byte-SHA-256-prefix>` of the blob.
- `--validity` (optional) — defaults to `7d`.
- `--scarcity` (optional) — defaults to `normal`.
  `--scarcity emergency` is **rejected** (locked at 3D:
  emergency-class capacity is the bootstrap pool budget;
  psiphon routes cannot share that budget without burning
  the publisher's quota).
- `--caveat-fa-ir` (optional) — Persian caveat override.
- `--experimental-min-engine-version` (optional) — semver
  pin.
- `--out` (required) — output file path.

The emitted route stub carries:

- `transport_family: "psiphon"`.
- `scarcity_class: <user choice; default "normal">`.
- `psiphon_bundle_blob_b64: <base64 of the blob>`.
- `family_specific_config: {}` (empty object; reserved).

## Phase 3D `conjure-bridge` subcommand

Generates a single `routes[]` entry stub for a Conjure
Tap-Dance station + phantom-pool selection. See
`specs/conjure-route-v1.md`.

- `--station-pubkey` (required) — 64 hex chars (32 bytes
  curve25519 station public key).
- `--phantom-subnets` (required) — comma-separated CIDR list.
  Floors `/24` IPv4, `/32` IPv6 are enforced (publisher-side
  AND parser-side, defence-in-depth).
- `--decoy-pool` (optional) — comma-separated RFC 1123
  hostnames the upstream library MAY use as registration
  cover.
- `--route-id` (optional) — defaults to
  `cj-<8-hex-station-pubkey-prefix>`.
- `--validity` (optional) — defaults to `7d`.
- `--scarcity` (optional) — defaults to `experimental`.
- `--caveat-fa-ir` (optional) — Persian caveat override.
- `--experimental-min-engine-version` (optional) — semver pin.
- `--out` (required) — output file path.

The emitted route stub carries:

- `transport_family: "conjure"`.
- `scarcity_class: <user choice; default "experimental">`.
- `conjure_phantom_subnets: [<CIDRs>]`.
- `conjure_station_pubkey: <hex>`.
- `conjure_decoy_pool: [<hostnames>]` (omitted from JSON when
  empty).
- `family_specific_config: {}` (empty object; reserved).

Both 3D subcommands inherit the no-network-socket OPSEC
invariant.

## Phase 3E `wasm-module` subcommand

Wraps a compiled `.wasm` blob into a `transport_modules[]`
entry stub plus a paired `routes[]` entry stub.

Flags:

- `--wasm <path>` — REQUIRED. Path to the compiled
  `.wasm` blob.
- `--slug <slug>` — REQUIRED. Module slug,
  `[a-z0-9_-]{3,32}`. Locked at 3E.
- `--out-module <path>` — REQUIRED. Path to write the
  module-entry JSON.
- `--out-route <path>` — REQUIRED. Path to write the
  paired route-stub JSON.
- `--route-id <id>` — Optional. Default `tm-<slug>`.
- `--validity <duration>` — Optional. Default `7d`.
- `--scarcity <class>` — Optional. Default
  `experimental`. Locked at 3E: `emergency` is rejected
  for `transport_module` routes (the family is
  experimental; routes MUST NOT consume the bootstrap
  pool).
- `--caveat-fa-ir <text>` — Optional. Iranian region
  caveat.
- `--experimental-min-engine-version <semver>` — Optional.
- `--min-engine-version <semver>` — Optional. The module's
  own min-engine-version pin. Default `0.8.0`.

CLI-side validation locks at 3E:

- `.wasm` blob > 4 MiB rejected.
- Slug regex enforced.
- `emergency` scarcity rejected.

Output JSON shapes match the bundle module's
`bundle.TransportModuleEntry` and a routes-array stub with
`transport_family: "transport_module"` and
`transport_module_slug: <slug>`.

## Phase 3E `wasm-killswitch` subcommand

Signs a `(slug, sha256, generation)` tuple under the
project-controlled WASM kill-switch private key (CC.4
hardware-token custody) and emits the canonical signed JSON
delta.

Flags:

- `--slug <slug>` — REQUIRED. Slug to kill (`[a-z0-9_-]{3,32}`).
- `--sha256 <hex>` — REQUIRED. Module sha256 hex (64 chars).
- `--generation <uint64>` — REQUIRED. Monotonically-
  increasing counter; engines reject deltas whose generation
  is ≤ the cached watermark.
- `--key <path>` — REQUIRED. Path to the Ed25519 private
  key. Accepts raw 64 bytes OR hex-encoded (128 chars).
- `--out <path>` — REQUIRED. Path to write the signed delta
  JSON.

Emitted JSON (locked shape):

```json
{
  "slug":       "<slug>",
  "sha256":     "<64-hex>",
  "generation": <N>,
  "signature":  "<base64-raw-std Ed25519 sig>"
}
```

Canonical signing payload (locked byte-for-byte; see
`specs/wasm-kill-switch-v1.md`):

```
{"slug":"<slug>","sha256":"<64-hex>","generation":<N>}
```

CLI-side validation locks at 3E:

- Slug regex enforced.
- `--sha256` MUST be exactly 64 hex chars.
- `--generation` MUST be > 0 (the engine watermark starts
  at 0; generation 0 is reserved).

The CLI does NOT publish — the operator splices the emitted
delta into the next bundle's `wasm_kill_switch_deltas[]` and
ships it through the existing publisher channel. Both 3E
subcommands inherit the no-network-socket OPSEC invariant.

## OPSEC Invariants

- The CLI never opens a network socket. Source-grep tests assert that
  `net.Dial`, `http.Get`, and `http.Client` do not appear in the CLI or
  publisher packages.
- Private-key bytes are not returned by error paths.
- File modes for keystore artifacts are tested.

## Phase 3F: `bundle` flag widening

The `bundle` subcommand gains two optional flags applied
uniformly to every route in the manifest:

- `--redistribution-policy=<none|delegated_n|transitive>` —
  closed enum; rejects unknown values at CLI parse time.
- `--delegate-cap=<1..255>` — uint8 cap. Required when
  `--redistribution-policy=delegated_n`; rejected for the other
  two values.

Per-route overrides require the operator to edit the manifest
JSON directly (the CLI applies a single policy to a build, by
design). The flags translate verbatim into
`routes[].redistribution_policy` + `routes[].redistribution_cap`
on the resulting `.sbp`. See `delegate-keys-v1.md`.
