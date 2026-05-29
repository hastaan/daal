# FRP-4b — Direct-deploy Integration — Handover

**Status: SHIPPED 2026-05-03**

FRP-4b glues the FRP-5 desktop wizard's two-layer key custody to
FRP-4a's deploy substrate, producing the first end-to-end signed
direct-mode RelayPack the wizard can hand off to a family member
via animated QR.

## Position B preserved

No new analytics/telemetry symbols were added. The
`no_analytics_vendor_symbols_in_wizard_sources` test sweeps both
the Rust crate and the Tauri frontend (including the 3 new
screens + ~22 new i18n strings each in EN/FA) and stays green.

## Engine ABI

Untouched at 48. FRP-4b is a publisher-side feature; the engine /
daal-core has no FRP-4b-specific code.

## Commits

| # | SHA | Subject |
|---|-----|---------|
| 1 | 6f1f845 | relaypack package skeleton + relay_pack_id + risk_graph + candidate_render |
| 2 | d61abd5 | BindAndSign live + 16 tests |
| 3 | a801cdb | daal-deploy bind-and-sign + qr-fountain + --progress-json |
| 4 | 4fab988 | Rust wizard plumbing + commands + OPSEC flip |
| 5 | 70a6951 | Tauri shims + LIVE screens 4/5/6 + i18n |
| 6 | 0c0f299 | E2E smoke + handover + status flips |

## Architecture

### Asymmetric guard preserved

The new package `publisher/deploy/relaypack/` imports
`bundle/go/bundle` and `bundle/go/relaypackvalidate` but never
imports `core/` or `bundle/go/publisher/`. The Helper-side bind
path is therefore non-fatal even if a recipient's libcore
crashes; the publisher's signing tooling is fully decoupled from
the engine.

### Key flow

```
   wizard (Rust)
   |
   |-- Keystore.open(priv_alias, pin)  -> Vec<u8> (ed25519 priv, 64 bytes)
   |
   |-- spawn `daal-deploy bind-and-sign --priv-key=-`
   |        |
   |        |-- pipes priv-key bytes through stdin
   |        |-- runs Go-side relaypack.BindAndSign
   |        |-- emits {"step":...,"message":...} on stderr
   |        |-- writes summary JSON on stdout
   |        |
   |        '-- exits 0 / non-zero
   |
   |-- Zeroizing<Vec<u8>> wipes the priv buffer
   |-- forwards summary to Screen 5; emits 'wizard://sign-event' to UI
```

The privkey never touches disk. The wizard's
`tests/key_opsec.rs::sign_relaypack_pipes_priv_key_through_stdin`
proves the transport via a MockRunner spy.

### Determinism

`BindAndSign(rec, priv, opts)` is a pure function. Same inputs
produce byte-identical .sbp bytes (proved by
`TestBindAndSign_DeterministicRoundTrip` and
`TestFRP4b_BindAndSignDeterministicCrossRun`). The CLI exposes
`--now-unix` so two operators on different machines can verify
they build identical .sbps from a given (rec, key, now) tuple.

### Validate-before-sign

The binder runs `relaypackvalidate.Validate` BEFORE producing
.sbp bytes. Any RP001..RP018/RP021 hard error returns
`error` from `BindAndSign` with no .sbp emitted. RP019/RP020 lint
warnings travel through `BindResult.LintReport` and surface in
the wizard frontend as a yellow banner (Screen 5).

## CLI subcommands

```sh
daal-deploy bind-and-sign \
    --operator-record path/to/rec.json \
    --priv-key -                          # stdin transport (preferred)
    --output path/to/out.sbp \
    --phase V1.5 \
    --now-unix 1746115200 \
    --expiry-days 30 \
    --publisher-name "Family Relay Publisher" \
    --progress-json

daal-deploy qr-fountain --sbp out.sbp --block-size 256 --frames 0 --seed 0

daal-deploy provision --progress-json   # stderr JSON-lines, FRP-4b
```

## V002 migration

`client-desktop/daal-wizard/migrations/V002__signed_sbp.sql`
adds three NULL-able columns to `operators`:

- `signed_sbp_sha256`        — hex(sha256(.sbp bytes))
- `signed_sbp_relay_pack_id` — `rp-...` id from the binder
- `signed_sbp_at_unix`       — bind timestamp

The wizard sets these via `record_signed_sbp(...)` after a
successful `sign_relaypack`.

## OPSEC test polarity flip

The `frp4b_command_names_present_in_wizard_sources` test
(formerly `no_frp4b_command_names_in_wizard_sources`) now asserts
that `pub fn provision_run`, `pub fn sign_relaypack`, and
`pub fn qr_render` ARE defined in the crate. Removing one
without re-adding it elsewhere fails the test before the Tauri
shim refuses to compile.

## Surface left for FRP-7+

- **CLI `bind-and-sign` does not yet accept `--rotation-prev-key`**.
  FRP-7 lifts this to support priv-key rotation; the SHA-pin in
  V002 lets us detect when a rotation is in flight.
- **Send-via-Signal / Print buttons disabled on Screen 6.** FRP-9
  wires Signal hand-off; print is a simple dialog wrapper around
  the QR canvas the same commit lights up.
- **Rotate button disabled on Screen 6** with the
  `rotate_disabled_caption` string. FRP-7 ships rotation; the
  button comes alive then.
- **Cloud-init / health-poll / ssh-close events.** Screen 4
  reserves rows 2-3 for these but the dry-run path's CLI events
  only cover provision_start / provision_cloud_call /
  provision_done. FRP-7 adds the remaining live VPS events.
- **QR streaming is finite-batched in the Tauri frontend.** The CLI
  still supports `--frames 0` for direct operator use, but Screen 6
  requests bounded batches so leaving the screen cannot leak an
  unbounded `qr-fountain` subprocess.
- **No engine ABI work needed** at FRP-4b; ABI stays at 48.
- **freshness_url stays empty at V1.5** (RP021 enforces). FRP-8
  flips the validator phase to V1.6 and lifts the empty
  constraint.

## Surface left for FRP-8

- `Phase` in `BindOpts` accepts V1.6 / PostV2 today; the binder
  is correct under those settings already (tests cover V1.5
  only because that's the ship phase). FRP-8 just flips the
  default.

## Test inventory

| Layer | Tests | Where |
|-------|-------|-------|
| Go binder package | 33 | `publisher/deploy/relaypack/*_test.go` |
| Go binder E2E    | 2  | `publisher/deploy/relaypack/e2e_smoke_test.go` |
| CLI              | 19 | `publisher/deploy/cli/cli_*_test.go` |
| Rust wizard unit | 49 | `client-desktop/daal-wizard/src/**/tests` |
| Rust OPSEC       | 4  | `client-desktop/daal-wizard/tests/key_opsec.rs` |
| Rust schema xref | 2  | `client-desktop/daal-wizard/tests/schema_xref.rs` |

Total FRP-4b additions across commits 1-6 plus readiness correction: **109 test cases**.

## Build matrix at ship

```
cd publisher && go test ./...                              PASS
cd cmd/daal-deploy && go build ./...                      PASS
cd cmd/daal-deploy && go test -count=1 ./...              PASS
cd cmd/daal-deploy && go run . bind-and-sign --help       PASS
cd cmd/daal-deploy && go run . qr-fountain --help         PASS
cd bundle/go && go test -count=1 ./...                     PASS
cd core && go test -count=1 ./...                          PASS
cd client-desktop && cargo test -p daal-wizard             PASS
cd client-desktop && cargo test -p daal-wizard --features dev-no-keystore PASS
cd client-desktop && cargo build --workspace                PASS
cd client-desktop/tauri/src-tauri && cargo build            PASS
cd client-desktop/tauri/src-tauri && cargo build --release  PASS
cd client-desktop/tauri/src-tauri && cargo test             PASS
cd client-desktop/tauri && npm run build                    PASS
cd client-desktop/tauri && npm audit --audit-level=moderate PASS
```

ABI=48 locked. Position B preserved.
