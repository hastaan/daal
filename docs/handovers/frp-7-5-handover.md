# FRP-7.5 handover — publisher sub-key cert chain

**Status:** SHIPPED 2026-05-03 (engineering surface).
**Closure:** HOLD (`specs/v1-5-closure-v1.md`) — same gate as
FRP-7; FRP-7.5 is part of the V1.5 closure path, not a separate
milestone.
**Engine line:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI:** **48** UNCHANGED.
**Spec version:** `.sbp` `spec_version` bumps **3 → 4**
(verifier accepts `{1, 2, 3, 4}`; producers default to v4 when
signing with a sub-key).

This handover summarises the seven-commit FRP-7.5 series. It
closes the 1A handover deferred-followup ("staged guard in
`bundle_cmd.go` + sign-with-subkey path live") and ships the
sub-key cert chain end-to-end: producer, verifier, CLI, wizard,
UI, banner, and on-disk sample.

## What FRP-7.5 ships

FRP-7.5 lets a long-running FRP rotate their publisher sub-key
on a 90-day cadence without ever touching the root publisher
key. The root key opens once when the operator chooses to mint
a fresh sub-key; subsequent RelayPack rotations sign with the
sub-key. A 75 % / 95 % lifetime banner prompts ahead of expiry.

### Commit-by-commit

| # | SHA | Title |
|---|---|---|
| 1 | `4827d44` | spec_version 3→4 + VerifyBundle sub-key chain branch + 11 unit tests |
| 2 | `b916ae0` | lift staged guard in bundle_cmd.go + sign-with-subkey path live |
| 3 | `7ecae75` | E2E no-root-touch test + subkey-signed-A.sbp sample artefact |
| 4 | `c077544` | daal-publish subkey rotate CLI subcommand |
| 5 | `4a90601` | wizard subkey-rotate Tauri command + Settings modal |
| 6 | `719f387` | 75%/95% sub-key lifetime banner + i18n |
| 7 | (this commit) | spec sub-key section + relaypack cross-ref + handover |

### New code surfaces

* `bundle/go/bundle/subkey_chain.go` — bundle-side mirror of
  `publisher.SubkeyCert` plus the canonical cert verification
  logic. Bundle never imports `publisher/...`; the mirror keeps
  the verifier dependency-isolated.
* `bundle/go/bundle/sbp.go::VerifyBundle` — extended to walk
  `pub → cert → sub` when the archive carries
  `trust/subkey-cert.json`. Spec gate widened from `{1,2,3}` to
  `{1,2,3,4}`. Cert path requires `spec_version >= 4`.
* `bundle/go/bundle/errors.go` — five new sentinel errors
  (`ErrSubkeyCertMalformed`, `ErrSubkeyCertRootMismatch`,
  `ErrSubkeyCertOutOfWindow`, `ErrSubkeyCertBadSignature`,
  `ErrSubkeyCertSpecVersionTooOld`).
* `bundle/go/bundle/sbp_subkey_test.go` + `sbp_subkey_e2e_test.go`
  — 11 unit tests + an E2E rootCounter test that asserts only
  two root signs happen across two cert mints and three
  bundle sign/verify cycles.
* `bundle/go/cmd/bundle-subkey-sample/main.go` +
  `specs/test-vectors/bundles/samples/subkey-signed-A.sbp` —
  deterministic sample generator and the on-disk artefact
  (1969 bytes, `spec_version=4`, root_fp `baf7fd3808058a85`,
  sub_fp `47be59894e1b4563`). `TestSubkeySignedSampleArtefact`
  re-verifies it from disk.
* `bundle/go/publisher/bundle_cmd.go` — staged guard removed;
  signing with a sub-key reads the sibling `subkey.cert`,
  embeds it as `trust/subkey-cert.json`, and forces
  `spec_version >= 4`. `enforceManifestPolicy` widened from
  `{1,2}` to `{1,2,3,4}` (corrects a pre-existing FRP-1
  oversight).
* `bundle/go/cmd/daal-publish/main.go` — `subkey rotate`
  subcommand (default validity=90d, default
  label="rotated-subkey", optional `--json` shape matching
  `SubkeyRotateResult`).
* `client-desktop/daal-wizard/migrations/V004__subkeys.sql` —
  the `subkeys` history table (operator_id, fingerprint, paths,
  inline cert_json, validity windows, `active=1` partial-unique
  index).
* `client-desktop/daal-wizard/src/operator_db.rs` —
  `SubkeyRow` type, `insert_subkey_rotation` /
  `active_subkey` / `list_subkey_history` ops, three new V004
  tests.
* `client-desktop/daal-wizard/src/commands.rs::subkey_rotate` —
  PIN-gated; opens root from keystore; writes a 0o600
  tempfile; spawns `daal-publish subkey rotate --json` via
  env `DAAL_PUBLISH_BIN`; parses the JSON; persists in V004.
  Tempfile is best-effort unlinked after the subprocess exits.
* `client-desktop/daal-wizard/src/commands.rs::sign_relaypack` —
  when V004 has an active sub-key, reads that sub-key private
  artefact, passes it to `daal-deploy bind-and-sign` via stdin,
  and supplies the active `subkey.cert` via `--subkey-cert`. This
  makes subsequent RelayPacks sub-key-signed (`spec_version=4`)
  without touching the root key again.
* `publisher/deploy/relaypack.BindAndSign` +
  `publisher/deploy/cli bind-and-sign` — accept optional
  sub-key cert material, keep `publisher.pub` as the root key,
  embed `trust/subkey-cert.json`, and emit `spec_version=4`.
* `client-desktop/tauri/src-tauri/src/lib.rs` —
  `wizard_subkey_rotate`, `wizard_subkey_active`,
  `wizard_subkey_history` Tauri commands, registered in the
  invoke handler.
* `client-desktop/tauri/src/wizard/screens/SubkeyRotateModal.tsx`
  — single-step input → working → success modal with
  past-rotations list.
* `client-desktop/tauri/src/wizard/screens/SubkeyLifetimeBanner.tsx`
  + `client-desktop/tauri/src/wizard/subkeyLifetime.ts` — passive
  75 % / 95 % banner (yellow / red) on Screen 6.
* `specs/sbp-v1.md` §"Phase FRP-7.5 widening" — locked the new
  `spec_version` and the five sentinel errors.
* `specs/relaypack-v1.md` — forward-pointer made concrete:
  v4 + RelayPack are orthogonal additive surfaces.

### Locked invariants reinforced

The eight FRP-7.5-specific invariants from
`specs/v1-5-closure-v1.md` (numbered 17–24 in that document):

| # | Invariant | Evidence |
|---|---|---|
| 17 | Cert chain only new in-archive entry; canonical bytes preserved | `sbp_subkey_test.go` canonical cert-body coverage + sample re-verify |
| 18 | `spec_version` bumps once (3→4); pre-V1.5b verifier rejects explicitly | `v2_test.go::TestSpecV4Accepted` + `TestSpecV5Rejected` |
| 19 | Root-key touch eliminated for routine rotation | `sbp_subkey_e2e_test.go::TestNoRootTouchAfterRotation` (rootCounter == 2) |
| 20 | Cert validity enforced (`valid_from`/`valid_until`) | `sbp_subkey_test.go` future `valid_from` + past `valid_until` cases |
| 21 | ABI count stays 48 | nm check unchanged |
| 22 | Position B preserved | no analytics symbols in any FRP-7.5 source; wizard subkey path opens NO sockets |
| 23 | Old bundles (no cert chain) keep working | `sbp_subkey_test.go::TestNoCertFallback` + sample v3 corpus re-verify |
| 24 | Sub-key compromise is bounded | cert expiry is enforced via `ErrSubkeyCertOutOfWindow`; wizard can rotate forward to a fresh active sub-key; root/publisher revocation remains the emergency recovery path before expiry |

### Engine-line + ABI invariants (carried from FRP-7)

| Invariant | Evidence |
|---|---|
| Engine `daal-core 0.9.0+v3-share` | `core/internal/version` unchanged across all 7 commits |
| ABI count = 48 | nm check unchanged |
| `v3-superset` size = 31 | unchanged |
| `v2-superset` size = 26 | unchanged |
| `v1-5-superset` size = 6 | unchanged |

## Test matrix at ship

| Tree | Command | Result |
|---|---|---|
| `bundle/go/bundle/...` | `go test ./...` | PASS (11 new sub-key tests + E2E + sample re-verify) |
| `bundle/go/publisher/...` | `go test ./...` | PASS (3 new bundle_cmd tests) |
| `bundle/go/cmd/daal-publish/...` | `go test ./...` | PASS (3 new CLI tests) |
| `bundle/go/cmd/bundle-subkey-sample` | `go run ./...` | regenerates pinned sample artefact |
| `client-desktop/daal-wizard` | `cargo test -p daal-wizard` | PASS (adds active-subkey signing path coverage) |
| `client-desktop/tauri/src-tauri` | `cargo check` | PASS |
| `client-desktop/tauri` (TS) | `npx tsc --noEmit` | PASS |
| `client-desktop/tauri` (build) | `npx vite build` | PASS (~250 kB) |
| FRP-7 + FRP-6 + FRP-3 regressions | as in FRP-7 handover | unchanged |

## V1.5 milestone — what remains

FRP-7.5 does NOT change the V1.5 closure gate. The same four
operational items remain from the FRP-7 handover:

1. **Run a live pilot** with five FRPs per
   `docs/pilot/frp-7-pilot-template.md`. FRP-7.5 adds one
   optional pilot scenario: at least one FRP exercises the
   sub-key rotation flow during the seven-day window so the
   `subkeys` V004 table accumulates ≥ 1 active row.
2. **Native FA review of the consent template**.
3. **Native FA review of FRP-6 + FRP-7 + FRP-7.5 i18n**.
   FRP-7.5 keys: 19 per locale (14 modal + 5 banner) under
   `wizard.subkey.*` in
   `client-desktop/tauri/src/wizard/i18n/wizard.fa.json`.
4. **Project lead transcribes** the aggregate roll-up into
   `specs/v1-5-closure-v1.md` and flips status from HOLD to
   SHIPPED.

## V1.5 → V1.6 gate (unchanged)

V1.6 is the **CDN milestone** line (FRP-8: `cdn_fronted`
candidates per supplement §11.7 + §14.4). V1.5 closure is the
production precondition. FRP-7.5 engineering ships the last
piece of the V1.5 engineering surface.

V1.6 engine target: `daal-core 0.9.0+v3-share` UNCHANGED.
V1.6 stays `spec_version=4` unless cdn_fronted requires another
schema bump (current plan: additive widening on the existing
`_relaypack` sub-object, no `spec_version` change).

## Carry-over open items

* (FRP-6) FA copy native review — 30 keys.
* (FRP-7) FA copy native review — 30 keys (rotate modal).
* (FRP-7.5) FA copy native review — 19 keys (sub-key modal +
  banner).
* (FRP-7) FA consent text native review.
* (FRP-7) Live pilot run with 5 FRPs (now MAY include one
  sub-key rotation scenario).
* (V1.6 spec) `phases of development/38-phase-frp-8-v1-6-cdn-fronted.md`
  is filed but not started.

## Files to read first if you're picking this up

1. `specs/v1-5-closure-v1.md` invariants 17–24 (the FRP-7.5
   contract).
2. `specs/sbp-v1.md` §"Phase FRP-7.5 widening" (the locked
   wire shape and the verifier walk).
3. `bundle/go/bundle/sbp.go::VerifyBundle` (the actual walk).
4. `bundle/go/bundle/subkey_chain.go` (the bundle-side
   `SubkeyCert` mirror — the only place to touch if the wire
   shape ever extends).
5. `client-desktop/daal-wizard/src/commands.rs::subkey_rotate`
   (the wizard surface that ties everything together).
6. `specs/test-vectors/bundles/samples/subkey-signed-A.sbp`
   (the on-disk reference artefact; `TestSubkeySignedSampleArtefact`
   re-verifies it).

## Attestation

| Field | Value |
|---|---|
| Phase | FRP-7.5 |
| Engine | `daal-core 0.9.0+v3-share` |
| ABI count | 48 |
| `.sbp` `spec_version` | bumped 3 → 4 (additive; verifier accepts `{1,2,3,4}`) |
| Root-key touch eliminated | YES (`TestNoRootTouchAfterRotation`) |
| Sample artefact | `subkey-signed-A.sbp` (1969 B; root_fp `baf7fd3808058a85`; sub_fp `47be59894e1b4563`) |
| Synthetic soak | unchanged (`v1-5-superset` 6/6 PASS, `v3-superset` 31/31 PASS) |
| Live pilot | NOT YET RUN — V1.5 closure HOLD |
| Project position | B (no telemetry, unchanged) |
