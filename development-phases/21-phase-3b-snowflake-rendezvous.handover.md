# Phase 3B — Snowflake + Multi-Rendezvous Library — HANDOVER

## Status

**SHIPPED.** All 11 sub-tasks landed. Engine version
`daal-core 0.7.1+v3-transport`. Release ABI count **44**
(42 → 44; +2 new symbols, append-only).

## Roadmap line

V3.2 ("Snowflake-like ephemeral relays"). The 3B landing
converts "the Snowflake broker is blocked" from a fatal
failure to a degraded mode by introducing a closed v1
taxonomy of 5 rendezvous channels with hedged-at-4s
selection.

## What landed

### Engine

- **`core/rendezvous/`** — new internal package, stdlib-only.
  - 5 channel constants (`domain_fronted_broker`, `sqs`,
    `amp_cache`, `push`, `offline_hint`).
  - `Channel` interface + `Selector` with hedged Race.
  - 5 constructors (`NewDomainFrontedBroker`, `NewSQS`,
    `NewAMPCache`, `NewPush(enabledFn)`, `NewOfflineHint`)
    that take a `Solicitor` callback so the package stays
    free of the upstream Snowflake / pion / FCM / APNS
    dependencies and remains unit-testable without
    network access.
  - `PushQueue` + `VerifyPushPayload` for the FCM/APNS
    inbound path; signature verification under any pinned
    publisher key; clock-skew rejection at ±5 minutes.
  - `HedgeInterval = 4 * time.Second` (locked v1).
  - `DefaultPriority` excludes `push` (opt-in).
- **`core/transports/snowflake/`** — new package.
  - `FamilyID = "snowflake"`.
  - `Handler.Dial` races rendezvous → WebRTC dialer →
    `recordWinner` callback. The upstream
    `snowflake/client` integration is wired through a
    `WebRTCDialer` callback so this package is testable
    without WebRTC; `-tags no_snowflake` builds pass nil
    and `Dial` returns `ErrFamilyHandlerUnavailable`.
- **Routestore widening** (2 new columns).
  - `rendezvous_priority_json` (default `'[]'`).
  - `last_winning_rendezvous_channel` (default `''`).
  - `UpsertRoute` carries the priority field BUT does NOT
    clobber the engine-recorded winner (bundle re-imports
    preserve user-accumulated history).
  - New method `RecordRendezvousWinner(routeID, channelID)`.
- **Netmem widening.**
  - `Snapshot.LastWinningRendezvousChannel` field.
  - `Empty()` updated.
  - New methods `RecordWinningRendezvousChannel` /
    `LookupWinningRendezvousChannel`.
- **ABI.**
  - **2 new release symbols** (cshared + gomobile).
    `engine_set_rendezvous_priority` (43),
    `engine_set_push_rendezvous_enabled` (44).
  - **2 gomobile-only symbols** (NEVER cshared).
    `EngineSetPushDeviceToken`, `EngineDeliverPushPayload`.
  - Diagnostics widen additively with
    `rendezvous_priority`, `rendezvous_channel`,
    `push_rendezvous_enabled`,
    `last_winning_rendezvous_channel`.
  - Vault-profile rejection of push opt-in (-2). The vault
    profile must never call FCM/APNS at all because the
    device tokens would tie the user to platform back-ends
    that are not in the threat model.
  - Init daaltes the per-engine 3B state from secrets KV;
    rendezvous priority + push opt-in survive session
    epochs (user preferences).

### Bundle format

- `manifest.routes[].rendezvous_priority` — JSON array of
  channel IDs from the v1 closed list. Empty / absent =
  use engine default. Unknown entries reject the bundle
  (`ErrInvalidRendezvousChannel`).
- `manifest.rendezvous_hints[]` — top-level signed offline
  hints. Each entry is `{payload, signature}` where the
  publisher's signing key covers the canonical payload.
  The bundle parser verifies every entry; any failure
  rejects (`ErrRendezvousHintBadSignature`,
  `ErrRendezvousHintMalformed`).

### Publisher tooling

- `daal-publish snowflake-rendezvous-hint` subcommand.
  Produces a signed offline-hint envelope from
  `--bridge`, `--fingerprint`, `--validity`, `--out`,
  `--key`. Stamps a NotAfter (default 30d), signs the
  canonical payload with the publisher's ed25519 key,
  emits the `bundle.RendezvousHint` JSON ready to splice
  into `manifest.rendezvous_hints[]`.

### Soak

- 3 new scenarios:
  - `snowflake-rendezvous-fallback.json`
  - `snowflake-broker-burn.json`
  - `push-rendezvous-opt-in.json`
- `--scenarios v2-superset` whitelist widens 14 → **17**.
- Soak driver client adds `SetRendezvousPriority`,
  `SetPushRendezvousEnabled`, `SoakSimulatePushPayload`,
  `SoakBurnRendezvousChannel`.
- `runEngineActions` dispatches the 4 new action names.

### Specs

- **New:** `specs/rendezvous-channels-v1.md`,
  `specs/snowflake-route-v1.md`,
  `specs/push-rendezvous-v1.md`.
- **Amended:** `specs/sbp-v1.md`,
  `specs/transport-families-v1.md`,
  `specs/publisher-cli-v1.md`,
  `specs/engine-abi-v1.md`,
  `specs/route-object-v1.md`,
  `specs/routestore-v1.md`,
  `specs/network-memory-v1.md`,
  `specs/failure-taxonomy-v1.md`.

## Locked decisions held through 3B

1. Snowflake vendored unconditionally; `-tags no_snowflake`
   build excluder reserved.
2. Push rendezvous: engine-only at 3B (UI in client
   phases).
3. Channel provenance: persist winning channel
   per-route AND per-network.
4. ABI append-only; 2 new release symbols; 0 removed; 0
   renamed.
5. Per-network channel memory: yes
   (`Snapshot.LastWinningRendezvousChannel`).
6. Hedged selection: priority[0] at t=0; rest at t=4s; 4s
   is the locked v1 interval; the netmem hint biases t=0
   over priority[0].
7. Push: full FCM/APNS code path at the gomobile boundary;
   project NEVER operates a token registry; partner-
   operated registries reach the engine through the active
   tunnel only.
8. Closed channel taxonomy (5); a 6th value is a roadmap
   decision.
9. Push opt-in vault-rejected; `SetPushRendezvousEnabled`
   returns -2 in the vault profile.
10. Per-engine override, NOT per-network (cross-product is
    a fingerprint surface).
11. `ErrChannelDisabled` is a non-failure skip — does NOT
    count toward all-fail.
12. `UpsertRoute` MUST NOT clobber
    `last_winning_rendezvous_channel`; only
    `RecordRendezvousWinner` updates it.

## Test surfaces

| Package                          | New tests | Status |
|----------------------------------|-----------|--------|
| `core/rendezvous`                | 18        | green  |
| `core/transports/snowflake`      | 5         | green  |
| `core/routestore`                | +1 (3B)   | green  |
| `core/netmem`                    | +1 (3B)   | green  |
| `core/abi` rendezvous + push     | 15        | green  |
| `bundle/go/bundle` (3B)          | 6         | green  |
| `bundle/go/publisher` (3B)       | 5         | green  |
| Soak driver                      | builds    | green  |

`core/...` full suite: green. Bundle module: green.
Soak-driver: green.

## Known follow-ups (3B-Soak / 3-Soak)

- Wire `route:[].RendezvousPriority` from the bundle
  importer through the trust adapter into the routestore.
  Currently only the bundle parser validates the field;
  end-to-end engine activation lands when the snowflake
  family handler is wired into the path manager (3-Soak).
- Add a `publisher_pub:<fp>` index in the routestore so
  `EngineDeliverPushPayload` can resolve the pinned
  pubkey by fingerprint without iterating publishers.
  Today the resolver consults that key and returns
  `(nil,false)` if absent, which is the safe default
  (push payloads from unknown publishers are rejected
  with -5).
- Per-channel cooldown ledger (3-Soak; deferred from 3B).
- 4-second hedge interval tuning with OONI / Censored
  Planet data (3-Soak).
- Auto-promotion threshold tuning for snowflake routes
  (3-Soak).
- Burn-classifier real-DPI mode (partner-lab; orthogonal).

## Carry-overs to V4

- Sixth rendezvous channel — closed at v1; a 6th entry is
  V4.
- WASM-loaded channels — 3E (placeholder).
- App-store-search rendezvous discovery — V4.

## Handover to 3C

3C receives:

- The closed family taxonomy from 3A AND the closed
  rendezvous channel taxonomy from 3B.
- The Snowflake working pattern (Solicitor callback +
  hedged selector + per-route + per-network winning-channel
  persistence) as a reference for adding WebRTC-style
  transports — 3D and 3E will reuse it.
- The hedged-Race + cooldown ledger seam for MASQUE's
  multi-CDN ladder (3C does NOT use rendezvous; MASQUE is
  a single-family ladder — but the priority + per-network
  memory pattern translates).
- ABI release surface = 44; append-only.
- Engine version `daal-core 0.7.1+v3-transport`.

## Files added/modified at 3B

```
specs/rendezvous-channels-v1.md         NEW
specs/snowflake-route-v1.md             NEW
specs/push-rendezvous-v1.md             NEW
specs/{sbp, transport-families, publisher-cli, engine-abi,
       route-object, routestore, network-memory,
       failure-taxonomy}-v1.md          AMENDED

core/rendezvous/channels.go             NEW
core/rendezvous/impls.go                NEW
core/rendezvous/push.go                 NEW
core/rendezvous/selector_test.go        NEW (10 tests)
core/rendezvous/push_test.go            NEW  (8 tests)

core/transports/snowflake/snowflake.go  NEW
core/transports/snowflake/snowflake_test.go NEW (5 tests)

core/routestore/schema.go               +2 ALTERs
core/routestore/store.go                widened
core/routestore/store_test.go           +TestUpsertRoute_3BFieldsRoundTrip

core/netmem/snapshot.go                 widened
core/netmem/store.go                    +Record/LookupWinningRendezvousChannel
core/netmem/store_test.go               +TestRecordWinningRendezvousChannel

core/abi/abi.go                         widened (Core fields, Init daalte, diagnostics)
core/abi/rendezvous.go                  NEW (Set/Get + RecordRendezvousWinner)
core/abi/rendezvous_export.go           NEW (cshared symbols 43+44)
core/abi/rendezvous_gomobile.go         NEW (gomobile facades + EngineDeliverPushPayload)
core/abi/rendezvous_test.go             NEW (15 tests)
core/abi/refresh_test.go                version-string regression updated to 0.7.1

bundle/go/bundle/types.go               +RendezvousHint, +RendezvousPriority
bundle/go/bundle/sbp.go                 +validate3B + verifyRendezvousHints
bundle/go/bundle/errors.go              +3 errors
bundle/go/bundle/v3b_test.go            NEW (6 tests)

bundle/go/publisher/snowflake_hint.go        NEW
bundle/go/publisher/snowflake_hint_test.go   NEW (5 tests)
bundle/go/cmd/daal-publish/main.go          +snowflake-rendezvous-hint subcommand

test-rigs/distribution-failure/scenarios/snowflake-rendezvous-fallback.json NEW
test-rigs/distribution-failure/scenarios/snowflake-broker-burn.json         NEW
test-rigs/distribution-failure/scenarios/push-rendezvous-opt-in.json        NEW
test-rigs/distribution-failure/soak-driver/internal/client/client.go        +4 methods
test-rigs/distribution-failure/soak-driver/internal/soak/soak.go            +4 cases
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go          v2-superset 14→17
```
