# Phase 1.5A — Reliability Hardening

## Status

Active. The umbrella `08-phase-1-5-reliability-and-desktop.md` is now the
parent document; this file plus `09-phase-1-5b-desktop-port.md` and
`10-phase-1-5c-blackout-soak.md` are the three concrete sub-phases.

## Scope

| Roadmap item | In 1.5A? |
|---|---|
| V1.5.1 — subscription refresh through tunnel + atomic profile cache | ✅ |
| V1.5.2 — revocation list refresh + key-rotation UX                   | ✅ |
| V1.5.3 — diagnostics expansion ("Why this route?")                   | ✅ |
| V1.5.4 — Tauri 2 desktop port                                        | ❌ → 1.5B |
| V1.5.5 — pointer rotation operations                                 | ✅ |
| V1.5.6 — 30-day blackout simulation                                  | ❌ → 1.5C |

## Decisions

1. **Three-way split.** 1.5A = engineering hardening; 1.5B = desktop;
   1.5C = soak rig + 7-day + 30-day runs.
2. **Subscriptions = first-class objects.** New `subscriptions` table
   in routestore; URL age-encrypted in `secrets_kv:subscription-url:*`;
   refresh through the active tunnel via the same primitive Phase 1D's
   bootstrap fetcher uses; parsed body wrapped in a synthetic .sbp
   signed by the device delegate key from `share/identity:v1`.
3. **Per-publisher revocation.** `publisher.revocation_url` lives in v2
   manifests; client refreshes each publisher's own list through the
   tunnel every 6h.
4. **Pointer rotation** ships as a project-root-signed envelope
   alongside the directory bundle; persisted under
   `secrets_kv:bootstrap-pointers:v1`; overlays embedded set on the
   next launch when newer.
5. **Forward-incompat manifest bump:** `spec_version` 1 → 2. Phase 1B/
   1C/1D clients see v2 as `bundle_corrupted`. The publisher CLI emits
   v2 by default; `--legacy-v1` keeps v1 production for the transition.
6. **No soak runs in 1.5A.** Engineering completeness is validated by
   unit tests; sustained-load validation lands in 1.5C.

## Engine version

`engine_version` returns **`daal-core 0.4.0+reliability`**.

## ABI surface

26 (Phase 1D) → **32** (Phase 1.5A). Six new functions, all
append-only. Signatures and JSON shape are documented in
`specs/engine-abi-v1.md` (Phase 1.5A section).

## New code

- `core/refresh/{doc,parse,synthetic,subscription,revocation,audit}.go`
  + tests
- `core/bootstrap/pointer_rotation.go` + test
- `core/bootstrap/fetcher.go` — extracted `FetchRaw` (body-only)
- `core/pathmanager/explain.go` + test
- `core/routestore/subscriptions.go` (new tables + accessors)
- `core/abi/refresh.go` + cshared/gomobile + test
- `bundle/go/publisher/revocation.go`
- `bundle/go/bundle/v2_test.go`
- `cmd/daal-core/main.go` — 6 new subcommands
- `client-android/app/src/main/.../ui/SubscriptionsScreen.kt`,
  `KeyRotationCard.kt`, `WhyThisRouteScreen.kt`
- `client-android/app/src/main/.../vm/DaalViewModel.kt` — extended
  state and load functions
- `client-android/app/src/main/.../data/DaalCoreBridge.kt` — 7 new
  delegating methods
- EN + FA strings.

## New + amended specs

- New: `subscription-v1.md`, `revocation-v1.md`,
  `key-rotation-ux-v1.md`, `pointer-rotation-v1.md`,
  `diagnostics-explain-v1.md`.
- Amended: `sbp-v1.md` (`spec_version: 2`), `engine-abi-v1.md`
  (Phase 1.5A surface), `routestore-v1.md` (3 tables + 3 columns),
  `publisher-keys-v1.md` (revocation_url).

## Tests

`go test ./...` from `/home/daal/core` and `/home/daal/bundle/go` is
green. The OPSEC source-grep `TestNoNetHTTPInRefresh` enforces that
`core/refresh` does not import `net/http`, never directly logs URLs,
and never calls `log.Printf` / `fmt.Println`.

## Out of scope

- Tauri 2 desktop. Lands in **1.5B**.
- 7-day and 30-day soak runs. Land in **1.5C**.
- TunnelDialer wired to the engine's local SOCKS5. Phase 1.5A's
  Refresher accepts a `Dialer` and treats the active-tunnel/direct
  decision as injectable, but the wiring is `NewDirectDialer` only.
  The tunnel-side wiring lands when sing-box is enabled in 1.5B.
- Subscription auto-refresh scheduler. Refresh is operator-driven
  (CLI/UI). The `profile_update_min` column is recorded for V2 use.
