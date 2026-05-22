# Phase 3F — One-Tap Delegate-Share — Handover

**Status**: SHIPPED.
**Date**: 2026-04-28.
**Engine version**: `daal-core 0.9.0+v3-share`.
**ABI release surface**: 47 → **48** (append-only).

## What shipped

A user-facing affordance to one-tap re-share an in-store route with a friend, gated by a publisher-declared closed-enum policy and a uint8 cap. The 1C share identity (already at `secrets_kv:share/identity:v1`) IS the delegate key; no new key derivation is introduced. The `.sbp.share` wire format embeds an append-only redistribution chain whose original publisher signature is preserved verbatim.

## Closed-enum surfaces (locked at v1)

| Surface | Values |
|----|----|
| `redistribution_policy` (per-route) | `none` / `delegated_n` / `transitive` (default `none`) |
| `Outcome` (`engine_redistribute_route`) | `ok` / `policy_refuses` / `cap_exhausted` / `chain_depth_exceeded` / `route_unknown` / `identity_unavailable` |
| `MaxChainDepth` | 5 |
| Cap range | uint8 (0..255); required when `delegated_n` |

## Files added

```
core/delegate/                                          NEW package
core/delegate/delegate.go                               (chain walker, EnforcePolicy, EnforceCap, AppendHop, VerifyChain)
core/delegate/delegate_excluded.go                      (-tags no_delegate_share twin)
core/delegate/delegate_test.go                          (12 tests)
core/delegate/delegate_excluded_test.go                 (2 tests)

core/abi/delegate.go                                    NEW (engine-side state, RedistributeRoute, diagnostics)
core/abi/delegate_export.go                             NEW (cshared engine_redistribute_route)
core/abi/delegate_gomobile.go                           NEW (gomobile wrapper)
core/abi/delegate_compiled.go                           NEW (delegateShareCompiledIn = true)
core/abi/delegate_compiled_excluded.go                  NEW (delegateShareCompiledIn = false)
core/abi/delegate_test.go                               NEW (5 ABI tests)
core/abi/delegate_excluded_test.go                      NEW (excluded-tag parity test)
core/abi/delegate_soak.go                               NEW (SoakSeedDelegateRoute helper)

bundle/go/bundle/v3f_test.go                            NEW (8 wire-format tests)

specs/delegate-keys-v1.md                               NEW
specs/ui-share-with-a-friend-v1.md                      NEW

test-rigs/distribution-failure/scenarios/
  delegate-share-cap.json                               NEW
  delegate-share-policy-respected.json                  NEW
  delegate-share-chain-depth-5.json                     NEW

phases of development/25-phase-3f-one-tap-share.md      REPLACED (full locked spec)
phases of development/25-phase-3f-one-tap-share.handover.md  NEW (this doc)
```

## Files modified

```
core/abi/abi.go                          (Version → 0.9.0+v3-share; +3 diagnostics fields; resetDelegateStateForShutdown)
core/abi/share.go                        (forward RedistributionPolicy/Cap from RouteRow into ExportInput)
core/abi/wasm_test.go                    (rename TestEngineVersion_3EBump → TestEngineVersion_3FBump)
core/abi/refraction_test.go              (version pin → 0.9.0+v3-share)
core/abi/refresh_test.go                 (version pin → 0.9.0+v3-share)
core/abi/rendezvous_test.go              (version-substring pin → 0.9.0+v3-share)
core/routestore/schema.go                (1 ALTER: redistribution_policy TEXT)
core/routestore/store.go                 (RouteRow widening; Encode/DecodeRedistributionPolicy)
core/routestore/store_test.go            (TestUpsertRoute_3FFieldsRoundTrip + TestEncodeDecodeRedistributionPolicy)

bundle/go/bundle/types.go                (RouteManifestEntry + Manifest widening; RedistributionChainHop + DelegateCapEntry)
bundle/go/bundle/errors.go               (+6 errors)
bundle/go/bundle/sbp.go                  (+validate3FRouteFields, +validate3FManifestFields)
bundle/go/share/export.go                (ExportInput widening; BuildShareBundleDelegated)
bundle/go/publisher/bundle_cmd.go        (BundleOptions widening; applyRedistributionPolicy)
bundle/go/publisher/bundle_cmd_test.go   (+2 3F tests)
bundle/go/cmd/daal-publish/main.go      (--redistribution-policy, --delegate-cap flags)

cmd/daal-soak-engine/main.go            (+soak-seed-delegate-route, +soak-redistribute-route handlers)

test-rigs/distribution-failure/soak-driver/internal/client/client.go
                                         (SoakSeedDelegateRoute, SoakRedistributeRoute methods)
test-rigs/distribution-failure/soak-driver/internal/soak/soak.go
                                         (action dispatchers)
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go
                                         (v2-superset 23 → 26 with the 3 new scenarios)

specs/sbp-v1.md                          (Phase 3F widening section)
specs/share-bundle-v1.md                 (Phase 3F delegate-share variant section)
specs/route-object-v1.md                 (Phase 3F redistribution policy/cap)
specs/engine-abi-v1.md                   (Phase 3F additions, +1 release symbol)
specs/publisher-cli-v1.md                (Phase 3F bundle flags)
specs/routestore-v1.md                   (Phase 3F policy column + counter namespace)
specs/blackout-soak-rig-v1.md            (Phase 3F: 3 new scenarios + 2 RPC actions)
```

## Build matrix at 3F exit

| Command | Result |
|---|---|
| `cd core && go build ./...` | green |
| `cd core && go build -tags no_delegate_share ./abi/...` | green |
| `cd core && go build -tags "no_psiphon no_wasm no_delegate_share" ./abi/...` | green |
| `cd core && go test ./...` | green (all packages) |
| `cd bundle/go && go build ./... && go test ./...` | green |
| `cd cmd/daal-soak-engine && go build -tags soak ./...` | green |
| `cd test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...` | green |
| `nm /tmp/libdaalcore.so \| grep ' T engine_' \| wc -l` | **48** (locked target) |

## Key invariants preserved

- ABI append-only: 47 → 48; the existing 47 release symbols are unchanged.
- 1C share identity reused verbatim; NO new key derivation.
- Original publisher signature on every `.sbp` is preserved verbatim; delegate signatures only ever append.
- UpsertRoute non-clobber: `secrets_kv:delegate_share_counter:*` is NEVER touched by a route re-import.
- Soft-validation discipline preserved: bundle parser surfaces 6 closed-enum errors, never silently mutates.
- Position B preserved: no new telemetry; `delegate_share_counters` is local-only.
- V0 failure category set unchanged.

## Next phase

Phase 3F closes the V3 transport-shipped-without-app-update milestone (started at 3E). The next phase per the roadmap is the V3 soak (3-Soak) which exercises the v2-superset of 26 scenarios on the in-engine scheduler.

End — locked at 3F.
