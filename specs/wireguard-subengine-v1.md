# WireGuard Sub-Engine V1 — Cloudflare-WARP Memory Pattern

**Status:** Locked at Phase 2E.

**Implementation:** `client-ios/DaalTunnel/Sources/`
(`WireguardSubEngine.swift`, `WireguardLibboxImpl.swift`,
`WireguardBoringtunImpl.swift`, `MemorySampler.swift`).

**Related:** `ios-build-v1.md`, `engine-abi-v1.md`,
`route-budgets-v1.md`.

## Threat / constraint model

The iOS Network Extension process has a documented **~50 MiB**
memory ceiling on older iPhones. sing-box's in-Go WireGuard
implementation has been observed pushing the resident-set size
past that under load (the engine state + crypto buffers + the WG
outbound itself). When this happens, iOS terminates the
extension; the user's tunnel drops.

This spec locks the Cloudflare-WARP pattern: split WireGuard out
to a `boringtun`-backed alternative implementation (Rust,
~1.5 MiB) that the bridge swaps in when a 1 Hz memory sampler
observes a watermark crossing.

## Locked constants

| Constant         | Value           | Rationale |
|------------------|-----------------|-----------|
| Watermark        | 38 MiB          | Margin of 12 MiB under the 50 MiB ceiling so the swap itself has room to run. |
| Sampling rate    | 1 Hz            | Below the OS's typical foreground-process sampling cadence. |
| Handoff downtime | <200 ms         | One Mach scheduler slice; no perceptible UX impact. |
| Direction        | One-way         | After handoff the session stays on `boringtun` until disconnect. Avoids hysteresis flapping near the watermark. |
| boringtun pin    | **v0.6.0**      | cloudflare/boringtun, MIT-licensed. Documented as `Vendored/boringtun/COMMIT`. |

## Selection algorithm

```
1. NE bridge starts the route on WireguardLibboxImpl (default).
2. MemorySampler reads task_info(TASK_VM_INFO).phys_footprint at
   1 Hz.
3. On the first crossing of the 38 MiB watermark in a session:
     a. Log the crossing to RingLogger.
     b. Fire engine_lifecycle_event("memory_pressure_warning")
        so diagnostics records the cause.
     c. Pause the active route.
     d. Tear down the Libbox WG outbound.
     e. Instantiate WireguardBoringtunImpl with the same key
        material from the App Group secrets KV.
     f. Resume packet flow.
4. Subsequent watermark crossings in the same session are no-ops
   (handoff is one-way; we are already on boringtun).
5. On disconnect, both impls are torn down; the next session
   starts fresh on WireguardLibboxImpl.
```

## API

```swift
public protocol WireguardSubEngine: AnyObject {
    func requestHandoff()
}

public final class WireguardLibboxImpl: WireguardSubEngine { ... }
public final class WireguardBoringtunImpl: WireguardSubEngine { ... }
```

`WireguardLibboxImpl.requestHandoff()` flips an internal
`handedOff` flag the FIRST time it is called; subsequent calls
are no-ops. The bridge owns the actual swap by replacing the
`wgSubEngine` reference with a fresh `WireguardBoringtunImpl`.

## Build pin

```sh
git clone https://github.com/cloudflare/boringtun
cd boringtun && git checkout v0.6.0
cargo lipo --release --package boringtun
cp target/universal/release/libboringtun.a \
   ../client-ios/Vendored/boringtun/libboringtun.a
cp boringtun/src/ffi/wireguard_ffi.h \
   ../client-ios/Vendored/boringtun/boringtun.h
```

The vendored archive is recorded with its SHA-256 in
`client-ios/Vendored/boringtun/SHA256SUMS` so a third party can
reproduce the build from upstream sources.

## Soak coverage

`ios-wireguard-handoff` (see `ios-build-v1.md`) drives the
soak-only knobs `engine_soak_set_wg_memory_kib` and
`engine_soak_force_wg_handoff` to model the watermark crossing
without an actual iOS device. The diagnostics surface gains two
soak-only fields, `wg_subengine_memory_kib` and
`wg_subengine_handoff_at`, that the rig asserts after the forced
handoff. The boringtun side is mocked as a Go shim for soak
purposes; the real Rust archive is exercised only on Apple CI /
partner-mac on-device.

## Developer / audit builds

Builds without the vendored `libboringtun.a` (e.g. an audit
reproducibility build that excludes the Rust dependency) will
fail to link `WireguardBoringtunImpl`. That is the intended
signal: a build labelled "no Rust dependencies" must not silently
fall back to a no-op handoff. The watermark check still runs;
crossings are logged but no handoff happens.

## v2 considerations (not implemented)

* Hysteretic two-way swap (`boringtun` ↔ `Libbox`) when memory
  drops below a low watermark. Held for V3 measurement evidence
  that hysteresis is worth the complexity.
* Memory-pressure-driven graceful tunnel teardown if BOTH impls
  exceed budget. Held for V3.
* Per-route sub-engine selection (some WG routes prefer Libbox
  for protocol reasons). Held for V3.
