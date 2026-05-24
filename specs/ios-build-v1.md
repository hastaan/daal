# iOS Build V1 — Network Extension + Shared App Group

**Status:** Locked at Phase 2E.

**Implementation:** `client-ios/`.

**Related:** `engine-abi-v1.md`, `key-vault-v1.md`,
`lifeline-mode-v1.md`, `wireguard-subengine-v1.md`,
`network-memory-v1.md`.

## Goal

Land a TestFlight-capable iOS build that consumes the same engine
binary the desktop and Android shipped through 2A–2G. Reach feature
parity for V2 (route budgets, mode budgets, posture FSM,
per-network memory, lifeline-strict, auto-promotion) inside the
Network Extension's strict memory ceiling.

Phase 2E adds **one** release ABI symbol — `engine_lifecycle_event`
— and **does not** bump the engine version (still
`daal-core 0.6.0+v2-soak`). 2E is platform integration, not
engine work.

## Targets

* `DaalApp` — main app target, SwiftUI, runs the host-side
  configuration view and (critically) the Argon2id PIN-vault
  unlock.
* `DaalTunnel` — `NEPacketTunnelProvider` extension target, hosts
  the engine, packet flow, WireGuard sub-engine, and memory
  sampler.

Both targets call `abi.Init(stateDir, ...)` against the **same**
App Group container path. Mode, network-memory, lifeline-strict
state, and the auto-promotion preference round-trip via the
shared SQLite database — there is no XPC IPC layer.

## Engine packaging

```sh
gomobile bind \
    -target=ios -iosversion=15.0 -tags ios \
    -ldflags='-s -w' \
    -o client-ios/Libbox.xcframework \
    ./core/abi
```

* `-tags ios` excludes desktop-only paths (tun-helper, AppImage
  logger).
* `-ldflags='-s -w'` strips debug info; the xcframework is tens
  of MiB before strip and a few MiB after.
* Reproducibility is gated on the toolchain pin in
  `.tool-versions`.

Linker pruning checklist: GeoIP / GeoSite tables already absent
from the engine; verify the per-arch xcframework slice lands
≤30 MiB. Above 30 MiB, audit dead-stripped symbols and file an
issue — do NOT hide bloat behind extra build tags.

## Memory budget

The NE process has a documented **~50 MiB** ceiling on older
iPhones. The engine targets this envelope by:

1. Excluding GeoIP / GeoSite tables (already absent).
2. Running Argon2id PIN-vault unlock in the **host app**, not
   the extension. See "PIN unlock" below.
3. Splitting WireGuard out to a `boringtun`-backed
   sub-engine when a 1 Hz memory sampler observes a 38 MiB
   crossing. See `wireguard-subengine-v1.md`.

## App Group container

```
group.org.daal-project.shared/
  state/
    daal.db                 # routestore SQLite
    .age_identity.vault      # sealed identity (vault profile)
    .use_vault               # empty marker; presence selects vault
    secrets_kv               # 2D secrets KV
    network_memory.db        # 2C per-network memory
  logs/                      # off by default; user opt-in
```

All files in `state/` are created with the iOS Data Protection
class **`NSFileProtectionCompleteUntilFirstUserAuthentication`**.
This protects the unsealed identity at rest (the device must be
unlocked at least once after boot for the data to be readable).

## PIN unlock

Argon2id v1 has a **64 MiB** memory peak. The NE has a ~50 MiB
ceiling. Resolution: **the host app runs unlock**, the extension
does not.

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
RESULT of unlock does. The unsealed identity persists in the
secrets KV under file protection
`NSFileProtectionCompleteUntilFirstUserAuthentication`; on the
next launch after a reboot the user re-unlocks before the
extension can start the tunnel.

This is documented in `key-vault-v1.md` under "Phase 2E carry-over".

## Lifecycle events

Phase 2E adds `engine_lifecycle_event(token)` to the release ABI.
The Swift bridge calls this once per Network-Extension state
transition. Locked v1 token set:

| Token                       | When                                            | Engine action |
|-----------------------------|-------------------------------------------------|---------------|
| `will_sleep`                | NE process is being suspended                   | Records event for diagnostics. Does NOT bump session epoch. |
| `did_wake`                  | NE process resumed                              | Records event. Does NOT reset cooldown counters. The bridge follows up with `engine_network_changed` if the network actually changed. |
| `memory_pressure_warning`   | NE approaching the memory ceiling               | Records event. The Swift bridge owns the WG sub-engine handoff; the engine takes no action by itself. |

Tokens outside this set are rejected with `-1` from the cshared
ABI; the gomobile facade returns `EngineBridgeError.unknownLifecycleEvent`.

`engine_export_diagnostics` widens additively at 2E:

* `last_lifecycle_event` — the most recent token, or absent.
* `last_lifecycle_at` — RFC3339 timestamp; absent if no event has
  fired in this engine session.

Both fields are absent on Linux / Android / desktop builds (no
caller invokes the symbol on those platforms). Non-iOS soak
parity is unaffected.

## Network detection privacy floor

iOS withholds SSIDs from apps without a hard-to-get entitlement
(approved on a case-by-case basis by Apple). The Swift bridge
calls `engine_network_changed("wifi", "", "")` on Wi-Fi
transitions — empty carrier, empty SSID. The 2C SHA-256 hash
function buckets all `wifi||` identifiers together for that
device.

This is a **deliberate degradation**. The privacy floor on iOS
is intentionally lower-resolution than on Android / desktop. A
user who roams between four Wi-Fi networks during the day has
ONE per-network memory bucket on iOS, not four. The trade-off
is that the project does NOT request the Apple-gated SSID
entitlement; the entitlement is hard to renew under sanctions
pressure and adds a clear "this app reads SSIDs" line to App
Store reviews.

## Auto-promotion preference round-trip

Phase 2G's `engine_set_auto_promotion(enabled)` is exposed via a
SwiftUI `Toggle` mirrored over `UserDefaults` (key
`autoPromotionEnabled`). The engine is the source of truth; the
mirror is a UX-side optimisation so the toggle shows the right
state on fresh launch before the bridge has read diagnostics.

## Distribution

* **TestFlight continuous-reissue pipeline.** Apple infrastructure
  rebuilds and re-uploads at least every 60 days. At least two
  parallel TestFlight groups provisioned for shard-scaling beyond
  the 10 k cap.
* **App Store via foreign legal entity.** Identified at 2E ship
  time; documented in `client-ios/README.md`. Apple may
  region-restrict.
* **AltStore re-sign smoke.** Hard ship gate — re-sign through
  AltStore on at least one physical device, verify a 30 min smoke
  pass. On failure, file a documented waiver in the 2E handover
  and treat App Store / TestFlight as the sole release vector
  for that iOS version.
* **Personal Apple ID self-sign docs.** At
  `client-ios/docs/personal-apple-id-self-sign.{en,fa}.md`.

## Soak coverage

Phase 2E adds two scenarios to the v2-superset whitelist (10 → 12):

* `ios-extension-memory` — runs the soak engine subprocess with
  `GOMEMLIMIT=50MiB` (per-scenario `engine_env` in the rig). Asserts
  the same invariant ledger passes; surfaces the 2E
  `engine_lifecycle_event` codepath via three driven events.
* `ios-wireguard-handoff` — drives the soak-only WG memory gauge
  past 38 MiB on day 2, then stamps a one-way handoff. Asserts the
  diagnostics surface carries `wg_subengine_memory_kib` and
  `wg_subengine_handoff_at` after the forced handoff. The
  boringtun side is mocked as a Go shim for soak purposes; the
  real Rust archive is exercised only on Apple CI / partner-mac
  on-device.

The 2G load tier (`run-burn`, 1k×30d) is unchanged. iOS does NOT
participate in the load tier — per-process memory profile is
platform-specific and the 2G primary metric is engine-side.

## Out of scope

* iOS UI features beyond V2 parity — no widgets, no Shortcuts,
  no Siri intents.
* Watch / Vision companions.
* Device-to-device sync of network memory (V4).
* Refraction / Conjure (V3).
* Optional partner-operated lifeline relay (V3.7).
