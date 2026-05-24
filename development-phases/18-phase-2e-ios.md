# Phase 2E — iOS Bring-Up

## Roadmap Coverage

V2.5 ("iOS — `NEPacketTunnelProvider`, `Libbox.xcframework`,
TestFlight or AltStore re-sign"). Closes the V2 plan with the only
remaining shipping platform.

## Goal

Ship a TestFlight-capable iOS build that reuses the same engine
binary the desktop and Android shipped through 2A–2D. Reach feature
parity for V2 (route budgets, mode budgets, FSM, per-network memory,
lifeline-strict) inside the Network Extension's strict memory ceiling.

## Scope

- **Network Extension**: full `NEPacketTunnelProvider` subclass that
  hosts a static `Libbox.xcframework`. The extension reads packets
  from the OS, hands them to the engine via Libbox, receives the
  response packets, and writes them back.
- **Engine packaging**: `gomobile bind -target=ios -tags ios ./abi`
  produces `Libbox.xcframework`. Linker pruning is critical — the
  extension's memory ceiling is ~50 MB on older iPhones; we strip
  GeoIP / GeoSite tables (already not loaded by the engine) and
  ensure no unused gomobile facades carry weight.
- **WireGuard sub-engine fallback (Cloudflare WARP playbook).** If
  the NE process exceeds the ~50 MB ceiling under load (most
  commonly with WireGuard's in-process Go implementation
  competing for memory with sing-box), split WireGuard out to
  `boringtun` (Rust, ~1.5 MB) and load it conditionally. The
  selection is done at WireGuard route activation: when the
  active route's transport family is `wireguard` and the NE
  resident-set size is observed to climb past a watermark, the
  Swift bridge tears down the in-Libbox WireGuard outbound and
  hands off to a `boringtun`-backed alternative implementation
  exposed through the same `EngineBridge` API. The user does not
  see the swap. This is the documented Cloudflare-WARP pattern
  the roadmap explicitly cites.
- **App ↔ Extension IPC**: `NEVPNManager` group container holds a
  shared SQLite handle the engine uses for `secrets_kv`. Mode and
  network-memory state is identical between the host app and the
  extension.
- **AltStore re-sign**: documented procedure with a release blocker
  attached. Iranian users frequently sideload via AltStore /
  Sideloadly because the App Store is geofenced; the AltStore re-
  signed bundle MUST work, or a documented waiver MUST be filed
  before ship.
- **TestFlight as a continuous re-issue pipeline (V2.6 explicit
  deliverable).** TestFlight has a 10k user cap and a 90-day
  build-expiry window. The pipeline is designed for continuous
  rebuild + re-upload so an existing tester base never
  experiences a single-build expiry cliff. Concretely:
  - A new build is produced, signed, and uploaded **at least
    every 60 days** (well inside the 90-day window).
  - The pipeline supports **at least two parallel TestFlight
    "groups"** so the tester ceiling can scale beyond 10k by
    sharding across groups (Apple's per-group caps stack).
  - The pipeline runs on Apple infrastructure (partner CI or a
    macOS build machine); the project's primary CI does NOT
    require macOS, so the pipeline is documented as an
    operational dependency rather than a CI dependency.
- **App Store via foreign legal entity.** Per V2.6: "App Store
  via foreign legal entity (foundation, NGO, partner). Apple may
  region-restrict; assume so." The legal entity is identified at
  V2 ship time; documented in `client-ios/README.md` along with
  the foreign-IBAN payment story.
- **Personal Apple ID self-signing docs (V2.6 explicit
  deliverable).** A docs-only deliverable: written instructions
  in `client-ios/docs/personal-apple-id-self-sign.md` covering
  the 7-day re-sign flow that activists with technical comfort
  can run themselves. The roadmap is honest about the trade-off:
  "fine for activists, miserable for general public." No
  engineering dependency on Apple infra; the doc ships
  independently of any TestFlight or App Store release.
- **Spec**: new `specs/ios-build-v1.md`; amend
  `specs/engine-abi-v1.md` to document the `gomobile bind ios`
  artifact.
- **No new release ABI surface**. Surface stays at **37**.

## Out of scope (deferred)

- **iOS UI features beyond V2 parity** — no widgets, no Shortcuts
  integration, no Siri intents.
- **Watch / Vision** companions.
- **Device-to-device sync** of network memory (V4).

## Implementation Details

### Repo layout

```
client-ios/
  DaalApp/
    DaalApp.xcodeproj
    Sources/
      App.swift
      ContentView.swift
      ModePicker.swift
      RouteBudgetTable.swift
      LifelineOnlyBanner.swift
      ConfigurationStore.swift  // shared SQLite via App Group
    Resources/
      en.lproj/Localizable.strings
      fa.lproj/Localizable.strings
  DaalTunnel/                  // Network Extension target
    Sources/
      PacketTunnelProvider.swift
      EngineBridge.swift        // wraps Libbox.xcframework
      Logger.swift              // ring-buffer; never to disk by default
    Info.plist                  // NetworkExtension key
  Libbox.xcframework            // built by gomobile, vendored
  Configuration/
    Daal.entitlements          // App Group identifier, network-extension capability
  README.md
```

The maintainer who lacks macOS commits the Swift sources but the
Xcode build runs on Apple infrastructure. The repo's CI does not
build the iOS targets.

### Engine packaging

```
gomobile bind \
    -target=ios \
    -iosversion=15.0 \
    -tags ios \
    -ldflags='-s -w' \
    -o client-ios/Libbox.xcframework \
    ./core/abi
```

`-tags ios` excludes desktop-only paths (the tun-helper, AppImage
log line, etc). The `-ldflags='-s -w'` strips debug info; the
xcframework is tens of MB before strip and a few MB after.

### WireGuard sub-engine fallback (boringtun)

```
client-ios/DaalTunnel/Sources/
  WireguardSubEngine.swift     // protocol; both impls conform
  WireguardLibboxImpl.swift    // default — uses sing-box's Go-based WireGuard
  WireguardBoringtunImpl.swift // FFI shim over libboringtun.a
client-ios/Vendored/boringtun/
  libboringtun.a               // built from cloudflare/boringtun via cargo lipo
  boringtun.h                  // C-callable surface
```

The sub-engine selection algorithm:

1. NE bridge starts the route on the default `WireguardLibboxImpl`.
2. A 1-Hz memory sampler reads
   `task_info(mach_task_self(), TASK_VM_INFO, ...)` and tracks the
   `phys_footprint` field. A watermark of **38 MiB** triggers the
   handoff (well below the documented ~50 MiB ceiling so we have
   margin for the swap itself).
3. On crossing the watermark the bridge pauses the active route,
   tears down the Libbox WireGuard outbound, instantiates
   `WireguardBoringtunImpl` with the same key material from the
   shared SQLite handle, and resumes packet flow. The total
   downtime budget is **<200 ms** (one Mach-tier scheduling
   slice).
4. The handoff is one-way per session; once we are on
   `boringtun` we stay there until the user disconnects. This
   avoids hysteresis flapping near the watermark.
5. If the engine packaging is built without the boringtun
   vendored archive (a developer build, or a build flag for
   audit reproducibility), the watermark check still runs but
   merely logs the breach to the in-memory ring buffer; no
   handoff happens.

This is what the roadmap V2.6 calls out: *"If the NE process
exceeds the ~50 MB ceiling under load, split WireGuard out to
boringtun (Rust, ~1.5 MB) and load it conditionally. This is the
Cloudflare WARP playbook."*

### Mode parity

The Swift app calls into Libbox to set mode, read diagnostics, and
trigger `engine_network_changed`. The same four modes ship on iOS:
lifeline, normal, bulk, lifeline-strict. Persian + English copy is in
the standard `.lproj` bundles.

### Network detection

iOS does not expose SSIDs to apps without specific entitlements
(approved on a case-by-case basis by Apple). The engine accepts
`network_kind="wifi", carrier="", ssid=""` from iOS, which under
2C's hash function buckets all Wi-Fi networks together for that
device. This is a **deliberate degradation**: the privacy floor on
iOS is intentionally lower-resolution than on Android / desktop.
Documented in `specs/ios-build-v1.md`.

### AltStore re-sign

```
1. Build .ipa locally / on partner CI.
2. Submit to AltStore developer portal for re-sign.
3. Install via AltStore on a test device.
4. Verify the engine boots, the tunnel comes up, and a 30-min
   smoke test passes the same X/Y/Z thresholds 2G ships.
5. If the re-sign breaks (e.g., entitlements stripped, App Group
   inaccessible), file a documented waiver in
   `phases of development/18-phase-2e-ios.handover.md` and treat
   the App Store TestFlight path as the sole release vector for
   that iOS version.
```

The smoke is mandatory. The re-sign waiver is a hard ship decision.

### Privacy invariants on iOS

- The Network Extension's logger writes only to a ring buffer in
  memory by default. A user-toggleable preference enables a
  rotating file log in the App Group container; off by default.
- The shared SQLite handle is age-encrypted using the same key the
  desktop uses (Keychain-stored on iOS).
- `engine_export_diagnostics` produces the same redacted output it
  produces on desktop; the iOS Share Sheet pipeline does not add
  any device identifiers.

## Testing Requirements

- Local: unit tests for `EngineBridge.swift` against a stub
  `LibboxFake` (no actual Go dependency, just a Swift impl of the
  same protocol).
- Apple CI: `xcodebuild build` for both targets succeeds. Linter
  (`swiftlint`) clean.
- Apple CI: `xcodebuild test` runs the bridge unit tests on the
  iOS Simulator.
- Manual on physical device: install via TestFlight; install via
  AltStore re-sign; run a 30-min smoke per re-sign target. Record
  a verdict in the handover.
- Soak: a NEW soak scenario `ios-extension-memory` simulates the
  iOS extension's memory ceiling by setting `GOMEMLIMIT=50MiB` on
  the soak-engine subprocess and asserts the soak passes the same
  invariant ledger. (This is a sanity check, not a substitute for
  on-device testing.)
- Soak: a NEW soak scenario `ios-wireguard-handoff` simulates the
  watermark crossing by enabling a debug knob in the engine that
  artificially inflates the WireGuard outbound's memory residency
  past 38 MiB after 60 simulated seconds of traffic. The scenario
  asserts (a) the in-engine bridge logs the watermark crossing,
  (b) a handoff event is emitted to the diagnostics ring buffer,
  (c) packet flow resumes within the 200 ms budget. The boringtun
  side is mocked as a Go shim for soak purposes — the real Rust
  archive is only exercised on the Apple CI / partner machine.
- Manual on physical device: install via TestFlight; install via
  AltStore re-sign; run the 30-min smoke per re-sign target with
  a memory-pressure load (browser-window-storm) that forces the
  WireGuard handoff at least once per session. Record observed
  RSS and handoff count in the handover.
- All previous tests green.
- `nm` count still **37** on the desktop libdaalcore.so.

## Exit criteria

1. `Libbox.xcframework` builds reproducibly with the documented
   `gomobile bind` command.
2. Both Xcode targets compile and pass their unit tests on Apple
   CI / partner machine.
3. **TestFlight build distributed to internal testers**.
4. **AltStore re-sign smoke passes on at least one physical
   device**, OR a documented waiver lands in the handover.
5. `ios-extension-memory` AND `ios-wireguard-handoff` soak
   scenarios PASS in both modes.
6. WireGuard sub-engine handoff verified at least once on a
   physical device under memory-pressure load; observed handoff
   downtime ≤200 ms.
7. **TestFlight continuous re-issue pipeline operational** — a
   re-upload has run successfully on Apple infrastructure within
   the 60-day cadence; at least one secondary TestFlight group
   is provisioned for shard-scaling beyond 10k testers.
8. **Personal Apple ID self-signing docs landed** at
   `client-ios/docs/personal-apple-id-self-sign.md`, in English
   and Persian, with screenshots of the 7-day re-sign flow.
9. `specs/ios-build-v1.md` shipped; `engine-abi-v1.md` amended
   to document the iOS artifact.

## Handover to Phase 3

Phase 3 receives:
- A stable, V2-complete engine ABI on all four platforms (Linux,
  Windows, Android, iOS).
- A budget + mode-budget + FSM + per-network-memory + lifeline-strict
  feature set tested at 1000-client soak scale.
- Cross-cutting items CC.1 (external audit) and CC.7 (Persian
  wordlist commissioning) ready to gate broader rollout.
- New transport families (Phase 3) plug into the existing trust /
  budget / FSM / diagnostics surfaces — no new architecture is
  expected.
