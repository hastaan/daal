# Platform reality — what each platform can actually do

**Compiled 2026-08-18, during the solidify-before-selection wave.**
Scope: the OWNER PLATFORM lane. This is a self-contained section the
capability-matrix owner can include verbatim.

Every claim below is backed by a file:line, a build flag read off a real
artefact, or a test that was run in this working tree. Where something
was **not** verified against hardware, it says so. Android is the only
platform this project has ever run on a real device
(Samsung SM-S931B); everything else on this page is read from source and
from built binaries, not from a device.

---

## The one-line answer

| Platform | Can it carry traffic? | Could it *claim* to? | Status |
|---|---|---|---|
| **Android** | **Yes** — real in-process sing-box over a `VpnService` TUN fd | n/a | Only platform with a data plane, only platform tested on hardware |
| **Linux desktop** | No | **It did, until this wave** | Stub driver; now fails closed |
| **Windows** | No | **It did, until this wave** | Stub driver + no TUN helper of any kind |
| **macOS** | No | **It did, until this wave** | Stub driver; no helper path designed |
| **iOS** | No | No (fails honestly) | Tauri app only; the native app + Network Extension referenced by the specs **does not exist in this repo** |

---

## 1. Desktop: it could say "Connected" with traffic in the clear

**This was real, and it was the most dangerous defect in the
repository.** A censorship-circumvention client that renders "Connected"
while the user browses in the clear does not merely fail to help — it
withdraws the caution the user would otherwise have exercised.

### The chain, end to end

1. `core/abi/driver.go:11` — `var newEngineDriver = engine.NewDefaultDriver`.
2. `core/engine/engine_default.go` is `//go:build !singbox` and returns
   `NewStub()`.
3. `core/engine/engine.go:48` — `Stub.Start()` ignores the config, sets
   `connected = true`, and publishes `Event{Type:"state", State:"Connected"}`.
   It never opens a socket.
4. `core/abi/abi.go` `SetRoute` gets `nil` from `driver.Start`, calls
   `c.pm.Connected()` and advances the posture to `ImportedActive`.
5. `client-ui/src/backends/tauri.ts:122` `postureToConnState` maps
   `ImportedActive → 'connected'`.
6. `client-ui/src/d2pages/ConnectionPage.tsx:54` renders that as
   **"Connected · Routing"**, the eagle goes live, and the throughput
   poll starts.

Nothing anywhere in that chain checks whether a data plane exists.

### The desktop is exactly such a build — verified on the artefact

Not inferred from the scripts; read off the `.so` the desktop app
actually dlopens
(`client-shell/tauri/src-tauri/resources/libdaalcore.so`, built
2026-08-17, gitignored via `.gitignore:81`):

```
$ go version -m libdaalcore.so
    build   -buildmode=c-shared
    build   -tags=cshared          <-- no `singbox`
$ strings -a libdaalcore.so | grep -c "sagernet/sing-box"
0
$ nm -D --defined-only libdaalcore.so | grep -c ' T engine_'
58
```

58 ABI symbols, zero sing-box.

*(That reading is of the **stale** artefact, kept verbatim because it is the
evidence for §4c. Rebuilt at repair from the same source with the same tags,
it exports **59** and still zero sing-box — the driver conclusion below is
unchanged by the rebuild, because the tag set is what selects the driver.)*

*(Reconciliation note: `node tools/check-plumbing.mjs --json` reports
`engineExports: 62` from the Go source. The two numbers are not in conflict
and not the same fact — three of the four missing symbols are build-tag-gated
out of a plain `cshared` build (`engine_set_now_unix`,
`engine_soak_force_wg_handoff`, `engine_soak_set_wg_memory_kib`, all
`//go:build … && soak`). **The fourth is not, and it is evidence for §4c:**
`engine_set_tunnel_refresh` lives in `core/abi/tunnel_export.go`, which is
plain `//go:build cshared`, so it belongs in this artefact — and it is absent,
because the `.so` was built at 09:03 on 2026-08-17 and that file landed at
15:32 the same day, in `ea2538b`. The desktop app in this checkout could not
start at all — `Engine::load` resolves that symbol eagerly and `run()` panics
on the miss (§4c) — and nothing anywhere reported it. As of this wave
`tools/check-engine-so-manifest.sh` does; it is the check that produced this
number.)*

Every desktop build path agrees:

| Artefact | Build command | Tags | Driver |
|---|---|---|---|
| Android | `tools/build-engine-android.sh:74` | `cshared,singbox,with_gvisor,…` | real |
| iOS | `tools/build-engine-ios.sh:74` | `cshared,singbox,with_gvisor,…` | real |
| Linux desktop | `daal:258` | `cshared` | **Stub** |
| Windows | `appveyor.yml:253` | `cshared` | **Stub** |
| macOS | `appveyor.yml:340` | `cshared` | **Stub** |

And the stub's behaviour, observed by running it in this tree:

```
HasRealDataPlane=false
stub published: type=state state=Connected
stub.Connected()=true
```

### What changed in this wave (honesty fix — the driver was NOT flipped)

Flipping the desktop to the sing-box driver is out of scope and is a
wave of its own (see §5). What landed is the refusal:

- `core/engine/engine_default.go` / `engine_singbox.go` — new
  `HasRealDataPlane` constant, twinned per build tag, with matching
  twin tests in `driver_selection_{stub,singbox}_test.go` so the
  constant cannot drift from the driver.
- `core/abi/dataplane.go` — `ErrNoDataPlane` and `DataPlaneKind()`.
- `core/abi/abi.go` `SetRoute` now returns `ErrNoDataPlane` **before it
  touches anything**, so the posture never leaves `NoRoute` and the
  driver is never started. Regression:
  `TestSetRoute_FailsClosedWithoutDataPlane`.
- `ExportDiagnostics` now emits `data_plane: "singbox" | "none"` so a
  GUI can warn *before* the user presses Connect rather than only
  reacting to a refusal.
- `client-ui` — `ConnectionPage` renders a persistent alert
  (`conn.no_data_plane.*`, en + fa) and refuses the Connect gesture
  outright instead of flipping the eagle to an optimistic "connecting"
  it cannot honour.

The desktop now says what is missing and refuses, on every desktop OS.

### The sidecar and Clash REST path: dead, and already known to be

`daal-desktop-core/src/singbox.rs` still spawns a real `sing-box` child
process at app launch, but it is inert as a tunnel:

- `render_initial_json` writes `route.final = "direct"` with only
  `direct`/`block` outbounds.
- The route → outbound translation over Clash REST **was never
  implemented** — `commands.rs:164` says so in the source.
- Wave 2 already removed the genuinely harmful part: `start_sidecar`
  used to install the sidecar's SOCKS inlet as the engine's global
  refresh dialer, which sent every scheduled subscription / revocation
  / bootstrap fetch out of the user's real address *and* suppressed
  `refresh.directFallback`'s fail-closed guard. That is gone
  (`commands.rs` `start_sidecar` doc comment).

**Verdict: partially wired and load-bearing for nothing.** It spawns a
process, listens on two loopback ports, and carries no user traffic. It
should be deleted with D1, not before — deleting it first would only
remove the evidence.

### The TUN-helper path: built, correct-looking, and has no caller

`daal-desktop-core/src/tun_helper.rs` `unix::open_fd` is a complete
SCM_RIGHTS receive path, and `commands::deliver_tun_fd` /
`clear_tun_fd` wrap it. Nothing calls them —
`tools/check-plumbing.mjs` already reports exactly this
("`deliver_tun_fd`/`clear_tun_fd` desktop-only with no caller"), and a
repo-wide grep finds the only other `set_tun_fd` callers are the
Android JNI entry points in `src-tauri/src/lib.rs:2876`.

There is a second, quieter gap in the same path: the `.deb` postinst
(`client-shell/tauri/packaging/linux/deb/postinst`) sets the setuid bit
on `/usr/libexec/daal/daal-tun-helper`, but nothing stages the binary
there. `tauri.conf.json` bundles only `resources/*`, and
`daal-tun-helper` is a workspace member that no packaging step copies.
The postinst is guarded by `if [ -e "$HELPER" ]`, so it exits 0 having
done nothing — a silent no-op, the same "documented step nobody runs"
shape as the `tools/patch-android-*` scripts before Wave 4.

---

## 2. iOS: the native app in the specs does not exist

**`client-ios/` is not in this repository.** `ls client-ios` fails.

Three specs and two phase docs are written as though it does:

- `specs/ios-build-v1.md:5` — "**Implementation:** `client-ios/`",
  describing a `DaalApp` SwiftUI target and a `DaalTunnel`
  `NEPacketTunnelProvider` extension.
- `specs/wireguard-subengine-v1.md:5,80` — `client-ios/DaalTunnel/Sources/`,
  vendored `client-ios/Vendored/boringtun/libboringtun.a`.
- `development-phases/18-phase-2e-ios.md`, and
  `docs/handovers/frp-6-handover.md:90`, whose stated verification step
  is `rg -n "…" client-ios/` — a grep over a directory that is not here.

### What does exist

1. **One orphaned Swift file**: `client-shell/tauri/plugins/daal-platform/ios/PacketTunnelProvider.swift`,
   which the plugin's own README labels "preserved from client-ios; not
   yet wired". No Xcode target references it.
2. **A Tauri iOS build in CI** (`appveyor.yml:400-470`): `npx tauri ios
   init` scaffolds into the gitignored `src-tauri/gen/apple`,
   `tools/build-engine-ios.sh` cross-compiles a **real** singbox-tagged
   `libdaalcore.dylib`, `tools/patch-ios-signing.sh` strips the signing
   requirements, and the job then *expects* `xcodebuild -exportArchive`
   to fail (no Apple account) and extracts the `.app` out of the
   xcarchive by hand, zipping it as `Daal_<version>_unsigned.ipa`.

### What that build can and cannot do

It is an ordinary sandboxed iOS app. It has **no Network Extension
target**, therefore no `NEPacketTunnelProvider`, therefore no way to
obtain a packet-tunnel file descriptor — and on iOS an app without that
entitlement cannot capture system traffic at all.

The saving grace is that it fails honestly and always did: the iOS
dylib *is* built with `-tags singbox`, so `HasRealDataPlane` is true and
the new fail-closed guard stays out of the way — but
`singBox.Start` refuses with
`"engine: TUN fd not set; VpnService must call engine_set_tun_fd before
engine_set_route"` (`core/engine/engine_singbox.go:109`), and no fd
will ever arrive. **iOS cannot connect, and cannot claim to.**

An unsigned `.ipa` with no Apple Developer account is also not
installable by an ordinary user; it is a build artefact, not a
distribution.

**Verdict: scaffolding only.** The roadmap should stop carrying "iOS"
as a platform with an implementation. Reaching a tunnelling iOS client
means writing the Network Extension target — either restoring the
`client-ios/` Xcode project the specs describe, or adding an extension
target to the Tauri iOS scaffold, plus a paid Apple Developer account
for the `packet-tunnel-provider` entitlement (Apple does not grant it
to free personal teams).

---

## 3. Windows (D2): the stub is only half the story

`daal-desktop-core/src/tun_helper.rs:232` is confirmed a stub — but the
backlog understates it in two ways:

1. **Only `ping` exists.** The Windows module has no `open_fd`
   equivalent at all, so there is nothing for a caller to call even
   once `ping` works. Linux's `unix` module exports `ping`, `open` and
   `open_fd`.
2. **The server side does not exist either.** The module doc says the
   pipe is "served by `daal-win-service`". Grep the repository: that
   name appears in exactly two places, this doc comment and an ASCII
   diagram in `specs/desktop-architecture-v1.md:18`. There is no such
   crate, binary, or service.

There is also a design question the backlog line hides: **Windows has no
TUN file descriptors.** The Linux path receives a `RawFd` over
SCM_RIGHTS and hands it to `engine_set_tun_fd`, which takes a `c_int`.
Windows uses Wintun, whose adapter is a `HANDLE` with a
session/ring-buffer API, not a pollable fd — so this is not a port of
the Linux transport, it is a different handoff shape that the engine ABI
does not currently have a symbol for.

**Honest size for D2:**

| Piece | Cost |
|---|---|
| `windows-sys` named-pipe client (mirror of `unix::send_request`, length-framed JSON) | small — ~150 lines, 1 day |
| `daal-win-service`: a privileged service that opens a Wintun adapter, plus its installer/uninstaller and service registration in the NSIS/WiX bundle | **large — the real cost**, and it must be written from nothing |
| Handing a Wintun session to the engine: either a new ABI symbol taking a `HANDLE`, or a Windows-side reader/writer thread that bridges the ring buffer to something the existing driver accepts | medium, and it is an **ABI decision**, not just plumbing |
| Code-signing the service (Windows blocks unsigned drivers/services in practice) | procurement, not engineering |

Calling D2 "needs the named-pipe `windows-sys` impl" describes the
cheapest quarter of the job. It should be re-scoped in the backlog.

---

## 4. Build story per platform — where a skipped step fails silently

The pattern from Wave 4 (`gen/android` is generated and gitignored, and
nothing ran the four `tools/patch-android-*` scripts until they were
chained into `npm run android:patch`) recurs. Findings, worst first:

### 4a. `libdaal_deploy.so` vs `artifacts.go` — **fixed this wave**

`libdaal_deploy.so` is `cmd/daal-deploy` cross-compiled into
`gen/android/.../jniLibs/`. It is built **only** by
`tools/build-deploy-android.sh`; `tauri android build` packages
whatever `.so` is already sitting there, and `gen/android` is
gitignored. Editing `publisher/deploy/cloudinit/artifacts.go` (a new
relay release, a new pin, a new mirror) and rebuilding the APK
therefore ships an app that provisions relays from the **previous**
manifest, with no warning. This has already cost one full debugging
cycle.

New gate: **`tools/check-deploy-so-manifest.sh`**, wired into
`tools/hooks/pre-push`. The manifest is Go source compiled into the
binary, so every `Sha256`/`SigHex` literal in `artifacts.go` must
appear verbatim in the `.so`'s string data — `-ldflags "-s -w"` strips
symbols and DWARF, not `.rodata`. The check is arch-neutral (the host
cannot execute an Android arm64 binary) and skips cleanly when no `.so`
has been built. Verified both directions in this tree: it passes on
all three ABIs today, and flipping one pin in `artifacts.go` makes it
fail on all three with exit 1.

### 4b. `daal-tun-helper` is never staged for packaging

See §1. The `.deb` postinst chmods a path nothing installs to, and does
it under an `if [ -e ]` guard, so the failure is invisible. Not fixed
here — it becomes real work only alongside D1, and fixing the packaging
before there is a data plane would install a setuid binary that nothing
uses, which is strictly worse.

### 4c. `resources/libdaalcore.*` is gitignored, so "which engine am I
running?" is unanswerable from the repo

`.gitignore:81` excludes `client-shell/tauri/src-tauri/resources/libdaalcore.*`.
A developer's desktop app loads whatever `.so` was last dropped there,
possibly months old, possibly from a different branch. The engine
version prefix check (`REQUIRED_VERSION_PREFIX = "daal-core 0.9"` in
`daal-desktop-core/src/engine.rs:27`) catches a *major* mismatch and
nothing finer. The new `data_plane` diagnostics field at least makes
"this is a stub engine" visible in an exported diagnostics blob.

**This is not hypothetical in this very checkout** (measured at
reconciliation, see §1): the staged `resources/libdaalcore.so` exports 58
`engine_*` symbols; the source defines 62; three of the four are
`soak`-tagged and correctly absent, but `engine_set_tunnel_refresh`
(`core/abi/tunnel_export.go`, plain `//go:build cshared`) is missing purely
because the artefact predates the commit that added it by six hours.

**The consequence is worse than a lazily-failing feature, and the first draft
of this section understated it.** Symbol resolution is EAGER and the failure
is FATAL: `Engine::load` (`daal-desktop-core/src/engine.rs`) resolves every
symbol up front with `*lookup::<…>(&lib, b"…")?`, `lookup` (engine.rs:1100)
maps a `dlsym` miss to `DesktopError::EngineSymbol`, and
`src-tauri/src/lib.rs:2494` wraps `Engine::load` in `unwrap_or_else(|e|
panic!(…))` at the top of `run()`, before the Tauri builder. So one absent
export does not degrade one call path — **the engine never loads, no window
opens, and every capability behind the C ABI is dead.** Measured at
reconciliation rather than reasoned: the loader dlsyms 58 distinct
`engine_*` names, and the staged `.so` was missing exactly one of them.
A developer or reviewer whose local artefact has gone stale therefore does
not see a degraded tunnel-refresh path — they see an immediate panic, and in
particular they never see the `conn.no_data_plane` refusal this wave added,
because no window ever opens to show it.

Note the blast radius is a *workstation*, not a clone: `libdaalcore.*` is
gitignored (`resources/README.md` explains why it was untracked on
2026-08-17), so a fresh clone has no artefact at all and `./daal build` is the
documented first step. The hazard is the stale local copy, which is exactly
the case nothing could see.

**Gate: built in this wave.** `tools/check-engine-so-manifest.sh` enumerates
the `//export engine_*` names in `core/abi` whose build constraint is *plain*
`cshared` (soak-tagged exports are deliberately not required, or the gate
would cry stale on a correct artefact) and asserts each is a defined dynamic
symbol in any `resources/libdaalcore.{so,dylib}` / `daalcore.dll` present. It
skips, announced, when no artefact is staged or `nm(1)` is unavailable — same
shape and same skip semantics as the `libdaal_deploy.so` gate in §4a. It is
wired into `tools/hooks/pre-push`. Run against the artefact described above it
reported `STALE (1 of 59 exports absent): engine_set_tunnel_refresh`, which is
how the eager-load consequence above came to be measured rather than assumed.

### 4d. Bundle metadata describes dead topology

`src-tauri/tauri.conf.json` `longDescription` tells the user the
desktop client "runs a long-lived sing-box sidecar". It does spawn one;
it carries no traffic (§1). Cosmetic, but it is installer-visible copy
that asserts a data plane. Left alone deliberately — changing bundle
metadata mid-wave risks release-check churn — and logged instead.

---

## 5. Sizing D1 honestly (assessed, not attempted)

Flipping the desktop to `-tags singbox` is **not** a one-line build
change. What it actually requires:

1. **Build**: add `singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api`
   to three build sites (`daal:258`, `appveyor.yml:253`,
   `appveyor.yml:340`). Cheap, and it pulls the full sing-box
   dependency tree into a CGO c-shared build on three OSes — the
   Windows mingw64 leg is where this historically hurts.
2. **A TUN fd, per OS**: Linux can use the existing helper path once
   something *calls* `deliver_tun_fd` and packaging actually installs
   the helper (§4b). Windows needs §3 in full. macOS needs a
   `NetworkExtension` system extension and a signed, notarised app —
   Apple has no unprivileged TUN path — which is a larger job than
   Windows and has no design in this repo at all.
3. **`androidPlatform`**: `engine_singbox.go` builds its TUN inbound
   around an `androidPlatform` `PlatformInterface` and a `protect`
   callback whose purpose (escaping the VPN's own routes) is
   Android-shaped. The desktop equivalent needs deciding, not porting.
4. **Retire the sidecar** (§1) once the in-process driver carries
   traffic, and delete its ports, its config file and its binary
   resolution.
5. **Verification**: there is currently no way to test this without a
   second machine, and the owner has one Linux desktop. A desktop data
   plane that nobody can test on hardware is how the "Connected" lie
   got in.

The honest ordering is Linux-first, and only after the helper is
packaged and called. Windows and macOS should be split out of D1 into
their own items rather than carried as though the tag flip covers them.

---

## 6. Verification run for this section

Run in this working tree on 2026-08-18:

```
cd core && go test ./...                                  # PASS
cd core && go test -tags singbox ./abi/ ./engine/         # PASS
cd core && go vet  -tags singbox ./abi/ ./engine/         # clean
cd client-ui && npx tsc --noEmit                          # clean
bash tools/check-hardcoded-strings.sh                     # OK
bash tools/check-deploy-so-manifest.sh                    # OK (3 ABIs)
cmp client-shared/i18n/d2-extra.{en,fa}.json \
    client-ui/src/i18n/d2/d2-extra.{en,fa}.json           # identical
go version -m client-shell/tauri/src-tauri/resources/libdaalcore.so
```

Re-run at reconciliation (2026-08-18, after all four lanes landed):
every Go module `go build ./... && go vet ./... && go test ./...` (soak module
under `-tags soak`), `core` again under `-tags singbox`, `go test -race` on
`core/scheduler` and `core/refresh`, `daal-wizard` `cargo check --all-targets`
+ `cargo test` (19 passed), `daal-desktop-core` `cargo check --all-targets`,
`client-ui` `npm run build` + `vitest` (90 passed), and the whole
`tools/hooks/pre-push` suite — all green.
`client-shell/tauri/src-tauri` `cargo check` **cannot run on this machine**:
`pkg-config` cannot find `gdk-pixbuf-2.0` (GTK/WebKit dev packages are not
installed). That is a pre-existing environment gap, not a code defect, and was
not "fixed" by removing anything.

**Not verified against hardware.** No Android device, desktop install,
Windows machine, Mac, or iPhone was used. Every platform statement above
is from source, from build configuration, or from inspecting a binary
that was already built in this tree.
