# Desktop architecture v1

## Status

**Phase 1.5B.** Implemented in `client-shell/tauri/`. Linux + Windows are
shipping targets; macOS is a CI-matrix entry only.

> **THE DESKTOP HAS NO DATA PLANE TODAY.** Every way the desktop engine
> is actually built compiles `./cmd/libdaalcore` with `-tags cshared`
> and nothing else — the README quick-start (`client-shell/tauri/README.md`),
> the AppVeyor Windows job (`appveyor.yml:252`, `libdaalcore.dll`), the
> AppVeyor macOS job (`appveyor.yml:339`, `libdaalcore.dylib`) and
> `tools/preflight-appveyor.py:257`. Only `tools/build-engine-android.sh`
> and `tools/build-engine-ios.sh` append `singbox` to the tag list. So
> `engine.NewDefaultDriver()` resolves to the
> deterministic `engine.Stub` (`core/engine/engine_default.go`). The
> Stub's `Start()` returns nil and publishes a `Connected` state event
> without opening a socket. Since Wave 5 `abi.SetRoute` refuses outright
> on such a build (`ErrNoDataPlane`, `core/abi/dataplane.go`) and
> diagnostics carry `data_plane: "none"`, so the desktop reports what it
> is instead of rendering a tunnel it does not have. Everything below
> describing sing-box carrying traffic is the TARGET topology; the rows
> marked *(not implemented)* do not exist in any shipping build. Read
> this section before trusting the diagram.

## Process model

```
+-----------------------------------+      +---------------------+
|  unprivileged GUI process         |      | privileged TUN      |
|                                   |      | helper (Linux:      |
|  React UI (Tauri webview)         |      | setuid; Windows:    |
|  +-------------------------+      |      | service)            |
|  | typed bridge.ts ── Tauri |      |      |                    |
|  | command handlers        |<-IPC-+----->|  daal-tun-helper /  |
|  +-------------------------+      |      |  daal-win-service   |
|             |                     |      |                     |
|             v                     |      |  opens TUN fd /     |
|  daal-desktop-core (Rust)        |      |  WinTUN handle and  |
|  • engine.rs (dlopen libdaalcore) |      |  hands it back via  |
|  • singbox.rs (spawn + Clash REST) |      |  SCM_RIGHTS / pipe   |
|  • tun_helper.rs (IPC client)     |      +---------------------+
|  • commands.rs (command surface)  |
|  • bundle-rs (verify-only)        |
|             |                     |
|             v dlopen              |
|  libdaalcore.{so,dll,dylib}      |      +---------------------+
|  (Go c-shared from core/abi)      |      | sing-box sidecar    |
|                                   |      | (long-lived child   |
|             |                     |<-spawn| of GUI; Clash REST  |
|             |                     |  +-->| on 127.0.0.1;       |
|             |                     |  |   | route.final=direct  |
|             |                     |  |   | — carries NO tunnel |
|             v                     |  |   +---------------------+
+-----------------------------------+  |
                                       +- Clash REST control plane
```

What the diagram does NOT show, because it does not happen:

- The sidecar never receives a TUN fd. `deliver_tun_fd` hands the fd
  from the helper to **libdaalcore** (`engine_set_tun_fd`), the same
  mechanism Android uses — never to the sidecar.
- The sidecar's rendered config is `route.final = "direct"` with a
  direct/block outbound pair. The route → outbound translation that
  would make it carry a user's traffic was never written, so a running
  sidecar egresses from the user's real address by construction.
- No SOCKS5 inlet is installed. `commands::start_sidecar` deliberately
  stopped calling `engine_set_tunnel_socks` in Wave 2: pointing refresh
  at a `final: direct` listener sent every scheduled subscription,
  revocation and bootstrap fetch out of the user's real address while
  the Go core reported `via_tunnel: true`, which also suppressed the
  fail-closed guard in `refresh.directFallback`. Desktop refresh now
  rides the engine's own in-process inlet (`core/engine/inlet.go`) or
  fails closed.

## Boundaries

| Boundary | Direction | Protocol | Notes |
|---|---|---|---|
| GUI ↔ engine | in-process | C ABI via libloading | dlopen at startup; ABI version asserted. Liveness: the GUI POLLS `heartbeat_tick` every 2s (App.tsx owns the cadence; there is no supervisor thread). A `true` means `engine_version` returned non-NULL — the library answered — and says nothing about the network or the data plane. |
| GUI ↔ sing-box | sibling process | Clash REST API on `127.0.0.1:<random>` with random secret | *(not implemented)* No SOCKS5 inlet is installed — see above. The sidecar is legacy topology that `deliver_tun_fd` replaces on builds carrying `-tags singbox`. |
| GUI ↔ TUN helper | sibling process | Unix abstract socket (Linux: `\0daal/tun-helper`) / named pipe (Windows: `\\.\pipe\daal-engine`) | helper passes raw fd / handle via SCM_RIGHTS / DuplicateHandle |
| engine ↔ TUN | in-process | TUN fd handed to `libdaalcore` via `engine_set_tun_fd` at Connect | helper has no engine knowledge. *(Linux only)* The Windows WinTUN handoff is a stub — `daal-desktop-core/src/tun_helper.rs`. And the fd is only USABLE by a `-tags singbox` build; on the shipping desktop build the Stub ignores it. |

## Threat model

The GUI is unprivileged. The only privileged actor is the TUN helper.
The helper's threat surface is intentionally tiny:

- Helper accepts **one** request, responds, and exits (Linux). Windows
  service is long-lived but accepts a fixed JSON command set with no
  free-form URL or path arguments.
- Helper's only privileged action is opening `/dev/net/tun` (or the
  WinTUN handle); it does not read user files, connect to the network,
  or know what routes the GUI uses.
- Engine knowledge stays in the GUI process, where it can be sandboxed
  in V2 via per-process seccomp / AppArmor / Job Object profiles.

## ABI mismatch handling

On startup the GUI calls `engine_version()` and rejects any string
that does not begin with `daal-core 0.4.1`. The user sees a one-line
banner: *"Engine version mismatch — please reinstall Daal."* The GUI
does not attempt to call any other ABI function in this state.

## Heartbeat

A background timer in `App.tsx` calls `heartbeat_tick` every 2 seconds.
The Rust side calls `engine_version()` (cheap; no allocations on the Go
side beyond the returned C string) and toggles the `healthy` flag. On
flap-to-unhealthy the UI surfaces *"Engine stopped responding —
restart Daal."* and disables Connect.

## Privacy invariants (CC.6)

- The GUI emits no analytics. The frontend imports zero third-party
  SDKs that could phone home. CI tests this by name-grep against
  `client-shell/tauri/` (see `core/opsec_test.go::TestNoTelemetryInDesktop`).
- The Rust supervisor logs panics to a local file the user can review;
  it does not upload anything.
- sing-box stderr goes to `/dev/null`; if the user wants engine logs
  they re-run with `--log` (V2).
- `engine_set_tunnel_socks` is the only ABI function that takes a host
  string from the GUI; it accepts loopback only by convention (the GUI
  never passes anything else) and never accepts URLs.
