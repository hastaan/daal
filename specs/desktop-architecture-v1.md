# Desktop architecture v1

## Status

**Phase 1.5B.** Implemented in `client-shell/tauri/`. Linux + Windows are
shipping targets; macOS is a CI-matrix entry only.

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
|             | SOCKS5 inlet        |  +-->| on 127.0.0.1)       |
|             | from                |  |   |                     |
|             | engine_set_tunnel_socks |  |   | sees TUN fd from   |
|             v                     |  |   | helper via IPC     |
+-----------------------------------+  |   +---------------------+
                                       |
                                       +- Clash REST control plane
```

## Boundaries

| Boundary | Direction | Protocol | Notes |
|---|---|---|---|
| GUI ↔ engine | in-process | C ABI via libloading | dlopen at startup; ABI version asserted; supervisor heartbeat every 2s |
| GUI ↔ sing-box | sibling process | Clash REST API on `127.0.0.1:<random>` with random secret | also: SOCKS5 inlet on `127.0.0.1:<random>` for refresh + system-proxy toggle |
| GUI ↔ TUN helper | sibling process | Unix abstract socket (Linux: `\0daal/tun-helper`) / named pipe (Windows: `\\.\pipe\daal-engine`) | helper passes raw fd / handle via SCM_RIGHTS / DuplicateHandle |
| sing-box ↔ TUN | direct | TUN fd handed off at Connect | helper has no engine knowledge |

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
