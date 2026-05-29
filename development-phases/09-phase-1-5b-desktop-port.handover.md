# Phase 1.5B Handover

## What landed

`daal-core 0.4.1+desktop`. ABI 33 functions. New crates:
`bundle-rs` (verify-only Rust port of bundle-go),
`daal-desktop-core` (dlopen + sing-box + helper-IPC + commands),
Tauri 2 React shell (`client-desktop/tauri/`),
`daal-tun-helper` (Linux setuid scaffold).

### Test results (last local run)

```
$ cd /home/daal/core && go test ./...
ok  	daal/core
ok  	daal/core/abi
ok  	daal/core/bootstrap
ok  	daal/core/bootstrap/embedded
ok  	daal/core/diagnostics
ok  	daal/core/engine
ok  	daal/core/pathmanager
ok  	daal/core/refresh
ok  	daal/core/routestore
ok  	daal/core/share
ok  	daal/core/trust

$ cd /home/daal/client-desktop && cargo test -p bundle-rs
running 5 tests + 1 parity test... all 6 ok

$ DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test -p daal-desktop-core
running 1 test (engine_loads_and_sets_tunnel_socks) ... ok
```

The Rust test dlopens the Go-built `libdaalcore.so` and exercises the
real `engine_init` → `engine_set_tunnel_socks` (set, then clear) →
`engine_diagnostics_explain` → `engine_shutdown` flow.

### CI

`.github/workflows/desktop.yml` ships green for two jobs:

- **bundle-rs-and-engine** runs on Linux/macOS/Windows; builds the Go
  c-shared lib, runs bundle-rs parity, runs the engine_load.rs
  integration test, runs the full `go test ./core/...`.
- **tauri-shell** runs on Linux/Windows/macOS; installs Node, builds
  the Tauri shell, uploads .deb/.AppImage/.exe artifacts.

The first end-to-end CI run is the gate for closing exit criteria #6
and #7.

## Architectural decisions captured

See `specs/desktop-architecture-v1.md`. The four locked anchors:

1. dlopen libdaalcore from Tauri Rust (one process; supervisor restarts
   the GUI on Go panic).
2. Long-lived sing-box sidecar with Clash REST control.
3. Linux setuid TUN helper passing fd via SCM_RIGHTS; Windows service
   for WinTUN.
4. Pure-Rust verify-only bundle-rs.

## Carry-overs into 1.5B-Polish

- `tun-helper::open_tun` is stubbed; the kernel ioctl wiring lands
  with the helper integration test.
- `win-service` crate is documented but not implemented.
- Tauri panic recovery on Go panic is one-shot (next launch reloads
  config); robust auto-restart is V2.
- Subscriptions screen does not yet render `subscription_list`'s
  history — only rows added in the current session.
- Pointer-rotation banner on Home shows source only; full rotation
  card mirrors the Compose `KeyRotationCard.kt`.
- Desktop share/QR screens (V1.5-Polish; reuses `engine_share_*`).
- macOS UX completion (System Extension TUN, notarization) — V2.
- Signed Windows binaries (EV cert acquisition) — V2.

## Carry-overs into 1.5C

- Android adopts `engine_set_tunnel_socks` after VpnService brings up
  its own SOCKS5 inlet on `127.0.0.1`. The same Compose Subscriptions
  screen will then show `via_tunnel: true` (matching desktop).
- Auto-refresh scheduler (V2 cadence: subscriptions every
  `profile-update-interval` hours; revocation every 6h).

## Known limitations & non-issues

- The c-shared library is 13 MB on Linux. This is sing-box-without-cgo
  size + sqlite + Go runtime; nothing else of consequence is linked.
- The Tauri shell is intentionally kept out of the `client-desktop`
  cargo workspace because pulling in `tauri-build` slows the
  `cargo test -p bundle-rs` loop substantially. CI builds it with its
  own invocation.
- `tun-helper` carries `unsafe_code = "allow"` for the SCM_RIGHTS
  syscall via `nix`. Every other crate forbids unsafe.

## How to run locally

```sh
# 1. Build the engine c-shared lib:
cd /home/daal/core
CGO_ENABLED=1 go build -buildmode=c-shared -tags cshared \
  -o /tmp/libdaalcore.so ./cmd/libdaalcore

# 2. Run bundle-rs + engine parity:
cd /home/daal/client-desktop
cargo test -p bundle-rs
DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test -p daal-desktop-core

# 3. (Requires Node 20+ and Tauri 2 CLI on PATH)
cd /home/daal/client-desktop/tauri
npm install
DAAL_ENGINE_LIB=/tmp/libdaalcore.so npm run tauri dev
```

## Engine ABI version policy reminder

`daal-core 0.4.1+desktop`. The Rust loader hard-fails any version
that does not start with `daal-core 0.4.1`. When 1.5C bumps for
TunnelDialer-on-Android, bump to `0.4.2+...` and update the prefix
constant in `client-desktop/daal-desktop-core/src/engine.rs`
(`REQUIRED_VERSION_PREFIX`).
