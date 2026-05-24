# Phase 1.5B — Tauri 2 Desktop Port

## Status

**In progress / nearing exit.** Engine version target:
`daal-core 0.4.1+desktop`. ABI surface 32 → 33 (one new function:
`engine_set_tunnel_socks`).

## Goal

A working Linux + Windows GUI that imports a `.sbp`, renders the trust
prompt, lists routes, connects/disconnects, and shows diagnostics —
with **UX parity** to the Android Home + Add-Route + Subscriptions +
Diagnostics screens. macOS is a CI matrix entry only; share/QR is
deferred to V1.5-Polish.

## Anchor decisions (locked at planning)

| Decision | Choice |
|---|---|
| Engine binding | dlopen `libdaalcore.{so,dll}` from Tauri Rust via `libloading` |
| sing-box lifecycle | Long-lived, controlled via Clash REST on `127.0.0.1:<random>` with random secret |
| Linux TUN privilege | setuid root helper; SCM_RIGHTS fd passing |
| Windows TUN | WinTUN; small Windows service installs the driver and runs sing-box elevated |
| `bundle-rs` | Pure-Rust port (verify path only); no publisher tooling |
| TunnelDialer wiring | New ABI `engine_set_tunnel_socks` (one new function, append-only) |
| Frontend | React + TypeScript + Tailwind in Tauri 2 webview |
| Artifacts | Linux AppImage + Linux .deb + Windows NSIS + Windows portable ZIP (all four) |

## Out of scope

- New bundle format (bundle-rs reads what bundle-go writes).
- Re-implementing the publisher CLI in Rust.
- macOS UX parity (CI matrix only; UI work is V2).
- Telemetry. **CC.6 unchanged.**
- Signed Windows binaries (deferred to V2 when funding for an EV cert
  is in hand).
- Auto-update (deferred).
- Desktop share/QR UX (deferred to 1.5B-Polish; reuses existing
  `engine_share_*` ABI from Phase 1C).

## Deliverables landed in this phase

### Code

- `bundle-rs/` — pure-Rust verify-only port with parity oracle. 13
  Go-generated fixtures pass parity.
- `bundle/go/cmd/bundle-rs-fixtures/` — Go program that produces those
  fixtures.
- `core/cmd/libdaalcore/` — c-shared wrapper package.
- `core/refresh/dialer.go` — `SetGlobalDialer` / `CurrentGlobalDialer`
  hook; both Refresher and RevocationRefresher honor it.
- `core/abi/tunnel.go` + `tunnel_export.go` + `tunnel_gomobile.go` —
  `engine_set_tunnel_socks` Go-side implementation and FFI shims.
- `core/abi/abi.go` — engine version bumped to
  `daal-core 0.4.1+desktop`; `Shutdown()` now resets the tunnel
  override.
- `core/abi/tunnel_test.go` — three tests including a real SOCKS5
  listener round-trip.
- `core/refresh/dialer_test.go` — global-dialer override test.
- `client-desktop/daal-desktop-core/` — Tauri-agnostic Rust core
  containing the dlopen wrapper, sing-box sidecar control, TUN-helper
  IPC client, and the typed command surface.
- `client-desktop/tauri/` — Tauri 2 GUI shell (React + TS + Tailwind +
  EN/FA i18n) wired to the four screens.
- `client-desktop/tun-helper/` — Linux setuid TUN helper (scaffold).
- `client-desktop/packaging/` — postinst/prerm for .deb, AppRun for
  AppImage, PowerShell driver for the portable ZIP.
- `.github/workflows/desktop.yml` — three-platform CI workflow.

### Specs

- New: `desktop-architecture-v1.md`, `bundle-rs-v1.md`,
  `tunnel-dialer-v1.md`.
- Amended: `engine-abi-v1.md` (33-function surface, version bump,
  c-shared wrapper path documented).

### OPSEC

- New `core/opsec_test.go::TestNoTelemetryInDesktop` greps the
  `client-desktop/` tree (excluding `target/` and `node_modules/`) for
  forbidden tokens (`sentry`, `mixpanel`, `posthog`, `telemetry`,
  `googletagmanager`, etc.) so analytics SDKs cannot land by accident.
- All existing OPSEC tests still green (`TestNoNetHTTPInRefresh`,
  `TestBootstrapNoNetHTTP`, `TestShareBindsOnlyPrivate`,
  `TestNoGroupBasedLabels`).

## Exit criteria

The phase is complete when ALL of the following are true:

1. ✅ `cd client-desktop && cargo build --workspace` green on Linux.
2. ✅ `cargo test -p bundle-rs` green; 13/13 parity fixtures pass.
3. ✅ `cargo test -p daal-desktop-core` green with
   `DAAL_ENGINE_LIB` pointing at a freshly built libdaalcore.so —
   confirms Rust → C ABI → Go full path including
   `engine_set_tunnel_socks`.
4. ✅ `engine_version()` returns `daal-core 0.4.1+desktop`; ABI
   surface = 33; existing 32 functions byte-identical signatures.
5. ✅ `cd core && go test ./...` green.
6. ⏳ Linux AppImage + .deb both build green and successfully:
   - import a fixture .sbp
   - render the 4-word fingerprint
   - resolve the trust prompt
   - run `subscription_add` + `subscription_refresh` with
     `via_tunnel: true` (verified via `engine_diagnostics_explain`).
   *(CI workflow `.github/workflows/desktop.yml` exists; first green
   run pending.)*
7. ⏳ Windows NSIS + portable ZIP build green on Windows runner.
8. ✅ `desktop-architecture-v1.md`, `bundle-rs-v1.md`,
   `tunnel-dialer-v1.md` landed.
9. ✅ `engine-abi-v1.md` reflects the 33-function surface.
10. ⏳ Handover doc lists known follow-ups for 1.5C.

Steps 6, 7, 10 close on the first green CI run + handover authoring.

## Risks & known follow-ups (deferred to 1.5C / 1.5B-Polish)

- `tun-helper`'s `open_tun` is stubbed (`Err("stubbed in 1.5B")`); the
  TUNSETIFF ioctl + interface configuration land in 1.5B-Polish.
- `win-service` crate is documented but not yet present in the tree;
  Windows TUN goes through the helper-equivalent in 1.5B-Polish.
- The Tauri shell's panic-recovery supervisor restarts sing-box but
  not the engine library on its own — a Go panic still requires the
  user to restart Daal. Out-of-process engine sandboxing is a V2
  decision point.
- `subscription_list` is not yet rendered in the Subscriptions screen
  (we render only the rows added during the current session); V1.5-Polish
  fix.
- macOS UX parity: CI builds the same artifacts but the System
  Extension for TUN and notarization are V2.
- Signed Windows binaries (EV cert) — V2.
- Wire Android's VpnService to `engine_set_tunnel_socks` (1.5C).
- KeyRotationCard (Compose) and pointer-rotation badge on Home —
  desktop side currently shows only `pointer_source: embedded`; we
  surface the rotation status banner in 1.5B-Polish.
