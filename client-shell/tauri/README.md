# client-shell/tauri — Tauri 2 shell (desktop + Android + iOS)

The single Daal application shell. Loads `client-ui/dist` (the React
GUI) into a Tauri 2 WebView. Desktop ships today; Android and iOS
follow via Tauri Mobile.

Cargo workspace contents:

| Crate | Purpose |
|---|---|
| `src-tauri/` | Tauri 2 GUI host. Wires `daal-desktop-core` commands into JS. |
| `daal-desktop-core/` | Rust adapter that dlopens `libdaalcore` (Go engine cshared) and exposes contract methods. |
| `daal-wizard/` | First-run wizard logic (route import, PIN, keystore). |
| `bundle-rs/` | Pure-Rust port of the bundle verify path (manifest parse, ed25519 verify, .sbp parse, rotation/revocation). |
| `tun-helper/` | Tiny setuid Linux helper that opens `/dev/net/tun` and passes the fd to the GUI via `SCM_RIGHTS`. |
| `packaging/` | Per-OS packaging scripts (NSIS/MSI, deb/AppImage, dmg). |
| `plugins/daal-platform/` | (planned) Tauri Mobile plugin housing the Android `VpnService` + iOS `NetworkExtension` code under one plugin. |

## Quick start

```sh
# 1. Build the engine c-shared library.
cd ../../core
CGO_ENABLED=1 go build -buildmode=c-shared -tags cshared \
  -o ../client-shell/tauri/src-tauri/resources/libdaalcore.so \
  ./cmd/libdaalcore

# 2. Install Tauri CLI + run the desktop shell.
cd ../client-shell/tauri
npm install
npm run dev       # Tauri dev (cargo + vite hot-reload)
# or
npm run build     # release bundle (deb/appimage/nsis/dmg)
```

The React UI lives in `../../client-ui/` and is built first by
Tauri's `beforeBuildCommand`.

## Tauri Mobile (planned)

```sh
npm run android:init    # one-time scaffold of gen/android/
npm run android:dev     # build APK, install on connected device
npm run android:build   # release APK + bundle

npm run ios:init        # one-time scaffold of gen/apple/
npm run ios:dev
npm run ios:build
```

## Anchor decisions

See `specs/` and `development-phases/` for full architecture notes.
The four locked choices remain:

1. Engine load: **dlopen** `libdaalcore` from Rust via `libloading`.
2. sing-box: **long-lived** sidecar with Clash REST control.
3. Linux TUN: **setuid helper** with `SCM_RIGHTS` fd passing.
4. `bundle-rs`: **pure-Rust port**, verify-only.

## CC.6 telemetry posture

Unchanged: there is none. No analytics, no phone-home, no third-party
crash SDK. The only outbound network calls inside the GUI are made by
sing-box (user traffic) and `core/refresh` (subscription/revocation
fetches over the user's tunnel or direct).
