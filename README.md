# Daal

Daal (Persian: **دال**) is an anti-censorship app and relay-publishing
toolkit. The FRP / RelayPack engineering track is complete; field closure
records remain gated on live pilots.

## Install

Pre-built signed installers for every supported platform live on the
GitHub Releases page.

**Latest release:**
[github.com/hastaan/daal/releases/latest](https://github.com/hastaan/daal/releases/latest)

| Platform | Asset | Notes |
| --- | --- | --- |
| Android (modern phones, arm64) | `Daal-v<v>-arm64-v8a.apk`     | Sideload via "Install unknown apps" |
| Android (older phones, arm32)  | `Daal-v<v>-armeabi-v7a.apk`  | |
| Linux (Debian / Ubuntu)        | `daal_<v>_amd64.deb`         | `sudo apt install ./daal_*.deb` |
| Linux (any distro)             | `Daal_<v>_amd64.AppImage`    | `chmod +x` then run |
| macOS (Apple Silicon)          | `Daal_<v>_aarch64.dmg`       | Experimental / unsigned in v0.1.0 — see release notes |
| Windows (10/11, x64)           | `Daal_<v>_x64-setup.exe`     | NSIS installer |

Releases are pre-release until the FRP pilot closure records ship; expect
the early series to remain marked as such for a while.

## Build locally

Use the root build script. It is the same entry point CI uses.

```bash
./daal doctor
./daal test
./daal build
./daal package
DAAL_RELEASE_STRICT=1 ./daal release-check
```

The build entry point is `./daal`. Environment-variable overrides use
the `DAAL_*` prefix.

Artifacts are written under `build/` and packaged under `build/release/`.
On Linux, `./daal build` emits a desktop `.deb` by default plus the
Android debug APK; set `DAAL_TAURI_BUNDLES="deb,appimage"` on a full
release host if you want AppImage packaging too.

## Important directories

- `development-phases/` — roadmap phase docs and handovers.
- `specs/` — protocol and closure specs.
- `core/` — Go engine and C-shared ABI.
- `bundle/go/` — `.sbp` bundle parser / verifier / publisher primitives.
- `publisher/` and `cmd/daal-deploy/` — Family Relay Publisher tooling.
- `client-desktop/`, `client-android/`, `client-ios/` — clients.
- `client-shared/branding/` — canonical brand assets.
- `docs/daal-gui-design-brief-v2.md` — designer source-of-truth for the
  D-2 GUI rebuild.

For release details, see `docs/build-and-release.md`.
