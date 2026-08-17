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

Use the root build script. Note that no CI runs these — `appveyor.yml`
packages Windows/macOS/iOS installers and runs no tests. Running these
locally is the only gate this project has.

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
On Linux, `./daal build` emits a desktop `.deb` by default; set
`DAAL_TAURI_BUNDLES="deb,appimage"` on a full release host if you want
AppImage packaging too. There is no Android target in `./daal build` —
the legacy Compose build was removed in v0.2 and the Tauri Mobile
Android build is driven separately.

## Important directories

- `development-phases/` — roadmap phase docs and handovers.
- `specs/` — protocol and closure specs.
- `core/` — Go engine and C-shared ABI.
- `bundle/go/` — `.sbp` bundle parser / verifier / publisher primitives.
- `publisher/` and `cmd/daal-deploy/` — Family Relay Publisher tooling.
- `client-ui/` — the React UI. One codebase for every platform:
  desktop and Android render the same screens.
- `client-shell/tauri/` — the Rust/Tauri shell that hosts `client-ui`
  (desktop + Android), plus `daal-wizard` (publisher logic),
  `daal-desktop-core` (engine FFI), and `tun-helper` (Linux TUN).
  Android scaffolding lives under `client-shell/tauri/src-tauri/gen/android/`;
  there is no iOS shell yet.
- `client-shared/branding/` — canonical brand assets.
- `docs/daal-gui-design-brief-v2.md` — designer source-of-truth for the
  D-2 GUI rebuild. Caveat: its header grounds itself in reference HTMLs
  and brand assets under `/home/daal/src/`, a path that does not exist
  in this repo or on any current machine. The prose is still the design
  authority; the file pointers are dead.

For release details, see `docs/build-and-release.md`.
