# Daal build and release

One contract for both you and CI: the root `./daal` script. CI calls the
same subcommands you do; nothing drifts.

## Quick start

```bash
./daal doctor          # check Go / Rust / Node / Android SDK
./daal test            # run all Go + Rust test suites
./daal build           # build engine + CLIs + Tauri + Android (slow)
./daal package         # collect artifacts under build/release/
./daal release-check   # verify ABI=48, engine version, no bad imports
./daal manifest        # print build/release/manifest.json
```

Each subcommand can be run independently. CI runs `doctor → test → release-check` on every push (see `.github/workflows/ci.yml`).

By default, `test` and `build` are strict: Rust parity failures, Tauri failures, and Android build failures fail the command. During local bring-up only, a developer can opt into partial behavior with `DAAL_ALLOW_BUNDLE_RS_WARN=1` or `DAAL_ALLOW_PARTIAL_BUILD=1`.

The script sets writable defaults for Go and Gradle build state:

```bash
GOCACHE=/tmp/daal-go-build
GRADLE_USER_HOME=/tmp/daal-gradle-home
```

Desktop packaging defaults to a Linux `.deb` bundle because AppImage packaging needs a less restricted host filesystem than the project sandbox provides. Override it on a full release host:

```bash
DAAL_TAURI_BUNDLES="deb,appimage" ./daal build
```

## Versioning layers

| Layer            | Source             | Bump when                                                        |
|------------------|--------------------|------------------------------------------------------------------|
| Engine version   | `core/abi/abi.go`  | ABI changes (new C-shared symbol, signature change). Currently `daal-core 0.9.0+v3-share`. |
| SBP spec_version | `bundle/go/...`    | RelayPack format changes. Currently `4`.                         |
| App version      | `VERSION`          | Each release. Currently `0.1.0`.                                  |
| Build manifest   | `build/release/manifest.json` (generated) | Every `./daal package` run.                |

The first three are independent. Bumping the app version does NOT bump the engine or SBP version. Bumping the engine ABI MUST be a separate phase and is gated by `release-check`.

## Releasing to `hastaan/daal`

The `hastaan/daal` GitHub repo (https://github.com/hastaan/daal) is the publish target. Local `main` is the working tree; we push only when a release is ready.

### One-time setup

```bash
git config user.name  "hastaan"
git config user.email "hastaan@gmail.com"
git remote add hastaan git@github.com:hastaan/daal.git
```

### Release flow

```bash
# 1. Bump the version + add a CHANGELOG entry under the new heading
#    `## [0.1.1] — YYYY-MM-DD`. The release workflow extracts
#    that section verbatim into the GitHub Release body.
echo "0.1.1" > VERSION
$EDITOR CHANGELOG.md
git commit VERSION CHANGELOG.md -m "release: 0.1.1"

# 2. Verify locally.
./daal doctor
./daal test
./daal build
./daal package
DAAL_RELEASE_STRICT=1 ./daal release-check
cat build/release/manifest.json

# 3. Tag.
git tag -a v0.1.1 -m "Daal 0.1.1"

# 4. Push to hastaan/daal. Push the branch and the tag together.
git push hastaan main
git push hastaan v0.1.1
```

Do NOT push to `hastaan/daal` automatically from CI. Pushes to `hastaan/daal` are deliberate: they only happen when you (the human) have decided a release is ready.

Pushing the tag triggers `.github/workflows/release.yml`, which gates on `release-check`, builds desktop bundles on Linux / macOS / Windows runners, builds signed Android APKs, and creates a GitHub Release with the bundles attached and the matching CHANGELOG section as the body. Tags whose name contains a hyphen (e.g. `v0.1.1-rc.1`) are marked as prereleases automatically.

## What `release-check` enforces

- **Engine version pinned.** `daal-core 0.9.0+v3-share` must appear in `core/` or `specs/`.
- **Asymmetric module guard.** `core/` and `bundle/` must NOT import `daal/publisher`.
- **Locked invariant 52.** No `daal/publisher/directory` references anywhere (FRP-13 closure).
- **Locked invariant 47.** No Android admin / cell-admin / modifier-admin surfaces in `client-android/`.
- **`spec_version=4`** pinned in specs / bundle.
- **ABI symbol count.** If the engine `.so` has been built, `nm -D --defined-only` must show 48 `engine_*` exported symbols. (If you haven't run `./daal build` first, this becomes a warn, not a fail.)
- **Working tree clean.** A dirty tree is a warn, not a fail — but a dirty tree on a release tag is a problem you should fix.

Set `DAAL_RELEASE_STRICT=1` for release cuts. Strict mode turns a dirty tree or missing built engine binary into a hard failure.

A failure (`exit 2`) means a locked invariant was violated and the release MUST NOT ship.

## CI vs. local

| | local (your laptop) | CI (`.github/workflows/ci.yml`) |
|-|-|-|
| `./daal doctor` | yes | yes |
| `./daal test` | yes | yes |
| `./daal release-check` | yes (`DAAL_RELEASE_STRICT=1` for releases) | yes |
| `./daal build` (Tauri + Android) | yes | **no** — desktop.yml handles that on its own schedule |
| `./daal package` | yes (when releasing) | no (the artifacts are local-only by design — no automatic upload to releases) |

This split is intentional. CI gives you a fast green / red signal on every push (~3 min). Heavyweight Tauri / Android packaging happens locally before a release, so you control exactly which artifacts ship.

## What's NOT here

- **Code signing.** No code-signing certificate is configured. Windows users will see a SmartScreen warning. Mitigation is a future concern.
- **macOS signing.** macOS DMG packaging is best-effort until Apple notarization credentials are configured.
- **Reproducible builds.** Build outputs are deterministic for Go (`-trimpath` is implied at release time; not yet wired); Tauri and Android are not yet reproducible. This is a V4-era concern.

End — root build script + CI + release runbook.
