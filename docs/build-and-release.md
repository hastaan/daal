# Daal build and release

One contract for building and releasing: the root `./daal` script.

**Read this first: there is no test CI.** `appveyor.yml` is a
packaging pipeline only — it contains no `test_script` key and no
`go test`, `cargo test`, or `tsc` invocation, and it references none of
the five gate scripts under `tools/`. There is no `.github/` directory
either; GitHub Actions was dropped when the account was rate-throttled
(see `CHANGELOG.md`). **Every gate in this document runs on your machine
or it does not run at all.**

## Quick start

```bash
./daal doctor          # check Go / Cargo / Node / npm / git
./daal test            # run all Go + Rust test suites
./daal build           # build engine + CLIs + Tauri desktop (slow)
./daal package         # collect artifacts under build/release/
./daal release-check   # verify ABI=58, engine version, no bad imports
./daal manifest        # print build/release/manifest.json
```

Each subcommand can be run independently. Nothing runs them for you on
push — run `doctor → test → release-check` yourself before a release.

By default, `test` and `build` are strict: Rust parity failures and Tauri
failures fail the command. During local bring-up only, a developer can opt
into partial behavior with `DAAL_ALLOW_BUNDLE_RS_WARN=1` or
`DAAL_ALLOW_PARTIAL_BUILD=1`.

There is no Android target in `cmd_build`; the legacy Android Compose
build was removed in v0.2 and the Tauri Mobile replacement is built
separately.

The script sets one writable default for Go build state:

```bash
GOCACHE=/tmp/daal-go-build
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

Pushing the tag does **not** trigger a release workflow — there isn't
one. What actually exists is AppVeyor (`appveyor.yml`), a three-image
packaging matrix that runs on push:

| image | `DAAL_TARGET` | produces | staged as |
|---|---|---|---|
| Visual Studio 2022 | `windows` | `.exe` (NSIS) + `.msi` | `release-assets\*.exe`, `release-assets\*.msi` |
| macOS | `macos` | `.app.zip` + `.dmg` (aarch64) | `release-assets/*.dmg`, `release-assets/*.app.zip` |
| macOS | `ios` | unsigned `.ipa` (re-sign with Sideloadly) | — |

Each image builds the Go engine itself (`-buildmode=c-shared` straight
into `client-shell/tauri/src-tauri/resources/`), then `tauri build`, then
renames the bundle into `release-assets/` and publishes it as an AppVeyor
build artifact.

Three things this does NOT do, and you must do by hand:

1. **It runs no tests and no gates.** Run `./daal test` and
   `DAAL_RELEASE_STRICT=1 ./daal release-check` locally first.
2. **It builds no Linux bundle.** There is no Linux image in the matrix.
   `.deb` comes from a local `./daal build`.
3. **It creates no GitHub Release.** Download the AppVeyor artifacts and
   attach them to a release yourself, with the matching CHANGELOG section
   as the body.

## What `release-check` enforces

- **Engine version pinned.** `daal-core 0.9.0+v3-share` must appear in `core/` or `specs/`.
- **Asymmetric module guard.** `core/` and `bundle/` must NOT import `daal/publisher`.
- **Locked invariant 52.** No `daal/publisher/directory` references anywhere (FRP-13 closure).
- **Locked invariant 47.** No `CellAdminScreen` / `ModifierAdminScreen` / `publisherAdmin` references anywhere in the tree. This was Android-specific when written; since the Compose tree was removed (`daal:405-407`) it greps every `.kt` / `.java` / `.ts` / `.tsx` / `.rs` source file.
- **`spec_version=4`** pinned in specs / bundle.
- **ABI symbol count.** If the engine `.so` has been built, `nm -D --defined-only` must show 58 `engine_*` exported symbols — the authoritative ledger is at the end of `specs/engine-abi-v1.md`. The check reads `build/libdaalcore.so`, not the tracked copy under `client-shell/tauri/src-tauri/resources/`, so without a prior `./daal build` in the same tree it warns rather than fails.
- **Working tree clean.** A dirty tree is a warn, not a fail — but a dirty tree on a release tag is a problem you should fix.

Set `DAAL_RELEASE_STRICT=1` for release cuts. Strict mode turns a dirty tree or missing built engine binary into a hard failure.

A failure (`exit 2`) means a locked invariant was violated and the release MUST NOT ship.

## What runs where

| | local (your laptop) | AppVeyor |
|-|-|-|
| `./daal doctor` | yes | no |
| `./daal test` | yes | **no** |
| the five `tools/` gate scripts | yes, by hand | **no** |
| `./daal release-check` | yes (`DAAL_RELEASE_STRICT=1` for releases) | **no** |
| `./daal build` (Tauri desktop `.deb`) | yes | no — no Linux image |
| Windows `.exe` / `.msi`, macOS `.dmg` / `.app.zip`, iOS `.ipa` | possible but slow | **yes** — this is the only thing it does |
| `./daal package` | yes (when releasing) | no |

This split is **not** intentional; it is where the project ended up after
GitHub Actions was dropped. The consequence is that nothing gives you a
green/red signal on push — the correctness of a commit is only ever
established by a human running `./daal test` locally. Treat adopting a
`test_script` block in `appveyor.yml` as outstanding work, not as
something already covered.

## What's NOT here

- **Code signing.** No code-signing certificate is configured. Windows users will see a SmartScreen warning. Mitigation is a future concern.
- **macOS signing.** macOS DMG packaging is best-effort until Apple notarization credentials are configured.
- **Reproducible builds.** Build outputs are deterministic for Go (`-trimpath` is implied at release time; not yet wired); Tauri and Android are not yet reproducible. This is a V4-era concern.

End — root build script + CI + release runbook.
