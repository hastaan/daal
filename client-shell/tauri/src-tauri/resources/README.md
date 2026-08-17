This directory is intentionally tracked (via this file) so Tauri's
`resources/*` bundle glob always resolves during local builds.

## The engine library is NOT in git

`libdaalcore.{so,dll,dylib}` is a build output and is gitignored. Build it
before packaging a desktop bundle:

    ./daal build          # Linux: writes resources/libdaalcore.so

CI already does this per platform — see `appveyor.yml` (Windows builds
`libdaalcore.dll`, macOS builds `libdaalcore.dylib`, both straight into this
directory from `./cmd/libdaalcore`).

A bare `npx tauri build` on a fresh Linux clone, with no `./daal build` first,
produces an engine-less bundle that fails at launch. That is the intended
workflow, not a regression.

## Why it is not tracked

It was, until 2026-08-17, and that caused three separate live bugs:

1. **It went stale and nothing noticed.** `engine.rs` resolves its symbols with
   `?`-propagating `dlsym` lookups, so a tracked binary that lags the Rust it
   must satisfy panics at launch before the first frame. The tracked copy was
   missing four required symbols on `main` — the desktop app could not start,
   and no test could see it because a hand-maintained binary in git has nothing
   verifying it.
2. **It made a release gate unpassable.** `./daal build` overwrites this file,
   and `./daal release-check` fails on a dirty tree under
   `DAAL_RELEASE_STRICT=1` — so build-then-release-check could never pass.
3. **It shipped to the wrong platforms.** `resources/*` is a glob and neither
   the Windows nor macOS build removes a checked-in Linux ELF first, so every
   Windows and macOS installer carried a useless ~16 MB Linux `.so`. The same
   bug was already found and patched for Android only (see
   `tools/patch-android-signing.sh`).

Every ordinary `go build ./...` also silently rewrote the tracked file, so the
repository accreted ~8-9 MiB per rebuild-and-commit, forever.
