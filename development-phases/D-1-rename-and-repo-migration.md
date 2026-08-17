# Phase D-1 — Daal Public Release Repository

**Status:** **SHIPPED.** Handover: `development-phases/D-1-handover.md`. (The "`v0.1.0` release CI is the active gate" line is obsolete twice over: the rename landed, and there is no release CI — see `docs/build-and-release.md`.)
**Maturity target:** first public Daal source snapshot.
**Engine version target:** `daal-core 0.9.0+v3-share`.
**ABI release surface target:** unchanged at 48 exported `engine_*`
symbols.
**Successor:** Phase D-2 - Daal GUI rebuild.

---

## 1. Goal

Publish Daal from a clean public release repository:

1. The working tree is `/home/daal`.
2. The GitHub repository is `hastaan/daal`.
3. The public repository starts with a single signed `main` commit.
4. Each release version is represented by one signed snapshot commit
   and one signed `v*` tag.
5. `CHANGELOG.md` reads as first-release information, not as internal
   process history.
6. Public source text, comments, docs, package identifiers, tracked
   paths, filenames, release metadata, and CI artefacts use Daal naming.

This phase does not redesign the UI, change engine behavior, change
wire formats, or change persistent-state schemas.

---

## 2. Locked Decisions

| Topic | Decision |
|---|---|
| Public product name | **Daal** (`دال` where Persian typography is used). |
| Public repo | `hastaan/daal`. |
| Git history | Public release repo uses clean snapshots only; development history is not pushed. |
| Release commit policy | One signed root snapshot commit per public version. |
| Tag policy | Signed `v*` tags only; protected from deletion and non-fast-forward updates. |
| Branch policy | `main` requires signed commits and linear history; force-push disabled after snapshot update. |
| Changelog policy | First-release notes only. Internal process notes stay out of public release notes. |
| Engine ABI | Unchanged; ABI symbol count remains 48. |
| User-facing "Subscriptions" label | Stays for D-1; the "Sources" UI label belongs to D-2. |

---

## 3. D-1 Scope

### Repository

- `origin` points at `https://github.com/hastaan/daal.git`.
- `main` is a clean signed snapshot commit.
- `v0.1.0` is a signed tag on the snapshot commit.
- Branch protection is active on `main`.
- A tag ruleset protects `refs/tags/v*`.

### Naming Sweep

- Absolute paths use `/home/daal`.
- Public package identifiers use Daal names, including Android
  `ai.daal.app`.
- Desktop, Android, iOS, docs, workflow files, comments, and tracked
  paths use Daal naming.
- The public repository contains no retired development-name text or
  tracked filenames.

### Release Metadata

- Desktop product name, window title, bundle metadata, installer names,
  AppImage metadata, and DMG metadata use Daal.
- Android app name, notification text, package label, launcher icon, and
  release APK names use Daal.
- iOS bundle display names use Daal.
- Release asset normalization is idempotent, so CI can pass whether
  a bundler already emitted the target filename or not.

### Documentation

- `README.md` presents Daal as the public product.
- `CHANGELOG.md` contains only first-release notes for `0.1.0`.
- `docs/release-snapshot-policy.md` describes the one-commit-per-version
  public release repository policy.

---

## 4. Acceptance Criteria

- [x] `hastaan/daal` exists and is public.
- [x] Android release secrets are configured.
- [x] Branch protection is active on `main`.
- [x] Tag ruleset protects `refs/tags/v*`.
- [x] Local working tree is `/home/daal`.
- [x] Public snapshot uses a single signed root commit on `main`.
- [x] `v0.1.0` is a signed tag.
- [x] `CHANGELOG.md` is first-release information only.
- [x] `README.md` points at the Daal public release.
- [x] Daal naming is used across source text, comments, docs, package
      identifiers, tracked paths, and CI metadata.
- [x] Local `git diff --check` passes.
- [x] Local text/path audit for retired names passes.
- [x] Local Android unit tests pass.
- [x] Local Go ABI tests pass with gomobile build tags.
- [ ] GitHub `ci` workflow is green for the final snapshot.
- [ ] GitHub `desktop` workflow is green for the final snapshot.
- [ ] GitHub `v0.1.0 release` workflow is green for the final tag.
- [ ] Release assets exist for Linux, Windows, macOS best-effort, and
      Android.
- [ ] Hardware smoke is completed on available Linux, Windows, Android,
      and macOS targets.

---

## 5. Verification Commands

```sh
git log --show-signature -1
git tag -v v0.1.0
git ls-remote origin refs/heads/main refs/tags/v0.1.0
git diff --check
latin='hy''dra'
persian='هی''درا'
rg -n -i "${latin}|${persian}" . --hidden -g '!.git' -g '!**/node_modules/**' -g '!**/target/**' -g '!build/**'
find . -path ./.git -prune -o -name node_modules -prune -o -name target -prune -o -name build -prune -o -iname "*${latin}*" -print
env GOCACHE=/tmp/daal-go-build /usr/local/go/bin/go test -tags gomobile ./abi
env ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk GRADLE_USER_HOME=/tmp/daal-gradle-home ./gradlew --no-daemon testDebugUnitTest
DAAL_RELEASE_STRICT=1 ./daal release-check
gh run list -R hastaan/daal --limit 5
gh run watch -R hastaan/daal
```

The text/path audit commands are expected to print no matches.
