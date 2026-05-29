# D-1 — Handover for repo bootstrap and tag cut

**State at handover.** All in-tree D-1 work is complete and committed-ready
on the `/home/daal/` working tree. `./daal release-check` is green;
`./daal test` is green; the CI rename gate passes; all platform asset
catalogs are wired.

Two categories of work remain:

1. **Operations on github.com** — creating the `hastaan/daal` repo,
   pushing the snapshot, configuring secrets and rulesets. These cannot
   be done from inside the tree; a human (or a tool with a GitHub PAT)
   must run them.
2. **Working-directory rename** — `mv /home/daal /home/daal` plus a
   path sweep. This is mechanical but disruptive (every absolute path
   in the dev environment changes), so it's been deferred to the very
   end so it doesn't invalidate other tooling mid-execution.

This doc is the runbook for both.

---

## 1. Create the `daal` repo

```sh
gh repo create hastaan/daal \
  --public \
  --license GPL-3.0 \
  --description "Daal — anti-censorship app and relay-publishing toolkit.." \
  --homepage "https://hastaan.github.io/daal/"
```

If you don't yet have the GitHub Pages landing site (D-3), drop
`--homepage`.

## 2. Configure GitHub Actions secrets

Mirror the Daal repo's secrets. The release workflow reads:

| Secret | Used by |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | Android signing |
| `ANDROID_KEYSTORE_PASSWORD` | Android signing |
| `ANDROID_KEY_ALIAS` | Android signing |

```sh
gh secret set ANDROID_KEYSTORE_BASE64 -R hastaan/daal < /path/to/keystore.b64
gh secret set ANDROID_KEYSTORE_PASSWORD -R hastaan/daal
gh secret set ANDROID_KEY_ALIAS -R hastaan/daal
```

Windows / macOS code-signing is **not currently consumed** by the
workflow. macOS `.dmg` ships unsigned in v0.1.0 and will surface a
Gatekeeper warning; Windows NSIS ships unsigned and will surface
SmartScreen. Both are documented in the v0.1.0 release notes as
experimental until the certificates are in place.

## 3. Configure branch protection + tag protection

Branch protection on `main` (covers PRs and force-push):

```sh
gh api -X PUT repos/hastaan/daal/branches/main/protection \
  -f required_status_checks='{"strict":true,"contexts":["lint + test + invariants"]}' \
  -F enforce_admins=false \
  -F required_pull_request_reviews='{"required_approving_review_count":0}' \
  -F restrictions=null \
  -F allow_force_pushes=false \
  -F allow_deletions=false \
  -F required_linear_history=true
```

Tag protection on `v*` (separate from branch protection — branch
protection does not cover tags):

```sh
gh api -X POST repos/hastaan/daal/tags/protection \
  -f pattern='v*'
```

If `gh api` for tag protection isn't available in your `gh` version,
configure it via the repository **Settings → Tags → New rule**, pattern
`v*`. (The legacy "Tag protection" UI is being merged into Rulesets;
either route works.)

## 4. Working-directory rename + path sweep

```sh
# 1. Move the working tree.
mv /home/daal /home/daal
cd /home/daal

# 2. Sweep absolute paths in scripts and configs.
rg -l '/home/daal' --type=yaml --type=sh --type=md . | \
  xargs sed -i 's|/home/daal|/home/daal|g'

# 3. Sanity-check that no `/home/daal` survives.
rg -n '/home/daal' .   # should print nothing

# 4. Verify the public build script has the Daal name.
ls ./daal
./daal doctor
```

> **Note.** If you're running under VS Code / a Droid session that has
> `/home/daal` open as a workspace, close and reopen as `/home/daal/`
> before continuing.

## 5. Bootstrap the new repo from a clean snapshot

The clean-snapshot rule is non-negotiable — no Daal-era commits, no
tags, no branches are migrated. From the renamed working tree:

```sh
cd /home/daal

# 1. Detach from the old git history. We replace .git entirely.
rm -rf .git
git init -b main

# 2. Identity.
git config user.name  "hastaan"
git config user.email "hastaan@gmail.com"

# 3. Single squashed initial commit.
git add -A
git commit -S -m "Initial public release: Daal v0.1.0

Public release snapshot created. See CHANGELOG.md and docs/release-snapshot-policy.md.

The engine, ABI, and internal code identifiers are unchanged from the
public launch snapshot.
"

# 4. Push.
git remote add origin git@github.com:hastaan/daal.git
git push -u origin main

# 5. Tag v0.1.0 (signed) and push the tag — triggers release.yml.
git tag -s v0.1.0 -m "Daal 0.1.0"
git push origin v0.1.0
```

## 6. Verify the release

After pushing `v0.1.0`, `release.yml` runs the gate, builds desktop +
Android bundles on three OSes, normalizes asset names, and creates the
GitHub Release. The expected published assets are:

| Asset | Where it comes from |
|---|---|
| `daal_0.1.0_amd64.deb`            | Linux runner — Tauri deb |
| `Daal_0.1.0_amd64.AppImage`       | Linux runner — Tauri AppImage |
| `Daal_0.1.0_x64-setup.exe`        | Windows runner — Tauri NSIS |
| `Daal_0.1.0_aarch64.dmg`          | macOS runner — Tauri DMG (unsigned) |
| `Daal-v0.1.0-arm64-v8a.apk`       | Android job |
| `Daal-v0.1.0-armeabi-v7a.apk`     | Android job |

If `Daal-v0.1.0-universal.apk` appears it's a multi-ABI fallback —
inspect the gradle log; ABI splits are configured to produce per-arch
APKs only.

## 7. Smoke install on real hardware

The CI smoke step verifies the app launches and stays alive 8 s under
xvfb. For a release, also smoke-test:

| Platform | Smoke checklist |
|---|---|
| Linux x64 | Install `daal_0.1.0_amd64.deb`. App drawer entry shows "Daal" with the phoenix icon. Launching opens a window titled "Daal". Engine reports `daal-core 0.9.0+v3-share` in Settings → Status. |
| Windows 10/11 x64 | Run `Daal_0.1.0_x64-setup.exe`. Start Menu folder is "Daal". Window title is "Daal". |
| Android arm64 | Install `Daal-v0.1.0-arm64-v8a.apk`. Launcher icon is the phoenix on brand teal. App label is "Daal" / "دال". Foreground notification on connect says "Daal is idle." / "Connected via …". |
| macOS aarch64 | Open the DMG. Drag to Applications. Right-click → Open to bypass the Gatekeeper warning (unsigned in v0.1.0). |
| iOS | TestFlight build from the Xcode project; AppIcon now resolves from `Assets.xcassets/AppIcon.appiconset`. |

## 8. Archive the old `daal` working tree

The old `daal` Daal-era checkout has been retained on this dev
workstation only (no force-archive of any GitHub repo). Once `v0.1.0`
ships and is verified, the dev-side archive can be tarballed for
posterity:

```sh
tar czf ~/archives/daal-private-snapshot-$(date +%Y%m%d).tgz \
  --exclude='.git/objects/pack/*.pack' \
  /home/daal/   # whatever path the dev's `daal` checkout lived at
```

(There is no GitHub-side archive step — the `daal` repo never went
public.)

---

## D-1 acceptance gate (final check before declaring done)

- [x] `VERSION` is `0.1.0`
- [x] `tauri.conf.json` `productName` is `Daal`; identifier is unchanged
- [x] Android `app_name` is `Daal` / `دال`; package id `ai.daal.app` unchanged
- [x] iOS `CFBundleDisplayName` is `Daal`; bundle id unchanged
- [x] All four desktop i18n files (base + wizard, EN + FA) use Daal
- [x] iOS `.strings` files use Daal
- [x] Tauri icons regenerated from `client-shared/branding/favicon-512x512.png`
- [x] Android adaptive-icon resources created (mipmap-{anydpi-v26, mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi})
- [x] Android manifest references mipmap icon + roundIcon + colour
- [x] iOS `Assets.xcassets/AppIcon.appiconset` exists with 1024x1024 master
- [x] CI rename gate passes
- [x] `./daal release-check` passes
- [x] `./daal test` passes
- [x] CHANGELOG `[0.1.0]` section added
- [x] `docs/release-snapshot-policy.md` exists
- [x] `client-shared/branding/README.md` exists
- [ ] **Remaining:** new repo bootstrap (this doc, §1–§5)
- [ ] **Remaining:** working-directory rename (§4)
- [ ] **Remaining:** signed `v0.1.0` tag pushed and Release published (§5–§6)
- [ ] **Remaining:** real-hardware smoke on each platform (§7)
