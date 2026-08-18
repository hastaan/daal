#!/usr/bin/env bash
# tools/patch-android-manifest.sh — declares the permissions Daal's
# Android shell needs into the Tauri-generated AndroidManifest.xml.
#
# WHY THIS EXISTS
#
# The QR-receive lane (client-ui/src/recipient/RecipientImport.tsx) opens
# in camera mode and calls getUserMedia({video}). On Android that reaches
# the generated RustWebChromeClient.onPermissionRequest, which calls
#   permissionLauncher.launch([Manifest.permission.CAMERA])
# Android returns DENIED IMMEDIATELY, WITHOUT SHOWING A DIALOG, for any
# permission the manifest never declared. So without this patch the
# camera lane cannot work at all — and it fails in the worst possible
# way: the UI classifies the rejection as "denied", then after a retry as
# "blocked", and tells the user to fix it in Settings → Apps → Daal →
# Permissions → Camera. That entry does not exist for a permission that
# was never requested, so the instruction is impossible to follow.
#
# `tauri android init` writes a stock manifest with only INTERNET, and
# src-tauri/gen/android is gitignored and regenerated between sessions,
# so this script — not the generated file — is the durable source of
# truth. Run it after `tauri android init`, before `tauri android build`,
# alongside patch-android-mainactivity.sh and patch-android-signing.sh.
#
# Idempotent: re-running makes no further change.

# WIRED INTO THE BUILD, not left to memory.
#
# gen/android is generated and gitignored, so every patch in tools/patch-android-*
# is undone by `tauri android init` and by any clean checkout. Until 2026-08-18
# nothing ran them: `npm run android:build` was bare `tauri android build`, and
# the four scripts were documented in handovers only.
#
# For THIS script the failure is silent and cruel: without the CAMERA
# declaration Android denies getUserMedia with no dialog at all, the QR scanner
# reports "blocked", and the app then instructs the user to open
# Settings -> Apps -> Daal -> Permissions -> Camera, where Daal has no Camera
# entry because the permission was never declared. A confident, impossible
# instruction.
#
# `npm run android:patch` now runs all four and is chained into android:build
# and android:dev. Keep every one of them idempotent so re-running is free.

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MANIFEST="${MANIFEST:-$ROOT/client-shell/tauri/src-tauri/gen/android/app/src/main/AndroidManifest.xml}"

if [ ! -f "$MANIFEST" ]; then
  echo "FATAL: $MANIFEST not found (run \`tauri android init\` first)" >&2
  exit 1
fi

changed=0

add_line_after_internet() {
  # $1 = literal XML line to ensure is present, $2 = grep -F needle
  if grep -qF "$2" "$MANIFEST"; then
    return 0
  fi
  # Anchor on the INTERNET permission the generator always emits, so the
  # insert point does not depend on line numbers.
  if ! grep -qF 'android.permission.INTERNET' "$MANIFEST"; then
    echo "FATAL: no INTERNET permission line to anchor on in $MANIFEST" >&2
    exit 1
  fi
  python3 - "$MANIFEST" "$1" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2]
src = open(path, encoding='utf-8').read()
needle = '<uses-permission android:name="android.permission.INTERNET" />'
idx = src.index(needle) + len(needle)
open(path, 'w', encoding='utf-8').write(src[:idx] + '\n' + line + src[idx:])
PY
  changed=1
}

# The camera itself. Declared so the runtime request can actually prompt.
add_line_after_internet \
  '    <uses-permission android:name="android.permission.CAMERA" />' \
  'android.permission.CAMERA'

# required="false" keeps the app installable on cameraless devices (and
# on Android TV, which this manifest already targets via leanback). The
# QR lane has a Paste-frames mode that needs no camera, so a missing
# camera must not make the app uninstallable.
add_line_after_internet \
  '    <uses-feature android:name="android.hardware.camera" android:required="false" />' \
  'android.hardware.camera'

if [ "$changed" -eq 1 ]; then
  echo "patched: $MANIFEST"
else
  echo "already current: $MANIFEST"
fi

# Prove the postcondition rather than trusting the edit.
for needle in 'android.permission.CAMERA' 'android.hardware.camera'; do
  grep -qF "$needle" "$MANIFEST" || { echo "FATAL: $needle missing after patch" >&2; exit 1; }
done
