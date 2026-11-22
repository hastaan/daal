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

# "Open with Daal" and "Share to Daal" (UI spec G.1, X-13).
#
# A person inside Iran gets their file in Telegram or WhatsApp. Without
# these filters Daal is not offered when they tap it, and the only way in
# is Save -> open Daal -> Add my file -> Choose a file -> Downloads -> the
# file (I-1, 9 taps). With them it is: tap the file, Daal (4).
#
# The filters only bring the file to the page. NOTHING IS IMPORTED: the
# daal-platform plugin holds it (platform/OpenedFiles.kt; which intents
# are taken is decided in vpn/OpenedIntent.kt), the page takes it with
# `take_opened_file` and shows it, and the person decides. The activity is
# singleTask (the generator's default, enforced below), so a second file
# while Daal runs reaches onNewIntent and arrives as the
# `daal://opened-file` event instead of starting a second Daal.
#
#   1. VIEW of a content:// URI whose name ends in .sbpx / .sbp, any type.
#      pathPattern is not a real regex (".*" does not backtrack over a
#      dot), so the usual one-to-four-dots ladder is listed.
#   2. VIEW of a content:// URI typed application/octet-stream, any name:
#      messengers hand over a URI with no file name in it, typed as the
#      sender typed it (Daal's own share sheet sends octet-stream).
#   3. SEND of one file typed application/octet-stream (messenger "Share").
#   4. SEND of text/plain: a Daal file that was pasted into a chat as text.
#
# file:// is not listed: no app may send one since Android 7, and the
# plugin refuses it (it would be read with Daal's own rights).
#
# The block sits between BEGIN/END markers and is rewritten on every run,
# so a change here reaches a manifest an earlier run patched.
open_with_out="$(python3 - "$MANIFEST" <<'PY'
import re, sys
path = sys.argv[1]
src = open(path, encoding='utf-8').read()
orig = src

BEGIN = '<!-- daal:open-with BEGIN (tools/patch-android-manifest.sh) -->'
END = '<!-- daal:open-with END -->'
I = ' ' * 12   # inside <activity>
J = ' ' * 16   # inside <intent-filter>

def data(attr, value):
    return '%s<data android:%s="%s" />' % (J, attr, value)

def intent_filter(action, datas):
    return '\n'.join(
        ['%s<intent-filter>' % I,
         '%s<action android:name="android.intent.action.%s" />' % (J, action),
         '%s<category android:name="android.intent.category.DEFAULT" />' % J]
        + datas
        + ['%s</intent-filter>' % I])

# In the manifest a literal dot in a pathPattern is written "\\." .
patterns = []
for ext in ('sbpx', 'sbp'):
    for dots in range(4):
        patterns.append('.*' + '\\\\..*' * dots + '\\\\.' + ext)

block = '\n'.join([
    BEGIN,
    intent_filter('VIEW', [data('scheme', 'content'), data('host', '*'), data('mimeType', '*/*')]
                  + [data('pathPattern', p) for p in patterns]),
    intent_filter('VIEW', [data('scheme', 'content'), data('mimeType', 'application/octet-stream')]),
    intent_filter('SEND', [data('mimeType', 'application/octet-stream')]),
    intent_filter('SEND', [data('mimeType', 'text/plain')]),
    I + END,
])

# The main activity's opening tag; make it singleTask.
m = re.search(r'<activity\b[^>]*android:name="\.MainActivity"[^>]*>', src, re.S)
if not m:
    sys.stderr.write('FATAL: no .MainActivity <activity> in %s\n' % path)
    sys.exit(1)
tag = m.group(0)
if 'android:launchMode=' in tag:
    new_tag = re.sub(r'android:launchMode="[^"]*"', 'android:launchMode="singleTask"', tag)
else:
    new_tag = tag.replace('<activity', '<activity\n            android:launchMode="singleTask"', 1)
src = src[:m.start()] + new_tag + src[m.start() + len(tag):]
act_start = m.start()
act_end = src.index('</activity>', act_start)

if BEGIN in src:
    b = src.index(BEGIN)
    e = src.index(END, b) + len(END)
    if not (act_start < b < act_end):
        sys.stderr.write('FATAL: the open-with block is outside .MainActivity\n')
        sys.exit(1)
    src = src[:b] + block.lstrip() + src[e:]
else:
    launcher = src.find('android.intent.category.LAUNCHER', act_start, act_end)
    if launcher < 0:
        sys.stderr.write('FATAL: no LAUNCHER intent-filter in .MainActivity to anchor on\n')
        sys.exit(1)
    close = src.index('</intent-filter>', launcher) + len('</intent-filter>')
    src = src[:close] + '\n' + I + block + src[close:]

if src != orig:
    open(path, 'w', encoding='utf-8').write(src)
    print('changed')
PY
)" || exit 1
[ "$open_with_out" = "changed" ] && changed=1

if [ "$changed" -eq 1 ]; then
  echo "patched: $MANIFEST"
else
  echo "already current: $MANIFEST"
fi

# The FileProvider's paths (@xml/file_paths, which the generated manifest's
# <provider android:authorities="${applicationId}.fileprovider"> names).
#
# MainActivity.shareFile hands a file to the share sheet through that
# provider, and FileProvider refuses any file outside the roots listed
# here ("Failed to find configured root"). The generator lists only the
# cache and external storage. Daal's own files live in the app's files
# directory, under the state directory <filesDir>/daal:
#
#   daal/staging/        relay packs, people's files and the backup handed
#                        to the share sheet (staging moved into the state
#                        directory on 2026-11-20; it was in the cache before)
#   daal/fieldprobe-out/ the sealed network-test report, written there by
#                        the engine and removed by it (specs/field-probe-v2.md)
#
# Nothing else under filesDir is shareable: the database, the keys and the
# engine's store stay out of reach of every other app. Rewritten whole on
# every run, so it is idempotent.
FILE_PATHS="${FILE_PATHS:-$(dirname "$MANIFEST")/res/xml/file_paths.xml}"
mkdir -p "$(dirname "$FILE_PATHS")"
paths_want='<?xml version="1.0" encoding="utf-8"?>
<!-- Written by tools/patch-android-manifest.sh: edit it there. -->
<paths xmlns:android="http://schemas.android.com/apk/res/android">
  <external-path name="my_images" path="." />
  <cache-path name="my_cache_images" path="." />
  <files-path name="daal_staging" path="daal/staging/" />
  <files-path name="daal_fieldprobe" path="daal/fieldprobe-out/" />
</paths>'
if [ ! -f "$FILE_PATHS" ] || [ "$(cat "$FILE_PATHS")" != "$paths_want" ]; then
  printf '%s\n' "$paths_want" > "$FILE_PATHS"
  echo "patched: $FILE_PATHS"
else
  echo "already current: $FILE_PATHS"
fi
grep -qF 'daal/fieldprobe-out/' "$FILE_PATHS" || { echo "FATAL: fieldprobe path missing after patch" >&2; exit 1; }

# Prove the postcondition rather than trusting the edit.
for needle in 'android.permission.CAMERA' 'android.hardware.camera' \
  'daal:open-with BEGIN' 'android.intent.action.SEND' 'android:mimeType="text/plain"' \
  'android:launchMode="singleTask"'; do
  grep -qF "$needle" "$MANIFEST" || { echo "FATAL: $needle missing after patch" >&2; exit 1; }
done
