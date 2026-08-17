#!/usr/bin/env bash
# tools/patch-android-icons.sh — regenerate the Android launcher icons from
# the daal eagle. Must run AFTER `tauri android init` (which drops the stock
# green two-circle placeholder into gen/android) and before packaging, the
# same way patch-android-mainactivity.sh re-applies the Kotlin layer.
#
# Source of truth: client-shared/branding/daal-app-icon-1024.png
# (the eagle centered on the app's dark-teal background, adaptive-safe).
#
# Regenerate that source from the raw eagle with:
#   python3 tools/make-android-icon-source.py   (see that file)
#
# SIDE EFFECT, read before committing: `tauri icon` has no per-platform
# switch, so it also rewrites the DESKTOP icon set in
# src-tauri/icons/. Six of those files are tracked and bundled
# (32x32.png, 128x128.png, 128x128@2x.png, icon.icns, icon.ico,
# icon.png — see tauri.conf.json) and nothing in any build regenerates
# them, so if the eagle changed they must be committed here or the
# desktop app ships the old icon. The rest of what it drops there
# (Square*Logo.png, 64x64.png, ios/) is unreferenced Windows/iOS output
# and is gitignored.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/client-shared/branding/daal-app-icon-1024.png"
TAURI_DIR="$ROOT/client-shell/tauri"
RES="$TAURI_DIR/src-tauri/gen/android/app/src/main/res"
BG="#0D2E35"  # matches --bg oklch(28% 0.04 215)

[ -f "$SRC" ] || { echo "FATAL: icon source missing: $SRC" >&2; exit 1; }
[ -d "$RES" ] || { echo "FATAL: android res dir missing (run 'tauri android init' first): $RES" >&2; exit 1; }

echo "==> regenerating Android icons from $SRC"
( cd "$TAURI_DIR" && npx tauri icon "$SRC" )

# tauri's adaptive icon references @color/ic_launcher_background; pin it to the
# brand dark-teal so the maskable edges match the baked-in background.
cat > "$RES/values/ic_launcher_background.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<resources>
  <color name="ic_launcher_background">$BG</color>
</resources>
EOF
# drop the stock green template vector if tauri left it behind
rm -f "$RES/drawable/ic_launcher_background.xml"

echo "==> Android launcher icons updated (daal eagle on $BG)"
