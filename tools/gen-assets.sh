#!/usr/bin/env bash
# tools/gen-assets.sh — derive every platform's icon asset from the
# canonical sources in client-shared/branding/sources/.
#
# Canonical sources (the ONLY human-editable assets):
#   daal-eagle.svg              — vector master, used as-is for SVG slots
#                                  (in-app glyph, favicon.svg, landing).
#   daal-eagle-transparent.png  — 1024×1024 raster, eagle on transparent.
#                                  Used in-app where the surface bg is dark.
#   daal-eagle-onwhite.png      — 1024×1024 raster, eagle centered on
#                                  OPAQUE WHITE. Used for OS launcher icons
#                                  (Win .ico, macOS .icns, iOS AppIcon,
#                                  Android legacy ic_launcher) so the icon
#                                  appears identical across all OSs.
#
# Android adaptive icon foreground: padded to fit the center 66% safe
# zone so launcher masks (Samsung's squircle, Pixel's circle, OnePlus's
# teardrop) never clip the eagle's wings or head.
#
# This script is idempotent: re-running it overwrites all generated
# outputs from the current sources. Pre-flight invokes it under a PATH
# that only exposes IM7's `magick` to validate Windows CI path.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/client-shared/branding/sources"

# IM7 ships `magick`; IM6 ships `convert`. Prefer IM7 (matches Windows
# AppVeyor which installs IM7 via Chocolatey).
if command -v magick >/dev/null 2>&1; then
    CONVERT="magick"
elif command -v convert >/dev/null 2>&1; then
    CONVERT="convert"
else
    echo "FATAL: neither 'magick' (IM7) nor 'convert' (IM6) on PATH" >&2
    exit 1
fi
echo "==> gen-assets using $(command -v $CONVERT || echo $CONVERT)"

# Sanity-check sources exist.
for f in daal-eagle.svg daal-eagle-transparent.png daal-eagle-onwhite.png; do
    [ -f "$SRC/$f" ] || { echo "FATAL: $SRC/$f missing" >&2; exit 1; }
done
EAGLE_SVG="$SRC/daal-eagle.svg"
EAGLE_T="$SRC/daal-eagle-transparent.png"    # transparent
EAGLE_W="$SRC/daal-eagle-onwhite.png"        # opaque white bg

# det_png — wrap convert with deterministic output flags so Tauri (which
# rejects palette / grayscale-alpha / 16-bit PNGs) always gets 8-bit
# RGBA color-type 6. Also strips timestamps so committed PNGs don't
# have noisy diffs.
#
# CRITICAL: `-depth 8` must be present. Without it, ImageMagick
# preserves the input's bit depth (often 16-bit when the source is
# rendered from SVG), which Tauri's image-rs decoder mis-reads as
# grayscale-alpha producing the runtime panic:
#   "invalid icon: The specified dimensions (32x32) don't match the
#    number of pixels supplied by the rgba argument (2048)"
# (Tauri expected 32*32*4 = 4096 bytes but got 32*32*2 = 2048.)
det_png() {
    local last_idx=$(( $# - 1 ))
    local args=()
    local i=0
    for a in "$@"; do
        if [ "$i" -eq "$last_idx" ]; then
            args+=( -colorspace sRGB -alpha on -type TrueColorAlpha -depth 8 -define png:color-type=6 -define png:bit-depth=8 -strip -define "png:exclude-chunk=time,date" "$a" )
        else
            args+=( "$a" )
        fi
        i=$((i+1))
    done
    "$CONVERT" "${args[@]}"
}

# det_png_rgb — same but for fully-opaque outputs (Apple iOS rejects
# alpha-channel PNGs in some toolchains; this preserves RGB layout
# without an alpha channel). 8-bit depth same as det_png — the Tauri
# 16-bit gotcha applies equally here.
det_png_rgb() {
    local last_idx=$(( $# - 1 ))
    local args=()
    local i=0
    for a in "$@"; do
        if [ "$i" -eq "$last_idx" ]; then
            args+=( -colorspace sRGB -alpha off -type TrueColor -depth 8 -define png:color-type=2 -define png:bit-depth=8 -strip -define "png:exclude-chunk=time,date" "$a" )
        else
            args+=( "$a" )
        fi
        i=$((i+1))
    done
    "$CONVERT" "${args[@]}"
}

# adaptive_fg — produce an Android adaptive-icon foreground PNG. The
# eagle artwork (after tight-trimming any existing transparent padding
# in the source) is scaled to 66% of the canvas and centered. The
# remaining 34% is transparent padding so launcher masks
# (squircle/circle/teardrop) NEVER clip the eagle.
#
# We must trim first because the source EAGLE_T is a 1024×1024 PNG that
# already contains ~20% transparent padding around the eagle. Without
# trimming, "resize to 66%" actually scales the padded PNG, producing
# an eagle that's only ~50% of the safe zone — visually too small.
adaptive_fg() {
    local size="$1"
    local out="$2"
    local inner=$(( size * 66 / 100 ))
    "$CONVERT" "$EAGLE_T" -trim +repage \
        -resize "${inner}x${inner}" \
        -background none -gravity center -extent "${size}x${size}" \
        -colorspace sRGB -alpha on -type TrueColorAlpha -depth 8 \
        -define png:color-type=6 -define png:bit-depth=8 -strip \
        -define "png:exclude-chunk=time,date" "$out"
}

# ---------- Tauri desktop bundler (Win .ico, macOS .icns, Linux deb/rpm icons) ----------
echo "==> Tauri desktop bundler icons (Win/macOS/Linux launcher)"
TAURI_ICONS="$ROOT/client-shell/tauri/src-tauri/icons"
mkdir -p "$TAURI_ICONS"
# Tauri's tauri.conf.json bundle.icon list. ALL on opaque white so the
# OS launcher (Windows taskbar, macOS dock, GNOME shell) shows the same
# icon on every platform regardless of theme.
det_png "$EAGLE_W" -resize 32x32   "$TAURI_ICONS/32x32.png"
det_png "$EAGLE_W" -resize 128x128 "$TAURI_ICONS/128x128.png"
det_png "$EAGLE_W" -resize 256x256 "$TAURI_ICONS/128x128@2x.png"
det_png "$EAGLE_W" -resize 512x512 "$TAURI_ICONS/icon.png"
det_png "$EAGLE_W" -resize 512x512 "$TAURI_ICONS/icon-512.png"

# Windows .ico (multi-size).
TMP_ICO="$(mktemp -d)"
trap 'rm -rf "$TMP_ICO"' EXIT
for sz in 16 24 32 48 64 128 256; do
    det_png "$EAGLE_W" -resize "${sz}x${sz}" "$TMP_ICO/icon-${sz}.png"
done
"$CONVERT" \
    "$TMP_ICO/icon-16.png" \
    "$TMP_ICO/icon-24.png" \
    "$TMP_ICO/icon-32.png" \
    "$TMP_ICO/icon-48.png" \
    "$TMP_ICO/icon-64.png" \
    "$TMP_ICO/icon-128.png" \
    "$TMP_ICO/icon-256.png" \
    -strip "$TAURI_ICONS/icon.ico"

# macOS .icns: png2icns if available, else iconutil, else fallback.
if command -v png2icns >/dev/null 2>&1; then
    P2I="$(mktemp -d)"
    for sz in 16 32 64 128 256 512 1024; do
        det_png "$EAGLE_W" -resize "${sz}x${sz}" "$P2I/icon-${sz}.png"
    done
    png2icns "$TAURI_ICONS/icon.icns" \
        "$P2I/icon-16.png" "$P2I/icon-32.png" "$P2I/icon-128.png" \
        "$P2I/icon-256.png" "$P2I/icon-512.png" "$P2I/icon-1024.png"
    rm -rf "$P2I"
elif command -v iconutil >/dev/null 2>&1; then
    ICONSET="$(mktemp -d)/Daal.iconset"
    mkdir -p "$ICONSET"
    for entry in \
        "16:icon_16x16" "32:icon_16x16@2x" "32:icon_32x32" \
        "64:icon_32x32@2x" "128:icon_128x128" "256:icon_128x128@2x" \
        "256:icon_256x256" "512:icon_256x256@2x" "512:icon_512x512" \
        "1024:icon_512x512@2x"; do
        sz="${entry%%:*}"; name="${entry##*:}"
        det_png "$EAGLE_W" -resize "${sz}x${sz}" "$ICONSET/${name}.png"
    done
    iconutil -c icns -o "$TAURI_ICONS/icon.icns" "$ICONSET"
    rm -rf "$(dirname "$ICONSET")"
else
    echo "WARN: png2icns/iconutil missing; using 512×512 PNG as icon.icns" >&2
    cp -f "$TAURI_ICONS/icon.png" "$TAURI_ICONS/icon.icns"
fi

# Desktop tray icons (these keep transparency — the system tray bg is
# themed by the OS so we must NOT bake white in here).
det_png "$EAGLE_T" -resize 32x32 "$TAURI_ICONS/tray-on.png"
det_png "$EAGLE_T" -resize 32x32 -modulate 100,0,100 "$TAURI_ICONS/tray-off.png"

# ---------- Android (Tauri scaffold) ----------
ANDROID_RES="$ROOT/client-shell/tauri/src-tauri/gen/android/app/src/main/res"
if [ -d "$ANDROID_RES" ]; then
    echo "==> Android mipmaps (legacy + adaptive)"
    declare -A ABUCKETS=([mdpi]=48 [hdpi]=72 [xhdpi]=96 [xxhdpi]=144 [xxxhdpi]=192)
    for dpi in "${!ABUCKETS[@]}"; do
        sz="${ABUCKETS[$dpi]}"
        # Legacy ic_launcher.png (Android 7-) — full-bleed eagle on white.
        det_png "$EAGLE_W" -resize "${sz}x${sz}" "$ANDROID_RES/mipmap-${dpi}/ic_launcher.png"
        det_png "$EAGLE_W" -resize "${sz}x${sz}" "$ANDROID_RES/mipmap-${dpi}/ic_launcher_round.png"
        # Adaptive foreground (Android 8+) — eagle scaled to 66% safe zone,
        # transparent padding. Composited at runtime against the
        # ic_launcher_background color (which we set to white).
        adaptive_fg "$sz" "$ANDROID_RES/mipmap-${dpi}/ic_launcher_foreground.png"
    done

    # Adaptive background color → WHITE (was teal #033E51 which clipped to
    # a teal squircle on Samsung One UI). White makes the launcher mask
    # invisible regardless of shape because eagle + white-padding = white-square.
    BG_XML="$ANDROID_RES/values/ic_launcher_background.xml"
    if [ -f "$BG_XML" ]; then
        cat > "$BG_XML" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="ic_launcher_background">#FFFFFF</color>
</resources>
EOF
    fi
fi

# ---------- iOS AppIcon (Tauri scaffold) ----------
IOS_ICONSET="$ROOT/client-shell/tauri/src-tauri/gen/apple/Assets.xcassets/AppIcon.appiconset"
if [ -d "$IOS_ICONSET" ]; then
    echo "==> iOS AppIcon (Tauri scaffold)"
    for sz in 20 29 40 58 60 76 80 87 120 152 167 180 1024; do
        det_png_rgb "$EAGLE_W" -resize "${sz}x${sz}" "$IOS_ICONSET/AppIcon-${sz}.png"
    done
fi

# ---------- client-ui/public (in-app webview favicons + apple touch) ----------
echo "==> client-ui/public/ (in-app web favicons)"
CUI="$ROOT/client-ui/public"
mkdir -p "$CUI"
det_png "$EAGLE_W" -resize 16x16  "$CUI/daal-favicon-16.png"
det_png "$EAGLE_W" -resize 32x32  "$CUI/daal-favicon-32.png"
det_png "$EAGLE_W" -resize 96x96  "$CUI/daal-favicon-96.png"
det_png "$EAGLE_W" -resize 180x180 "$CUI/daal-icon-bg-180.png"
# Multi-size .ico for browsers that prefer the legacy format.
TMP_ICO2="$(mktemp -d)"
for sz in 16 24 32 48 64; do
    det_png "$EAGLE_W" -resize "${sz}x${sz}" "$TMP_ICO2/f-${sz}.png"
done
"$CONVERT" "$TMP_ICO2"/f-16.png "$TMP_ICO2"/f-24.png "$TMP_ICO2"/f-32.png \
    "$TMP_ICO2"/f-48.png "$TMP_ICO2"/f-64.png -strip "$CUI/daal-favicon.ico"
rm -rf "$TMP_ICO2"

# ---------- landing/public (gh-pages site) ----------
echo "==> landing/public/ (landing site favicons)"
LP="$ROOT/landing/public"
mkdir -p "$LP"
det_png "$EAGLE_W" -resize 16x16  "$LP/daal-favicon-16.png"
det_png "$EAGLE_W" -resize 32x32  "$LP/daal-favicon-32.png"
det_png "$EAGLE_W" -resize 96x96  "$LP/daal-favicon-96.png"
det_png "$EAGLE_W" -resize 180x180 "$LP/daal-icon-bg-180.png"
cp -f "$CUI/daal-favicon.ico" "$LP/daal-favicon.ico"
# favicon.svg → vector master, for browsers that prefer SVG (Firefox,
# modern Chrome). Always serves the cleanest, scaling-aware icon.
cp -f "$EAGLE_SVG" "$LP/favicon.svg"

echo "==> done"
