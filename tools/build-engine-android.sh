#!/usr/bin/env bash
# tools/build-engine-android.sh — cross-compiles libdaalcore.so for
# Android ABIs using the Android NDK. The Tauri Mobile shell links
# these and packs them into the APK's lib/<abi>/ directories where
# the system linker can find them.
#
# Required env:
#   ANDROID_NDK_HOME   path to the NDK root (CI sets this from setup-android)
#   ANDROID_API_LEVEL  minSdkVersion the .so will target (default 24 — Android 7.0)
#   OUT_DIR            where to drop jniLibs/<abi>/libdaalcore.so
#                      (default: gen/android/app/src/main/jniLibs)
#   CRONET_LIB_DIR     where to find prebuilt libcronet.so per ABI, as
#                      <CRONET_LIB_DIR>/<abi>/libcronet.so (default:
#                      $ROOT/vendor/cronet). See "naive" below.
#   DAAL_NAIVE         1 (default) build with the naive/Cronet outbound,
#                      0 leave it out.
#
# Outputs:
#   <OUT_DIR>/arm64-v8a/libdaalcore.so
#   <OUT_DIR>/armeabi-v7a/libdaalcore.so
#   <OUT_DIR>/x86_64/libdaalcore.so
#   plus <OUT_DIR>/<abi>/libcronet.so when one was found (see below)
#
# ---------------------------------------------------------------------
# naive / Cronet — what a fresh machine actually needs
#
# The naive tier is field-proven on device, but that APK was built by
# hand during the Cronet work and this script used to omit the tag, so a
# clean rebuild from main silently produced an engine where every naive
# route dies at connect with "naive outbound is not included in this
# build". Two things are needed to reproduce the hand-built engine, and
# they are independent:
#
#  1. BUILD TAGS: `with_naive_outbound,with_purego`. The tag alone does
#     NOT build — verified: cronet-go's default path is cgo and links
#     the prebuilt libcronet.a, whose Chromium-produced relocations the
#     NDK linker cannot process (the same "relocation 315" wall that
#     tools/cronet/build-libcronet-android.sh exists to work around).
#     `with_purego` switches cronet-go to dlopen()ing libcronet.so at
#     runtime instead, so nothing is linked at build time. That is why
#     both tags go together and why core/engine/cronet_loader_naive.go
#     is gated on `with_naive_outbound && with_purego`.
#
#  2. RUNTIME LIBRARY: libcronet.so in the APK's lib/<abi>/. This is
#     the part a fresh machine will not have. Producing it needs
#     cronet-go's Chromium toolchain (a multi-GB one-time download) and
#     tools/cronet/build-libcronet-android.sh. Nothing here can bootstrap
#     that, so this script only *copies* an already-built one from
#     CRONET_LIB_DIR.
#
# Because (1) alone always links cleanly, the tags are on by default:
# a machine without libcronet.so still gets a working engine for the
# other tiers, and gets a loud warning that the naive tier will fail at
# connect (core/engine/cronet_loader_naive.go deliberately treats a
# missing library as non-fatal — only naive routes need it). Set
# DAAL_NAIVE=0 to build the engine without the naive outbound at all,
# which trades the runtime cronet error for sing-box's clearer
# "not included in this build" error.
# ---------------------------------------------------------------------

set -euo pipefail

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to the Android NDK root}"
: "${ANDROID_API_LEVEL:=24}"
: "${DAAL_NAIVE:=1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs}"
CRONET_LIB_DIR="${CRONET_LIB_DIR:-$ROOT/vendor/cronet}"

# Tags shared by every ABI. Keep this in one place: an engine built with
# a different tag set is a different engine, and the failure mode is a
# route that exists in the pack and cannot be dialled on the phone.
TAGS="cshared,singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api"
if [ "$DAAL_NAIVE" != "0" ]; then
  TAGS="$TAGS,with_naive_outbound,with_purego"
fi

HOST="linux-x86_64"
case "$(uname -s)" in
  Darwin) HOST="darwin-x86_64" ;;
esac
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin"

if [ ! -d "$NDK_BIN" ]; then
  echo "FATAL: NDK toolchain not found at $NDK_BIN" >&2
  exit 1
fi

# stage_cronet copies a prebuilt libcronet.so next to the engine for one
# ABI, or explains why the naive tier will not work without it. Never
# fatal: every other tier builds and runs fine without Cronet.
stage_cronet() {
  local abi="$1"
  local dest="$OUT_DIR/$abi/libcronet.so"
  local src="$CRONET_LIB_DIR/$abi/libcronet.so"
  if [ "$DAAL_NAIVE" = "0" ]; then
    return 0
  fi
  if [ -f "$src" ]; then
    cp -f "$src" "$dest"
    echo "    libcronet.so <- $src ($(stat -c%s "$dest" 2>/dev/null || echo ?) bytes)"
    return 0
  fi
  if [ -f "$dest" ]; then
    # Already staged by a previous run (or by hand — this is how the
    # field-proven APK got one). Leave it alone.
    echo "    libcronet.so already present at $dest"
    return 0
  fi
  echo "    WARNING: no libcronet.so for $abi." >&2
  echo "             The engine has the naive outbound compiled in, but naive routes" >&2
  echo "             will fail at connect until $dest exists." >&2
  echo "             Build one with tools/cronet/build-libcronet-android.sh (needs" >&2
  echo "             cronet-go's Chromium toolchain, multi-GB one-time download) and" >&2
  echo "             drop it at $src, or set DAAL_NAIVE=0 to build without naive." >&2
}

build_abi() {
  local goarch="$1" abi="$2" cc="$3"
  local out="$OUT_DIR/$abi/libdaalcore.so"
  mkdir -p "$(dirname "$out")"
  echo "==> $abi (GOARCH=$goarch CC=$cc)"
  (
    cd "$ROOT/core"
    CC="$NDK_BIN/$cc" \
    CGO_ENABLED=1 \
    GOOS=android \
    GOARCH="$goarch" \
    go build -buildmode=c-shared -tags "$TAGS" \
      -ldflags "-s -w" \
      -o "$out" \
      ./cmd/libdaalcore
  )
  ls -la "$out"
  stage_cronet "$abi"
}

echo "==> tags: $TAGS"

# clang wrapper names follow ${triple}${api}-clang convention.
build_abi arm64 arm64-v8a   "aarch64-linux-android${ANDROID_API_LEVEL}-clang"
build_abi arm   armeabi-v7a "armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
build_abi amd64 x86_64      "x86_64-linux-android${ANDROID_API_LEVEL}-clang"

echo "==> done"
ls -laR "$OUT_DIR"
