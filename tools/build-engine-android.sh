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
#
# Outputs:
#   <OUT_DIR>/arm64-v8a/libdaalcore.so
#   <OUT_DIR>/armeabi-v7a/libdaalcore.so
#   <OUT_DIR>/x86_64/libdaalcore.so

set -euo pipefail

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to the Android NDK root}"
: "${ANDROID_API_LEVEL:=24}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs}"

HOST="linux-x86_64"
case "$(uname -s)" in
  Darwin) HOST="darwin-x86_64" ;;
esac
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin"

if [ ! -d "$NDK_BIN" ]; then
  echo "FATAL: NDK toolchain not found at $NDK_BIN" >&2
  exit 1
fi

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
    go build -buildmode=c-shared -tags cshared,singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api \
      -ldflags "-s -w" \
      -o "$out" \
      ./cmd/libdaalcore
  )
  ls -la "$out"
}

# clang wrapper names follow ${triple}${api}-clang convention.
build_abi arm64 arm64-v8a   "aarch64-linux-android${ANDROID_API_LEVEL}-clang"
build_abi arm   armeabi-v7a "armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
build_abi amd64 x86_64      "x86_64-linux-android${ANDROID_API_LEVEL}-clang"

echo "==> done"
ls -laR "$OUT_DIR"
