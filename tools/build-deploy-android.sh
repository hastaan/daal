#!/usr/bin/env bash
# tools/build-deploy-android.sh — cross-compiles the daal-deploy CLI
# (cmd/daal-deploy) as libdaal_deploy.so for Android ABIs.
#
# Why a .so: modern Android only permits executing binaries that live
# in the app's extracted native-library directory, so the Go CLI is
# built as a PIE executable (ELF ET_DYN, same container as a shared
# lib) named lib*.so and dropped into jniLibs/<abi>/. At install time
# the platform extracts it next to libdaalcore.so; the Tauri shell
# resolves it there (see resolve_deploy_binary / find_native_lib_dir in
# client-shell/tauri/src-tauri/src/lib.rs) and spawns it as the
# subprocess the FRP publisher wizard drives (FRP-4a onward).
#
# extractNativeLibs=true MUST stay set on the app (it is, via
# android:extractNativeLibs in the plugin/app manifest) or the file is
# never materialised on disk and cannot be exec'd.
#
# Required env:
#   ANDROID_NDK_HOME   path to the NDK root
#   ANDROID_API_LEVEL  minSdkVersion (default 24 — Android 7.0)
#   OUT_DIR            jniLibs root (default: the tauri gen jniLibs dir)
#
# 16 KB PAGES: linked with max-page-size=16384 and verified. On an
# Android 15+ device with a 16 KB-page kernel a 4 KB-aligned executable
# (the Go and NDK r27 default) cannot be exec'd at all.

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
  local out="$OUT_DIR/$abi/libdaal_deploy.so"
  mkdir -p "$(dirname "$out")"
  echo "==> $abi (GOARCH=$goarch CC=$cc)"
  (
    cd "$ROOT/cmd/daal-deploy"
    CC="$NDK_BIN/$cc" \
    CGO_ENABLED=1 \
    GOOS=android \
    GOARCH="$goarch" \
    go build -buildmode=pie \
      -ldflags "-s -w -extldflags=-Wl,-z,max-page-size=16384" \
      -o "$out" \
      .
  )
  ls -la "$out"
  local small
  small="$("$NDK_BIN/llvm-readelf" -lW "$out" | awk '$1 == "LOAD" { print $NF }' | sort -u \
    | while read -r a; do if [ "$((a))" -lt 16384 ]; then printf '%s ' "$a"; fi; done)"
  if [ -n "$small" ]; then
    echo "FATAL: $out has LOAD segments aligned to ${small}— below 16 KB." >&2
    echo "       It could not be run on an Android 15+ device with 16 KB pages." >&2
    exit 1
  fi
}

build_abi arm64 arm64-v8a   "aarch64-linux-android${ANDROID_API_LEVEL}-clang"
build_abi arm   armeabi-v7a "armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
build_abi amd64 x86_64      "x86_64-linux-android${ANDROID_API_LEVEL}-clang"

echo "==> done"
ls -laR "$OUT_DIR"/*/libdaal_deploy.so
