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
#   CRONET_LIB_DIR     optional: a directory of ALREADY-BUILT libraries, as
#                      <CRONET_LIB_DIR>/<abi>/libcronet.so with its
#                      .stamp beside it (default: $ROOT/vendor/cronet,
#                      which normally does not exist). Without one the
#                      library is built here; see "naive" below.
#   DAAL_NAIVE         1 (default) build with the naive/Cronet outbound,
#                      0 leave it out.
#
# Outputs, for each of arm64-v8a, armeabi-v7a, x86_64:
#   <OUT_DIR>/<abi>/libdaalcore.so
#   <OUT_DIR>/<abi>/libcronet.so  and  libcronet.so.stamp   (unless DAAL_NAIVE=0)
#
# ---------------------------------------------------------------------
# naive / Cronet — the engine and libcronet.so are ONE unit
#
# Two things make the naive tier work on a phone, and they are pinned in
# different places, which is how they came apart once already:
#
#  1. BUILD TAGS: `with_naive_outbound,with_purego`. The tag alone does
#     NOT build — cronet-go's default path is cgo and links the prebuilt
#     libcronet.a, whose Chromium-produced relocations the NDK linker
#     cannot process on arm64 ("relocation 315"). `with_purego` switches
#     cronet-go to dlopen()ing libcronet.so at runtime instead, so
#     nothing of Cronet is linked into the engine. That is why both tags
#     go together and why core/engine/cronet_loader_naive.go is gated on
#     `with_naive_outbound && with_purego`.
#
#  2. RUNTIME LIBRARY: libcronet.so in the APK's lib/<abi>/, relinked
#     from the libcronet.a inside the cronet-go Go module that
#     core/go.mod pins. The Go wrapper compiled into the engine (1) calls
#     into it by symbol with the argument lists of ITS cronet-go version;
#     a library from another version exports the same names with
#     different arguments. Nothing fails at load. It is undefined
#     behaviour inside the VPN service.
#
# So this script does not treat the library as an optional extra. For
# every ABI, after the engine is built:
#
#   * a staged libcronet.so that verifies against core/go.mod is kept;
#   * a missing, unstamped or mismatched one is REBUILT in place by
#     tools/cronet/build-libcronet-android.sh (a relink of the pinned
#     archive: about a second per ABI, no Chromium toolchain — see that
#     script for which linker it needs and why);
#   * then the finished pair is checked against each other — the engine
#     binary records which cronet-go it was compiled from — and the build
#     FAILS if they disagree or the library could not be made. There is
#     no warning-and-continue: an APK whose naive routes cannot work is
#     not a build that succeeded. DAAL_NAIVE=0 is the explicit way to
#     build without the naive outbound.
#
# 16 KB PAGES. Everything here is linked with max-page-size=16384.
# Android 15+ devices may run a 16 KB-page kernel, where a library whose
# LOAD segments are 4 KB-aligned (the NDK r27 and Go default) is refused
# by the loader. The alignment is verified after each link.
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

CRONET_STAMP_CHECK="$ROOT/tools/cronet/check-libcronet-stamp.sh"
CRONET_BUILD="$ROOT/tools/cronet/build-libcronet-android.sh"
READELF="$NDK_BIN/llvm-readelf"

# require_16k fails the build when a LOAD segment of $1 is aligned to
# less than 16 KB. See "16 KB PAGES" above.
require_16k() {
  local f="$1" small
  small="$("$READELF" -lW "$f" | awk '$1 == "LOAD" { print $NF }' | sort -u \
    | while read -r a; do if [ "$((a))" -lt 16384 ]; then printf '%s ' "$a"; fi; done)"
  if [ -n "$small" ]; then
    echo "FATAL: $f has LOAD segments aligned to ${small}— below 16 KB." >&2
    echo "       It would not load on an Android 15+ device with 16 KB pages." >&2
    exit 1
  fi
}

# stage_cronet makes <OUT_DIR>/<abi>/libcronet.so the library this
# engine's cronet-go expects, or fails the build. See "naive" above.
stage_cronet() {
  local abi="$1"
  local dest="$OUT_DIR/$abi/libcronet.so"
  local src="$CRONET_LIB_DIR/$abi/libcronet.so"
  if [ "$DAAL_NAIVE" = "0" ]; then
    if [ -f "$dest" ]; then
      echo "    note: DAAL_NAIVE=0 — $dest is left where it is and is never loaded." >&2
    fi
    return 0
  fi
  if [ -f "$src" ]; then
    # A prebuilt library was supplied. It is used only if it matches;
    # it is never silently replaced by a locally built one.
    if ! "$CRONET_STAMP_CHECK" "$src" "$abi"; then
      echo "FATAL: refusing to package $src for $abi (see above)." >&2
      echo "       Remove it to have the library built here, or set DAAL_NAIVE=0." >&2
      exit 1
    fi
    cp -f "$src" "$dest"
    cp -f "$src.stamp" "$dest.stamp"
    echo "    libcronet.so <- $src"
  elif [ -f "$dest" ] && "$CRONET_STAMP_CHECK" "$dest" "$abi" 2>/dev/null; then
    echo "    libcronet.so already staged and matching"
  else
    if [ -f "$dest" ]; then
      echo "    libcronet.so staged at $dest does not match this engine's cronet-go:"
      "$CRONET_STAMP_CHECK" "$dest" "$abi" 2>&1 | sed 's/^/      /' || true
      echo "    rebuilding it"
    else
      echo "    libcronet.so not staged for $abi — building it"
    fi
    if ! ANDROID_API_LEVEL="$ANDROID_API_LEVEL" "$CRONET_BUILD" "$abi" "$dest"; then
      rm -f "$dest" "$dest.stamp"
      echo "FATAL: could not build libcronet.so for $abi (see above)." >&2
      echo "       The engine has the naive outbound compiled in and would be packaged" >&2
      echo "       without the library it calls. Fix what the message above names and" >&2
      echo "       re-run this script, or build without naive: DAAL_NAIVE=0 $0" >&2
      exit 1
    fi
  fi
  rm -f "$dest.cronet-lib-version"   # the pre-2026-11 stamp name
  # The pair, as built: the engine binary says which cronet-go lib it was
  # compiled against; the library says which one it was linked from.
  if ! "$CRONET_STAMP_CHECK" --pair "$OUT_DIR/$abi/libdaalcore.so" "$dest" "$abi"; then
    echo "FATAL: $OUT_DIR/$abi/libdaalcore.so and libcronet.so are not a pair (see above)." >&2
    exit 1
  fi
  require_16k "$dest"
  echo "    libcronet.so: $(wc -c < "$dest" | tr -d ' ') bytes, $(sed -n 's/^version=//p' "$dest.stamp")"
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
      -ldflags "-s -w -extldflags=-Wl,-z,max-page-size=16384" \
      -o "$out" \
      ./cmd/libdaalcore
  )
  ls -la "$out"
  require_16k "$out"
  stage_cronet "$abi"
}

echo "==> tags: $TAGS"

# clang wrapper names follow ${triple}${api}-clang convention.
build_abi arm64 arm64-v8a   "aarch64-linux-android${ANDROID_API_LEVEL}-clang"
build_abi arm   armeabi-v7a "armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
build_abi amd64 x86_64      "x86_64-linux-android${ANDROID_API_LEVEL}-clang"

echo "==> done"
ls -laR "$OUT_DIR"
