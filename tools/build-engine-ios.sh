#!/usr/bin/env bash
# tools/build-engine-ios.sh — cross-compiles libdaalcore.dylib for iOS
# device (arm64) and emits it where Tauri Mobile embeds Frameworks/.
#
# This script MUST run on macOS — it shells out to xcrun. CI invokes
# it from the macOS runner in the `package-ios` job.
#
# Outputs:
#   client-shell/tauri/src-tauri/gen/apple/Frameworks/libdaalcore.dylib
#     — iPhone arm64 device slice
#
# Why only the device slice (not the simulator):
#   Go's only valid GOOS values for iOS are `ios/amd64` and `ios/arm64`
#   (see `go tool dist list`). There is NO `iossimulator` GOOS. Building
#   an Apple-Silicon-simulator slice requires keeping `GOOS=ios
#   GOARCH=arm64` but switching the clang wrapper to add
#   `-target arm64-apple-ios-VER-simulator` against the iphonesimulator
#   SDK, with a separate GOCACHE (or the device build cache pollutes
#   the simulator artifact — golang/go#57442).
#
#   Tauri's `tauri ios build --export-method debugging` only embeds
#   the device slice into the .ipa, so the simulator dylib was never
#   shipped. We drop it here. When/if local `tauri ios dev` against
#   an Apple-Silicon simulator becomes a need, add a sim-arm64 step
#   with the `-target` clang flag.

set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "FATAL: build-engine-ios.sh must run on macOS (needs xcrun/lipo)" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/client-shell/tauri/src-tauri/gen/apple/Frameworks}"
mkdir -p "$OUT_DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Go does NOT support -buildmode=c-shared on iOS (Go forbids it: see
# cmd/internal/sys.BuildModeSupported). The official path is:
#
#   1. Go produces a static c-archive (.a) via -buildmode=c-archive.
#   2. clang re-links the .a into a dynamic library (.dylib) with
#      -shared -Wl,-all_load.
#   3. Install-name is rewritten to @rpath so dlopen("libdaalcore.dylib")
#      finds it inside the app bundle's Frameworks/ dir.
#
# References:
#   - https://stackoverflow.com/a/62029521
#   - golang/go issue #31036 (-buildmode=c-shared on iOS still rejected)
#   - golang/go issue #57442 (iossimulator GOOS does not exist)
#   - Tailscale's iOS app + sing-box-for-ios: same .a-to-.dylib trick.

SDK="iphoneos"
GOARCH="arm64"
MIN_FLAG="-mios-version-min=14.0"

cc="$(xcrun --sdk "$SDK" --find clang)"
sysroot="$(xcrun --sdk "$SDK" --show-sdk-path)"
archive="$TMP/${SDK}-${GOARCH}.a"
dylib="$OUT_DIR/libdaalcore.dylib"

echo "==> $SDK / GOARCH=$GOARCH -> c-archive"
(
  cd "$ROOT/core"
  CC="$cc" \
  CGO_ENABLED=1 \
  GOOS=ios \
  GOARCH="$GOARCH" \
  CGO_CFLAGS="-isysroot $sysroot -arch $GOARCH $MIN_FLAG -fembed-bitcode" \
  CGO_LDFLAGS="-isysroot $sysroot -arch $GOARCH $MIN_FLAG" \
  go build -buildmode=c-archive -tags cshared,singbox,with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api \
    -o "$archive" \
    ./cmd/libdaalcore
)

echo "==> linking $archive -> $dylib"
"$cc" \
  -isysroot "$sysroot" \
  -arch "$GOARCH" \
  $MIN_FLAG \
  -shared \
  -Wl,-all_load \
  "$archive" \
  -framework CoreFoundation \
  -framework Security \
  -install_name "@rpath/libdaalcore.dylib" \
  -o "$dylib"

echo "==> done"
ls -la "$OUT_DIR/"
file "$dylib"
otool -L "$dylib" || true
otool -D "$dylib" || true
