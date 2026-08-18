#!/usr/bin/env bash
# tools/build-tor-android.sh — packages Tor and its pluggable transports
# into jniLibs so the sing-box `tor` outbound can exec them on Android.
#
# STATUS: NEVER RUN. Written alongside the Wave-5 tor family from the
# proven template next to it (tools/build-deploy-android.sh, which does
# the same job for libdaal_deploy.so and ships today). The three Go
# transports below are mechanical translations of that script and should
# work as written; the tor daemon step at the bottom is NOT implemented,
# because tor is C with three C dependencies and cross-compiling it is a
# real piece of build engineering, not a shell loop. Do not treat a
# green run of this script as evidence a tor route works.
#
# WHY .so FOR A BINARY
# --------------------
# Since Android 10 an app may not execve a file it can write: the app
# data directory is labelled app_data_file with no execute permission.
# The one app-owned executable location is the extracted native-library
# directory, and the package manager only extracts files matching
# lib*.so out of the APK's lib/<abi>/. So each executable is built as a
# position-independent EXECUTABLE (-buildmode=pie, giving ELF ET_DYN —
# the same container as a shared library) and named lib<thing>.so.
#
# This is the Orbot / tor-android pattern, and Daal already relies on it
# for the publisher CLI. It requires extractNativeLibs=true, set in
# client-shell/tauri/plugins/daal-platform/android/src/main/AndroidManifest.xml
# and re-asserted as jniLibs.useLegacyPackaging in the app's
# build.gradle.kts. If either is lost, the libs stay compressed inside
# the APK, no file exists on disk, and every tor route fails with the
# "not installed" error from core/engine/torbin.go.
#
# NOTHING IS DOWNLOADED AT RUNTIME. These are build inputs baked into
# the APK. Fetching executable code at runtime would violate Google
# Play's Device and Network Abuse policy and would be a supply-chain
# hole besides.
#
# Required env:
#   ANDROID_NDK_HOME   path to the NDK root
#   ANDROID_API_LEVEL  minSdkVersion (default 24, matching the app)
#   TOR_PT_SRC         checkout root holding the pluggable-transport
#                      sources (see REPOS below)
#   OUT_DIR            jniLibs root (default: the tauri gen jniLibs dir)
#
# REPOS — pin these to a signed tag and record the commit in the release
# notes; a pluggable transport is a proxy that sees your traffic before
# tor does, so its provenance matters as much as the relay artefacts'.
#   lyrebird   https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird
#   webtunnel  https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel
#   snowflake  https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake
#
# VERIFY AFTER RUNNING:
#   file "$OUT_DIR/arm64-v8a/libtor.so"
#     must say "ELF 64-bit LSB pie executable ... interpreter /system/bin/linker64"
#     A "shared object" that is not also PIE will not exec.

set -euo pipefail

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to the Android NDK root}"
: "${ANDROID_API_LEVEL:=24}"
: "${TOR_PT_SRC:?TOR_PT_SRC must point at the pluggable-transport checkouts}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs}"

HOST="linux-x86_64"
case "$(uname -s)" in
  Darwin) HOST="darwin-x86_64" ;;
esac
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin"
[ -d "$NDK_BIN" ] || { echo "FATAL: NDK toolchain not found at $NDK_BIN" >&2; exit 1; }

# ABI -> (GOARCH, clang triple). Kept identical to
# tools/build-deploy-android.sh; x86 is omitted there too, and the
# resolver in core/engine/torbin.go reports a clean "not installed"
# rather than half-working on an ABI nobody built for.
abis() {
  echo "arm64-v8a   arm64 aarch64-linux-android${ANDROID_API_LEVEL}-clang"
  echo "armeabi-v7a arm   armv7a-linux-androideabi${ANDROID_API_LEVEL}-clang"
  echo "x86_64      amd64 x86_64-linux-android${ANDROID_API_LEVEL}-clang"
}

# build_go_pt <soname> <source dir> <main package>
build_go_pt() {
  local soname="$1" src="$2" pkg="$3"
  [ -d "$src" ] || { echo "FATAL: $src missing (set TOR_PT_SRC)" >&2; exit 1; }
  while read -r abi goarch cc; do
    local out="$OUT_DIR/$abi/$soname"
    mkdir -p "$(dirname "$out")"
    echo "==> $soname $abi"
    ( cd "$src" && \
      CC="$NDK_BIN/$cc" CGO_ENABLED=1 GOOS=android GOARCH="$goarch" \
      go build -buildmode=pie -trimpath -ldflags "-s -w" -o "$out" "$pkg" )
    file "$out" | grep -q "pie executable" \
      || { echo "FATAL: $out is not a PIE executable and cannot be exec'd" >&2; exit 1; }
  done < <(abis)
}

# obfs4 and meek_lite both come from lyrebird — one binary, two methods,
# which is why core/engine/torbin.go maps both names to liblyrebird.so.
build_go_pt liblyrebird.so  "$TOR_PT_SRC/lyrebird"  ./cmd/lyrebird
build_go_pt libwebtunnel.so "$TOR_PT_SRC/webtunnel" ./main/client
build_go_pt libsnowflake.so "$TOR_PT_SRC/snowflake" ./client

cat >&2 <<'TODO'

==> libtor.so is NOT built by this script.

tor is C and needs an NDK cross-compile of tor plus libevent, OpenSSL
and zlib for each ABI. Two routes, in order of preference:

  1. Reuse the Tor Project's own Android build
     (tpo/core/tor-android-service, or the tor-android submodule Orbot
     uses), which already produces a PIE tor per ABI, and copy its
     output in as libtor.so. Verify the checksum against the Tor
     Project's published artefacts and record it in the release notes.

  2. Build tor from a signed release tarball with the NDK toolchain and
     --host=<triple>. Budget real time for the dependency chain.

Either way the result must satisfy:
  file libtor.so  ->  "ELF ... pie executable ... interpreter /system/bin/linker64"

Until it exists, core/engine/torbin.go resolves nothing and every tor
route is refused at config time with a message naming the missing file.
That is the intended behaviour, not a bug.
TODO
