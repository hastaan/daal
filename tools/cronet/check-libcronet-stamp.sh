#!/usr/bin/env bash
# Is this libcronet.so the one the engine's cronet-go expects?
#
#   check-libcronet-stamp.sh <path/to/libcronet.so> <abi>     verify
#   check-libcronet-stamp.sh --want <abi>                      print the pinned lib version
#   check-libcronet-stamp.sh --stamp <path/to/libcronet.so> <abi>   write the stamp
#
# <abi> is an Android ABI directory name (arm64-v8a | armeabi-v7a |
# x86_64 | x86) or the short form build-libcronet-android.sh takes
# (arm64 | arm | amd64 | 386).
#
# WHY. On Android the naive outbound is cronet-go in `with_purego` mode:
# Go code that dlopen()s libcronet.so and calls its C functions by
# symbol, with the argument lists cronet-go was written against. The .so
# is NOT built by the engine build — it is relinked by hand, once, from
# the libcronet.a that ships in the Go module
# github.com/sagernet/cronet-go/lib/android_<arch> (see
# build-libcronet-android.sh) and then reused across engine builds. So
# the two halves are pinned in different places, and nothing compared
# them: bump cronet-go in core/go.mod and an old libcronet.so keeps
# being packaged, with a Go wrapper that no longer matches its C ABI
# (cronet-go 2026-09 added an argument to Cronet_Engine_SetUdpDialer,
# for one). That is not a clean failure. It is undefined behaviour inside
# the VPN service.
#
# The stamp is a sibling file, <libcronet.so>.cronet-lib-version, holding
# the version of that lib module the .so was linked from. A .so with no
# stamp predates this check and is treated as a mismatch: it cannot be
# shown to match, and "probably fine" is how the wrong one ships.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$HERE/../../core"

gomod_for() {
  case "$1" in
    arm64-v8a|arm64)   echo android_arm64 ;;
    armeabi-v7a|arm)   echo android_arm ;;
    x86_64|amd64)      echo android_amd64 ;;
    x86|386)           echo android_386 ;;
    *) echo "check-libcronet-stamp: unknown ABI '$1'" >&2; return 2 ;;
  esac
}

# The lib module version core/go.mod pins. Read from go.mod itself (no
# network, no module cache needed), so this works on a machine that has
# never downloaded the module.
want_version() {
  local mod v
  mod="github.com/sagernet/cronet-go/lib/$(gomod_for "$1")"
  v="$(awk -v m="$mod" '$1 == m { print $2; exit }' "$CORE/go.mod")"
  if [ -z "$v" ]; then
    echo "check-libcronet-stamp: $CORE/go.mod does not pin $mod" >&2
    return 2
  fi
  echo "$v"
}

case "${1:-}" in
  --want)
    want_version "${2:?abi}"
    ;;
  --stamp)
    so="${2:?path to libcronet.so}"
    [ -f "$so" ] || { echo "check-libcronet-stamp: $so does not exist" >&2; exit 2; }
    want_version "${3:?abi}" > "$so.cronet-lib-version"
    ;;
  *)
    so="${1:?path to libcronet.so}"
    abi="${2:?abi}"
    want="$(want_version "$abi")"
    stamp="$so.cronet-lib-version"
    if [ ! -f "$stamp" ]; then
      echo "check-libcronet-stamp: $so has no version stamp ($stamp)." >&2
      echo "  It was built before the stamp existed, so it cannot be shown to match the" >&2
      echo "  cronet-go this engine is built with (lib version $want). Rebuild it with" >&2
      echo "  tools/cronet/build-libcronet-android.sh, which writes the stamp." >&2
      exit 1
    fi
    have="$(tr -d '[:space:]' < "$stamp")"
    if [ "$have" != "$want" ]; then
      echo "check-libcronet-stamp: $so was linked from cronet-go lib $have," >&2
      echo "  but core/go.mod pins $want. The Go wrapper and this library do not share" >&2
      echo "  a C ABI. Rebuild it with tools/cronet/build-libcronet-android.sh." >&2
      exit 1
    fi
    ;;
esac
