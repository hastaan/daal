#!/usr/bin/env bash
# Is this libcronet.so the one the engine's cronet-go expects?
#
#   check-libcronet-stamp.sh <libcronet.so> <abi>            verify one library
#   check-libcronet-stamp.sh --pair <libdaalcore.so> <libcronet.so> <abi>
#                                                            verify an engine/library PAIR
#   check-libcronet-stamp.sh --stamp <libcronet.so> <abi>    write the stamp (refuses a
#                                                            library that does not verify)
#   check-libcronet-stamp.sh --want <abi>                    print the pinned lib version
#   check-libcronet-stamp.sh --id-prefix <abi>               print "<module>@<version>"
#
# <abi> is an Android ABI directory name (arm64-v8a | armeabi-v7a |
# x86_64 | x86) or the short form build-libcronet-android.sh takes
# (arm64 | arm | amd64 | 386).
#
# WHY. On Android the naive outbound is cronet-go in `with_purego` mode:
# Go code that dlopen()s libcronet.so and calls its C functions by
# symbol, with the argument lists cronet-go was written against. The .so
# is NOT built by the engine build — it is relinked from the libcronet.a
# that ships in the Go module github.com/sagernet/cronet-go/lib/android_<arch>
# (see build-libcronet-android.sh) and then reused across engine builds.
# So the two halves are pinned in different places, and nothing compared
# them: bump cronet-go in core/go.mod and an old libcronet.so keeps
# being packaged, with a Go wrapper that no longer matches its C ABI
# (cronet-go 2026-09 added an argument to Cronet_Engine_SetUdpDialer,
# for one — and exports exactly the same symbol NAMES as before, so
# nothing at load time notices). That is not a clean failure. It is
# undefined behaviour inside the VPN service.
#
# WHAT IS COMPARED. Three records, each of which has to agree:
#
#  1. THE LIBRARY'S OWN BYTES. build-libcronet-android.sh links a string
#       daal-cronet-lib-id: <module>@<version> archive-sha256=<hex>
#     into the .so (tools/cronet/cronet_stubs.cc). It names the Go module
#     and the exact libcronet.a the library was linked from. This is the
#     authority: it cannot be copied next to a different library.
#  2. THE STAMP, a sibling file <libcronet.so>.stamp:
#       module=…  version=…  archive_sha256=…  so_sha256=…  linker=…
#     so_sha256 is the hash of the finished .so. It catches a library
#     that was overwritten, truncated or half-copied after it was built,
#     and it is what a human reads to see what is staged.
#  3. THE PIN: core/go.mod (verify mode) or the engine binary itself
#     (--pair mode: a Go binary records the exact version of every module
#     it was built from, so libdaalcore.so says which cronet-go lib
#     module its wrapper belongs to — no source tree needed, and no way
#     for the answer to drift from what was compiled).
#
# A .so with no embedded id predates this check and is treated as a
# mismatch: it cannot be shown to match, and "probably fine" is how the
# wrong one ships.
#
# Also checked, because a matching version is not the whole story:
#   * the ELF machine is the ABI's (an arm64 library under x86_64/ loads
#     nowhere);
#   * when the pinned libcronet.a is in the module cache, its sha256 is
#     the one the library says it was linked from;
#   * when cronet-go's source is in the module cache and an nm that reads
#     the file is available, every Cronet_* function the wrapper looks up
#     at load is exported (one missing symbol fails LoadLibrary, and with
#     it every naive route).
# The last two are skipped — and say so — on a machine that has neither;
# everything above them needs only this repository and coreutils.
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${DAAL_CORE_DIR:-$HERE/../../core}"
ME="check-libcronet-stamp"
REBUILD_HINT="ANDROID_NDK_HOME=<ndk> bash tools/build-engine-android.sh   (rebuilds and re-stamps it)"

say() { echo "$ME: $*" >&2; }

gomod_for() {
  case "$1" in
    arm64-v8a|arm64)   echo android_arm64 ;;
    armeabi-v7a|arm)   echo android_arm ;;
    x86_64|amd64)      echo android_amd64 ;;
    x86|386)           echo android_386 ;;
    *) say "unknown ABI '$1'"; return 2 ;;
  esac
}

# e_machine (ELF header bytes 18-19, little-endian) per ABI.
machine_for() {
  case "$1" in
    arm64-v8a|arm64)   echo "b7 00" ;;
    armeabi-v7a|arm)   echo "28 00" ;;
    x86_64|amd64)      echo "3e 00" ;;
    x86|386)           echo "03 00" ;;
  esac
}

module_for() { echo "github.com/sagernet/cronet-go/lib/$(gomod_for "$1")"; }

# The lib module version core/go.mod pins. Read from go.mod itself (no
# network, no module cache needed), so this works on a machine that has
# never downloaded the module.
want_version() {
  local mod v
  mod="$(module_for "$1")"
  v="$(awk -v m="$mod" '$1 == m { print $2; exit }' "$CORE/go.mod")"
  if [ -z "$v" ]; then
    say "$CORE/go.mod does not pin $mod"
    return 2
  fi
  echo "$v"
}

# The cronet-go wrapper version (the Go half) core/go.mod pins.
want_wrapper_version() {
  awk '$1 == "github.com/sagernet/cronet-go" { print $2; exit }' "$CORE/go.mod"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# "<module>@<version> archive-sha256=<hex>" out of the library's bytes,
# or nothing.
embedded_id() {
  { grep -a -o 'daal-cronet-lib-id: [^[:cntrl:]]*' "$1" || true; } \
    | head -n 1 | sed 's/^daal-cronet-lib-id: //'
}

stamp_field() { # <stamp file> <key>
  awk -F= -v k="$2" '$1 == k { print substr($0, length(k) + 2); exit }' "$1"
}

gomodcache() {
  if [ -n "${GOMODCACHE:-}" ]; then echo "$GOMODCACHE"; return; fi
  if command -v go >/dev/null 2>&1; then go env GOMODCACHE 2>/dev/null || true; fi
}

# An nm that can read a foreign-architecture ELF's dynamic symbols.
# binutils nm usually cannot (it is built for the host only); the NDK's
# llvm-nm and any distro llvm-nm can.
find_nm() {
  local c
  for c in \
      "${ANDROID_NDK_HOME:+$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm}" \
      "${ANDROID_NDK_HOME:+$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-nm}" \
      llvm-nm llvm-nm-21 llvm-nm-20 llvm-nm-19 llvm-nm-18 nm; do
    [ -n "$c" ] || continue
    if command -v "$c" >/dev/null 2>&1 && "$c" -D --defined-only "$1" >/dev/null 2>&1; then
      echo "$c"; return 0
    fi
  done
  return 1
}

# verify_lib <so> <abi> <want version> <why that version>
# Everything that can be said about one library without its stamp.
verify_lib() {
  local so="$1" abi="$2" want="$3" why="$4"
  local mod id have_mod_ver have_sha machine cache a wrapper src nm missing

  if [ ! -f "$so" ]; then
    say "$so does not exist."
    return 1
  fi
  mod="$(module_for "$abi")"

  machine="$(od -An -tx1 -j18 -N2 "$so" | sed 's/^ *//; s/ *$//')"
  if [ "$(od -An -c -N4 "$so" | tr -d ' ')" != '177ELF' ] || [ "$machine" != "$(machine_for "$abi")" ]; then
    say "$so is not an ELF library for $abi (e_machine '$machine', want '$(machine_for "$abi")')."
    say "  It would be packaged under lib/$abi/ and could not be loaded there."
    return 1
  fi

  id="$(embedded_id "$so")"
  if [ -z "$id" ]; then
    say "$so does not say which cronet-go it was linked from"
    say "  (no 'daal-cronet-lib-id' string inside it). It was built before that"
    say "  existed, so it cannot be shown to match the cronet-go this engine is"
    say "  built with ($mod $want)."
    say "  Fix: $REBUILD_HINT"
    return 1
  fi
  have_mod_ver="${id%% *}"
  have_sha="${id##*archive-sha256=}"
  if [ "$have_mod_ver" != "$mod@$want" ]; then
    say "$so was linked from"
    say "    $have_mod_ver"
    say "  but $why"
    say "    $mod@$want"
    say "  The Go wrapper and this library do not share a C ABI."
    say "  Fix: $REBUILD_HINT"
    return 1
  fi

  cache="$(gomodcache)"
  a="$cache/$mod@$want/libcronet.a"
  if [ -n "$cache" ] && [ -f "$a" ]; then
    if [ "$(sha256_of "$a")" != "$have_sha" ]; then
      say "$so says it was linked from a libcronet.a with sha256"
      say "    $have_sha"
      say "  but $a is"
      say "    $(sha256_of "$a")"
      say "  Same module version, different archive: one of the two is not the real one."
      say "  Fix: go clean -modcache is NOT needed — run 'cd core && go mod verify', then"
      say "       $REBUILD_HINT"
      return 1
    fi
  else
    say "note: $mod@$want is not in the Go module cache; the archive hash inside $so was not compared."
  fi

  wrapper="$(want_wrapper_version)"
  src="$cache/github.com/sagernet/cronet-go@$wrapper/internal/cronet"
  if [ -n "$cache" ] && [ -n "$wrapper" ] && [ -d "$src" ] && nm="$(find_nm "$so")"; then
    missing="$(comm -23 \
      <(cat "$src"/loader_unix.go "$src"/api_purego*.go "$src"/symbols_purego.go 2>/dev/null \
          | grep -oE '"Cronet_[A-Za-z0-9_]+"' | tr -d '"' | sort -u) \
      <("$nm" -D --defined-only "$so" | awk '{print $NF}' | sort -u))"
    if [ -n "$missing" ]; then
      say "$so does not export $(printf '%s\n' "$missing" | wc -l | tr -d ' ') function(s) cronet-go $wrapper looks up at load:"
      printf '    %s\n' $missing >&2
      say "  LoadLibrary fails on the first one, and every naive route with it."
      say "  Fix: $REBUILD_HINT"
      return 1
    fi
  else
    say "note: exported-symbol coverage of $so was not checked (needs cronet-go $wrapper in the module cache and an llvm-nm)."
  fi
  return 0
}

# verify_stamp <so> <abi> — the sibling file agrees with the library.
verify_stamp() {
  local so="$1" abi="$2" stamp="$1.stamp" id k
  if [ ! -f "$stamp" ]; then
    say "$so has no stamp ($stamp)."
    say "  Fix: $REBUILD_HINT"
    return 1
  fi
  id="$(embedded_id "$so")"
  if [ "$(stamp_field "$stamp" module)@$(stamp_field "$stamp" version)" != "${id%% *}" ] \
     || [ "$(stamp_field "$stamp" archive_sha256)" != "${id##*archive-sha256=}" ]; then
    say "$stamp describes a different library than $so:"
    say "    stamp:   $(stamp_field "$stamp" module)@$(stamp_field "$stamp" version) archive-sha256=$(stamp_field "$stamp" archive_sha256)"
    say "    library: $id"
    say "  Fix: $REBUILD_HINT"
    return 1
  fi
  k="$(sha256_of "$so")"
  if [ "$(stamp_field "$stamp" so_sha256)" != "$k" ]; then
    say "$so is not the file its stamp was written for:"
    say "    stamp so_sha256: $(stamp_field "$stamp" so_sha256)"
    say "    file sha256:     $k"
    say "  It was changed, truncated or half-copied after it was built."
    say "  Fix: $REBUILD_HINT"
    return 1
  fi
  return 0
}

# The cronet-go lib module version a built libdaalcore.so was compiled
# against, read out of the Go build info inside it; empty when the engine
# was built without naive (DAAL_NAIVE=0). The build info is plain text in
# the binary, so this needs no Go toolchain and works across
# architectures.
engine_lib_version() { # <libdaalcore.so> <abi>
  { grep -a -o "dep.$(module_for "$2").v[0-9A-Za-z.+-]*" "$1" || true; } \
    | head -n 1 | sed 's/.*[^0-9A-Za-z.+-]\(v[0-9A-Za-z.+-]*\)$/\1/'
}

case "${1:-}" in
  --want)
    want_version "${2:?abi}"
    ;;
  --id-prefix)
    echo "$(module_for "${2:?abi}")@$(want_version "$2")"
    ;;
  --stamp)
    so="${2:?path to libcronet.so}"
    abi="${3:?abi}"
    want="$(want_version "$abi")"
    # A stamp is a statement that the library matches. Never write one
    # for a library that does not.
    verify_lib "$so" "$abi" "$want" "core/go.mod pins" || {
      say "refusing to stamp $so."
      exit 1
    }
    id="$(embedded_id "$so")"
    {
      echo "module=$(module_for "$abi")"
      echo "version=$want"
      echo "archive_sha256=${id##*archive-sha256=}"
      echo "so_sha256=$(sha256_of "$so")"
      echo "linker=${DAAL_CRONET_LINKER:-unknown}"
    } > "$so.stamp"
    ;;
  --pair)
    engine="${2:?path to libdaalcore.so}"
    so="${3:?path to libcronet.so}"
    abi="${4:?abi}"
    if [ ! -f "$engine" ]; then say "$engine does not exist."; exit 1; fi
    ever="$(engine_lib_version "$engine" "$abi")"
    if [ -z "$ever" ]; then
      if [ -f "$so" ]; then
        say "note: $engine was built without the naive outbound; $so beside it is never loaded."
      fi
      exit 0
    fi
    if [ ! -f "$so" ]; then
      say "$engine has the naive outbound, and there is no"
      say "  $so"
      say "  beside it: every naive route would fail at connect on $abi."
      say "  Fix: $REBUILD_HINT"
      exit 1
    fi
    verify_lib "$so" "$abi" "$ever" "$engine was built against" || exit 1
    verify_stamp "$so" "$abi" || exit 1
    ;;
  *)
    so="${1:?path to libcronet.so}"
    abi="${2:?abi}"
    want="$(want_version "$abi")"
    verify_lib "$so" "$abi" "$want" "core/go.mod pins" || exit 1
    verify_stamp "$so" "$abi" || exit 1
    ;;
esac
