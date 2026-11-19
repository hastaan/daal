#!/usr/bin/env bash
# Produce a self-contained libcronet.so (naiveproxy's patched Cronet /
# Chromium net stack) for Android, for the engine's `naive` outbound.
#
#   ANDROID_NDK_HOME=<ndk> tools/cronet/build-libcronet-android.sh <abi> [out]
#
#   <abi>  arm64-v8a | armeabi-v7a | x86_64 | x86   (or arm64 | arm | amd64 | 386)
#   [out]  where to write it (default: $OUT, else ./libcronet.so). The
#          stamp is written beside it as <out>.stamp.
#
# You normally do not run this: tools/build-engine-android.sh calls it
# for every ABI whose staged libcronet.so is missing or does not match.
#
# WHY this exists: sing-box's naive outbound is a Cronet wrapper gated
# behind `with_naive_outbound`. cronet-go ships Cronet for Android only
# as a STATIC archive, libcronet.a, inside the Go module
# github.com/sagernet/cronet-go/lib/android_<arch> — there is no
# prebuilt native-C-API .so for Android to drop in (the linux_* modules
# carry one, the android_* modules do not; Google ships Java Cronet
# only). The engine cannot link that archive itself (see below), so it
# runs cronet-go in `with_purego` mode, which dlopen()s a libcronet.so at
# runtime. This script makes that .so by relinking the archive.
#
# WHERE THE ARCHIVE COMES FROM: the Go module cache, at exactly the
# version core/go.mod pins — the same bytes `go build` verified against
# core/go.sum. Not whichever version sorts first in the cache (after a
# cronet-go bump that is the old one). The Go wrapper compiled into the
# engine and this library must come from the same cronet-go or they do
# not share a C ABI; check-libcronet-stamp.sh enforces it and explains.
#
# WHICH LINKER, and why not simply the NDK's: the archive is built with
# Chromium's own, much newer, clang. On arm64 its objects use relocation
# R_AARCH64_GOTPCREL32 (number 315), which the lld inside NDK r27
# (LLVM 18) does not know: "unknown relocation (315)". The lld of LLVM 20
# links it (verified; 19 was not tried). Chromium's toolchain is NOT needed — nothing is
# compiled from Chromium here, the archive is only linked — so this
# script tries, in order, and uses the first that links cleanly:
#
#   1. $CRONET_LLD, if set (then nothing else is tried);
#   2. the NDK's own ld.lld (enough for armeabi-v7a and x86_64 today,
#      and for arm64 from the NDK release that ships LLVM >= 20);
#   3. the lld inside the Rust toolchain (`rustc --print sysroot`) — the
#      Android app cannot be built without Rust, so this one is always
#      there on a machine that builds the APK;
#   4. ld.lld / ld.lld-NN on PATH;
#   5. cronet-go's Chromium toolchain, if $CRONET_GO points at a checkout
#      that has downloaded it (how the first library was made by hand).
#
# The NDK's clang++ is always the driver, so the sysroot, the CRT
# objects and the compiler runtime are the NDK's whichever lld links.
#
# The archive leaves a few Java-provided android bridges undefined;
# cronet_stubs.cc provides weak headless defaults, and `-z defs` turns
# anything still unresolved into a link error here rather than a
# dlopen() failure on the phone.
#
# STRIPPED: the app's Gradle config keeps native libraries as they are
# (jniLibs.keepDebugSymbols), so the static symbol table would ship —
# 9-13 MB per ABI of C++ names nothing reads. --strip-all drops it and
# keeps the dynamic symbols dlsym() uses.
#
# 16 KB PAGES: linked with max-page-size=16384, so the library loads on
# Android 15+ devices that run a 16 KB-page kernel (NDK r27 still
# defaults to 4 KB; a 4 KB-aligned library is refused there).
set -euo pipefail
export LC_ALL=C
: "${ANDROID_NDK_HOME:?path to the Android NDK}"
: "${ANDROID_API_LEVEL:=24}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$HERE/../../core"
CHECK="$HERE/check-libcronet-stamp.sh"

ABI="${1:-arm64}"
case "$ABI" in
  arm64|arm64-v8a)  TRIPLE="aarch64-linux-android${ANDROID_API_LEVEL}";    GOMOD=android_arm64 ;;
  arm|armeabi-v7a)  TRIPLE="armv7a-linux-androideabi${ANDROID_API_LEVEL}"; GOMOD=android_arm ;;
  amd64|x86_64)     TRIPLE="x86_64-linux-android${ANDROID_API_LEVEL}";     GOMOD=android_amd64 ;;
  386|x86)          TRIPLE="i686-linux-android${ANDROID_API_LEVEL}";       GOMOD=android_386 ;;
  *) echo "build-libcronet-android: unknown ABI '$ABI'" >&2; exit 2 ;;
esac
OUT="${2:-${OUT:-libcronet.so}}"

HOST="linux-x86_64"
case "$(uname -s)" in
  Darwin) HOST="darwin-x86_64" ;;
esac
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin"
NDK_CXX="$NDK_BIN/${TRIPLE}-clang++"
if [ ! -x "$NDK_CXX" ]; then
  echo "build-libcronet-android: no NDK compiler at $NDK_CXX" >&2
  exit 1
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

LIBVER="$("$CHECK" --want "$ABI")"
MODULE="github.com/sagernet/cronet-go/lib/${GOMOD}"
ARCHIVE="$(go env GOMODCACHE)/${MODULE}@${LIBVER}/libcronet.a"
if [ ! -f "$ARCHIVE" ]; then
  # The engine build needs the same module, so this is normally a no-op.
  # `go mod download` verifies what it fetches against core/go.sum.
  echo "    fetching ${MODULE}@${LIBVER} (pinned by core/go.mod)"
  (cd "$CORE" && go mod download "$MODULE")
fi
if [ ! -f "$ARCHIVE" ]; then
  echo "build-libcronet-android: no libcronet.a at $ARCHIVE" >&2
  echo "  run: (cd core && go mod download $MODULE)" >&2
  exit 1
fi
ARCHIVE_SHA="$(sha256_of "$ARCHIVE")"
LIB_ID="${MODULE}@${LIBVER} archive-sha256=${ARCHIVE_SHA}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/daal-libcronet.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

"$NDK_CXX" -c -O2 -fPIC -fvisibility=hidden "-DDAAL_CRONET_LIB_ID=\"${LIB_ID}\"" \
  "$HERE/cronet_stubs.cc" -o "$WORK/cronet_stubs.o"

# The allocator and libc wraps cronet-go's own cgo link line uses
# (lib/android_*/libcronet_cgo.go) — the archive's allocator shim is
# written to be linked this way.
WRAPS=""
for w in aligned_alloc calloc free malloc memalign posix_memalign pvalloc realloc valloc \
         malloc_usable_size realpath strdup strndup getcwd asprintf vasprintf; do
  WRAPS="$WRAPS -Wl,-wrap,$w"
done

candidates=()
if [ -n "${CRONET_LLD:-}" ]; then
  candidates+=("$CRONET_LLD")
else
  candidates+=("$NDK_BIN/ld.lld")
  if command -v rustc >/dev/null 2>&1; then
    for l in "$(rustc --print sysroot)"/lib/rustlib/*/bin/gcc-ld/ld.lld; do
      [ -x "$l" ] && candidates+=("$l")
    done
  fi
  for l in ld.lld ld.lld-23 ld.lld-22 ld.lld-21 ld.lld-20; do
    if command -v "$l" >/dev/null 2>&1; then candidates+=("$(command -v "$l")"); fi
  done
  if [ -n "${CRONET_GO:-}" ]; then
    candidates+=("$CRONET_GO/naiveproxy/src/third_party/llvm-build/Release+Asserts/bin/ld.lld")
  fi
fi

linked=""
for lld in "${candidates[@]}"; do
  [ -x "$lld" ] || continue
  if "$NDK_CXX" --ld-path="$lld" -shared -o "$WORK/libcronet.so" \
       -Wl,-soname,libcronet.so \
       -Wl,--whole-archive "$ARCHIVE" -Wl,--no-whole-archive "$WORK/cronet_stubs.o" \
       $WRAPS -unwindlib=none -nostdlib++ \
       -Wl,-z,noexecstack -Wl,-z,defs -Wl,-z,max-page-size=16384 -Wl,--strip-all \
       -ldl -lm -llog -landroid > "$WORK/link.log" 2>&1; then
    linked="$lld"
    break
  fi
  {
    echo "--- $lld ($("$lld" --version 2>/dev/null | head -n 1)) could not link it:"
    grep -m 3 'error' "$WORK/link.log" | cut -c1-240 || true
  } >> "$WORK/tried.log"
  rm -f "$WORK/libcronet.so"
done

if [ -z "$linked" ]; then
  echo "build-libcronet-android: no linker here can relink libcronet.a for $ABI." >&2
  [ -f "$WORK/tried.log" ] && sed 's/^/    /' "$WORK/tried.log" >&2
  echo "  The archive needs an lld from LLVM 20 or newer (NDK r27's is LLVM 18 and stops" >&2
  echo "  at arm64 'relocation 315'). Chromium does NOT have to be built or downloaded." >&2
  echo "  Fix, one command:   rustup toolchain install stable" >&2
  echo "  (its bundled lld is found automatically), or point CRONET_LLD at any ld.lld >= 20." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
# Never leave a new library beside an old stamp, or the reverse.
rm -f "$OUT.stamp" "$OUT.cronet-lib-version"
mv -f "$WORK/libcronet.so" "$OUT"
DAAL_CRONET_LINKER="$("$linked" --version 2>/dev/null | head -n 1 | cut -c1-120)" \
  "$CHECK" --stamp "$OUT" "$ABI"
echo "    wrote $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
echo "      from   ${LIB_ID}"
echo "      linker $linked"
