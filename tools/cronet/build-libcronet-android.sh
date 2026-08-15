#!/usr/bin/env bash
# Produce a self-contained libcronet.so (naiveproxy's patched Cronet /
# Chromium net stack) for Android, for the engine's `naive` outbound.
#
# WHY this exists: sing-box's naive outbound is a Cronet wrapper gated
# behind `with_naive_outbound`, which links cronet-go's prebuilt
# libcronet.a. That .a is built with Chromium's own clang/lld and the NDK
# linker cannot process its relocations (relocation 315). There is no
# prebuilt Cronet native-C-API .so for Android to just drop in (Google
# ships Java Cronet only; naiveproxy stopped shipping native binaries at
# Chromium 106). So we relink the prebuilt .a into a .so USING Chromium's
# own clang (which handles its relocations); the fully-linked .so is then
# dlopen'd at runtime via purego and the NDK never touches its relocations.
#
# The .a excludes a few Java-provided android bridges (user-added CA roots,
# pre-freeze memory trimmer, power/thermal monitor); cronet_stubs.cc
# provides safe headless no-op/default implementations so the .so has no
# unresolved strong symbols.
#
# Requirements: cronet-go's Chromium toolchain (one-time, multi-GB):
#   git clone --recursive --depth=1 https://github.com/sagernet/cronet-go CRONET_GO
#   ( cd CRONET_GO && go run ./cmd/build-naive --target=android/arm64 download-toolchain )
# Then set CRONET_GO + ANDROID_NDK_HOME and run this per ABI.
set -euo pipefail
: "${CRONET_GO:?path to a cronet-go checkout with the downloaded toolchain}"
: "${ANDROID_NDK_HOME:?path to Android NDK}"
ABI="${1:-arm64}"                 # arm64 | arm | amd64 | 386
case "$ABI" in
  arm64) TRIPLE=aarch64-linux-android24; GOMOD=android_arm64 ;;
  arm)   TRIPLE=armv7a-linux-androideabi24; GOMOD=android_arm ;;
  amd64) TRIPLE=x86_64-linux-android24; GOMOD=android_amd64 ;;
  386)   TRIPLE=i686-linux-android24; GOMOD=android_386 ;;
  *) echo "unknown ABI $ABI" >&2; exit 2 ;;
esac
OUT="${OUT:-libcronet.so}"
CLANG="$CRONET_GO/naiveproxy/src/third_party/llvm-build/Release+Asserts/bin/clang++"
SYSROOT="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
NDK_CXX="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/${TRIPLE}-clang++"
LIBMOD="$(ls -d "$(go env GOMODCACHE)"/github.com/sagernet/cronet-go/lib/${GOMOD}@* | head -1)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPS="-Wl,-wrap,aligned_alloc -Wl,-wrap,calloc -Wl,-wrap,free -Wl,-wrap,malloc -Wl,-wrap,memalign -Wl,-wrap,posix_memalign -Wl,-wrap,pvalloc -Wl,-wrap,realloc -Wl,-wrap,valloc -Wl,-wrap,malloc_usable_size -Wl,-wrap,realpath -Wl,-wrap,strdup -Wl,-wrap,strndup -Wl,-wrap,getcwd -Wl,-wrap,asprintf -Wl,-wrap,vasprintf"
"$NDK_CXX" -c -O2 -fPIC "$HERE/cronet_stubs.cc" -o "/tmp/cronet_stubs_${ABI}.o"
"$CLANG" --target="$TRIPLE" --sysroot="$SYSROOT" -fuse-ld=lld -shared -o "$OUT" \
  -Wl,--whole-archive "$LIBMOD/libcronet.a" -Wl,--no-whole-archive "/tmp/cronet_stubs_${ABI}.o" \
  $WRAPS -unwindlib=none -nostdlib++ -Wl,-z,noexecstack -ldl -lm -llog -landroid
echo "wrote $OUT ($(stat -c%s "$OUT") bytes)"
