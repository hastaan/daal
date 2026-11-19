#!/usr/bin/env bash
# tools/check-android-so-manifest.sh — the native libraries staged for
# the Android APK must be a consistent set.
#
# THE FAILURE THIS EXISTS TO CATCH
# --------------------------------
# `tauri android build` compiles none of the Go code. It packages
# whatever lib*.so files are sitting in gen/android/.../jniLibs/<abi>/,
# and gen/android is gitignored build state. Three independently built
# things meet there and nothing else compares them:
#
#   libdaalcore.so  the engine          tools/build-engine-android.sh
#   libcronet.so    Cronet, for naive   tools/cronet/build-libcronet-android.sh
#   libdaal_deploy.so  the publisher CLI   tools/build-deploy-android.sh
#
# 1. THE ENGINE / CRONET PAIR. The engine's naive outbound is a Go
#    wrapper that dlopen()s libcronet.so and calls it by symbol with the
#    argument lists of the cronet-go version it was compiled from. A
#    libcronet.so relinked from another cronet-go exports the same names
#    with different arguments (cronet-go 2026-09 changed
#    Cronet_Engine_SetUdpDialer), so a stale one loads without complaint
#    and is undefined behaviour inside the VPN service. The engine binary
#    records which cronet-go it was built from; the library records which
#    one it was linked from; tools/cronet/check-libcronet-stamp.sh --pair
#    compares them. A naive-capable engine with NO library beside it is
#    refused too.
# 2. STALE ENGINE. Every plain-`cshared` //export in core/abi must be a
#    dynamic symbol of each Android libdaalcore.so (the same rule
#    check-engine-so-manifest.sh applies to the desktop artefact).
# 3. 16 KB PAGES. Android 15+ devices may run a 16 KB-page kernel; there
#    the loader refuses a library, and the kernel refuses an executable,
#    whose LOAD segments are aligned to less. Go and NDK r27 both default
#    to 4 KB; the build scripts pass max-page-size=16384. Checked on the
#    64-bit ABIs (no 32-bit Android runs 16 KB pages).
#
# The Tauri/Rust app library is held to the same rule (its flag is in
# client-shell/tauri/src-tauri/.cargo/config.toml). Any OTHER library
# these scripts do not build, and an ABI directory with no engine in it,
# are REPORTED, not failed: real problems, fixed somewhere else than here.
#
# Called by check-engine-so-manifest.sh and check-deploy-so-manifest.sh,
# so either gate alone refuses a mismatched set.
#
# Exit 0 and skip — out loud — when nothing has been staged: a source
# checkout that has never run the Android build is not broken.

set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.."

TAG="[check-android-so-manifest]"
ABI_DIR="core/abi"
JNILIBS="${OUT_DIR:-client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs}"
CRONET_CHECK="tools/cronet/check-libcronet-stamp.sh"
FIX="ANDROID_NDK_HOME=<ndk> bash tools/build-engine-android.sh && ANDROID_NDK_HOME=<ndk> bash tools/build-deploy-android.sh"

mapfile -t ENGINES < <(find "$JNILIBS" -mindepth 2 -maxdepth 2 -name libdaalcore.so -type f 2>/dev/null | sort)
if [ "${#ENGINES[@]}" -eq 0 ]; then
    echo "$TAG no libdaalcore.so under $JNILIBS — skipping"
    echo "$TAG (build it with tools/build-engine-android.sh)"
    exit 0
fi

# The guard is only worth calling if it refuses what it should.
bash tools/cronet/selftest-check-libcronet-stamp.sh

EXPECTED="$(
    for f in "$ABI_DIR"/*.go; do
        case "$f" in *_test.go) continue ;; esac
        constraint="$(grep -m1 '^//go:build ' "$f" || true)"
        [ "$constraint" = "//go:build cshared" ] || continue
        grep -h '^//export engine_' "$f" | sed 's|^//export ||'
    done | sort -u
)"
if [ -z "$EXPECTED" ]; then
    echo "$TAG FATAL: no plain-cshared //export names found in $ABI_DIR" >&2
    exit 1
fi
N_EXPECTED="$(printf '%s\n' "$EXPECTED" | wc -l | tr -d ' ')"

# Tools that read a foreign-architecture ELF. binutils readelf does;
# binutils nm usually does not, so prefer an llvm-nm.
pick() { # <probe file> <args...> -- <candidates...>
    local probe="$1"; shift
    local args=()
    while [ "$1" != "--" ]; do args+=("$1"); shift; done
    shift
    local c
    for c in "$@"; do
        [ -n "$c" ] || continue
        if command -v "$c" >/dev/null 2>&1 && "$c" "${args[@]}" "$probe" >/dev/null 2>&1; then
            echo "$c"; return 0
        fi
    done
    return 1
}
NDK_BIN=""
for h in linux-x86_64 darwin-x86_64; do
    d="${ANDROID_NDK_HOME:-/nonexistent}/toolchains/llvm/prebuilt/$h/bin"
    if [ -d "$d" ]; then NDK_BIN="$d"; fi
done
NM="$(pick "${ENGINES[0]}" -D --defined-only -- "${NDK_BIN:+$NDK_BIN/llvm-nm}" llvm-nm llvm-nm-21 llvm-nm-20 llvm-nm-19 llvm-nm-18 nm || true)"
READELF="$(pick "${ENGINES[0]}" -lW -- "${NDK_BIN:+$NDK_BIN/llvm-readelf}" llvm-readelf llvm-readelf-21 llvm-readelf-20 llvm-readelf-19 llvm-readelf-18 readelf || true)"
[ -n "$NM" ]      || echo "$TAG note: no nm here can read Android libraries — engine exports NOT checked (install llvm, or set ANDROID_NDK_HOME)"
[ -n "$READELF" ] || echo "$TAG note: no readelf here — 16 KB page alignment NOT checked (install binutils or llvm, or set ANDROID_NDK_HOME)"

# small_aligns <file> — LOAD alignments below 16 KB, space separated.
small_aligns() {
    "$READELF" -lW "$1" | awk '$1 == "LOAD" { print $NF }' | sort -u \
        | while read -r a; do if [ "$((a))" -lt 16384 ]; then printf '%s ' "$a"; fi; done
}

violations=0
warnings=0
fail() { echo "$TAG FAIL: $*"; violations=$((violations + 1)); }
warn() { echo "$TAG WARN: $*"; warnings=$((warnings + 1)); }

for engine in "${ENGINES[@]}"; do
    dir="$(dirname "$engine")"
    abi="$(basename "$dir")"
    ok=1

    # 1. the engine / Cronet pair
    if out="$(bash "$CRONET_CHECK" --pair "$engine" "$dir/libcronet.so" "$abi" 2>&1)"; then
        [ -z "$out" ] || printf '%s\n' "$out" | sed "s/^/$TAG   /"
    else
        fail "$abi: libdaalcore.so and libcronet.so are not a pair"
        printf '%s\n' "$out" | sed "s/^/$TAG   /"
        ok=0
    fi

    # 2. stale engine
    if [ -n "$NM" ]; then
        present="$("$NM" -D --defined-only "$engine" 2>/dev/null | awk '{print $NF}' | grep '^engine_' | sort -u || true)"
        missing="$(comm -23 <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$present") || true)"
        if [ -n "$missing" ]; then
            fail "$abi: libdaalcore.so is STALE ($(printf '%s\n' "$missing" | wc -l | tr -d ' ') of $N_EXPECTED core/abi exports absent):"
            printf '  %s\n' $missing
            ok=0
        fi
    fi

    # 3. 16 KB pages
    if [ -n "$READELF" ]; then
        case "$abi" in
            arm64-v8a|x86_64)
                for f in "$dir"/lib*.so; do
                    [ -f "$f" ] || continue   # a dangling symlink is not a library yet
                    small="$(small_aligns "$f")"
                    [ -n "$small" ] || continue
                    case "$(basename "$f")" in
                        libdaalcore.so|libcronet.so|libdaal_deploy.so)
                            fail "$abi: $(basename "$f") has LOAD segments aligned to ${small}(below 16 KB) — it cannot be loaded on a 16 KB-page Android 15+ device"
                            ok=0 ;;
                        libdaal_desktop_tauri_lib.so)
                            fail "$abi: $(basename "$f") has LOAD segments aligned to ${small}(below 16 KB) — the app cannot start on a 16 KB-page Android 15+ device. It is a build from before client-shell/tauri/src-tauri/.cargo/config.toml set max-page-size for this target: rebuild it (cd client-shell/tauri && npm run android:build)"
                            ok=0 ;;
                        *)
                            warn "$abi: $(basename "$f") has LOAD segments aligned to ${small}(below 16 KB) — it cannot be loaded on a 16 KB-page Android 15+ device. Not built by tools/build-*-android.sh; for a Rust library add  -C link-arg=-Wl,-z,max-page-size=16384  to its rustflags." ;;
                    esac
                done ;;
        esac
    fi

    if [ "$ok" -eq 1 ]; then
        if [ -f "$dir/libcronet.so.stamp" ]; then
            echo "$TAG OK: $abi — engine carries all $N_EXPECTED exports; libcronet.so pairs with it ($(sed -n 's/^version=//p' "$dir/libcronet.so.stamp"))"
        else
            echo "$TAG OK: $abi — engine carries all $N_EXPECTED exports; built without naive"
        fi
    fi
done

# An ABI directory that will be packaged and has no engine in it: the
# APK installs on that ABI and the app cannot start there.
for dir in "$JNILIBS"/*/; do
    dir="${dir%/}"
    [ -d "$dir" ] || continue
    [ -f "$dir/libdaalcore.so" ] && continue
    if compgen -G "$dir/lib*.so" >/dev/null; then
        warn "$(basename "$dir"): libraries are staged but there is no libdaalcore.so — an APK that ships this ABI installs there and cannot start. Build the engine for it or drop the ABI from the app build."
    fi
done

# naive on some ABIs and not others is one APK that behaves two ways.
with=0; without=0
for engine in "${ENGINES[@]}"; do
    if [ -f "$(dirname "$engine")/libcronet.so" ]; then with=$((with + 1)); else without=$((without + 1)); fi
done
if [ "$with" -ne 0 ] && [ "$without" -ne 0 ]; then
    fail "libcronet.so is staged for $with ABI(s) and missing for $without — the naive tier would work on some devices and not others"
fi

if [ "$violations" -ne 0 ]; then
    cat >&2 <<MSG

ERROR: the native libraries staged for the Android APK are not a
consistent set ($violations problem(s) above). An APK built from this
tree would package them as they are.

Fix: $FIX
MSG
    exit 1
fi

if [ "$warnings" -ne 0 ]; then
    echo "$TAG OK, with $warnings warning(s) above"
else
    echo "$TAG OK"
fi
