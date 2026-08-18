#!/usr/bin/env bash
# tools/check-engine-so-manifest.sh — catch a STALE libdaalcore shared library.
#
# THE FAILURE THIS EXISTS TO CATCH
# --------------------------------
# `client-shell/tauri/src-tauri/resources/libdaalcore.so` is core/abi
# built with `-buildmode=c-shared -tags cshared`. It is a build artifact
# that is CHECKED IN, and nothing rebuilds it as a side effect of
# building the desktop app — `cargo`/`tauri` just package whatever .so
# is sitting in resources/.
#
# That would be survivable if a missing export degraded one feature. It
# does not. `Engine::load` (daal-desktop-core/src/engine.rs) resolves
# every symbol EAGERLY with `?` — `lookup` turns a dlsym miss into
# DesktopError::EngineSymbol — and src-tauri/src/lib.rs wraps
# `Engine::load` in a panic at the top of `run()`, before the Tauri
# builder. So ONE missing export is not a lazy failure in some code
# path: the engine never loads, the window never opens, and every
# capability behind the C ABI is dead.
#
# That was the state of this tree when the gate was written: the staged
# .so predated core/abi/tunnel_export.go and had no
# `engine_set_tunnel_refresh`. Nothing anywhere reported it.
#
# HOW IT CHECKS
# -------------
# Enumerate the `//export engine_*` names in core/abi whose build
# constraint is plain `cshared`, and assert each is a defined dynamic
# symbol in the artefact. Exports behind extra tags (`cshared && soak`)
# are deliberately NOT required: they are not in this build variant, and
# demanding them would make the gate cry stale on a correct artefact.
#
# Exit 0 and skip when no artefact is checked in, or when `nm` is
# unavailable — a source checkout that has never built the engine is not
# broken. The skip is announced, never silent.

set -euo pipefail

cd "$(dirname "$0")/.."

ABI_DIR="core/abi"
RES_DIR="${DAAL_ENGINE_RES_DIR:-client-shell/tauri/src-tauri/resources}"

if [ ! -d "$ABI_DIR" ]; then
    echo "[check-engine-so-manifest] FATAL: $ABI_DIR missing" >&2
    exit 1
fi

# Files whose build constraint is exactly `cshared` — no extra tags.
# `//go:build cshared && soak` must not contribute.
EXPECTED="$(
    for f in "$ABI_DIR"/*.go; do
        case "$f" in *_test.go) continue ;; esac
        constraint="$(grep -m1 '^//go:build ' "$f" || true)"
        [ "$constraint" = "//go:build cshared" ] || continue
        grep -h '^//export engine_' "$f" | sed 's|^//export ||'
    done | sort -u
)"

if [ -z "$EXPECTED" ]; then
    echo "[check-engine-so-manifest] FATAL: no plain-cshared //export names found in $ABI_DIR" >&2
    echo "[check-engine-so-manifest] the gate would pass vacuously; refusing" >&2
    exit 1
fi
N_EXPECTED="$(printf '%s\n' "$EXPECTED" | wc -l | tr -d ' ')"

mapfile -t LIBS < <(find "$RES_DIR" -maxdepth 1 \
    \( -name 'libdaalcore.so' -o -name 'libdaalcore.dylib' -o -name 'daalcore.dll' \) \
    -type f 2>/dev/null | sort)

if [ "${#LIBS[@]}" -eq 0 ]; then
    echo "[check-engine-so-manifest] no libdaalcore artefact under $RES_DIR — skipping"
    echo "[check-engine-so-manifest] (build it with: cd core && CGO_ENABLED=1 go build \\"
    echo "[check-engine-so-manifest]    -buildmode=c-shared -tags cshared \\"
    echo "[check-engine-so-manifest]    -o ../$RES_DIR/libdaalcore.so ./cmd/libdaalcore)"
    exit 0
fi

if ! command -v nm >/dev/null 2>&1; then
    echo "[check-engine-so-manifest] nm(1) not available — skipping (binutils not installed)"
    exit 0
fi

violations=0
for lib in "${LIBS[@]}"; do
    present="$(nm -D --defined-only "$lib" 2>/dev/null \
        | awk '$2 ~ /^[TtWw]$/ && $3 ~ /^engine_/ {print $3}' | sort -u || true)"
    if [ -z "$present" ]; then
        echo "[check-engine-so-manifest] FAIL: $lib exports no engine_* dynamic symbols at all"
        violations=$((violations + 1))
        continue
    fi
    missing="$(comm -23 <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$present") || true)"
    if [ -n "$missing" ]; then
        n_missing="$(printf '%s\n' "$missing" | wc -l | tr -d ' ')"
        echo "[check-engine-so-manifest] FAIL: $lib is STALE ($n_missing of $N_EXPECTED exports absent):"
        printf '  %s\n' $missing
        violations=$((violations + 1))
    else
        echo "[check-engine-so-manifest] OK: $lib carries all $N_EXPECTED cshared exports"
    fi
done

if [ "$violations" -ne 0 ]; then
    cat >&2 <<'MSG'

ERROR: a checked-in libdaalcore artefact is older than core/abi.

This is NOT a degraded feature. daal-desktop-core resolves every engine
symbol eagerly in Engine::load, and src-tauri panics when load fails —
so a single missing export means the desktop app does not start.

Fix: cd core && CGO_ENABLED=1 go build -buildmode=c-shared -tags cshared \
       -o ../client-shell/tauri/src-tauri/resources/libdaalcore.so \
       ./cmd/libdaalcore
MSG
    exit 1
fi

echo "[check-engine-so-manifest] OK"
