#!/usr/bin/env bash
# tools/check-deploy-so-manifest.sh — catch a STALE libdaal_deploy.so.
#
# THE FAILURE THIS EXISTS TO CATCH
# --------------------------------
# `libdaal_deploy.so` is cmd/daal-deploy cross-compiled for Android's
# jniLibs directory. It is built ONLY by tools/build-deploy-android.sh —
# `tauri android build` does not rebuild it, it just packages whatever
# .so is already sitting in gen/android/.../jniLibs/, and gen/android is
# gitignored. So editing publisher/deploy/cloudinit/artifacts.go (new
# relay release, new pin, new mirror) and then running `tauri android
# build` produces an APK that provisions relays from the PREVIOUS
# manifest, silently. That mismatch has already cost a full debugging
# cycle.
#
# HOW IT CHECKS
# -------------
# The manifest is Go source compiled INTO the binary, so every pinned
# Sha256 / SigHex literal in artifacts.go must appear verbatim in the
# .so's string data. `-ldflags "-s -w"` strips symbols and DWARF, not
# .rodata, so this holds for release builds too — and it is arch-neutral,
# which matters because the host cannot execute an Android arm64 binary.
#
# A missing literal proves the .so predates the current artifacts.go.
# (The converse is not proven: a .so can carry extra literals from a
# manifest entry that was since deleted. Deletions are rare and this
# check is deliberately the cheap direction.)
#
# Exit 0 and skip when no .so has been built — a source checkout that
# has never run the Android build is not broken.

set -euo pipefail

cd "$(dirname "$0")/.."

MANIFEST_SRC="publisher/deploy/cloudinit/artifacts.go"
JNILIBS="${OUT_DIR:-client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs}"

if [ ! -f "$MANIFEST_SRC" ]; then
    echo "[check-deploy-so-manifest] FATAL: $MANIFEST_SRC missing" >&2
    exit 1
fi

# Every 64-hex Sha256 and 128-hex SigHex literal in the manifest source.
mapfile -t PINS < <(
    grep -oE '(Sha256|SigHex): *"[0-9a-f]+"' "$MANIFEST_SRC" \
        | grep -oE '"[0-9a-f]+"' | tr -d '"' | sort -u
)

if [ "${#PINS[@]}" -eq 0 ]; then
    echo "[check-deploy-so-manifest] FATAL: no pins parsed out of $MANIFEST_SRC" >&2
    exit 1
fi

# Only the jniLibs copies are the build INPUT that ships. The Gradle
# intermediates under app/build/ are derived and get regenerated.
mapfile -t SOS < <(find "$JNILIBS" -name libdaal_deploy.so -type f 2>/dev/null | sort)

if [ "${#SOS[@]}" -eq 0 ]; then
    echo "[check-deploy-so-manifest] no libdaal_deploy.so under $JNILIBS — skipping"
    echo "[check-deploy-so-manifest] (build it with tools/build-deploy-android.sh)"
    exit 0
fi

violations=0
for so in "${SOS[@]}"; do
    missing=0
    for pin in "${PINS[@]}"; do
        if ! grep -a -F -q "$pin" "$so"; then
            echo "[check-deploy-so-manifest] FAIL: $so is missing pin $pin"
            missing=$((missing + 1))
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo "[check-deploy-so-manifest]   -> $so is STALE ($missing of ${#PINS[@]} pins absent)"
        violations=$((violations + 1))
    else
        echo "[check-deploy-so-manifest] OK: $so carries all ${#PINS[@]} pins"
    fi
done

if [ "$violations" -ne 0 ]; then
    cat >&2 <<'MSG'

ERROR: a shipped libdaal_deploy.so does not match
publisher/deploy/cloudinit/artifacts.go. An APK built from this tree
would provision relays from a stale artefact manifest.

Fix: ANDROID_NDK_HOME=... bash tools/build-deploy-android.sh
MSG
    exit 1
fi

echo "[check-deploy-so-manifest] OK"
