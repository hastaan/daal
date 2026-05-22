#!/usr/bin/env bash
# tools/patch-android-signing.sh — inserts a release signingConfig block
# into the Tauri-generated client-shell/tauri/src-tauri/gen/android/app/build.gradle.kts.
#
# Tauri's `tauri android init` does not configure a release-signing
# keystore. We patch the freshly generated file once per CI run to
# read keystore.properties (also written by CI) and sign the release
# APK / AAB. When keystore.properties is absent (local dev), the
# release build falls back to the debug signing config so engineers
# can still produce installable APKs without secrets.
#
# This script is idempotent; running it twice is a no-op.

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
APP_GRADLE="${APP_GRADLE:-$ROOT/client-shell/tauri/src-tauri/gen/android/app/build.gradle.kts}"

if [ ! -f "$APP_GRADLE" ]; then
  echo "FATAL: $APP_GRADLE not found (run \`tauri android init\` first)" >&2
  exit 1
fi

if grep -q 'DAAL_RELEASE_SIGNING' "$APP_GRADLE"; then
  echo "patch already applied"
  exit 0
fi

# Add Properties import after the existing imports, then inject the
# signingConfigs and tweak the release buildType to reference it.
python3 - "$APP_GRADLE" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1])
src = p.read_text()

added = []
if "java.io.FileInputStream" not in src:
    added.append("import java.io.FileInputStream")
if "java.util.Properties" not in src:
    added.append("import java.util.Properties")
if added:
    src = "\n".join(added) + "\n" + src

PROPS_DECL = '''
    // DAAL_RELEASE_SIGNING — wired by tools/patch-android-signing.sh.
    // CI writes keystore.properties before invoking `tauri android build`.
    // Local dev without secrets falls back to the debug signing config
    // (release builds remain installable for engineers).
    val keystorePropertiesFile = rootProject.file("keystore.properties")
    val keystoreProperties = Properties()
    val hasReleaseKeystore = keystorePropertiesFile.exists()
    if (hasReleaseKeystore) {
        keystoreProperties.load(FileInputStream(keystorePropertiesFile))
    }
'''

CREATE_RELEASE = '''        if (hasReleaseKeystore) {
            create("release") {
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["password"] as String
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["password"] as String
            }
        }
'''

# 1. Insert the keystore-properties decl at the top of the android { } block.
src = re.sub(
    r'(android\s*\{\s*\n)',
    r'\1' + PROPS_DECL + '\n',
    src,
    count=1,
)

# 2. If a signingConfigs { } block already exists, merge our `create("release")`
#    into it. Otherwise, append a fresh signingConfigs block right after the
#    properties decl.
if re.search(r'signingConfigs\s*\{', src):
    src = re.sub(
        r'(signingConfigs\s*\{\s*\n)',
        r'\1' + CREATE_RELEASE,
        src,
        count=1,
    )
else:
    SIGN_BLOCK = '    signingConfigs {\n' + CREATE_RELEASE + '    }\n'
    src = re.sub(
        r'(// DAAL_RELEASE_SIGNING.*?\n.*?keystoreProperties\.load\(FileInputStream\(keystorePropertiesFile\)\)\s*\n\s*\}\n)',
        r'\1' + SIGN_BLOCK,
        src,
        count=1,
        flags=re.DOTALL,
    )

# 3. Hook the release buildType to use the release signing config when present.
if 'signingConfig = signingConfigs.getByName("release")' not in src:
    src = re.sub(
        r'(getByName\("release"\)\s*\{\s*\n)',
        r'\1            signingConfig = if (hasReleaseKeystore) signingConfigs.getByName("release") else signingConfigs.getByName("debug")\n',
        src,
        count=1,
    )

# 4. APK size reduction patches.
#    - isShrinkResources = true: removes unused drawables, layouts, etc.
#    - packaging block: strip the redundant libdaalcore.so from
#      assets/resources/ (Tauri's bundle.resources copies it there for
#      ALL platforms, but on Android we load it via JNI from lib/<abi>/
#      so the assets copy is dead weight (~15 MB per APK).
#    - Drop kotlin metadata that's already stripped by proguard.
SIZE_PATCH = '''            isShrinkResources = true
            packaging {
                // Tauri's bundle.resources copies libdaalcore.so into
                // assets/resources/ for every platform. On Android the
                // file is loaded via JNI from lib/<abi>/ instead, so
                // the assets copy is dead weight (~15 MB per APK).
                resources.excludes.add("assets/resources/libdaalcore.so")
                resources.excludes.add("META-INF/*.kotlin_module")
                resources.excludes.add("kotlin-tooling-metadata.json")
                resources.excludes.add("DebugProbesKt.bin")
                jniLibs.useLegacyPackaging = true
            }
'''
if 'isShrinkResources = true' not in src:
    # Insert right after the signingConfig line we added in step 3, inside the release block.
    src = re.sub(
        r'(signingConfig = if \(hasReleaseKeystore\)[^\n]*\n)',
        r'\1' + SIZE_PATCH,
        src,
        count=1,
    )

p.write_text(src)
print("patched", p)
PY

echo "==> done"
