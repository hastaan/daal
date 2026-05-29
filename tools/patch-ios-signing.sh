#!/usr/bin/env bash
# tools/patch-ios-signing.sh — disables code-signing in the freshly
# generated Tauri iOS Xcode project.
#
# Daal v0.1.0 ships an *unsigned* iOS bundle. End users re-sign it
# locally with their own free Apple ID via Sideloadly. CI doesn't have
# (and doesn't need) an Apple Developer certificate; we just need the
# Tauri/xcodebuild pipeline to stop demanding one.
#
# Why this script exists:
#   `tauri ios build` (the CLI) is the outer process; xcodebuild is
#   invoked underneath it. The "Build Rust Code" run-script phase in
#   the scaffolded Xcode project reads an env var
#   (TAURI_OPTIONS_SERVER_ADDR) that only the CLI sets, so we can't
#   bypass the CLI by calling xcodebuild directly. Instead we have to
#   make the project file itself say "signing not required".
#
# What we patch in `gen/apple/<name>.xcodeproj/project.pbxproj`:
#   * CODE_SIGN_IDENTITY = ""
#   * CODE_SIGNING_REQUIRED = NO
#   * CODE_SIGNING_ALLOWED = NO
#   * CODE_SIGN_STYLE = Manual
#   * DEVELOPMENT_TEAM = ""
#   * PROVISIONING_PROFILE_SPECIFIER = ""
#
# Idempotent: re-running the script is a no-op once the marker line is
# present.

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
GEN="${GEN:-$ROOT/client-shell/tauri/src-tauri/gen/apple}"

PBXPROJ="$(find "$GEN" -maxdepth 3 -name 'project.pbxproj' -type f | head -n 1 || true)"
if [ -z "${PBXPROJ:-}" ]; then
    echo "FATAL: no project.pbxproj found under $GEN" >&2
    echo "(run \`tauri ios init\` first)" >&2
    exit 1
fi

echo "Patching $PBXPROJ"

if grep -q 'DAAL_UNSIGNED_IOS' "$PBXPROJ"; then
    echo "patch already applied"
    exit 0
fi

python3 - "$PBXPROJ" <<'PY'
import pathlib, re, sys

p = pathlib.Path(sys.argv[1])
src = p.read_text()

# Insert marker comment AFTER the `// !$*UTF8*$!` magic header. Xcode
# requires that header to be the literal first line of the file, so we
# inject our marker on line 2.
if "DAAL_UNSIGNED_IOS" not in src:
    marker = "// DAAL_UNSIGNED_IOS — patched by tools/patch-ios-signing.sh\n"
    if src.startswith("// !$*UTF8*$!"):
        nl = src.index("\n") + 1
        src = src[:nl] + marker + src[nl:]
    else:
        src = marker + src

# Set each signing build setting to a no-cert value. Each line in the
# pbxproj XCBuildConfiguration block looks like one of:
#     CODE_SIGN_IDENTITY = "iPhone Developer";
#     "CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "iPhone Distribution";
# `force()` accepts the unquoted key name and rewrites both the bare
# and the `[sdk=...]`-qualified forms.
def force(setting: str, value: str, text: str) -> str:
    esc = re.escape(setting)
    # Bare:   KEY = ...;
    # Quoted: "KEY[sdk=...]" = ...;
    key_pat = rf'(?:{esc}|"{esc}(?:\[[^"\]]+\])?")'
    pattern = re.compile(
        rf'((?:^|\s){key_pat}\s*=\s*)("?[^";\n]*"?)(\s*;)',
        re.MULTILINE,
    )
    return pattern.sub(rf'\1{value}\3', text)

src = force('CODE_SIGN_IDENTITY', '""', src)
src = force('CODE_SIGN_STYLE', 'Manual', src)
src = force('DEVELOPMENT_TEAM', '""', src)
src = force('PROVISIONING_PROFILE_SPECIFIER', '""', src)

# Inject CODE_SIGNING_REQUIRED = NO + CODE_SIGNING_ALLOWED = NO into
# every `buildSettings = { ... }` block that doesn't already have them.
def add_setting_to_block(text: str, key: str, value: str) -> str:
    out = []
    i = 0
    needle = "buildSettings = {"
    while True:
        idx = text.find(needle, i)
        if idx == -1:
            out.append(text[i:])
            break
        end = text.find("};", idx)
        if end == -1:
            out.append(text[i:])
            break
        block = text[idx:end]
        if key not in block:
            # Match indentation of the existing settings (last
            # non-empty line in the block).
            lines = block.splitlines(keepends=True)
            indent = ""
            for line in reversed(lines):
                stripped = line.lstrip()
                if stripped and stripped != block.splitlines()[0].lstrip():
                    indent = line[: len(line) - len(stripped)]
                    break
            if not indent:
                indent = "\t\t\t\t"
            insertion = f"{indent}{key} = {value};\n"
            block = block.rstrip() + "\n" + insertion + "\t\t\t"
        out.append(text[i:idx])
        out.append(block)
        i = end
    return "".join(out)

src = add_setting_to_block(src, 'CODE_SIGNING_REQUIRED', 'NO')
src = add_setting_to_block(src, 'CODE_SIGNING_ALLOWED', 'NO')
src = add_setting_to_block(src, 'ENTITLEMENTS_REQUIRED', 'NO')

p.write_text(src)
print("patched", p)
PY

echo "==> done"
