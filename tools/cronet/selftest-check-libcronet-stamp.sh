#!/usr/bin/env bash
# Self-test for check-libcronet-stamp.sh: does the guard actually refuse
# what it exists to refuse?
#
# Each case builds a small stand-in library (an ELF header for the right
# machine plus the identity string a real libcronet.so carries) in a
# temporary directory, next to a stand-in core/go.mod, and asserts the
# verdict. No NDK and no network; the one case that needs a real ELF
# (exported-symbol coverage) runs only when ANDROID_NDK_HOME is set and
# says so when it is skipped.
#
# tools/check-android-so-manifest.sh runs this before it trusts the
# guard, so it runs wherever the gates do (tools/hooks/pre-push).
set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/check-libcronet-stamp.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/daal-cronet-selftest.XXXXXX")"
trap 'rm -rf "$T"' EXIT

MOD=github.com/sagernet/cronet-go/lib/android_arm64
NEW=v0.0.0-20260912104006-c10c03c318db
OLD=v0.0.0-20260513071149-ade33496efb8
WRAP=v0.0.0-20260912104727-0d28acc44093

mkdir -p "$T/core" "$T/emptycache"
cat > "$T/core/go.mod" <<MODEOF
module example.invalid/core

require (
	github.com/sagernet/cronet-go $WRAP // indirect
	$MOD $NEW // indirect
)
MODEOF

export DAAL_CORE_DIR="$T/core"
export GOMODCACHE="$T/emptycache"

fails=0
n=0
expect() { # <pass|fail> <name> <command...>
  local want="$1" name="$2" rc=0
  shift 2
  n=$((n + 1))
  "$@" > "$T/out.log" 2>&1 || rc=$?
  if { [ "$want" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$want" = fail ] && [ "$rc" -eq 1 ]; }; then
    return 0
  fi
  echo "[selftest-check-libcronet-stamp] FAIL: $name — expected $want, exit $rc"
  sed 's/^/    /' "$T/out.log"
  fails=$((fails + 1))
}

# fake_elf <path> <e_machine as two octal-escaped bytes> [text to embed]
fake_elf() {
  {
    printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\003\000'
    printf "$2"
    printf '\001\000\000\000padding-padding-padding\n'
    if [ -n "${3:-}" ]; then printf '%s\n' "$3"; fi
    printf 'trailing bytes\n'
  } > "$1"
}
ARM64='\267\000'
X8664='\076\000'
SHA_A=1111111111111111111111111111111111111111111111111111111111111111
id() { echo "daal-cronet-lib-id: $MOD@$1 archive-sha256=$SHA_A"; }
engine_with() { # <path> <lib version or ''>
  {
    printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\003\000'
    printf "$ARM64"
    printf '\001\000\000\000\n'
    if [ -n "$2" ]; then
      printf 'dep\tgithub.com/sagernet/cronet-go\t%s\th1:x=\n' "$WRAP"
      printf 'dep\t%s\t%s\th1:y=\n' "$MOD" "$2"
    fi
    printf 'build\t-buildmode=c-shared\n'
  } > "$1"
}

# --- one library against core/go.mod -----------------------------------
fake_elf "$T/good.so" "$ARM64" "$(id "$NEW")"
expect pass "stamping a matching library"            "$CHECK" --stamp "$T/good.so" arm64-v8a
expect pass "a matching, stamped library"            "$CHECK" "$T/good.so" arm64-v8a
expect pass "the short ABI name means the same"      "$CHECK" "$T/good.so" arm64

fake_elf "$T/noid.so" "$ARM64"
cp "$T/good.so.stamp" "$T/noid.so.stamp"
expect fail "a library with no identity (pre-stamp build), even with a stamp beside it" \
                                                     "$CHECK" "$T/noid.so" arm64-v8a
expect fail "refusing to stamp a library with no identity" \
                                                     "$CHECK" --stamp "$T/noid.so" arm64-v8a

fake_elf "$T/old.so" "$ARM64" "$(id "$OLD")"
cp "$T/good.so.stamp" "$T/old.so.stamp"
expect fail "a library linked from the previous cronet-go, with a current stamp copied beside it" \
                                                     "$CHECK" "$T/old.so" arm64-v8a
expect fail "refusing to stamp a library from the previous cronet-go" \
                                                     "$CHECK" --stamp "$T/old.so" arm64-v8a

fake_elf "$T/nostamp.so" "$ARM64" "$(id "$NEW")"
expect fail "a matching library with no stamp"       "$CHECK" "$T/nostamp.so" arm64-v8a

cp "$T/good.so" "$T/changed.so"; cp "$T/good.so.stamp" "$T/changed.so.stamp"
printf 'x' >> "$T/changed.so"
expect fail "a library changed after it was stamped" "$CHECK" "$T/changed.so" arm64-v8a

cp "$T/good.so" "$T/otherstamp.so"
sed "s/^archive_sha256=.*/archive_sha256=2222/" "$T/good.so.stamp" > "$T/otherstamp.so.stamp"
expect fail "a stamp that names a different archive than the library does" \
                                                     "$CHECK" "$T/otherstamp.so" arm64-v8a

fake_elf "$T/wrongarch.so" "$X8664" "$(id "$NEW")"
expect fail "an x86_64 library offered as arm64-v8a" "$CHECK" "$T/wrongarch.so" arm64-v8a

printf 'not an elf at all %s\n' "$(id "$NEW")" > "$T/notelf.so"
expect fail "a file that is not an ELF library"      "$CHECK" "$T/notelf.so" arm64-v8a

# --- the archive hash, when the module is in the cache ------------------
mkdir -p "$T/cache/$MOD@$NEW"
printf 'the real archive\n' > "$T/cache/$MOD@$NEW/libcronet.a"
REAL_SHA="$(sha256sum "$T/cache/$MOD@$NEW/libcronet.a" 2>/dev/null | awk '{print $1}' \
            || shasum -a 256 "$T/cache/$MOD@$NEW/libcronet.a" | awk '{print $1}')"
fake_elf "$T/realarchive.so" "$ARM64" "daal-cronet-lib-id: $MOD@$NEW archive-sha256=$REAL_SHA"
expect pass "a library whose archive hash is the cached module's" \
            env GOMODCACHE="$T/cache" "$CHECK" --stamp "$T/realarchive.so" arm64-v8a
expect fail "a library of the right version linked from some other archive" \
            env GOMODCACHE="$T/cache" "$CHECK" "$T/good.so" arm64-v8a

# --- the pair: engine binary against library ----------------------------
engine_with "$T/engine-new.so" "$NEW"
engine_with "$T/engine-old.so" "$OLD"
engine_with "$T/engine-nonaive.so" ""
expect pass "engine and library from the same cronet-go" \
                                                     "$CHECK" --pair "$T/engine-new.so" "$T/good.so" arm64-v8a
expect fail "engine built against the previous cronet-go beside the current library" \
                                                     "$CHECK" --pair "$T/engine-old.so" "$T/good.so" arm64-v8a
expect fail "current engine beside a library from the previous cronet-go" \
                                                     "$CHECK" --pair "$T/engine-new.so" "$T/old.so" arm64-v8a
expect fail "current engine beside a pre-stamp library" \
                                                     "$CHECK" --pair "$T/engine-new.so" "$T/noid.so" arm64-v8a
expect fail "an engine with naive and no library at all" \
                                                     "$CHECK" --pair "$T/engine-new.so" "$T/absent.so" arm64-v8a
expect fail "a matching pair whose library changed after stamping" \
                                                     "$CHECK" --pair "$T/engine-new.so" "$T/changed.so" arm64-v8a
expect pass "an engine built without naive needs no library" \
                                                     "$CHECK" --pair "$T/engine-nonaive.so" "$T/absent.so" arm64-v8a
expect pass "an engine built without naive ignores a stray library" \
                                                     "$CHECK" --pair "$T/engine-nonaive.so" "$T/old.so" arm64-v8a

# --- exported-symbol coverage (needs a real ELF, so needs the NDK) ------
NDK_CC=""
for h in linux-x86_64 darwin-x86_64; do
  c="${ANDROID_NDK_HOME:-/nonexistent}/toolchains/llvm/prebuilt/$h/bin/aarch64-linux-android24-clang"
  if [ -x "$c" ]; then NDK_CC="$c"; fi
done
if [ -n "$NDK_CC" ]; then
  src="$T/cache/github.com/sagernet/cronet-go@$WRAP/internal/cronet"
  mkdir -p "$src"
  cat > "$src/loader_unix.go" <<'GOEOF'
package cronet

func registerSymbols() error {
	if err := registerFunc(&a, "Cronet_Buffer_Create"); err != nil {
		return err
	}
	return registerFunc(&b, "Cronet_Engine_SetUdpDialer")
}
GOEOF
  mk_real() { # <out> <c source>
    printf '%s\n' "$2" > "$T/real.c"
    "$NDK_CC" -shared -o "$1" "$T/real.c"
  }
  IDC="const char daal_cronet_lib_id[] __attribute__((used)) = \"daal-cronet-lib-id: $MOD@$NEW archive-sha256=$REAL_SHA\\n\";"
  mk_real "$T/both.so" "$IDC void Cronet_Buffer_Create(void){} void Cronet_Engine_SetUdpDialer(void){}"
  mk_real "$T/one.so"  "$IDC void Cronet_Buffer_Create(void){}"
  expect pass "a real library exporting every function the wrapper looks up" \
              env GOMODCACHE="$T/cache" "$CHECK" --stamp "$T/both.so" arm64-v8a
  expect fail "a real library missing a function the wrapper looks up" \
              env GOMODCACHE="$T/cache" "$CHECK" --stamp "$T/one.so" arm64-v8a
else
  echo "[selftest-check-libcronet-stamp] note: ANDROID_NDK_HOME not set — the exported-symbol case was skipped"
fi

if [ "$fails" -ne 0 ]; then
  echo "[selftest-check-libcronet-stamp] $fails of $n cases FAILED — the libcronet guard cannot be trusted"
  exit 1
fi
echo "[selftest-check-libcronet-stamp] OK ($n cases)"
