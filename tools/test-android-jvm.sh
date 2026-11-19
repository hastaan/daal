#!/usr/bin/env bash
# tools/test-android-jvm.sh — run the Android service's JVM unit tests.
#
# The decisions DaalVpnService makes at a connect, a route switch and a
# cancel, and what it tells the engine about the phone's network, live
# in files with no Android and no JNI in them (vpn/SwitchPolicy.kt,
# vpn/StartSequence.kt, vpn/NetworkWatch.kt) so that they can be tested
# on a plain JVM (src/test/.../SwitchPolicyTest.kt, StartSequenceTest.kt,
# NetworkWatchTest.kt), plus the back answer, the screen-capture flag
# (vpn/SecureScreen.kt, PB-20) and the saved-file name (vpn/SavedName.kt,
# PB-3).
# Until this script existed nothing ran those tests: the Gradle task
# (`:tauri-plugin-daal-platform:testDebugUnitTest`) needs the generated
# Android project, the Android SDK and a junit download, none of which
# `./daal test` or the gate has. A regression back to "a refused switch
# tears the tunnel down" passed every gate.
#
# This compiles exactly those sources with a Kotlin compiler and runs
# them with real JUnit 4 — no Android SDK, no network.
#
# Needs:
#   - a Kotlin compiler: `kotlinc` on PATH, or $KOTLINC, or the
#     embeddable compiler that ships inside any Gradle distribution;
#   - junit-4 + hamcrest-core jars: $JUNIT_CP, or a Gradle distribution's
#     lib/ ($GRADLE_HOME, ~/.gradle/wrapper/dists, /usr/share/gradle*);
#   - a JDK/JRE the compiler understands. Kotlin 2.0's compiler cannot
#     parse the version string of Java 25, so 21 or 17 is preferred
#     ($JAVA_HOME first, then /usr/lib/jvm).
#
# Exit codes:
#   0   every test passed
#   1   a test failed, or the sources did not compile
#   77  SKIPPED — a tool is missing. NOT a pass: nothing was tested.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/client-shell/tauri/plugins/daal-platform/android/src"
MAIN="$SRC/main/java/org/daal/desktop/vpn"
TEST="$SRC/test/java/org/daal/desktop/vpn"

# Pure sources only. A file that imports android.* does not belong here.
SOURCES=("$MAIN/SwitchPolicy.kt" "$MAIN/StartSequence.kt" "$MAIN/NetworkWatch.kt" "$MAIN/BackAnswer.kt" "$MAIN/SecureScreen.kt" "$MAIN/SavedName.kt")
TESTS=()
CLASSES=()
for f in "$TEST"/*Test.kt; do
  [[ -f "$f" ]] || continue
  TESTS+=("$f")
  CLASSES+=("org.daal.desktop.vpn.$(basename "$f" .kt)")
done
if [[ ${#TESTS[@]} -eq 0 ]]; then
  echo "test-android-jvm: no tests under $TEST" >&2
  exit 1
fi
for f in "${SOURCES[@]}"; do
  if grep -qE '^import (android|androidx)\.' "$f"; then
    echo "test-android-jvm: $f imports Android classes; it can no longer be tested on a plain JVM" >&2
    exit 1
  fi
done

skip() {
  echo "test-android-jvm: SKIPPED — $1" >&2
  echo "test-android-jvm: the Android service's switch/cancel tests did NOT run. This is not a pass." >&2
  exit 77
}

# --- a Java the Kotlin compiler can run on.
pick_java() {
  local c v
  for c in "${JAVA_HOME:-}" /usr/lib/jvm/java-21-openjdk* /usr/lib/jvm/java-17-openjdk* /usr/lib/jvm/temurin-21* /usr/lib/jvm/temurin-17*; do
    [[ -n "$c" && -x "$c/bin/java" ]] || continue
    v="$("$c/bin/java" -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')"
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 11 && v <= 22 )); then
      echo "$c/bin/java"; return 0
    fi
  done
  if command -v java >/dev/null 2>&1; then
    v="$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')"
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 11 && v <= 22 )); then
      command -v java; return 0
    fi
  fi
  return 1
}
JAVA="$(pick_java)" || skip "no Java 11–22 found (set JAVA_HOME; Kotlin's compiler does not run on newer ones)"

# --- a Gradle distribution's lib/ directory, for jars that ship with it.
gradle_libs() {
  local d
  for d in "${GRADLE_HOME:-}/lib" "$HOME"/.gradle/wrapper/dists/*/*/gradle-*/lib /usr/share/gradle*/lib /usr/share/gradle*/gradle-*/lib /opt/gradle*/lib; do
    [[ -f "$(ls "$d"/junit-4*.jar 2>/dev/null | head -1)" ]] && { echo "$d"; return 0; }
  done
  return 1
}
GL="$(gradle_libs || true)"
jar_in() { ls "$1"/$2 2>/dev/null | head -1; }

JUNIT_CP="${JUNIT_CP:-}"
if [[ -z "$JUNIT_CP" ]]; then
  [[ -n "$GL" ]] || skip "no junit-4 jar found (set JUNIT_CP, or install Gradle)"
  JUNIT_CP="$(jar_in "$GL" 'junit-4*.jar'):$(jar_in "$GL" 'hamcrest-core-*.jar')"
fi

OUT="$(mktemp -d "${TMPDIR:-/tmp}/daal-android-jvm.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

KOTLINC="${KOTLINC:-$(command -v kotlinc || true)}"
STDLIB=""
compile_rc=0
if [[ -n "$KOTLINC" ]]; then
  JAVA_HOME="$(dirname "$(dirname "$JAVA")")" "$KOTLINC" -nowarn -jvm-target 1.8 \
    -cp "$JUNIT_CP" -d "$OUT" "${SOURCES[@]}" "${TESTS[@]}" || compile_rc=$?
  STDLIB="$(jar_in "$(dirname "$(dirname "$(readlink -f "$KOTLINC")")")/lib" 'kotlin-stdlib.jar')"
  [[ -n "$STDLIB" ]] || STDLIB="$( [[ -n "$GL" ]] && jar_in "$GL" 'kotlin-stdlib-[0-9]*.jar')"
else
  [[ -n "$GL" && -f "$(jar_in "$GL" 'kotlin-compiler-embeddable-*.jar')" ]] \
    || skip "no Kotlin compiler found (install kotlinc, set KOTLINC, or install Gradle)"
  STDLIB="$(jar_in "$GL" 'kotlin-stdlib-[0-9]*.jar')"
  ccp="$(jar_in "$GL" 'kotlin-compiler-embeddable-*.jar'):$STDLIB"
  for j in 'kotlin-script-runtime-*.jar' 'kotlin-reflect-*.jar' 'kotlin-daemon-embeddable-*.jar' 'trove4j-*.jar' 'annotations-[0-9]*.jar' 'kotlinx-coroutines-core-jvm-*.jar'; do
    p="$(jar_in "$GL" "$j")"; [[ -n "$p" ]] && ccp="$ccp:$p"
  done
  "$JAVA" -cp "$ccp" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect -nowarn \
    -jvm-target 1.8 -cp "$JUNIT_CP:$STDLIB" -d "$OUT" "${SOURCES[@]}" "${TESTS[@]}" || compile_rc=$?
fi
if [[ "$compile_rc" -ne 0 ]]; then
  echo "test-android-jvm: the sources did not compile" >&2
  exit 1
fi
[[ -n "$STDLIB" ]] || skip "no kotlin-stdlib jar found to run the tests with"

"$JAVA" -cp "$OUT:$STDLIB:$JUNIT_CP" org.junit.runner.JUnitCore "${CLASSES[@]}"
