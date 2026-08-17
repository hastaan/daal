#!/usr/bin/env bash
# tools/check-phase.sh — there is exactly ONE RelayPack phase value.
#
# WHY THIS GATE EXISTS
#
# On 2026-08-17 six sites in this repo hard-coded a phase literal and
# they disagreed:
#
#   bundle/go/importer/importer.go        V1.5   <- the recipient path
#   bundle/go/importer/refresh_apply.go   V1.6
#   client-ui/.../PublisherWizard.tsx     V1.6   <- what the wizard signs
#   daal-wizard/src/commands.rs           V1.5   <- what a ROTATION re-signs
#   publisher/deploy/cli/cli.go           V1.6
#   core/internal/selection/explain.go    V1.5
#
# Nothing failed. Every one of those calls succeeded; they just applied
# different rule-sets. The visible consequence was that the two gates
# FRP-8 had already lifted (RP004 cdn_fronted, RP021 freshness_url)
# stayed shut on the device, and a publisher rotation silently
# downgraded a pack's phase back to V1.5.
#
# A disagreement that produces no error can only be caught by a gate
# that reads all the call sites at once. This is that gate.
#
# WHAT IT ENFORCES
#
#   1. No phase string literal anywhere in source except the three
#      declaration sites and an explicit, reviewed allow-list.
#   2. The three declarations — Go, Rust, TypeScript — carry the same
#      value. They cannot import each other (the value crosses two
#      process boundaries as a plain string), so this is the only
#      place they are compared.
#
# NO RIPGREP. `rg` is a shell *function* in some environments here, so
# a clean `#!/usr/bin/env bash` script cannot call it; a gate that
# cannot run is a gate that protects nothing. Same fallback reasoning
# as tools/check-hardcoded-strings.sh, except this one never had a
# ripgrep path to begin with.

set -uo pipefail

cd "$(dirname "$0")/.."

if ! command -v grep >/dev/null 2>&1; then
    echo "[check-phase] FAIL: grep is not available" >&2
    exit 2
fi

# ---------------------------------------------------------------
# The three declaration sites. Each must exist AND must be the only
# place its language spells a phase.
# ---------------------------------------------------------------
GO_DECL="bundle/go/phase/phase.go"
RS_DECL="client-shell/tauri/daal-wizard/src/phase.rs"
TS_DECL="client-ui/src/publisher/phase.ts"

ALLOWLIST="tools/phase-allowlist.txt"

fail=0

for f in "$GO_DECL" "$RS_DECL" "$TS_DECL"; do
    if [ ! -f "$f" ]; then
        echo "[check-phase] FAIL: declaration site missing: $f" >&2
        echo "  The canonical phase must be declared in all three languages." >&2
        exit 2
    fi
done

# ---------------------------------------------------------------
# 1. Cross-language agreement.
# ---------------------------------------------------------------
# Go:   `const Current = V16`, then `V16 Phase = "V1.6"`.
go_alias="$(grep -E '^const Current = ' "$GO_DECL" | head -n1 | sed -E 's/^const Current = //; s/[[:space:]]*$//')"
if [ -z "$go_alias" ]; then
    echo "[check-phase] FAIL: no 'const Current = …' line in $GO_DECL" >&2
    exit 2
fi
go_val="$(grep -E "^[[:space:]]*${go_alias}[[:space:]]+Phase[[:space:]]*=" "$GO_DECL" |
    head -n1 | sed -E 's/.*"([^"]*)".*/\1/')"

# Rust: `pub const RELAYPACK_PHASE: &str = "V1.6";`
rs_val="$(grep -E 'pub const RELAYPACK_PHASE' "$RS_DECL" | head -n1 | sed -E 's/.*"([^"]*)".*/\1/')"

# TS:   `export const RELAYPACK_PHASE = 'V1.6';`
ts_val="$(grep -E 'export const RELAYPACK_PHASE' "$TS_DECL" | head -n1 | sed -E "s/.*['\"]([^'\"]*)['\"].*/\1/")"

if [ -z "$go_val" ] || [ -z "$rs_val" ] || [ -z "$ts_val" ]; then
    echo "[check-phase] FAIL: could not read the phase out of all three declarations." >&2
    echo "  go=${go_val:-<none>} rust=${rs_val:-<none>} ts=${ts_val:-<none>}" >&2
    exit 2
fi

if [ "$go_val" != "$rs_val" ] || [ "$go_val" != "$ts_val" ]; then
    echo "[check-phase] FAIL: the three phase declarations disagree." >&2
    echo "  $GO_DECL  -> $go_val" >&2
    echo "  $RS_DECL  -> $rs_val" >&2
    echo "  $TS_DECL  -> $ts_val" >&2
    echo "  A rotation signed at one phase and imported at another is exactly" >&2
    echo "  the bug this gate exists to stop. Make all three match." >&2
    fail=1
fi

# ---------------------------------------------------------------
# 2. No stray phase literals.
# ---------------------------------------------------------------
# Matches a quote-delimited phase and nothing else: "V1.5" / 'V1.6' /
# `V1.6`. A phase mentioned INSIDE a longer sentence (an assert message,
# a doc string) is not a call site and is not matched.
#
# THE VALUES ARE DERIVED, NOT TYPED HERE. This used to be a hard-coded
# `V1\.[56]`, which is a gate that stops covering the phase the moment
# the phase moves: flip `const Current = V2` and the scan starts hunting
# for a value nobody uses while reporting OK — strictly worse than no
# gate, because the pre-push output then asserts an invariant it no
# longer checks. Every value in the enum is read straight out of the Go
# declaration, so adding a phase constant extends this scan for free.
phase_values="$(grep -E '^[[:space:]]*[A-Za-z0-9_]+[[:space:]]+Phase[[:space:]]*=[[:space:]]*"' "$GO_DECL" |
    sed -E 's/.*"([^"]*)".*/\1/')"
if [ -z "$phase_values" ]; then
    echo "[check-phase] FAIL: no 'X Phase = \"…\"' declarations in $GO_DECL" >&2
    exit 2
fi
alternation=""
for v in $phase_values; do
    # Escape regex metacharacters in the value ('.' in "V1.5").
    esc="$(printf '%s' "$v" | sed -E 's/[.[\*^$()+?{}|\\]/\\&/g')"
    if [ -z "$alternation" ]; then alternation="$esc"; else alternation="$alternation|$esc"; fi
done
PATTERN="[\"'\`](${alternation})[\"'\`]"

# Source trees only. Docs, phase write-ups, and the signed corpus are
# excluded on purpose:
#   - specs/test-vectors/**  is the per-phase conformance corpus; every
#     vector states its own phase by design (that is the fixture).
#   - docs/, development-phases/, research/, CHANGELOG are prose.
SCAN_PATHS=(
    "bundle"
    "core"
    "publisher"
    "cmd"
    "client-ui/src"
    "client-shared"
    "client-shell/tauri/daal-wizard/src"
    "client-shell/tauri/daal-wizard/tests"
    "client-shell/tauri/src-tauri/src"
    # The --include list below advertises .kt/.java/.swift coverage; it
    # bought nothing until these two were scanned. Source dirs only —
    # the Gradle `build/` trees under plugins/ are generated.
    "client-shell/tauri/plugins/daal-platform/android/src"
    "client-shell/tauri/plugins/daal-platform/ios"
    "tools"
)

for p in "${SCAN_PATHS[@]}"; do
    # A missing scan path is a hard failure, not a skip: a silent skip
    # after a rename shrinks this gate's coverage with zero signal.
    if [ ! -e "$p" ]; then
        echo "[check-phase] FAIL: scan path does not exist: $p" >&2
        echo "  Update SCAN_PATHS in $0 to match the current tree." >&2
        exit 2
    fi
done

hits=0
while IFS= read -r line; do
    file="${line%%:*}"

    # The declaration sites are where the literal is supposed to live.
    case "$file" in
        "$GO_DECL" | "$RS_DECL" | "$TS_DECL" | "$0" | "./$0") continue ;;
    esac

    # Skip comment-only lines. A phase named in a comment explaining
    # the history (`// was literal "V1.5" here`) is documentation, not
    # a call site, and rewording prose to appease a grep makes the
    # comment worse.
    body="${line#*:}"      # strip path
    body="${body#*:}"      # strip line number
    trimmed="${body#"${body%%[![:space:]]*}"}"
    case "$trimmed" in
        //* | '#'* | '*'* | '/*'*) continue ;;
    esac

    # Explicit, reviewed exceptions.
    if [ -f "$ALLOWLIST" ] && grep -qF -- "$file" "$ALLOWLIST" 2>/dev/null; then
        continue
    fi

    echo "  $line"
    hits=1
done < <(
    grep -rnE -e "$PATTERN" "${SCAN_PATHS[@]}" \
        --include='*.go' --include='*.rs' --include='*.ts' --include='*.tsx' \
        --include='*.js' --include='*.mjs' --include='*.kt' --include='*.java' \
        --include='*.swift' --include='*.sh' \
        --exclude-dir='node_modules' --exclude-dir='target' \
        --exclude-dir='dist' --exclude-dir='.git' 2>/dev/null || true
)

if [ "$hits" -ne 0 ]; then
    echo >&2
    echo "[check-phase] FAIL: stray phase literals found above." >&2
    echo "  Read the phase from the one canonical constant instead:" >&2
    echo "    Go    daal/bundle-go/phase.Current  (or relaypackvalidate.CurrentPhase)" >&2
    echo "    Rust  crate::phase::RELAYPACK_PHASE" >&2
    echo "    TS    RELAYPACK_PHASE from src/publisher/phase.ts" >&2
    echo "  A test fixture that deliberately exercises a NON-current phase" >&2
    echo "  should use the enum (PhaseV15 / phase.V15). If it genuinely needs" >&2
    echo "  the bare string, add its path to $ALLOWLIST with a reason." >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "[check-phase] OK — one phase ($go_val), agreed across Go / Rust / TypeScript."
