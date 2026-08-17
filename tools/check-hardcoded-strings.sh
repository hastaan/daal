#!/usr/bin/env bash
# CI: forbid user-visible hard-coded English strings in UI source.
# Called by `./daal release-check` and the lint workflow.
#
# Strategy: ripgrep for common UI text patterns inside the three
# client trees, *outside* i18n catalogs and dev/test fixtures. Any
# line that matches an English ASCII string of >= 12 letters inside
# JSX/Compose/SwiftUI literals is flagged.
#
# False positives are silenced by:
#   - Skipping i18n catalogs (the source-of-truth)
#   - Skipping comments
#   - Skipping snapshot / test fixture files
#   - An explicit allow-list (`tools/i18n-allowlist.txt`)

set -euo pipefail

cd "$(dirname "$0")/.."

ALLOWLIST="tools/i18n-allowlist.txt"

# Hard precondition. The scan below ends in `|| true` (a no-match from
# ripgrep is exit 1 and must not abort the loop), which also swallows
# exit 127 when ripgrep is absent — making "no hits" and "no ripgrep"
# indistinguishable. `set -euo pipefail` does not catch it either,
# because the invocation sits in a process substitution.
# Pick a scanner. ripgrep is preferred, but it is not installed everywhere
# (notably it is a shell *function* in some interactive environments, which a
# clean `#!/usr/bin/env bash` script cannot call) — and a gate that cannot run
# on a given machine is a gate that silently protects nothing there. Fall back
# to POSIX grep with the equivalent exclusions rather than failing.
if command -v rg >/dev/null 2>&1; then
    SCANNER=rg
elif command -v grep >/dev/null 2>&1; then
    SCANNER=grep
    echo "[check-hardcoded-strings] note: ripgrep not found, using grep fallback" >&2
else
    echo "[check-hardcoded-strings] FAIL: neither ripgrep nor grep is available" >&2
    exit 2
fi

# We only care about new D-2 surfaces; legacy code is allow-listed.
SCAN_PATHS=(
    "client-ui/src/d2pages"
    "client-ui/src/shell"
    "client-ui/src/onboarding"
    "client-ui/src/components/AddEntryModal.tsx"
    "client-ui/src/components/PanicWipeDialog.tsx"
    "client-ui/src/components/RecoverySheet.tsx"
    "client-ui/src/components/TrustPrompt.tsx"
)
# Pattern: a string literal of >= 12 ASCII letters (with spaces),
# wrapped in double or single quotes. The search is conservative
# but catches the common offenders ("Connect to Daal", "Add a
# route", etc.).
PATTERN='"[A-Z][A-Za-z][A-Za-z ]{10,}"'

found=0
for p in "${SCAN_PATHS[@]}"; do
    # A missing scan path is a hard failure, not a skip. Silently
    # skipping means any future file rename shrinks this gate's
    # coverage with zero signal.
    if [ ! -e "$p" ]; then
        echo "[check-hardcoded-strings] FAIL: scan path does not exist: $p" >&2
        echo "  Update SCAN_PATHS in $0 to match the current tree." >&2
        exit 2
    fi
    # Run ripgrep with json output so we can post-filter per-line.
    while IFS= read -r line; do
        # Skip allow-listed lines.
        if grep -qF -- "$line" "$ALLOWLIST" 2>/dev/null; then
            continue
        fi
        echo "$line"
        found=1
    done < <(
        if [ "$SCANNER" = rg ]; then
            rg -n -e "$PATTERN" "$p" \
                --glob '!**/*.json' \
                --glob '!**/*.lproj/*' \
                --glob '!**/test*/**' \
                --glob '!**/*.snap' || true
        else
            # Same exclusions as the ripgrep globs above.
            grep -rnE -e "$PATTERN" "$p" \
                --exclude='*.json' \
                --exclude='*.snap' \
                --exclude-dir='*.lproj' \
                --exclude-dir='test' \
                --exclude-dir='tests' \
                --exclude-dir='__tests__' || true
        fi
    )
done

if [ "$found" -ne 0 ]; then
    echo
    echo "ERROR: hard-coded user-visible strings found above." >&2
    echo "Move them to client-shared/i18n/{en,fa}.json (or platform mirror)." >&2
    echo "If a hit is a false positive, add it to $ALLOWLIST." >&2
    exit 1
fi

echo "[check-hardcoded-strings] OK — no D-2 surfaces have hard-coded user-visible strings."
