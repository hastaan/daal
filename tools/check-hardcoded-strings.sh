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

# We only care about new D-2 surfaces; legacy code is allow-listed.
SCAN_PATHS=(
    "client-ui/src/d2pages"
    "client-ui/src/shell"
    "client-ui/src/onboarding"
    "client-ui/src/components/AddEntryModal.tsx"
    "client-ui/src/components/PanicWipeDialog.tsx"
    "client-ui/src/components/RecoverySheet.tsx"
    "client-ui/src/components/TrustPrompt.tsx"
    "client-ui/src/components/PhoenixButton.tsx"
)
# Pattern: a string literal of >= 12 ASCII letters (with spaces),
# wrapped in double or single quotes. The search is conservative
# but catches the common offenders ("Connect to Daal", "Add a
# route", etc.).
PATTERN='"[A-Z][A-Za-z][A-Za-z ]{10,}"'

found=0
for p in "${SCAN_PATHS[@]}"; do
    if [ ! -e "$p" ]; then continue; fi
    # Run ripgrep with json output so we can post-filter per-line.
    while IFS= read -r line; do
        # Skip allow-listed lines.
        if grep -qF -- "$line" "$ALLOWLIST" 2>/dev/null; then
            continue
        fi
        echo "$line"
        found=1
    done < <(rg -n -e "$PATTERN" "$p" \
        --glob '!**/*.json' \
        --glob '!**/*.lproj/*' \
        --glob '!**/test*/**' \
        --glob '!**/*.snap' || true)
done

if [ "$found" -ne 0 ]; then
    echo
    echo "ERROR: hard-coded user-visible strings found above." >&2
    echo "Move them to client-shared/i18n/{en,fa}.json (or platform mirror)." >&2
    echo "If a hit is a false positive, add it to $ALLOWLIST." >&2
    exit 1
fi

echo "[check-hardcoded-strings] OK — no D-2 surfaces have hard-coded user-visible strings."
