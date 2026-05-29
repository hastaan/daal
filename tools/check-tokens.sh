#!/usr/bin/env bash
# CI: verify generated token files match the source-of-truth JSON.
# Re-runs the generator and fails if `git diff` shows changes.

set -euo pipefail

cd "$(dirname "$0")/.."

node tools/gen-tokens.mjs >/dev/null

# Files we generate; the diff scope is fixed so unrelated changes
# elsewhere don't trigger this check.
PATHS=(
    client-ui/src/styles.tokens.css
)

if ! git diff --quiet --exit-code -- "${PATHS[@]}"; then
    echo "ERROR: token outputs drifted from client-shared/tokens/colors.json" >&2
    echo "Run \`node tools/gen-tokens.mjs\` and commit the regenerated files." >&2
    git --no-pager diff -- "${PATHS[@]}" >&2 || true
    exit 1
fi

echo "[check-tokens] OK — generated files match source."
