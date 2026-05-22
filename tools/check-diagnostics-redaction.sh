#!/usr/bin/env bash
# CI: ensure exported diagnostics never include known sensitive
# strings. Reads a fixture export (or invokes the engine to produce
# one), then greps for known destinations / IPs / fingerprint hex.

set -euo pipefail

cd "$(dirname "$0")/.."

FIXTURE="${1:-test-rigs/snapshots-d2/fixtures/diagnostics-export-sample.json}"

if [ ! -f "$FIXTURE" ]; then
    echo "[check-diagnostics-redaction] no fixture at $FIXTURE — skipping"
    exit 0
fi

# Patterns that must not appear in the redacted export.
FORBIDDEN=(
    # Sample destination FQDNs / IPs from test-rigs.
    'cloudfront\.net'
    'akamaihd\.net'
    '203\.0\.113\.'
    '198\.51\.100\.'
    # Hex fingerprints (32+ hex chars) — all fingerprints in the
    # export must be 6-word renderings, not raw hex.
    '[0-9a-fA-F]{32}'
)

violations=0
for p in "${FORBIDDEN[@]}"; do
    if rg -n -e "$p" "$FIXTURE" >/dev/null 2>&1; then
        echo "[check-diagnostics-redaction] FAIL: pattern '$p' found in export"
        rg -n -e "$p" "$FIXTURE" || true
        violations=1
    fi
done

if [ "$violations" -ne 0 ]; then
    echo "ERROR: redacted diagnostics export contains forbidden text." >&2
    exit 1
fi

echo "[check-diagnostics-redaction] OK"
