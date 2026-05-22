#!/usr/bin/env bash
# tools/sync-i18n.sh — mirrors the canonical client-shared/i18n catalogs
# into client-ui/src/i18n/d2/ where the TS bundler can resolve them.
# Run automatically by `npm run build`.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/client-ui/src/i18n/d2"
mkdir -p "$OUT"
cp -f "$REPO_ROOT/client-shared/i18n/desktop.en.json"     "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/desktop.fa.json"     "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/onboarding.en.json"  "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/onboarding.fa.json"  "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/mobile.en.json"      "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/mobile.fa.json"      "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/d2-extra.en.json"    "$OUT/"
cp -f "$REPO_ROOT/client-shared/i18n/d2-extra.fa.json"    "$OUT/"
