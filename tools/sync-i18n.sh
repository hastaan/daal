#!/usr/bin/env bash
# tools/sync-i18n.sh — DEPRECATED. Do not use; do not extend.
#
# Superseded by tools/sync-i18n.mjs, which is functionally identical and
# is the one `npm run build` actually calls (client-ui/package.json).
# This script is referenced by nothing and is kept only so that any
# stale local alias or muscle-memory invocation still works. If you add
# a catalog, add it to the .mjs — changes here have no effect on any
# build.
#
# Mirrors the canonical client-shared/i18n catalogs into
# client-ui/src/i18n/d2/ where the TS bundler can resolve them.
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
