#!/usr/bin/env node
// tools/sync-i18n.mjs — mirrors the canonical client-shared/i18n catalogs
// into client-ui/src/i18n/d2/ where the TS bundler can resolve them.
// Run automatically by `npm run build`. Node port of sync-i18n.sh so it
// works on Windows runners where bash isn't on PATH.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const outDir = join(repoRoot, "client-ui", "src", "i18n", "d2");
const srcDir = join(repoRoot, "client-shared", "i18n");

const files = [
  "desktop.en.json",
  "desktop.fa.json",
  "onboarding.en.json",
  "onboarding.fa.json",
  "mobile.en.json",
  "mobile.fa.json",
  "d2-extra.en.json",
  "d2-extra.fa.json",
];

mkdirSync(outDir, { recursive: true });
for (const f of files) {
  copyFileSync(join(srcDir, f), join(outDir, f));
}
