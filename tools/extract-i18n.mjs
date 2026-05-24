#!/usr/bin/env node
// tools/extract-i18n.mjs — extract the HTML's `const i18n = { en:{...}, fa:{...} }`
// JS object into machine-readable JSON catalogs.
//
// Usage:  node tools/extract-i18n.mjs
//
// Inputs (visual contracts):
//   client-shared/designs/daal-desktop.html
//   client-shared/designs/daal-mobile-app.html
//   client-shared/designs/on-boarding.html
//
// Outputs (canonical i18n source of truth):
//   client-shared/i18n/desktop.{en,fa}.json
//   client-shared/i18n/mobile.{en,fa}.json
//   client-shared/i18n/onboarding.{en,fa}.json
//
// Strategy: locate "const i18n = {" then capture balanced braces, then
// `eval` the resulting expression in a safe sandbox (only literal
// objects/strings — no function calls). We then stringify back to
// stable, sorted JSON.

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// Sources annotated with their extraction strategy:
//   'js'    — has `const i18n = { en:{...}, fa:{...} }` (desktop)
//   'attr'  — uses `data-i18n="key"` attrs with EN inline text (mobile, onboarding)
const SOURCES = [
  { file: 'client-shared/designs/daal-desktop.html',     out: 'desktop',    strategy: 'js'   },
  { file: 'client-shared/designs/daal-mobile-app.html',  out: 'mobile',     strategy: 'attr' },
  { file: 'client-shared/designs/on-boarding.html',      out: 'onboarding', strategy: 'attr' },
];

const OUT_DIR = path.join(ROOT, 'client-shared/i18n');
fs.mkdirSync(OUT_DIR, { recursive: true });

function extractI18nObjectSource(html) {
  // Find a JS declaration "const i18n = { ... }" with balanced braces.
  const declRe = /(?:const|let|var)\s+i18n\s*=\s*\{/m;
  const m = declRe.exec(html);
  if (!m) return null;
  const start = m.index + m[0].length - 1; // index of opening '{'
  // Walk braces, ignoring strings and template literals.
  let depth = 0;
  let i = start;
  let inStr = null; // ' " ` or null
  let escape = false;
  while (i < html.length) {
    const ch = html[i];
    if (inStr) {
      if (escape) { escape = false; }
      else if (ch === '\\') { escape = true; }
      else if (ch === inStr) { inStr = null; }
    } else {
      if (ch === '"' || ch === "'" || ch === '`') inStr = ch;
      else if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          return html.slice(start, i + 1);
        }
      }
    }
    i++;
  }
  return null;
}

function evalLiteralObject(src) {
  // Use vm.runInNewContext with NO globals. The HTML i18n objects are
  // pure data: nested object literals + string literals only.
  const code = `(${src})`;
  return vm.runInNewContext(code, Object.create(null), { timeout: 1000 });
}

function sortKeysDeep(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeysDeep);
  const out = {};
  for (const k of Object.keys(obj).sort()) out[k] = sortKeysDeep(obj[k]);
  return out;
}

// HTML entity decode for the small set we care about
const HTML_ENTITY_MAP = {
  '&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&#39;':"'",'&nbsp;':' ','&middot;':'·',
  '&mdash;':'—','&ndash;':'–','&hellip;':'…','&rsquo;':'\u2019','&lsquo;':'\u2018',
  '&rdquo;':'\u201d','&ldquo;':'\u201c','&times;':'×','&check;':'✓','&copy;':'©',
};
function decodeEntities(s) {
  return s
    .replace(/&[a-z#0-9]+;/gi, (m) => HTML_ENTITY_MAP[m] ?? m)
    .replace(/\s+/g, ' ')
    .trim();
}

// Extract { key: "english text" } from `data-i18n="key">text</...` patterns
function extractDataI18n(html) {
  const out = {};
  // Match: data-i18n="KEY" optionally with other attrs > TEXT < (until next tag)
  // We cap TEXT to 600 chars to avoid pathological matches.
  const re = /data-i18n=(["'])([^"']+)\1[^>]*>([^<]{0,600})</g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const key = m[2];
    const text = decodeEntities(m[3]);
    if (text && !out[key]) {
      out[key] = text;
    } else if (text && out[key] && out[key] !== text) {
      // Conflict — keep the first; warn.
      // (HTMLs sometimes reuse a key in two places; designer's intent is consistent text.)
    }
  }
  return out;
}

// Load the existing hand-written FA catalog (if any) and try to map
// keys whose EN is identical or whose key-stem matches.
function loadExistingFa() {
  const candidates = [
    'client-ui/src/i18n/fa.json',
  ];
  const merged = {};
  for (const c of candidates) {
    const p = path.join(ROOT, c);
    if (!fs.existsSync(p)) continue;
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    Object.assign(merged, j);
  }
  return merged;
}

const EXISTING_FA = loadExistingFa();

// For attr-mode HTMLs, we don't have FA from the HTML. We attempt a
// best-effort lookup against the existing FA catalogs. Keys not found
// are written as "" (empty string) — surfaces will fall back to EN at
// render time, but the JSON file makes the gap explicit so a translator
// can fill it.
function buildFaForAttr(enMap) {
  const fa = {};
  for (const [k, en] of Object.entries(enMap)) {
    // Try: exact key match in existing catalogs
    if (EXISTING_FA[k] && EXISTING_FA[k] !== en) {
      fa[k] = EXISTING_FA[k];
      continue;
    }
    // Try: dotted variants (existing uses 'nav.connection', HTML uses 'nav-connection')
    const dotted = k.replace(/[-_]/g, '.');
    if (EXISTING_FA[dotted] && EXISTING_FA[dotted] !== en) {
      fa[k] = EXISTING_FA[dotted];
      continue;
    }
    // Fallback: blank — translator-todo
    fa[k] = '';
  }
  return fa;
}

let total = 0;
for (const { file, out, strategy } of SOURCES) {
  const html = fs.readFileSync(path.join(ROOT, file), 'utf8');
  let en, fa;
  if (strategy === 'js') {
    const objSrc = extractI18nObjectSource(html);
    if (!objSrc) {
      console.error(`extract-i18n: no i18n object in ${file}, skipping`);
      continue;
    }
    let obj;
    try {
      obj = evalLiteralObject(objSrc);
    } catch (e) {
      console.error(`extract-i18n: failed to eval i18n in ${file}: ${e.message}`);
      process.exitCode = 1;
      continue;
    }
    if (!obj.en || !obj.fa) {
      console.error(`extract-i18n: ${file} missing en/fa branches`);
      process.exitCode = 1;
      continue;
    }
    en = sortKeysDeep(obj.en);
    fa = sortKeysDeep(obj.fa);
  } else if (strategy === 'attr') {
    const enMap = extractDataI18n(html);
    if (Object.keys(enMap).length === 0) {
      console.error(`extract-i18n: no data-i18n attrs in ${file}`);
      process.exitCode = 1;
      continue;
    }
    en = sortKeysDeep(enMap);
    fa = sortKeysDeep(buildFaForAttr(enMap));
  } else {
    console.error(`extract-i18n: unknown strategy ${strategy}`);
    continue;
  }
  fs.writeFileSync(
    path.join(OUT_DIR, `${out}.en.json`),
    JSON.stringify(en, null, 2) + '\n',
  );
  fs.writeFileSync(
    path.join(OUT_DIR, `${out}.fa.json`),
    JSON.stringify(fa, null, 2) + '\n',
  );
  const enKeys = Object.keys(en).length;
  const faFilled = Object.values(fa).filter(v => v && v.length).length;
  console.log(`extract-i18n: ${file} → ${out}.{en,fa}.json (${enKeys} EN, ${faFilled}/${enKeys} FA filled)`);
  total += enKeys;
}

console.log(`extract-i18n: total ${total} keys across ${SOURCES.length} surfaces`);
