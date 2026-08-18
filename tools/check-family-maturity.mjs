#!/usr/bin/env node
// check-family-maturity.mjs — one transport family, three tables, no
// import edge between them.
//
//   bundle/go/bundle/types.go        TransportFamily — what a pack may DECLARE
//   core/routestore/family.go        familyMaturity  — what this build can DIAL
//   client-ui/.../derive_tree.ts     FAMILY_MATURITY — what the user is TOLD
//
// The first two are Go, the third is TypeScript, and nothing in the tree
// compares them. That is not hypothetical: during Wave 5 the TS mirror
// drifted twice in one wave — `wireguard` sat at 'unsupported' while Go
// had promoted it to experimental, and `anytls` was missing from the TS
// table entirely, which renders as the 'unhandled' badge. Both were
// caught by a human reading three files side by side at the end of the
// wave, which is not a process that scales past this wave.
//
// The badge is the whole user-facing honesty surface for a family: it is
// what tells someone whether a route is field-proven or has never
// carried traffic. A family missing from the TS table does not fail
// loudly, it renders as 'unhandled' — the one state that means "we have
// no idea", shown for a family Go knows perfectly well.
//
// Fails non-zero on:
//   - a TransportFamily enum value with no row in familyMaturity
//   - a familyMaturity row with no TransportFamily enum value
//   - a family in one maturity table and not the other
//   - the same family labelled differently in Go and TS

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TYPES_GO = join(ROOT, 'bundle/go/bundle/types.go');
const FAMILY_GO = join(ROOT, 'core/routestore/family.go');
const DERIVE_TS = join(ROOT, 'client-ui/src/contract/derive_tree.ts');

function read(p) {
    try {
        return readFileSync(p, 'utf8');
    } catch (e) {
        console.error(`[check-family-maturity] cannot read ${p}: ${e.message}`);
        process.exit(2);
    }
}

// A parser that silently matches nothing would make this gate green
// forever, which is worse than not having it — so every extractor
// asserts it found a plausible number of rows.
function must(name, set, min) {
    if (set.size < min) {
        console.error(
            `[check-family-maturity] parsed only ${set.size} entries from ${name} (expected >= ${min}).\n` +
            `The file's shape changed and this gate stopped checking anything. Fix the extractor.`);
        process.exit(2);
    }
    return set;
}

// bundle/go/bundle/types.go: `Transport<Name> TransportFamily = "value"`
const enumValues = new Set(
    [...read(TYPES_GO).matchAll(/^\s*Transport\w+\s+TransportFamily\s*=\s*"([^"]+)"/gm)].map((m) => m[1]));
must('types.go TransportFamily', enumValues, 15);

// core/routestore/family.go: the familyMaturity map literal.
const familyGo = read(FAMILY_GO);
const goMapBody = familyGo.match(/familyMaturity\s*=\s*map\[string\]\w+\{([\s\S]*?)\n\}/);
if (!goMapBody) {
    console.error('[check-family-maturity] could not find the familyMaturity map in core/routestore/family.go');
    process.exit(2);
}
const goMaturity = new Map(
    [...goMapBody[1].matchAll(/"([^"]+)":\s*Maturity(\w+)/g)].map((m) => [m[1], m[2].toLowerCase()]));
must('family.go familyMaturity', goMaturity, 15);

// client-ui/src/contract/derive_tree.ts: the FAMILY_MATURITY record.
const deriveTs = read(DERIVE_TS);
const tsMapBody = deriveTs.match(/FAMILY_MATURITY[^=]*=\s*\{([\s\S]*?)\n\};/);
if (!tsMapBody) {
    console.error('[check-family-maturity] could not find FAMILY_MATURITY in client-ui/src/contract/derive_tree.ts');
    process.exit(2);
}
const tsMaturity = new Map(
    [...tsMapBody[1].matchAll(/^\s*'?([A-Za-z0-9_-]+)'?:\s*'([a-z]+)'\s*,/gm)].map((m) => [m[1], m[2]]));
must('derive_tree.ts FAMILY_MATURITY', tsMaturity, 15);

const problems = [];

for (const f of enumValues) {
    if (!goMaturity.has(f)) {
        problems.push(
            `${f}: declared in bundle/go/bundle/types.go but has no row in core/routestore/family.go's ` +
            `familyMaturity. A pack may declare it and nothing in the build can say whether it is dialable.`);
    }
}
for (const f of goMaturity.keys()) {
    if (!enumValues.has(f)) {
        problems.push(
            `${f}: has a maturity row but is not a TransportFamily value — no pack can ever carry it, ` +
            `so the row describes nothing.`);
    }
}
for (const [f, label] of goMaturity) {
    if (!tsMaturity.has(f)) {
        problems.push(
            `${f}: Go says '${label}' and the TS mirror has no entry at all, so the UI renders the ` +
            `'unhandled' badge — "we have no idea" — for a family Go has a definite answer for.`);
    } else if (tsMaturity.get(f) !== label) {
        problems.push(
            `${f}: Go says '${label}', client-ui says '${tsMaturity.get(f)}'. The badge is what tells a ` +
            `user whether a route is field-proven; the two must not disagree.`);
    }
}
for (const f of tsMaturity.keys()) {
    if (!goMaturity.has(f)) {
        problems.push(`${f}: in the client-ui mirror but not in Go's familyMaturity.`);
    }
}

if (problems.length) {
    console.error('[check-family-maturity] transport-family tables disagree:\n');
    for (const p of problems) console.error(`  - ${p}`);
    console.error('');
    process.exit(1);
}

console.log(`[check-family-maturity] ${goMaturity.size} families agree across types.go, family.go and derive_tree.ts.`);
