#!/usr/bin/env node
// check-toolbox-profiles.mjs — the L4/L6 confirm sheets read from TS
// mirrors of Go tables. This is the gate that keeps them mirrors.
//
// Three tables live in Go and are re-declared in
// client-ui/src/publisher/rebuildPlan.ts, because the sheets need them
// before any command is called — they decide whether the button is
// even pressable, and a round-trip to the backend to find out is a
// round-trip that cannot happen inside a render:
//
//   publisher/deploy/profiles/*.json        which families a profile carries
//   publisher/deploy/sni/pool.go            region -> peering neighbourhood
//   publisher/deploy/providers/*/regions.go the per-provider offerable set
//   publisher/deploy/rotation/recommender.go  the wall-clock column
//
// This follows check-family-maturity.mjs exactly, and for the same
// reason: during Wave 5 a TS mirror of a Go table drifted twice in one
// wave and was caught by a human reading files side by side. That is
// not a process. Here the cost of drift is higher than a wrong badge —
// the profile mirror decides whether the sheet lets an operator delete
// a server for no change, and the region mirror decides which
// datacentres it offers at all.
//
// Fails non-zero on:
//   - a profile in the TS mirror whose families/defaults/udp flags
//     disagree with its JSON, or vice versa
//   - a region in the TS mirror with a different zone in sni/pool.go
//   - a vultr/stark SupportedRegions entry missing from the TS mirror
//   - a wall-clock figure that disagrees with estWallClockV15
//   - L4 or L6 dropping out of `alwaysDestroys`, which is what makes
//     the mirrored figure equal to WallClockFor's answer
//   - the two i18n catalog copies differing

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PLAN_TS = join(ROOT, 'client-ui/src/publisher/rebuildPlan.ts');
const PROFILES_DIR = join(ROOT, 'publisher/deploy/profiles');
const POOL_GO = join(ROOT, 'publisher/deploy/sni/pool.go');
const RECOMMENDER_GO = join(ROOT, 'publisher/deploy/rotation/recommender.go');

const fails = [];
const fail = (m) => fails.push(m);

function read(p) {
    try {
        return readFileSync(p, 'utf8');
    } catch (e) {
        console.error(`[check-toolbox-profiles] cannot read ${p}: ${e.message}`);
        process.exit(2);
    }
}

// A parser that silently matches nothing makes the gate green forever,
// which is worse than no gate. Every extractor asserts a floor.
function must(name, n, min) {
    if (n < min) {
        console.error(
            `[check-toolbox-profiles] parsed only ${n} entries from ${name} (expected >= ${min}).\n` +
                `The file's shape changed and this gate stopped checking anything. Fix the extractor.`,
        );
        process.exit(2);
    }
}

const planSrc = read(PLAN_TS);

// ---- 1. Toolbox profiles ------------------------------------------

/** Parse TOOLBOX_PROFILES out of the TS mirror. */
function tsProfiles() {
    const block = planSrc.slice(
        planSrc.indexOf('export const TOOLBOX_PROFILES'),
        planSrc.indexOf('export function profileBySlug'),
    );
    const out = new Map();
    const re = /slug:\s*'([^']+)',\s*candidates:\s*\[([\s\S]*?)\],\s*\}/g;
    let m;
    while ((m = re.exec(block)) != null) {
        const fams = [];
        const cre =
            /\{\s*family:\s*'([^']+)',\s*defaultEnabled:\s*(true|false),\s*udpGated:\s*(true|false)\s*\}/g;
        let c;
        while ((c = cre.exec(m[2])) != null) {
            fams.push({ family: c[1], def: c[2] === 'true', udp: c[3] === 'true' });
        }
        out.set(m[1], fams);
    }
    return out;
}

const ts = tsProfiles();
must('rebuildPlan.ts TOOLBOX_PROFILES', ts.size, 2);

const goSlugs = readdirSync(PROFILES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));
must('publisher/deploy/profiles/*.json', goSlugs.length, 2);

for (const slug of goSlugs) {
    if (!ts.has(slug)) {
        fail(
            `profile "${slug}" exists in publisher/deploy/profiles but not in TOOLBOX_PROFILES.\n` +
                `  The L6 sheet cannot offer it, so the rung silently has one fewer destination.`,
        );
        continue;
    }
    const go = JSON.parse(read(join(PROFILES_DIR, `${slug}.json`)));
    const mine = ts.get(slug);
    const goFams = go.candidates.map((c) => c.family);
    const tsFams = mine.map((c) => c.family);
    if (goFams.join(',') !== tsFams.join(',')) {
        fail(
            `profile "${slug}" families differ.\n  go: ${goFams.join(', ')}\n  ts: ${tsFams.join(', ')}\n` +
                `  The sheet projects the post-rebuild family set from the TS list, so a mismatch\n` +
                `  makes it promise a wire shape the rebuild will not produce.`,
        );
        continue;
    }
    for (const c of mine) {
        const g = go.candidates.find((x) => x.family === c.family);
        if (!!g.default_enabled !== c.def) {
            fail(`profile "${slug}" family "${c.family}": default_enabled go=${!!g.default_enabled} ts=${c.def}`);
        }
        if (!!g.udp_gated !== c.udp) {
            fail(`profile "${slug}" family "${c.family}": udp_gated go=${!!g.udp_gated} ts=${c.udp}`);
        }
    }
}
for (const slug of ts.keys()) {
    if (!goSlugs.includes(slug)) {
        fail(
            `TOOLBOX_PROFILES offers "${slug}", which is not a file in publisher/deploy/profiles.\n` +
                `  profiles.ByName would reject it, so the sheet would offer a rung that always errors.`,
        );
    }
}

// ---- 2. Regions ----------------------------------------------------

/** regionZones from publisher/deploy/sni/pool.go: `"code": ZoneName,` */
function goZones() {
    const src = read(POOL_GO);
    const block = src.slice(src.indexOf('var regionZones'), src.indexOf('func ZoneFor'));
    const out = new Map();
    const re = /"([a-z0-9-]+)":\s*Zone(\w+)/g;
    let m;
    while ((m = re.exec(block)) != null) {
        // ZoneEUCentral -> eu-central, ZoneUSEast -> us-east, ZoneAPAC -> apac
        const zone = {
            EUCentral: 'eu-central',
            EUNorth: 'eu-north',
            USEast: 'us-east',
            USWest: 'us-west',
            APAC: 'apac',
        }[m[2]];
        if (zone) out.set(m[1], zone);
    }
    return out;
}

/** REGIONS from the TS mirror, as provider -> [{code, zone}]. */
function tsRegions() {
    const block = planSrc.slice(
        planSrc.indexOf('export const REGIONS'),
        planSrc.indexOf('export function regionsFor'),
    );
    const out = new Map();
    const re = /(\w+):\s*\[([\s\S]*?)\],/g;
    let m;
    while ((m = re.exec(block)) != null) {
        const rows = [];
        const rre = /\{\s*code:\s*'([^']+)',\s*zone:\s*'([^']+)'\s*\}/g;
        let r;
        while ((r = rre.exec(m[2])) != null) rows.push({ code: r[1], zone: r[2] });
        if (rows.length) out.set(m[1], rows);
    }
    return out;
}

const zones = goZones();
must('sni/pool.go regionZones', zones.size, 10);
const regions = tsRegions();
must('rebuildPlan.ts REGIONS', regions.size, 2);

for (const [provider, rows] of regions) {
    for (const r of rows) {
        const z = zones.get(r.code);
        if (z === undefined) {
            fail(
                `region "${r.code}" (${provider}) is offered by the L4 sheet but is not in sni/pool.go's regionZones.\n` +
                    `  An unlisted code resolves to ZoneAny, so the rebuilt relay's cover host is picked from\n` +
                    `  the whole pool rather than the neighbourhood it actually sits in.`,
            );
        } else if (z !== r.zone) {
            fail(`region "${r.code}": zone go=${z} ts=${r.zone}`);
        }
    }
}

// SupportedRegions in the provider adapters that publish one.
for (const provider of ['vultr', 'stark']) {
    const p = join(ROOT, `publisher/deploy/providers/${provider}/regions.go`);
    let src;
    try {
        src = readFileSync(p, 'utf8');
    } catch {
        continue; // adapter has no region table; nothing to compare
    }
    const block = src.slice(src.indexOf('SupportedRegions'));
    const codes = [...block.matchAll(/"([a-z0-9-]+)",/g)].map((m) => m[1]);
    must(`${provider}/regions.go SupportedRegions`, codes.length, 2);
    const mine = new Set((regions.get(provider) ?? []).map((r) => r.code));
    for (const c of codes) {
        if (!mine.has(c)) {
            fail(
                `${provider} supports region "${c}" but the L4 sheet does not offer it.\n` +
                    `  Nothing breaks; the rung is just quietly narrower than the provider is.`,
            );
        }
    }
    for (const c of mine) {
        if (!codes.includes(c)) {
            fail(
                `the L4 sheet offers ${provider} region "${c}", which is not in SupportedRegions.\n` +
                    `  reprovision deletes the box before provision runs, so an unsupported region is a deleted relay.`,
            );
        }
    }
}

// ---- 3. Wall clock -------------------------------------------------

const rec = read(RECOMMENDER_GO);
const wcBlock = rec.slice(rec.indexOf('estWallClockV15 = map[Level]string{'));
const tsWc = [
    ...planSrc
        .slice(planSrc.indexOf('export const EST_WALLCLOCK'))
        .slice(0, 400)
        .matchAll(/(L\d):\s*'([^']+)'/g),
].map((m) => [m[1], m[2]]);
must('rebuildPlan.ts EST_WALLCLOCK', tsWc.length, 3);
for (const [level, est] of tsWc) {
    const m = new RegExp(`${level}:\\s*"([^"]+)"`).exec(wcBlock);
    if (!m) {
        fail(`${level} has no row in estWallClockV15, but the sheet quotes "${est}" for it.`);
    } else if (m[1] !== est) {
        fail(
            `${level} wall clock: go="${m[1]}" ts="${est}".\n` +
                `  The sheet is the last thing an operator reads before deleting a server; a number\n` +
                `  it invented rather than inherited is exactly the dial-that-lies the recommender refuses.`,
        );
    }
}

// WallClockFor returns the raw table value for a rung only while that
// rung is in alwaysDestroys — otherwise it substitutes the reprovision
// fallback string and the mirrored figure would be wrong.
const alwaysDestroys = /func alwaysDestroys\(l Level\) bool \{ return ([^}]+)\}/.exec(rec);
if (!alwaysDestroys) {
    fail(
        `alwaysDestroys has moved or changed shape in recommender.go.\n` +
            `  It is what makes the sheet's mirrored wall-clock figure equal to WallClockFor's answer.`,
    );
} else {
    for (const level of ['L4', 'L6']) {
        if (!alwaysDestroys[1].includes(level)) {
            fail(
                `${level} is no longer in alwaysDestroys, so WallClockFor may substitute the reprovision\n` +
                    `  fallback string — and the L4/L6 sheet would quote a figure the recommender would not.`,
            );
        }
    }
}

// ---- 4. i18n catalog copies ---------------------------------------

for (const f of ['d2-extra.en.json', 'd2-extra.fa.json']) {
    const a = readFileSync(join(ROOT, 'client-shared/i18n', f));
    const b = readFileSync(join(ROOT, 'client-ui/src/i18n/d2', f));
    if (!a.equals(b)) {
        fail(`${f} differs between client-shared/i18n and client-ui/src/i18n/d2 — run tools/sync-i18n.mjs`);
    }
}

// ---- report --------------------------------------------------------

if (fails.length) {
    console.error('[check-toolbox-profiles] FAIL');
    for (const f of fails) console.error('  - ' + f);
    process.exit(1);
}
console.log(
    `[check-toolbox-profiles] OK — ${ts.size} profiles, ` +
        `${[...regions.values()].reduce((n, r) => n + r.length, 0)} regions, ` +
        `${tsWc.length} wall-clock figures`,
);
