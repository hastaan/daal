#!/usr/bin/env node
// check-rotation-ladder.mjs — every rung of the rotation ladder is
// reachable, and every destroying rung refuses BEFORE it destroys.
//
// WHY THIS GATE EXISTS, given check-plumbing.mjs already runs.
//
// check-plumbing asserts that each #[tauri::command] has a UI caller.
// `wizard_rotate_execute` has had one since Wave 3 — AddressSwap.tsx —
// so that rule was green for the entire life of the ladder while L4,
// L5 and L6 were fully coded, validated, tested, and reachable by
// nothing. The rung is a STRING ARGUMENT, and a command-level gate
// cannot see arguments. Wave 6 found the same blind spot one layer
// down: `wizard_rotate_execute` had taken `new_toolbox_profile` since
// FRP-7 and the TS wrapper's argument object simply never carried the
// key, so serde saw None and L6 could not have been driven by any
// screen. Nothing was misspelled and nothing was unwired; a key was
// absent from an object literal.
//
// So this file checks the two things a per-command gate structurally
// cannot:
//
//   1. REACHABILITY PER RUNG. For L1..L6, some client-ui caller drives
//      that specific rung. A rung with no caller must be listed in
//      UNREACHABLE_RUNGS with a written reason — the same discipline
//      check-plumbing.mjs applies to allowlisted engine exports.
//
//   2. REFUSAL BEFORE DESTRUCTION. L4/L5/L6 delete the relay and build
//      a new one; `reprovision` deliberately does not re-create
//      (hetzner/provider.go). Their no-op and coherence guards
//      therefore have to run before the first provider call, because a
//      guard that fires afterwards is not a guard — the operator has
//      already lost the relay over a field the form should have
//      caught. These checks used to sit BETWEEN reprovision and
//      provision. Ordering is the whole property, and ordering is
//      exactly what a reviewer's eye slides over.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const COMMANDS_RS = join(ROOT, 'client-shell/tauri/daal-wizard/src/commands.rs');
const ACTION_GO = join(ROOT, 'publisher/deploy/rotation/action.go');
const UI_SRC = join(ROOT, 'client-ui/src');

const RUNGS = ['L1', 'L2', 'L3', 'L4', 'L5', 'L6'];

// A rung listed here has a backend arm and no way to reach it from the
// app. The string is not a note, it is the justification that has to
// survive review — delete the entry the day a screen drives the rung.
const UNREACHABLE_RUNGS = {
    // EMPTY, AND IT HAS TO STAY THAT WAY TO PASS.
    //
    // L5 lived here for one wave with a written reason: it is the only
    // rotation needing TWO cloud credentials live at once — one to
    // delete on the provider being left, one to create on the one being
    // joined — and an operator row stores exactly one. That was a
    // custody question, not a layout one, and RelayRebuild.tsx now
    // answers it: the second credential is held in component state for
    // the life of the sheet, spent on one read-only catalogue lookup
    // and the rotation, and taken into custody by the backend only
    // after `provision` has returned a live server.
    //
    // An entry added here is not a note. It is a justification that has
    // to survive review, and it must name what is missing rather than
    // what is hard.
};

// How each rung is driven from the UI. L1 and L2 are not rotate_execute
// levels on the UI side at all: they are the management fast paths
// (`rotate_credentials` / `rotate_tls`), which is why "is 'L1' written
// somewhere in client-ui" is the wrong question to ask about them.
const UI_EVIDENCE = {
    L1: (src) => src.includes('Wizard.rotateCredentials('),
    L2: (src) => src.includes('Wizard.rotateTls('),
};
const drivesExecute = (src) => src.includes('Wizard.rotateExecute(');
const namesRung = (src, rung) => new RegExp(`['"\`]${rung}['"\`]`).test(src);

function walk(dir, out = []) {
    for (const e of readdirSync(dir)) {
        const p = join(dir, e);
        if (statSync(p).isDirectory()) walk(p, out);
        else if (['.ts', '.tsx'].includes(extname(p)) && !p.includes('.test.')) out.push(p);
    }
    return out;
}

// The guard block runs from its `if matches!` down to the RUNG
// DISPATCH — the `match input.level.as_str()` at function indentation.
// Anchored on the indent because the guard block contains a `match` on
// the same expression (the preflight picks its arguments per rung), and
// a marker that matches both ends the slice before the guards it is
// supposed to be reading. Slicing to a fixed byte count instead would
// silently stop covering the block the moment it grows.
const DISPATCH = '\n    match input.level.as_str()';
function guardBlockEnd(body, guardAt) {
    const end = body.indexOf(DISPATCH, guardAt);
    return end < 0 ? guardAt + 20000 : end;
}
function guardBlockHas(body, guardAt, needle) {
    return body.slice(guardAt, guardBlockEnd(body, guardAt)).includes(needle);
}

const failures = [];
const notes = [];

// ---------------------------------------------------------------- 1
const uiFiles = walk(UI_SRC).map((p) => ({ p, src: readFileSync(p, 'utf8') }));
const rs = readFileSync(COMMANDS_RS, 'utf8');

for (const rung of RUNGS) {
    // Backend arm first: a UI caller for a rung the backend does not
    // handle is the mirror-image bug and just as invisible.
    const hasArm = new RegExp(`"${rung}"\\s*(\\||=>)`).test(rs);
    if (!hasArm) failures.push(`${rung}: no arm in rotate_execute (commands.rs)`);

    const callers = uiFiles.filter(({ p, src }) => {
        if (p.includes('wizardCommands.ts')) return false; // the wrapper is not a caller
        return UI_EVIDENCE[rung] ? UI_EVIDENCE[rung](src) : drivesExecute(src) && namesRung(src, rung);
    });

    if (callers.length > 0) {
        if (UNREACHABLE_RUNGS[rung]) {
            failures.push(
                `${rung}: listed in UNREACHABLE_RUNGS but ${callers.length} caller(s) now drive it ` +
                    `(${callers.map((c) => c.p.slice(ROOT.length + 1)).join(', ')}). Delete the entry.`,
            );
        } else {
            notes.push(`${rung}: reachable via ${callers.map((c) => c.p.slice(ROOT.length + 1)).join(', ')}`);
        }
    } else if (UNREACHABLE_RUNGS[rung]) {
        notes.push(`${rung}: UNREACHABLE — declared, with reason`);
    } else {
        failures.push(
            `${rung}: has a backend arm and NO client-ui caller. Either drive it from a screen ` +
                `or add it to UNREACHABLE_RUNGS in this file with the reason it cannot be driven.`,
        );
    }
}

// ---------------------------------------------------------------- 2
// The guards must be textually ahead of every provider call inside
// rotate_execute_inner. Offsets, not cleverness: the property is "this
// code runs first", and the first provider call is the point of no
// return for L4/L5/L6.
const innerAt = rs.indexOf('fn rotate_execute_inner');
if (innerAt < 0) failures.push('rotate_execute_inner not found — this gate is reading the wrong file');
else {
    const body = rs.slice(innerAt);
    const guardAt = body.indexOf('if matches!(input.level.as_str(), "L4" | "L5" | "L6")');
    if (guardAt < 0) {
        failures.push('the L4/L5/L6 pre-provider guard block is gone from rotate_execute_inner');
    } else {
        // The read-only viability preflight. Presence guards prove a
        // field was filled in; this proves the value WORKS — the
        // credential authenticates on the target provider, the region
        // exists in its vocabulary, and the plan is sold there. All
        // three are otherwise discovered by the create leg, which runs
        // after the delete leg has destroyed the relay. It is the one
        // provider call allowed ahead of the guards because it creates
        // nothing and bills nothing.
        if (!guardBlockHas(body, guardAt, '.run_list_server_types(')) {
            failures.push(
                'the L4/L5/L6 guard block no longer runs the read-only viability preflight ' +
                    '(run_list_server_types). Without it a mistyped token, a region code from the ' +
                    'wrong provider, or an unsold plan id passes every guard and is discovered by ' +
                    'the create leg — after the delete leg has destroyed the relay.',
            );
        }
        for (const call of ['.run_reprovision(', '.run_provision(', '.run_assign_fip(']) {
            const callAt = body.indexOf(call);
            if (callAt >= 0 && callAt < guardAt) {
                failures.push(
                    `${call} runs BEFORE the L4/L5/L6 guards. A rung that provisions and then ` +
                        `discovers it was a no-op has already spent money; a rung that DELETES and ` +
                        `then discovers it has already spent the relay.`,
                );
            }
        }
        // Each destroying rung must actually be REFUSED for each input
        // it cannot proceed without — and "refused" means a condition,
        // not a mention. Every one of these field names also appears in
        // the prose of the error message that reports it, so a check
        // for the bare string stays green when the condition guarding
        // it is neutered. Match the `is_none()` test itself.
        const required = {
            L4: ['new_region'],
            L5: ['new_provider', 'new_region', 'new_server_type', 'new_provider_token'],
            L6: ['new_profile'], // local binding for input.new_toolbox_profile
        };
        const guardBlock = body.slice(guardAt, guardBlockEnd(body, guardAt));
        for (const [rung, fields] of Object.entries(required)) {
            for (const f of fields) {
                const condition = new RegExp(`${f}(?:\\.as_ref\\(\\))?[^\\n]*\\.is_none\\(\\)`);
                if (!condition.test(guardBlock)) {
                    failures.push(
                        `${rung}: the pre-provider guard block never TESTS ${f}. Naming the field in ` +
                            `an error message is not a refusal — the rung proceeds and deletes the relay.`,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------- 3
// L3 IS NOT ONE RUNG, IT IS ONE RUNG PER PROVIDER.
//
// Section 1 asks "does some screen drive L3", and a single Hetzner
// relay makes that green forever. But whether the button is ENABLED is
// decided per provider, by `provider_can_reserve_address` in
// commands.rs — a hand-maintained mirror of which adapters implement
// `CreateFloatingIP`. Wave 6 shipped a real Vultr implementation and
// updated the Go mirror (`ActionForProvider`) and not the Rust one, so
// every Vultr relay was shown a DISABLED address swap under the
// sentence "your hosting company cannot reserve a movable address".
// Nothing failed; the cheapest rung was simply invisible on one
// provider, and the operator was pushed onto a rebuild that kills every
// distributed pack.
//
// Section 1 structurally cannot see this: it counts callers, and there
// is one. So compare the two lists directly.
const goSrc = readFileSync(ACTION_GO, 'utf8');
const goCase = goSrc.match(/case\s+((?:"[a-z]+"\s*,\s*)*"[a-z]+")\s*:\s*\n\s*\/\/ The adapter can do its half/);
const rsMatch = rs.match(/fn provider_can_reserve_address[^{]*\{([\s\S]{0,400}?)\n\}/);
if (!goCase) {
    failures.push(
        'could not find the floating-IP provider case in rotation/action.go — this gate is ' +
            'reading the wrong file or the arm was reshaped; re-anchor it rather than deleting it.',
    );
} else if (!rsMatch) {
    failures.push('could not find provider_can_reserve_address in commands.rs');
} else {
    const goList = [...goCase[1].matchAll(/"([a-z]+)"/g)].map((m) => m[1]).sort();
    const rsList = [...rsMatch[1].matchAll(/"([a-z]+)"/g)].map((m) => m[1]).sort();
    if (goList.join(',') !== rsList.join(',')) {
        failures.push(
            `L3 provider mirrors disagree: rotation/action.go says [${goList.join(', ')}] can ` +
                `reserve an address, commands.rs says [${rsList.join(', ')}]. The Go side decides ` +
                `whether the CLI will mint one; the Rust side decides whether the operator is ` +
                `OFFERED the rung. Whichever is stale, one set of relays is silently one rung short.`,
        );
    } else {
        notes.push(`L3 address reservation: [${rsList.join(', ')}] in both mirrors`);
    }
}

// ---------------------------------------------------------------- 4
// THE ADVICE PANEL'S SUBSTANCE REACHES A FARSI OPERATOR.
//
// Everything decisive on the advice panel — which rung, why, and what
// could not be seen — is computed in Go, and Go builds it in English.
// The panel ships in Farsi. So the recommender emits a stable code
// beside each English sentence and the panel keys the code, which only
// works if all four links hold: Go declares the code, the Rust mirror
// carries the field, the panel keys it, and both catalogs answer.
//
// Link 2 is why this rule is here rather than in a unit test. serde
// drops unknown keys silently, and `absent_codes` shipped declared in
// Go, keyed in the panel, and ABSENT from cli_bridge.rs — so the codes
// were emitted, discarded mid-hop, and the panel's English fallback
// fired on every single run. Nothing errored. Nothing was misspelled.
// The operator deciding whether to destroy a relay read the decisive
// text in a language they may not have, and every test was green.
const RECOMMENDER_GO = join(ROOT, 'publisher/deploy/rotation/recommender.go');
const CLI_BRIDGE_RS = join(ROOT, 'client-shell/tauri/daal-wizard/src/cli_bridge.rs');
// The panel's text layer, split out of RotationAdvice.tsx so the
// fallbacks can be tested without a renderer. This is the file that
// turns a code into a sentence, so this is the file to check.
const ADVICE_TEXT = join(ROOT, 'client-ui/src/publisher/adviceText.ts');
const CATALOGS = {
    en: join(ROOT, 'client-shared/i18n/d2-extra.en.json'),
    fa: join(ROOT, 'client-shared/i18n/d2-extra.fa.json'),
};
const CATALOG_MIRROR = join(ROOT, 'client-ui/src/i18n/d2');

const recGo = readFileSync(RECOMMENDER_GO, 'utf8');
const codesIn = (prefix) =>
    [...recGo.matchAll(new RegExp(`\\b${prefix}[A-Za-z]+\\s*=\\s*"([a-z_]+)"`, 'g'))].map((m) => m[1]);

// `absent` first: it is the half that carries the panel's honesty, the
// difference between "measured and fine" and "never measured at all".
const CODE_GROUPS = [
    { kind: 'absent', codes: codesIn('Absent'), keyPrefix: 'pub.danger.advice.absent.' },
    { kind: 'reason', codes: codesIn('Reason'), keyPrefix: 'pub.danger.advice.reason.' },
];

const bridgeRs = readFileSync(CLI_BRIDGE_RS, 'utf8');
for (const field of ['reason_code', 'reason_detail', 'absent_codes']) {
    if (!new RegExp(`pub\\s+${field}\\s*:`).test(bridgeRs)) {
        failures.push(
            `cli_bridge.rs does not declare \`${field}\`, so serde drops it on the Go→Rust hop ` +
                `and the advice panel falls back to English on every run. The failure is silent: ` +
                `no error, no missing key, just the decisive sentence in the wrong language.`,
        );
    }
}

const adviceText = readFileSync(ADVICE_TEXT, 'utf8');
const catalogs = {};
for (const [lang, path] of Object.entries(CATALOGS)) {
    catalogs[lang] = JSON.parse(readFileSync(path, 'utf8'));
}

for (const { kind, codes, keyPrefix } of CODE_GROUPS) {
    if (!codes.length) {
        failures.push(
            `no ${kind} codes found in recommender.go — this gate is reading the wrong file or ` +
                `the const block was reshaped; re-anchor it rather than deleting it.`,
        );
        continue;
    }
    // The INTERPOLATED form specifically. A bare `${keyPrefix}title`
    // sitting in a heading satisfies a substring test while nothing
    // keys the codes at all — which is how this check first passed on
    // the absences while reading the wrong file.
    if (!adviceText.includes(`${keyPrefix}\${`)) {
        failures.push(
            `adviceText.ts never builds a \`${keyPrefix}<code>\` key, so the ${kind} text renders ` +
                `as the Go side's English prose whatever the operator's language is.`,
        );
    }
    for (const code of codes) {
        const key = keyPrefix + code;
        const en = catalogs.en[key];
        const fa = catalogs.fa[key];
        if (!en) {
            failures.push(`${kind} code "${code}" has no ${key} in d2-extra.en.json`);
            continue;
        }
        if (!fa || !fa.trim()) {
            failures.push(
                `${kind} code "${code}" has no Farsi at ${key}. It degrades to English, which is ` +
                    `the designed fallback — but shipping it that way is the bug this rule exists ` +
                    `to catch, because a Farsi operator reads the decisive text and cannot act on it.`,
            );
        } else if (fa === en) {
            failures.push(`${kind} code "${code}": ${key} is the English string, not a translation`);
        }
        // A catalog string that interpolates must interpolate in BOTH
        // languages, or the Farsi reader loses the concrete blocker /
        // the list of what was seen and gets a sentence naming no cause.
        if (en.includes('{detail}') !== (fa || '').includes('{detail}')) {
            failures.push(
                `${kind} code "${code}": ${key} has {detail} in one language and not the other, so ` +
                    `one of the two renders a sentence with the specifics missing.`,
            );
        }
    }
    notes.push(`${kind} codes: ${codes.length} declared, all keyed in en + fa`);
}

// The bundler reads the mirrored copy, not the canonical one.
for (const lang of Object.keys(CATALOGS)) {
    const mirror = join(CATALOG_MIRROR, `d2-extra.${lang}.json`);
    if (readFileSync(mirror, 'utf8') !== readFileSync(CATALOGS[lang], 'utf8')) {
        failures.push(
            `client-ui/src/i18n/d2/d2-extra.${lang}.json differs from client-shared — the app ` +
                `bundles the mirror, so the catalog you edited is not the one that ships. Run ` +
                `node tools/sync-i18n.mjs.`,
        );
    }
}

for (const n of notes) console.log(`  · ${n.split('\n')[0]}`);
if (failures.length) {
    console.error('\n[check-rotation-ladder] FAILED:');
    for (const f of failures) console.error(`  ✗ ${f}`);
    process.exit(1);
}
console.log(`[check-rotation-ladder] ${RUNGS.length} rungs checked, guards ordered before the first provider call.`);
