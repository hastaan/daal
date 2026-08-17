#!/usr/bin/env node
// check-plumbing.mjs — verifies the four-layer end-to-end plumbing:
//
//   Engine ABI (//export engine_*)  →  desktop-core (engine.rs/commands.rs)
//   →  Tauri (#[tauri::command])    →  D2Contract / wizard/recipient
//
// Fails non-zero on:
//   - engine export not reached by any commands.rs function (test-only
//     exports are listed in the allowlist below)
//   - #[tauri::command] not registered in generate_handler!
//   - #[tauri::command] not invoked from any client-ui invoke() call
//     (recipient/wizard commands count when invoke() is in client-ui)
//
// Designed to run in CI; prints a JSON report to stdout when --json.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const ENGINE_DIR = join(ROOT, 'core/abi');
const ENGINE_RS = join(ROOT, 'client-shell/tauri/daal-desktop-core/src/engine.rs');
const CMD_RS = join(ROOT, 'client-shell/tauri/daal-desktop-core/src/commands.rs');
const LIB_RS = join(ROOT, 'client-shell/tauri/src-tauri/src/lib.rs');
const UI_SRC = join(ROOT, 'client-ui/src');

// Test/soak exports we deliberately don't surface to the GUI.
const ENGINE_ALLOWLIST = new Set([
    'engine_set_now_unix',
    'engine_soak_set_wg_memory_kib',
    'engine_soak_force_wg_handoff',
    // share_browse / share_pull are LAN-receive sister APIs; the
    // current UI uses the QR fountain path. These remain Go-only
    // exports that we'll wire when a LAN/peer pairing flow lands.
    'engine_share_begin',
    'engine_share_end',
    'engine_share_browse',
    'engine_share_pull',
    'engine_share_pull_url',
    'engine_fountain_next_frame',
]);

// ---- 1. Collect engine //export symbols ----

function listEngineExports() {
    const out = new Set();
    for (const f of readdirSync(ENGINE_DIR)) {
        if (!f.endsWith('_export.go')) continue;
        const src = readFileSync(join(ENGINE_DIR, f), 'utf8');
        const re = /^\/\/export\s+(\w+)/gm;
        let m;
        while ((m = re.exec(src)) != null) out.add(m[1]);
    }
    return [...out].sort();
}

// ---- 2. Identify engine exports referenced from engine.rs ----

function symbolsReferencedInEngineRs() {
    const src = readFileSync(ENGINE_RS, 'utf8');
    const out = new Set();
    const re = /b"(engine_\w+)"/g;
    let m;
    while ((m = re.exec(src)) != null) out.add(m[1]);
    return out;
}

// ---- 3. Tauri commands registered in lib.rs ----

function tauriCommandsRegistered() {
    const src = readFileSync(LIB_RS, 'utf8');
    const m = src.match(/generate_handler!\[([\s\S]*?)\]/);
    if (!m) return new Set();
    // Strip line comments first so they don't survive in the items.
    const body = m[1].replace(/\/\/[^\n]*/g, '');
    return new Set(
        body
            .split(',')
            .map((s) => s.trim())
            .filter((s) => s && /^[A-Za-z_]\w*$/.test(s)),
    );
}

// All #[tauri::command] fn names declared (whether registered or not).
function tauriCommandsDeclared() {
    const src = readFileSync(LIB_RS, 'utf8');
    const out = new Set();
    const re = /#\[tauri::command\][\s\S]{0,200}?\n\s*(?:async\s+)?fn\s+(\w+)/g;
    let m;
    while ((m = re.exec(src)) != null) out.add(m[1]);
    return out;
}

// ---- 4. invoke() targets used in client-ui/ ----

function* walk(dir) {
    for (const ent of readdirSync(dir)) {
        const p = join(dir, ent);
        const st = statSync(p);
        if (st.isDirectory()) yield* walk(p);
        else yield p;
    }
}

function invokeTargetsInClientUi() {
    const out = new Set();
    for (const p of walk(UI_SRC)) {
        if (!/\.(ts|tsx)$/.test(p)) continue;
        const src = readFileSync(p, 'utf8');
        const re = /invoke[<\(]\s*(?:[^,>]+,\s*)?['"]([\w]+)['"]/g;
        let m;
        while ((m = re.exec(src)) != null) out.add(m[1]);
        const re2 = /invoke<[^>]*>\s*\(\s*['"]([\w]+)['"]/g;
        while ((m = re2.exec(src)) != null) out.add(m[1]);
    }
    return out;
}

// ---- run ----

const args = process.argv.slice(2);
const wantJson = args.includes('--json');

const exports_ = listEngineExports();
const engineRs = symbolsReferencedInEngineRs();
const registered = tauriCommandsRegistered();
const declared = tauriCommandsDeclared();
const invoked = invokeTargetsInClientUi();

const missingFromEngineRs = exports_.filter(
    (e) => !engineRs.has(e) && !ENGINE_ALLOWLIST.has(e),
);
const declaredNotRegistered = [...declared].filter((d) => !registered.has(d));
// Commands deliberately registered before anything calls them. Each entry is a
// promise that a consumer is coming — keep this list SHORT and delete an entry
// the moment its caller lands, or it degrades into the false-green this gate
// exists to prevent.
const UNINVOKED_ALLOWLIST = new Map([
    [
        'scheduler_tick',
        'Driven from Rust and Kotlin, never from the UI: src-tauri/src/lib.rs ' +
        'spawns a 60s thread calling cmd::scheduler_tick, and on Android ' +
        'DaalVpnService.startSchedulerPump ticks through the JNI bridge while ' +
        'the tunnel is up. This gate only scans client-ui for invoke() ' +
        'targets, so it can see NEITHER caller. This entry is therefore ' +
        'permanent, not a promise: do not delete it expecting a UI caller to ' +
        'appear — a scheduler driven from the UI would stop the moment the ' +
        'window closed, which is the bug, not the fix.',
    ],
]);

const registeredNotInvoked = [...registered]
    .filter((r) => !invoked.has(r) && !UNINVOKED_ALLOWLIST.has(r))
    .sort();
const registeredNotInvokedAllowlisted = [...registered]
    .filter((r) => !invoked.has(r) && UNINVOKED_ALLOWLIST.has(r))
    .sort();

const report = {
    engineExports: exports_.length,
    engineExportsAllowlisted: [...ENGINE_ALLOWLIST].sort(),
    missingFromEngineRs,
    tauriDeclared: declared.size,
    tauriRegistered: registered.size,
    declaredNotRegistered,
    registeredNotInvoked,
    invokeTargetCount: invoked.size,
};

if (wantJson) {
    console.log(JSON.stringify(report, null, 2));
} else {
    console.log(`Engine exports:            ${report.engineExports}`);
    console.log(`Allowlisted (soak/test):   ${report.engineExportsAllowlisted.length}`);
    console.log(`Tauri commands declared:   ${report.tauriDeclared}`);
    console.log(`Tauri commands registered: ${report.tauriRegistered}`);
    console.log(`invoke() targets in UI:    ${report.invokeTargetCount}`);
    console.log('');
    if (missingFromEngineRs.length) {
        console.log('Engine exports NOT reached by engine.rs:');
        for (const e of missingFromEngineRs) console.log(`  - ${e}`);
    }
    if (declaredNotRegistered.length) {
        console.log('Tauri fn declared but not in generate_handler!:');
        for (const f of declaredNotRegistered) console.log(`  - ${f}`);
    }
    if (registeredNotInvoked.length) {
        console.log('Tauri commands registered but NOT invoked from client-ui:');
        for (const c of registeredNotInvoked) console.log(`  - ${c}`);
    }
    if (registeredNotInvokedAllowlisted.length) {
        console.log('Registered-ahead-of-consumer (allowlisted, not failing):');
        for (const c of registeredNotInvokedAllowlisted) {
            console.log(`  - ${c} — ${UNINVOKED_ALLOWLIST.get(c)}`);
        }
    }
}

const fail =
    missingFromEngineRs.length + declaredNotRegistered.length + registeredNotInvoked.length;
process.exit(fail > 0 ? 1 : 0);
