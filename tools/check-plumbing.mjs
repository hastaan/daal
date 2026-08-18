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
//   - a `pub fn` in daal-desktop-core/src/commands.rs not reached by any
//     #[tauri::command] in src-tauri/src/lib.rs
//
// That last rule exists because rules 1-3 have a gap between them that
// hid a whole capability. Rule 1 is satisfied the moment a symbol is
// dlsym'd in engine.rs; rules 2 and 3 only ever look at functions that
// are ALREADY #[tauri::command]s. So an engine export could be dlsym'd,
// given a typed Rust wrapper, taken off the engine allowlist — and still
// have no Tauri command and no UI caller, with every rule green and the
// allowlist now claiming it was wired. Wrapping an export in Rust is not
// the same as making it reachable, and the gate has to be able to tell
// the difference.
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
    // engine_share_browse is the ONLY share export still allowlisted,
    // and NOT because a caller is coming. core/abi/share.go::ShareBrowse
    // is a hardcoded `{"services":[]}` stub: there is no Go-side mDNS
    // browser behind it (Android uses NsdManager directly and hands the
    // result to engine_share_pull). dlsym'ing it would let the desktop
    // present a "look for nearby senders" affordance that is guaranteed
    // to find nothing, which is worse than not offering it — so this
    // entry is a statement about the Go side, not a promise about the
    // Rust side. Delete it the day core grows a real browser, and not
    // before.
    //
    // The other five Phase 1C share/fountain exports — engine_share_begin,
    // engine_share_end, engine_share_pull, engine_share_pull_url and
    // engine_fountain_next_frame — came off this list in Wave 4 Step 11
    // because they really are dlsym'd in daal-desktop-core/src/engine.rs
    // with typed wrappers in commands.rs. That is ALL their absence here
    // means. It does NOT mean the LAN capability is reachable: as of this
    // wave there is no #[tauri::command] over those wrappers and no
    // client-ui caller, so LAN share is driven only from cmd/daal-core.
    // Rule 4 below is what records that fact and keeps it honest.
    'engine_share_browse',
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

// ---- 5. desktop-core wrappers reached by a Tauri command ----

// `pub fn`s in daal-desktop-core/src/commands.rs that no #[tauri::command]
// calls. Each entry must say WHY, truthfully — "a caller is coming" is not
// a reason, it is a note to self. An entry whose reason has become false is
// worse than a failing gate, because it reads as a capability that shipped.
const CORE_WRAPPER_ALLOWLIST = new Map([
    ...['share_begin', 'share_end', 'share_pull', 'share_pull_url', 'fountain_next_frame'].map(
        (n) => [
            n,
            'LAN share is NOT reachable from any GUI. These wrappers are ' +
            'dlsym\'d and typed, but there is no #[tauri::command] over them ' +
            'and no client-ui caller: the only driver is the cmd/daal-core ' +
            'CLI (share-serve / share-pull). Wave 4 Step 11 wired the QR and ' +
            'base64-paste lanes and deliberately did NOT wire LAN. Delete the ' +
            'entry when a Tauri command lands — at that point rules 2 and 3 ' +
            'take over and police it properly.',
        ],
    ),
    [
        'deliver_tun_fd',
        'Desktop-only tun-fd handoff helper with no caller today. On Android ' +
        'the fd is delivered by the daal-platform plugin straight to ' +
        'engine_set_tun_fd over JNI, bypassing this wrapper; on desktop the ' +
        'tunnel is brought up without it. Kept because the Linux tun-helper ' +
        'topology it belongs to is still live in tun_helper::unix.',
    ],
    [
        'clear_tun_fd',
        'Same topology as deliver_tun_fd: the Android teardown path calls ' +
        'engine_clear_tun_fd through the daal-platform plugin, not through ' +
        'this wrapper.',
    ],
]);

function coreWrapperFns() {
    const src = readFileSync(CMD_RS, 'utf8');
    return [...src.matchAll(/^pub (?:async )?fn (\w+)/gm)].map((m) => m[1]);
}

// A wrapper counts as reached if lib.rs names it as cmd::x / commands::x.
function coreWrappersUsedInLibRs() {
    const src = readFileSync(LIB_RS, 'utf8');
    return new Set([...src.matchAll(/\b(?:cmd|commands)::(\w+)/g)].map((m) => m[1]));
}

const coreWrappers = coreWrapperFns();
const coreWrappersUsed = coreWrappersUsedInLibRs();
const coreWrappersUnreached = coreWrappers
    .filter((f) => !coreWrappersUsed.has(f) && !CORE_WRAPPER_ALLOWLIST.has(f))
    .sort();
// An allowlist entry for a wrapper that IS now reached is stale: the reason
// has silently become false, which is the exact failure this rule catches.
const coreWrapperAllowlistStale = [...CORE_WRAPPER_ALLOWLIST.keys()]
    .filter((f) => coreWrappersUsed.has(f) || !coreWrappers.includes(f))
    .sort();

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
    coreWrappers: coreWrappers.length,
    coreWrappersUnreached,
    coreWrapperAllowlistStale,
    coreWrappersAllowlisted: [...CORE_WRAPPER_ALLOWLIST.keys()].sort(),
};

if (wantJson) {
    console.log(JSON.stringify(report, null, 2));
} else {
    console.log(`Engine exports:            ${report.engineExports}`);
    console.log(`Allowlisted (soak/test):   ${report.engineExportsAllowlisted.length}`);
    console.log(`Tauri commands declared:   ${report.tauriDeclared}`);
    console.log(`Tauri commands registered: ${report.tauriRegistered}`);
    console.log(`invoke() targets in UI:    ${report.invokeTargetCount}`);
    console.log(`desktop-core wrappers:     ${report.coreWrappers}`);
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
    if (coreWrappersUnreached.length) {
        console.log('commands.rs wrappers NOT reached by any #[tauri::command]:');
        for (const f of coreWrappersUnreached) console.log(`  - ${f}`);
    }
    if (coreWrapperAllowlistStale.length) {
        console.log('STALE wrapper-allowlist entries (reason is no longer true):');
        for (const f of coreWrapperAllowlistStale) console.log(`  - ${f}`);
    }
    if (report.coreWrappersAllowlisted.length) {
        console.log('Wrapped but NOT reachable from the GUI (allowlisted, not failing):');
        for (const f of report.coreWrappersAllowlisted) {
            if (coreWrapperAllowlistStale.includes(f)) continue;
            console.log(`  - ${f} — ${CORE_WRAPPER_ALLOWLIST.get(f)}`);
        }
    }
    if (registeredNotInvokedAllowlisted.length) {
        console.log('Registered-ahead-of-consumer (allowlisted, not failing):');
        for (const c of registeredNotInvokedAllowlisted) {
            console.log(`  - ${c} — ${UNINVOKED_ALLOWLIST.get(c)}`);
        }
    }
}

const fail =
    missingFromEngineRs.length +
    declaredNotRegistered.length +
    registeredNotInvoked.length +
    coreWrappersUnreached.length +
    coreWrapperAllowlistStale.length;
process.exit(fail > 0 ? 1 : 0);
