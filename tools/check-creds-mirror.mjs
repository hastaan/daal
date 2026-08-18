#!/usr/bin/env node
// check-creds-mirror.mjs — the box→publisher credential struct is
// declared THREE times in TWO languages, with no import edge between
// them, and every field that has ever been added to it has at some
// point been dropped in transit.
//
//   cmd/daal-relay-mgmt/users.go   userCreds        (what the box sends)
//   publisher/deploy/mgmt/users.go UserCreds        (what the CLI parses)
//   client-shell/tauri/daal-wizard/src/cli_bridge.rs
//       UserCredsResult        (provision response, and the struct the
//                               wizard re-serialises into the creds file
//                               that `users-pack-sbp[x]` reads)
//       RotateCredentialsResult (rotation response, same job)
//
// THE FAILURE MODE, three times over:
//
//   Wave 2  `mux_inbound` — the box echoed it, the Rust struct omitted
//           it, `serde_json::to_value` discarded it, and every pack the
//           wizard minted came out with no multiplexing for a whole
//           wave. No error anywhere.
//   Wave 5  `anytls_password` — same mechanism. The box echoed it, both
//           Rust structs omitted it, the minter read "", and the pack
//           step then failed the ENTIRE pack on the route it could not
//           render.
//
// Both are silent because serde and encoding/json agree on ignoring
// unknown keys. There is no compiler, no test and no type that spans
// the hop; this gate is the only thing that can span it.
//
// Rule: every json tag on publisher/deploy/mgmt.UserCreds must appear
// as a field on BOTH Rust structs. The reverse is allowed — the Rust
// side may carry fields the Go struct does not (e.g. rotation-only
// timestamps).

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GO = join(ROOT, 'publisher/deploy/mgmt/users.go');
const RS = join(ROOT, 'client-shell/tauri/daal-wizard/src/cli_bridge.rs');

// Fields the Rust side deliberately does not carry, each with the
// reason. An entry here is a claim that the wizard does not need the
// value — not a place to park a field you have not wired yet.
const RUST_EXEMPT = new Map([]);

function goStructFields(src, name) {
    const start = src.indexOf(`type ${name} struct {`);
    if (start < 0) throw new Error(`${name} not found in ${GO}`);
    const end = src.indexOf('\n}', start);
    const body = src.slice(start, end);
    const out = [];
    for (const m of body.matchAll(/json:"([a-z0-9_]+)/g)) out.push(m[1]);
    return out;
}

function rustStructFields(src, name) {
    const start = src.indexOf(`pub struct ${name} {`);
    if (start < 0) throw new Error(`${name} not found in ${RS}`);
    const end = src.indexOf('\n}', start);
    const body = src.slice(start, end);
    const out = new Set();
    for (const m of body.matchAll(/pub\s+([a-z0-9_]+)\s*:/g)) out.add(m[1]);
    // #[serde(rename = "x")] counts as the wire name.
    for (const m of body.matchAll(/rename\s*=\s*"([a-z0-9_]+)"/g)) out.add(m[1]);
    return out;
}

const goSrc = readFileSync(GO, 'utf8');
const rsSrc = readFileSync(RS, 'utf8');

const wire = goStructFields(goSrc, 'UserCreds');
const structs = ['UserCredsResult', 'RotateCredentialsResult'];

const problems = [];
for (const s of structs) {
    const have = rustStructFields(rsSrc, s);
    for (const f of wire) {
        if (have.has(f)) continue;
        if (RUST_EXEMPT.has(f)) continue;
        problems.push(
            `${s} (cli_bridge.rs) has no field for mgmt.UserCreds json tag "${f}". ` +
                `serde will DISCARD it silently: the box sends the value, the wizard drops it, ` +
                `and the pack step mints a route that cannot authenticate — or refuses the route ` +
                `and reports nothing. Add "#[serde(default)] pub ${f}: ..." or exempt it here with a reason.`
        );
    }
}

const stale = [...RUST_EXEMPT.keys()].filter((f) => !wire.includes(f));
for (const f of stale) {
    problems.push(`RUST_EXEMPT lists "${f}", which is no longer a field of mgmt.UserCreds. Remove it.`);
}

if (problems.length) {
    console.error('check-creds-mirror: FAIL');
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
}
console.log(`check-creds-mirror: OK (${wire.length} fields mirrored into ${structs.length} Rust structs)`);
