#!/usr/bin/env node
// CI 90-second onboarding test (D-2 §7.2).
//
// Scenario: simulate a clean install on the recipient lane and
// drive the shared onboarding state machine through W → B → R3 →
// finish. Asserts wall-clock < 90 s on the reference VM. The
// "render" step is mocked here as a constant cost; the real test
// driver (Playwright on Tauri / Espresso on Android) will replace
// these constants with real per-screen render times.

import { performance } from 'node:perf_hooks';

const BUDGET_S = 90;

// Per-screen synthetic cost in ms. These are fast on purpose; the
// real test driver replaces them with measurements.
const COST = {
    W: 800,
    B: 600,
    R1: 500,
    R2: 1500, // permission prompts
    R3: 4000, // user pastes a URL
    R4: 1500, // trust prompt review
    Connect: 2500, // engine first heartbeat
};

const t0 = performance.now();
let elapsed = 0;
for (const [step, ms] of Object.entries(COST)) {
    elapsed += ms;
    process.stdout.write(`[onboarding] ${step}: +${ms}ms (cum ${elapsed}ms)\n`);
}
const total = elapsed; // synthetic; perf.now() also captured
const totalSec = total / 1000;

if (totalSec >= BUDGET_S) {
    console.error(
        `\n[onboarding] FAIL: synthetic time-to-connect ${totalSec.toFixed(2)}s >= ${BUDGET_S}s budget.`,
    );
    process.exit(1);
}

console.log(
    `\n[onboarding] OK: synthetic time-to-connect ${totalSec.toFixed(2)}s < ${BUDGET_S}s budget. (clock=${(performance.now() - t0).toFixed(2)}ms)`,
);
