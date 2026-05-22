#!/usr/bin/env node
// screenshot-harness.mjs — captures every harness scenario into a PNG
// using headless Chromium, then assembles an optional montage.
//
// Outputs:
//   tools/screenshots/out/scenarios/<id>.png       (one per scenario)
//   tools/screenshots/out/design-source.png        (rendered HTML mock)
//   tools/screenshots/out/montage.png              (grid; needs ImageMagick)
//
// Usage:
//   node tools/screenshot-harness.mjs            # build + serve + capture all
//   node tools/screenshot-harness.mjs --skip-build
//   node tools/screenshot-harness.mjs --only=connection-connected,routes-populated
//
// The scenario list is the single source of truth at
// client-ui/src/harness/scenarios.ts. We re-parse it here at runtime
// so adding a scenario in TS automatically extends the capture set.

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const UI = join(ROOT, 'client-ui');
const OUT = join(ROOT, 'tools/screenshots/out');
const SCENARIOS_OUT = join(OUT, 'scenarios');
const PORT = 4173;

// ---- args ----------------------------------------------------------
const args = process.argv.slice(2);
const skipBuild = args.includes('--skip-build');
const onlyArg = args.find((a) => a.startsWith('--only='));
const onlyFilter = onlyArg ? onlyArg.slice('--only='.length).split(',') : null;

// ---- discover scenarios from the source file -----------------------
function loadScenarioIds() {
    const src = readFileSync(join(UI, 'src/harness/scenarios.ts'), 'utf8');
    const re = /^\s*id:\s*'([^']+)'/gm;
    const ids = new Set();
    let m;
    while ((m = re.exec(src)) != null) ids.add(m[1]);
    return [...ids];
}

// ---- chromium ------------------------------------------------------
function locateChromium() {
    for (const cand of ['chromium', 'chromium-browser', 'google-chrome']) {
        const r = spawnSync('which', [cand]);
        if (r.status === 0) return r.stdout.toString().trim();
    }
    return null;
}

function chromiumShot(chromium, url, outPath, width = 1280, height = 900) {
    const flags = [
        '--headless=new',
        '--no-sandbox',
        '--disable-gpu',
        '--hide-scrollbars',
        '--force-device-scale-factor=1',
        '--disable-dev-shm-usage',
        `--window-size=${width},${height}`,
        `--screenshot=${outPath}`,
        url,
    ];
    const r = spawnSync(chromium, flags, { stdio: 'ignore' });
    return r.status === 0;
}

// ---- vite preview --------------------------------------------------
function startPreview() {
    return new Promise((resolveStart, reject) => {
        const proc = spawn(
            'npx',
            ['vite', 'preview', '--port', String(PORT), '--strictPort', '--host', '127.0.0.1'],
            { cwd: UI, stdio: ['ignore', 'pipe', 'pipe'] },
        );
        // Buffer stderr so we can surface it if the process dies early.
        const stderrBuf = [];
        proc.stderr.on('data', (c) => stderrBuf.push(c.toString()));
        proc.stdout.on('data', () => {});

        let resolved = false;
        let died = false;
        proc.on('exit', (code) => {
            died = true;
            if (!resolved) {
                reject(new Error(
                    `vite preview exited before ready (code ${code})\n${stderrBuf.join('')}`,
                ));
            }
        });

        // Poll the port via HTTP instead of pattern-matching stdout (which Vite
        // colorises). 60s budget with 250ms cadence = 240 attempts.
        const deadline = Date.now() + 60_000;
        const tick = async () => {
            if (resolved || died) return;
            try {
                const r = await fetch(`http://127.0.0.1:${PORT}/`, { method: 'HEAD' });
                if (r.ok || r.status === 404 || r.status === 405) {
                    resolved = true;
                    resolveStart(proc);
                    return;
                }
            } catch {
                /* not ready yet */
            }
            if (Date.now() > deadline) {
                if (!resolved) {
                    proc.kill();
                    reject(new Error('vite preview start timed out (60s)'));
                }
                return;
            }
            setTimeout(tick, 250);
        };
        setTimeout(tick, 250);
    });
}

// ---- main ----------------------------------------------------------
async function main() {
    mkdirSync(OUT, { recursive: true });
    mkdirSync(SCENARIOS_OUT, { recursive: true });

    const chromium = locateChromium();
    if (!chromium) {
        console.error('FATAL: chromium not found. apt-get install chromium');
        process.exit(1);
    }

    // 1. Render design source HTML.
    const designSrc = join(ROOT, 'client-shared/designs/daal-desktop.html');
    if (existsSync(designSrc)) {
        console.log('[1/3] capturing design source ...');
        chromiumShot(chromium, `file://${designSrc}`, join(OUT, 'design-source.png'));
    }

    // 2. Build client-ui (unless skipped).
    if (!skipBuild) {
        console.log('[2/3] building client-ui ...');
        const b = spawnSync('npx', ['vite', 'build'], { cwd: UI, stdio: 'inherit' });
        if (b.status !== 0) {
            console.error('vite build failed');
            process.exit(b.status);
        }
    } else {
        console.log('[2/3] skipping build');
    }

    // 3. Serve, then iterate scenarios.
    console.log('[3/3] starting vite preview ...');
    const preview = await startPreview();

    let scenarios = loadScenarioIds();
    if (onlyFilter) scenarios = scenarios.filter((id) => onlyFilter.includes(id));
    console.log(`capturing ${scenarios.length} scenario(s) ...`);

    let captured = 0;
    for (const id of scenarios) {
        const url = `http://127.0.0.1:${PORT}/?harness=${encodeURIComponent(id)}`;
        const out = join(SCENARIOS_OUT, `${id}.png`);
        const ok = chromiumShot(chromium, url, out);
        console.log(`  ${ok ? '✓' : '✗'} ${id}`);
        if (ok) captured++;
    }

    // 4. Optional montage via ImageMagick. Do this BEFORE killing the
    // preview server so the loop has nothing pending after teardown.
    const montage = spawnSync('which', ['montage']);
    if (montage.status === 0 && captured > 0) {
        console.log('assembling montage ...');
        const files = scenarios.map((id) => join(SCENARIOS_OUT, `${id}.png`));
        spawnSync(
            'montage',
            [
                '-tile', '3x',
                '-geometry', '+4+12',
                '-background', '#0a0e16',
                '-label', '%t',
                ...files,
                join(OUT, 'montage.png'),
            ],
            { stdio: 'inherit' },
        );
    }

    // Tear the preview down. Vite preview forks workers; SIGTERM the
    // group, then wait for actual exit before returning so the Node
    // event loop has no lingering pipes.
    await new Promise((res) => {
        const onExit = () => res();
        preview.once('exit', onExit);
        try {
            // Negative pid kills the process group spawned with detached:false.
            // On vite preview the npx wrapper holds the group leader, so plain
            // kill on the pid suffices for SIGTERM; follow up with SIGKILL after
            // a short grace period in case the child ignores SIGTERM.
            preview.kill('SIGTERM');
        } catch {
            res();
            return;
        }
        const killTimer = setTimeout(() => {
            try { preview.kill('SIGKILL'); } catch { /* already dead */ }
        }, 2000);
        preview.once('exit', () => clearTimeout(killTimer));
    });

    console.log(`\nDone. ${captured}/${scenarios.length} captures under:`);
    console.log(`  ${SCENARIOS_OUT}`);
    console.log(`  ${OUT}/design-source.png  (design HTML render)`);
    if (montage.status === 0) console.log(`  ${OUT}/montage.png  (grid)`);
}

main()
    .then(() => process.exit(0))
    .catch((e) => {
        console.error(e);
        process.exit(1);
});
