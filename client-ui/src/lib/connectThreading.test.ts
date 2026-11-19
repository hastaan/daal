// engine_set_route blocks for the engine's connection check — seconds on
// a dead route. Both hosts used to call it on the thread that draws the
// app: the Android VpnService from onStartCommand (the main thread: a
// frozen app and an ANR on exactly the routes that do not work), the
// desktop shell from a plain `#[tauri::command] fn` (the event-loop
// thread, with `disconnect` queued behind it).
//
// Neither host's own test suite can run here (an Android service; a
// Tauri crate that needs the system webview to build), so the property
// is pinned on the source, the way tests/recipient_opsec_test.rs pins
// "the recipient module opens no sockets". It fails on the code as it
// was.
import { describe, expect, it } from 'vitest';
// Vite's ?raw import: the file's text, at test time, with no Node types
// needed by the app's type-check (src/publisher/raw-source.d.ts).
import vpnServiceSource from '../../../client-shell/tauri/plugins/daal-platform/android/src/main/java/org/daal/desktop/vpn/DaalVpnService.kt?raw';
import shellSource from '../../../client-shell/tauri/src-tauri/src/lib.rs?raw';

/** Source with comments removed, so prose about a call is not a call. */
function code(src: string): string {
    // Line comments first: one of them contains "/proc/net/*", which a
    // block-comment pass would take for an opening.
    return src
        .split('\n')
        .map((l) => l.replace(/^\s*(\/\/|\*|\/\*\*).*$/, ''))
        .join('\n')
        .replace(/\/\*[\s\S]*?\*\//g, '');
}

/** The text of a Kotlin/Rust function from its header to the next
 *  top-level-in-class `fun`/`fn` header. */
function body(src: string, header: string, next: RegExp): string {
    const i = src.indexOf(header);
    expect(i, `missing ${header}`).toBeGreaterThanOrEqual(0);
    const rest = src.slice(i + header.length);
    const m = rest.search(next);
    return m < 0 ? rest : rest.slice(0, m);
}

describe('Android: no engine call on the service main thread', () => {
    const kt = code(vpnServiceSource);
    const nextFun = /\n {2}(override |private )?fun /;

    it('setRoute is called in exactly one place: start(), which runs on the control thread', () => {
        expect(kt.match(/DaalCoreBridge\.setRoute\(/g)).toHaveLength(1);
        expect(body(kt, 'private fun start(', nextFun)).toContain('DaalCoreBridge.setRoute(');
    });

    it('the lifecycle callbacks touch the engine only through the control thread', () => {
        const callbacks = [
            body(kt, 'override fun onStartCommand(', nextFun),
            body(kt, 'override fun onRevoke(', nextFun),
            body(kt, 'override fun onDestroy(', nextFun),
        ];
        for (const b of callbacks) {
            for (const call of ['setRoute(', 'setTunFd(', 'clearTunFd(', 'setTunnelRefresh(', 'teardownEngine(']) {
                expect(b, call).not.toContain(call);
            }
        }
        // start() is reached only from inside control.execute { … }.
        const onStart = callbacks[0];
        const exec = onStart.indexOf('control.execute');
        const call = onStart.indexOf('start(routeId');
        expect(exec).toBeGreaterThanOrEqual(0);
        expect(call).toBeGreaterThan(exec);
        expect(onStart.slice(0, exec)).not.toMatch(/[^.\w]start\(/);
        // The one thing that MUST be on the main thread, promptly.
        expect(onStart.slice(0, exec)).toContain('promoteToForeground(');
    });

    it('a stop cancels a check in flight instead of queueing behind it', () => {
        const stop = body(kt, 'private fun requestStop(', nextFun);
        // Supersede the start, cancel from a thread of its own, and
        // only QUEUE the teardown.
        expect(stop).toContain('generation.incrementAndGet()');
        expect(stop).toMatch(/Thread\s*\{[\s\S]*DaalCoreBridge\.clearRoute\(\)/);
        expect(stop).toMatch(/control\.execute\s*\{[\s\S]*teardownEngine\(\)/);
        // And no blocking engine call directly on the caller's thread.
        const direct = stop.replace(/Thread\s*\{[\s\S]*?\n {6}\}/, '').replace(/control\.execute\s*\{[\s\S]*?\n {4}\}/, '');
        expect(direct).not.toContain('DaalCoreBridge.');
    });

    it('a superseded start does not leave a tunnel up', () => {
        const start = body(kt, 'private fun start(', nextFun);
        expect(start).toContain('superseded()');
        // After setRoute succeeds the stop still wins.
        const after = start.slice(start.indexOf('DaalCoreBridge.setRoute('));
        expect(after).toMatch(/if \(superseded\(\)\)/);
        expect(after).toMatch(/if \(lost\) \{\s*teardownEngine\(\)/);
        // …and the pump is never started for a start a stop has overtaken.
        expect(after).toMatch(/if \(!superseded\(\)\) startSchedulerPump\(\)/);
    });
});

describe('desktop: connect does not run on the event-loop thread', () => {
    const rs = code(shellSource);
    it('the connect command is async and blocks on the blocking pool', () => {
        expect(rs).not.toMatch(/\nfn connect\(/);
        const b = body(rs, 'async fn connect(', /\n(async )?fn |\n#\[tauri::command/);
        expect(b).toContain('spawn_blocking');
        expect(b).toContain('cmd::connect(');
    });
});
