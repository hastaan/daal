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
import startSequenceSource from '../../../client-shell/tauri/plugins/daal-platform/android/src/main/java/org/daal/desktop/vpn/StartSequence.kt?raw';
import policySource from '../../../client-shell/tauri/plugins/daal-platform/android/src/main/java/org/daal/desktop/vpn/SwitchPolicy.kt?raw';
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
    const seq = code(startSequenceSource);
    const nextFun = /\n {2}(override |private )?fun /;

    // Since the first phone pass the ORDER of a start lives in
    // StartSequence.kt (pure, unit tested on a JVM) and the service
    // supplies each step through StartSequence.Host. The properties
    // pinned here are the same as before; the anchors moved.

    it('setRoute is called in exactly one place, reached only from start() on the control thread', () => {
        expect(kt.match(/DaalCoreBridge\.setRoute\(/g)).toHaveLength(1);
        expect(body(kt, 'private fun checkedSetRoute(', nextFun)).toContain('DaalCoreBridge.setRoute(');
        // checkedSetRoute: its definition, and one use — the Host that
        // start() builds.
        expect(kt.match(/checkedSetRoute\(/g)).toHaveLength(2);
        const start = body(kt, 'private fun start(', nextFun);
        expect(start).toContain('checkedSetRoute(routeId, gen)');
        expect(start).toContain('StartSequence(host).run(routeId)');
        // The sequence reaches the engine only through its Host.
        expect(seq).not.toContain('DaalCoreBridge');
    });

    it('the lifecycle callbacks touch the engine only through the control thread', () => {
        const onStart = body(kt, 'override fun onStartCommand(', nextFun);
        const callbacks = [
            onStart,
            body(kt, 'override fun onRevoke(', nextFun),
            body(kt, 'override fun onDestroy(', nextFun),
        ];
        // No direct engine call in any of them.
        for (const b of callbacks) {
            for (const call of ['DaalCoreBridge.', 'setRoute(', 'setTunFd(', 'clearTunFd(', 'setTunnelRefresh(', 'establishTun(']) {
                expect(b, call).not.toContain(call);
            }
        }
        for (const b of callbacks.slice(1)) expect(b).not.toContain('teardownEngine(');
        // start() and the teardown after a start that threw are reached
        // only from inside control.execute { … }, which runs to the end
        // of the ACTION_START branch.
        const exec = onStart.indexOf('control.execute');
        const branchEnd = onStart.indexOf('return START_STICKY');
        expect(exec).toBeGreaterThanOrEqual(0);
        expect(branchEnd).toBeGreaterThan(exec);
        const before = onStart.slice(0, exec);
        const after = onStart.slice(branchEnd);
        expect(onStart.indexOf('start(routeId')).toBeGreaterThan(exec);
        expect(onStart.indexOf('start(routeId')).toBeLessThan(branchEnd);
        expect(before).not.toMatch(/[^.\w]start\(/);
        for (const part of [before, after]) {
            expect(part).not.toContain('teardownEngine(');
            expect(part).not.toMatch(/[^.\w]start\(/);
        }
        // The one thing that MUST be on the main thread, promptly.
        expect(before).toContain('promoteToForeground(');
        // Every teardownEngine call in the file is on the control
        // thread: the two control.execute blocks, and the Host the
        // sequence runs with (itself on the control thread).
        const calls = kt.match(/[^\w]teardownEngine\(/g) ?? [];
        expect(calls).toHaveLength(4); // definition + 3 call sites
        expect(onStart.slice(exec, branchEnd)).toContain('teardownEngine(');
        expect(body(kt, 'private fun start(', nextFun)).toMatch(/override fun teardown\(why: String\) = teardownEngine\(/);
        expect(body(kt, 'private fun requestStop(', nextFun)).toMatch(/control\.execute\s*\{\s*teardownEngine\(/);
    });

    it('a stop cancels a check in flight instead of queueing behind it', () => {
        const stop = body(kt, 'private fun requestStop(', nextFun);
        // Supersede the start, cancel from a thread of its own, and
        // only QUEUE the teardown.
        expect(stop).toContain('generation.incrementAndGet()');
        expect(stop).toMatch(/cancelInFlight\(pendingStart, stopping = true\)/);
        expect(stop).toMatch(/control\.execute\s*\{\s*teardownEngine\(/);
        // No engine call directly on the caller's (main) thread.
        expect(stop).not.toContain('DaalCoreBridge.');

        const cancel = body(kt, 'private fun cancelInFlight(', nextFun);
        // The engine's cancel, from a thread of its own…
        expect(cancel).toMatch(/Thread\s*\{[\s\S]*DaalCoreBridge\.clearRoute\(\)/);
        expect(cancel.slice(0, cancel.search(/Thread\s*\{/))).not.toContain('DaalCoreBridge.');
        expect(cancel).toMatch(/t\.start\(\)/);
        // …when the policy says so (a stop: until the start has finished).
        expect(cancel).toContain('SwitchPolicy.cancelStep(stopping, pendingStart, finishedStartGen, checkingGen)');
        expect(policySource).toMatch(/stopping -> CancelStep\.CANCEL/);
    });

    it('a newer start cancels the check of the one it replaces', () => {
        const onStart = body(kt, 'override fun onStartCommand(', nextFun);
        expect(onStart).toMatch(/if \(finishedStartGen < previousStart\) \{[\s\S]*cancelInFlight\(previousStart, stopping = false\)/);
        // Only while the old start is inside its connection check:
        // clearRoute would otherwise disconnect a working route.
        expect(code(policySource)).toMatch(/checkingGen in 1\.\.pendingStart -> CancelStep\.CANCEL/);
        const checked = body(kt, 'private fun checkedSetRoute(', nextFun);
        expect(checked).toMatch(/checkingGen = gen/);
        expect(checked).toMatch(/finally \{[\s\S]*checkingGen = 0/);
    });

    it('a superseded start does not leave a tunnel up', () => {
        // Before the engine is asked at all…
        const checked = body(kt, 'private fun checkedSetRoute(', nextFun);
        expect(checked).toMatch(/if \(generation\.get\(\) != gen\)/);
        expect(checked).toContain('return RC_SUPERSEDED');
        // …after setRoute returns without a route (the cancel landed):
        // nothing is restored or published; the newer request decides…
        const run = seq.slice(seq.indexOf('val routeRc = host.setRoute(routeId)'));
        const failedBranch = run.slice(run.indexOf('if (host.superseded())'));
        expect(run.indexOf('if (host.superseded())')).toBeGreaterThan(0);
        expect(failedBranch.indexOf('return Outcome.SUPERSEDED')).toBeLessThan(failedBranch.indexOf('settleFailure('));
        // …and after setRoute succeeded: the stop still wins.
        const up = body(kt, 'private fun routeIsUp(', nextFun);
        expect(up).toContain('superseded()');
        expect(up).toMatch(/if \(lost\) \{[\s\S]*?return Outcome\.SUPERSEDED/);
        expect(up.indexOf('return Outcome.SUPERSEDED')).toBeLessThan(up.indexOf('setTunnelRefresh(true)'));
        // The stop that superseded it has queued the teardown right behind.
        // And the pump is never started for a start a stop has overtaken.
        expect(up).toMatch(/if \(!superseded\(\)\) startSchedulerPump\(\)/);
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
