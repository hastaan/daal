// The Connections page, through its pure rules.
//
// First phone pass, one tap on r2 while r1 was connected: no row marked,
// a red banner reading "unknown", and "Loading…" for ever.
import { describe, expect, it } from 'vitest';
import type { ConnectionSummary } from '../contract/D2Contract';
import { idOnlyRoute, type ConnectionSummaryPlus } from './activeRoute';
import {
    PENDING_GRACE_MS,
    PENDING_IDLE_MS,
    PENDING_TIMEOUT_MS,
    listView,
    pendingOutcomeNow,
    resolvePending,
    rowAction,
    rowActionDisabled,
    rowActionLabelKey,
    acceptPending,
    pendingFailureKey,
    rowState,
    rowStateLabelKey,
    runningPhase,
    startPending,
    switchingAwayFromRunning,
} from './networkRows';
import en from '../i18n/en.json';
import fa from '../i18n/fa.json';
import enD2 from '../i18n/d2/d2-extra.en.json';
import faD2 from '../i18n/d2/d2-extra.fa.json';

const sum = (over: Partial<ConnectionSummaryPlus>): ConnectionSummary => ({
    state: 'disconnected',
    mode: 'normal',
    ...over,
});
const on = (id: string) => idOnlyRoute(id);

describe('listView', () => {
    it('never says "Loading…" once the read has failed', () => {
        expect(listView(null, false)).toBe('loading');
        expect(listView(null, true)).toBe('failed');
    });
    it('does not call a list it could not re-read "empty"', () => {
        expect(listView([], false)).toBe('empty');
        expect(listView([], true)).toBe('failed');
    });
    it('keeps the rows it has through a failed re-read', () => {
        expect(listView([{}], false)).toBe('list');
        expect(listView([{}], true)).toBe('list');
    });
});

describe('rowState during a switch from r1 to r2', () => {
    it('tap on r2, engine still on r1: r1 stays connected, r2 is checking', () => {
        expect(rowState('r1', 'r1', 'r2', false)).toBe('connected');
        expect(rowState('r2', 'r1', 'r2', false)).toBe('checking');
        expect(rowState('r3', 'r1', 'r2', false)).toBe('idle');
    });
    it('engine reports r2 and is still proving it: r2 checking, r1 no longer marked', () => {
        expect(rowState('r2', 'r2', 'r2', true)).toBe('checking');
        expect(rowState('r1', 'r2', 'r2', true)).toBe('idle');
    });
    it('engine proved r2: r2 connected', () => {
        expect(rowState('r2', 'r2', null, false)).toBe('connected');
        expect(rowState('r1', 'r2', null, false)).toBe('idle');
    });
    it('engine refused r2: r1 is still the connected row', () => {
        expect(rowState('r1', 'r1', null, false)).toBe('connected');
        expect(rowState('r2', 'r1', null, false)).toBe('idle');
    });
    it('a check this page did not start shows as checking too', () => {
        expect(rowState('r1', 'r1', null, true)).toBe('checking');
    });
});

describe('rowAction', () => {
    it('a row being checked can be cancelled; a connected one disconnected', () => {
        expect(rowAction('checking')).toBe('cancel');
        expect(rowAction('connected')).toBe('disconnect');
        expect(rowAction('idle')).toBe('connect');
    });
    it('only a second Connect is held back while one is unanswered', () => {
        expect(rowActionDisabled('connect', 'r2')).toBe(true);
        expect(rowActionDisabled('connect', null)).toBe(false);
        expect(rowActionDisabled('cancel', 'r2')).toBe(false);
        expect(rowActionDisabled('disconnect', 'r2')).toBe(false);
    });
    it('has a word for each, in both languages', () => {
        const e = { ...en, ...enD2 } as Record<string, string>;
        const f = { ...fa, ...faD2 } as Record<string, string>;
        expect(e[rowActionLabelKey('cancel')]).toBe('Cancel');
        expect(e[rowActionLabelKey('connect')]).toBe('Connect');
        expect(e[rowActionLabelKey('disconnect')]).toBe('Disconnect');
        for (const a of ['cancel', 'connect', 'disconnect'] as const) {
            expect(f[rowActionLabelKey(a)], a).toBeTruthy();
        }
        for (const k of [
            'network.load_failed',
            'network.action_failed',
            'network.try_again',
            'network.error_details',
            'status.load_failed',
            'conn.checking',
        ]) {
            expect(e[k], k).toBeTruthy();
            expect(f[k], k).toBeTruthy();
            expect(f[k], k).not.toBe(e[k]);
        }
        expect(e['network.load_failed']).toBe('Daal could not read your connections. Try again.');
    });
});

describe('a tapped connect waiting for the engine', () => {
    const T0 = 1_000_000;
    const connectedOnR1 = sum({ state: 'connected', activeRoute: on('r1'), routeRunning: true, routeCheck: 'ok' });

    it('waits while the engine still reports the old route', () => {
        const p = startPending('r2', T0, connectedOnR1);
        expect(p.baseline).toBe('waiting');
        expect(resolvePending(p, connectedOnR1, T0 + 2000)).toBe('waiting');
        expect(resolvePending(p, connectedOnR1, T0 + 30_000)).toBe('waiting');
    });
    it('waits while the engine is proving the new route', () => {
        const p = startPending('r2', T0, connectedOnR1);
        const verifying = sum({ state: 'connecting', activeRoute: on('r2'), routeRunning: true, routeCheck: 'verifying' });
        expect(resolvePending(p, verifying, T0 + 2000)).toBe('waiting');
    });
    it('ends connected only when the engine says the NEW route is connected', () => {
        const p = startPending('r2', T0, connectedOnR1);
        expect(
            resolvePending(p, sum({ state: 'connected', activeRoute: on('r2'), routeRunning: true }), T0 + 4000),
        ).toBe('connected');
    });
    it('a refusal for the tapped route ends it, while the old route is still up', () => {
        const p = startPending('r2', T0, connectedOnR1);
        const refused = sum({
            state: 'connected',
            activeRoute: on('r1'),
            routeRunning: true,
            connectRefused: 'cooldown',
            connectRefusedRoute: 'r2',
        });
        expect(resolvePending(p, refused, T0 + 2000)).toBe('refused');
    });
    it('a refusal about some other route is not this tap\'s answer', () => {
        const p = startPending('r2', T0, connectedOnR1);
        const other = sum({
            state: 'connected',
            activeRoute: on('r1'),
            connectRefused: 'cooldown',
            connectRefusedRoute: 'r3',
        });
        expect(resolvePending(p, other, T0 + 2000)).toBe('waiting');
    });
    it('an engine that names no route for its refusal is taken to mean this tap', () => {
        const p = startPending('r2', T0, connectedOnR1);
        expect(
            resolvePending(p, sum({ state: 'connected', activeRoute: on('r1'), connectRefused: 'other' }), T0 + 2000),
        ).toBe('refused');
    });
    it('a refusal already standing at the tap is old news until the grace period has passed', () => {
        const standing = sum({ connectRefused: 'cooldown', connectRefusedRoute: 'r2' });
        const p = startPending('r2', T0, standing);
        expect(p.baseline).toBe('refused');
        expect(resolvePending(p, standing, T0 + PENDING_GRACE_MS - 1)).toBe('waiting');
        expect(resolvePending(p, standing, T0 + PENDING_GRACE_MS)).toBe('refused');
    });
    it('a failed check on the tapped route ends it; a stale one waits out the grace period', () => {
        const failed = sum({ state: 'error', routeCheck: 'failed', routeRunning: false, activeRoute: on('r2') });
        expect(pendingOutcomeNow('r2', failed)).toBe('failed');
        expect(pendingOutcomeNow('r5', failed)).toBe('waiting');
        const fresh = startPending('r2', T0, connectedOnR1);
        expect(resolvePending(fresh, failed, T0 + 1000)).toBe('failed');
        const stale = startPending('r2', T0, failed);
        expect(resolvePending(stale, failed, T0 + 1000)).toBe('waiting');
        expect(resolvePending(stale, failed, T0 + PENDING_GRACE_MS)).toBe('failed');
    });
    it('a tap that ends with nothing running and no reason is reported, not left "checking"', () => {
        const p = acceptPending(startPending('r2', T0 - 500, connectedOnR1), T0);
        const nothing = sum({ state: 'disconnected', routeRunning: false });
        expect(resolvePending(p, nothing, T0 + PENDING_IDLE_MS - 1)).toBe('waiting');
        expect(resolvePending(p, nothing, T0 + PENDING_IDLE_MS)).toBe('failed');
    });
    it('stops waiting eventually', () => {
        const p = acceptPending(startPending('r2', T0 - 500, connectedOnR1), T0);
        expect(resolvePending(p, connectedOnR1, T0 + PENDING_TIMEOUT_MS)).toBe('timeout');
    });
    it('no clock runs while the person is still on the VPN permission dialog', () => {
        // First connect on a fresh install: the connect call does not
        // return until the system dialog is answered. Thirty seconds on
        // it with nothing running is not a failed connect.
        const nothing = sum({ state: 'disconnected', routeRunning: false });
        const p = startPending('r1', T0, nothing);
        expect(p.accepted).toBe(false);
        expect(resolvePending(p, nothing, T0 + 30_000)).toBe('waiting');
        expect(resolvePending(p, nothing, T0 + PENDING_TIMEOUT_MS + 1)).toBe('waiting');
        // Once the host has taken it the idle rule counts from THEN.
        const a = acceptPending(p, T0 + 30_000);
        expect(resolvePending(a, nothing, T0 + 30_000 + PENDING_IDLE_MS - 1)).toBe('waiting');
        expect(resolvePending(a, nothing, T0 + 30_000 + PENDING_IDLE_MS)).toBe('failed');
        // An answer the engine does give is still taken at once.
        const up = sum({ state: 'connected', activeRoute: on('r1'), routeRunning: true, routeCheck: 'ok' });
        expect(resolvePending(p, up, T0 + 30_000)).toBe('connected');
    });
});

describe('a switch the service undid: r1 connected, tap r2, r2 carries nothing, back on r1', () => {
    const T0 = 2_000_000;
    const connectedOnR1 = sum({ state: 'connected', activeRoute: on('r1'), routeRunning: true, routeCheck: 'ok' });
    const note = { routeId: 'r2', keptRouteId: 'r1', outcome: 'failed' as const, reason: 'timeout' };

    it('ends failed from the service note, though the engine only ever reports r1', () => {
        const p = acceptPending(startPending('r2', T0, connectedOnR1), T0 + 100);
        // Poll 1: the service is reconnecting r1.
        const verifyingR1 = sum({
            state: 'connecting', activeRoute: on('r1'), routeRunning: true, routeCheck: 'verifying', lastSwitch: note,
        });
        expect(resolvePending(p, verifyingR1, T0 + 2000)).toBe('failed');
        // Poll 2: r1 is connected again.
        const backOnR1 = sum({ ...connectedOnR1, lastSwitch: note } as Partial<ConnectionSummaryPlus>);
        expect(resolvePending(p, backOnR1, T0 + 4000)).toBe('failed');
        expect(pendingOutcomeNow('r2', backOnR1)).toBe('failed');
        // Without the note this is the 90 s of "Checking the connection…".
        expect(resolvePending(p, connectedOnR1, T0 + 4000)).toBe('waiting');
    });
    it('says the old route is still connected, in both languages', () => {
        const backOnR1 = sum({ ...connectedOnR1, lastSwitch: note } as Partial<ConnectionSummaryPlus>);
        expect(pendingFailureKey('r2', 'failed', backOnR1)).toBe('network.switch_failed_kept');
        const nothingLeft = sum({ state: 'disconnected', routeRunning: false, lastSwitch: { ...note, keptRouteId: undefined } });
        expect(pendingFailureKey('r2', 'failed', nothingLeft)).toBe('network.switch_failed_none');
        // An ordinary failed connect keeps the engine-chosen sentence.
        expect(pendingFailureKey('r2', 'failed', connectedOnR1)).toBeUndefined();
        // A wait that ran out is never silent.
        expect(pendingFailureKey('r2', 'timeout', connectedOnR1)).toBe('network.connect_timeout');
        const e = { ...en, ...enD2 } as Record<string, string>;
        const f = { ...fa, ...faD2 } as Record<string, string>;
        for (const k of ['network.switch_failed_kept', 'network.switch_failed_none', 'network.connect_timeout']) {
            expect(e[k], k).toBeTruthy();
            expect(f[k], k).toBeTruthy();
            expect(f[k], k).not.toBe(e[k]);
        }
        expect(e['network.switch_failed_kept']).toBe(
            'That route could not be used. You are still connected through the other one.',
        );
    });
    it('a note about some other route is not this tap\'s answer', () => {
        const p = acceptPending(startPending('r3', T0, connectedOnR1), T0);
        const s = sum({ ...connectedOnR1, lastSwitch: note } as Partial<ConnectionSummaryPlus>);
        expect(resolvePending(p, s, T0 + 5000)).toBe('waiting');
    });
    it('a note left by an EARLIER attempt on the same route is old news during the grace period', () => {
        const withNote = sum({ ...connectedOnR1, lastSwitch: note } as Partial<ConnectionSummaryPlus>);
        const p = acceptPending(startPending('r2', T0, withNote), T0);
        expect(p.baseline).toBe('failed');
        expect(resolvePending(p, withNote, T0 + 1000)).toBe('waiting');
    });
    it('a refused switch is read from the note too', () => {
        const s = sum({
            ...connectedOnR1,
            lastSwitch: { routeId: 'r2', keptRouteId: 'r1', outcome: 'refused', reason: 'cooldown' },
        } as Partial<ConnectionSummaryPlus>);
        expect(pendingOutcomeNow('r2', s)).toBe('refused');
    });
});

describe('the button on a row while a switch is pending', () => {
    it('does not say "Cancel" when pressing it would stop a working route', () => {
        // r1 connected and carrying; r2 just tapped.
        expect(switchingAwayFromRunning('r2', 'r1', 'r2')).toBe(true);
        const state = rowState('r2', 'r1', 'r2', 'steady');
        expect(state).toBe('checking');
        expect(rowAction(state, true)).toBe('disconnect');
        expect(rowActionLabelKey(rowAction(state, true))).toBe('network.disconnect');
    });
    it('still says "Cancel" when nothing else is running', () => {
        expect(switchingAwayFromRunning('r2', null, 'r2')).toBe(false);
        // The engine has moved to r2 and is proving it: r1 is gone.
        expect(switchingAwayFromRunning('r2', 'r2', 'r2')).toBe(false);
        expect(switchingAwayFromRunning('r1', 'r1', 'r2')).toBe(false);
        expect(rowAction('checking', false)).toBe('cancel');
    });
});

describe('a connected route that stopped carrying traffic', () => {
    const lost = sum({ state: 'connecting', activeRoute: on('r1'), routeRunning: true, routeCheck: 'failed' });
    it('is not labelled "connected"', () => {
        expect(runningPhase(lost)).toBe('lost');
        const state = rowState('r1', 'r1', null, runningPhase(lost));
        expect(state).toBe('lost');
        expect(rowStateLabelKey(state)).toBe('conn.state.lost');
        // It can still be stopped from the row.
        expect(rowAction(state)).toBe('disconnect');
    });
    it('the other phases', () => {
        expect(runningPhase(sum({ state: 'connected', routeCheck: 'ok', routeRunning: true }))).toBe('steady');
        expect(runningPhase(sum({ state: 'connecting', routeCheck: 'verifying', routeRunning: true }))).toBe('verifying');
        // A failed CONNECT (engine stopped) is state 'error', not lost.
        expect(runningPhase(sum({ state: 'error', routeCheck: 'failed', routeRunning: false }))).toBe('steady');
        expect(rowStateLabelKey('connected')).toBe('network.connected');
        expect(rowStateLabelKey('checking')).toBe('conn.checking');
        expect(rowStateLabelKey('idle')).toBeUndefined();
        const e = { ...en, ...enD2 } as Record<string, string>;
        const f = { ...fa, ...faD2 } as Record<string, string>;
        for (const k of ['conn.state.lost', 'network.connected', 'conn.checking']) {
            expect(e[k], k).toBeTruthy();
            expect(f[k], k).toBeTruthy();
        }
    });
});
