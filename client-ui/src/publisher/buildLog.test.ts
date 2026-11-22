import { describe, expect, it } from 'vitest';
import { appendEvent, cancelOutcome, clock, healthWait, lineTime, upButNotAnswering, visibleLines } from './buildLog';
import type { ProgressEvent } from './wizardCommands';

const feed = (evs: ProgressEvent[]) => evs.reduce<ProgressEvent[]>((l, ev) => appendEvent(l, ev, 1_000), []);

describe('build log', () => {
    it('keeps one copy of an event heard on both channels', () => {
        // The shell emits each provision event as a Tauri event AND a
        // CustomEvent; the page listens to both.
        const a = { step: 'provision_create_server', message: 'Creating server on Hetzner', ts: '2026-11-22T10:00:00Z', seq: 4 };
        const log = feed([a, { ...a }, { ...a, seq: 5, message: 'Server ready' }, { ...a, seq: 5, message: 'Server ready' }]);
        expect(log.map((e) => e.seq)).toEqual([4, 5]);
    });

    it('without a number, a repeat is the same step, message and stamp', () => {
        const a = { step: 'sign', message: 'canonicalize', ts: '2026-11-22T10:00:00Z' };
        expect(feed([a, { ...a }])).toHaveLength(1);
        // Two different seconds are two lines.
        expect(feed([a, { ...a, ts: '2026-11-22T10:00:01Z' }])).toHaveLength(2);
        // Harness lines carry no stamp and are never merged.
        expect(feed([{ step: 'x', message: 'y' }, { step: 'x', message: 'y' }])).toHaveLength(2);
    });

    it('stamps each line with a local time', () => {
        const [ev] = feed([{ step: 's', message: 'm', ts: '2026-11-22T10:04:05Z' }]);
        expect(ev.at).toBe(1_000);
        const d = new Date(Date.parse('2026-11-22T10:04:05Z'));
        const want = [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
        expect(lineTime(ev)).toBe(want);
        // No CLI stamp: the time it was heard.
        expect(lineTime({ step: 's', message: 'm', at: new Date(2026, 10, 22, 7, 8, 9).getTime() })).toBe('07:08:09');
    });

    it('prints the health wait as one live line, its latest try', () => {
        const log = feed([
            { step: 'provision_cloud_firewall', message: 'window for 90.1.2.3', seq: 1 },
            { step: 'provision_health_wait', message: 'try 1 of 60', attempt: 1, max_attempts: 60, elapsed_s: 0, seq: 2 },
            { step: 'provision_ssh_debug', message: '(optional log viewer) waiting', seq: 3 },
            { step: 'provision_health_wait', message: 'try 2 of 60', attempt: 2, max_attempts: 60, elapsed_s: 190, helper_ip: '90.1.2.3', seq: 4 },
        ]);
        expect(visibleLines(log).map((e) => e.message)).toEqual([
            'window for 90.1.2.3',
            '(optional log viewer) waiting',
            'try 2 of 60',
        ]);
        expect(healthWait(log)).toEqual({ attempt: 2, max: 60, elapsedS: 190, boxIp: '', helperIp: '90.1.2.3' });
        expect(clock(190)).toBe('3:10');
        // Once the server answered, there is no wait to show.
        expect(healthWait([...log, { step: 'provision_healthy', message: 'up', seq: 5 }])).toBeNull();
    });

    it('says "up but not answering" only until the server answers', () => {
        const un = { step: 'provision_health_unreachable', message: 'up, not answering', seq: 9 };
        expect(upButNotAnswering(feed([un]))).toBe(true);
        expect(upButNotAnswering(feed([un, { step: 'provision_healthy', message: 'up', seq: 10 }]))).toBe(false);
        expect(upButNotAnswering([])).toBe(false);
    });

    it('reads what a cancel removed', () => {
        const log = feed([
            { step: 'provision_server_ready', message: 'Server ready: 203.0.113.5', seq: 1 },
            { step: 'provision_rollback', message: 'Cancelled — removing', rollback: 'start', cancelled: true, public_ip: '203.0.113.5', server_id: '42', seq: 2 },
            { step: 'provision_rollback', message: 'Rolled back', rollback: 'done', cancelled: true, public_ip: '203.0.113.5', server_id: '42', server_deleted: true, firewall_deleted: true, warnings: 0, seq: 3 },
        ]);
        expect(cancelOutcome(log)).toEqual({ serverDeleted: true, firewallDeleted: true, ip: '203.0.113.5', serverId: '42', rented: true, warnings: 0 });
        // Stopped before anything was rented.
        expect(cancelOutcome(feed([{ step: 'provision_ssh_key', message: 'Creating SSH key', seq: 1 }])).rented).toBe(false);
        // Rented, and no word that it was deleted: not confirmed.
        const half = cancelOutcome(feed([{ step: 'provision_server_ready', message: 'ready', seq: 1 }]));
        expect(half.rented && !half.serverDeleted).toBe(true);
    });
});
