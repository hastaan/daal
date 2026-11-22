// The build screen's log: what the Details panel prints and the few
// facts the screen reads out of it (the health wait's live line, "up but
// not answering", what a cancel removed). Pure, so it is tested alone.

import type { ProgressEvent } from './wizardCommands';

/** How far back a repeat is looked for. The two channels deliver the
 *  same event within milliseconds of each other. */
const DEDUPE_WINDOW = 40;

/**
 * Add one event to the log, once. The shell sends every provision event
 * twice (the Tauri event and a CustomEvent injected for webviews whose
 * event bridge is flaky); the page listens to both, so every line used
 * to show twice. The shell numbers each event (`seq`) and the first copy
 * wins; an event without a number (sign events, an older shell) is a
 * repeat when step, message and time stamp all match a recent one.
 */
export function appendEvent(log: ProgressEvent[], ev: ProgressEvent, now: number): ProgressEvent[] {
    const from = Math.max(0, log.length - DEDUPE_WINDOW);
    for (let i = log.length - 1; i >= from; i--) {
        const o = log[i];
        if (typeof ev.seq === 'number') {
            if (o.seq === ev.seq) return log;
        } else if (
            typeof o.seq !== 'number' &&
            o.step === ev.step &&
            (o.message ?? o.detail) === (ev.message ?? ev.detail) &&
            (o.ts ?? '') === (ev.ts ?? '') &&
            !!ev.ts
        ) {
            return log;
        }
    }
    return [...log, { ...ev, at: ev.at ?? now }];
}

const pad = (n: number) => String(n).padStart(2, '0');

/** The line's local time, HH:MM:SS: the CLI's own stamp when it has
 *  one (it is UTC, shown here in local time), else when it was heard. */
export function lineTime(ev: ProgressEvent): string {
    let ms = ev.ts ? Date.parse(ev.ts) : NaN;
    if (Number.isNaN(ms)) ms = ev.at ?? NaN;
    if (Number.isNaN(ms)) return '--:--:--';
    const d = new Date(ms);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** The lines the panel prints: the health wait is one live line (its
 *  latest try), not sixty. */
export function visibleLines(log: ProgressEvent[]): ProgressEvent[] {
    let last = -1;
    for (let i = log.length - 1; i >= 0; i--) {
        if (log[i].step === 'provision_health_wait') {
            last = i;
            break;
        }
    }
    return log.filter((ev, i) => ev.step !== 'provision_health_wait' || i === last);
}

export interface HealthWait {
    attempt: number;
    max: number;
    elapsedS: number;
    boxIp: string;
    helperIp: string;
}

/** The health wait's latest try, while it is the latest thing that
 *  happened in the provision (null once the server answered). */
export function healthWait(log: ProgressEvent[]): HealthWait | null {
    for (let i = log.length - 1; i >= 0; i--) {
        const ev = log[i];
        if (ev.step === 'provision_healthy' || ev.step === 'provision_done' || ev.step === 'provision_rollback') {
            return null;
        }
        if (ev.step === 'provision_health_wait' && typeof ev.attempt === 'number') {
            return {
                attempt: ev.attempt,
                max: typeof ev.max_attempts === 'number' ? ev.max_attempts : 0,
                elapsedS: typeof ev.elapsed_s === 'number' ? ev.elapsed_s : 0,
                boxIp: ev.box_ip ?? '',
                helperIp: ev.helper_ip ?? '',
            };
        }
    }
    return null;
}

/** The relay's 443 is up but its health check never answered this
 *  device: most likely the network between them. */
export function upButNotAnswering(log: ProgressEvent[]): boolean {
    let said = false;
    for (const ev of log) {
        if (ev.step === 'provision_health_unreachable') said = true;
        if (ev.step === 'provision_healthy' || ev.step === 'provision_done') said = false;
    }
    return said;
}

/** m:ss */
export function clock(seconds: number): string {
    const s = Math.max(0, Math.floor(seconds));
    return `${Math.floor(s / 60)}:${pad(s % 60)}`;
}

export interface CancelOutcome {
    /** The rollback finished and said the server is gone. */
    serverDeleted: boolean;
    firewallDeleted: boolean;
    /** The server's address, when one was rented. */
    ip: string;
    serverId: string;
    /** A server was rented in this run (Hetzner said it exists). */
    rented: boolean;
    /** The rollback finished, with warnings. */
    warnings: number;
}

/** What a stopped build left, read from its own lines. */
export function cancelOutcome(log: ProgressEvent[]): CancelOutcome {
    const out: CancelOutcome = { serverDeleted: false, firewallDeleted: false, ip: '', serverId: '', rented: false, warnings: 0 };
    for (const ev of log) {
        if (ev.step === 'provision_server_ready' || ev.step === 'provision_rollback') out.rented = true;
        if (ev.step === 'provision_rollback') {
            if (ev.public_ip) out.ip = ev.public_ip;
            if (ev.server_id) out.serverId = ev.server_id;
            if (ev.rollback === 'done') {
                out.serverDeleted = ev.server_deleted === true;
                out.firewallDeleted = ev.firewall_deleted === true;
                out.warnings = typeof ev.warnings === 'number' ? ev.warnings : 0;
            }
        }
    }
    return out;
}
