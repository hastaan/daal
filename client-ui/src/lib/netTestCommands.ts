// netTestCommands — the network test's shell commands
// (src-tauri/src/lib.rs field_probe_*). Typed wrappers only; the
// answers are parsed by lib/netTest.ts.
//
// The phone's own facts (the network's DNS servers, Private DNS, VPN up,
// IPv6, "blocked without VPN") are added by the shell on Android: the
// page sends only what the person chose. The page never chooses where a
// sealed file goes: `share` seals into the engine's own folder and opens
// the share sheet (Android) or shows the file (desktop).

import { invoke } from '@tauri-apps/api/core';
import { parseSeal, parseStart, parseStatus } from './netTest';
import type { NetStatus, NetworkLabel, SealAnswer, StartAnswer } from './netTest';

export interface NetTestApi {
    status(): Promise<NetStatus>;
    start(label: NetworkLabel, consentVersion: number): Promise<StartAnswer>;
    cancel(reason?: '' | 'backgrounded'): Promise<boolean>;
    /** Seal (a share, always) and open the share sheet. */
    share(chooserTitle: string): Promise<SealAnswer>;
    discard(): Promise<number>;
}

export const NetTest: NetTestApi = {
    async status() {
        try {
            return parseStatus(await invoke<string>('field_probe_status'));
        } catch {
            // An older shell or engine: the test is not offered.
            return { kind: 'unavailable' };
        }
    },
    async start(label, consentVersion) {
        const opts = JSON.stringify({ network_label: label, consent_version: consentVersion });
        return parseStart(await invoke<string>('field_probe_start', { optsJson: opts }));
    },
    async cancel(reason = '') {
        return invoke<boolean>('field_probe_cancel', { reason });
    },
    async share(chooserTitle) {
        const opts = JSON.stringify({ notes: '', net_kind: '' });
        return parseSeal(await invoke<string>('field_probe_share', { optsJson: opts, chooserTitle }));
    },
    async discard() {
        return invoke<number>('field_probe_discard');
    },
};
