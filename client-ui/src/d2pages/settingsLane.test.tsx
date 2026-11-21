// Settings, Status, the erase confirm and the shells (spec C5, C6, C8,
// C9), rendered in the miniDom fake against a fake engine.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr, FakeEvent } from '../test/miniDom';
import type { FakeNode, FakeWindow } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';

// The Tauri commands CustodyPanel calls; anything else is refused.
const tauri: Record<string, () => unknown> = {};
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string) => (tauri[cmd] ? Promise.resolve(tauri[cmd]()) : Promise.reject(`not mocked: ${cmd}`)),
}));

// Tauri events the shells listen to.
const events: Record<string, (e: { payload: unknown }) => void> = {};
vi.mock('@tauri-apps/api/event', () => ({
    listen: async (name: string, fn: (e: { payload: unknown }) => void) => {
        events[name] = fn;
        return () => {
            delete events[name];
        };
    },
}));

// The engine, as the pages see it. Each test sets what it needs.
const fake: Record<string, (...a: unknown[]) => Promise<unknown>> = {};
vi.mock('../contract/ContractProvider', () => ({ useContract: () => fake }));

// Other lanes' pages: the shells only need to know which one is up.
vi.mock('./ConnectionPage', () => ({
    default: ({ onNavigate }: { onNavigate: (s: string) => void }) => (
        <div data-page="connection">
            <button data-button="home-status" onClick={() => onNavigate('status')}>status</button>
        </div>
    ),
}));
vi.mock('./NetworkPage', () => ({ default: () => <div data-page="network" /> }));
vi.mock('./PublisherPage', () => ({ default: () => <div data-page="publisher" /> }));

let rig: Rig;
let win: FakeWindow;
beforeAll(() => {
    rig = createRig();
    win = rig.win;
    // Prefs reads the global localStorage, devMode the window's.
    const store = new Map<string, string>();
    const ls = {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, String(v)),
        removeItem: (k: string) => void store.delete(k),
        clear: () => store.clear(),
    };
    (globalThis as unknown as { localStorage: unknown }).localStorage = ls;
    (win as unknown as { localStorage: unknown }).localStorage = ls;
});

const React = await import('react');
const { translate } = await import('../lib/i18n');
const { setDeveloperMode, isDeveloperMode } = await import('../lib/devMode');
const { default: SettingsPage } = await import('./SettingsPage');
const { default: StatusPage, healthRollup } = await import('./StatusPage');
const { default: PanicWipeDialog } = await import('../components/PanicWipeDialog');
const { default: SubscriptionsPanel, updatedText, outcomeState } = await import('../components/SubscriptionsPanel');
const { default: CustodyPanel, groupAddress } = await import('../components/CustodyPanel');
const { default: MobileShell } = await import('../shell/MobileShell');
const { default: DesktopShell } = await import('../shell/DesktopShell');
const { formatElapsed } = await import('../shell/StatusStrip');

const t = (k: string) => translate('en', k);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const text = (root: FakeNode) => root.textContent;
const listRows = (root: FakeNode) => all(root, (n) => n.nodeType === 1 && n.getAttribute('data-list-row') !== null);

function engine(over: Record<string, (...a: unknown[]) => Promise<unknown>> = {}) {
    for (const k of Object.keys(fake)) delete fake[k];
    Object.assign(fake, {
        connectionSummary: async () => ({ state: 'disconnected', mode: 'normal' }),
        versionInfo: async () => ({ engineVersion: 'daal-core 0.9.1', guiVersion: '0.9.0' }),
        setMode: async () => undefined,
        loadedWasmModules: async () => ['hello-https'],
        wasmKillSwitchPubkey: async () => 'abcd',
        setAllowBulkCapable: async () => undefined,
        setAutoPromotion: async () => undefined,
        setPushRendezvousEnabled: async () => undefined,
        setExperimentalFamiliesEnabled: async () => undefined,
        setMasqueSubmodeOverride: async () => undefined,
        subscriptionList: async () => [],
        subscriptionRefresh: async () => undefined,
        subscriptionRemove: async () => undefined,
        statusPagePayload: async () => ({
            connection: { state: 'connected', mode: 'normal', activeRoute: { routeId: 'r1', publisherName: 'Pars Relays', routeNickname: 'Rescue 03' } },
            why: null,
            pointer: { havePersisted: true, validForDays: 14 },
            routeHealth: [
                { routeId: 'r1', label: 'Pars · Rescue 03', pct: 96, severity: 'ok' },
                { routeId: 'r2', label: 'Friend · May 6', pct: 28, severity: 'bad' },
            ],
            rawDiagnosticsJson: '{"engine":"raw"}',
        }),
        exportDiagnostics: async () => '{"report":1}',
        schedulerStatus: async () => ({ json: '{"tick":1}' }),
        statsRedacted: async () => ({ json: '' }),
        bootstrapStatus: async () => ({ json: '' }),
        throughputSnapshot: async () => ({ upBytesPerSec: null, downBytesPerSec: null }),
        panicWipe: async () => undefined,
        ...over,
    });
}

const settingsProps = {
    t,
    locale: 'en' as const,
    onLocaleChange: () => {},
    publisherEnabled: false,
    onPublisherEnabledChange: () => {},
    appVersion: '0.9.0',
};

beforeEach(() => {
    engine();
    setDeveloperMode(false);
    win.innerWidth = 400;
});
afterEach(async () => {
    for (const k of Object.keys(tauri)) delete tauri[k];
    await rig.unmountAll();
    setDeveloperMode(false);
    vi.unstubAllGlobals();
});

describe('Settings main (C5.1)', () => {
    it('one short list: Status, Language, Theme, Help family connect, Advanced, then Erase on its own', async () => {
        const m = await rig.mount(<SettingsPage {...settingsProps} />);
        const rows = listRows(m.container);
        expect(rows.length).toBeLessThanOrEqual(7);
        const s = text(m.container);
        for (const k of ['page.status.title', 'settings.language.label', 'settings.theme.label', 'settings.publisher.toggle', 'settings.advanced.title', 'settings.erase.row']) {
            expect(s, k).toContain(t(k));
        }
        expect(btn(m.container, 'status-row')).toBeTruthy();
        expect(btn(m.container, 'advanced-row')).toBeTruthy();
        expect(btn(m.container, 'erase')).toBeTruthy();
        // Gone from the main list: the chip row, the mode pill, the fake green dot row.
        expect(s).not.toContain('Diagnostics');
        expect(s).not.toContain('Mode ·');
        expect(s).not.toContain(translate('en', 'settings.emergency.body'));
    });

    it('no engine words while developer tools are off, on any Settings page', async () => {
        const m = await rig.mount(<SettingsPage {...settingsProps} />);
        await rig.click(btn(m.container, 'advanced-row'));
        const s = text(m.container);
        expect(s).toContain(t('settings.network.mode'));
        for (const w of ['MASQUE', 'WASM', 'Push rendezvous', 'Experimental', 'Kill-switch']) expect(s, w).not.toContain(w);
    });

    it('the erase row opens the erase confirm (two taps from the Settings tab)', async () => {
        const m = await rig.mount(<SettingsPage {...settingsProps} />);
        await rig.click(btn(m.container, 'erase'));
        expect(byAttr(win.document.body, 'data-panic-dialog')).toBeTruthy();
        expect(text(win.document.body)).toContain('This cannot be undone.');
    });

    it('seven taps on the version line within 3 s switch developer tools on, with a toast; seven more switch them off', async () => {
        const m = await rig.mount(<SettingsPage {...settingsProps} />);
        const v = btn(m.container, 'version')!;
        expect(text(v)).toContain('Daal 0.9.0');
        for (let i = 0; i < 6; i++) await rig.click(v);
        expect(isDeveloperMode()).toBe(false);
        await rig.click(v);
        expect(isDeveloperMode()).toBe(true);
        expect(text(m.container)).toContain(t('ui.dev.on'));
        for (let i = 0; i < 7; i++) await rig.click(btn(m.container, 'version'));
        expect(isDeveloperMode()).toBe(false);
        expect(text(m.container)).toContain(t('ui.dev.off'));
    });

    it('slow taps do not count', async () => {
        const m = await rig.mount(<SettingsPage {...settingsProps} />);
        const now = vi.spyOn(Date, 'now');
        let clock = 1_000_000;
        now.mockImplementation(() => clock);
        for (let i = 0; i < 7; i++) {
            await rig.click(btn(m.container, 'version'));
            clock += 600; // 7 taps over 4.2 s
        }
        now.mockRestore();
        expect(isDeveloperMode()).toBe(false);
    });

    it('the Status row opens Status, and Back returns to the list', async () => {
        const m = await rig.mount(<SettingsPage {...settingsProps} />);
        await rig.click(btn(m.container, 'status-row'));
        expect(byAttr(m.container, 'data-status-page')).toBeTruthy();
        await rig.back();
        expect(byAttr(m.container, 'data-status-page')).toBeNull();
        expect(btn(m.container, 'status-row')).toBeTruthy();
    });

    it('the publisher switch is a real switch and the whole row flips it', async () => {
        const seen: boolean[] = [];
        const m = await rig.mount(<SettingsPage {...settingsProps} onPublisherEnabledChange={(v) => seen.push(v)} />);
        const sw = btn(m.container, 'publisher-toggle')!;
        expect(sw.getAttribute('role')).toBe('switch');
        await rig.click(sw);
        expect(seen).toEqual([true]);
    });
});

describe('Settings → Advanced (C5.2)', () => {
    it('a refused mode change puts the old mode back and says so', async () => {
        engine({ setMode: async () => Promise.reject('refused') });
        const m = await rig.mount(<SettingsPage {...settingsProps} subPage="advanced" onSubPageChange={() => {}} />);
        await rig.click(btn(m.container, 'mode-lifeline'));
        expect(text(m.container)).toContain(t('settings.failed'));
        expect(btn(m.container, 'mode-normal')!.getAttribute('aria-selected')).toBe('true');
    });

    it('developer tools: every switch kept, a refused one flips back and shows a line, and the card turns itself off', async () => {
        setDeveloperMode(true);
        engine({ setAutoPromotion: async () => Promise.reject('no such setting') });
        const m = await rig.mount(<SettingsPage {...settingsProps} subPage="advanced" onSubPageChange={() => {}} />);
        const s = text(m.container);
        for (const k of ['settings.network.bulk', 'settings.advanced.autopromote', 'settings.advanced.push', 'settings.advanced.experimental', 'settings.advanced.masque', 'settings.notifications.detailed', 'settings.engine_version', 'settings.about.wasm', 'settings.about.killswitch']) {
            expect(s, k).toContain(t(k));
        }
        const ap = btn(m.container, 'dev-autopromote')!;
        expect(ap.getAttribute('aria-checked')).toBe('true');
        await rig.click(ap);
        expect(btn(m.container, 'dev-autopromote')!.getAttribute('aria-checked')).toBe('true');
        expect(text(m.container)).toContain(t('settings.failed'));
        await rig.click(btn(m.container, 'dev-off'));
        expect(isDeveloperMode()).toBe(false);
        expect(text(m.container)).not.toContain('MASQUE');
    });

    it('Automatic updates is not drawn at all with no update addresses', async () => {
        const m = await rig.mount(<SubscriptionsPanel t={t} />);
        expect(byAttr(m.container, 'data-subscriptions-panel')).toBeNull();
        expect(text(m.container)).toBe('');
    });

    it('an update address is one row: state, name, "Updated …", a check button and ⋯ with Remove (asked first)', async () => {
        const removed: string[] = [];
        engine({
            subscriptionList: async () => [
                { subscriptionId: 's1', publisherId: 'p', displayName: 'Pars Relays', profileTitle: '', lastRefreshBucket: '', lastRefreshOutcome: 'ok', lastGoodRefreshBucket: new Date(Date.now() - 2 * 3600_000).toISOString() },
            ],
            subscriptionRemove: async (id) => {
                removed.push(String(id));
            },
        });
        const m = await rig.mount(<SubscriptionsPanel t={t} />);
        expect(text(m.container)).toContain('Pars Relays');
        expect(text(m.container)).toContain('Updated');
        expect(btn(m.container, 'sub-refresh')).toBeTruthy();
        await rig.click(btn(m.container, 'sub-more'));
        await rig.click(btn(win.document.body, 'sub-remove'));
        expect(removed).toEqual([]);
        expect(text(m.container)).toContain('Stop updates from Pars Relays?');
        await rig.click(btn(m.container, 'sub-remove-confirm'));
        expect(removed).toEqual(['s1']);
    });

    it('My Daal address: nothing to show is no card at all', async () => {
        const m = await rig.mount(<CustodyPanel t={t} />);
        expect(byAttr(m.container, 'data-custody-panel')).toBeNull();
    });

    it('My Daal address: the address grouped, the protection as one badge, and a new address only after the checkbox', async () => {
        let rotated = 0;
        tauri.device_custody_level = () => 'os_keystore';
        tauri.device_custody_is_unlocked = () => true;
        tauri.recipient_identity_get = () => ({ address: 'daal1qm3n8v2kabcd', fingerprint_hex: '', created_at_unix: 1 });
        tauri.device_custody_history = () => [];
        tauri.device_custody_events = () => [];
        tauri.device_custody_rotate = () => {
            rotated++;
            return { address: 'daal1zzzz', fingerprint_hex: '', created_at_unix: 2 };
        };
        const m = await rig.mount(<CustodyPanel t={t} />);
        const s = text(m.container);
        expect(s).toContain('daal1 qm3n 8v2k abcd');
        expect(s).toContain(t('settings.custody.badge.os_keystore'));
        expect(s).not.toContain('UNLOCKED');
        // No history yet: no empty fold.
        expect(btn(m.container, 'custody-history')).toBeNull();
        await rig.click(btn(m.container, 'new-address'));
        const body = win.document.body;
        expect(text(body)).toContain(t('settings.custody.rotate.dialog.checkbox'));
        expect(btn(body, 'rotate-confirm')!.getAttribute('disabled')).not.toBeNull();
        const box = btn(body, 'rotate-understand')!;
        await React.act(async () => {
            box.checked = true;
            box.dispatchEvent(new FakeEvent('click'));
        });
        await rig.settle();
        expect(btn(body, 'rotate-confirm')!.getAttribute('disabled')).toBeNull();
        await rig.click(btn(body, 'rotate-confirm'));
        expect(rotated).toBe(1);
        expect(text(m.container)).toContain(t('settings.custody.rotated_toast'));
    });

    it('outcome and age helpers', () => {
        expect(outcomeState('')).toBe('none');
        expect(outcomeState('ok')).toBe('ok');
        expect(outcomeState('error: x')).toBe('bad');
        expect(updatedText(t, 'en', '')).toBe(t('subs.never'));
        expect(updatedText(t, 'en', '2026-01-01T10:00:00Z', Date.parse('2026-01-01T12:00:00Z'))).toContain('2 hours ago');
        expect(groupAddress('daal1qm3n8v2kxyz')).toBe('daal1 qm3n 8v2k xyz');
    });
});

describe('Status (C6)', () => {
    it('a summary of at most four rows, one button, one closed fold; no raw JSON', async () => {
        const m = await rig.mount(<StatusPage t={t} onBack={() => {}} />);
        const rows = all(m.container, (n) => n.nodeType === 1 && n.getAttribute('data-sum-row') !== null);
        expect(rows.length).toBeGreaterThan(0);
        expect(rows.length).toBeLessThanOrEqual(4);
        const s = text(m.container);
        expect(s).toContain(t('connection.connected'));
        expect(s).toContain('Pars Relays · Rescue 03');
        expect(s).toContain('1 of 2');
        expect(s).not.toContain('{');
        expect(s).not.toContain('Internet');
        expect(btn(m.container, 'export')).toBeTruthy();
        expect(btn(m.container, 'helper-fold')!.getAttribute('aria-expanded')).toBe('false');
        expect(btn(m.container, 'page-back')).toBeTruthy();
        // No engine words on the page while closed.
        for (const w of ['Bucket', 'Scheduler', 'Throughput']) expect(s, w).not.toContain(w);
    });

    it('the fold holds the numbers that mean something, with names not ids', async () => {
        const m = await rig.mount(<StatusPage t={t} />);
        await rig.click(btn(m.container, 'helper-fold'));
        const s = text(m.container);
        expect(s).toContain(t('status.acc.routes'));
        expect(s).toContain('Friend · May 6');
        expect(s).not.toContain('r2');
        expect(s).toContain('Valid 14 days');
        expect(s).not.toContain('not measured');
    });

    it('"Copy a report" always answers: copied, or could not', async () => {
        const writes: string[] = [];
        vi.stubGlobal('navigator', { clipboard: { writeText: async (s: string) => void writes.push(s) } });
        const m = await rig.mount(<StatusPage t={t} />);
        await rig.click(btn(m.container, 'export'));
        expect(writes).toEqual(['{"report":1}']);
        expect(text(m.container)).toContain(t('status.report.done'));
        vi.stubGlobal('navigator', { clipboard: { writeText: async () => Promise.reject(new Error('denied')) } });
        await rig.click(btn(m.container, 'export'));
        expect(text(m.container)).toContain(t('status.report.failed'));
    });

    it('No internet only when the browser says offline', async () => {
        vi.stubGlobal('navigator', { onLine: false });
        const m = await rig.mount(<StatusPage t={t} />);
        expect(text(m.container)).toContain(t('status.sum.no_internet'));
    });

    it('developer tools show the raw parts, the whole blob and the stubbed probe label', async () => {
        setDeveloperMode(true);
        const m = await rig.mount(<StatusPage t={t} />);
        const s = text(m.container);
        expect(s).toContain(t('settings.dev.title'));
        expect(s).toContain(t('status.tile.bucket'));
        // Throughput is null: no row.
        expect(s).not.toContain(t('status.tile.throughput'));
        await rig.click(btn(m.container, 'dev-raw'));
        expect(text(m.container)).toContain('"engine": "raw"');
        await rig.click(btn(m.container, 'dev-network'));
        expect(text(btn(m.container, 'run-probes')!)).toContain('(not built yet)');
    });

    it('rollup counts only measured ways', () => {
        const r = healthRollup([
            { routeId: 'a', label: 'A', pct: 90, severity: 'ok' },
            { routeId: 'b', label: 'B' },
        ]);
        expect(r).toMatchObject({ total: 2, measured: 1, ok: 1, avg: 90 });
        expect(healthRollup([]).avg).toBeNull();
    });
});

describe('Erase confirm (C5.4)', () => {
    it('the red Erase stays off until the word is typed; Cancel and Back close it; the locked question folds', async () => {
        let closed = 0;
        const m = await rig.mount(<PanicWipeDialog t={t} onClose={() => closed++} />);
        const body = win.document.body;
        expect(text(body)).toContain('Erases your files, keys and history on this phone. This cannot be undone.');
        expect(btn(body, 'erase-hold')!.getAttribute('disabled')).not.toBeNull();
        await rig.type(btn(body, 'erase-word'), 'eras');
        expect(btn(body, 'erase-hold')!.getAttribute('disabled')).not.toBeNull();
        await rig.type(btn(body, 'erase-word'), 'Erase');
        expect(btn(body, 'erase-hold')!.getAttribute('disabled')).toBeNull();
        expect(text(body)).not.toContain(t('settings.emergency.body'));
        await rig.click(btn(body, 'erase-locked-q'));
        expect(text(body)).toContain(t('settings.emergency.body'));
        await rig.click(btn(body, 'erase-cancel'));
        expect(closed).toBe(1);
        await rig.back();
        expect(closed).toBe(2);
        await m.unmount();
    });

    it('a tap is not a hold: releasing at once erases nothing', async () => {
        let wiped = 0;
        engine({ panicWipe: async () => void wiped++ });
        await rig.mount(<PanicWipeDialog t={t} onClose={() => {}} />);
        const body = win.document.body;
        await rig.type(btn(body, 'erase-word'), 'erase');
        const hold = btn(body, 'erase-hold')!;
        await React.act(async () => {
            hold.dispatchEvent(new FakeEvent('pointerdown'));
            hold.dispatchEvent(new FakeEvent('pointerup'));
        });
        await rig.settle(8);
        expect(wiped).toBe(0);
    });

    it('Farsi asks for «پاک» and also accepts "erase"', async () => {
        const tf = (k: string) => translate('fa', k);
        await rig.mount(<PanicWipeDialog t={tf} onClose={() => {}} />);
        const body = win.document.body;
        expect(text(body)).toContain('پاک');
        expect(text(body)).not.toContain('erase را');
        await rig.type(btn(body, 'erase-word'), 'پاک');
        expect(btn(body, 'erase-hold')!.getAttribute('disabled')).toBeNull();
        await rig.type(btn(body, 'erase-word'), 'پا');
        expect(btn(body, 'erase-hold')!.getAttribute('disabled')).not.toBeNull();
        await rig.type(btn(body, 'erase-word'), 'erase');
        expect(btn(body, 'erase-hold')!.getAttribute('disabled')).toBeNull();
    });

    it('a full hold erases once, even when the caller re-renders with a new onClose', async () => {
        let wiped = 0;
        engine({ panicWipe: async () => void wiped++ });
        let bump: () => void = () => {};
        function Parent() {
            const [n, setN] = React.useState(0);
            bump = () => setN((x) => x + 1);
            return <PanicWipeDialog key="d" t={t} holdMs={60} onClose={() => void n} />;
        }
        await rig.mount(<Parent />);
        const body = win.document.body;
        await rig.type(btn(body, 'erase-word'), 'erase');
        await React.act(async () => {
            btn(body, 'erase-hold')!.dispatchEvent(new FakeEvent('pointerdown'));
        });
        await React.act(async () => {
            await new Promise((r) => setTimeout(r, 200));
        });
        for (let i = 0; i < 4; i++) {
            await React.act(async () => {
                bump();
                await new Promise((r) => setTimeout(r, 80));
            });
        }
        expect(wiped).toBe(1);
    });

    it('a computer says "this computer"', async () => {
        win.innerWidth = 1280;
        await rig.mount(<PanicWipeDialog t={t} onClose={() => {}} />);
        expect(text(win.document.body)).toContain('on this computer. This cannot be undone.');
    });
});

describe('Shells (C8, C9)', () => {
    it('phone: Home\'s Status lands on Settings → Status, Back returns to the Settings list', async () => {
        const m = await rig.mount(<MobileShell t={t} locale="en" onLocaleChange={() => {}} engineHealthy appVersion="0.9.0" />);
        expect(byAttr(m.container, 'data-page', 'connection')).toBeTruthy();
        await rig.click(btn(m.container, 'home-status'));
        expect(byAttr(m.container, 'data-status-page')).toBeTruthy();
        expect(btn(m.container, 'tab-settings')!.getAttribute('aria-selected')).toBe('true');
        await rig.back();
        expect(btn(m.container, 'status-row')).toBeTruthy();
        // The Files tab is named Files.
        expect(text(btn(m.container, 'tab-network')!)).toContain('Files');
    });

    it('desktop: four places at most, no Diagnostics item, no filled red button, a quiet erase row, nothing on the right while healthy', async () => {
        win.innerWidth = 1280;
        const m = await rig.mount(<DesktopShell t={t} locale="en" onLocaleChange={() => {}} engineHealthy appVersion="0.9.0" />);
        const navItems = all(m.container, (n) => n.nodeType === 1 && /^nav-/.test(n.getAttribute('data-button') ?? ''));
        expect(navItems.map((n) => n.getAttribute('data-button'))).toEqual(['nav-connection', 'nav-network', 'nav-settings']);
        expect(btn(m.container, 'nav-status')).toBeNull();
        expect(text(m.container)).not.toContain('Engine healthy');
        expect(text(m.container)).not.toContain('Main');
        const erase = btn(m.container, 'erase')!;
        expect(erase.style.background).toBe('transparent');
        expect(text(erase)).toContain(t('nav.erase'));
        await rig.click(erase);
        expect(byAttr(win.document.body, 'data-panic-dialog')).toBeTruthy();
    });

    it('desktop: when the engine stops answering, one warning opens Status; Ctrl+3 picks the third place', async () => {
        win.innerWidth = 1280;
        const m = await rig.mount(<DesktopShell t={t} locale="en" onLocaleChange={() => {}} engineHealthy={false} appVersion="0.9.0" />);
        await rig.click(btn(m.container, 'title-engine'));
        expect(byAttr(m.container, 'data-status-page')).toBeTruthy();
        await rig.click(btn(m.container, 'nav-connection'));
        expect(byAttr(m.container, 'data-page', 'connection')).toBeTruthy();
        await React.act(async () => {
            const e = new FakeEvent('keydown') as FakeEvent & { key: string; ctrlKey: boolean };
            e.key = '3';
            e.ctrlKey = true;
            win.fire(e, false, win);
        });
        await rig.settle();
        expect(btn(m.container, 'status-row')).toBeTruthy();
    });

    it('a file opened with Daal while the person is in Settings waits: "Open" brings them to Home', async () => {
        const { _resetOpenedFile } = await import('../recipient/openedFile');
        _resetOpenedFile();
        const m = await rig.mount(<MobileShell t={t} locale="en" onLocaleChange={() => {}} engineHealthy appVersion="0.9.0" />);
        await rig.click(btn(m.container, 'tab-settings'));
        expect(byAttr(m.container, 'data-page', 'connection')).toBeNull();
        expect(events['daal://opened-file']).toBeTruthy();
        await React.act(async () => events['daal://opened-file']({ payload: { path: '/staged/x.sbpx' } }));
        await rig.settle();
        // Not pulled away: Settings stays, and a toast offers the file.
        expect(byAttr(m.container, 'data-page', 'connection')).toBeNull();
        expect(btn(m.container, 'status-row')).toBeTruthy();
        expect(text(win.document.body)).toContain('A file is waiting to be added.');
        await rig.click(btn(win.document.body, 'opened-file-open'));
        expect(byAttr(m.container, 'data-page', 'connection')).toBeTruthy();
    });

    it('an opened file never unmounts what is on the Publisher tab (a relay being built, words on screen)', async () => {
        const { _resetOpenedFile, _deliverOpenedFile } = await import('../recipient/openedFile');
        _resetOpenedFile();
        localStorage.setItem('daal.d2.publisher.enabled', '1');
        const m = await rig.mount(<MobileShell t={t} locale="en" onLocaleChange={() => {}} engineHealthy appVersion="0.9.0" />);
        const tab = btn(m.container, 'tab-publisher');
        expect(tab).toBeTruthy();
        await rig.click(tab);
        expect(byAttr(m.container, 'data-page', 'publisher')).toBeTruthy();
        await React.act(async () => _deliverOpenedFile('/staged/y.sbp'));
        await rig.settle();
        expect(byAttr(m.container, 'data-page', 'publisher')).toBeTruthy();
        expect(btn(win.document.body, 'opened-file-open')).toBeTruthy();
        localStorage.removeItem('daal.d2.publisher.enabled');
    });

    it('a file Daal was launched with goes to Home at once', async () => {
        const { _resetOpenedFile, _deliverOpenedFile } = await import('../recipient/openedFile');
        _resetOpenedFile();
        const m = await rig.mount(<MobileShell t={t} locale="en" onLocaleChange={() => {}} engineHealthy appVersion="0.9.0" />);
        await rig.click(btn(m.container, 'tab-settings'));
        await React.act(async () => _deliverOpenedFile('/staged/z.sbp', 'launch'));
        await rig.settle();
        expect(byAttr(m.container, 'data-page', 'connection')).toBeTruthy();
    });

    it('elapsed time reads hh:mm:ss', () => {
        expect(formatElapsed(0, 3723_000)).toBe('01:02:03');
        expect(formatElapsed(null, 5)).toBe('00:00:00');
    });
});
