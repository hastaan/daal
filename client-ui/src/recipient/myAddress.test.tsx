// "My Daal address" (spec C4.4 and G.2, this wave): made as it opens,
// shown in groups, copied with a toast; on Android "Send address" opens
// the share sheet (share_text) and Copy is second; a shell without
// share_text copies instead.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';

const calls: string[] = [];
let identity: { address: string; fingerprint_hex: string; created_at_unix: number } | null = null;
let shareWorks = true;
let level = 'hardware';

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push(cmd);
        if (cmd === 'recipient_identity_get') return identity;
        if (cmd === 'recipient_identity_get_or_create') {
            identity = { address: 'daal1qm3n8v2kc5xy', fingerprint_hex: 'ab', created_at_unix: 1 };
            return identity;
        }
        if (cmd === 'device_custody_level') return level;
        if (cmd === 'device_custody_is_unlocked') return level !== 'session_passphrase';
        if (cmd === 'share_text') {
            if (!shareWorks) throw new Error('command share_text not found');
            calls.push(`share:${String(args?.text)}`);
            return null;
        }
        throw new Error(`not mocked: ${cmd}`);
    },
}));

const { default: MyAddress, groupAddress } = await import('./MyAddress');
const legacyEn = (await import('../i18n/en.json')).default as Record<string, string>;
const d2En = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...d2En };
const t = (k: string) => EN[k] ?? k;

let rig: Rig;
let copied: string[] = [];
beforeAll(() => {
    rig = createRig();
});
beforeEach(() => {
    calls.length = 0;
    identity = null;
    shareWorks = true;
    level = 'hardware';
    copied = [];
    vi.stubGlobal('navigator', {
        userAgent: 'Mozilla/5.0 (Linux; Android 10)',
        clipboard: { writeText: async (s: string) => void copied.push(s) },
    });
});
afterEach(async () => {
    await rig.unmountAll();
    vi.unstubAllGlobals();
});

const btn = (root: Parameters<typeof byAttr>[0], id: string) => byAttr(root, 'data-button', id);

describe('My Daal address', () => {
    it('groups it as daal1 then fours', () => {
        expect(groupAddress('daal1qm3n8v2kc5xy')).toBe('daal1 qm3n 8v2k c5xy');
        expect(groupAddress('daal1 qm3n\n8v2k')).toBe('daal1 qm3n 8v2k');
    });

    it('is made as the sheet opens: no "Create" tap', async () => {
        const m = await rig.mount(<MyAddress t={t} />);
        await rig.settle(6);
        expect(calls).toContain('recipient_identity_get_or_create');
        expect(btn(m.container, 'create-address')).toBeNull();
        expect(m.container.textContent).toContain('daal1 qm3n 8v2k c5xy');
    });

    it('with a session passphrase not entered yet, the field and "Create" stay', async () => {
        level = 'session_passphrase';
        const m = await rig.mount(<MyAddress t={t} />);
        await rig.settle(6);
        expect(calls).not.toContain('recipient_identity_get_or_create');
        expect(btn(m.container, 'create-address')).toBeTruthy();
    });

    it('on Android: "Send address" opens the share sheet and says nothing; Copy copies and says Copied', async () => {
        identity = { address: 'daal1abcd', fingerprint_hex: 'ab', created_at_unix: 1 };
        const m = await rig.mount(<MyAddress t={t} />);
        await rig.settle(6);
        await rig.click(btn(m.container, 'send-address'));
        expect(calls).toContain('share:daal1abcd');
        expect(m.container.textContent).not.toContain('Copied');
        await rig.click(btn(m.container, 'copy-address'));
        expect(copied).toEqual(['daal1abcd']);
        expect(m.container.textContent).toContain('Copied');
    });

    it('an older shell without share_text: "Send address" copies instead, and says so', async () => {
        shareWorks = false;
        identity = { address: 'daal1abcd', fingerprint_hex: 'ab', created_at_unix: 1 };
        const m = await rig.mount(<MyAddress t={t} />);
        await rig.settle(6);
        await rig.click(btn(m.container, 'send-address'));
        expect(copied).toEqual(['daal1abcd']);
        expect(m.container.textContent).toContain('Copied');
    });

    it('away from Android: Copy is the one button', async () => {
        vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0 (X11; Linux x86_64)', clipboard: { writeText: async () => {} } });
        identity = { address: 'daal1abcd', fingerprint_hex: 'ab', created_at_unix: 1 };
        const m = await rig.mount(<MyAddress t={t} />);
        await rig.settle(6);
        expect(btn(m.container, 'send-address')).toBeNull();
        expect(btn(m.container, 'copy-address')).toBeTruthy();
    });
});
