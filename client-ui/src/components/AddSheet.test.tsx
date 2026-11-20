// "Add my file", driven in the miniDom rig (spec C3): three ways in, no
// tabs and no Import/Preview taps; a recognised paste and a chosen file
// go on by themselves; a new publisher gets the trust question in place
// of the whole sheet; the result is "File added" + Connect, or one
// reason + Close.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';

const calls: string[] = [];
let verdict = '';
let trustAnswer = '';
let sealed = false;
let picked: string | null = 'content://downloads/maman.sbp';

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push(`${cmd}${args?.path ? `:${String(args.path)}` : ''}`);
        if (cmd === 'stage_picked_file') return '/staging/maman.sbp';
        if (cmd === 'recipient_sbpx_sniff') return sealed;
        if (cmd === 'device_custody_is_unlocked') return true;
        if (cmd === 'recipient_import_sbpx') return '/staging/maman.plain.sbp';
        throw new Error(`not mocked: ${cmd}`);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));
vi.mock('@tauri-apps/plugin-dialog', () => ({
    open: async () => {
        calls.push('dialog');
        return picked;
    },
}));

const preview = {
    fingerprintHex: 'ab12',
    fingerprintEN: 'phoenix rescue may sky',
    fingerprintFA: 'ققنوس نجات اردیبهشت آسمان',
    fingerprintVisualDataUri: '',
    publisherName: 'Maman',
    bundleId: 'b1',
    specVersion: 1,
    routeCount: 2,
};
const fake = {
    importSbpBytes: async () => {
        calls.push('importSbpBytes');
        return verdict;
    },
    previewBundle: async (p: string) => {
        calls.push(`previewBundle:${p}`);
        return preview;
    },
    importSbp: async (p: string) => {
        calls.push(`importSbp:${p}`);
        return verdict;
    },
    resolveTrustPrompt: async (fp: string, d: number) => {
        calls.push(`resolve:${fp}:${d}`);
        return trustAnswer;
    },
    listPublishers: async () => [{ publisherId: 'ab12', displayName: 'Maman' }],
    subscriptionAdd: async () => {
        calls.push('subscriptionAdd');
        return 'sub';
    },
    uriImport: async () => {
        calls.push('uriImport');
        return {};
    },
};
vi.mock('../contract/ContractProvider', () => ({ useContract: () => fake }));

const React = await import('react');
const { default: AddSheet, classifyPaste, PASTE_SETTLE_MS, unsafeError } = await import('./AddSheet');
const legacyEn = (await import('../i18n/en.json')).default as Record<string, string>;
const d2En = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...d2En };
const t = (k: string) => EN[k] ?? k;

// A pasted .sbp: the base64 of a zip ("UEsDB…"), long enough to be one.
const BUNDLE_TEXT = 'UEsDBBQAAAAIAA' + 'Kx3mQ9vT2bN8pLr4Wc7Zy1Hd6Fg0Js5Ae9Ui2Ok8Tn3Bv7Mq4Xw1Cs6Dp0Ga5Hf9Ej2Il8Ro'.repeat(9);

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
beforeEach(() => {
    calls.length = 0;
    verdict = JSON.stringify({ Kind: 0, Fingerprint: 'ab12', RouteCount: 2 });
    trustAnswer = JSON.stringify({ Kind: 0, Fingerprint: 'ab12', RouteCount: 2 });
    sealed = false;
    picked = 'content://downloads/maman.sbp';
});
afterEach(async () => {
    await rig.unmountAll();
});

const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const buttons = (root: FakeNode) =>
    all(root, (n) => n.nodeName === 'BUTTON' && n.getAttribute('aria-expanded') === null && n.getAttribute('aria-label') === null);
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function open(props: Partial<Parameters<typeof AddSheet>[0]> = {}) {
    const onClose = vi.fn();
    const onConnect = vi.fn();
    const onImported = vi.fn();
    const m = await rig.mount(
        <AddSheet t={t} onClose={onClose} onConnect={onConnect} onImported={onImported} {...props} />,
    );
    return { ...m, onClose, onConnect, onImported };
}

async function pasteBundle(root: FakeNode) {
    await rig.click(btn(root, 'add-paste'));
    await rig.type(btn(root, 'paste-box'), BUNDLE_TEXT);
    await React.act(async () => {
        await wait(PASTE_SETTLE_MS + 60);
    });
    await rig.settle(8);
}

describe('the add sheet: one sheet, three ways in', () => {
    it('opens on three choices: no tabs, no Import, no Cancel', async () => {
        const m = await open();
        for (const id of ['add-choose-file', 'add-paste', 'add-scan']) expect(btn(m.container, id), id).toBeTruthy();
        expect(all(m.container, (n) => n.getAttribute('role') === 'tab')).toHaveLength(0);
        const text = m.container.textContent ?? '';
        expect(text).not.toContain(t('common.cancel'));
        expect(text).toContain('Add my file');
    });

    it('a pasted Daal file goes on by itself: no Import tap, and it says what it is', async () => {
        const m = await open();
        await rig.click(btn(m.container, 'add-paste'));
        await rig.type(btn(m.container, 'paste-box'), BUNDLE_TEXT);
        expect(m.container.textContent).toContain('Daal file');
        expect(calls).not.toContain('importSbpBytes');
        await React.act(async () => {
            await wait(PASTE_SETTLE_MS + 60);
        });
        await rig.settle(8);
        expect(calls).toContain('importSbpBytes');
        expect(m.container.textContent).toContain('File added');
        expect(m.onImported).toHaveBeenCalled();
    });

    it('text that is not a Daal file: one red line, and nothing is imported', async () => {
        const m = await open();
        await rig.click(btn(m.container, 'add-paste'));
        await rig.type(btn(m.container, 'paste-box'), 'hello, here is my holiday photo');
        await React.act(async () => {
            await wait(PASTE_SETTLE_MS + 60);
        });
        expect(m.container.textContent).toContain("This isn't a Daal file.");
        expect(calls).not.toContain('importSbpBytes');
    });

    it('a pasted web address is not added by itself: it waits for "Add"', async () => {
        const m = await open();
        await rig.click(btn(m.container, 'add-paste'));
        await rig.type(btn(m.container, 'paste-box'), 'https://news.example.org/today');
        await React.act(async () => {
            await wait(PASTE_SETTLE_MS + 200);
        });
        await rig.settle(8);
        expect(calls).not.toContain('subscriptionAdd');
        expect(m.container.textContent).toContain('Web address');
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(calls.filter((c) => c === 'subscriptionAdd')).toHaveLength(1);
        expect(m.container.textContent).toContain('File added');
    });

    it('an address typed by hand, with a pause in the middle, adds nothing', async () => {
        const m = await open();
        await rig.click(btn(m.container, 'add-paste'));
        await rig.type(btn(m.container, 'paste-box'), 'https://exa');
        await React.act(async () => {
            await wait(500);
        });
        await rig.type(btn(m.container, 'paste-box'), 'https://example.org/sub');
        await React.act(async () => {
            await wait(500);
        });
        await rig.settle(8);
        expect(calls).not.toContain('subscriptionAdd');
    });

    it('a proxy link waits for "Add" too, then goes through uriImport once', async () => {
        const m = await open();
        await rig.click(btn(m.container, 'add-paste'));
        await rig.type(btn(m.container, 'paste-box'), 'vless://abc@host:443');
        await React.act(async () => {
            await wait(PASTE_SETTLE_MS + 200);
        });
        expect(calls).not.toContain('uriImport');
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(calls.filter((c) => c === 'uriImport')).toHaveLength(1);
    });

    it('a chosen file is read and checked at once: picker, stage, preview, import — then "From Maman"', async () => {
        const m = await open();
        await rig.click(btn(m.container, 'add-choose-file'));
        await rig.settle(8);
        expect(calls).toEqual([
            'dialog',
            'stage_picked_file:content://downloads/maman.sbp',
            'recipient_sbpx_sniff:/staging/maman.sbp',
            'previewBundle:/staging/maman.sbp',
            'importSbp:/staging/maman.sbp',
        ]);
        const text = m.container.textContent ?? '';
        expect(text).toContain('File added');
        expect(text).toContain('From Maman');
    });

    it('a sealed file opens with this phone\'s key, read once', async () => {
        sealed = true;
        const m = await open();
        await rig.click(btn(m.container, 'add-choose-file'));
        await rig.settle(8);
        expect(calls.filter((c) => c.startsWith('recipient_import_sbpx'))).toHaveLength(1);
        expect(calls).toContain('importSbp:/staging/maman.plain.sbp');
        expect(m.container.textContent).toContain('File added');
    });

    it('closing the picker without a file leaves the three choices', async () => {
        picked = null;
        const m = await open();
        await rig.click(btn(m.container, 'add-choose-file'));
        expect(btn(m.container, 'add-paste')).toBeTruthy();
        expect(calls).toEqual(['dialog']);
    });
});

describe('the result', () => {
    it('"Connect" connects and closes the sheet; "Not now" only closes', async () => {
        const m = await open();
        await pasteBundle(m.container);
        expect(btn(m.container, 'import-connect')).toBeTruthy();
        await rig.click(btn(m.container, 'import-connect'));
        expect(m.onConnect).toHaveBeenCalledTimes(1);
        expect(m.onClose).toHaveBeenCalledTimes(1);

        const n = await open();
        await pasteBundle(n.container);
        await rig.click(btn(n.container, 'import-later'));
        expect(n.onConnect).not.toHaveBeenCalled();
        expect(n.onClose).toHaveBeenCalledTimes(1);
    });

    it('a file that gives this phone fewer ways says so in one fold, with no protocol name', async () => {
        verdict = JSON.stringify({
            Kind: 0,
            Fingerprint: 'ab12',
            Unavailable: [{ RouteID: 'x/hysteria2', Family: 'hysteria2', Reason: 'not_offered' }],
        });
        const m = await open();
        await pasteBundle(m.container);
        const text = m.container.textContent ?? '';
        expect(text).toContain('Some ways to connect are not in this file');
        expect(text).not.toContain('hysteria2');
        await rig.click(btn(m.container, 'import-partial'));
        expect(m.container.textContent).toContain('Nothing is wrong with your phone.');
        expect(m.container.textContent).not.toContain('hysteria2');
    });

    it('a refused file: "This file isn\'t safe to use", the reason, and only Close', async () => {
        verdict = JSON.stringify({ Kind: 3, Reason: 'bundle_signature_invalid' });
        const m = await open();
        await pasteBundle(m.container);
        const text = m.container.textContent ?? '';
        expect(text).toContain("This file isn't safe to use");
        expect(text).toContain('changed on the way');
        expect(btn(m.container, 'import-connect')).toBeNull();
        expect(buttons(m.container).map((b) => b.getAttribute('data-button'))).toEqual(['import-close']);
        expect(m.onImported).not.toHaveBeenCalled();
    });

    it('a publisher whose key changed: "Don\'t use this file", with the check-in-person warning', async () => {
        verdict = JSON.stringify({ Kind: 3, Reason: 'publisher_key_changed' });
        const m = await open();
        await pasteBundle(m.container);
        const text = m.container.textContent ?? '';
        expect(text).toContain("Don't use this file");
        expect(text).toContain('in person or by voice');
        expect(buttons(m.container).map((b) => b.getAttribute('data-button'))).toEqual(['import-close']);
    });

    it('an engine error that means the file must not be used goes to the refused screen too', () => {
        expect(unsafeError('ErrInvalidSignature: bad')).toBe(true);
        expect(unsafeError('envelope corrupt or not addressed to this recipient')).toBe(true);
        expect(unsafeError('ErrIo: could not read')).toBe(false);
    });
});

describe('the trust question replaces the whole sheet', () => {
    beforeEach(() => {
        verdict = JSON.stringify({ Kind: 1, Fingerprint: 'ab12', HexEN: 'phoenix rescue may sky', HexFA: 'ققنوس نجات اردیبهشت آسمان' });
    });

    it('two answers and one fold; the paste box is gone; both word sets are shown', async () => {
        const m = await open();
        await pasteBundle(m.container);
        expect(btn(m.container, 'paste-box')).toBeNull();
        expect(btn(m.container, 'trust-yes')).toBeTruthy();
        expect(btn(m.container, 'trust-no')).toBeTruthy();
        expect(btn(m.container, 'trust-once')).toBeNull();
        const text = m.container.textContent ?? '';
        expect(text).toContain('Do you know who sent this file?');
        expect(text).toContain('phoenix');
        expect(text).toContain('ققنوس');
        expect(text).not.toMatch(/ENGLISH|bundle/i);
        await rig.click(btn(m.container, 'trust-more'));
        expect(btn(m.container, 'trust-once')).toBeTruthy();
    });

    it('"Yes, I know them" trusts (decision 0), and the engine\'s answer decides the result', async () => {
        const m = await open();
        await pasteBundle(m.container);
        await rig.click(btn(m.container, 'trust-yes'));
        await rig.settle(6);
        expect(calls).toContain('resolve:ab12:0');
        expect(m.container.textContent).toContain('File added');
        expect(m.onImported).toHaveBeenCalled();
    });

    it('the engine refusing at that moment is a refusal, not a success', async () => {
        trustAnswer = JSON.stringify({ Kind: 3, Reason: 'publisher_revoked' });
        const m = await open();
        await pasteBundle(m.container);
        await rig.click(btn(m.container, 'trust-yes'));
        await rig.settle(6);
        expect(m.container.textContent).toContain("Don't use this file");
        expect(m.onImported).not.toHaveBeenCalled();
    });

    it('"No" adds nothing and closes the sheet', async () => {
        const m = await open();
        await pasteBundle(m.container);
        await rig.click(btn(m.container, 'trust-no'));
        await rig.settle(4);
        expect(calls).toContain('resolve:ab12:2');
        expect(m.onClose).toHaveBeenCalled();
        expect(m.onImported).not.toHaveBeenCalled();
    });
});

describe('a file handed to Daal by Android', () => {
    it('goes straight to the check, with no tap', async () => {
        verdict = JSON.stringify({ Kind: 1, Fingerprint: 'ab12', HexEN: 'a b c d', HexFA: 'ا ب پ ت' });
        const m = await open({ openedPath: '/staging/opened.sbpx' });
        await rig.settle(8);
        expect(calls[0]).toBe('recipient_sbpx_sniff:/staging/opened.sbpx');
        expect(calls).toContain('importSbp:/staging/opened.sbpx');
        expect(btn(m.container, 'trust-yes')).toBeTruthy();
        expect(m.container.textContent).toContain('Is this file from Maman?');
    });

    it('shared text that holds no Daal file gets the share refusal line, and nothing is imported', async () => {
        const m = await open({ openedPath: '/staging/opened/opened-1a2b.txt' });
        await rig.settle(8);
        expect(calls.some((c) => c.startsWith('importSbp'))).toBe(false);
        expect(calls.some((c) => c.startsWith('recipient_sbpx_sniff'))).toBe(false);
        expect(m.container.textContent).toContain("This isn't a Daal file");
        // They used Share, not Paste: the advice says what to share.
        expect(m.container.textContent).toContain('Share the whole message, or the file itself.');
        expect(m.container.textContent).not.toContain('paste again');
    });
});

describe('the sheet says when it is in the middle of something', () => {
    it('the three choices and a result are not; a paste box or a trust question is', async () => {
        const seen: boolean[] = [];
        const m = await open({ onProgress: (b) => seen.push(b) });
        expect(seen[seen.length - 1]).toBe(false);
        await rig.click(btn(m.container, 'add-paste'));
        expect(seen[seen.length - 1]).toBe(true);
        verdict = JSON.stringify({ Kind: 1, Fingerprint: 'ab12', HexEN: 'a b c d', HexFA: 'ا ب پ ت' });
        const o = await open({ openedPath: '/staging/opened.sbpx', onProgress: (b) => seen.push(b) });
        await rig.settle(8);
        expect(btn(o.container, 'trust-yes')).toBeTruthy();
        expect(seen[seen.length - 1]).toBe(true);
    });
});

describe('classifyPaste', () => {
    it('knows a bundle, a web address and a link; anything else is unknown', () => {
        expect(classifyPaste(BUNDLE_TEXT)).toBe('sbp-b64');
        expect(classifyPaste('https://example.org/sub')).toBe('http');
        expect(classifyPaste('vless://abc@host:443')).toBe('uri');
        expect(classifyPaste('hello')).toBe('unknown');
        expect(classifyPaste('  ')).toBe('empty');
    });
});
