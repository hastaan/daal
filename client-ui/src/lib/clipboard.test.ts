// The one Paste / Copy (clipboard.ts): the phone's own clipboard first,
// because the Android web view refuses the page's (owner, Samsung,
// Android 16: every Paste said "Couldn't read what you copied"), then the
// page's, then '' / a throw that does not carry the text.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type Handler = (args: Record<string, unknown> | undefined) => unknown;
let handlers: Record<string, Handler> = {};
const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        const h = handlers[cmd];
        if (!h) throw `E_NOT_BUILT: ${cmd} is not mocked`;
        return h(args);
    },
}));

const { readClipboardText, writeClipboardText } = await import('./clipboard');
import clipboardSource from './clipboard.ts?raw';

let page: { readText?: () => Promise<string>; writeText?: (s: string) => Promise<void> } | undefined;
const pageWrites: string[] = [];

beforeEach(() => {
    handlers = {};
    calls.length = 0;
    pageWrites.length = 0;
    page = undefined;
    vi.stubGlobal('navigator', {
        get clipboard() {
            return page;
        },
    });
});
afterEach(() => {
    vi.unstubAllGlobals();
});

const refuses = () => Promise.reject(new DOMException('Read permission denied.', 'NotAllowedError'));

describe('readClipboardText', () => {
    it("the phone's clipboard first: the page's is not even asked", async () => {
        handlers.platform_clipboard_read = () => 'cf-key-from-the-phone';
        page = { readText: async () => 'never' };
        expect(await readClipboardText()).toBe('cf-key-from-the-phone');
        expect(calls.map((c) => c.cmd)).toEqual(['platform_clipboard_read']);
    });

    it("the page's own when the shell has none (desktop says null, a browser throws)", async () => {
        page = { readText: async () => 'from the page' };
        handlers.platform_clipboard_read = () => null;
        expect(await readClipboardText()).toBe('from the page');
        delete handlers.platform_clipboard_read;
        expect(await readClipboardText()).toBe('from the page');
    });

    it("'' when neither can: the Android web view refuses, or there is no clipboard at all", async () => {
        handlers.platform_clipboard_read = () => '';
        page = { readText: refuses };
        expect(await readClipboardText()).toBe('');
        page = undefined;
        delete handlers.platform_clipboard_read;
        expect(await readClipboardText()).toBe('');
        handlers.platform_clipboard_read = () => {
            throw 'clipboardRead failed';
        };
        expect(await readClipboardText()).toBe('');
    });
});

describe('writeClipboardText', () => {
    it('the phone writes it; the page is not asked', async () => {
        handlers.platform_clipboard_write = () => true;
        page = { writeText: async (s) => void pageWrites.push(s) };
        await writeClipboardText('daal1-address');
        expect(calls).toEqual([{ cmd: 'platform_clipboard_write', args: { text: 'daal1-address' } }]);
        expect(pageWrites).toEqual([]);
    });

    it("the page's own when the shell has none (desktop says false, a browser throws)", async () => {
        page = { writeText: async (s) => void pageWrites.push(s) };
        handlers.platform_clipboard_write = () => false;
        await writeClipboardText('one');
        delete handlers.platform_clipboard_write;
        await writeClipboardText('two');
        expect(pageWrites).toEqual(['one', 'two']);
    });

    it('throws when neither could, and the error does not carry what was copied', async () => {
        page = { writeText: () => Promise.reject(new Error('Document is not focused.')) };
        const secret = 'cfut_SECRET_do_not_leak';
        const e = await writeClipboardText(secret).then(
            () => null,
            (x: unknown) => x,
        );
        expect(e).toBeInstanceOf(Error);
        expect(String((e as Error).message)).not.toContain(secret);
    });
});

describe('the helper', () => {
    it('never logs what is on the clipboard', () => {
        expect(clipboardSource).not.toMatch(/console\./);
    });

    it('is the only way the app touches the clipboard', () => {
        const sources = import.meta.glob(['../**/*.ts', '../**/*.tsx', '!../**/*.test.ts', '!../**/*.test.tsx', '!../harness/**'], {
            query: '?raw',
            import: 'default',
            eager: true,
        }) as Record<string, string>;
        // The glob really reaches the app (the Paste buttons among it).
        expect(Object.keys(sources)).toContain('../publisher/addons/AccountSheets.tsx');
        expect(Object.keys(sources).length).toBeGreaterThan(100);
        const direct = Object.entries(sources)
            .filter(([path, src]) => path !== './clipboard.ts' && /navigator\.clipboard/.test(src))
            .map(([path]) => path);
        expect(direct).toEqual([]);
    });
});
