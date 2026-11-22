// clipboard.ts — Paste and Copy, the one way every button does them.
//
// The Android web view refuses `navigator.clipboard.readText()` outright
// (there is no permission prompt to grant it), so every Paste button
// said "Couldn't read what you copied" on the phone (owner, Samsung,
// Android 16, 2026-11-22). And `writeText()` needs a fresh tap, which a
// Copy that first waits for the app (a file as text, a script, a report)
// no longer has. So both go to the phone first (the daal-platform
// plugin's `clipboardRead` / `clipboardWrite`, through the shell's
// `platform_clipboard_read` / `platform_clipboard_write`), and to the
// page's own clipboard where the shell has none of its own: the desktop
// answers `null` / `false`, a browser or an older shell throws.
//
// What is on the clipboard may be a key or a script with one in it:
// nothing here logs it, and no error message carries it.

import { invoke } from '@tauri-apps/api/core';

/** The clipboard's text, '' when nothing could be read (or there is
 *  nothing). Never throws: the caller shows its own "paste it into the
 *  field" line on ''. */
export async function readClipboardText(): Promise<string> {
    try {
        const native = await invoke<string | null>('platform_clipboard_read');
        if (typeof native === 'string' && native.trim() !== '') return native;
    } catch {
        /* not the app, or a shell without it: the page's own */
    }
    try {
        const text = await navigator.clipboard?.readText?.();
        if (typeof text === 'string') return text;
    } catch {
        /* the web view would not read it */
    }
    return '';
}

/** Put `text` on the clipboard. Throws when neither the phone nor the
 *  page could (as `navigator.clipboard.writeText` does), with a message
 *  that does not carry the text. */
export async function writeClipboardText(text: string): Promise<void> {
    try {
        if ((await invoke<boolean>('platform_clipboard_write', { text })) === true) return;
    } catch {
        /* not the app, or a shell without it: the page's own */
    }
    try {
        await navigator.clipboard.writeText(text);
        return;
    } catch {
        /* nothing more to try */
    }
    throw new Error('the clipboard could not be written');
}
