// Backlog PH-27: for a sealed file the add sheet said both "enter the
// PIN you created with your Daal address" and "It will open
// automatically using your device's key". Exactly one line now, chosen
// by what device custody says. Rendered to static markup — no DOM.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import PickedFileNote, { pickedFileNoteKey, sealedCustody } from './PickedFileNote';
import legacyEn from '../i18n/en.json';
import legacyFa from '../i18n/fa.json';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

// The app's own merge order (lib/i18n.ts): d2-extra over legacy.
const dict = (a: unknown, b: unknown) => ({ ...(a as object), ...(b as object) }) as Record<string, string>;
const EN = dict(legacyEn, en);
const FA = dict(legacyFa, fa);
const tr = (d: Record<string, string>) => (k: string) => d[k] ?? k;
const text = (html: string) => html.replace(/<[^>]+>/g, '').replace(/&#x27;/g, "'");

describe('sealedCustody: how the sheet knows', () => {
    it("reads DeviceCustody.isUnlocked's answer; a failed call is 'unknown', never a guess", () => {
        expect(sealedCustody(true)).toBe('ready');
        expect(sealedCustody(false)).toBe('locked');
        expect(sealedCustody(undefined)).toBe('unknown');
    });
});

describe('PickedFileNote', () => {
    it('sealed + this phone can open it: ONLY "opens by itself" — no PIN anywhere', () => {
        const s = text(renderToStaticMarkup(<PickedFileNote t={tr(EN)} sealed custody="ready" />));
        expect(s).toBe("This file is sealed for this phone. Daal opens it by itself, with this phone's own key.");
        expect(s).not.toMatch(/PIN|passphrase|enter/i);
    });
    it('sealed + Daal locked: ONLY "unlock first" — no promise that it opens by itself', () => {
        const s = text(renderToStaticMarkup(<PickedFileNote t={tr(EN)} sealed custody="locked" />));
        expect(s).toContain('Daal is locked right now');
        expect(s).toContain('Unlock Daal first');
        expect(s).not.toMatch(/by itself|automatically/i);
    });
    it('sealed + custody could not be asked: says it is sealed and promises nothing', () => {
        const s = text(renderToStaticMarkup(<PickedFileNote t={tr(EN)} sealed custody="unknown" />));
        expect(s).toBe('This file is sealed for this phone.');
    });
    it('a plain file says only that it was chosen', () => {
        const s = text(renderToStaticMarkup(<PickedFileNote t={tr(EN)} sealed={false} custody="ready" />));
        expect(s).toBe(EN['add.file.picked']);
        expect(s).not.toMatch(/sealed/i);
    });
    it('one line, never two, in every state', () => {
        for (const sealed of [true, false]) {
            for (const custody of ['ready', 'locked', 'unknown'] as const) {
                const html = renderToStaticMarkup(<PickedFileNote t={tr(EN)} sealed={sealed} custody={custody} />);
                expect(html.match(/<div/g)).toHaveLength(1);
            }
        }
    });
    it('has Persian for each line, with no file-type or protocol word', () => {
        for (const custody of ['ready', 'locked', 'unknown'] as const) {
            const key = pickedFileNoteKey(true, custody);
            expect(FA[key]).toMatch(/[؀-ۿ]/);
            expect(FA[key]).not.toMatch(/sbpx?|PIN/i);
            expect(EN[key]).not.toMatch(/sbpx?|PIN/i);
        }
    });
});

describe('the add sheet speaks plainly (PH-27)', () => {
    const PROTOCOL = /vless|vmess|trojan|wg:|\.sbpx?|subscription url|uri\b/i;
    it('the paste box and the file button use plain words', () => {
        expect(EN['add.paste_placeholder']).toBe('Paste what you were sent');
        expect(EN['add.file.choose']).toBe('Choose the file you were sent');
        expect(EN['add.lede.paste']).toBe('Paste what you were sent.');
    });
    it('no protocol list outside the "What can I paste?" disclosure', () => {
        const outside = [
            'add.title', 'add.tab.paste', 'add.tab.file', 'add.paste_placeholder', 'add.lede.paste',
            'add.file.choose', 'add.file.change', 'add.file.picked', 'add.file.preview_routes',
            'add.detect.sbp', 'add.detect.sbpx', 'add.detect.subscription', 'add.detect.uri', 'add.detect.unknown',
            'add.paste_help.title',
        ];
        for (const k of outside) {
            for (const d of [EN, FA]) {
                expect(d[k], k).toBeTruthy();
                expect(d[k], k).not.toMatch(PROTOCOL);
            }
        }
        // ...where the kinds of link ARE listed, for whoever asks.
        expect(EN['add.paste_help.title']).toBe('What can I paste?');
        expect(EN['add.paste_help.body']).toMatch(/vless:\/\//);
        expect(FA['add.paste_help.body']).toMatch(/vless:\/\//);
    });
});
