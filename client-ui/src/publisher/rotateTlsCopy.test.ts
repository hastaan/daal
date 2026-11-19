// What the app tells an operator after a disguise change (rotate-tls).
//
// It used to say, whatever the relay: "every file you have handed out
// is dead — rebuild each and deliver it by hand". Measured on a relay
// with all seven families, six kept connecting untouched (the cover
// host is on the wire for one route only), and the seventh heals by
// itself on a phone whose file carries refresh addresses. An operator
// told to hand-deliver files during a blackout to people who are not
// cut off is being lied to at the worst moment — rig finding LC-O1.
//
// The backend (`relay_rotation::NeedsFile`) decides which of five
// things is true. This holds the COPY to it, in both languages.
import { describe, expect, it } from 'vitest';
import enCatalog from '../i18n/d2/d2-extra.en.json';
import faCatalog from '../i18n/d2/d2-extra.fa.json';

import type { RotateTlsNeedsFile } from './wizardCommands';

const en = enCatalog as Record<string, string>;
const fa = faCatalog as Record<string, string>;

// Every value of the union, spelled out: a verdict added on the Rust
// side without copy here would render as a raw key.
const VERDICTS: Record<RotateTlsNeedsFile, true> = {
    nobody: true,
    nobody_heals_itself: true,
    nobody_heals_itself_offline_meanwhile: true,
    one_route_until_new_file: true,
    everyone: true,
};
const key = (v: string) => `pub.danger.rotate_tls.done.verdict.${v}`;

describe('rotate-tls result copy', () => {
    it('has a sentence for every verdict, in English and Persian', () => {
        for (const v of Object.keys(VERDICTS)) {
            expect(en[key(v)], `en ${v}`).toBeTruthy();
            expect(fa[key(v)], `fa ${v}`).toBeTruthy();
        }
    });

    it('says "everyone needs a new file" in exactly one case', () => {
        for (const v of Object.keys(VERDICTS)) {
            const everyone = /everyone needs a new file/i.test(en[key(v)]);
            const hameh = fa[key(v)].includes('همه فایل تازه لازم دارند');
            expect(everyone, `en ${v}`).toBe(v === 'everyone');
            expect(hameh, `fa ${v}`).toBe(v === 'everyone');
        }
    });

    it('no longer tells the operator that every file is dead', () => {
        const stale = [
            'pub.danger.rotate_tls.done.next',
            'pub.danger.rotate_tls.done.next_fresh',
        ];
        for (const k of stale) {
            expect(en[k], k).toBeUndefined();
            expect(fa[k], k).toBeUndefined();
        }
        for (const [k, v] of Object.entries(en)) {
            if (!k.startsWith('pub.danger.rotate_tls.')) continue;
            expect(v, k).not.toMatch(/every (connection )?file you have handed out (stops working|is dead)/i);
            expect(v, k).not.toMatch(/everything you have handed out is dead/i);
        }
        for (const [k, v] of Object.entries(fa)) {
            if (!k.startsWith('pub.danger.rotate_tls.')) continue;
            expect(v, k).not.toContain('از کار افتاده‌اند');
            expect(v, k).not.toContain('همان لحظه از کار می‌افتند');
        }
    });

    it('names the step that stays the operator\'s when a note went out', () => {
        expect(en['pub.danger.rotate_tls.done.upload']).toMatch(/download address/i);
        expect(fa['pub.danger.rotate_tls.done.upload']).toContain('آدرس دانلود');
        for (const why of ['no_refresh_address', 'note_not_published', 'not_signed']) {
            expect(en[`pub.danger.rotate_tls.done.why.${why}`], why).toBeTruthy();
            expect(fa[`pub.danger.rotate_tls.done.why.${why}`], why).toBeTruthy();
        }
    });
});
