// After a disguise change the app must not say "nobody needs a new
// file" when signing the relay's file again failed.
//
// The backend computes `needs_file` from what the signed file commits
// to. When the re-sign fails it can be left with nothing to read and
// fall through to `nobody` (relay_rotation.rs: `None => (false, false)`
// → `who_needs_a_file` returns Nobody). The screen then printed the
// `nobody` sentence above a warning that signing had failed.
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import { resignFailed, rotateTlsVerdict } from './rotateTlsVerdict';
import type { RotateTlsNeedsFile } from './wizardCommands';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;

const base = {
    needs_file: 'nobody' as RotateTlsNeedsFile,
    pack_resigned: true,
    refresh_note_published: false,
    live_recipients: 3,
    shared_pack_stale: false,
    warnings: [] as string[],
};
const SIGN_WARNING =
    "the disguise was changed, but signing the relay's file again failed, so nothing was published: relay unreachable";

describe('rotateTlsVerdict', () => {
    it('re-sign failed + backend says nobody → says what happened and what to do, never "nobody"', () => {
        const v = rotateTlsVerdict(
            { ...base, pack_resigned: false, warnings: [SIGN_WARNING] },
            2,
        );
        expect(v.verdictKey).toBe('pub.danger.rotate_tls.done.verdict.sign_failed');
        expect(v.alarming).toBe(true);
        expect(v.nextKey).toBe('pub.danger.rotate_tls.done.sign_failed.next');
        expect(v.showUpload).toBe(false);
        for (const cat of [EN, FA]) {
            expect(cat[v.verdictKey]).toBeTruthy();
            expect(cat[v.nextKey!]).toBeTruthy();
        }
        expect(EN[v.verdictKey]).not.toMatch(/nobody needs a new file/i);
        expect(EN[v.verdictKey]).toMatch(/could not sign/i);
        expect(FA[v.verdictKey]).not.toContain('هیچ‌کس فایل تازه لازم ندارد');
        expect(EN[v.nextKey!]).toMatch(/what to do/i);
    });

    it('detects the failure from who holds a file, without relying on the wording of a warning', () => {
        expect(resignFailed({ ...base, pack_resigned: false, live_recipients: 1 })).toBe(true);
        expect(
            resignFailed({ ...base, pack_resigned: false, live_recipients: 0, shared_pack_stale: true }),
        ).toBe(true);
        // …and from the backend's own words when nobody holds one yet.
        expect(
            resignFailed({ ...base, pack_resigned: false, live_recipients: 0, warnings: [SIGN_WARNING] }),
        ).toBe(true);
    });

    it('nobody stays nobody when the file WAS signed again', () => {
        const v = rotateTlsVerdict(base, 2);
        expect(v.verdictKey).toBe('pub.danger.rotate_tls.done.verdict.nobody');
        expect(v.alarming).toBe(false);
        expect(v.nextKey).toBeNull();
    });

    it('nobody stays nobody when there was nothing to sign', () => {
        // A relay nobody holds a file from: no re-sign is attempted, no
        // warning is raised, and "nobody" is simply true.
        const s = { ...base, pack_resigned: false, live_recipients: 0 };
        expect(resignFailed(s)).toBe(false);
        expect(rotateTlsVerdict(s, 0).verdictKey).toBe('pub.danger.rotate_tls.done.verdict.nobody');
        // An unrelated warning does not turn it into a signing failure.
        expect(resignFailed({ ...s, warnings: ['the relay did not echo the host'] })).toBe(false);
    });

    it('a failed re-sign with a real verdict keeps the verdict and adds why and what to do', () => {
        for (const needs of ['one_route_until_new_file', 'everyone'] as const) {
            const v = rotateTlsVerdict({ ...base, needs_file: needs, pack_resigned: false }, 2);
            expect(v.verdictKey).toBe(`pub.danger.rotate_tls.done.verdict.${needs}`);
            expect(v.whyKey).toBe('pub.danger.rotate_tls.done.why.not_signed');
            expect(v.nextKey).toBe('pub.danger.rotate_tls.done.sign_failed.next');
            expect(v.alarming).toBe(needs === 'everyone');
        }
    });

    it('keeps the existing reasons when signing worked', () => {
        const s = { ...base, needs_file: 'one_route_until_new_file' as const };
        expect(rotateTlsVerdict(s, 2).whyKey).toBe('pub.danger.rotate_tls.done.why.note_not_published');
        expect(rotateTlsVerdict(s, 0).whyKey).toBe('pub.danger.rotate_tls.done.why.no_refresh_address');
        expect(rotateTlsVerdict({ ...s, refresh_note_published: true }, 2).whyKey).toBe(
            'pub.danger.rotate_tls.done.why.no_refresh_address',
        );
        const healed = rotateTlsVerdict(
            { ...base, needs_file: 'nobody_heals_itself', refresh_note_published: true },
            2,
        );
        expect(healed).toMatchObject({ whyKey: null, nextKey: null, showUpload: true, alarming: false });
    });

    it('the result sheet takes its headline from here and nowhere else', () => {
        expect(pageSource.includes('rotateTlsVerdict(rotateTlsDone, mirrorsInPack)')).toBe(true);
        expect(pageSource.includes('t(tlsVerdict.verdictKey)')).toBe(true);
        expect(/done\.verdict\.\$\{rotateTlsDone\.needs_file\}/.test(pageSource)).toBe(false);
    });
});
