// The relay page, as the owner asked for it after one real session:
// each section does one job under a plain name, one short sentence is
// visible per section, no two buttons differ only by a noun nobody
// explained, and the internal build artefact is not in the list of
// files to hand out.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import freshSource from './FreshnessPanel.tsx?raw';
import peopleSource from './PeopleSection.tsx?raw';
import everyoneSource from './EveryoneFileSection.tsx?raw';
import listSource from './RelayListPage.tsx?raw';
import actionSource from './useAction.tsx?raw';
import { EveryoneFileSection } from './EveryoneFileSection';
import { PeopleSection, joinPeople, personState } from './PeopleSection';
import type { ArtifactInfo, RecipientSummary } from './wizardCommands';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? `MISSING:${k}`;
const idle = { busy: null, outcome: null };

function person(id: number, over: Partial<RecipientSummary> = {}): RecipientSummary {
    return {
        id,
        name: `r${id}`,
        display_name: `Person ${id}`,
        address_str: `daal1qqqqqqqqqqqqqqqqqqqq${id}`,
        provisioned_at_unix: 1_763_500_000,
        revoked_at_unix: 0,
        ...over,
    } as RecipientSummary;
}
function file(id: number | null, over: Partial<ArtifactInfo> = {}): ArtifactInfo {
    return {
        kind: 'sbpx',
        path: `/stage/${id}.sbpx`,
        exists: true,
        size_bytes: 900,
        modified_at_unix: 1_763_500_000,
        recipient_id: id,
        recipient_label: id == null ? '' : `Person ${id}`,
        ...over,
    };
}
const noop = () => {};

const SOURCES = [pageSource, freshSource, peopleSource, everyoneSource, listSource, actionSource];

describe('relay page copy', () => {
    it('every string the restructured screens use exists in English and Persian', () => {
        const keys = new Set<string>();
        for (const src of SOURCES) {
            for (const m of src.matchAll(/t\(\s*'((?:pub|common)\.[A-Za-z0-9_.]+)'/g)) keys.add(m[1]);
        }
        expect(keys.size).toBeGreaterThan(80);
        for (const k of keys) {
            // The base catalog (not d2-extra) carries a few common.* keys.
            if (k.startsWith('common.') && !(k in EN)) continue;
            expect(EN[k], `en ${k}`).toBeTruthy();
            expect(FA[k], `fa ${k}`).toBeTruthy();
            expect(FA[k], `fa ${k} is still English`).not.toBe(EN[k]);
        }
    });

    it('the four sections have plain names, in order', () => {
        const order = [
            '<PeopleSection',
            '<EveryoneFileSection',
            '<FreshnessPanel',
            "title={t('pub.danger.title')}",
            "title={t('pub.details.title')}",
        ].map((m) => pageSource.indexOf(m));
        expect(order.every((i) => i > 0)).toBe(true);
        expect([...order].sort((a, b) => a - b)).toEqual(order);
        expect(EN['pub.people.title']).toBe('People');
        expect(EN['pub.everyone.title']).toBe('One file for everyone');
        expect(EN['pub.keep.title']).toBe('Keep it working');
        expect(EN['pub.danger.title']).toBe('Danger zone');
    });

    it('at most one short sentence is visible per section', () => {
        const visible = [
            'pub.people.line',
            'pub.everyone.line',
            'pub.keep.summary.can',
            'pub.keep.summary.cannot',
            'pub.danger.line',
            'pub.details.line',
        ];
        for (const k of visible) {
            for (const [lang, cat] of [['en', EN], ['fa', FA]] as const) {
                const s = cat[k];
                expect(s.length, `${lang} ${k} length`).toBeLessThanOrEqual(110);
                // One sentence: at most one full stop, and only at the end.
                const stops = [...s.matchAll(/[.!?؟](\s|$)/g)];
                expect(stops.length, `${lang} ${k}`).toBeLessThanOrEqual(1);
            }
        }
    });

    it('the summary says whether people\'s apps can repair themselves', () => {
        expect(EN['pub.keep.summary.can']).toBe("People's apps can repair themselves.");
        expect(EN['pub.keep.summary.cannot']).toBe("People's apps can not repair themselves yet.");
        // Closed until tapped.
        expect(freshSource.includes('useState(false)')).toBe(true);
        expect(freshSource.includes('<Collapsible')).toBe(true);
    });

    it('no two "add" buttons differ only by an unexplained noun', () => {
        // The owner could not tell "+ Add" from "+ Add address".
        expect(pageSource.includes("'pub.recipients.add'")).toBe(false);
        expect(freshSource.includes("'pub.fresh.add.action'")).toBe(false);
        expect(EN['pub.people.add']).toBe('Add a person');
        expect(EN['pub.fresh.add.title']).toBe('Add a refresh address');
        // …and the second one sits in a section that explains the noun.
        expect(EN['pub.keep.what']).toMatch(/refresh address/);
        expect(EN['pub.fresh.none.body']).toMatch(/^A refresh address is/);
        expect(freshSource.includes("t('pub.keep.what')")).toBe(true);
    });

    it('the internal signed bundle is under Details, not among the files to hand out', () => {
        expect(pageSource.includes('pub.artifacts.raw')).toBe(false);
        const details = pageSource.indexOf("title={t('pub.details.title')}");
        const raw = pageSource.indexOf('rawArtifact?.exists');
        expect(raw).toBeGreaterThan(details);
        expect(peopleSource.includes('raw')).toBe(false);
        expect(everyoneSource.includes('raw')).toBe(false);
    });

    it('nothing on these screens ends in a silent catch or a grey notice', () => {
        for (const src of [pageSource, freshSource, listSource]) {
            expect(src.includes('setNotice')).toBe(false);
            expect(/set\w*Err(or)?\(String\(e\)\)/.test(src)).toBe(false);
        }
        expect(pageSource.includes('<ActionToast')).toBe(true);
        expect(listSource.includes('<ActionToast')).toBe(true);
    });

    it('every command the page could call before is still called', () => {
        const all = pageSource + freshSource;
        for (const cmd of [
            'shareInvite(', 'shareInviteSbpx(', 'saveSharedSbpToDownloads(', 'saveSbpxToDownloads(',
            'copyPasteable(', 'produceSharedSbp(', 'recipientProvision(', 'recipientRepackSbpx(',
            'recipientRevoke(', 'recipientDelete(', 'recipientList(', 'recipientListRemote(',
            'rotateCredentials(', 'rotateTls(', 'saveRecoveryKey(', 'setOperatorNickname(',
            'listArtifacts(', 'listOperators(', 'freshnessStatus(', 'setFreshnessPackUrl(',
            'publishFreshness(', 'deleteFreshnessEndpoint(', 'addFreshnessEndpoint(',
        ]) {
            expect(all.includes(`Wizard.${cmd}`), cmd).toBe(true);
        }
        for (const part of ['<RotationAdvice', '<AddressSwap', '<RelayRebuild', '<RelayGonePanel', '<QrSendSheet', '<RelayDestroySheet']) {
            expect(pageSource.includes(part), part).toBe(true);
        }
    });
});

describe('joinPeople', () => {
    it('makes one row per person, with their own file on it', () => {
        const rows = joinPeople([person(1), person(2)], [
            { ...file(null), kind: 'shared_sbp', path: '/stage/1.shared.sbp' },
            file(2),
            file(1),
        ]);
        expect(rows.map((r) => [r.label, r.file?.path])).toEqual([
            ['Person 1', '/stage/1.sbpx'],
            ['Person 2', '/stage/2.sbpx'],
        ]);
    });

    it('keeps a file reachable when its roster row is gone, and drops a ghost', () => {
        const rows = joinPeople([person(1)], [file(1), file(9), file(8, { exists: false })]);
        expect(rows.map((r) => r.key)).toEqual(['p1', 'f/stage/9.sbpx']);
        expect(rows[1].recipient).toBeNull();
    });

    it('says where each person stands', () => {
        const [ok, missing, removed] = joinPeople(
            [person(1), person(2), person(3, { revoked_at_unix: 5 })],
            [file(1), file(2, { exists: false }), file(3, { exists: false })],
        );
        expect(personState(t, ok)).toMatch(/^Has a file · added 20\d\d-/);
        expect(personState(t, missing)).toBe(EN['pub.people.state.no_file']);
        expect(personState(t, removed)).toBe(EN['pub.people.state.removed']);
    });
});

describe('PeopleSection', () => {
    const render = (people: ReturnType<typeof joinPeople>, busy: string | null = null) =>
        renderToStaticMarkup(
            <PeopleSection
                t={t}
                action={{ busy, outcome: null }}
                loading={false}
                people={people}
                onAdd={noop}
                onSend={noop}
                onSave={noop}
                onRemake={noop}
                onReplace={noop}
                onRemoveAccess={noop}
                onRemoveFromList={noop}
            />,
        );
    const count = (html: string, s: string) => html.split(s).length - 1;

    it('has one primary action and one sentence', () => {
        const html = render([]);
        expect(html).not.toContain('MISSING:');
        expect(count(html, '>Add a person<')).toBe(1);
        expect(html).toContain(EN['pub.people.line']);
        expect(html).toContain(EN['pub.people.empty']);
    });

    it('puts the file actions and Remove access on the person\'s own row', () => {
        const html = render(joinPeople([person(1)], [file(1)]));
        expect(html).not.toContain('MISSING:');
        for (const label of ['Send file', 'Save file', 'Remove access']) {
            expect(count(html, `>${label}<`), label).toBe(1);
        }
        // Replacing their file is there, but behind a question.
        expect(html).toContain('<details>');
        expect(html).toContain(EN['pub.people.more']);
        expect(html).toContain('Replace their file');
        expect(html).not.toContain('Make their file again');
    });

    it('offers to make a missing file again, and never to a person whose access was removed', () => {
        const missing = render(joinPeople([person(1)], [file(1, { exists: false })]));
        expect(missing).toContain('Make their file again');
        expect(missing).toContain('Remove access');
        expect(missing).not.toContain('Send file');
        const removed = render(
            joinPeople([person(1, { revoked_at_unix: 9 })], [file(1, { exists: false })]),
        );
        expect(removed).toContain('Remove from list');
        // Re-making would hand a working file back to someone cut off.
        expect(removed).not.toContain('Make their file again');
        expect(removed).not.toContain('Send file');
        expect(removed).not.toContain('>Remove access<');
    });

    it('shows progress on the button that was pressed and locks the rest', () => {
        const html = render(joinPeople([person(1)], [file(1)]), 'save:/stage/1.sbpx');
        expect(html).toContain('Saving…');
        expect(html).not.toContain('>Save file<');
        expect(count(html, 'disabled=""')).toBe(4); // send, save, remove access, replace
    });

    it('uses no physical left/right, so it lays out right-to-left', () => {
        for (const src of [peopleSource, everyoneSource]) {
            expect(/(margin|padding|border)(Left|Right)|textAlign: '(left|right)'|\b(left|right):/.test(src)).toBe(false);
        }
    });
});

describe('EveryoneFileSection', () => {
    const render = (f: ArtifactInfo | null) =>
        renderToStaticMarkup(
            <EveryoneFileSection
                t={t}
                action={idle}
                file={f}
                onSend={noop}
                onSave={noop}
                onQr={noop}
                onCopy={noop}
                onMake={noop}
                onReplace={noop}
            />,
        );
    const shared = (exists: boolean): ArtifactInfo => ({
        ...file(null, { exists }),
        kind: 'shared_sbp',
        path: '/stage/1.shared.sbp',
    });

    it('says in one line when to use it instead of a person\'s file', () => {
        const html = render(shared(true));
        expect(html).not.toContain('MISSING:');
        expect(html).toContain('One file for everyone');
        expect(html).toContain(EN['pub.everyone.line']);
        for (const label of ['Send file', 'Save file', 'Show as QR', 'Copy as text', 'Replace this file']) {
            expect(html, label).toContain(`>${label}<`);
        }
        expect(html).toContain('What is this?');
    });

    it('offers to make it when it is missing, and not to replace what is not there', () => {
        const html = render(shared(false));
        expect(html).toContain('Make the file');
        expect(html).toContain(EN['pub.everyone.none']);
        expect(html).not.toContain('Send file');
        expect(html).not.toContain('Replace this file');
    });
});

describe('the page as it first appears', () => {
    // Static render = the page before anything is tapped: closed
    // sections closed, no sheet open. (Effects do not run, so no
    // command is called.)
    const render = async (cat: Record<string, string>) => {
        const { default: Page } = await import('./PublisherRecipientsPage');
        const { DensityProvider } = await import('../design/DensityProvider');
        return renderToStaticMarkup(
            <DensityProvider>
                <Page t={(k) => cat[k] ?? EN[k] ?? `MISSING:${k}`} operatorId={7} onBack={noop} />
            </DensityProvider>,
        );
    };

    it.each([
        ['en', EN],
        ['fa', FA],
    ] as const)('%s: four named sections in order, one sentence each, nothing from behind a tap', async (_l, cat) => {
        const html = await render(cat);
        expect(html).not.toContain('MISSING:');
        const at = ['pub.people.title', 'pub.everyone.title', 'pub.keep.title', 'pub.danger.title', 'pub.details.title'].map(
            (k) => html.indexOf(`>${cat[k]}<`),
        );
        expect(at.every((i) => i > 0)).toBe(true);
        expect([...at].sort((a, b) => a - b)).toEqual(at);
        for (const k of ['pub.people.line', 'pub.everyone.line', 'pub.danger.line', 'pub.details.line']) {
            expect(html, k).toContain(cat[k].replace(/'/g, '&#x27;'));
        }
        // Closed sections show their one line and none of their rows.
        for (const k of [
            'pub.danger.recovery.body',
            'pub.danger.rotate_tls.body',
            'pub.danger.decommission.body',
            'pub.fresh.pack_url.body',
            'pub.fresh.privacy.body',
            'pub.details.signed_file',
            'pub.details.compare',
        ]) {
            expect(html.includes(cat[k].slice(0, 40).replace(/'/g, '&#x27;')), k).toBe(false);
        }
        expect((html.match(/aria-expanded="false"/g) ?? []).length).toBe(3);
        // The only "add" on the default page adds a person.
        expect(html).toContain(`>${cat['pub.people.add']}<`);
        expect(html.includes(cat['pub.fresh.add.title'])).toBe(false);
    });
});

// Repair pass: the result sheets and the opened "Keep it working"
// section still spoke the old page's language — "the everyone pack",
// "Rebuild", "the list above", "this computer" — none of which is on
// the reorganised page.
describe('what the sheets tell the publisher to press exists on the page', () => {
    const AFTER_A_REBUILD = [
        'pub.danger.rebuild.done.by_hand',
        'pub.danger.rebuild.done.by_hand_fresh',
        'pub.danger.address.done.no_self_heal',
    ];
    it('names the buttons by the words on them, in both languages', () => {
        for (const cat of [EN, FA]) {
            for (const k of AFTER_A_REBUILD) {
                expect(cat[k], k).toContain(cat['pub.everyone.replace']);
                expect(cat[k], k).toContain(cat['pub.people.replace']);
                expect(cat[k], k).toContain(cat['pub.everyone.title']);
            }
            expect(cat['pub.danger.rebuild.done.by_hand']).toContain(cat['pub.people.more']);
            for (const k of ['pub.danger.rebuild.done.by_hand_fresh', 'pub.danger.rebuild.confirm.by_hand_fresh']) {
                expect(cat[k], k).toContain(cat['pub.keep.title']);
                expect(cat[k], k).toContain(`“${cat['pub.fresh.publish.action']}”`.replace(/“|”/g, (q) => (cat === FA ? (q === '“' ? '«' : '»') : q)));
            }
            expect(cat['qr.send.error.body']).toContain(cat['pub.everyone.make']);
        }
    });
    it('no string still says "everyone pack", "rebuild" a file, or "this computer"', () => {
        for (const [k, v] of Object.entries(EN)) {
            if (!/^(pub\.|qr\.send\.)/.test(k)) continue;
            expect(v, k).not.toMatch(/everyone pack/i);
        }
        for (const k of [...AFTER_A_REBUILD, 'pub.danger.rotate_tls.done.local_files', 'pub.danger.rebuild.confirm.by_hand', 'pub.danger.address.confirm.no_self_heal']) {
            expect(EN[k], k).not.toMatch(/\brebuild\b/i);
            expect(EN[k], k).not.toMatch(/list above|this computer|on this screen/i);
        }
        for (const [k, v] of Object.entries(FA)) {
            if (!/^(pub\.|qr\.send\.)/.test(k)) continue;
            expect(v, k).not.toContain('بستهٔ همگانی');
        }
        expect(FA['pub.danger.rotate_tls.done.local_files']).not.toContain('رایانه');
    });
    it('the closed section\'s pill says what it is about', () => {
        expect(EN['pub.fresh.pill.healing']).toBe('Repairs itself');
        expect(EN['pub.fresh.pill.manual']).toBe('Needs new files');
        expect(FA['pub.fresh.pill.healing']).not.toBe('خودترمیم');
        expect(FA['pub.fresh.pill.manual']).not.toBe('دستی');
    });
    it('"Keep it working" says each thing once and keeps the long explanation behind a tap', () => {
        // What a refresh address IS: once, behind "What is this?".
        expect(freshSource.match(/t\('pub\.fresh\.none\.body'\)/g)).toHaveLength(1);
        expect(freshSource).toContain("t('pub.fresh.none.short')");
        // The download address: one sentence; the rest behind its own question.
        for (const cat of [EN, FA]) {
            expect((cat['pub.fresh.pack_url.body'].match(/[.؟!]/g) ?? []).length).toBeLessThanOrEqual(2);
            expect(cat['pub.fresh.pack_url.what.label']).toBeTruthy();
            expect(cat['pub.fresh.pack_url.what']).toBeTruthy();
            expect(cat['pub.fresh.none.short']).toBeTruthy();
        }
        expect(freshSource).toMatch(/<WhatIsThis label=\{t\('pub\.fresh\.pack_url\.what\.label'\)\}>/);
        // The sentence about what went wrong is in both languages.
        expect(EN['pub.danger.rotate_tls.done.sign_failed.next']).toContain('The message below says what went wrong.');
        expect(FA['pub.danger.rotate_tls.done.sign_failed.next']).toContain('پیام پایین می‌گوید');
    });
});
