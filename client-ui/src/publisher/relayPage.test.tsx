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
import { EveryoneFileSheet } from './EveryoneFileSection';
import { DensityProvider } from '../design/DensityProvider';
import { PeopleSection, joinPeople, personState, personStateOf } from './PeopleSection';
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

    it('the relay page is health, People, Details, Danger zone, in that order (C7.2)', () => {
        const order = [
            '<HealthPanel',
            '<PeopleSection',
            "summary={t('pub.details.title')}",
            "summary={t('pub.danger.title')}",
        ].map((m) => pageSource.indexOf(m));
        expect(order.every((i) => i > 0)).toBe(true);
        expect([...order].sort((a, b) => a - b)).toEqual(order);
        // The file for everyone and "Keep files working" are no longer
        // sections of the page (H-23, H-25): they open from the ⋯.
        expect(pageSource.includes('<EveryoneFileSection')).toBe(false);
        expect(pageSource).toContain("label: t('pub.more.everyone')");
        expect(pageSource).toContain("label: t('pub.more.keep')");
        expect(EN['pub.people.title']).toBe('People');
        expect(EN['pub.everyone.title']).toBe('File for everyone');
        expect(EN['pub.keep.title']).toBe('Keep files working');
        expect(EN['pub.danger.title']).toBe('Danger zone');
    });

    it('the lines left visible are short: at most two sentences', () => {
        const visible = [
            'pub.health.hedge',
            'pub.everyone.line',
            'pub.keep.summary.can',
            'pub.keep.summary.cannot',
            'pub.people.empty',
            'pub.keep.failing',
        ];
        for (const k of visible) {
            for (const [lang, cat] of [['en', EN], ['fa', FA]] as const) {
                const s = cat[k];
                expect(s.length, `${lang} ${k} length`).toBeLessThanOrEqual(150);
                const stops = [...s.matchAll(/[.!?؟](\s|$)/g)];
                expect(stops.length, `${lang} ${k}`).toBeLessThanOrEqual(2);
            }
        }
        // MUST KEEP 7: hedged, and the limit named.
        expect(EN['pub.health.hedge']).toMatch(/^As far as this phone can tell\./);
        expect(EN['pub.health.hedge']).toMatch(/can't see blocking inside Iran/);
    });

    it('the summary says whether people\'s apps can repair themselves, and the privacy cost is in view', () => {
        expect(EN['pub.keep.summary.can']).toBe("People's apps can repair themselves.");
        expect(EN['pub.keep.summary.cannot']).toBe("People's apps cannot repair themselves yet.");
        // A sub-page now, not a fold; MUST KEEP 14 visible above the forms.
        expect(freshSource.includes('<Collapsible')).toBe(false);
        expect(freshSource).toContain('data-testid="keep-privacy"');
        // The two facts in view (logs count readers; a stored key can
        // replace the trusted note), the reasoning behind Details.
        expect(freshSource.indexOf("t('pub.fresh.privacy.line')")).toBeLessThan(freshSource.indexOf("t('pub.fresh.pack_url.title')"));
        expect(freshSource.indexOf("t('pub.fresh.privacy.key_line')")).toBeLessThan(freshSource.indexOf("t('pub.fresh.pack_url.title')"));
        expect(EN['pub.fresh.privacy.line']).toMatch(/count your readers and see roughly where they are/);
        expect(freshSource.indexOf("t('pub.fresh.privacy.body')")).toBeLessThan(freshSource.indexOf("t('pub.fresh.pack_url.title')"));
        // No amber "needs new files" pill by default (H-25).
        expect(freshSource.includes('pub.fresh.pill.manual')).toBe(false);
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
        const details = pageSource.indexOf("summary={t('pub.details.title')}");
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
        expect(personState(t, ok)).toBe(EN['pub.people.state.has_file']);
        expect(personStateOf(ok)).toBe('ready');
        expect(personStateOf(missing)).toBe('no_file');
        expect(personStateOf(removed)).toBe('removed');
        expect(personStateOf(ok, true)).toBe('waiting');
        expect(personState(t, missing)).toBe(EN['pub.people.state.no_file']);
        expect(personState(t, removed)).toBe(EN['pub.people.state.removed']);
    });
});

describe('PeopleSection', () => {
    const render = (people: ReturnType<typeof joinPeople>, busy: string | null = null, extra = {}) =>
        renderToStaticMarkup(
            <DensityProvider>
            <PeopleSection
                t={t}
                action={{ busy, outcome: null }}
                loading={false}
                people={people}
                onAdd={noop}
                onSend={noop}
                onRemake={noop}
                onReplace={noop}
                onRemoveAccess={noop}
                onRemoveFromList={noop}
                {...extra}
            />
            </DensityProvider>,
        );
    const count = (html: string, s: string) => html.split(s).length - 1;

    it('with nobody yet, "Add" is the one gold button and the empty line says why', () => {
        const html = render([]);
        expect(html).not.toContain('MISSING:');
        expect(count(html, 'data-button="add-person"')).toBe(1);
        expect(html).toContain(`aria-label="${EN['pub.people.add']}"`);
        expect(html).toContain(EN['pub.people.empty']);
        expect(html).not.toContain(EN['pub.people.line'] ?? 'Each person gets their own file');
    });

    it('one row per person: a badge, ONE send button and a ⋯ — never a row of buttons (H-14)', () => {
        const html = render(joinPeople([person(1)], [file(1)]));
        expect(html).not.toContain('MISSING:');
        expect(count(html, 'data-button="person-send"')).toBe(1);
        expect(count(html, 'data-button="person-more"')).toBe(1);
        expect(html).toContain(`>${EN['pub.people.badge.ready']}<`);
        for (const gone of ['Send file', 'Save file', 'Show as QR code', 'Copy as text', '>Remove access<']) {
            expect(html, gone).not.toContain(gone);
        }
        // The raw address is not on the row (H-20).
        expect(html).not.toContain('daal1qqqq');
        // With someone on the list, "Add" is no longer the gold button.
        expect(html).not.toMatch(/data-button="add-person"[^>]*background:var\(--gold\)/);
    });

    it('offers to make a missing file again, and never to a person whose access was removed', () => {
        const missing = render(joinPeople([person(1)], [file(1, { exists: false })]));
        expect(missing).toContain(`aria-label="${EN['pub.people.remake']}"`);
        expect(missing).toContain(`>${EN['pub.people.badge.no_file']}<`);
        expect(missing).not.toContain('data-button="person-send"');
        const removed = render(joinPeople([person(1, { revoked_at_unix: 9 })], [file(1, { exists: false })]));
        // Removed people are history, folded at the end.
        expect(removed).toContain(EN['pub.people.removed'].replace('{n}', '1'));
        // Re-making would hand a working file back to someone cut off.
        expect(removed).not.toContain(EN['pub.people.remake']);
        expect(removed).not.toContain('data-button="person-send"');
    });

    it('a person waiting for an answer offers no send, and says so', () => {
        const html = render(joinPeople([person(1)], [file(1)]), null, { waiting: new Set([1]) });
        expect(html).toContain(`>${EN['pub.people.badge.needs_answer']}<`);
        expect(html).not.toContain('data-button="person-send"');
    });

    it('while any action runs, the send buttons are locked', () => {
        const html = render(joinPeople([person(1), person(2)], [file(1), file(2)]), 'save:/stage/1.sbpx');
        expect(count(html, 'data-button="person-send" disabled=""')).toBe(2);
    });

    it('the everyone file is one more row, with its own send button', () => {
        const html = render(joinPeople([person(1)], [file(1)]), null, { everyone: { onSend: noop, onAbout: noop } });
        expect(html).toContain('data-testid="everyone-row"');
        expect(html).toContain(EN['pub.everyone.badge']);
        expect(count(html, 'data-button="everyone-send"')).toBe(1);
    });

    it('uses no physical left/right, so it lays out right-to-left', () => {
        for (const src of [peopleSource, everyoneSource]) {
            expect(/(margin|padding|border)(Left|Right)|textAlign: '(left|right)'|\b(left|right):/.test(src)).toBe(false);
        }
    });
});

describe('EveryoneFileSheet', () => {
    const render = (f: ArtifactInfo | null) =>
        renderToStaticMarkup(
            <DensityProvider>
                <EveryoneFileSheet t={t} action={idle} file={f} onSend={noop} onMake={noop} onReplace={noop} onClose={noop} />
            </DensityProvider>,
        );
    const shared = (exists: boolean): ArtifactInfo => ({
        ...file(null, { exists }),
        kind: 'shared_sbp',
        path: '/stage/1.shared.sbp',
    });

    it('says what it costs first (MUST KEEP 9), then Send… and Replace', () => {
        const html = render(shared(true));
        expect(html).not.toContain('MISSING:');
        expect(html).toContain('File for everyone');
        expect(html).toContain(EN['pub.everyone.line'].replace(/'/g, '&#x27;'));
        expect(html).toContain(`>${EN['pub.everyone.send_open']}<`);
        expect(html).toContain(`>${EN['pub.everyone.replace']}<`);
        expect(html).toContain('What is this?');
    });

    it('offers to make it when it is missing, and not to replace what is not there', () => {
        const html = render(shared(false));
        expect(html).toContain('Make the file');
        expect(html).not.toContain(EN['pub.everyone.send_open']);
        expect(html).not.toContain(EN['pub.everyone.replace']);
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
    ] as const)('%s: People, Details, Danger zone in order; nothing from behind a tap', async (_l, cat) => {
        const html = await render(cat);
        expect(html).not.toContain('MISSING:');
        const at = ['pub.people.title', 'pub.details.title', 'pub.danger.title'].map((k) => html.indexOf(`>${cat[k]}<`));
        expect(at.every((i) => i > 0)).toBe(true);
        expect([...at].sort((a, b) => a - b)).toEqual(at);
        // No "One file for everyone" or "Keep it working" section.
        expect(html.includes(cat['pub.everyone.line'].slice(0, 30).replace(/'/g, '&#x27;'))).toBe(false);
        // Closed sections show none of their rows.
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
        expect((html.match(/aria-expanded="false"/g) ?? []).length).toBeGreaterThanOrEqual(2);
        // The only "add" on the default page adds a person.
        expect(html).toContain(`aria-label="${cat['pub.people.add']}"`);
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
            // The person's own ⋯ action, by its words; the old fold is gone.
            expect(cat['pub.danger.rebuild.done.by_hand']).toContain(cat['pub.more.everyone'].replace('…', ''));
            expect(cat['pub.danger.rebuild.done.by_hand']).not.toContain('File lost');
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
    it('the "needs new files" pill is gone from the page by default (H-25)', () => {
        expect(freshSource.includes('pub.fresh.pill')).toBe(false);
        expect(pageSource.includes('pub.fresh.pill')).toBe(false);
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
