// The publisher redesign (spec C7): what a publisher sees, pinned.
//
//  - the send sheet: four ways out, the person's MUST KEEP line, no toast
//    after a share that worked;
//  - a person added with a pasted address that has spaces and a newline;
//  - the app's own confirm sheet in place of window.confirm (H-29);
//  - the QR sheet: no counters unless developer mode; it draws under
//    StrictMode (H-39);
//  - the wizard: no "Coming soon", the token path once, the cost line,
//    and "Add the first person" at the end.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { StrictMode } from 'react';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import uiEn from '../i18n/en.json';
import uiFa from '../i18n/fa.json';
import { byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import wizardSource from './PublisherWizard.tsx?raw';
import qrSource from './QrSendSheet.tsx?raw';

const answer: { fn: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } = {
    fn: () => new Promise(() => {}),
};
const invoked: [string, unknown][] = [];
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: Record<string, unknown>) => {
        invoked.push([cmd, args]);
        return answer.fn(cmd, args);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const UI_EN = uiEn as Record<string, string>;
const UI_FA = uiFa as Record<string, string>;
const t = (k: string) => EN[k] ?? UI_EN[k] ?? k;
const button = (c: FakeNode, name: string) => byAttr(c, 'data-button', name);

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
    invoked.length = 0;
    answer.fn = () => new Promise(() => {});
});

describe('the send sheet (C7.2a)', () => {
    it('four ways out, the share way first and gold, and who can open it', async () => {
        const { SendSheet } = await import('./ui');
        const ways = { share: vi.fn(), qr: vi.fn(), copy: vi.fn(), save: vi.fn() };
        let closed = 0;
        const m = await rig.mount(<SendSheet t={t} name="Maman" ways={ways} onClose={() => (closed += 1)} />);
        for (const id of ['share', 'qr', 'copy', 'save']) expect(button(m.container, id), id).not.toBeNull();
        // MUST KEEP 17.
        expect(m.container.textContent).toContain("Only Maman's phone can open it.");
        expect(m.container.textContent).toContain("Send Maman's file");
        // Close first, then act.
        await rig.click(button(m.container, 'save'));
        expect(closed).toBe(1);
        expect(ways.save).toHaveBeenCalledTimes(1);
    });

    it('for everyone: MUST KEEP 9, short', async () => {
        const { SendSheet } = await import('./ui');
        const ways = { share: vi.fn(), qr: vi.fn(), copy: vi.fn(), save: vi.fn() };
        const m = await rig.mount(<SendSheet t={t} name="" everyone ways={ways} onClose={() => {}} />);
        expect(m.container.textContent).toContain(EN['pub.send.everyone_line']);
        expect(EN['pub.send.everyone_line']).toMatch(/can't cut off one person/);
    });

    it('one label per action for a person and for everyone (H-24); a share that worked gets no toast', () => {
        for (const k of ['pub.send.share', 'pub.send.qr', 'pub.send.copy', 'pub.send.save']) {
            expect(EN[k]).toBeTruthy();
            expect(FA[k]).toBeTruthy();
            expect(FA[k]).not.toBe(EN[k]);
        }
        // Both share commands report only a failure.
        expect(pageSource).toMatch(/shareInvite\(operatorId, friendlyName\),\s*\/\/[^\n]*\n\s*\{ ok: null, fail:/);
        expect(pageSource).toMatch(/shareInviteSbpx\(path, label\),\s*\{ ok: null, fail:/);
    });
});

describe('adding a person (C7.3)', () => {
    it('an address pasted with spaces, capitals or a line break is accepted', async () => {
        const { looksLikeDaalAddress, normalizeDaalAddress } = await import('./PublisherRecipientsPage');
        const pasted = 'DAAL1 qm3n 8v2k\nx7p4 9w0e rt5y';
        expect(normalizeDaalAddress(pasted)).toBe('daal1qm3n8v2kx7p49w0ert5y');
        expect(looksLikeDaalAddress(pasted)).toBe(true);
        expect(looksLikeDaalAddress('hello there')).toBe(false);
        expect(looksLikeDaalAddress('daal1 short')).toBe(false);
    });

    it('the name comes first and is required; the sheet then offers "Send their file"', () => {
        const name = pageSource.indexOf("t('pub.person.add.name')");
        const address = pageSource.indexOf("t('pub.recipients.add.address')");
        expect(name).toBeGreaterThan(0);
        expect(name).toBeLessThan(address);
        expect(pageSource).toContain("const addReady = addName !== '' && looksLikeDaalAddress(addAddr);");
        expect(pageSource).toContain("disabled={addBusy || !addReady}");
        expect(pageSource).toContain('data-testid="person-added"');
        expect(pageSource).toContain("t('pub.person.send_their')");
        // No "For {relay}" footnote (H-22).
        expect(pageSource.includes("'pub.artifacts.for'")).toBe(false);
        expect(EN['pub.person.add.where']).toContain('My Daal address');
    });
});

describe('the app\'s own confirm in place of window.confirm (H-29)', () => {
    it('no publisher screen calls window.confirm', async () => {
        const files = import.meta.glob('./*.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
        for (const [f, src] of Object.entries(files)) {
            if (f.includes('.test.')) continue;
            expect(/window\.confirm\(/.test(src), f).toBe(false);
        }
    });

    it('asks with the consequence visible, and answers yes or no', async () => {
        const { useConfirm } = await import('./ui');
        const answers: boolean[] = [];
        function Asker() {
            const c = useConfirm();
            return (
                <div>
                    <button
                        data-button="ask"
                        onClick={async () =>
                            answers.push(
                                await c.ask({ title: 'Save it?', body: 'Other apps can read it.', confirmLabel: 'Save', cancelLabel: 'Cancel' }),
                            )
                        }
                    >
                        ask
                    </button>
                    {c.node}
                </div>
            );
        }
        const m = await rig.mount(<Asker />);
        await rig.click(button(m.container, 'ask'));
        expect(byAttr(m.container, 'data-testid', 'confirm-body')?.textContent).toBe('Other apps can read it.');
        await rig.click(button(m.container, 'confirm-cancel'));
        await rig.click(button(m.container, 'ask'));
        await rig.click(button(m.container, 'confirm-yes'));
        expect(answers).toEqual([false, true]);
        // Back is "no".
        await rig.click(button(m.container, 'ask'));
        await rig.back();
        expect(answers).toEqual([false, true, false]);
    });

    it('the recovery key keeps MUST KEEP 12 in its confirm', () => {
        expect(EN['pub.danger.recovery.confirm']).toMatch(/in the clear/);
        expect(EN['pub.danger.recovery.confirm']).toMatch(/any app with storage access can read it/);
        expect(pageSource).toContain("body: t('pub.danger.recovery.confirm')");
    });
});

describe('the QR sheet (C7.2b)', () => {
    it('no counters unless developer mode, one line, Done; it draws under StrictMode (H-39)', async () => {
        const { QrSendSheet } = await import('./QrSendSheet');
        const asked: string[] = [];
        answer.fn = (cmd) => {
            asked.push(cmd);
            return new Promise(() => {});
        };
        const m = await rig.mount(
            <StrictMode>
                <QrSendSheet t={t} operatorId={6} relayName="Bahar" artifact="recipient:4" name="Maman" onClose={() => {}} />
            </StrictMode>,
        );
        await rig.settle(4);
        expect(m.container.textContent).toContain("Show this to Maman's phone");
        expect(m.container.textContent).toContain(EN['qr.send.how']);
        expect(byAttr(m.container, 'data-testid', 'qr-dev')).toBeNull();
        expect(m.container.textContent).not.toMatch(/Frame|Pass|\d+s\b/);
        expect(button(m.container, 'qr-done')).not.toBeNull();
        // The mount after StrictMode's unmount still asks for frames.
        expect(asked.filter((c) => c === 'wizard_qr_render').length).toBeGreaterThanOrEqual(1);
        expect(qrSource).toContain('exhaustedRef.current = false;');
    });
});

describe('the wizard (C7.8)', () => {
    it('step 1: no provider tiles, the token path once, the cost line first', () => {
        expect(wizardSource.includes("t('wiz.provider.soon')")).toBe(false);
        expect(wizardSource.includes("t('wiz.provider.label')")).toBe(false);
        expect(wizardSource.includes("t('wiz.provider.vps.tip.body')")).toBe(false);
        expect(wizardSource.includes('tokenHintKey)')).toBe(false);
        for (const cat of [UI_EN, UI_FA]) {
            // The provider hint keys stay for the provider code path; they are never shown.
            const withPath = Object.entries(cat).filter(([k, v]) => k.startsWith('wiz.') && /API.?tokens?/i.test(v) && !k.endsWith('.tokenHint'));
            expect(withPath.map(([k]) => k)).toEqual(['wiz.guide.2']);
        }
        // MUST KEEP 4.
        expect(UI_EN['wiz.step.cloud.line']).toMatch(/About €5–8 a month/);
        expect(UI_FA['wiz.step.cloud.line']).toMatch(/۵ تا ۸ یورو/);
        expect(wizardSource).toContain("blurbKey: 'wiz.step.cloud.line'");
        expect(wizardSource.includes("t('wiz.eyebrow')")).toBe(false);
    });

    it('done: "Add the first person" is the one primary, the check words are chips, no hex', () => {
        const done = wizardSource.slice(wizardSource.indexOf('data-testid="wizard-done"'));
        expect(done).toContain("onClick={() => onDone(operatorId, true)} dataButton=\"add-first-person\"");
        expect(done).toContain('variant="link" onClick={() => onDone(operatorId)} dataButton="open-relay"');
        expect(done.slice(0, done.indexOf('</Card>'))).not.toContain('fp.hex');
        expect(UI_EN['wiz.build.done.add']).toBe('Add the first person');
        // No automatic hand-off any more: the person chooses.
        expect(wizardSource.includes('setTimeout(r, 1200)')).toBe(false);
    });

    it('the build log is behind Details (H-52)', () => {
        const at = wizardSource.indexOf('<EventList events={buildLog} />');
        expect(wizardSource.slice(at - 300, at)).toContain("<Disclosure summary={t('ui.details')}");
    });
});

describe('copy that must not weaken', () => {
    it('the unfinished badge, the remove choices and the hedge keep their warning', () => {
        expect(EN['pub.relays.status.unfinished']).toMatch(/may cost money/);
        expect(EN['pub.relays.destroy.local.line']).toMatch(/keeps costing money/);
        expect(EN['pub.relays.destroy.write_down']).toBe('Write this address down.');
        expect(EN['pub.relays.destroy.server.line']).toMatch(/loses their connection.*cannot be undone/);
        expect(EN['pub.health.hedge']).toMatch(/As far as this phone can tell/);
        expect(EN['pub.people.replace.hint']).toMatch(/old one stops working at once/);
        expect(EN['pub.recipients.revoke.body']).toBe("{name}'s file will stop working. Nobody else is affected.");
        expect(EN['pub.relays.empty.line']).toBe('About €5–8 a month.');
    });

    it('every new Persian string keeps its placeholders', () => {
        for (const [k, v] of Object.entries(EN)) {
            if (!/^(pub|qr\.send)\./.test(k)) continue;
            const ph = (s: string) => (s.match(/\{[a-z_]+\}/gi) ?? []).sort().join();
            expect(ph(FA[k] ?? ''), k).toBe(ph(v));
        }
    });

    it('renders no MISSING key for the relay list empty state', async () => {
        const { EmptyState } = await import('../design/primitives');
        const html = renderToStaticMarkup(<EmptyState icon="server" title={t('pub.relays.empty.title')} body={t('pub.relays.empty.line')} />);
        expect(html).toContain('Set up a relay for your family');
    });
});
