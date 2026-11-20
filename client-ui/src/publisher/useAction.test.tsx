// Every publisher action answers the person who tapped it.
//
// The owner pressed Save on a person's file four times on a real phone:
// the save worked each time and the screen said nothing. These hold the
// three halves of the fix — one tap is one call, success is said, and
// failure is said in plain words with the raw error one tap away.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ActionButton, ActionController, ActionToast } from './useAction';
import type { ActionOutcome } from './useAction';

const explain = (e: unknown) => ({ message: 'PLAIN WHY.', detail: String(e) });
const t = (k: string) => k;

/** A promise the test settles by hand, so "still running" is a state
 *  the test can stand in. */
function gate<T>() {
    let open!: (v: T) => void;
    let fail!: (e: unknown) => void;
    const p = new Promise<T>((res, rej) => {
        open = res;
        fail = rej;
    });
    return { p, open, fail };
}

describe('ActionController', () => {
    it('a double tap fires the action once', async () => {
        const c = new ActionController(explain);
        const g = gate<string>();
        let calls = 0;
        const fn = () => {
            calls += 1;
            return g.p;
        };
        // Two taps in the same tick, before anything could re-render.
        const first = c.run('save', fn, { ok: 'Saved.', fail: 'Not saved.' });
        const second = c.run('save', fn, { ok: 'Saved.', fail: 'Not saved.' });
        expect(calls).toBe(1);
        expect(c.getState().busy).toBe('save');
        expect(await second).toEqual({ ran: false, ok: false });
        g.open('x');
        expect(await first).toEqual({ ran: true, ok: true, value: 'x' });
        expect(calls).toBe(1);
        expect(c.getState().busy).toBeNull();
    });

    it('a different action cannot start while one is running', async () => {
        const c = new ActionController(explain);
        const g = gate<void>();
        let other = 0;
        const first = c.run('send', () => g.p, { ok: 'ok', fail: 'no' });
        await c.run(
            'remove',
            async () => {
                other += 1;
            },
            { ok: 'ok', fail: 'no' },
        );
        expect(other).toBe(0);
        g.open();
        await first;
        // …and can once it has ended.
        await c.run(
            'remove',
            async () => {
                other += 1;
            },
            { ok: 'ok', fail: 'no' },
        );
        expect(other).toBe(1);
    });

    it('success ends with a visible result', async () => {
        const c = new ActionController(explain);
        const seen: (string | null)[] = [];
        c.subscribe(() => seen.push(c.getState().busy));
        await c.run('save', async () => '/Downloads/a.sbpx', {
            ok: (path) => `Saved to ${path}.`,
            fail: 'Not saved.',
        });
        const o = c.getState().outcome;
        expect(o?.kind).toBe('ok');
        expect(o?.message).toBe('Saved to /Downloads/a.sbpx.');
        // Listeners saw it go busy and come back.
        expect(seen).toEqual(['save', null]);
    });

    it('failure ends with what did not happen, why in plain words, and the raw error as detail', async () => {
        const c = new ActionController(explain);
        const r = await c.run(
            'save',
            async () => {
                throw 'context deadline exceeded';
            },
            { ok: 'Saved.', fail: 'The file was not saved.' },
        );
        expect(r).toEqual({ ran: true, ok: false });
        const o = c.getState().outcome;
        expect(o?.kind).toBe('fail');
        expect(o?.message).toBe('The file was not saved. PLAIN WHY.');
        expect(o?.message).not.toContain('deadline');
        expect(o?.detail).toBe('context deadline exceeded');
        // A failed action must not leave the screen locked.
        expect(c.getState().busy).toBeNull();
    });

    it('two identical results in a row are two results', async () => {
        const c = new ActionController(explain);
        await c.run('save', async () => 1, { ok: 'Saved.', fail: 'no' });
        const a = c.getState().outcome?.seq;
        await c.run('save', async () => 1, { ok: 'Saved.', fail: 'no' });
        expect(c.getState().outcome?.seq).not.toBe(a);
    });

    it('starting an action clears the previous result', async () => {
        const c = new ActionController(explain);
        await c.run('a', async () => 1, { ok: 'Done.', fail: 'no' });
        const g = gate<void>();
        const p = c.run('b', () => g.p, { ok: null, fail: 'no' });
        expect(c.getState().outcome).toBeNull();
        g.open();
        await p;
        // `ok: null` is for actions whose success opens its own screen.
        expect(c.getState().outcome).toBeNull();
    });
});

describe('ActionToast', () => {
    const ok: ActionOutcome = { seq: 1, key: 'save', kind: 'ok', message: 'Saved to Downloads.' };
    const fail: ActionOutcome = {
        seq: 2,
        key: 'save',
        kind: 'fail',
        message: 'The file was not saved. Check the connection.',
        detail: 'E_SOMETHING: raw text',
    };

    it('renders nothing when there is nothing to say', () => {
        expect(renderToStaticMarkup(<ActionToast t={t} outcome={null} onDismiss={() => {}} />)).toBe('');
    });

    it('renders a success', () => {
        const html = renderToStaticMarkup(<ActionToast t={t} outcome={ok} onDismiss={() => {}} />);
        expect(html).toContain('Saved to Downloads.');
        expect(html).toContain('role="status"');
        expect(html).toContain('data-kind="ok"');
        expect(html).not.toContain('<details');
    });

    it('renders a failure, with the raw error behind Details and not in the sentence', () => {
        const html = renderToStaticMarkup(<ActionToast t={t} outcome={fail} onDismiss={() => {}} />);
        expect(html).toContain('The file was not saved. Check the connection.');
        expect(html).toContain('role="alert"');
        expect(html).toContain('data-kind="fail"');
        const details = html.slice(html.indexOf('<details'), html.indexOf('</details>'));
        expect(details).toContain('pub.fb.details');
        expect(details).toContain('E_SOMETHING: raw text');
        // The raw text appears only inside the disclosure.
        expect(html.replace(details, '')).not.toContain('E_SOMETHING');
    });

    it('is pinned with logical insets, so it lays out the same right-to-left', () => {
        const html = renderToStaticMarkup(<ActionToast t={t} outcome={ok} onDismiss={() => {}} />);
        expect(html).toContain('position:fixed');
        expect(html).toContain('inset-inline-end:16px');
        expect(html).not.toMatch(/(?<![-a-z])(left|right):/);
    });
});

describe('ActionButton', () => {
    const render = (busy: string | null) =>
        renderToStaticMarkup(
            <ActionButton action={{ busy, outcome: null }} k="save" busyLabel="Saving…">
                Save file
            </ActionButton>,
        );

    it('is a normal button when nothing is running', () => {
        const html = render(null);
        expect(html).toContain('Save file');
        expect(html).not.toContain('disabled');
    });

    it('shows progress and cannot fire while its own action runs', () => {
        const html = render('save');
        expect(html).toContain('Saving…');
        expect(html).not.toContain('Save file');
        expect(html).toContain('disabled');
        expect(html).toContain('aria-busy="true"');
    });

    it('cannot fire while another action runs, and keeps its own label', () => {
        const html = render('send');
        expect(html).toContain('Save file');
        expect(html).toContain('disabled');
        expect(html).not.toContain('aria-busy');
    });
});
