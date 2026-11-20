// driver.ts — walks a harness page to the screen a scenario names.
//
// Sheets, inner pages and filled-in forms are React state behind a
// tap, so a URL alone cannot open them. A scenario with a `fake` block
// (scenarios.ts) lists the taps instead, and this runs them after the
// page has drawn: open a tab, press a button, type into a field, scroll
// a section into view, or hold the page still mid-progress.
//
// Targets are named so they work in both languages:
//   btn:<data-button>    an element with that data-button attribute
//   key:<i18n key>       the element whose text is that string, in the
//                        page's language (exact match first, then the
//                        shortest element that contains it)
//   css:<selector>       a CSS selector
//   text:<literal>       literal text, as with key:
//
// `{ keep: true }` stops the page's long timers so a notice shown after
// the next tap does not hide itself; `{ freeze }` stops all of them.
//
// When the walk ends the root element carries `data-harness-drive`
// ("done", or "failed:<step>") so a capture script can tell. Harness
// only: it runs from installPublisherFake, which never runs outside it.

import type { DriveStep, FakeShell, Scenario } from './scenarios';
import { detectLocale, translate } from '../lib/i18n';
import { Prefs } from '../lib/prefs';

const STEP_TIMEOUT_MS = 6000;
const POLL_MS = 60;
const SETTLE_MS = 250;

const CLICKABLE = 'button, a, [role="button"], [role="tab"], summary, label, [data-button]';

function norm(s: string | null | undefined): string {
    return (s ?? '').replace(/\s+/g, ' ').trim();
}

function visible(el: Element): boolean {
    const r = (el as HTMLElement).getClientRects?.();
    return !!r && r.length > 0;
}

function textFor(matcher: string): string | null {
    if (matcher.startsWith('key:')) return translate(detectLocale(), matcher.slice(4));
    if (matcher.startsWith('text:')) return matcher.slice(5);
    return null;
}

/** Every visible element the matcher names, in document order. */
export function findAll(matcher: string, root: ParentNode = document): HTMLElement[] {
    if (matcher.startsWith('btn:')) {
        return [...root.querySelectorAll<HTMLElement>(`[data-button="${matcher.slice(4)}"]`)].filter(visible);
    }
    if (matcher.startsWith('css:')) {
        return [...root.querySelectorAll<HTMLElement>(matcher.slice(4))].filter(visible);
    }
    const want = norm(textFor(matcher));
    if (!want) return [];
    const all = [...root.querySelectorAll<HTMLElement>('body *')].filter(
        (el) => el.tagName !== 'SCRIPT' && el.tagName !== 'STYLE' && visible(el),
    );
    // Deepest elements whose whole text is the string.
    const exact = all.filter(
        (el) => norm(el.textContent) === want && ![...el.children].some((c) => norm(c.textContent) === want),
    );
    if (exact.length) return exact;
    const contains = all.filter(
        (el) => norm(el.textContent).includes(want) && ![...el.children].some((c) => norm(c.textContent).includes(want)),
    );
    return contains.sort((a, b) => norm(a.textContent).length - norm(b.textContent).length);
}

// The walk's own clock, kept from before any freeze below.
const realSetTimeout: typeof setTimeout =
    typeof window !== 'undefined' ? window.setTimeout.bind(window) : setTimeout;

function sleep(ms: number): Promise<void> {
    return new Promise((r) => realSetTimeout(r, ms));
}

async function waitFor(matcher: string, nth = 0): Promise<HTMLElement | null> {
    const end = Date.now() + STEP_TIMEOUT_MS;
    while (Date.now() < end) {
        const found = findAll(matcher)[nth];
        if (found) return found;
        await sleep(POLL_MS);
    }
    return null;
}

function setValue(el: HTMLElement, text: string) {
    const proto =
        el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
    setter?.call(el, text);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Stop every timer the page starts from now on, so a progress screen
 *  holds still for its picture. React renders through MessageChannel
 *  and keeps working. */
function freezeTimers() {
    const w = window as unknown as Record<string, unknown>;
    w.setTimeout = () => 0;
    w.setInterval = () => 0;
}

/** Drop only the page's LONG timers from now on (a notice that hides
 *  itself after seven seconds), so the screen after a tap stays up for
 *  its picture while everything quick still runs. */
const KEEP_MS = 3000;
function keepNotices(from: number) {
    const w = window as unknown as Record<string, unknown>;
    const st = window.setTimeout.bind(window);
    w.setTimeout = ((fn: TimerHandler, ms?: number, ...rest: unknown[]) =>
        (ms ?? 0) >= from ? 0 : st(fn, ms, ...rest)) as typeof setTimeout;
}

/** The taps that open the scenario's part of the app. */
function openSteps(fake: FakeShell): DriveStep[] {
    switch (fake.open) {
        case 'publisher':
            return [{ click: 'key:nav.publisher' }];
        case 'network':
            return [{ click: 'key:nav.network' }];
        default:
            return [];
    }
}

function mark(v: string) {
    try {
        document.documentElement.setAttribute('data-harness-drive', v);
    } catch {
        /* ignore */
    }
}

async function runStep(step: DriveStep): Promise<boolean> {
    if ('sleep' in step) {
        await sleep(step.sleep);
        return true;
    }
    if ('keep' in step) {
        keepNotices(step.keep === true ? KEEP_MS : step.keep);
        return true;
    }
    if ('freeze' in step) {
        if (step.freeze !== true && !(await waitFor(step.freeze))) return false;
        freezeTimers();
        return true;
    }
    if ('waitFor' in step) return (await waitFor(step.waitFor, step.nth)) !== null;
    if ('scroll' in step) {
        const el = await waitFor(step.scroll, step.nth);
        if (!el) return false;
        el.scrollIntoView({ block: 'start' });
        return true;
    }
    if ('type' in step) {
        const el = await waitFor(step.type, step.nth);
        if (!el) return false;
        el.focus();
        setValue(el, step.text);
        return true;
    }
    const el = await waitFor(step.click, step.nth);
    if (!el) return !!step.optional;
    const target = (el.closest(CLICKABLE) as HTMLElement | null) ?? el;
    target.click();
    return true;
}

/** Pre-mount: which tabs exist. A publisher scenario turns the
 *  Publisher tab on; any other turns it off. */
export function preparePrefs(fake: FakeShell) {
    try {
        Prefs.setPublisherEnabled(fake.open === 'publisher');
    } catch {
        /* storage blocked: the walk will say where it stopped */
    }
}

export async function runDrive(scenario: Scenario, fake: FakeShell): Promise<void> {
    preparePrefs(fake);
    mark('running');
    // Let the first render and its loads land.
    await sleep(400);
    const steps = [...openSteps(fake), ...(fake.steps ?? [])];
    for (let i = 0; i < steps.length; i++) {
        const ok = await runStep(steps[i]);
        if (!ok) {
            mark(`failed:${i}`);
            // eslint-disable-next-line no-console
            console.warn(`[harness] ${scenario.id}: step ${i} found nothing`, steps[i]);
            return;
        }
        if (!('freeze' in steps[i])) await sleep(SETTLE_MS);
    }
    mark('done');
}
