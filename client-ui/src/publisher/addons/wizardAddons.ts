// wizardAddons.ts — the extras chosen while building a relay, and the
// one call each extra makes when it is turned on.
//
// Accounts are separate from relays, and each relay picks its own
// extras: one relay may have the standby, Cloudflare and Google, another
// none. The build wizard asks on its «More protection (optional)» step;
// the choice is kept per relay (so a relaunch mid-build still knows it),
// applied once the relay is built, and then forgotten.
//
// A choice that fails to turn on never fails the relay. It is kept as a
// failure for that relay, and the relay page's row shows it as one line
// with «Try again» (AddonsSection reads `failedAddons`).

import { Addons } from '../wizardCommands';
import type { AccountsState } from './accounts';
import type { AddonKind } from './addonTypes';

/** The order the rows show and the order they are applied in. */
export const ADDON_ORDER: readonly AddonKind[] = ['standby', 'cdn', 'google'];

const CHOICE_KEY = (op: number) => `daal.wizard.addons.${op}`;
const FAILED_KEY = (op: number) => `daal.addons.failed.${op}`;

function store(): Storage | null {
    try {
        return typeof localStorage === 'undefined' ? null : localStorage;
    } catch {
        return null;
    }
}

function readJson<T>(key: string, fallback: T): T {
    try {
        const v = store()?.getItem(key);
        return v ? (JSON.parse(v) as T) : fallback;
    } catch {
        return fallback;
    }
}

function writeJson(key: string, v: unknown | null): void {
    try {
        const s = store();
        if (!s) return;
        if (v == null) s.removeItem(key);
        else s.setItem(key, JSON.stringify(v));
    } catch {
        /* not kept: the choice is asked again, the failure not shown */
    }
}

function onlyKinds(v: unknown): AddonKind[] {
    const list = Array.isArray(v) ? v : [];
    return ADDON_ORDER.filter((k) => list.includes(k));
}

/** What was chosen for relay `op` and not applied yet. */
export function recallAddonChoices(op: number): AddonKind[] {
    return onlyKinds(readJson<unknown>(CHOICE_KEY(op), []));
}

export function rememberAddonChoices(op: number, kinds: readonly AddonKind[]): void {
    const k = onlyKinds(kinds);
    writeJson(CHOICE_KEY(op), k.length > 0 ? k : null);
}

/** The extras whose turning on failed after a build: kind → the error. */
export function failedAddons(op: number): Partial<Record<AddonKind, string>> {
    const v = readJson<Record<string, unknown>>(FAILED_KEY(op), {});
    const out: Partial<Record<AddonKind, string>> = {};
    for (const k of ADDON_ORDER) if (typeof v?.[k] === 'string') out[k] = v[k] as string;
    return out;
}

export function recordAddonFailure(op: number, kind: AddonKind, error: unknown): void {
    const text = typeof error === 'string' ? error : error instanceof Error ? error.message : String(error ?? '');
    writeJson(FAILED_KEY(op), { ...failedAddons(op), [kind]: text });
}

export function clearAddonFailure(op: number, kind: AddonKind): void {
    const all = failedAddons(op);
    delete all[kind];
    writeJson(FAILED_KEY(op), Object.keys(all).length > 0 ? all : null);
}

/** What turning an extra on needs before it can run. */
export type AddonNeed = 'ready' | 'cloudflare' | 'google' | 'by_hand';

export function addonNeed(kind: AddonKind, acc: AccountsState): AddonNeed {
    if (kind === 'cdn' && (!acc.cloudflare.connected || !acc.cloudflare.zone)) return 'cloudflare';
    if (kind === 'google' && !acc.google) return 'google';
    if (kind === 'google' && acc.google === 'manual') return 'by_hand';
    return 'ready';
}

/** The one call that turns `kind` on for relay `op`: the same call the
 *  relay page's switch makes. The standby is always sealed. */
export async function runAddon(kind: AddonKind, op: number, acc: AccountsState): Promise<void> {
    if (kind === 'standby') await Addons.standbyAdd({ operator_id: op, mode: 'sealed' });
    else if (kind === 'cdn') await Addons.cdnBuild({ operator_id: op, zone: acc.cloudflare.zone });
    else await Addons.googleSignIn({ operator_id: op });
}

/** One chosen extra on the wizard's finishing screen. */
export type ApplyState =
    | { k: 'waiting' }
    | { k: 'running' }
    | { k: 'on' }
    | { k: 'failed'; error: unknown }
    /** Google by hand: the person pastes the script for this relay. */
    | { k: 'by_hand' };

/** Relays whose choices are being applied in this app run: a second
 *  mount (StrictMode, a re-render) must never rent a second standby. */
const applying = new Set<number>();

/**
 * Turn the chosen extras on for a relay that has just been built, one
 * after another. Each is taken out of the stored choices BEFORE it runs,
 * so an app killed mid-way never runs it twice; one that fails is kept
 * as a failure for the relay page and the next one still runs.
 */
export async function applyAddonChoices(
    op: number,
    kinds: readonly AddonKind[],
    deps: {
        accounts: () => Promise<AccountsState>;
        onState: (kind: AddonKind, st: ApplyState) => void;
        run?: (kind: AddonKind, op: number, acc: AccountsState) => Promise<void>;
    },
): Promise<void> {
    if (applying.has(op)) return;
    applying.add(op);
    try {
        const todo = onlyKinds(kinds);
        for (const k of todo) deps.onState(k, { k: 'waiting' });
        const acc = await deps.accounts();
        const run = deps.run ?? runAddon;
        for (const kind of todo) {
            rememberAddonChoices(op, recallAddonChoices(op).filter((k) => k !== kind));
            const need = addonNeed(kind, acc);
            if (need === 'by_hand') {
                deps.onState(kind, { k: 'by_hand' });
                continue;
            }
            if (need === 'cloudflare') {
                const error = 'E_CDN_NO_TOKEN: Cloudflare is not connected';
                recordAddonFailure(op, kind, error);
                deps.onState(kind, { k: 'failed', error });
                continue;
            }
            deps.onState(kind, { k: 'running' });
            try {
                await run(kind, op, acc);
                clearAddonFailure(op, kind);
                deps.onState(kind, { k: 'on' });
            } catch (error) {
                recordAddonFailure(op, kind, error);
                deps.onState(kind, { k: 'failed', error });
            }
        }
    } finally {
        applying.delete(op);
    }
}
