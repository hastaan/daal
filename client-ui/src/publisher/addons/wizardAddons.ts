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
import type { AddonKind, AddonRow } from './addonTypes';

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

/** What turning an extra on needs before it can run: its account. */
export type AddonNeed = 'ready' | 'cloudflare' | 'google';

export function addonNeed(kind: AddonKind, acc: AccountsState): AddonNeed {
    if (kind === 'cdn' && (!acc.cloudflare.connected || !acc.cloudflare.zone)) return 'cloudflare';
    if (kind === 'google' && !acc.google.connected) return 'google';
    return 'ready';
}

/** The one call that turns `kind` on for relay `op`: the same call the
 *  relay page's switch makes. The standby is always sealed; Google takes
 *  a place in the account's script. */
export async function runAddon(kind: AddonKind, op: number, acc: AccountsState): Promise<AddonRow | void> {
    if (kind === 'standby') return Addons.standbyAdd({ operator_id: op, mode: 'sealed' });
    if (kind === 'cdn') return Addons.cdnBuild({ operator_id: op, zone: acc.cloudflare.zone });
    return Addons.googleOn({ operator_id: op });
}

/** The way in through Cloudflare is set up and signed, and the relay's
 *  door opens once the first person is on the relay (addon_cdn.rs,
 *  `door_waits`). */
export function waitsForPerson(row: unknown): boolean {
    const r = row as Partial<AddonRow> | null | undefined;
    return r?.kind === 'cdn' && r.state === 'ready' && r.detail?.door_waits === true;
}

/** One chosen extra on the wizard's finishing screen. `waitsForPerson`:
 *  on, and starts working with the relay's first person. */
export type ApplyState =
    | { k: 'waiting' }
    | { k: 'running' }
    | { k: 'on'; waitsForPerson?: boolean }
    | { k: 'failed'; error: unknown };

/** The line kept for an extra whose account is not connected any more. */
const NOT_CONNECTED: Record<Exclude<AddonNeed, 'ready'>, string> = {
    cloudflare: 'E_CDN_NO_TOKEN: Cloudflare is not connected',
    google: 'E_GOOGLE_NO_ACCOUNT: Google is not connected',
};

/** Turn one extra on, reporting its state; a failure is kept for the
 *  relay page. */
async function applyOne(
    op: number,
    kind: AddonKind,
    acc: AccountsState,
    onState: (kind: AddonKind, st: ApplyState) => void,
    run: (kind: AddonKind, op: number, acc: AccountsState) => Promise<unknown>,
): Promise<void> {
    const need = addonNeed(kind, acc);
    if (need !== 'ready') {
        const error = NOT_CONNECTED[need];
        recordAddonFailure(op, kind, error);
        onState(kind, { k: 'failed', error });
        return;
    }
    onState(kind, { k: 'running' });
    try {
        const row = await run(kind, op, acc);
        clearAddonFailure(op, kind);
        onState(kind, waitsForPerson(row) ? { k: 'on', waitsForPerson: true } : { k: 'on' });
    } catch (error) {
        recordAddonFailure(op, kind, error);
        onState(kind, { k: 'failed', error });
    }
}

/** «Try again» on the finishing screen: the same call once more. */
export async function retryAddon(
    op: number,
    kind: AddonKind,
    deps: {
        accounts: () => Promise<AccountsState>;
        onState: (kind: AddonKind, st: ApplyState) => void;
        run?: (kind: AddonKind, op: number, acc: AccountsState) => Promise<unknown>;
    },
): Promise<void> {
    if (applying.has(op)) return;
    applying.add(op);
    try {
        deps.onState(kind, { k: 'running' });
        await applyOne(op, kind, await deps.accounts(), deps.onState, deps.run ?? runAddon);
    } finally {
        applying.delete(op);
    }
}

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
        run?: (kind: AddonKind, op: number, acc: AccountsState) => Promise<unknown>;
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
            await applyOne(op, kind, acc, deps.onState, run);
        }
    } finally {
        applying.delete(op);
    }
}
