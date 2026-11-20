// addonText.ts — what the Add-ons section says about each add-on, as
// i18n keys (pub.addons.*), and whether this build can turn it on.
//
// Every card carries the same three facts, because they are what a
// publisher weighs before paying for or signing up to anything:
//   rescues — when it helps people keep connecting, and when it does not
//   cost    — what it costs, and who bills it
//   ties    — what it links to the publisher (accounts, cards, what a
//             third party can see)
// The wording is docs/optional-addons-plan.md §1.1, §2.1, §3.1 and the
// "Ties to the publisher" row of §0. Never soften a cost or a risk here.

import type { AddonKind, AddonRow, AddonState } from './addonTypes';

export interface AddonCopy {
    kind: AddonKind;
    titleKey: string;
    lineKey: string;
    rescuesKey: string;
    costKey: string;
    tiesKey: string;
}

/** In the order the cards are shown: cheapest and simplest first. */
export const ADDON_COPY: readonly AddonCopy[] = [
    {
        kind: 'standby',
        titleKey: 'pub.addons.standby.title',
        lineKey: 'pub.addons.standby.line',
        rescuesKey: 'pub.addons.standby.rescues',
        costKey: 'pub.addons.standby.cost',
        tiesKey: 'pub.addons.standby.ties',
    },
    {
        kind: 'cdn',
        titleKey: 'pub.addons.cdn.title',
        lineKey: 'pub.addons.cdn.line',
        rescuesKey: 'pub.addons.cdn.rescues',
        costKey: 'pub.addons.cdn.cost',
        tiesKey: 'pub.addons.cdn.ties',
    },
    {
        kind: 'google',
        titleKey: 'pub.addons.google.title',
        lineKey: 'pub.addons.google.line',
        rescuesKey: 'pub.addons.google.rescues',
        costKey: 'pub.addons.google.cost',
        tiesKey: 'pub.addons.google.ties',
    },
];

/**
 * Whether this build can turn each add-on on. False shows the card in
 * its "in development" state: visible, off, and nothing to press. Each
 * add-on's lane flips its own entry when its commands stop answering
 * E_NOT_BUILT.
 */
export const ADDON_BUILT: Readonly<Record<AddonKind, boolean>> = {
    // L-standby-pub (S3-S6) + L-ui (S8).
    standby: true,
    // L-cdn-server (B-1..B-5) + L-ui (B-7). The relay door verb and the
    // binder's CDN route are other lanes' (see addon_cdn.rs).
    cdn: true,
    // L-google-pub (G1-G3) + L-ui (G6).
    google: true,
};

/** The i18n key of the badge for an add-on that has a ledger row. */
export function stateKey(s: AddonState): string {
    return `pub.addons.state.${s}`;
}

/** The live row for a kind: a promoted standby is the relay's address
 *  now, not the add-on, so it does not make the card "on". */
export function liveRow(rows: readonly AddonRow[], kind: AddonKind): AddonRow | null {
    return rows.find((r) => r.kind === kind && r.state !== 'promoted') ?? null;
}

/** The section's one-line summary key and its {n}. */
export function summaryOf(
    rows: readonly AddonRow[],
    built: Readonly<Record<AddonKind, boolean>> = ADDON_BUILT,
): { key: string; n: number } {
    const on = ADDON_COPY.filter((c) => liveRow(rows, c.kind)).length;
    if (on > 0) return { key: 'pub.addons.summary.on', n: on };
    if (!ADDON_COPY.some((c) => built[c.kind])) return { key: 'pub.addons.summary.soon', n: 0 };
    return { key: 'pub.addons.summary.off', n: 0 };
}

/** Every key this section uses, for the catalogue test. */
export function addonKeys(): string[] {
    const keys = new Set<string>([
        'pub.addons.title',
        'pub.addons.intro',
        'pub.addons.wizard.intro',
        'pub.addons.summary.off',
        'pub.addons.summary.on',
        'pub.addons.summary.soon',
        'pub.addons.soon',
        'pub.addons.soon.line',
        'pub.addons.label.rescues',
        'pub.addons.label.cost',
        'pub.addons.label.ties',
        'pub.addons.turn_on',
        'pub.addons.set_up',
        'pub.addons.manage',
    ]);
    for (const c of ADDON_COPY) {
        for (const k of [c.titleKey, c.lineKey, c.rescuesKey, c.costKey, c.tiesKey]) keys.add(k);
    }
    for (const s of ['building', 'ready', 'promoted', 'removing'] as const) keys.add(stateKey(s));
    return [...keys];
}
