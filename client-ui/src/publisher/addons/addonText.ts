// addonText.ts — what «More protection» says about each extra, as i18n
// keys (pub.addons.*), and every key the relay section and the Accounts
// page use (for the catalogue test).
//
// Each row is a title, ONE short line and its cost. What a third party
// can see is said once, on that account's sheet in Accounts; what keeps
// billing is said in the one sentence that confirms turning a row off.
// Daal decides the rest (always sealed, no plain fallback, ECH as the
// zone allows), so none of it is a choice or a word here.

import type { AddonKind, AddonRow } from './addonTypes';
import type { ServiceId } from './accounts';

export interface AddonCopy {
    kind: AddonKind;
    titleKey: string;
    lineKey: string;
    costKey: string;
    /** The account the row needs first; none for the standby (it rents
     *  from the relay's own hosting account). */
    needs: Exclude<ServiceId, 'hetzner'> | null;
    /** The one sentence that confirms turning it off. */
    offKey: string;
}

/** In the order the rows are shown: cheapest and simplest first. */
export const ADDON_COPY: readonly AddonCopy[] = [
    {
        kind: 'standby',
        titleKey: 'pub.addons.standby.title',
        lineKey: 'pub.addons.standby.line',
        costKey: 'pub.addons.standby.cost',
        needs: null,
        offKey: 'pub.addons.off.standby',
    },
    {
        kind: 'cdn',
        titleKey: 'pub.addons.cdn.title',
        lineKey: 'pub.addons.cdn.line',
        costKey: 'pub.addons.cdn.cost',
        needs: 'cloudflare',
        offKey: 'pub.addons.off.cdn',
    },
    {
        kind: 'google',
        titleKey: 'pub.addons.google.title',
        lineKey: 'pub.addons.google.line',
        costKey: 'pub.addons.google.cost',
        needs: 'google',
        offKey: 'pub.addons.off.google',
    },
    // The update notes (addon_notes.rs): where a person's app looks when
    // every ordinary update address is blocked.
    {
        kind: 'gittag',
        titleKey: 'pub.addons.gittag.title',
        lineKey: 'pub.addons.gittag.line',
        costKey: 'pub.addons.gittag.cost',
        needs: 'github',
        offKey: 'pub.addons.gittag.off',
    },
    {
        kind: 'dnsnote',
        titleKey: 'pub.addons.dnsnote.title',
        lineKey: 'pub.addons.dnsnote.line',
        costKey: 'pub.addons.dnsnote.cost',
        needs: 'cloudflare',
        offKey: 'pub.addons.dnsnote.off',
    },
];

/** The two note switches: they write on their own and say how it went. */
export const NOTE_KINDS: readonly AddonKind[] = ['gittag', 'dnsnote'];

/** The keys a note switch's status and its "new files" line use (its
 *  button is the refile sheet's own name, `pub.refile.menu`). */
export function noteKeys(kind: AddonKind): string[] {
    return ['updated', 'retry', 'new_files'].map((k) => `pub.addons.${kind}.${k}`);
}

/** The live row for a kind: a promoted standby is the relay's address
 *  now, not the extra, so it does not turn the switch on. */
export function liveRow(rows: readonly AddonRow[], kind: AddonKind): AddonRow | null {
    return rows.find((r) => r.kind === kind && r.state !== 'promoted') ?? null;
}

/** Every key the relay section, its sheets and the Accounts page use. */
export function addonKeys(): string[] {
    const keys = new Set<string>([
        'pub.addons.title',
        'pub.addons.wizard.intro',
        'pub.addons.wizard.standby.cost',
        'pub.addons.wizard.waiting',
        'pub.addons.needs.cloudflare',
        'pub.addons.needs.google',
        'pub.addons.needs.github',
        'pub.addons.state.running',
        'pub.addons.state.stopping',
        'pub.addons.state.on',
        'pub.addons.state.building',
        'pub.addons.state.removing',
        'pub.addons.try_again',
        'pub.addons.details',
        'pub.addons.cancel',
        'pub.addons.close',
        'pub.addons.copy',
        'pub.addons.copied',
        'pub.addons.share',
        'pub.addons.off.title',
        'pub.addons.off.go',
        'pub.addons.billing.domain',
        'pub.addons.billing.address',
        'pub.addons.standby.key.show',
        'pub.addons.standby.key.title',
        'pub.addons.standby.key.body',
        'pub.addons.standby.switch',
        'pub.addons.standby.switch.title',
        'pub.addons.standby.switch.body',
        'pub.addons.standby.switch.go',
        'pub.addons.standby.in_use',
        'pub.addons.cdn.name_hidden',
        'pub.addons.cdn.waits_person',
        ...ACCOUNT_KEYS,
    ]);
    for (const c of ADDON_COPY) {
        for (const k of [c.titleKey, c.lineKey, c.costKey, c.offKey]) keys.add(k);
    }
    for (const k of NOTE_KINDS) for (const n of noteKeys(k)) keys.add(n);
    keys.add('pub.addons.gittag.repo_left');
    return [...keys];
}

/** The Accounts page and its sheets. */
export const ACCOUNT_KEYS = [
    'pub.accounts.title',
    'pub.accounts.connected',
    'pub.accounts.connected_to',
    'pub.accounts.not_connected',
    'pub.accounts.connect',
    'pub.accounts.disconnect',
    'pub.accounts.done',
    'pub.accounts.group.hosting',
    'pub.accounts.group.hosting.line',
    'pub.accounts.group.extra',
    'pub.accounts.group.extra.line',
    'pub.accounts.summary.start',
    'pub.accounts.summary.on',
    'pub.accounts.checking',
    'pub.accounts.hetzner.line',
    'pub.accounts.cloudflare.line',
    'pub.accounts.google.line',
    'pub.accounts.cf.step.1',
    'pub.accounts.cf.step.1.action',
    'pub.accounts.cf.step.2',
    'pub.accounts.cf.step.2.action',
    'pub.accounts.cf.step.3',
    'pub.accounts.cf.step.3.action',
    'pub.accounts.cf.key',
    'pub.accounts.cf.sees',
    'pub.accounts.cf.verdict.invalid',
    'pub.accounts.cf.verdict.no_zone',
    'pub.accounts.cf.verdict.zone_not_visible',
    'pub.accounts.cf.verdict.missing_permission',
    'pub.accounts.cf.verdict.refused',
    'pub.accounts.cf.pick',
    'pub.accounts.cf.broad',
    'pub.accounts.cf.perm.some',
    'pub.accounts.cf.perm.zone',
    'pub.accounts.cf.perm.dns',
    'pub.accounts.cf.perm.ssl',
    'pub.accounts.cf.perm.zone_settings',
    'pub.accounts.cf.perm.origin_rules',
    'pub.accounts.cf.perm.user_details',
    'pub.accounts.cf.perm.api_tokens',
    'pub.accounts.cf.perm.workers_routes',
    'pub.accounts.cf.perm.firewall',
    'pub.accounts.cf.perm.page_rules',
    'pub.accounts.cf.perm.workers_scripts',
    'pub.accounts.cf.perm.registrar',
    'pub.accounts.cf.perm.billing',
    'pub.accounts.cf.perm.members',
    'pub.accounts.google.step',
    'pub.accounts.google.step.action',
    'pub.accounts.google.warn',
    'pub.accounts.google.sign_in',
    'pub.accounts.google.unverified',
    'pub.accounts.google.api.open',
    'pub.accounts.google.hand.1',
    'pub.accounts.google.hand.1.action',
    'pub.accounts.google.hand.2',
    'pub.accounts.google.hand.2.action',
    'pub.accounts.google.hand.3',
    'pub.accounts.google.hand.4',
    'pub.accounts.google.hand.url',
    'pub.accounts.google.hand.secret',
    'pub.accounts.google.kept',
    'pub.accounts.google.disconnect.line',
    'pub.accounts.hz.step.2',
    'pub.accounts.hz.console',
    'pub.accounts.hz.kept',
    'pub.accounts.hz.relay_only',
    'pub.accounts.hz.disconnect.line',
    'pub.accounts.hz.refused',
    'pub.accounts.github.line',
    'pub.accounts.github.step.1',
    'pub.accounts.github.step.1.action',
    'pub.accounts.github.step.2',
    'pub.accounts.github.step.2.action',
    'pub.accounts.github.step.3',
    'pub.accounts.github.key',
    'pub.accounts.github.kept',
    'pub.accounts.github.connected_as',
    'pub.accounts.github.expires',
    'pub.accounts.github.broad',
    'pub.accounts.github.disconnect.line',
    'pub.accounts.github.verdict.invalid',
    'pub.accounts.github.verdict.missing_permission',
    'pub.accounts.github.verdict.owner_mismatch',
    'pub.accounts.github.verdict.rate_limited',
    'pub.accounts.github.perm.public_repo',
] as const;
