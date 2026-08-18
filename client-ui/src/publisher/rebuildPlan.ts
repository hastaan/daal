// rebuildPlan — what an L4 or an L6 will ACTUALLY do to this relay,
// computed before the operator can press the button.
//
// WHY THIS IS A MODULE AND NOT A FEW LINES INSIDE THE SHEET
//
// L4 (rebuild in a different datacenter) and L6 (rebuild onto a
// different protocol mix) are the two rungs of the ladder that destroy
// the server. They are not L3. L3 keeps the box, keeps every key, and
// finishes in seconds; these two delete the machine and build another
// one, which means a new address, a new management pin, and every file
// ever handed out dead with no network path to repair it.
//
// A sheet that says that in prose is not enough, because the prose is
// the same whether the rung is about to do something or nothing. Both
// rungs have a degenerate form that the backend does NOT catch, and
// arriving at it costs the operator a relay:
//
//   L4 into a region that turns out not to offer this relay's server
//   type. `reprovision` DELETES the box (hetzner/provider.go:475,
//   ServerDelete, and it deliberately does not re-create) and only
//   THEN does `provision` run. A region that cannot host the type
//   fails the second half, and the operator is left with no relay at
//   all — the old one is already gone. So the region list has to be
//   checked against the live catalogue BEFORE the press, not after.
//
//   L6 onto a profile that removes nothing. This is the subtle one and
//   it is the reason this file exists. The wizard refuses an L6 whose
//   target profile EQUALS the current one (commands.rs:2559) — but that
//   is not the same question as "does the wire shape change". The
//   family set the rebuild is given is `rotation_families(&rec)`
//   (commands.rs:2259), and for every provisioned relay that resolves
//   to the record's CURRENT candidate families: `enabled_families` is a
//   pre-provision-only field, and `provision` overwrites the stored
//   record wholesale with the Go OperatorRecord, which has no such
//   field (commands.rs:1722, provider/types.go:37). The Go side then
//   intersects — `candidatesForProfile` keeps a profile candidate only
//   if it is in the supplied family list (hetzner/profile_render.go:54).
//
//   Intersection only ever SHRINKS. So an L6 can remove families and
//   can never add one, and a profile change in the "widening"
//   direction — iran-tcp443 back to iran-default — passes every check
//   in the wizard and produces a relay with exactly the same routes as
//   the one it destroyed. Every recipient's file is dead, the operator
//   pays for a rebuild and waits three minutes, and a censor sees the
//   identical wire shape at a new address.
//
// Both of those are refusals this module computes, and the sheets
// disable the button on them and say which one fired.
//
// EVERYTHING BELOW IS A MIRROR OF A GO FILE, AND A GATE KEEPS IT ONE.
// `tools/check-toolbox-profiles.mjs` compares TOOLBOX_PROFILES against
// publisher/deploy/profiles/*.json and REGIONS against the region
// tables in publisher/deploy. A mirror with no gate is a table that is
// correct on the day it is written.

/** One transport family a profile is willing to carry. */
export interface ProfileCandidate {
    family: string;
    /** Whether a relay built with no explicit family list gets it. */
    defaultEnabled: boolean;
    /** True when the family needs UDP. The entire content of
     *  iran-tcp443 is that these are gone. */
    udpGated: boolean;
}

/** One toolbox profile — the thing L6 rotates between. */
export interface ToolboxProfile {
    slug: string;
    candidates: ProfileCandidate[];
}

/**
 * Mirror of publisher/deploy/profiles/*.json.
 *
 * Two profiles exist, which is what makes L6 non-degenerate at all: a
 * ladder rung whose payload is "pick a different profile" needs a
 * second profile to pick.
 */
export const TOOLBOX_PROFILES: ToolboxProfile[] = [
    {
        slug: 'iran-default',
        candidates: [
            { family: 'vless-reality', defaultEnabled: true, udpGated: false },
            { family: 'websocket-tls', defaultEnabled: true, udpGated: false },
            { family: 'naive', defaultEnabled: true, udpGated: false },
            { family: 'hysteria2', defaultEnabled: true, udpGated: true },
            { family: 'shadowsocks', defaultEnabled: false, udpGated: false },
            { family: 'anytls', defaultEnabled: false, udpGated: false },
            { family: 'tuic', defaultEnabled: false, udpGated: true },
        ],
    },
    {
        slug: 'iran-tcp443',
        candidates: [
            { family: 'vless-reality', defaultEnabled: true, udpGated: false },
            { family: 'websocket-tls', defaultEnabled: true, udpGated: false },
            { family: 'naive', defaultEnabled: true, udpGated: false },
            { family: 'shadowsocks', defaultEnabled: false, udpGated: false },
            { family: 'anytls', defaultEnabled: false, udpGated: false },
        ],
    },
];

export function profileBySlug(slug: string): ToolboxProfile | undefined {
    return TOOLBOX_PROFILES.find((p) => p.slug === slug);
}

/** A peering neighbourhood, mirrored from publisher/deploy/sni.Zone. */
export type Zone = 'eu-central' | 'eu-north' | 'us-east' | 'us-west' | 'apac';

export interface RegionOption {
    /** Provider-side region code. Codes are PROVIDER-SCOPED and collide
     *  on purpose: Vultr and Stark both call Frankfurt "fra". */
    code: string;
    zone: Zone;
}

/**
 * Mirror of the region tables in publisher/deploy.
 *
 * Hetzner's set comes from the `// Hetzner` block of
 * publisher/deploy/sni/pool.go's regionZones — that map's own doc says
 * it lists "every provider region code the wizard can offer", and
 * Hetzner has no regions.go of its own. Vultr and Stark come from
 * their `SupportedRegions` slices.
 *
 * The ZONE is carried because it is what makes an L4 worth doing. Two
 * regions in one zone sit in the same peering mesh and frequently the
 * same announced space; moving fsn1 -> nbg1 is a new address in the
 * same neighbourhood, which is the failure L3 already handles more
 * cheaply. Moving zones is the thing L4 is for.
 */
export const REGIONS: Record<string, RegionOption[]> = {
    hetzner: [
        { code: 'fsn1', zone: 'eu-central' },
        { code: 'nbg1', zone: 'eu-central' },
        { code: 'hel1', zone: 'eu-north' },
        { code: 'ash', zone: 'us-east' },
        { code: 'hil', zone: 'us-west' },
        { code: 'sin', zone: 'apac' },
    ],
    vultr: [
        { code: 'fra', zone: 'eu-central' },
        { code: 'ams', zone: 'eu-central' },
        { code: 'lhr', zone: 'eu-central' },
        { code: 'par', zone: 'eu-central' },
        { code: 'sto', zone: 'eu-north' },
        { code: 'waw', zone: 'eu-central' },
    ],
    stark: [
        { code: 'vno', zone: 'eu-north' },
        { code: 'kun', zone: 'eu-north' },
        { code: 'fra', zone: 'eu-central' },
    ],
};

export function regionsFor(provider: string): RegionOption[] {
    return REGIONS[provider.trim().toLowerCase()] ?? [];
}

export function zoneFor(provider: string, code: string): Zone | null {
    return regionsFor(provider).find((r) => r.code === code)?.zone ?? null;
}

/**
 * The V1.5 wall-clock column, mirrored from
 * publisher/deploy/rotation/recommender.go's estWallClockV15.
 *
 * Quoted verbatim rather than rounded into prose. The recommender
 * already refuses to quote L1's ~90s for a relay whose only route to
 * the same outcome is a rebuild, on the grounds that a dial that lies
 * is worse than no dial; a sheet that invented its own smaller number
 * would be the same lie one layer up.
 *
 * `rotation.WallClockFor` is the Go function every surface is supposed
 * to render, and it is not reachable from here: no Tauri command
 * exposes a duration for a level the caller names, and the one command
 * that returns a recommendation returns the level the RECOMMENDER
 * chose, not the rung the operator just opened a sheet for.
 *
 * The mirror is nonetheless equal to what that function would answer
 * for these two rungs, and only for these two: WallClockFor
 * substitutes the reprovision-fallback string when
 * `action.DestroysServer && !alwaysDestroys(level)`, and L4/L6 are both
 * inside `alwaysDestroys`, so it returns the raw table value
 * unconditionally. tools/check-toolbox-profiles.mjs asserts both halves
 * — the figures AND L4/L6's membership of alwaysDestroys — so the day
 * that equality stops holding, this table fails the build instead of
 * quietly under-quoting an outage.
 */
export const EST_WALLCLOCK: Record<'L3' | 'L4' | 'L5' | 'L6', string> = {
    L3: '~10s',
    L4: '~3min',
    L5: '~3min',
    L6: '~3min',
};

// ---------------------------------------------------------------------
// L5 — what a different hosting company means
// ---------------------------------------------------------------------

/**
 * The providers a relay can actually be REBUILT onto.
 *
 * NOT the list the first-run wizard offers. That list has five entries
 * because it also collects a token for providers Daal cannot drive yet;
 * `buildProvider` (publisher/deploy/cli/cli.go) constructs exactly
 * three adapters, and only two of them can build a relay:
 *
 *   hetzner  live, hardware-proven (the relay in the field runs here)
 *   vultr    live as of Wave 6 — a real /v2 REST client, never run
 *            against a live account
 *   stark    NOT offered. Its client talks to
 *            api.starkindustries.example, the RFC 2606 example TLD:
 *            every request shape in it is invented. It is also a
 *            sanctioned bulletproof host whose address space is widely
 *            blocklisted, which would make a relay worthless and give
 *            an EU/UK operator a legal problem. See providers/vultr's
 *            doc.go for the full reasoning.
 *
 * Offering a destination Daal cannot build on would be worse here than
 * anywhere else in the app: L5 DELETES the relay first, so a
 * destination that turns out to be unbuildable does not fail — it ends
 * the relay. The list is short on purpose.
 */
export const REBUILD_PROVIDERS = ['hetzner', 'vultr'] as const;
export type RebuildProvider = (typeof REBUILD_PROVIDERS)[number];

/**
 * Where this relay could move TO: every live provider except the one it
 * is already on.
 *
 * An empty answer is meaningful and the sheet says so rather than
 * showing an empty list — it means this build has no second cloud, and
 * the rung has nowhere to go.
 */
export function rebuildDestinations(currentProvider: string): RebuildProvider[] {
    const cur = currentProvider.trim().toLowerCase();
    return REBUILD_PROVIDERS.filter((p) => p !== cur);
}

export interface ProviderPlan {
    from: string;
    to: string;
    /** The rung's no-op, refused here and again in the wizard. */
    isSameProvider: boolean;
    /** True when the destination is not one Daal can build on. Never
     *  reachable from the sheet's own list; computed because the value
     *  can also arrive from a restored draft or a future caller, and
     *  the failure mode is the relay, not an error. */
    isKnownProvider: boolean;
}

export function planProviderChange(from: string, to: string): ProviderPlan {
    const f = from.trim().toLowerCase();
    const t = to.trim().toLowerCase();
    return {
        from: f,
        to: t,
        isSameProvider: t !== '' && t === f,
        isKnownProvider: (REBUILD_PROVIDERS as readonly string[]).includes(t),
    };
}

// ---------------------------------------------------------------------
// L6 — what the profile change does to the family set
// ---------------------------------------------------------------------

export interface ProfilePlan {
    /** The families the relay serves today. */
    before: string[];
    /** The families it will serve after the rebuild. */
    after: string[];
    /** Families the rebuild takes away. */
    removed: string[];
    /** Families the rebuild adds. Empty in every reachable case on a
     *  provisioned relay — see `projectFamilies`. Computed rather than
     *  asserted so a future profile or a future record shape cannot
     *  make the sheet quietly wrong. */
    added: string[];
    /** True when `after` equals `before`: the destroy-and-rebuild
     *  changes nothing a censor can see. A refusal, not a warning. */
    noWireChange: boolean;
    /** True only when the rebuild ADDS anytls to a relay that does not
     *  serve it today. A pack that names anytls must declare
     *  spec_version 5 (relaypack/binder.go:276), and every client
     *  shipped before Wave 5 rejects such a pack WHOLE rather than
     *  skipping the one route. */
    addsAnyTLS: boolean;
    /** UDP-needing families being dropped — the substantive content of
     *  a move to iran-tcp443, worth naming on its own because the user
     *  chose those families for speed. */
    removedUdp: string[];
}

/**
 * Mirror of `candidatesForProfile` (hetzner/profile_render.go:35) fed
 * by `rotation_families` (commands.rs:2259).
 *
 * `current` is the relay's served family set. A provisioned relay
 * always has one, so the empty branch below is the pre-provision shape
 * only — kept because the Go function has it and a mirror that drops a
 * branch is a mirror that disagrees under exactly the input nobody
 * tested.
 */
export function projectFamilies(current: string[], target: ToolboxProfile): string[] {
    const selected = new Set(current);
    return target.candidates
        .filter((c) => (selected.size === 0 ? c.defaultEnabled : selected.has(c.family)))
        .map((c) => c.family);
}

export function planProfileChange(
    currentFamilies: string[],
    target: ToolboxProfile,
): ProfilePlan {
    const before = [...currentFamilies];
    const after = projectFamilies(before, target);
    const beforeSet = new Set(before);
    const afterSet = new Set(after);
    const removed = before.filter((f) => !afterSet.has(f));
    const added = after.filter((f) => !beforeSet.has(f));
    const udp = new Set(
        TOOLBOX_PROFILES.flatMap((p) => p.candidates)
            .filter((c) => c.udpGated)
            .map((c) => c.family),
    );
    return {
        before,
        after,
        removed,
        added,
        noWireChange: removed.length === 0 && added.length === 0,
        addsAnyTLS: added.includes('anytls'),
        removedUdp: removed.filter((f) => udp.has(f)),
    };
}

// ---------------------------------------------------------------------
// L4 — what the region change does
// ---------------------------------------------------------------------

export interface RegionPlan {
    from: string;
    to: string;
    zoneFrom: Zone | null;
    zoneTo: Zone | null;
    /** The rung's own no-op, refused here as well as in the wizard so
     *  the button is dead before the press rather than the error
     *  arriving after it. */
    isSameRegion: boolean;
    /** Same peering neighbourhood. Not a refusal — a different
     *  datacenter in the same mesh is still a different prefix, which
     *  can be the whole point after a prefix-level block — but it is
     *  not the "move the relay's network neighbourhood" outcome the
     *  rung's copy promises, so the sheet says which one it is. */
    isSameZone: boolean;
}

export function planRegionChange(
    provider: string,
    from: string,
    to: string,
): RegionPlan {
    const zoneFrom = zoneFor(provider, from);
    const zoneTo = zoneFor(provider, to);
    return {
        from,
        to,
        zoneFrom,
        zoneTo,
        isSameRegion: to !== '' && to === from,
        isSameZone: zoneFrom !== null && zoneTo !== null && zoneFrom === zoneTo,
    };
}

/**
 * Does the target region actually offer this relay's server type?
 *
 * `types` is what `Wizard.listServerTypes(operatorId, region)` returned
 * for the TARGET region. A null answer means the question has not been
 * asked yet (or the lookup failed) and the caller must not treat that
 * as a yes: `reprovision` deletes the box before `provision` gets to
 * find out, so a wrong answer here is a relay that no longer exists.
 */
export function serverTypeAvailable(
    types: { id: string }[] | null,
    serverType: string,
): boolean | null {
    if (types === null) return null;
    return types.some((t) => t.id === serverType);
}

/**
 * A plan's monthly price WITH the currency it is actually billed in.
 *
 * L5 lists Hetzner and Vultr plans through the same component, and the
 * two do not bill in the same money: Hetzner is EUR, Vultr is USD.
 * `providers/vultr/live_client.go` stamps `currency` on every entry and
 * its comment says the field is "what stops a dollar figure being drawn
 * behind a euro sign" — but the Rust mirror dropped the field, so serde
 * discarded it before the UI could ask, and the copy hard-coded a euro
 * sign anyway. The Farsi copy hard-coded the WORD "یورو".
 *
 * The result was a $5.00 Vultr plan offered as "about €5 a month" on
 * the one sheet whose entire purpose is getting the operator to accept
 * a second bill — three lines above the warning that they will be
 * paying two providers at once.
 *
 * The wire field is called `monthly_eur` because that name is the
 * frozen contract with `daal-deploy`. It is not a claim about currency,
 * and nothing may render it behind a hard-coded symbol.
 *
 * An unset `currency` means a `daal-deploy` older than the second
 * provider, which could only ever have been quoting Hetzner.
 */
export function formatPlanPrice(ty: {
    monthly_eur: number;
    currency?: string;
}): string {
    const amount = ty.monthly_eur.toFixed(2);
    switch ((ty.currency || 'EUR').toUpperCase()) {
        case 'USD':
            return `$${amount}`;
        case 'EUR':
            return `\u20ac${amount}`;
        default:
            // A currency this build has no symbol for prints as a code
            // beside the number rather than being guessed at.
            return `${amount} ${(ty.currency ?? '').toUpperCase()}`;
    }
}
