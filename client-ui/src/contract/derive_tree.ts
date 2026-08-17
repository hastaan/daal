// derive_tree.ts — client-side aggregator that turns the engine's flat
// `availableRoutes` + `subscriptionList` projection into the
// publisher-rooted tree the new Network page renders.
//
// This lives in the contract layer because both backends (tauri.ts and
// harness.ts) share the same derivation rules. Until the engine grows
// a dedicated `list_publishers` aggregator (deferred to a follow-up),
// this function is the single source of truth for the tree shape.

import type {
    BurnpressureVerdict,
    CellRow,
    FamilyChip,
    PublisherTreeRow,
    RouteDisplayRow,
    SkippedFamilyRow,
    SourceKind,
    SubscriptionRow,
} from './D2Contract';

// FRP-3D + 3A taxonomy mirror (kept here so the UI doesn't have to
// fetch it). Keep in sync with core/routestore/family.go.
const EXPERIMENTAL_FAMILIES = new Set<string>([
    'webtunnel',
    'snowflake',
    'masque',
    'psiphon',
    'conjure',
    'transport_module',
    'lifeline_relay',
]);

function isExperimental(family: string): boolean {
    return EXPERIMENTAL_FAMILIES.has(family);
}

// Naming-only: pick a sourceKind from the raw RouteDisplayRow. Real
// engine source_type values would come from the routestore but the
// flat projection collapses everything; we infer.
//   - has a sourceName  → produced by a subscription
//   - publisherName looks like "Pasted" / "Imported"  → pasted
//   - everything else inherits from the trustClass (trusted/pinned → sbpx/sbp)
function inferSourceKind(routes: RouteDisplayRow[]): SourceKind {
    if (routes.length === 0) return 'pasted';
    const sourceNames = new Set(
        routes.map((r) => r.sourceName ?? '').filter(Boolean),
    );
    const allFromSub = sourceNames.size > 0 && routes.every((r) => !!r.sourceName);
    const someFromSub = sourceNames.size > 0;
    const trusted = routes.every((r) => r.trustClass === 'trusted');
    const pinned = routes.every(
        (r) => r.trustClass === 'pinned' || r.trustClass === 'trusted',
    );
    if (allFromSub) return 'subscription';
    if (someFromSub) return 'mixed';
    if (trusted) return 'sbpx';
    if (pinned) return 'sbp';
    return 'pasted';
}

function chipFor(
    family: string,
    routes: RouteDisplayRow[],
    skipped: Map<string, SkippedFamilyRow>,
): FamilyChip {
    // Only proven routes contribute a meaningful health number; averaging
    // in the placeholder 50 of untested routes would fabricate a score.
    const provenRoutes = routes.filter(
        (r) => r.proven && typeof r.healthPct === 'number',
    );
    const totalPct = provenRoutes.reduce((acc, r) => acc + (r.healthPct ?? 0), 0);
    const cooledCount = routes.filter((r) => r.inCooldown).length;
    const skip = skipped.get(family);
    return {
        family,
        count: routes.length,
        healthPct:
            provenRoutes.length === 0
                ? 0
                : Math.round(totalPct / provenRoutes.length),
        proven: provenRoutes.length > 0,
        cooledCount: skip ? Math.max(cooledCount, 1) : cooledCount,
        experimental: isExperimental(family),
        lastErrorTag: skip?.reasonTag,
    };
}

// M1 cell partitioning: every publisher gets a single synthetic
// "default" cell holding all of its routes. FRP-11 cells will become a
// real per-route attribute in M5; until then the page renders one cell
// per publisher without losing fidelity (the user sees the same family
// chips they would inside a real cell).
function cellsFor(
    routes: RouteDisplayRow[],
    skipped: Map<string, SkippedFamilyRow>,
    labelLookup: (cellIdFpHex: string) => string,
): CellRow[] {
    if (routes.length === 0) return [];
    const families = new Map<string, RouteDisplayRow[]>();
    for (const r of routes) {
        const list = families.get(r.family) ?? [];
        list.push(r);
        families.set(r.family, list);
    }
    const chips: FamilyChip[] = [];
    for (const [family, list] of families) {
        chips.push(chipFor(family, list, skipped));
    }
    chips.sort((a, b) => a.family.localeCompare(b.family));
    return [
        {
            cellIdFpHex: 'default',
            label: labelLookup('default'),
            families: chips,
            routes,
        },
    ];
}

/** Build the publisher tree from the existing flat engine projections. */
export function buildPublisherTree(
    routes: RouteDisplayRow[],
    subs: SubscriptionRow[],
    skippedFamilies: SkippedFamilyRow[],
    labelLookup: (cellIdFpHex: string) => string,
): PublisherTreeRow[] {
    const skipMap = new Map<string, SkippedFamilyRow>();
    for (const s of skippedFamilies) skipMap.set(s.family, s);

    // Group routes by publisherName. The flat row's publisherName is
    // already the display name; we use it as the identity key in M1
    // because the engine projection does not surface publisher fingerprint
    // on RouteDisplayRow yet. M5 will replace this with the real
    // publisher_id from routestore.
    const byPub = new Map<string, RouteDisplayRow[]>();
    for (const r of routes) {
        const key = r.publisherName || '(unknown)';
        const list = byPub.get(key) ?? [];
        list.push(r);
        byPub.set(key, list);
    }

    // Index subscriptions by display name (same key as publisherName).
    const subByPub = new Map<string, SubscriptionRow>();
    for (const s of subs) {
        const existing = subByPub.get(s.displayName);
        if (
            !existing ||
            (s.lastGoodRefreshBucket || s.lastRefreshBucket || '') >
                (existing.lastGoodRefreshBucket || existing.lastRefreshBucket || '')
        ) {
            subByPub.set(s.displayName, s);
        }
    }
    // Publishers that have subscriptions but no current routes yet (e.g.
    // refresh hasn't run) still deserve a row.
    for (const s of subs) {
        if (!byPub.has(s.displayName)) byPub.set(s.displayName, []);
    }

    const out: PublisherTreeRow[] = [];
    for (const [name, list] of byPub) {
        const sub = subByPub.get(name);
        const cells = cellsFor(list, skipMap, labelLookup);
        // Display heuristic for trust level (M1): trusted if every
        // route says so, else pinned, else unknown.
        let trustLevel = 'unknown';
        if (list.length > 0) {
            if (list.every((r) => r.trustClass === 'trusted')) trustLevel = 'trusted';
            else if (list.every((r) => r.trustClass === 'pinned' || r.trustClass === 'trusted'))
                trustLevel = 'pinned';
        } else if (sub) {
            trustLevel = 'pinned';
        }
        out.push({
            // The real engine publisher_id (fingerprint) from the
            // routes, so delete/forget target the right publisher.
            //
            // Empty — never the display name — for subscription-only
            // groups whose first refresh has not landed yet, because
            // there is no publisher in the engine to name. Substituting
            // the display name made `publisherDelete` a silent no-op
            // (Store::DeletePublisher matches the literal string, finds
            // nothing and returns 0, nil by design) while the caller
            // still tore the tunnel down: the button looked broken and
            // cost the user their connection. Callers must treat "" as
            // "no publisher row to remove".
            publisherId: list[0]?.publisherId ?? '',
            displayName: name,
            trustLevel,
            sourceKind: sub ? 'subscription' : inferSourceKind(list),
            revoked: false,
            routeCount: list.length,
            cells,
            subscription: sub
                ? {
                      subscriptionId: sub.subscriptionId,
                      profileTitle: sub.profileTitle,
                      lastRefreshBucket: sub.lastRefreshBucket,
                      lastRefreshOutcome: sub.lastRefreshOutcome,
                  }
                : undefined,
        });
    }

    out.sort((a, b) => a.displayName.localeCompare(b.displayName));
    return out;
}

// burnpressure V1 thresholds, mirrored from core/burnpressure/doc.go.
// Keeping them client-side lets us derive the verdict from skippedFamilies
// alone until the engine ABI exposes the real Verdict struct.
const BURNPRESSURE_DISTINCT_MIN = 3;
const BURNPRESSURE_STEP_MIN = 3;

/** Pure-derivation burnpressure verdict from a skippedFamilies list. */
export function deriveBurnpressureVerdict(
    skipped: SkippedFamilyRow[],
): BurnpressureVerdict {
    const highest = skipped.reduce((m, s) => Math.max(m, s.ladderStep), 0);
    const distinct = skipped.length;
    return {
        promote:
            distinct >= BURNPRESSURE_DISTINCT_MIN && highest >= BURNPRESSURE_STEP_MIN,
        distinctFamilies: distinct,
        highestLadderStep: highest,
    };
}
