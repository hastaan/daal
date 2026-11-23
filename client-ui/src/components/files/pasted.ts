// What the Files tab says about links and confs pasted on this phone
// (wave 2, app leftovers): the group's own plain title instead of the
// phone's sharing identity ("My Daal", which says nothing), each pasted
// route by the name its link gave it, and a WireGuard conf as a way Daal
// uses only when the person picks it.
//
// The engine says all three (core/abi/d2_summaries.go: `pasted_by_you`,
// `name_from_link`, `manual_only`). A row from an engine or a backend
// mapping that predates them is read from what is already there: a
// pasted route's id starts with "pasted-" (core/abi/share.go URIImport),
// its old nickname was the id's last eight characters (a short hash,
// never a name), and the only pasted WireGuard route is a conf, which is
// manual-only by construction.
import type { PublisherTreeRow, RouteDisplayRow } from '../../contract/D2Contract';
import { isPastedRoute } from '../pasteSurvey';

type T = (k: string) => string;


/** Added by pasting a link or a conf on this phone. */
export function pastedHere(r: RouteDisplayRow): boolean {
    return r.pastedByYou === true || isPastedRoute(r.routeId);
}

/** Dialled only when the person picks it (a pasted WireGuard conf). */
export function manualOnly(r: RouteDisplayRow): boolean {
    const n = r.manualOnly;
    if (typeof n === 'boolean') return n;
    return (r.family ?? '').trim().toLowerCase() === 'wireguard' && isPastedRoute(r.routeId);
}

/** The name a pasted link gave itself, or undefined. Never a piece of
 *  the route id. */
export function pastedName(r: RouteDisplayRow): string | undefined {
    if (!pastedHere(r)) return undefined;
    const n = (r.routeNickname ?? '').trim();
    if (!n) return undefined;
    if (r.nameFromLink === true) return n;
    if (r.nameFromLink === false) return undefined;
    // An older engine: its fallback nickname is the id's tail.
    if (r.routeId === n || r.routeId.endsWith(n) || r.routeId.endsWith(`-${n}`)) return undefined;
    return n;
}

/** The group of routes pasted on this phone. */
export function isPastedGroup(p: PublisherTreeRow): boolean {
    const routes = p.cells.flatMap((c) => c.routes);
    return routes.length > 0 && routes.every(pastedHere);
}

/** What a file is called on the Files tab: the pasted group by its own
 *  plain words, every other file by its publisher's name. */
export function fileTitle(t: T, p: PublisherTreeRow): string {
    return isPastedGroup(p) ? t('files.pasted.group') : p.displayName;
}

/** The name of the group a route belongs to, wherever a route is shown
 *  with its file: the pasted group by its own words, else the
 *  publisher's name. */
export function groupName(t: T, r: Pick<RouteDisplayRow, 'publisherName'> & RouteDisplayRow): string {
    return pastedHere(r) ? t('files.pasted.group') : r.publisherName;
}

/** A route's own name for display: a pasted route's link name (never the
 *  short hash the engine falls back to), else its nickname. */
export function routeDisplayName(r: RouteDisplayRow): string | undefined {
    if (pastedHere(r)) return pastedName(r);
    return r.routeNickname || undefined;
}
