// What the webview itself remembers about the routes on this phone, and
// how it is forgotten.
//
// The engine's panic wipe deletes the engine's state directory. It
// knows nothing of the webview's localStorage, where two things written
// by this app say something about what the phone held: the fingerprint
// of every publisher a file was imported from (lib/importOrigin.ts) and
// the id of the route the person last chose by hand
// (lib/autoConnect.ts). Left behind, they are readable in clear text
// after a wipe whose whole purpose is that nothing is.
//
// Language, theme and the other display preferences (lib/prefs.ts) say
// nothing about routes and are left alone.
import { forgetPinnedRoute, setPinnedRoute } from './autoConnect';
import { clearImportOrigins, forgetImportOrigin } from './importOrigin';

/** Panic wipe. Called BEFORE the engine is asked: if that call fails, or
 *  the app is killed half-way, this side is already clean. */
export function clearLocalTraces(): void {
    setPinnedRoute(null);
    clearImportOrigins();
}

/** A publisher (and every route under it) was removed. */
export function forgetPublisher(publisherId: string): void {
    forgetImportOrigin(publisherId);
}

/** One route was removed. */
export function forgetRoute(routeId: string): void {
    forgetPinnedRoute(routeId);
}
