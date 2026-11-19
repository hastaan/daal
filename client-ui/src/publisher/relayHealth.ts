// relayHealth — the health check, in plain words, with its honest limit
// (D3).
//
// The check runs from wherever the publisher's phone is: it asks the
// hosting company whether the server exists and runs, asks the relay's
// management a signed question, and knocks on each way in. None of that
// can see what a phone inside the censored country sees. The screen
// says so once, plainly, and never turns "answers from here" into
// "works for your family".

import { Wizard } from './wizardCommands';
import type { RelayHealth } from './wizardCommands';
import { reAllowlist, withHelperIp } from './helperIp';
import { explainFailure, failureKey } from './failureText';
import type { Failure } from './failureText';

/** Rust refuses to re-run within this window unless forced; the badge
 *  goes back to the recorded state after it. */
export const HEALTH_FRESH_SECONDS = 600;

export function healthIsFresh(h: RelayHealth | null | undefined, nowUnix: number): boolean {
    if (!h || !h.checked_at_unix) return false;
    return nowUnix - h.checked_at_unix <= HEALTH_FRESH_SECONDS;
}

/** The only condition under which a relay may be shown green. */
export function checkedWorking(h: RelayHealth | null | undefined, nowUnix: number): boolean {
    return !!h && h.overall === 'working' && healthIsFresh(h, nowUnix);
}

export function nowUnix(): number {
    return Math.floor(Date.now() / 1000);
}

export function overallKey(o: RelayHealth['overall']): string {
    return `pub.health.overall.${o}`;
}

export function serverLineKey(s: RelayHealth['server']): string | null {
    switch (s) {
        case 'running':
        case 'starting':
        case 'stopped':
        case 'missing':
        case 'error':
            return `pub.health.server.${s}`;
        // No token stored, or a hosting company Daal cannot ask: say
        // nothing rather than "fine".
        default:
            return 'pub.health.server.not_checked';
    }
}

export function managementLineKey(h: RelayHealth): string {
    if (h.management === 'no_answer' && h.management_reason === 'address_may_have_changed') {
        return 'pub.health.mgmt.address_changed';
    }
    switch (h.management) {
        case 'answers':
        case 'no_answer':
        case 'refused':
        case 'too_old':
        case 'error':
            return `pub.health.mgmt.${h.management}`;
        default:
            return 'pub.health.mgmt.not_checked';
    }
}

const KNOWN_FAMILIES = new Set([
    'vless-reality',
    'websocket-tls',
    'naive',
    'anytls',
    'shadowsocks',
    'hysteria2',
    'tuic',
    'wireguard',
]);

/** A way in, by its plain name. Never the protocol token: an unknown
 *  family is described, not quoted. */
export function familyNameKey(family: string): string {
    return KNOWN_FAMILIES.has(family)
        ? `pub.health.family.${family.replace(/-/g, '_')}`
        : 'pub.health.family.other';
}

export function wayStateKey(state: RelayHealth['ways'][number]['state']): string {
    return `pub.health.way.${state}`;
}

export interface HealthLine {
    key: string;
    /** Substituted for {name} / {n}. */
    name?: string;
    n?: number;
    tone: 'good' | 'bad' | 'neutral';
    /** keys_match === false: serious, reads like E_RELAY_KEYS_CHANGED. */
    serious?: boolean;
}

/** Every plain line the panel shows, in order. */
export function healthLines(t: (k: string) => string, h: RelayHealth): HealthLine[] {
    const out: HealthLine[] = [];
    const sk = serverLineKey(h.server);
    if (sk) {
        out.push({
            key: sk,
            tone: h.server === 'running' ? 'good' : h.server === 'not_checked' ? 'neutral' : 'bad',
        });
    }
    out.push({
        key: managementLineKey(h),
        tone: h.management === 'answers' ? 'good' : h.management === 'not_checked' ? 'neutral' : 'bad',
    });
    if (h.keys_match === false) {
        out.push({ key: 'pub.health.keys_changed', tone: 'bad', serious: true });
    }
    for (const w of h.ways ?? []) {
        out.push({
            key: wayStateKey(w.state),
            name: t(familyNameKey(w.family)),
            tone: w.state === 'answers' ? 'good' : w.state === 'not_testable_here' ? 'neutral' : 'bad',
        });
    }
    if ((h.people_missing ?? 0) > 0) {
        out.push({ key: 'pub.health.people_missing', n: h.people_missing ?? 0, tone: 'bad' });
    }
    if (h.everyone_missing === true) {
        out.push({ key: 'pub.health.everyone_missing', tone: 'bad' });
    }
    return out;
}

export function renderLine(t: (k: string) => string, l: HealthLine): string {
    return t(l.key)
        .replace('{name}', l.name ?? '')
        .replace('{n}', String(l.n ?? 0));
}

/** Why the check itself could not run, in plain words: "Update the app"
 *  for a helper that predates the check, the custody / address
 *  sentences for those — "try again" only when nothing more is known. */
export function healthFailure(t: (k: string) => string, e: unknown): Failure {
    const f = explainFailure(t, e);
    return failureKey(e) === 'pub.fail.generic' ? { ...f, message: t('pub.health.could_not_check') } : f;
}

export interface HealthDeps {
    relayHealth: (op: number, force: boolean) => Promise<RelayHealth>;
    /** This phone's address as stored for the relay, null if none. */
    storedHelperIp: (op: number) => Promise<string | null>;
    /** Re-detect this phone's address and store it; null if it could
     *  not be found. */
    reAllowlist: (op: number) => Promise<string | null>;
    withHelperIp: <T>(op: number, fn: () => Promise<T>) => Promise<T>;
}

const DEFAULT_DEPS: HealthDeps = {
    relayHealth: (op, force) => Wizard.relayHealth(op, force),
    storedHelperIp: (op) => Wizard.getHelperIp(op).catch(() => null),
    reAllowlist,
    withHelperIp,
};

/** Run the check once. When the management did not answer because this
 *  phone's address may have changed, detect it again with the existing
 *  helper and — only if it DID change — run the check once more, never
 *  more than once.
 *
 *  Only for a fresh result: a cached one must not turn every opening of
 *  a page into a forced check (a firewall rule opened and closed on the
 *  provider, per relay) for a relay that is simply down. And once the
 *  address is ruled out — unchanged, or the re-run with the new one does
 *  not answer either — the line no longer blames it. */
export async function checkHealth(
    op: number,
    force: boolean,
    deps: HealthDeps = DEFAULT_DEPS,
): Promise<RelayHealth> {
    const h = await deps.withHelperIp(op, () => deps.relayHealth(op, force));
    if (h.management_reason !== 'address_may_have_changed' || h.from_cache) return h;
    const before = await deps.storedHelperIp(op);
    const fresh = await deps.reAllowlist(op);
    if (!fresh) return h;
    const ruledOut = (r: RelayHealth): RelayHealth =>
        r.management_reason === 'address_may_have_changed' ? { ...r, management_reason: 'timeout' } : r;
    if (fresh === before) return ruledOut(h);
    return ruledOut(await deps.relayHealth(op, true));
}

/** One relay after another, never in parallel: each opens a temporary
 *  firewall rule on its relay, and a phone on a slow line should not
 *  open five at once. A failure on one does not stop the next. */
export async function checkSequentially(
    ops: number[],
    check: (op: number) => Promise<RelayHealth>,
    onResult: (op: number, h: RelayHealth | null) => void,
): Promise<void> {
    for (const op of ops) {
        try {
            onResult(op, await check(op));
        } catch {
            onResult(op, null);
        }
    }
}

export function healthFixture(over: Partial<RelayHealth> = {}): RelayHealth {
    return {
        operator_id: 1,
        checked_at_unix: nowUnix(),
        from_cache: false,
        overall: 'working',
        server: 'running',
        management: 'answers',
        management_reason: '',
        keys_match: true,
        people_missing: 0,
        everyone_missing: false,
        ways: [
            { family: 'vless-reality', state: 'answers' },
            { family: 'websocket-tls', state: 'answers' },
            { family: 'hysteria2', state: 'not_testable_here' },
        ],
        details: [],
        ...over,
    };
}
