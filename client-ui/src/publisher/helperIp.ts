// helperIp.ts — the publisher's outbound public IP: detect it, persist
// it, and self-heal it.
//
// WHY THIS MODULE EXISTS
// ----------------------
// `daal-deploy` punches an *ephemeral* cloud-firewall rule for the
// publisher's public IP immediately before every mgmt-plane call. Two
// facts follow from that and shape everything below:
//
//   1. A stale helper IP is repairable without touching the box. The
//      provider API is reachable from anywhere with the cloud token, so
//      re-detecting and re-punching is enough. No reprovision, no
//      redeploy, no signed release.
//   2. The box itself cannot tell us the IP first. Any /whoami on the
//      relay sits *behind* the same firewall, so it can only confirm an
//      address that already works — it is a verification source, never
//      a discovery source.
//
// The old code was a single hardcoded `fetch('https://api.ipify.org')`
// in PublisherWizard with no timeout, no retry, no persistence, and an
// IPv4-only regex — so on an IPv6-only mobile network it silently
// produced nothing, and on every relaunch whatever it had found
// evaporated and left buttons disabled for invisible reasons. The
// database is now the cache (`operators.helper_ip`, migration V012);
// this module is only the detector and the self-heal path.

import { Wizard, classifyPublisherError } from './wizardCommands';

export interface DetectedIp {
    ip: string;
    /** Which endpoint answered, for diagnostics. */
    via: string;
}

// Three independent operators. One being blocked, rate-limited, or
// hijacked by a captive portal must not be able to stop the user, and
// no single one of them gets to be a chokepoint for the publisher
// surface.
const SOURCES: readonly string[] = [
    'https://api.ipify.org?format=text',
    'https://ifconfig.me/ip',
    'https://icanhazip.com',
];

const IPV4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_RE = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}$`);

/**
 * IPv6 textual form, including `::` compression, an optional `%zone`
 * suffix and the `::ffff:1.2.3.4` dotted-quad tail. Written out longhand
 * rather than as one heroic regex because the failure mode we care about
 * is *accepting garbage* — a captive-portal HTML page must never end up
 * stored as an IP and then punched into a firewall rule.
 */
function isValidIpv6(s: string): boolean {
    const zoneAt = s.indexOf('%');
    const body = zoneAt >= 0 ? s.slice(0, zoneAt) : s;
    if (body.length === 0) return false;
    if (!/^[0-9A-Fa-f:.]+$/.test(body)) return false;

    const halves = body.split('::');
    if (halves.length > 2) return false;
    const compressed = halves.length === 2;

    let hextets = 0;
    for (let h = 0; h < halves.length; h++) {
        const part = halves[h];
        if (part === '') continue;
        const groups = part.split(':');
        for (let i = 0; i < groups.length; i++) {
            const g = groups[i];
            // An empty group here means ':::' or a stray leading /
            // trailing single colon.
            if (g === '') return false;
            if (g.includes('.')) {
                // A dotted quad is legal only as the very last group.
                if (h !== halves.length - 1 || i !== groups.length - 1) {
                    return false;
                }
                if (!IPV4_RE.test(g)) return false;
                hextets += 2; // the quad stands for two 16-bit groups
                continue;
            }
            if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) return false;
            hextets += 1;
        }
    }
    // `::` stands for one or more zero groups, so a compressed address
    // must leave at least one group's worth of room.
    return compressed ? hextets <= 7 : hextets === 8;
}

/** IPv4 dotted-quad or IPv6 textual form. */
export function isValidIp(s: string): boolean {
    const v = s.trim();
    if (v.length === 0 || v.length > 64) return false;
    return IPV4_RE.test(v) || isValidIpv6(v);
}

async function fetchIp(url: string, timeoutMs: number): Promise<DetectedIp> {
    const ac = new AbortController();
    const timer = window.setTimeout(() => ac.abort(), timeoutMs);
    try {
        const res = await fetch(url, { signal: ac.signal, cache: 'no-store' });
        if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
        const body = (await res.text()).trim();
        // Validate before returning, not after storing: an interstitial
        // or captive-portal page answers 200 with HTML and would
        // otherwise be persisted as an "IP".
        if (!isValidIp(body)) throw new Error(`${url}: not an IP address`);
        return { ip: body, via: url };
    } finally {
        window.clearTimeout(timer);
    }
}

/**
 * Race several independent echo services with a per-request timeout,
 * returning the first well-formed answer. Resolves null when every
 * source fails or times out — callers must then offer manual entry.
 * Never throws.
 */
export function detectPublicIp(timeoutMs = 4000): Promise<DetectedIp | null> {
    return Promise.any(SOURCES.map((u) => fetchIp(u, timeoutMs))).catch(
        () => null,
    );
}

// One in-flight detection per operator. Not a cache of the *result* —
// the DB is the cache — just de-duplication so a screen that mounts
// three artifact rows doesn't fire nine HTTP requests.
const inFlight = new Map<number, Promise<string | null>>();

/**
 * Ensure `operators.helper_ip` is populated for this relay.
 *  - non-empty in the DB and `force` is false -> returns it unchanged
 *  - otherwise detect, persist via Wizard.setHelperIp(id, ip, 'auto'),
 *    return it
 *  - detection fails -> returns null; caller shows the manual field
 * Never throws.
 */
export function ensureHelperIp(
    operatorId: number,
    force = false,
): Promise<string | null> {
    const pending = inFlight.get(operatorId);
    if (pending) return pending;

    const p = (async (): Promise<string | null> => {
        try {
            if (!force) {
                const stored = await Wizard.getHelperIp(operatorId);
                if (stored && isValidIp(stored)) return stored;
            }
            const detected = await detectPublicIp();
            if (!detected) return null;
            await Wizard.setHelperIp(operatorId, detected.ip, 'auto');
            return detected.ip;
        } catch {
            // Deliberately swallowed. A helper-IP failure is never a
            // reason to fail the action the user asked for — the action
            // itself will report E_HELPER_IP_* and the self-heal path
            // below takes over.
            return null;
        } finally {
            inFlight.delete(operatorId);
        }
    })();

    inFlight.set(operatorId, p);
    return p;
}

/**
 * Self-heal after E_HELPER_IP_STALE: force a fresh detection, persist
 * it, and return it so the caller can retry the failed action once.
 */
export function reAllowlist(operatorId: number): Promise<string | null> {
    // Drop any in-flight *non-forced* detection so we cannot hand back
    // the stale value we are trying to replace.
    inFlight.delete(operatorId);
    return ensureHelperIp(operatorId, true);
}

/** Persist a hand-typed address. Throws when it isn't an IP at all. */
export function setHelperIpManually(
    operatorId: number,
    ip: string,
): Promise<void> {
    const v = ip.trim();
    if (!isValidIp(v)) return Promise.reject(new Error('not an IP address'));
    inFlight.delete(operatorId);
    return Wizard.setHelperIp(operatorId, v, 'manual');
}

/**
 * Wrap a mgmt-plane action so the helper IP repairs itself instead of
 * disabling a button.
 *
 * The rule this enforces: **no publisher button is ever disabled
 * because of the helper IP.** The action is always tappable; if the
 * stored address is missing or stale the action re-detects, re-punches
 * the firewall rule, and retries exactly once. Only if that retry also
 * fails does the caller show the manual-entry card.
 */
export async function withHelperIp<T>(
    operatorId: number,
    fn: () => Promise<T>,
): Promise<T> {
    await ensureHelperIp(operatorId); // no-op when already stored
    try {
        return await fn();
    } catch (e) {
        const code = classifyPublisherError(e);
        if (code === 'E_HELPER_IP_MISSING' || code === 'E_HELPER_IP_STALE') {
            const fresh = await reAllowlist(operatorId);
            if (fresh) return await fn(); // exactly one retry
        }
        throw e;
    }
}
