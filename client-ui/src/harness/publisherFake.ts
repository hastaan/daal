// publisherFake.ts — a pretend Tauri shell for the browser harness.
//
// The publisher screens (relay list, relay page, people, health,
// sharing, backup) and the recipient's QR / address screens call Tauri
// commands through `invoke` from @tauri-apps/api/core. That resolves to
// `window.__TAURI_INTERNALS__.invoke`, which a plain browser does not
// have, so those screens could only be seen with a real relay.
//
// `installPublisherFake()` gives the page a `__TAURI_INTERNALS__` that
// answers those commands from canned fixtures (via the official
// `mockIPC` helper, which also delivers events such as QR frames) — and
// does it ONLY when all of these hold:
//
//   * the URL carries `?harness=<id>` naming a known scenario, AND
//   * that scenario declares a `fake` block (scenarios.ts), AND
//   * there is no real `__TAURI_INTERNALS__` already (the real app is
//     never touched, whatever its URL says).
//
// Otherwise it returns false and changes nothing. The engine contract
// is NOT affected: backends/index.ts checks `isHarnessActive()` before
// `isTauriRuntime()`, so a harness page keeps the HarnessContract even
// though `isTauriRuntime()` now reads true. Every other
// `isTauriRuntime()` caller in the app is likewise paired with
// `!isHarnessActive()` (App.tsx, backupHarness.ts, RestorePage.tsx,
// PublisherWizard.tsx), except the wizard's "open in browser", which
// falls back to window.open when the fake refuses `open_external_url`.
//
// Commands the fake does not know are refused, exactly as they fail
// in a plain browser today. Nothing here is real and nothing leaves
// the page: while the fake is installed, fetches to any other origin
// are refused too (the helper-IP lookup would otherwise ask the
// internet).

import { mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { emit } from '@tauri-apps/api/event';
import { scenarioFromUrl, type FakeShell, type Scenario } from './scenarios';
import type {
    AccountCheck,
    ArtifactInfo,
    FreshnessStatus,
    OperatorSummary,
    PublisherCustodyStatus,
    RecipientSummary,
    RelayHealth,
    RestoreUnsettled,
} from '../publisher/wizardCommands';
import { runDrive } from './driver';
import { activeContract } from '../backends';
import { HarnessContract } from '../backends/harness';
import { netTestCommands } from './netTestFake';

// ---- fixtures ----------------------------------------------------------

const NOW = () => Math.floor(Date.now() / 1000);
const DAY = 86400;

export const LIVE_RELAY_ID = 1;
export const UNFINISHED_RELAY_ID = 2;

function operators(f: FakeShell): OperatorSummary[] {
    if (f.relays === 'none') return [];
    const both = twoRelays(f);
    return f.relays === 'one' ? [both[0]] : both;
}

function twoRelays(f: FakeShell): OperatorSummary[] {
    const now = NOW();
    const live: OperatorSummary = {
        id: LIVE_RELAY_ID,
        status: 'provisioned',
        provider: 'hetzner',
        region: 'fsn1',
        server_type: 'cax11',
        publisher_pub_hex: 'c0ffee'.repeat(10) + 'beef',
        created_at_unix: now - 41 * DAY,
        nickname: 'Family relay',
        public_ip: '203.0.113.24',
        public_ipv6: '2001:db8::24',
        server_id: '51234567',
        helper_ip: '198.51.100.7',
        last_provisioned_at_unix: now - 41 * DAY,
        decommissioned_at_unix: 0,
        has_signed_sbp: true,
        signed_sbp_at_unix: now - 12 * DAY,
        live_recipient_count: 2,
        total_recipient_count: 3,
        floating_ip_id: '',
        can_reserve_address: true,
        toolbox_profile: 'iran-default',
        served_families: ['vless-reality', 'websocket-tls', 'naive', 'hysteria2'],
        has_cloud_token: true,
        setup_interrupted: false,
        people_needing_renewal: 0,
        people_needing_answer: f.waiting ? 1 : 0,
        unreleased_addresses: [],
    };
    const unfinished: OperatorSummary = {
        ...live,
        id: UNFINISHED_RELAY_ID,
        status: 'pre-provision',
        nickname: 'Second relay',
        public_ip: '',
        public_ipv6: '',
        server_id: '',
        created_at_unix: now - 2 * DAY,
        last_provisioned_at_unix: 0,
        has_signed_sbp: false,
        signed_sbp_at_unix: 0,
        live_recipient_count: 0,
        total_recipient_count: 0,
        served_families: [],
        setup_interrupted: true,
        people_needing_answer: 0,
    };
    return [live, unfinished];
}

function people(): RecipientSummary[] {
    const now = NOW();
    const p = (id: number, name: string, days: number, revokedDays = 0): RecipientSummary => ({
        id,
        name: `r${id}`,
        display_name: name,
        address_str: `daal1q${'x7k2m9p4'.repeat(4)}${id}`,
        fingerprint_hex: `${id}`.repeat(64).slice(0, 64),
        provisioned_at_unix: now - days * DAY,
        revoked_at_unix: revokedDays ? now - revokedDays * DAY : 0,
        sbpx_path: `/data/daal/relay-1/r${id}.sbpx`,
    });
    return [p(1, 'Maman', 30), p(2, 'Baba', 29), p(3, 'Ali', 20, 6)];
}

function artifacts(): ArtifactInfo[] {
    const now = NOW();
    const file = (over: Partial<ArtifactInfo>): ArtifactInfo => ({
        kind: 'sbpx',
        path: '',
        exists: true,
        size_bytes: 6_412,
        modified_at_unix: now - 12 * DAY,
        recipient_id: null,
        recipient_label: '',
        ...over,
    });
    return [
        file({ kind: 'shared_sbp', path: '/data/daal/relay-1/1.shared.sbp', size_bytes: 5_980 }),
        file({ kind: 'raw_sbp', path: '/data/daal/relay-1/1.sbp', size_bytes: 5_120 }),
        ...people().map((r) =>
            file({
                path: r.sbpx_path,
                recipient_id: r.id,
                recipient_label: r.display_name,
                exists: r.revoked_at_unix === 0,
            }),
        ),
    ];
}

const ALL_WAYS = ['vless-reality', 'websocket-tls', 'naive', 'hysteria2'];

function health(f: FakeShell, op: number): RelayHealth {
    const base: RelayHealth = {
        operator_id: op,
        checked_at_unix: NOW() - 90,
        from_cache: false,
        overall: 'working',
        server: 'running',
        management: 'answers',
        management_reason: '',
        keys_match: true,
        people_missing: 0,
        everyone_missing: false,
        people_unknown: f.relayOnly ? 1 : 0,
        relay_only: f.relayOnly ? ['r7'] : [],
        people_needing_answer: f.waiting ? 1 : 0,
        ways: ALL_WAYS.map((family) => ({ family, state: 'answers' as const })),
        details: ['server 51234567 running (hetzner fsn1)', 'mgmt 203.0.113.24:8443 answered in 212 ms'],
    };
    switch (f.health ?? 'good') {
        case 'way_failing':
            return {
                ...base,
                overall: 'partly',
                ways: ALL_WAYS.map((family) => ({
                    family,
                    state: family === 'hysteria2' ? ('no_answer' as const) : ('answers' as const),
                })),
                details: [...base.details, 'hysteria2 udp/443: no answer in 5 s'],
            };
        case 'unreachable':
            return {
                ...base,
                overall: 'not_working',
                server: 'running',
                management: 'no_answer',
                // Not `address_may_have_changed`: that one asks the
                // internet for this computer's address.
                management_reason: 'timeout',
                keys_match: null,
                people_missing: null,
                everyone_missing: null,
                people_unknown: null,
                relay_only: null,
                ways: ALL_WAYS.map((family) => ({ family, state: 'no_answer' as const })),
                details: ['mgmt 203.0.113.24:8443: timed out after 10 s'],
            };
        default:
            return base;
    }
}

function unsettled(f: FakeShell): RestoreUnsettled {
    return f.waiting
        ? { people: [{ recipient_id: 2, name: 'Baba', relay_user: 'r2' }], checked: true, check_error: null }
        : { people: [], checked: true, check_error: null };
}

const FRESHNESS: FreshnessStatus = {
    endpoints: [],
    distinct_providers: 0,
    min_mirrors: 2,
    pack_url: '',
    mirrors_in_pack: [],
    pack_signed_at_unix: 0,
};

const CUSTODY: PublisherCustodyStatus = {
    level: 'hardware',
    unlocked: true,
    ok: true,
    error: '',
    legacy_pending: false,
    legacy_aliases: [],
    passphrase_set: false,
};

function accountCheck(): AccountCheck {
    return {
        checked_at_unix: NOW(),
        accounts: [
            {
                account_key: 'hetzner:1',
                provider: 'hetzner',
                relay_ids: [LIVE_RELAY_ID, UNFINISHED_RELAY_ID],
                complete: true,
                error_code: '',
                details: [],
                items: [
                    {
                        kind: 'server',
                        id: '51234567',
                        name: 'daal-family-relay',
                        address: '203.0.113.24',
                        billing: true,
                        verdict: 'in-use',
                        finding: 'yours_in_use',
                        belongs_to_relay_id: LIVE_RELAY_ID,
                        can_delete: false,
                    },
                    {
                        kind: 'server',
                        id: '51299901',
                        name: 'daal-second-relay',
                        address: '203.0.113.77',
                        billing: true,
                        verdict: 'unclaimed',
                        finding: 'unfinished_setup',
                        belongs_to_relay_id: UNFINISHED_RELAY_ID,
                        can_delete: true,
                    },
                ],
            },
        ],
    };
}

/** A base64url string that looks like a pasted file. */
function pasteable(prefix: string, n: number, seed = 7): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let s = prefix;
    let x = seed;
    for (let i = 0; i < n; i++) {
        x = (x * 1103515245 + 12345) & 0x7fffffff;
        s += alphabet[x % 64];
    }
    return s;
}

/** One QR fountain frame (~110 bytes, base64url). */
function qrFrame(i: number, k: number) {
    // 12-byte header + 96-byte block = 108 bytes = 144 base64url chars,
    // which is what the fixed QR version is sized for.
    return { i, k, frame_b64: pasteable('', 144, 1000 + i) };
}

// ---- verdicts ---------------------------------------------------------

export const FINGERPRINT_HEX = '3f9a1c07d2e84b56a0c3e1f9b7d4205e';
const WORDS_EN = 'phoenix rescue may sky honest stone river hill';
const WORDS_FA = 'ققنوس نجات اردیبهشت آسمان درست سنگ رود تپه';

export function verdictJson(kind: FakeShell['importVerdict']): string {
    switch (kind) {
        case 'trust':
            return JSON.stringify({
                Kind: 1,
                Fingerprint: FINGERPRINT_HEX,
                HexEN: WORDS_EN,
                HexFA: WORDS_FA,
                BundleID: 'family-relay-1',
                RouteCount: 4,
            });
        case 'refused':
            return JSON.stringify({ Kind: 3, Reason: 'bundle_signature_invalid' });
        case 'changed':
            return JSON.stringify({ Kind: 3, Reason: 'publisher_key_changed' });
        case 'partial':
            return JSON.stringify({
                Kind: 0,
                Fingerprint: FINGERPRINT_HEX,
                BundleID: 'family-relay-1',
                RouteCount: 4,
                Unavailable: [{ RouteID: 'family-relay-1/hysteria2', Family: 'hysteria2', Reason: 'not_offered' }],
            });
        default:
            return JSON.stringify({
                Kind: 0,
                Fingerprint: FINGERPRINT_HEX,
                BundleID: 'family-relay-1',
                RouteCount: 4,
                Unavailable: null,
            });
    }
}

// ---- the command table -------------------------------------------------

type Args = Record<string, unknown> | undefined;

/** The fake shell's answer to one command, or `undefined` for a
 *  command it does not know (refused, like a plain browser). */
export function makeHandler(f: FakeShell): (cmd: string, args: Args) => unknown {
    let scanReceived = 0;
    const SCAN_TOTAL = 40;
    const identity = {
        address: `daal1q${'m3n8v2c5'.repeat(5)}`,
        fingerprint_hex: 'ab'.repeat(32),
        created_at_unix: NOW() - 3 * DAY,
    };
    let identityMade = f.identity === 'made';
    // "Open with Daal": the path the shell hands over, once.
    let opened = f.opened ?? null;
    const op = (a: Args) => Number(a?.operatorId ?? LIVE_RELAY_ID);
    // The fake add-on ledger (optional add-ons).
    type FakeAddon = {
        id: number;
        operator_id: number;
        kind: 'standby' | 'cdn' | 'google';
        state: 'building' | 'ready' | 'promoted' | 'removing';
        provider_ids: Record<string, string>;
        monthly_cost_cents: number;
        cost_currency: string;
        has_secret: boolean;
        detail: Record<string, unknown>;
        created_at_unix: number;
        updated_at_unix: number;
    };
    let addons: FakeAddon[] = [];
    let cfAccount: { connected: boolean; zone: string; extra?: string[] } = { connected: false, zone: '' };
    let googleAccount = { connected: false, script_made: false, url: '', sign_in: false };
    let hostingAccount = false;
    const STANDBY_KEY = '000G40 R40M3 0E209 185WP 03H2G';
    const addonOp = (a: Args) => Number((a?.input as { operator_id?: number })?.operator_id ?? LIVE_RELAY_ID);
    const addonStep = async (operator_id: number, kind: FakeAddon['kind'], step: string) => {
        await emit('wizard://addon-progress', { operator_id, kind, step, state: 'running', detail: '' });
        await new Promise((r) => setTimeout(r, 250));
        await emit('wizard://addon-progress', { operator_id, kind, step, state: 'ok', detail: '' });
    };
    const addAddon = (
        operator_id: number,
        kind: FakeAddon['kind'],
        detail: Record<string, unknown>,
        cents: number,
        currency: string,
    ): FakeAddon => {
        const r: FakeAddon = {
            id: addons.length + 100,
            operator_id,
            kind,
            state: 'ready',
            provider_ids: {},
            monthly_cost_cents: cents,
            cost_currency: currency,
            has_secret: kind === 'google',
            detail,
            created_at_unix: NOW(),
            updated_at_unix: NOW(),
        };
        addons = [...addons.filter((x) => !(x.operator_id === operator_id && x.kind === kind && x.state !== 'promoted')), r];
        return r;
    };

    const table: Record<string, (a: Args) => unknown> = {
        // ---- publisher: relays
        wizard_list_operators: () => operators(f),
        wizard_set_operator_nickname: () => null,
        wizard_get_helper_ip: () => '198.51.100.7',
        wizard_set_helper_ip: () => null,
        publisher_custody_status: () => CUSTODY,
        wizard_freshness_status: () => FRESHNESS,
        wizard_recipient_list: (a) => (op(a) === LIVE_RELAY_ID ? people() : []),
        // "Links for other apps": one link (made-up values, a
        // documentation address) and the ways left out.
        wizard_recipient_share_links: () => ({
            links: [
                {
                    way: 'vless-reality',
                    label: 'Home · VLESS Reality',
                    link: 'vless://00000000-0000-4000-8000-000000000000@203.0.113.10:443?encryption=none&security=reality&sni=cover.example.org&fp=chrome&pbk=AAAA&sid=00&type=tcp#Home',
                },
            ],
            left_out: ['hysteria2', 'websocket-tls', 'naive', 'tuic'].map((way) => ({ way, reason: 'needs_insecure' })),
        }),
        wizard_list_artifacts: (a) => (op(a) === LIVE_RELAY_ID ? artifacts() : []),
        wizard_relay_health: (a) => health(f, op(a)),
        // Optional add-ons: none on any relay until a sheet turns one on.
        // The fake ledger keeps what the sheets make, so the cards can be
        // walked in a browser end to end.
        wizard_addons_list: (a) => addons.filter((r) => r.operator_id === op(a)),
        wizard_addon_remove: (a) => {
            const id = Number(a?.addonId);
            const r = addons.find((x) => x.id === id);
            addons = addons.filter((x) => x.id !== id);
            return {
                addon_id: id,
                removed: true,
                still_billing: [],
                by_hand: r?.kind === 'cdn' ? ['delete_cloudflare_token', 'cancel_domain'] : [],
                warnings: [],
            };
        },
        wizard_addon_standby_price: () => ({ monthly_cents: 300, currency: 'EUR', vat_included: false }),
        wizard_addon_standby_add: async (a) => {
            const o = addonOp(a);
            for (const step of ['renting', 'attaching', 'checking', 'signing']) await addonStep(o, 'standby', step);
            return addAddon(o, 'standby', { mode: String((a?.input as { mode?: string })?.mode ?? 'sealed') }, 300, 'EUR');
        },
        wizard_addon_standby_promote: async (a) => {
            const o = addonOp(a);
            await addonStep(o, 'standby', 'signing');
            const r = addons.find((x) => x.operator_id === o && x.kind === 'standby' && x.state === 'ready');
            if (r) r.state = 'promoted';
            return { addon: r, key: STANDBY_KEY, refresh_note_published: true, warnings: [] };
        },
        wizard_addon_standby_key: () => ({ key: STANDBY_KEY }),
        // The Cloudflare account (Accounts page): kept for every relay.
        wizard_addon_cdn_account: () => cfAccount,
        // A key with "short" in it lacks a permission; "broad" can do
        // more (kept, named); "two" sees two domains and asks which.
        wizard_addon_cdn_connect: (a) => {
            const input = (a?.input as { token?: string; zone?: string }) ?? {};
            const tok = String(input.token ?? '');
            const want = String(input.zone ?? '');
            if (tok.includes('short'))
                return { zones: ['example.com'], zone: 'example.com', verdict: 'missing_permission', stored: false, missing: ['Zone — DNS'] };
            if (tok.includes('two') && !want) return { zones: ['example.com', 'other.org'], verdict: 'pick_zone', stored: false };
            const zone = want || 'example.com';
            const zones = tok.includes('two') ? ['example.com', 'other.org'] : [zone];
            if (tok.includes('broad')) {
                cfAccount = { connected: true, zone, extra: ['Account — Billing'] };
                return { zones, zone, verdict: 'ok_broad', stored: true, extra: ['Account — Billing'] };
            }
            cfAccount = { connected: true, zone };
            return { zones, zone, verdict: 'ok', stored: true };
        },
        wizard_addon_cdn_disconnect: () => {
            cfAccount = { connected: false, zone: '' };
            return null;
        },
        wizard_addon_cdn_set_token: (a) => {
            const tok = String((a?.input as { token?: string })?.token ?? '');
            return tok.includes('short')
                ? { zones: ['example.com'], zone: 'example.com', verdict: 'missing_permission', stored: false, missing: ['Zone — DNS'] }
                : { zones: ['example.com'], zone: 'example.com', verdict: 'ok', stored: true };
        },
        wizard_addon_cdn_build: async (a) => {
            const o = addonOp(a);
            for (const step of ['cloudflare', 'firewall', 'door', 'testing', 'signing']) await addonStep(o, 'cdn', step);
            return addAddon(o, 'cdn', { hostname: 'k3j9.example.com', zone: 'example.com', name_hidden: true, plain_fallback: false }, 0, '');
        },
        wizard_addon_cdn_posture: (a) => ({
            name_hidden: true,
            door_closed_to_others: true,
            last_test_at_unix: NOW() - 60,
            last_test_ok: true,
            renews_at_unix: 0,
            needs_rebuild: false,
            hostname: 'k3j9.example.com',
            zone: 'example.com',
            plain_fallback: !!addons.find((x) => x.operator_id === addonOp(a) && x.kind === 'cdn')?.detail.plain_fallback,
            notes: '',
        }),
        wizard_addon_cdn_set_plain_fallback: (a) => {
            const r = addons.find((x) => x.operator_id === addonOp(a) && x.kind === 'cdn');
            if (r) r.detail = { ...r.detail, plain_fallback: !!(a?.input as { allow?: boolean })?.allow };
            return r;
        },
        // The Google account (Accounts page): one script for every relay.
        wizard_google_account: () => googleAccount,
        wizard_google_account_script: () => {
            if (!googleAccount.connected) googleAccount = { ...googleAccount, script_made: true };
            return {
                code_gs: '// Daal update channel\nvar WRITE_KEY_B64 = "harness-not-a-real-key";\nfunction doGet(e) { /* … */ }',
                manifest_json: '{}',
            };
        },
        wizard_google_account_attach: async (a) => {
            const url = String((a?.input as { url?: string })?.url ?? '').trim();
            await addonStep(0, 'google', 'checking');
            if (!/^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]{20,}\/exec\/?$/.test(url))
                throw 'E_GOOGLE_BAD_ADDRESS: the address must look like script.google.com/macros/s/…/exec';
            googleAccount = { ...googleAccount, connected: true, script_made: false, url: url.replace(/\/$/, '') };
            return googleAccount;
        },
        wizard_google_account_disconnect: () => {
            googleAccount = { connected: false, script_made: false, url: '', sign_in: false };
            return null;
        },
        wizard_addon_google_on: async (a) => {
            const o = addonOp(a);
            if (!googleAccount.connected) throw 'E_GOOGLE_NO_ACCOUNT: connect Google on the Accounts page first';
            for (const step of ['slot', 'checking']) await addonStep(o, 'google', step);
            return addAddon(o, 'google', { slot: 'AAAAAAAAAAA', url: `${googleAccount.url}?s=AAAAAAAAAAA&k=harness` }, 0, '');
        },
        wizard_addon_google_check: () => ({ ok: true, via_front: true, checked_at_unix: NOW(), reason: '' }),
        wizard_restore_unsettled: () => unsettled(f),
        wizard_setup_recovery: (a) => ({
            state: 'server_running',
            provider: 'hetzner',
            server_origin: 'created',
            can_finish_here: true,
            server_id: '51299901',
            public_ip: '203.0.113.77',
            billing: 'yes',
            leftovers: [{ kind: 'server', id: '51299901', name: 'daal-second-relay', billing: true }],
            check_error: '',
            started_at_unix: NOW() - 2 * DAY,
            details: [`relay ${op(a)}: journal open since 2 days`],
        }),
        wizard_account_check: () => accountCheck(),
        wizard_saved_cloud_token: () => (hostingAccount ? { operator_id: 0, nickname: '', account: true } : null),
        // The hosting account (Accounts page): kept for every new relay.
        wizard_hosting_account_status: () => ({
            hetzner: { connected: hostingAccount || operators(f).length > 0, account: hostingAccount },
        }),
        wizard_hosting_account_connect: (a) => {
            const tok = String((a?.input as { token?: string })?.token ?? '');
            if (tok.includes('wrong')) throw 'pricing: list-server-types: hetzner: 401 unauthorized';
            hostingAccount = true;
            return { connected: true, account: true };
        },
        wizard_hosting_account_disconnect: () => {
            hostingAccount = false;
            return null;
        },
        wizard_get_sbp_path: () => '/data/daal/relay-1/1.sbp',
        // ---- publisher: handing files out
        share_invite: (a) => `/cache/share/${String(a?.friendlyName ?? 'relay')}.sbp`,
        share_invite_sbpx: (a) => `/cache/share/${String(a?.friendlyName ?? 'person')}.sbpx`,
        save_shared_sbp_to_downloads: (a) => String(a?.fileName ?? 'Family relay.sbp'),
        save_sbpx_to_downloads: (a) => String(a?.fileName ?? 'Maman.sbpx'),
        wizard_copy_pasteable: (a) =>
            String(a?.artifact ?? '').startsWith('recipient:')
                ? pasteable('RFNCU', 7900)
                : pasteable('UEsDB', 7400),
        wizard_produce_shared_sbp: () => ({ sbp_path: '/data/daal/relay-1/1.shared.sbp', server: '203.0.113.24' }),
        wizard_qr_render: async (a) => {
            const max = Math.min(Number(a?.maxFrames ?? 60), 60);
            for (let i = 0; i < max; i++) await emit('wizard://qr-frame', qrFrame(i, 58));
            return null;
        },
        platform_secure_screen: () => null,
        // The desktop answer: the page's own clipboard (fakeClipboard).
        platform_clipboard_read: () => null,
        platform_clipboard_write: () => false,
        // ---- recipient: QR receive, address, custody
        recipient_qr_session_new: () => 'harness-scan-1',
        recipient_qr_feed_frame: () => {
            scanReceived = Math.min(SCAN_TOTAL, scanReceived + 3);
            const complete = scanReceived >= SCAN_TOTAL;
            return {
                session_id: 'harness-scan-1',
                received: scanReceived,
                total_frames: SCAN_TOTAL,
                bytes_decoded: scanReceived * 96,
                complete,
                verdict: complete ? JSON.parse(verdictJson(f.importVerdict)) : null,
            };
        },
        recipient_qr_status: () => ({
            session_id: 'harness-scan-1',
            received: scanReceived,
            total_frames: SCAN_TOTAL,
            bytes_decoded: scanReceived * 96,
            complete: false,
            verdict: null,
        }),
        recipient_qr_finalize: () => verdictJson(f.importVerdict),
        recipient_qr_cancel: () => null,
        recipient_identity_get: () => (identityMade ? identity : null),
        recipient_identity_get_or_create: () => {
            identityMade = true;
            return identity;
        },
        device_custody_level: () => 'hardware',
        device_custody_is_unlocked: () => true,
        // The file chooser: nothing chosen, or the scenario's file.
        'plugin:dialog|open': () => f.picked ?? null,
        stage_picked_file: (a) => {
            const uri = String(a?.uri ?? a?.path ?? f.picked ?? 'picked.sbp');
            return `/staging/${uri.split('/').pop() || 'picked.sbp'}`;
        },
        // A sealed file would need this phone's key; the fixtures are not.
        recipient_sbpx_sniff: () => false,
        // ---- Android hand-over (spec G.1, G.2)
        take_opened_file: () => {
            const p = opened;
            opened = null;
            return p;
        },
        share_text: () => null,
    };
    // The network test (lib/netTestCommands.ts) and its publisher half,
    // only for a scenario that asks: without it the row stays hidden, as
    // with a shell that predates the test.
    if (f.netTest) Object.assign(table, netTestCommands(f.netTest, 'pars-relays'));
    if (f.engineDown) {
        table.engine_status = () => ({
            engine_ready: false,
            engine_error: 'the engine library did not load',
        });
    }
    return (cmd, args) => {
        const h = table[cmd];
        return h ? h(args) : undefined;
    };
}

// ---- install -----------------------------------------------------------

interface TauriWindow {
    __TAURI_INTERNALS__?: unknown;
}

/** The scenario's fake shell, or null when this page is not a harness
 *  page that asked for one. */
export function fakeShellFor(s: Scenario | null): FakeShell | null {
    return s?.fake ?? null;
}

let installed = false;

/**
 * Install the fake shell if, and only if, this is a harness page whose
 * scenario asks for it and no real Tauri runtime is present. Returns
 * whether it did. Safe to call more than once.
 */
export function installPublisherFake(): boolean {
    if (installed) return true;
    if (typeof window === 'undefined') return false;
    const scenario = scenarioFromUrl();
    const fake = fakeShellFor(scenario);
    if (!scenario || !fake) return false;
    // Never shadow a real shell.
    if ((window as unknown as TauriWindow).__TAURI_INTERNALS__) return false;

    // Parameters other harness fakes read (`backup=stale`), unless the
    // URL already says otherwise. Those fakes read `location.search`
    // themselves, so the page is reloaded once with them added — a
    // `location.replace`, which adds no history entry (only
    // lib/backStack.ts may touch history; backStack.test.ts holds that).
    if (fake.params) {
        try {
            const url = new URL(window.location.href);
            let changed = false;
            for (const [k, v] of Object.entries(fake.params)) {
                if (!url.searchParams.has(k)) {
                    url.searchParams.set(k, v);
                    changed = true;
                }
            }
            if (changed) {
                window.location.replace(url.toString());
                return false;
            }
        } catch {
            /* ignore */
        }
    }

    const handle = makeHandler(fake);
    mockWindows('main');
    mockIPC(
        (cmd, args) => {
            const r = handle(cmd, args as Args);
            if (r === undefined) {
                return Promise.reject(`harness: the fake shell has no "${cmd}"`);
            }
            return r;
        },
        { shouldMockEvents: true },
    );
    guardFetch();
    fakeClipboard();
    if (fake.android) pretendAndroid();
    patchImports(fake);
    installed = true;
    void runDrive(scenario, fake);
    return true;
}

/** The harness engine answers every import "imported". A scenario that
 *  shows the trust question or a refusal swaps in the verdict the real
 *  importer gives, on the harness contract only. */
function patchImports(fake: FakeShell) {
    if (!fake.importVerdict) return;
    if (!(activeContract instanceof HarnessContract)) return;
    const c = activeContract as HarnessContract;
    const answer = async () => verdictJson(fake.importVerdict);
    c.importSbpBytes = answer;
    c.importSbp = answer;
}

/** Report an Android user agent, so the page offers what a phone has
 *  (the share sheet). */
function pretendAndroid() {
    try {
        const ua = navigator.userAgent;
        Object.defineProperty(navigator, 'userAgent', {
            configurable: true,
            get: () => (/Android/i.test(ua) ? ua : `${ua} (Linux; Android 10)`),
        });
    } catch {
        /* ignore */
    }
}

/** A headless page may not write the clipboard; a phone can. Copying
 *  succeeds (and goes nowhere) so the screen after "Copy" is the real
 *  one. */
function fakeClipboard() {
    try {
        Object.defineProperty(navigator, 'clipboard', {
            configurable: true,
            value: { writeText: async () => undefined, readText: async () => '' },
        });
    } catch {
        /* leave the real one */
    }
}

/** While the fake runs, nothing may leave this machine. */
function guardFetch() {
    const real = window.fetch?.bind(window);
    if (!real) return;
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
        try {
            const url = new URL(
                typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
                window.location.href,
            );
            if (url.origin !== window.location.origin) {
                return Promise.reject(new TypeError(`harness: offline (${url.origin})`));
            }
        } catch {
            /* let the real fetch report it */
        }
        return real(input, init);
    };
}
