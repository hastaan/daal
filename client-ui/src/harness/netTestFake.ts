// netTestFake — the network test's commands for the browser harness
// (publisherFake.ts installs it with the rest of the fake shell).
//
// A pretend engine: idle with a test relay held, a run that moves one
// step per status call, a kept result, a share, a discard — and, for
// the publisher, a test relay switch and a report to open. Nothing here
// is real; the answers have the engine's shapes (core/abi/fieldprobe.go,
// daal-wizard/src/report_key.rs).

export interface NetTestFake {
    /** Where the pretend engine starts. `none`: no test relay held. */
    state: 'none' | 'idle' | 'running' | 'done' | 'aborted' | 'blackout';
    /** The start answers this refusal (e.g. `rate_limited`). */
    refuse?: string;
    /** For `aborted`: why. */
    abort?: string;
    /** Publisher: the relay is already the test relay. */
    testRelayOn?: boolean;
    /** Publisher: how many people connect with the relay (not removed),
     *  and whether it has an everyone file. Default: 2 people and one. */
    relayPeople?: number;
    relayEveryone?: boolean;
    /** Publisher: what opening the picked report answers. */
    reportOpen?: 'ok' | 'not_ours' | 'not_a_report';
}

export const NET_PLAN = {
    steps: 23,
    max_connections: 30,
    max_relay_connections: 9,
    minutes: 4,
    consent_version: 1,
    targets_version: '2026-11-20.2',
    names: [
        'www.google.com',
        'script.google.com',
        'github.com',
        'hcaptcha.com',
        'cloudflare-ech.com',
        'crypto.cloudflare.com',
        'speed.cloudflare.com',
        'cloudflare-dns.com',
    ],
    public_resolver: '1.1.1.1',
};

const DONE_SUMMARY = [
    'netTest.summary.relayCutAtStart',
    'netTest.summary.splitHelloHelps',
    'netTest.summary.whiteNameHelps',
    'netTest.summary.googleGithubOpen',
    'netTest.summary.cdnSlowsAfterStart',
    'netTest.summary.quicClosed',
    'netTest.summary.privacy',
];

/** A report as `report-open` prints one (schema v2), like
 *  test-rigs/field-probe/sample-report-v2.json. */
export const SAMPLE_REPORT = {
    schema_version: 2,
    report_id: '7K2M9QXR4TVB8N3PWH6JCZ5D1A',
    generated_hour_bucket: '2026-11-20T19:00Z',
    platform: 'android',
    country_hint: 'IR',
    carrier_class: 'mobile',
    network_label: 'mci',
    net: { kind: 'cellular', validated: 'no', metered: 'yes', ipv6_global: false, private_dns: 'auto', resolver_class: 'isp_public' },
    app: { build: 'daal-core-0.9.0', targets_list_version: '2026-11-20.2', targets_list_sha256: '0'.repeat(64), desync_available: true, hello_fp: 'mixed' },
    relay_ref: '9e41c2ab',
    run: { complete: true, abort_reason: '', duration_bucket_s: 180, steps_run: 23, short_circuit: false },
    probes: [
        { id: 'A1', name: 'dns_link_allowed', target_role: 'google', variant: 'a', result: 'ok', phase: 'reach', signals: {} },
        { id: 'A1', name: 'dns_link_allowed', target_role: 'google', variant: 'aaaa', result: 'ok', phase: 'reach', signals: {} },
        { id: 'A2', name: 'dns_https_record', target_role: 'cf_edge', variant: 'https', result: 'type_dropped', phase: 'reach', signals: {} },
        { id: 'A5', name: 'dns_calibration', target_role: 'cf_edge', variant: 'a', result: 'bogon', phase: 'reach', signals: {} },
        { id: 'A6', name: 'dns_public_resolver', target_role: 'public_resolver', variant: 'calibration', result: 'bogon', phase: 'reach', signals: {} },
        { id: 'B1', name: 'tls_baseline', target_role: 'google', variant: 'addr_link', result: 'ok', phase: 'carry', signals: {} },
        { id: 'B6', name: 'cdn_neutral_carry', target_role: 'cf_edge', variant: 'addr_public', result: 'flow_capped_suspected', phase: 'carry', signals: {} },
        { id: 'B9', name: 'quic_443', target_role: 'google', variant: '', result: 'timeout', phase: 'handshake', signals: {} },
        { id: 'C2', name: 'relay_reality', target_role: 'relay', variant: 'desync_off', result: 'reset', phase: 'handshake', signals: {} },
        { id: 'C3', name: 'relay_reality_split', target_role: 'relay', variant: 'sni-cut', result: 'ok', phase: 'carry', signals: {} },
        { id: 'C4', name: 'relay_plain_white_sni', target_role: 'relay', variant: 'sni_white', result: 'ok_carried', phase: 'carry', signals: {} },
        { id: 'C5', name: 'relay_plain_cover_sni', target_role: 'relay', variant: 'sni_cover', result: 'reset_injected_likely', phase: 'handshake', signals: {} },
    ],
    findings: [
        { question: 'reality_443_works', answer: 'no', basis: ['C2'] },
        { question: 'split_hello_helps', answer: 'yes', basis: ['C2', 'C3'] },
        { question: 'white_name_helps_on_relay_ip', answer: 'yes', basis: ['C4', 'C5'] },
        { question: 'reset_looks_injected', answer: 'yes', basis: ['C5'] },
        { question: 'grey_cap_seen_on_cdn_ip', answer: 'yes', basis: ['B6'] },
        { question: 'quic_443_alive', answer: 'no', basis: ['B9'] },
    ],
    failures: [],
    notes: 'Mobile data, at home.',
};

type Args = Record<string, unknown> | undefined;

/** The command table for `f`. `publisherId` names the publisher whose
 *  file carries the test relay (a route of the scenario's file list). */
export function netTestCommands(f: NetTestFake, publisherId: string): Record<string, (a: Args) => unknown> {
    let state: NetTestFake['state'] = f.state;
    let step = 9;
    let abort = f.abort ?? 'cancelled';
    let testRelayOn = f.testRelayOn === true;
    const people = f.relayPeople ?? 2;
    const everyone = f.relayEveryone ?? true;
    const offered = () => state !== 'none';
    const result = () => {
        if (state === 'blackout') {
            return {
                state: 'aborted',
                net_kind: 'cellular',
                report: SAMPLE_REPORT,
                summary: ['netTest.summary.blackout', 'netTest.summary.relayNotTested', 'netTest.summary.privacy'],
                complete: false,
                abort_reason: '',
                has_test_relay: true,
                publisher_id: publisherId,
                plan: NET_PLAN,
            };
        }
        const done = state === 'done';
        return {
            state: done ? 'done' : 'aborted',
            net_kind: 'cellular',
            report: SAMPLE_REPORT,
            summary: done
                ? DONE_SUMMARY
                : ['netTest.summary.googleGithubOpen', 'netTest.summary.incomplete', 'netTest.summary.privacy'],
            complete: done,
            abort_reason: done ? '' : abort,
            has_test_relay: true,
            publisher_id: publisherId,
            plan: NET_PLAN,
        };
    };
    return {
        field_probe_status: () => {
            if (state === 'running') {
                const s = JSON.stringify({ state: 'running', step, of: NET_PLAN.steps });
                step += 1;
                if (step > NET_PLAN.steps) state = 'done';
                return s;
            }
            if (state === 'done' || state === 'aborted' || state === 'blackout') return JSON.stringify(result());
            return JSON.stringify({ state: 'idle', plan: NET_PLAN, has_test_relay: offered(), publisher_id: offered() ? publisherId : '' });
        },
        field_probe_start: () => {
            if (f.refuse) {
                return JSON.stringify({
                    started: false,
                    refused: f.refuse,
                    ...(f.refuse === 'rate_limited' ? { retry_after_min: 214 } : {}),
                });
            }
            state = 'running';
            step = 1;
            return JSON.stringify({ started: true });
        },
        field_probe_cancel: () => {
            const was = state === 'running';
            if (was) {
                state = 'aborted';
                abort = 'cancelled';
            }
            return was;
        },
        field_probe_share: () =>
            JSON.stringify({ sealed: true, path: '/data/daal/fieldprobe-out/net-ab12cd34.dat', file_name: 'net-ab12cd34.dat', bytes: 16714 }),
        field_probe_discard: () => {
            state = 'idle';
            return 1;
        },
        // ---- publisher
        wizard_test_relay_status: (a) => ({
            operator_id: Number(a?.operatorId ?? 1),
            is_test_relay: testRelayOn,
            has_key: testRelayOn,
            people_on_relay: people,
            everyone_file: everyone,
        }),
        wizard_test_relay_set: (a) => {
            const on = a?.on === true;
            if (on && a?.confirmInUse !== true && (people > 0 || everyone)) {
                return Promise.reject(
                    `E_TEST_RELAY_IN_USE: ${people} people connect with this relay; use a separate relay for testing`,
                );
            }
            const first = !testRelayOn && on;
            testRelayOn = on;
            return {
                operator_id: Number(a?.operatorId ?? 1),
                is_test_relay: on,
                key_made: first,
                people_to_send: people,
                everyone_file_kept: everyone,
                refresh_note_published: false,
            };
        },
        wizard_report_open: () => {
            switch (f.reportOpen ?? 'ok') {
                case 'not_ours':
                    return Promise.reject('E_REPORT_NOT_OURS: open: this report was not sealed to this key');
                case 'not_a_report':
                    return Promise.reject('E_REPORT_NOT_A_REPORT: the file is not a network test report');
                default:
                    return JSON.stringify(SAMPLE_REPORT);
            }
        },
    };
}
