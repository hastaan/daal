// The verdict every intake lane ends in, read once.
//
// The fixtures are not invented: `engine_first_seen.json` is the
// verbatim `verdict` object that `core/abi.FountainFeedFrame` returned
// for a real signed `.sbp` decoded through the real LT fountain codec
// on a fresh state directory — which is exactly the offline case, a
// publisher this device has never seen. Kind 1, not Kind 0.
import { describe, expect, it } from 'vitest';
import {
    KIND_REJECTED,
    KIND_TRUST_PROMPT_NEEDED,
    friendlyReason,
    parseVerdict,
    trustFailure,
    trustFromVerdict,
    unavailableLines,
} from './importVerdict';

/** Captured from core/abi.FountainFeedFrame, verbatim. */
const ENGINE_FIRST_SEEN = JSON.stringify({
    Kind: 1,
    Fingerprint: 'baf7fd3808058a8575c46473a0ef60dd38639bda92caf42550a4449995c001c9',
    HexEN: 'hotel-papa-alpha-alpha',
    HexFA: 'هشت-شانزده-یک-یک',
    BundleID: 'sample-bundle-A',
    RouteCount: 1,
    Reason: '',
});

// The REAL English catalog, so a key referenced here but never defined
// fails this test instead of rendering as its own name to the user.
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
const t = (k: string) => (en as Record<string, string>)[k] ?? k;

describe('parseVerdict', () => {
    it('reads what the engine really sends for an offline first-seen pack', () => {
        const v = parseVerdict(ENGINE_FIRST_SEEN);
        expect(v).not.toBeNull();
        // The whole point: the normal offline outcome is a TRUST PROMPT,
        // so any lane that treats "decoded" as "imported" commits nothing.
        expect(v!.Kind).toBe(KIND_TRUST_PROMPT_NEEDED);
    });

    it('treats a non-verdict response as silent success rather than throwing', () => {
        expect(parseVerdict('ok')).toBeNull();
        expect(parseVerdict('')).toBeNull();
        expect(parseVerdict('{"no_kind":true}')).toBeNull();
    });
});

describe('trustFromVerdict', () => {
    it('takes the word grid from the engine, which uses the real wordlists', () => {
        const p = trustFromVerdict(null, parseVerdict(ENGINE_FIRST_SEEN)!);
        expect(p.fingerprintEN).toBe('hotel-papa-alpha-alpha');
        expect(p.fingerprintFA).toBe('هشت-شانزده-یک-یک');
        // resolveTrustPrompt is keyed on this; an empty one silently
        // resolves nothing.
        expect(p.fingerprintHex).toHaveLength(64);
    });

    it('prefers the engine grid over a preview rendered with placeholder lists', () => {
        const base = {
            fingerprintHex: 'ff',
            fingerprintEN: 'alpha bravo charlie delta',
            fingerprintFA: 'alpha bravo charlie delta',
            fingerprintVisualDataUri: 'data:image/png;base64,AAA',
            publisherName: 'Someone',
            bundleId: 'x',
            specVersion: 5,
            routeCount: 9,
        };
        const p = trustFromVerdict(base, parseVerdict(ENGINE_FIRST_SEEN)!);
        expect(p.fingerprintEN).toBe('hotel-papa-alpha-alpha');
        // …while keeping the fields the verdict has no opinion about.
        expect(p.publisherName).toBe('Someone');
        expect(p.fingerprintVisualDataUri).toBe('data:image/png;base64,AAA');
    });
});

describe('friendlyReason', () => {
    it('translates a known token into real copy, not the key', () => {
        const got = friendlyReason(t, 'route_expired');
        expect(got).not.toBe('add.err.reason.route_expired');
        expect(got).toContain('expired');
    });
    it('collapses every relaypack RPxxx code onto one piece of copy', () => {
        expect(friendlyReason(t, 'relaypack_RP012')).toBe(
            en['add.err.reason.relaypack_invalid'],
        );
    });
    it('falls back to translated copy for a token it does not know', () => {
        // NOT verbatim. The tokens are Go identifiers, so showing one
        // raw hands a Farsi reader an untranslated Latin string inside
        // an RTL panel with no action attached — the same defect class
        // as the undefined `add.err.rejected` key below. Generic and
        // translated beats specific and unreadable.
        expect(friendlyReason(t, 'something_new')).toBe(en['add.err.rejected']);
    });
    it('has translated copy for every reason token the engine can emit', () => {
        // Enumerated from the Go side: bundle/go/importer (Reason:
        // literals + classifyVerifyError) and core/abi. If the engine
        // grows a token and nobody adds copy, this fails here rather
        // than showing the identifier to a user in Tehran.
        const tokens = [
            'bundle_corrupted',
            'bundle_signature_invalid',
            'publisher_key_changed',
            'publisher_revoked',
            'route_expired',
            'save_failed',
            'lookup_failed',
            'freshness_fp_mismatch',
            'publisher_unknown_freshness_path',
            'user_cancelled',
            'invalid_decision',
            // The signed-endpoint gate (bundle/go/importer
            // endpoint_plan.go).
            'endpoint_mismatch',
            'endpoint_unauthenticated',
            'endpoint_malformed',
            'endpoint_downgrade',
            'pack_has_no_credentials',
            'pack_is_older',
        ];
        const enMap = en as Record<string, string>;
        const faMap = fa as Record<string, string>;
        for (const token of tokens) {
            const key = `add.err.reason.${token}`;
            expect(enMap[key], `missing EN copy for ${token}`).toBeTruthy();
            expect(faMap[key], `missing FA copy for ${token}`).toBeTruthy();
            // Real Farsi, not English pasted into a fa file.
            expect(faMap[key], `${token} FA copy is not Farsi`).toMatch(/[\u0600-\u06FF]/);
            // And it must actually be reachable through the mapper.
            expect(friendlyReason(t, token)).toBe(enMap[key]);
        }
    });
    it('has real copy for the no-reason fallback, in both languages', () => {
        // `add.err.rejected` was referenced but defined nowhere, so an
        // empty-Reason rejection printed the key name at the user.
        const got = friendlyReason(t, '');
        expect(got).not.toBe('add.err.rejected');
        expect(got.length).toBeGreaterThan(10);
        expect(fa['add.err.rejected']).toBeTruthy();
        expect(fa['add.err.rejected']).toMatch(/[\u0600-\u06FF]/);
    });
});

describe('the rejected kind', () => {
    it('is 3, and is distinguishable from a trust prompt', () => {
        expect(KIND_REJECTED).toBe(3);
        expect(KIND_TRUST_PROMPT_NEEDED).not.toBe(KIND_REJECTED);
    });
});

describe('trustFailure — did the routes actually commit?', () => {
    // TrustPrompt used to discard resolveTrustPrompt's return value AND
    // swallow its exception, then report success either way. Kind 1 is
    // the NORMAL outcome for both offline lanes, so that made this the
    // primary path: a refused pack and a trusted pack were
    // indistinguishable, on the one screen whose whole premise is that
    // they must not be. The paste lane went further and rendered a
    // full-sheet "added" confirmation.
    const ok = (verdict: unknown = null) =>
        ({ decision: 0, verdict, error: null }) as never;

    it('reports no failure when the engine stayed silent (harness/dev)', () => {
        expect(trustFailure(t, ok(null))).toBeNull();
    });

    it('reports no failure on a genuine commit', () => {
        expect(trustFailure(t, ok({ Kind: 0 }))).toBeNull();
        expect(trustFailure(t, ok({ Kind: 2 }))).toBeNull();
    });

    it('reports a failure when the engine REJECTED at tap time', () => {
        // AcceptTrustPrompt re-parses and re-verifies before committing,
        // so a revocation landing while the word grid was on screen, an
        // expiry, or a full disk all surface here.
        const got = trustFailure(
            t,
            ok({ Kind: KIND_REJECTED, Reason: 'save_failed' }),
        );
        expect(got).toBe(en['add.err.reason.save_failed']);
    });

    it('reports a failure when the resolve call itself threw', () => {
        // `abi: no pending prompt for <fp>` — the pending body is gone
        // from memory and could not be loaded from disk, so nothing
        // committed at all.
        const got = trustFailure(t, {
            decision: 0,
            verdict: null,
            error: 'abi: no pending prompt for baf7fd',
        } as never);
        expect(got).toBeTruthy();
    });

    it('does not treat the user cancelling as a failure', () => {
        // Decision 2 is "cancel". The engine reports it as Kind 3 /
        // user_cancelled, which must not be shown as an error.
        const got = trustFailure(t, {
            decision: 2,
            verdict: { Kind: KIND_REJECTED, Reason: 'user_cancelled' },
            error: null,
        } as never);
        expect(got).toBeNull();
    });
});

describe('unavailableLines — what the file did NOT give this person', () => {
    // The shape the engine returns after importing a pack in which the
    // publisher's tool dropped one route and the relay's key changed
    // under another (bundle/go/importer.Verdict.Unavailable).
    const verdict = parseVerdict(
        JSON.stringify({
            Kind: 0,
            RouteCount: 2,
            Merged: 1,
            Unavailable: [
                { RouteID: 'r5', Family: 'tuic', Reason: 'not_offered' },
                { RouteID: 'r3', Family: 'naive', Reason: 'needs_new_file' },
                { RouteID: 'r6', Family: 'anytls', Reason: 'a_reason_from_a_newer_engine' },
            ],
        }),
    );
    it('says one plain line per route, naming the route type', () => {
        const lines = unavailableLines(t, verdict);
        expect(lines).toHaveLength(3);
        expect(lines[0]).toContain('tuic');
        expect(lines[0]).toBe(
            (en as Record<string, string>)['add.unavailable.not_offered'].replace('{family}', 'tuic'),
        );
        expect(lines[1]).toContain('new file');
        // An unknown reason never reaches the user as an identifier.
        expect(lines[2]).not.toContain('a_reason_from_a_newer_engine');
        expect(lines[2]).not.toContain('add.unavailable.');
    });
    it('is empty for a pack that gave everything it lists', () => {
        expect(unavailableLines(t, parseVerdict(ENGINE_FIRST_SEEN))).toEqual([]);
        expect(unavailableLines(t, null)).toEqual([]);
    });
    it('has Farsi for every reason the engine can give', () => {
        const faMap = fa as Record<string, string>;
        for (const reason of ['not_offered', 'no_credentials', 'needs_new_file', 'older_than_device']) {
            const key = `add.unavailable.${reason}`;
            expect((en as Record<string, string>)[key], key).toBeTruthy();
            expect(faMap[key], key).toMatch(/[\u0600-\u06FF]/);
            expect(faMap[key], key).toContain('{family}');
        }
        expect(faMap['add.unavailable.title']).toMatch(/[\u0600-\u06FF]/);
    });
});

// Backlog TW-6. `not_offered` is decided by a marker in the route's
// PROFILE, which the publisher's signature does not cover: whoever can
// alter the file chooses the code. They must never choose the words.
describe('unavailableLines — nothing from the file is displayed', () => {
    const hostile = parseVerdict(
        JSON.stringify({
            Kind: 0,
            Unavailable: [
                // A reason that is not one of the engine's codes.
                { RouteID: 'r1', Family: 'tuic', Reason: 'Your phone is infected. Call +1 555 0100' },
                // A code that names an i18n key which exists but is not a reason.
                { RouteID: 'r2', Family: 'naive', Reason: 'title' },
                // A family that is not a family.
                { RouteID: 'r3', Family: '<img src=x onerror=alert(1)> visit evil.example', Reason: 'not_offered' },
                // Wrong types altogether.
                { RouteID: 'r4', Family: 7, Reason: { toString: 'x' } },
            ],
        }),
    );
    const e = en as Record<string, string>;
    it('maps an unknown reason to the generic sentence', () => {
        const lines = unavailableLines(t, hostile);
        expect(lines).toHaveLength(4);
        expect(lines[0]).toBe(e['add.unavailable.other'].replace('{family}', 'tuic'));
        // 'title' is a real key under add.unavailable.* — and still not a reason.
        expect(lines[1]).toBe(e['add.unavailable.other'].replace('{family}', 'naive'));
        expect(lines[1]).not.toBe(e['add.unavailable.title']);
    });
    it('describes an unknown family instead of quoting it', () => {
        const lines = unavailableLines(t, hostile);
        expect(lines[2]).toBe(
            e['add.unavailable.not_offered'].replace('{family}', e['add.unavailable.family_other']),
        );
        expect(lines[3]).toBe(
            e['add.unavailable.other'].replace('{family}', e['add.unavailable.family_other']),
        );
    });
    it('never lets a byte of the file onto the screen', () => {
        const all = unavailableLines(t, hostile).join('\n');
        for (const s of ['infected', '555', 'evil.example', 'onerror', '<img', 'toString']) {
            expect(all).not.toContain(s);
        }
    });
    it('does not throw on a verdict whose list is not a list', () => {
        expect(unavailableLines(t, { Kind: 0, Unavailable: 'x' as never })).toEqual([]);
    });
    it('has the generic sentence and the generic family in both languages', () => {
        for (const k of ['add.unavailable.other', 'add.unavailable.family_other', 'add.unavailable.title']) {
            expect(e[k], `en ${k}`).toBeTruthy();
            expect((fa as Record<string, string>)[k], `fa ${k}`).toBeTruthy();
        }
        expect(e['add.unavailable.other']).toContain('{family}');
        expect((fa as Record<string, string>)['add.unavailable.other']).toContain('{family}');
    });
});
