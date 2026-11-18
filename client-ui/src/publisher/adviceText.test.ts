// What a Farsi operator actually reads on the rotation advice panel.
//
// The panel's whole substance is computed in Go and built in English:
// the reason, the evidence terms, the named absences. It renders in
// Farsi, on a screen where three of the six rungs DESTROY the relay and
// provisioning has no rollback. So the substance is keyed off stable
// Go-emitted codes, and these tests pin the two halves that can break
// silently: that the catalogs really answer in Farsi, and that a code
// they do not carry degrades to the English prose rather than to a bare
// key or a blank.
import { describe, expect, it } from 'vitest';
import { translate } from '../lib/i18n';
import type { RotationRecommendation } from './wizardCommands';
import {
    absentText,
    confidenceKey,
    levelKey,
    reasonText,
    termList,
    termText,
} from './adviceText';

const en = (k: string) => translate('en', k);
const fa = (k: string) => translate('fa', k);

/** The recommendation shape the panel receives, with only the fields
 *  the text layer reads. */
function rec(p: Partial<RotationRecommendation>): RotationRecommendation {
    return {
        level: 'L3',
        confidence: 'medium',
        reason: 'TCP reset on this relay, with no address-level attribution recorded',
        est_wallclock: '~10s',
        ...p,
    } as RotationRecommendation;
}

// Every code the Go recommender can emit today. tools/check-rotation-
// ladder.mjs is what keeps this in step with recommender.go — it reads
// the Go constants directly, which a bundler-side test cannot.
const REASON_CODES = [
    'credential_leak_suspected',
    'no_cdn_candidates',
    'provider_suspended',
    'udp_collapsed',
    'protocol_families_burned',
    'shared_risk_cooldown',
    'address_reset_attributed',
    'address_reset_unattributed',
    'address_timeout_attributed',
    'address_timeout_unattributed',
    'address_block_no_swap',
    'sni_block',
    'credential_leak_observed',
    'nothing_matched_ladder',
    'no_evidence_at_all',
];

const ABSENT_CODES = [
    'no_failures',
    'no_cooldown_producer',
    'no_prober',
    'operator_supplied',
];

describe('the reason — the sentence the panel exists to show', () => {
    it('is Farsi for every code the recommender can emit', () => {
        for (const code of REASON_CODES) {
            const out = reasonText(fa, rec({ reason_code: code, reason_detail: 'x' }));
            expect(out, code).not.toBe('');
            // Not the Go prose, and not a bare key.
            expect(out, code).not.toContain('reset on this relay');
            expect(out, code).not.toContain('pub.danger.advice');
            expect(out, code).toMatch(/[؀-ۿ]/);
            // The placeholder must be substituted, not printed.
            expect(out, code).not.toContain('{detail}');
        }
    });

    it('falls back to the Go prose for a code no catalog carries', () => {
        const r = rec({ reason_code: 'a_rule_added_after_this_catalog' });
        expect(reasonText(fa, r)).toBe(r.reason);
        expect(reasonText(en, r)).toBe(r.reason);
    });

    // An older daal-deploy emits no code at all. The panel must still
    // say something — the English prose — never an empty box.
    it('falls back to the Go prose when the field is absent entirely', () => {
        const r = rec({});
        expect(reasonText(fa, r)).toBe(r.reason);
    });

    it('substitutes the untranslatable fragment the sentence names', () => {
        const blocker = "this relay's software cannot configure an address";
        const out = reasonText(fa, rec({
            reason_code: 'address_block_no_swap',
            reason_detail: blocker,
        }));
        expect(out).toContain(blocker);
    });

    // A code that interpolates nothing gets no detail. Substituting an
    // undefined into the sentence would print "undefined" at the reader.
    it('never prints undefined when there is no detail', () => {
        const out = reasonText(fa, rec({ reason_code: 'sni_block' }));
        expect(out).not.toContain('undefined');
        expect(out).not.toContain('{detail}');
    });
});

describe('the absences — the half that separates unmeasured from fine', () => {
    it('is Farsi for every code the recommender can emit', () => {
        for (const code of ABSENT_CODES) {
            const out = absentText(fa, code, 'GO PROSE');
            expect(out, code).not.toBe('GO PROSE');
            expect(out, code).toMatch(/[؀-ۿ]/);
        }
    });

    it('falls back to the Go prose rather than vanishing', () => {
        expect(absentText(fa, 'an_absence_added_later', 'GO PROSE')).toBe('GO PROSE');
        // No code at all (an older daal-deploy, or the Rust hop dropping
        // the field — which is exactly how this shipped broken once).
        expect(absentText(fa, undefined, 'GO PROSE')).toBe('GO PROSE');
    });
});

describe('the evidence terms', () => {
    it('reads the diagnostics vocabulary as phrases, in both languages', () => {
        expect(termText(en, 'tcp_reset')).toBe('Connection blocked');
        expect(termText(fa, 'tcp_reset')).toMatch(/[؀-ۿ]/);
        expect(termText(fa, 'tcp_reset')).not.toBe(termText(en, 'tcp_reset'));
        expect(termText(fa, 'udp_collapsed')).toMatch(/[؀-ۿ]/);
    });

    // A classification Daal has no phrase for must stay visible as the
    // identifier. Blanking it would hide a failure the operator is
    // being asked to act on.
    it('shows an unknown term as its raw identifier', () => {
        expect(termText(fa, 'some_new_classification')).toBe('some_new_classification');
    });

    it('joins a list without losing the unknown ones', () => {
        const out = termList(fa, ['tcp_reset', 'some_new_classification']);
        expect(out).toContain('some_new_classification');
        expect(out.split(', ')).toHaveLength(2);
    });
});

describe('the rung and confidence names', () => {
    it('names all six rungs in Farsi, and an unknown rung as unknown', () => {
        for (const l of ['L1', 'L2', 'L3', 'L4', 'L5', 'L6']) {
            expect(fa(levelKey(l)), l).toMatch(/[؀-ۿ]/);
        }
        expect(levelKey('L7')).toBe('pub.danger.advice.level.unknown');
        expect(fa(levelKey('L7'))).toMatch(/[؀-ۿ]/);
    });

    // "not sure at all" is the answer on every ungrounded run, so the
    // default arm must not be the confident one.
    it('treats an unrecognised confidence as the least confident', () => {
        expect(confidenceKey('')).toBe('pub.danger.advice.confidence.low');
        expect(confidenceKey('extremely')).toBe('pub.danger.advice.confidence.low');
    });
});
