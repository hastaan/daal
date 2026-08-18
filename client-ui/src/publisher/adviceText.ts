// adviceText — the advice panel's text layer, extracted so it can be
// tested without a renderer (the same split as rebuildPlan.ts).
//
// EVERY FUNCTION HERE ANSWERS ONE QUESTION: what does a Farsi operator
// read? The recommender computes the whole substance of that panel in
// Go — which rung, why, what was seen, what could not be seen — and Go
// builds it in English. Rendering it gave a Farsi reader a translated
// frame around untranslated content, on a screen where three of the six
// rungs DESTROY the relay and provisioning has no rollback.
//
// So the Go side emits a stable CODE beside each English sentence, and
// every lookup below has the same shape: key the code, and fall back to
// the English prose when the catalog does not carry it. The fallback is
// the designed degradation, not an oversight — a rule or an absence
// added in Go must show up as an English sentence, never as a blank or
// a bare key. `translate` returns the key itself on a total miss, which
// is what makes the miss detectable here instead of silent.

import type { RotationRecommendation } from './wizardCommands';

/** A translator: `t(key)` returns the key itself when neither catalog
 *  carries it, which is what every fallback below tests for. */
export type T = (k: string) => string;

/** Human name for a rung. The Go side has `Level.String()` but it is a
 *  log-line rendering, not translated copy. */
export function levelKey(level: string): string {
    switch (level) {
        case 'L1':
            return 'pub.danger.advice.level.l1';
        case 'L2':
            return 'pub.danger.advice.level.l2';
        case 'L3':
            return 'pub.danger.advice.level.l3';
        case 'L4':
            return 'pub.danger.advice.level.l4';
        case 'L5':
            return 'pub.danger.advice.level.l5';
        case 'L6':
            return 'pub.danger.advice.level.l6';
        default:
            return 'pub.danger.advice.level.unknown';
    }
}

export function confidenceKey(c: string): string {
    switch (c) {
        case 'high':
            return 'pub.danger.advice.confidence.high';
        case 'medium':
            return 'pub.danger.advice.confidence.medium';
        default:
            return 'pub.danger.advice.confidence.low';
    }
}

/**
 * One absence, in the operator's own language where Daal has a
 * sentence for it.
 *
 * The recommender emits English prose plus a stable code per entry. The
 * absences are the half of this panel that carries its honesty — they
 * are what distinguishes "checked and fine" from "never measured" — so
 * they are the last thing that should reach a Farsi reader in English.
 *
 * Falls back to the Go prose when the catalog has no key for the code,
 * which is the intended degradation: a NEW absence must show up as an
 * English sentence, never vanish. `translate` returns the key on a
 * miss, so a miss is detectable rather than silent.
 */
export function absentText(
    t: T,
    code: string | undefined,
    prose: string,
): string {
    if (!code) return prose;
    const key = `pub.danger.advice.absent.${code}`;
    const s = t(key);
    return s === key ? prose : s;
}

/**
 * The recommendation's reason, in the operator's own language.
 *
 * This is the sentence the whole panel is for. It is the substance of
 * the answer — what Daal thinks is wrong and why — and three of the six
 * rungs it can point at DESTROY the relay. An operator deciding whether
 * to rebuild was reading it in English, inside a Farsi frame.
 *
 * Same shape as `absentText`, and for the same reason: the Go side
 * emits a stable code per rule and the English prose beside it, the
 * catalog carries a sentence per code, and a code the catalog does not
 * know falls back to the prose. `{detail}` takes the untranslatable
 * fragment — a provider's note, or the list of inputs that matched no
 * rung — which stays as Go wrote it. A Farsi sentence with an English
 * parenthetical beats an English paragraph.
 */
export function reasonText(
    t: T,
    rec: RotationRecommendation,
): string {
    if (!rec.reason_code) return rec.reason;
    const key = `pub.danger.advice.reason.${rec.reason_code}`;
    const s = t(key);
    if (s === key) return rec.reason;
    return s.replace('{detail}', rec.reason_detail ?? '');
}

/**
 * One evidence term — a classification or a network signal — as a
 * phrase rather than an identifier.
 *
 * These arrive as the closed diagnostics vocabulary (`tcp_reset`,
 * `udp_collapsed`), which is unreadable to most operators in ANY
 * language, and this app has already written that vocabulary out in
 * both languages for the recipient-side cooldown copy. Reuse those
 * keys: a second translation of `tcp_reset` under a publisher-only
 * namespace is a second thing to keep in step, and the two would drift.
 *
 * An unknown term renders as the raw identifier, which is honest — it
 * is exactly what `Evidence.Unrecognised` will also be naming — and
 * keeps a new classification visible instead of blank.
 */
export function termText(t: T, term: string): string {
    const key = `cooldown.${term}`;
    const s = t(key);
    return s === key ? term : s;
}

/** The same, as the comma-joined list the catalog strings interpolate.
 *  `, ` matches how the override rungs are already joined below, in
 *  both languages. */
export function termList(t: T, terms: string[]): string {
    return terms.map((x) => termText(t, x)).join(', ');
}
