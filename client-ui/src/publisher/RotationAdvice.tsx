// RotationAdvice — Wave 6. The rotation recommender, given a caller.
//
// WHY IT HAD NONE
//
// `publisher/deploy/rotation/recommender.go`, the Tauri command
// `wizard_rotate_recommend` and the TS wrapper `Wizard.rotateRecommend`
// have all existed since FRP-7 and **no component ever called any of
// them**. Worse, two of the three inputs the recommender reads had no
// producer anywhere in the tree, so had a component called it, every
// real run would have fallen through the rule list and answered
// "L1, confidence low" whatever was actually wrong.
//
// The two halves were fixed together, and neither is any use alone:
//
//   * core/abi now projects the durable per-route failure columns onto
//     `Explanation.failures` (they were `[]` in every blob this app has
//     ever emitted), so a recorded `tcp_reset` reaches the recommender
//     as a `tcp_reset`.
//   * the recommender now says "I don't know" out loud instead of
//     answering L1 in a sentence that reads like advice.
//
// WHAT THIS SCREEN MUST NOT DO
//
// It must not rotate anything. Three of the six rungs DESTROY the
// server and rebuild it — new address, new keys, and every file ever
// handed out dead — and provisioning has no rollback, so a failed
// rebuild can leave a second billing server behind. Advice next to a
// button that acts on it is how that happens by accident. Every rung on
// this page is pressed deliberately, below; this panel only tells the
// operator which one to read first.
//
// WHERE THE EVIDENCE COMES FROM, STATED PLAINLY
//
// From THIS computer's own engine — the failures it recorded while
// connecting, in the hour-bucketed, closed-vocabulary form
// `routestore.RecordFailure` writes. That is real measurement, and it
// is also NOT scoped to this relay: the engine records outcomes for
// every route this device holds, and nothing in the store maps a route
// back to the operator record on this page. So the panel says whose
// observations these are rather than implying the relay was surveyed.
// A recipient in the field who is actually being blocked is not
// visible here at all; their diagnostics have to reach the operator by
// hand, which is what the recommender's `context` path is for.
//
// And the absences are rendered, not swallowed. Four of the nine
// network signals have no prober, and the cooldown-tag vocabulary the
// destroy-and-rebuild rungs key off has no producer at all. Showing
// only what was observed would turn "never measured" into "checked and
// fine", which is the exact failure this whole lane exists to remove.
//
// WHY THE SUBSTANCE IS KEYED AND NOT PRINTED
//
// Everything decisive on this screen is computed in Go, and Go builds
// it in English. This is a D-2 surface that ships in Farsi, so printing
// it gave a Farsi operator a translated frame around untranslated
// content — the frame being the part that says "here is some advice"
// and the content being the advice. The reason, the recommendation's
// evidence terms and the named absences each arrive with a stable code
// beside the prose, and each is rendered through a helper that keys the
// code and falls back to the prose. A rule or an absence added in Go
// and not yet in a catalog therefore degrades to an English sentence,
// never to a blank or a bare key.
//
// TWO THINGS ARE DELIBERATELY NOT TRANSLATED, and both would be wrong
// to translate:
//
//   * `est_wallclock` — a figure the recommender computed, which
//     overrides the optimistic column when the same outcome needs a
//     rebuild. See the comment at its render site.
//   * `evidence.unrecognised` — the inputs that were present and that
//     NO rung consumes. An unrecognised input is by definition one Daal
//     has no sentence for; giving it a Farsi phrase would claim an
//     understanding the recommender has just finished disclaiming. The
//     sentence around the list is translated, the identifiers inside it
//     are not, and that is the honest split.

import { useCallback, useEffect, useState } from 'react';
import { Wizard } from './wizardCommands';
import type { RotationRecommendation } from './wizardCommands';
import { diagnosticsExplain } from '../lib/bridge';
import { ListRow, Button, Card } from '../design/primitives';
// The text layer lives next door so it can be tested without a
// renderer. Every lookup in it keys a Go-emitted code and falls back to
// the Go prose; see adviceText.ts for why that shape is load-bearing.
import {
    absentText,
    confidenceKey,
    levelKey,
    reasonText,
    termList,
} from './adviceText';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    /** Bumped by the parent after anything that could change the
     *  relay's situation, so the advice does not go stale on screen. */
    reloadToken?: number;
}

const BODY: React.CSSProperties = {
    fontSize: 13,
    color: 'var(--fg)',
    lineHeight: 1.55,
};
const MUTED: React.CSSProperties = { ...BODY, color: 'var(--muted)', fontSize: 12 };

export function RotationAdvice({ t, operatorId, reloadToken }: Props) {
    const [rec, setRec] = useState<RotationRecommendation | null>(null);
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);
    const [shown, setShown] = useState(false);

    const load = useCallback(async () => {
        setBusy(true);
        setErr(null);
        try {
            // The recipient-diagnostics path, fed by this device's own
            // engine. `diagnosticsExplain` returns the parsed blob; the
            // recommender wants the JSON text, and it tolerates an
            // empty body (which is what an engine that has not started
            // yet produces) by returning its no-evidence answer — which
            // is the right answer for "we could not look".
            let explanation = '';
            try {
                explanation = JSON.stringify(await diagnosticsExplain());
            } catch {
                // Engine not up. Deliberately NOT an error: the
                // recommendation that comes back says it saw nothing,
                // which is true and is more useful than a red box.
                explanation = '';
            }
            const out = await Wizard.rotateRecommend(operatorId, {
                mode: 'explanation',
                explanation_json: explanation,
            });
            setRec(out);
            setShown(true);
        } catch (e) {
            setErr(String(e));
        } finally {
            setBusy(false);
        }
    }, [operatorId]);

    // Refresh what is already on screen when the relay changes under
    // it; never open by itself.
    useEffect(() => {
        if (shown) void load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [reloadToken]);

    const grounded = rec?.grounded === true;
    const ev = rec?.evidence;

    return (
        <>
            <ListRow
                title={t('pub.danger.advice.title')}
                subtitle={t('pub.danger.advice.body')}
                trailing={
                    <Button
                        variant="secondary"
                        onClick={(e) => {
                            e.stopPropagation();
                            void load();
                        }}
                        disabled={busy}
                    >
                        {busy
                            ? t('pub.danger.advice.working')
                            : t('pub.danger.advice.action')}
                    </Button>
                }
            />

            {err && (
                <div style={{ padding: '0 14px 12px', color: 'var(--red)', fontSize: 12 }}>
                    {err}
                </div>
            )}

            {rec && (
                <div style={{ padding: '0 14px 14px', display: 'grid', gap: 10 }}>
                    <Card raised>
                        <div style={{ display: 'grid', gap: 10 }}>
                            {/* THE HEADLINE. When the recommender is not
                                grounded there is no rung here at all —
                                printing "L1" with a caveat underneath is
                                how a caveat gets skipped. */}
                            {grounded ? (
                                <div style={{ ...BODY, fontWeight: 600 }}>
                                    {t('pub.danger.advice.suggests').replace(
                                        '{rung}',
                                        t(levelKey(rec.level)),
                                    )}
                                </div>
                            ) : (
                                <div style={{ ...BODY, fontWeight: 600, color: 'var(--red)' }}>
                                    {t('pub.danger.advice.unknown.title')}
                                </div>
                            )}

                            <div style={BODY}>{reasonText(t, rec)}</div>

                            {grounded && (
                                <>
                                    {/* The wall-clock string comes from
                                        the recommender VERBATIM. It
                                        deliberately overrides the
                                        optimistic column when the relay
                                        can only reach the same outcome
                                        by destroy-and-rebuild, and a
                                        table on this side would quote 90
                                        seconds for a 3-minute rebuild —
                                        the dial-that-lies this project
                                        spent a step removing. */}
                                    <div style={MUTED}>
                                        {t('pub.danger.advice.time').replace(
                                            '{time}',
                                            rec.est_wallclock,
                                        )}
                                    </div>
                                    <div style={MUTED}>
                                        {t('pub.danger.advice.confidence').replace(
                                            '{level}',
                                            t(confidenceKey(rec.confidence)),
                                        )}
                                    </div>
                                    {rec.action?.destroys_server && (
                                        <div style={{ ...BODY, color: 'var(--red)' }}>
                                            {t('pub.danger.advice.destroys')}
                                        </div>
                                    )}
                                    {rec.action &&
                                        rec.action.availability !== 'ready' && (
                                            <div style={MUTED}>
                                                {t('pub.danger.advice.unverified')}
                                            </div>
                                        )}
                                </>
                            )}

                            {/* The override list. Alternatives the
                                operator may pick instead — read-only on
                                purpose. Turning these into buttons would
                                put a one-tap rebuild next to a sentence
                                that was never a decision. */}
                            {grounded && (rec.override ?? []).length > 0 && (
                                <div style={MUTED}>
                                    {t('pub.danger.advice.override').replace(
                                        '{rungs}',
                                        (rec.override ?? [])
                                            .map((l) => t(levelKey(l)))
                                            .join(', '),
                                    )}
                                </div>
                            )}

                            {/* WHAT WAS SEEN. */}
                            <div style={MUTED}>
                                {ev && ev.classifications.length > 0
                                    ? t('pub.danger.advice.saw').replace(
                                          '{list}',
                                          termList(t, ev.classifications),
                                      )
                                    : t('pub.danger.advice.saw_nothing')}
                            </div>
                            {ev && ev.signals.length > 0 && (
                                <div style={MUTED}>
                                    {t('pub.danger.advice.signals').replace(
                                        '{list}',
                                        termList(t, ev.signals),
                                    )}
                                </div>
                            )}
                            {ev && ev.unrecognised.length > 0 && (
                                <div style={MUTED}>
                                    {t('pub.danger.advice.unrecognised').replace(
                                        '{list}',
                                        ev.unrecognised.join('; '),
                                    )}
                                </div>
                            )}

                            {/* WHAT COULD NOT BE SEEN. Rendered every
                                time, including on a confident answer:
                                the rungs that never fire because nothing
                                produces their evidence are not rungs the
                                operator has ruled out. */}
                            {ev && ev.absent.length > 0 && (
                                <div style={{ display: 'grid', gap: 4 }}>
                                    <div style={{ ...MUTED, fontWeight: 600 }}>
                                        {t('pub.danger.advice.absent.title')}
                                    </div>
                                    {ev.absent.map((a, i) => (
                                        <div key={i} style={MUTED}>
                                            • {absentText(t, ev.absent_codes?.[i], a)}
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Whose observations these are. */}
                            <div style={MUTED}>{t('pub.danger.advice.scope')}</div>
                            <div style={{ ...MUTED, fontWeight: 600 }}>
                                {t('pub.danger.advice.advice_only')}
                            </div>
                        </div>
                    </Card>
                </div>
            )}
        </>
    );
}
