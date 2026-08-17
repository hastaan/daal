// WhyThisRoute — right-rail "Why this route?" panel.
import type { WhyThisRouteSummary } from '../../contract/D2Contract';

interface Props {
    data: WhyThisRouteSummary | null;
    t: (k: string) => string;
    /** Skip the eyebrow + heading. Used when the panel is nested
     *  inside a disclosure that already supplies its own header. */
    headless?: boolean;
}

export default function WhyThisRoute({ data, t, headless }: Props) {
    return (
        <div className="d2-rail-section">
            {!headless && (
                <>
                    <div className="d2-rail-title">{t('rail_diagnostic')}</div>
                    <h3>{t('why_this_route')}</h3>
                </>
            )}
            {!data && (
                <div style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                    {t('why.no_data')}
                </div>
            )}
            {data && (
                <>
                    <div className="d2-why-row">
                        <span className="k">{t('active')}</span>
                        <span className="v">
                            {data.active.publisherName} · {data.active.routeNickname}
                        </span>
                    </div>
                    <div className="d2-why-row">
                        <span className="k">{t('reason')}</span>
                        <span className="v">{data.reasonText || t('reason_text')}</span>
                    </div>
                    {/* Three distinct states, and the user can tell them
                        apart. null = the selector never compared the
                        other routes (today's reality — see the note on
                        WhyThisRouteSummary.skipped); [] = it compared
                        them and rejected none; non-empty = the list. The
                        old code rendered null and [] identically, as
                        nothing at all, so a broken comparison looked
                        exactly like a clean one. */}
                    {data.skipped === null ? (
                        <div className="d2-why-row">
                            <span className="k">{t('skipped')}</span>
                            <span className="v" style={{ color: 'var(--ink-soft)' }}>
                                {t('skipped.not_evaluated')}
                            </span>
                        </div>
                    ) : data.skipped.length === 0 ? (
                        <div className="d2-why-row">
                            <span className="k">{t('skipped')}</span>
                            <span className="v">{t('skipped.none')}</span>
                        </div>
                    ) : (
                        <div className="d2-why-row">
                            <span className="k">{t('skipped')}</span>
                            <span className="v">
                                <ul className="d2-skip-list">
                                    {data.skipped.map((s) => (
                                        <li key={s.route.routeId}>
                                            <span>
                                                {s.route.publisherName} · {s.route.routeNickname}
                                            </span>
                                            <span className="reason">— {s.reason}</span>
                                        </li>
                                    ))}
                                </ul>
                            </span>
                        </div>
                    )}
                    {/* Family cooldowns ARE measured (the path manager
                        writes them), so they render as a plain fact
                        alongside the unevaluated per-route list. */}
                    {data.skippedFamilies && data.skippedFamilies.length > 0 && (
                        <div className="d2-why-row">
                            <span className="k">{t('skipped_families')}</span>
                            <span className="v">
                                <ul className="d2-skip-list">
                                    {data.skippedFamilies.map((f) => (
                                        <li key={f.family}>
                                            <span>{f.family}</span>
                                            {f.reasonTag && (
                                                <span className="reason">— {f.reasonTag}</span>
                                            )}
                                        </li>
                                    ))}
                                </ul>
                            </span>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
