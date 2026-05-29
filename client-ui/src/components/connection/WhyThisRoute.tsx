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
                    {data.skipped.length > 0 && (
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
                </>
            )}
        </div>
    );
}
