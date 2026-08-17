// RouteHealthBars — last-hour health for each known route.
import type { Locale } from '../../lib/i18n';
import type { RouteHealthDisplayRow } from '../../contract/D2Contract';
import { HealthBar, NumeralSpan } from '../atoms';

interface Props {
    rows: RouteHealthDisplayRow[];
    locale: Locale;
    t: (k: string) => string;
}

export default function RouteHealthBars({ rows, locale, t }: Props) {
    return (
        <div className="d2-rail-section">
            <h3>{t('route_health')}</h3>
            {rows.length === 0 && (
                <div style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                    {t('health.no_data')}
                </div>
            )}
            {rows.map((r) =>
                // Honest render: with no measured percentage there is
                // nothing to draw a bar from, so show "not tested yet"
                // rather than a bar + % that looks measured. `pct` is
                // now absent (rather than a fabricated 0) whenever the
                // engine has recorded no outcome for the route, so the
                // presence test is the primary branch and `proven`
                // remains as the coarser backstop.
                r.pct === undefined || r.proven === false ? (
                    <div className="d2-health-row" key={r.routeId}>
                        <span className="name">{r.label}</span>
                        <span
                            className="pct"
                            style={{ color: 'var(--ink-soft)', fontSize: 12 }}
                        >
                            {t('network.untested')}
                        </span>
                    </div>
                ) : (
                    <div className="d2-health-row" key={r.routeId}>
                        <span className="name">{r.label}</span>
                        <HealthBar pct={r.pct} severity={r.severity} />
                        <span className="pct">
                            <NumeralSpan locale={locale}>
                                {Math.round(r.pct)}
                            </NumeralSpan>
                            %
                        </span>
                    </div>
                ),
            )}
        </div>
    );
}
