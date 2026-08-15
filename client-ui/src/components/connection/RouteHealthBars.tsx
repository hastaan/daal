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
                // Honest render: a route that has never succeeded has only a
                // placeholder health number, so show "not tested yet" rather
                // than a bar + % that looks measured.
                r.proven === false ? (
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
