// StatusLine — mono one-liner under the route chip.
// Format from HTML: "On Wi-Fi · using rotated pointers · valid 14 days"
import type { Locale } from '../../lib/i18n';
import { NumeralSpan } from '../atoms';

interface Props {
    locale: Locale;
    t: (k: string) => string;
    networkLabel?: string;
    pointerValidDays?: number;
}

export default function StatusLine({ locale, t, networkLabel, pointerValidDays }: Props) {
    const parts: React.ReactNode[] = [];
    if (networkLabel) parts.push(<span key="net">{networkLabel}</span>);
    parts.push(<span key="ptr">{t('status_pointers')}</span>);
    if (typeof pointerValidDays === 'number' && pointerValidDays > 0) {
        parts.push(
            <span key="valid">
                {t('status_valid_pre')}{' '}
                <NumeralSpan locale={locale}>{pointerValidDays}</NumeralSpan>
                {' '}{t('status_valid_post')}
            </span>
        );
    }
    return (
        <div className="d2-conn-status-line">
            {parts.map((p, i) => (
                <span key={i}>
                    {i > 0 && ' · '}
                    {p}
                </span>
            ))}
        </div>
    );
}
