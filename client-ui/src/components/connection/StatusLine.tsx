// StatusLine — mono one-liner under the route chip.
// Format from HTML: "On Wi-Fi · using rotated pointers · valid 14 days"
import type { Locale } from '../../lib/i18n';
import type { PointerSource } from '../../contract/D2Contract';
import { NumeralSpan } from '../atoms';

interface Props {
    locale: Locale;
    t: (k: string) => string;
    networkLabel?: string;
    pointerSource?: PointerSource;
    pointerValidDays?: number;
}

export default function StatusLine({
    locale,
    t,
    networkLabel,
    pointerSource,
    pointerValidDays,
}: Props) {
    const parts: React.ReactNode[] = [];
    if (networkLabel) parts.push(<span key="net">{networkLabel}</span>);
    // "using rotated pointers" used to be pushed unconditionally, on a
    // line that is supposed to be a factual status read-out. Most
    // devices are on the pointers compiled into the binary and have
    // rotated nothing. Say which set is in play, and say nothing at all
    // when the engine did not report one.
    if (pointerSource === 'persisted') {
        parts.push(<span key="ptr">{t('status_pointers')}</span>);
    } else if (pointerSource === 'embedded') {
        parts.push(<span key="ptr">{t('status_pointers_embedded')}</span>);
    }
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
