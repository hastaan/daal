// RouteChip — clickable route label + trust pill. Opens the route picker.
import { TrustBadge } from '../atoms';
import type { RouteDisplayRow } from '../../contract/D2Contract';

interface Props {
    row?: RouteDisplayRow;
    locale: 'en' | 'fa';
    t: (k: string) => string;
    onClick: () => void;
    disabled?: boolean;
}

export default function RouteChip({ row, t, onClick, disabled }: Props) {
    const label = row
        ? `${row.publisherName} · ${row.routeNickname}`
        : t('conn.no_route');
    const trustLabel =
        row?.trustClass === 'trusted' ? t('trust_trusted')
        : row?.trustClass === 'pinned' ? t('trust_pinned')
        : row?.trustClass === 'lan' ? t('trust_lan')
        : t('trust_unknown');
    return (
        <button
            type="button"
            className="d2-conn-route-chip"
            onClick={onClick}
            disabled={disabled}
        >
            <span>{label}</span>
            {row && <TrustBadge trustClass={row.trustClass} label={trustLabel} />}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                 strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="m6 9 6 6 6-6" />
            </svg>
        </button>
    );
}
