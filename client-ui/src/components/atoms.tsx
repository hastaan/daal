// D-2.1 atomic components shared across pages.
//
// Each atom is one job, one file would be premature; we co-locate them
// here so the Connection page (and others) can `import { NumeralSpan,
// BrandMark, TrustBadge } from '../components/atoms'`.

import type { Locale } from '../lib/i18n';
import { toFaDigits } from '../lib/i18n';
import daalFlatSvg from '@branding/sources/daal-eagle.svg';
import daal3dDesktop from '@branding/sources/daal-eagle-transparent.png';

/** NumeralSpan — wraps numeric content; converts to Persian digits when locale is fa. */
export function NumeralSpan({
    locale,
    children,
    className,
}: {
    locale: Locale;
    children: string | number;
    className?: string;
}) {
    const s = String(children);
    const out = locale === 'fa' ? toFaDigits(s) : s;
    return <span className={(className ? className + ' ' : '') + 'num'}>{out}</span>;
}

/** BrandMark — picks the correct Daal asset variant per surface. */
export function BrandMark({
    size = 'sidebar',
    style,
    alt = 'Daal',
}: {
    size?: 'sidebar' | 'tray' | 'hero' | number;
    style?: React.CSSProperties;
    alt?: string;
}) {
    if (size === 'hero') {
        return (
            <img
                src={daal3dDesktop}
                alt={alt}
                style={{ width: 220, height: 220, objectFit: 'contain', ...style }}
            />
        );
    }
    const px = typeof size === 'number' ? size : size === 'tray' ? 24 : 36;
    return (
        <img
            src={daalFlatSvg}
            alt={alt}
            style={{ width: px, height: px, objectFit: 'contain', ...style }}
        />
    );
}

/** TrustBadge — colored uppercase mono pill matching the design's `.trust-badge`. */
export type TrustClass = 'trusted' | 'pinned' | 'lan' | 'unknown';
export function TrustBadge({
    trustClass,
    label,
}: {
    trustClass: TrustClass;
    label: string;
}) {
    return <span className={`d2-trust-badge ${trustClass}`}>{label}</span>;
}

/** Eyebrow — mono uppercase letter-spaced 0.18em label (gold-warm). */
export function Eyebrow({ children }: { children: React.ReactNode }) {
    return <div className="d2-eyebrow">{children}</div>;
}

/** Kbd — keyboard hint, e.g. ⌘K, ⌘D. */
export function Kbd({ children }: { children: React.ReactNode }) {
    return <kbd className="d2-kbd">{children}</kbd>;
}

/** HealthBar — colored bar showing 0..100% health. */
export type Severity = 'ok' | 'warn' | 'bad';
export function HealthBar({
    pct,
    severity,
}: {
    pct: number;
    severity?: Severity;
}) {
    const sev = severity ?? (pct >= 80 ? 'ok' : pct >= 50 ? 'warn' : 'bad');
    const cls = sev === 'ok' ? '' : sev === 'warn' ? 'warn' : 'bad';
    const clamped = Math.max(0, Math.min(100, pct));
    return (
        <span className={`d2-health-bar ${cls}`}>
            <span style={{ width: `${clamped}%` }} />
        </span>
    );
}
