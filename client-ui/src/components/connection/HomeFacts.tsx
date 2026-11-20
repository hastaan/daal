// HomeFacts — what Daal knows about the connection, as short icon rows.
//
// Connected: one card under the bird on a phone (beside it on a
// computer): why this way, the network, live speed, quality. Each row
// is ONE short line and is drawn only when the engine sent its fact
// (lib/homeFacts.ts decides; this file draws). A "Details" fold at the
// bottom of the card lists every way on the device ONCE: its kind, one
// state disc, one status line, and its score over the last hour as a
// small bar.
//
// Also here: the step dots under "Trying VLESS Reality · 2 of 4", the
// kind chips under "Tap to connect" (with the same state dot as the
// Files tab), and the list of tries under a failed connect, by kind of
// connection and in plain words.
import type { CSSProperties, ReactNode } from 'react';
import { Badge, Disclosure, Icon, StateIcon } from '../../design/primitives';
import type { IconName } from '../../design/primitives';
import type { ConnectedFacts, ReadyKind, TriedRow, TryingFact, WayRow } from '../../lib/homeFacts';

type T = (k: string) => string;

const NET_ICON: Record<string, IconName> = {
    wifi: 'wifi',
    cellular: 'signal',
    ethernet: 'globe',
    other: 'globe',
};

/** How a kind did here, as the chip's dot (the Files tab's colours). */
export type ChipMark = 'good' | 'warn' | 'bad' | 'none';

const MARK_COLOR: Record<ChipMark, string | undefined> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    none: undefined,
};

const MARK_KEY: Record<ChipMark, string> = {
    good: 'files.state.works',
    warn: 'network.resting',
    bad: 'files.state.failing',
    none: 'measure.grade.unknown',
};

/** A kind of connection, as a small chip: "VLESS Reality". Latin names
 *  read left to right inside Persian text too. The same quiet pill as
 *  the Files tab's family tags (components/files/FileParts.tsx); with a
 *  `mark`, the same state dot in front. */
export function FamilyChip({
    name,
    mark,
    t,
    strong,
    tag,
}: {
    name: string;
    mark?: ChipMark;
    /** Needed with `mark` (the dot's words for screen readers). */
    t?: T;
    /** The first of the row: the kind Daal tries first. */
    strong?: boolean;
    /** A small word after the name ("Experimental"). */
    tag?: string;
}) {
    const color = mark ? MARK_COLOR[mark] : undefined;
    const label = mark && t ? `${name} · ${t(MARK_KEY[mark])}` : undefined;
    // Never squeezed: a name cut to "…steria 2" is no name.
    return (
        <span
            {...(label ? { role: 'img', 'aria-label': label, title: label } : {})}
            data-chip-mark={mark}
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                flexShrink: 0,
                maxWidth: '100%',
                height: strong ? 28 : 24,
                paddingInline: strong ? 11 : 9,
                borderRadius: 'var(--r-pill)',
                background: 'var(--surface-2)',
                border: strong ? '1px solid var(--green)' : '1px solid var(--line-soft)',
                color: 'var(--fg)',
                fontSize: strong ? 13 : 12,
                fontWeight: strong ? 600 : 500,
                whiteSpace: 'nowrap',
                lineHeight: 1,
                boxSizing: 'border-box',
            }}
        >
            {mark && (
                <span
                    aria-hidden
                    style={{
                        width: 7,
                        height: 7,
                        borderRadius: '50%',
                        flexShrink: 0,
                        boxSizing: 'border-box',
                        background: color ?? 'transparent',
                        border: color ? 'none' : '1.5px solid var(--dim)',
                    }}
                />
            )}
            <bdi dir="ltr" style={{ lineHeight: 1.6 }}>{name}</bdi>
            {tag && <span style={{ color: 'var(--amber)', fontSize: 11, fontWeight: 600 }}>{tag}</span>}
        </span>
    );
}

/** The kinds under "Tap to connect", in the order Daal tries them. */
export function ReadyChips({ t, kinds, more, moreText }: { t: T; kinds: readonly ReadyKind[]; more: number; moreText: string }) {
    return (
        <div
            data-testid="ready-kinds"
            style={{ display: 'flex', gap: 6, justifyContent: 'center', alignItems: 'center', flexWrap: 'wrap', marginBlockStart: 12, maxWidth: 420 }}
        >
            {kinds.map((k, i) => (
                <FamilyChip
                    key={k.name}
                    t={t}
                    name={k.name}
                    mark={k.mark}
                    strong={i === 0 && k.mark === 'good'}
                    tag={k.experimental ? t('files.way.experimental') : undefined}
                />
            ))}
            {more > 0 && (
                <Badge tone="neutral" size="sm">
                    {moreText}
                </Badge>
            )}
        </div>
    );
}

function FactRow({
    icon,
    label,
    children,
    first,
    testId,
}: {
    icon: IconName;
    label: string;
    children: ReactNode;
    first?: boolean;
    testId: string;
}) {
    return (
        <div
            data-testid={testId}
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                minHeight: 44,
                paddingBlock: 6,
                boxSizing: 'border-box',
                borderBlockStart: first ? undefined : '1px solid var(--line-soft)',
                fontSize: 14,
            }}
        >
            <span aria-hidden style={{ color: 'var(--muted)', display: 'inline-flex', flexShrink: 0 }}>
                <Icon name={icon} size={18} />
            </span>
            <span style={{ color: 'var(--muted)', flexShrink: 0 }}>{label}</span>
            {/* The value wraps rather than cutting itself short: a
                Persian "connected in 0.6 s" beside a badge does not fit a
                320 px card on one line. */}
            <span
                style={{
                    marginInlineStart: 'auto',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                    flexWrap: 'wrap',
                    columnGap: 8,
                    rowGap: 4,
                    minWidth: 0,
                    color: 'var(--fg)',
                    textAlign: 'end',
                }}
            >
                {children}
            </span>
        </div>
    );
}

const ellipsis = {
    minWidth: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
} as const;

interface CardProps {
    t: T;
    facts: ConnectedFacts;
    /** The "Way" row (the computer's panel; on a phone the line under
     *  "Connected" already names the way). */
    showWay?: boolean;
    /** A title on top ("This connection"). */
    title?: string;
    /** The Details fold, and anything else, at the bottom. */
    children?: ReactNode;
    style?: CSSProperties;
}

/** The card of facts while connected. Nothing at all when the engine
 *  sent none of them. */
export function HomeFactsCard({ t, facts, showWay, title, children, style }: CardProps) {
    const { way, why, network, speed, quality } = facts;
    const rows: { id: string; node: (first: boolean) => ReactNode }[] = [];
    if (showWay && way && (way.family || way.routeName)) {
        rows.push({
            id: 'way',
            node: (first) => (
                <FactRow key="way" icon="route" label={t('home.fact.way')} first={first} testId="fact-way">
                    {way.routeName && <bdi style={{ ...ellipsis, color: 'var(--muted)' }}>{way.routeName}</bdi>}
                    {way.family && <FamilyChip name={way.family} />}
                </FactRow>
            ),
        });
    }
    if (network) {
        rows.push({
            id: 'network',
            node: (first) => (
                <FactRow key="network" icon={NET_ICON[network.kind]} label={t('home.fact.network')} first={first} testId="fact-network">
                    <span style={ellipsis}>{network.text}</span>
                </FactRow>
            ),
        });
    }
    if (speed) {
        rows.push({
            id: 'speed',
            node: (first) => (
                <FactRow key="speed" icon="updown" label={t('home.fact.speed')} first={first} testId="fact-speed">
                    {/* Download first in the reading order of the page (on
                        the right in Persian); each figure isolated so its
                        digits and unit keep their own order. */}
                    <span style={{ display: 'inline-flex', gap: 12, fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
                        <bdi dir="ltr" aria-label={`${t('home.fact.down')}: ${speed.down}`}>
                            <span aria-hidden style={{ color: 'var(--green)' }}>↓</span> {speed.down}
                        </bdi>
                        <bdi dir="ltr" aria-label={`${t('home.fact.up')}: ${speed.up}`} style={{ color: 'var(--muted)' }}>
                            <span aria-hidden>↑</span> {speed.up}
                        </bdi>
                    </span>
                </FactRow>
            ),
        });
    }
    if (quality) {
        rows.push({
            id: 'quality',
            node: (first) => (
                <FactRow key="quality" icon="speed" label={t('home.fact.quality')} first={first} testId="fact-quality">
                    {quality.setup && <span style={{ color: 'var(--muted)', fontSize: 13 }}>{quality.setup}</span>}
                    <Badge tone={quality.tone} size="sm">
                        {quality.label}
                    </Badge>
                </FactRow>
            ),
        });
    }
    if (!why && rows.length === 0 && !children) return null;
    return (
        <section
            className="d2-home-facts"
            data-testid="home-facts"
            style={{
                background: 'var(--surface)',
                borderRadius: 'var(--r-card)',
                padding: '6px 16px 4px',
                inlineSize: '100%',
                boxSizing: 'border-box',
                textAlign: 'start',
                ...style,
            }}
        >
            {title && (
                <h2
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 'var(--fs-lg)',
                        fontWeight: 600,
                        margin: '10px 0 4px',
                    }}
                >
                    {title}
                </h2>
            )}
            {why && (
                <div
                    data-testid="fact-why"
                    data-why={why.token}
                    style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: 12,
                        padding: '12px 0',
                        fontSize: 14,
                        lineHeight: 1.45,
                        color: 'var(--fg)',
                    }}
                >
                    <span aria-hidden style={{ color: 'var(--gold-warm)', display: 'inline-flex', flexShrink: 0, marginBlockStart: 1 }}>
                        <Icon name="bulb" size={18} />
                    </span>
                    <span aria-label={`${t('home.fact.why')}: ${why.text}`}>{why.text}</span>
                </div>
            )}
            {rows.map((r, i) => r.node(i === 0 && !why))}
            {children}
        </section>
    );
}

/** The dots under "Trying …": one per way, the ones tried dim, the one
 *  (or two) being tried now lit. Only when the engine said where it is. */
export function TryingSteps({ fact }: { fact: TryingFact }) {
    if (fact.index === undefined || fact.total === undefined) return null;
    const dots = [];
    for (let k = 1; k <= fact.total; k++) {
        const now = k === fact.index || (fact.racing && k === fact.index + 1);
        const done = k < fact.index;
        dots.push(
            <span
                key={k}
                className={now ? 'd2-step-now' : undefined}
                style={{
                    inlineSize: now ? 18 : 8,
                    blockSize: 8,
                    borderRadius: 999,
                    background: now ? 'var(--gold-warm)' : done ? 'var(--dim)' : 'transparent',
                    border: now || done ? undefined : '1.5px solid var(--line)',
                    boxSizing: 'border-box',
                    transition: 'inline-size var(--t-base)',
                }}
            />,
        );
    }
    return (
        <div aria-hidden data-testid="trying-steps" style={{ display: 'flex', gap: 6, justifyContent: 'center', marginBlockStart: 10 }}>
            {dots}
        </div>
    );
}

/** The tries of one pass, by kind, with the plain reason for each. */
export function TriedList({ rows }: { rows: readonly TriedRow[] }) {
    return (
        <ul data-testid="tried-list" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 10 }}>
            {rows.map((x) => (
                <li key={x.key} data-tried-glyph={x.glyph} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 14, textAlign: 'start' }}>
                    <span style={{ marginBlockStart: 2, flexShrink: 0 }}>
                        <StateIcon state={x.glyph} size={18} />
                    </span>
                    <span style={{ minWidth: 0, display: 'grid', gap: 2 }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                            <FamilyChip name={x.family} />
                            {x.name && <bdi style={{ color: 'var(--muted)', fontSize: 13 }}>{x.name}</bdi>}
                        </span>
                        <span style={{ color: 'var(--muted)', fontSize: 13, lineHeight: 1.45 }}>{x.reason}</span>
                    </span>
                </li>
            ))}
        </ul>
    );
}

/** A score as a short bar and its number: "▬▬▬▭ 96%". */
export function ScoreBar({ pct, label, locale }: { pct: number; label: string; locale: string }) {
    const color = pct >= 70 ? 'var(--green)' : pct >= 40 ? 'var(--amber)' : 'var(--red)';
    const n = locale === 'fa' ? String(pct).replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]) : String(pct);
    return (
        <span role="img" aria-label={label} title={label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <span aria-hidden style={{ inlineSize: 36, blockSize: 4, borderRadius: 2, background: 'var(--surface-3)', overflow: 'hidden', display: 'block' }}>
                <span style={{ display: 'block', blockSize: '100%', inlineSize: `${Math.max(4, pct)}%`, background: color, borderRadius: 2 }} />
            </span>
            <span aria-hidden style={{ fontSize: 12, color: 'var(--muted)', fontVariantNumeric: 'tabular-nums', minInlineSize: 30, textAlign: 'end' }}>
                {locale === 'fa' ? `٪${n}` : `${n}%`}
            </span>
        </span>
    );
}

/** Every way on the device, once each: disc, kind, one status line,
 *  score. Shared by the Details fold and the computer's ready panel. */
export function WayList({ t, locale, ways, title }: { t: T; locale: string; ways: readonly WayRow[]; title?: string }) {
    const scored = ways.some((w) => w.scorePct !== undefined);
    return (
        <div data-testid="way-list">
            {(title || scored) && (
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, margin: '4px 0 8px' }}>
                    {title && <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--muted)' }}>{title}</span>}
                    {scored && (
                        <span style={{ marginInlineStart: 'auto', fontSize: 12, color: 'var(--dim)' }}>{t('home.details.score_hour')}</span>
                    )}
                </div>
            )}
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 10 }}>
                {ways.map((w) => (
                    <li
                        key={w.routeId}
                        data-way-row={w.state}
                        style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 13 }}
                    >
                        <span style={{ marginBlockStart: 4, flexShrink: 0 }}>
                            <StateIcon state={w.state} size={16} label={w.status} />
                        </span>
                        <span style={{ minWidth: 0, flex: 1, display: 'grid', gap: 2 }}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                                <FamilyChip name={w.family} />
                                {w.name && <bdi style={{ color: 'var(--muted)' }}>{w.name}</bdi>}
                            </span>
                            {w.status && (
                                <span style={{ color: w.active ? 'var(--green)' : 'var(--muted)', lineHeight: 1.45 }}>{w.status}</span>
                            )}
                        </span>
                        {w.scorePct !== undefined && (
                            <span style={{ marginBlockStart: 6 }}>
                                <ScoreBar
                                    pct={w.scorePct}
                                    locale={locale}
                                    label={`${t('files.way.facts.score')}: ${t('files.way.facts.score_value').replace('{n}', String(w.scorePct))}`}
                                />
                            </span>
                        )}
                    </li>
                ))}
            </ul>
        </div>
    );
}

interface DetailsProps {
    t: T;
    locale: string;
    ways: readonly WayRow[];
    /** "Ways on this phone" / "Ways on this device". */
    title: string;
}

/** The fold at the bottom of the card. Not drawn when it would be
 *  empty. */
export function HomeDetails({ t, locale, ways, title }: DetailsProps) {
    if (ways.length === 0) return null;
    return (
        <div style={{ borderBlockStart: '1px solid var(--line-soft)' }}>
            <Disclosure summary={t('ui.details')} dataButton="home-details">
                <div style={{ paddingBlockEnd: 12, textAlign: 'start' }}>
                    <WayList t={t} locale={locale} ways={ways} title={title} />
                </div>
            </Disclosure>
        </div>
    );
}
