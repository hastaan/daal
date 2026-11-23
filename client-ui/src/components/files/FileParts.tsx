// The Files tab's pieces: the card of one file and the row of one way
// inside it (d2pages/NetworkPage.tsx puts them together).
//
// What they show comes from lib/fileFacts.ts and is only ever what the
// engine sent: the kind of connection of each way ("VLESS Reality"),
// how it did on the network the phone is on now (a state disc and a
// few words), how long it took to connect there, its score as a small
// meter when the engine has one, and whether this build treats the
// kind as experimental or cannot use it at all. Badges and short lines,
// no paragraphs, except the one about the kind inside a way's details.
import { sep } from '../../lib/format';
import type { ReactNode } from 'react';
import type { PublisherTreeRow, RouteDisplayRow } from '../../contract/D2Contract';
import { Badge, Button, Icon, StateIcon } from '../../design/primitives';
import type { BadgeTone } from '../../design/primitives';
import { formatAgo, formatTime } from '../../lib/format';
import type { Locale } from '../../lib/i18n';
import {
    familyAbout,
    fileBadge,
    fileGlyph,
    fileGlyphVariant,
    healthTone,
    localNumber,
    maturityBadgeKey,
    setupText,
    wayGlyph,
    wayStateKey,
    type FamilyTagRow,
    type FileState,
    type WayState,
    type WayTitle,
} from '../../lib/fileFacts';
import { gradeText } from '../../lib/measured';
import { fileTitle, manualOnly, pastedName } from './pasted';

type T = (k: string) => string;

const MARK_COLOR: Record<FamilyTagRow['mark'], string | undefined> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    off: undefined,
    none: undefined,
};

const MARK_KEY: Record<FamilyTagRow['mark'], string | undefined> = {
    good: 'files.state.works',
    warn: 'network.resting',
    bad: 'files.state.failing',
    off: 'files.way.unsupported_short',
    none: undefined,
};

/** One kind of connection on a file card: a dot for how it does here,
 *  its name, and ×n when the file holds several of it. */
export function FamilyTag({ t, locale, tag }: { t: T; locale: Locale; tag: FamilyTagRow }) {
    const color = MARK_COLOR[tag.mark];
    const markKey = MARK_KEY[tag.mark];
    const label = markKey ? `${tag.name} · ${t(markKey)}` : tag.name;
    return (
        <span
            data-family-tag={tag.family}
            data-mark={tag.mark}
            title={label}
            aria-label={label}
            role="img"
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                height: 24,
                paddingInline: 9,
                borderRadius: 'var(--r-pill)',
                background: 'var(--surface-2)',
                border: '1px solid var(--line-soft)',
                color: tag.mark === 'off' ? 'var(--muted)' : 'var(--fg)',
                fontSize: 12,
                fontWeight: 500,
                whiteSpace: 'nowrap',
                lineHeight: 1,
                maxWidth: '100%',
                textDecoration: tag.mark === 'off' ? 'line-through' : undefined,
            }}
        >
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
            <bdi style={{ overflow: 'hidden', textOverflow: 'ellipsis', lineHeight: 1.6 }}>{tag.name}</bdi>
            {tag.count > 1 && (
                <span style={{ color: 'var(--muted)', fontVariantNumeric: 'tabular-nums' }}>
                    ×{localNumber(tag.count, locale)}
                </span>
            )}
        </span>
    );
}

interface FileCardProps {
    t: T;
    locale: Locale;
    p: PublisherTreeRow;
    state: FileState;
    /** "4 ways · Updated 3 minutes ago". */
    summary: string;
    tags: FamilyTagRow[];
    /** For a resting file: when the first way comes back, already as text. */
    restingUntil?: string;
    last: boolean;
    onOpen: () => void;
}

/** One file in the list: state disc, name and state badge, one line of
 *  facts, and the kinds of connection it holds. */
export function FileCard({ t, locale, p, state, summary, tags, restingUntil, last, onOpen }: FileCardProps) {
    const badge = fileBadge(state);
    const badgeText = badge
        ? state === 'resting' && restingUntil
            ? t('files.way.resting_until').replace('{time}', restingUntil)
            : t(badge.key)
        : undefined;
    return (
        <button
            type="button"
            data-button="file-row"
            data-file-state={state}
            className="daal-hover"
            onClick={onOpen}
            style={{
                appearance: 'none',
                display: 'flex',
                // The disc lines up with the name, not with the middle of
                // a three-line card.
                alignItems: 'flex-start',
                gap: 12,
                width: '100%',
                minHeight: 64,
                padding: '12px 0',
                margin: 0,
                background: 'transparent',
                border: 0,
                borderBlockEnd: last ? 'none' : '1px solid var(--line-soft)',
                color: 'inherit',
                font: 'inherit',
                textAlign: 'start',
                cursor: 'pointer',
            }}
        >
            <span style={{ display: 'inline-flex', flexShrink: 0, marginBlockStart: -1 }}>
                <StateIcon state={fileGlyph(state)} variant={fileGlyphVariant(state)} size={22} label={badgeText} />
            </span>
            <span style={{ display: 'grid', gap: 4, flex: 1, minWidth: 0 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flexWrap: 'wrap' }}>
                    <bdi
                        style={{
                            fontWeight: 600,
                            fontSize: 15,
                            color: 'var(--fg)',
                            lineHeight: 1.35,
                            minWidth: 0,
                            overflowWrap: 'anywhere',
                        }}
                    >
                        {fileTitle(t, p)}
                    </bdi>
                    {badge && badgeText && (
                        <Badge tone={badge.tone as BadgeTone} size="sm" icon={false}>
                            {badgeText}
                        </Badge>
                    )}
                </span>
                <span style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.4 }}>{summary}</span>
                {tags.length > 0 && (
                    <span style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBlockStart: 2 }}>
                        {tags.map((tag) => (
                            <FamilyTag key={tag.family} t={t} locale={locale} tag={tag} />
                        ))}
                    </span>
                )}
            </span>
            <span style={{ color: 'var(--muted)', display: 'inline-flex', flexShrink: 0, alignSelf: 'center' }}>
                <Icon name="chevron" size={18} />
            </span>
        </button>
    );
}

/** A score meter: four short bars, filled by the engine's score. */
export function ScoreMeter({ pct, label }: { pct: number; label: string }) {
    const tone = healthTone(pct) ?? 'good';
    const color = tone === 'good' ? 'var(--green)' : tone === 'warn' ? 'var(--amber)' : 'var(--red)';
    const filled = Math.max(1, Math.min(4, Math.ceil((Math.max(0, Math.min(100, pct)) / 100) * 4)));
    return (
        // Signal bars rise to the right in both languages.
        <span role="img" aria-label={label} title={label} dir="ltr" style={{ display: 'inline-flex', alignItems: 'flex-end', gap: 2, height: 12, direction: 'ltr' }}>
            {[0, 1, 2, 3].map((i) => (
                <span
                    key={i}
                    style={{
                        width: 3,
                        height: 5 + i * 2.3,
                        borderRadius: 1,
                        background: i < filled ? color : 'var(--surface-3)',
                    }}
                />
            ))}
        </span>
    );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
    return (
        <>
            <dt style={{ color: 'var(--muted)', fontSize: 12.5, margin: 0 }}>{label}</dt>
            <dd style={{ margin: 0, fontSize: 13, color: 'var(--fg)', minWidth: 0, overflowWrap: 'anywhere' }}>{children}</dd>
        </>
    );
}

interface WayRowProps {
    t: T;
    locale: Locale;
    r: RouteDisplayRow;
    title: WayTitle;
    state: WayState;
    open: boolean;
    onToggle: () => void;
    /** This way is the one the person chose ("Use only this way"). */
    pinned: boolean;
    /** This way is up and the engine chose it (automatic). */
    chosenByDaal: boolean;
    /** A connect from this page is waiting for its answer. */
    busy: boolean;
    /** Another way is connected now: "Use only this way" switches to
     *  this one at once, and says so. */
    otherConnected?: boolean;
    onUseOnly: () => void;
    onBackToAuto: () => void;
    last: boolean;
    /** Developer-mode lines and buttons, under the row. */
    dev?: ReactNode;
}

/** One way of a file: kind, state, setup time, score; a tap opens what
 *  the kind is, what Daal saw of it here, and "Use only this way". */
export function WayRow({
    t,
    locale,
    r,
    title,
    state,
    open,
    onToggle,
    pinned,
    chosenByDaal,
    busy,
    otherConnected,
    onUseOnly,
    onBackToAuto,
    last,
    dev,
}: WayRowProps) {
    const m = r.measured;
    const restUntil =
        state === 'resting' && r.cooldownUntilUnixMs !== undefined ? formatTime(locale, new Date(r.cooldownUntilUnixMs)) : undefined;
    const stateKey = wayStateKey(state);
    const stateText = stateKey
        ? state === 'resting'
            ? restUntil
                ? t(stateKey).replace('{time}', restUntil)
                : t('network.resting')
            : t(stateKey)
        : undefined;
    const setup = setupText(t, locale, m?.setupMs);
    const score = typeof r.healthPct === 'number' && Number.isFinite(r.healthPct) ? Math.round(r.healthPct) : undefined;
    const scoreText = score !== undefined ? t('files.way.facts.score_value').replace('{n}', localNumber(score, locale)) : undefined;
    const maturityKey = maturityBadgeKey(r);
    // An unsupported way's badge already says it; the line under the
    // title does not say it again.
    // A way in use says who chose it instead (its badge says "In use").
    const lead =
        state === 'unsupported'
            ? undefined
            : state === 'in_use'
            ? pinned
                ? t('files.way.chosen_you')
                : chosenByDaal
                ? t('files.way.chosen_auto')
                : undefined
            : stateText;
    // A pasted link is known by the name it gave itself ("Server 1"):
    // that is its title, and the kind moves to the line under it. Its
    // old fallback name, a piece of the route id, is never shown.
    const linkName = pastedName(r);
    const pasted = linkName !== undefined || r.routeId.startsWith('pasted-');
    const heading = linkName ?? title.title;
    const nickname = pasted ? undefined : title.nickname;
    // The file's own name for the way, quoted as each language quotes.
    const quoted = nickname ? <bdi>{locale === 'fa' ? `«${nickname}»` : `“${nickname}”`}</bdi> : undefined;
    const kindLine = linkName !== undefined ? title.title : undefined;
    const sub: ReactNode[] = [lead, kindLine, quoted].filter(Boolean);
    // Used only when the person picks it (a pasted WireGuard conf).
    const onlyWhenPicked = manualOnly(r);
    const about = familyAbout(t, r);
    const usable = state !== 'unsupported' && state !== 'resting' && state !== 'in_use' && state !== 'checking';
    // Only a name that tells the person something ("Rescue 03"): never
    // "r1", a date or a short code (lib/familyName.ts); for a pasted
    // link, the name in the link.
    const nick = linkName ?? nickname;
    // When it was last tried, as the card header says time: "2 hours
    // ago". The engine keeps it by the hour, so the last hour is said as
    // such rather than as a made-up number of minutes.
    const lastText =
        m?.lastUnix !== undefined
            ? Date.now() - m.lastUnix * 1000 < 3_600_000
                ? t('files.way.facts.last_hour')
                : formatAgo(locale, Date.now() - m.lastUnix * 1000)
            : undefined;
    const hasCounts = !!m && (m.samples > 0 || m.carried > 0 || m.failed > 0);

    return (
        <li
            data-way={r.routeId}
            data-way-state={state}
            style={{ borderBlockEnd: last ? 'none' : '1px solid var(--line-soft)' }}
        >
            <button
                type="button"
                data-button="way-row"
                aria-expanded={open}
                className="daal-hover"
                onClick={onToggle}
                style={{
                    appearance: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    width: '100%',
                    minHeight: 56,
                    padding: '9px 0',
                    margin: 0,
                    background: 'transparent',
                    border: 0,
                    color: 'inherit',
                    font: 'inherit',
                    textAlign: 'start',
                    cursor: 'pointer',
                }}
            >
                <StateIcon state={wayGlyph(state)} size={20} label={stateText} />
                <span style={{ display: 'grid', gap: 2, flex: 1, minWidth: 0 }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                        <bdi
                            style={{
                                fontSize: 15,
                                fontWeight: 600,
                                color: state === 'unsupported' ? 'var(--muted)' : 'var(--fg)',
                                minWidth: 0,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                lineHeight: 1.4,
                            }}
                        >
                            {heading}
                        </bdi>
                        {maturityKey && (
                            <Badge tone={maturityKey === 'files.way.experimental' ? 'gold' : 'neutral'} size="sm" icon={false}>
                                {t(maturityKey)}
                            </Badge>
                        )}
                        {state === 'in_use' && (
                            <Badge tone="good" size="sm" icon={false}>
                                {t('network.in_use')}
                            </Badge>
                        )}
                    </span>
                    {sub.length > 0 && (
                        <span
                            style={{
                                fontSize: 13,
                                color: 'var(--muted)',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                lineHeight: 1.45,
                            }}
                        >
                            {sub.map((x, i) => (
                                <span key={i}>
                                    {i > 0 ? sep() : ''}
                                    {x}
                                </span>
                            ))}
                        </span>
                    )}
                    {onlyWhenPicked && (
                        <span data-testid="way-manual-only" style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.45 }}>
                            {t('files.pasted.manual_only')}
                        </span>
                    )}
                </span>
                {(setup || scoreText) && (
                    <span style={{ display: 'grid', justifyItems: 'end', gap: 4, flexShrink: 0 }}>
                        {setup && (
                            <span style={{ fontSize: 12.5, color: 'var(--fg)', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
                                {setup}
                            </span>
                        )}
                        {score !== undefined && scoreText && (
                            <ScoreMeter pct={score} label={`${t('files.way.facts.score')}: ${scoreText}`} />
                        )}
                    </span>
                )}
                <span
                    aria-hidden
                    style={{
                        color: 'var(--muted)',
                        display: 'inline-flex',
                        flexShrink: 0,
                        transition: 'transform var(--t-fast)',
                        transform: open ? 'rotate(180deg)' : 'none',
                    }}
                >
                    <Icon name="chevronDown" size={18} />
                </span>
            </button>
            {open && (
                <div data-way-detail style={{ display: 'grid', gap: 12, paddingBlock: '0 14px', paddingInlineStart: 32 }}>
                    {about && <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6, color: 'var(--muted)' }}>{about}</p>}
                    <dl
                        style={{
                            display: 'grid',
                            gridTemplateColumns: 'auto 1fr',
                            columnGap: 14,
                            rowGap: 6,
                            margin: 0,
                            alignItems: 'baseline',
                        }}
                    >
                        {m && <Fact label={t('files.way.facts.here')}>{gradeText(t, m)}</Fact>}
                        {m && hasCounts && (
                            <Fact label={t('files.way.facts.tries')}>
                                {t('files.way.facts.tries_value')
                                    .replace('{n}', localNumber(Math.max(m.samples, m.carried + m.failed), locale))
                                    .replace('{a}', localNumber(m.carried, locale))
                                    .replace('{b}', localNumber(m.failed, locale))}
                            </Fact>
                        )}
                        {setup && <Fact label={t('files.way.facts.setup')}>{setup}</Fact>}
                        {lastText ? (
                            <Fact label={t('files.way.facts.last')}>{lastText}</Fact>
                        ) : (
                            m?.last && (
                                <Fact label={t('files.way.facts.last')}>
                                    <bdi dir="ltr">{m.last}</bdi>
                                </Fact>
                            )
                        )}
                        {restUntil && <Fact label={t('files.way.facts.resting')}>{restUntil}</Fact>}
                        {scoreText && <Fact label={t('files.way.facts.score')}>{scoreText}</Fact>}
                        {nick && (
                            <Fact label={t('files.way.facts.name')}>
                                <bdi>{nick}</bdi>
                            </Fact>
                        )}
                    </dl>
                    {scoreText && <div style={{ fontSize: 12, color: 'var(--dim)', lineHeight: 1.5 }}>{t('files.way.score_help')}</div>}
                    {pinned ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 13, color: 'var(--fg)' }}>{t('files.way.only_this')}</span>
                            <Button size="sm" variant="secondary" onClick={onBackToAuto} dataButton="way-back-auto">
                                {t('auto.chooser.back')}
                            </Button>
                        </div>
                    ) : usable ? (
                        <div style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
                            <Button size="sm" variant="secondary" disabled={busy} onClick={onUseOnly} dataButton="way-use-only">
                                {t(otherConnected ? 'files.way.use_only_now' : 'files.way.use_only')}
                            </Button>
                            <span style={{ fontSize: 12, color: 'var(--dim)' }}>
                                {otherConnected ? `${t('files.way.use_only_now_hint')} ${t('auto.chooser.advanced_hint')}` : t('auto.chooser.advanced_hint')}
                            </span>
                        </div>
                    ) : null}
                </div>
            )}
            {dev}
        </li>
    );
}
