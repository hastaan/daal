// WayChooser — the choice under the headline: "Automatic" (the
// default: Daal chooses the best way) or one route the person picked
// themselves.
//
// The route list is the ADVANCED choice and stays folded away. A
// person who knows nothing about routes sees one word, "Automatic",
// and never has to open it. A person who did pick one sees that they
// did, in words, with the way back right beside it.
//
// Rows are named "publisher · nickname", the way the rest of the app
// names a route. No protocol name is printed here.
//
// WHAT IS TRUE NOW vs WHAT WAS CHOSEN FOR NEXT TIME. While something is
// connected the chip says what the ENGINE is doing — it is choosing
// (`engineAuto`), or it is on a way the person picked — and a choice
// that differs from that is a separate, always visible line: "From the
// next time you connect: …". The chip used to show the saved choice as
// if it were already in force.
//
// In automatic mode no route is named on the main path: the name the
// engine has for a route falls back to its raw id, and a person who
// chose nothing has no use for either. Names are for the list.
import type { RouteDisplayRow } from '../../contract/D2Contract';
import { Button } from '../../design/primitives';

interface Props {
    t: (k: string) => string;
    /** The route the person chose by hand, or null for Automatic. A row
     *  with only an id (its details could not be read) is fine. */
    pinned: RouteDisplayRow | null;
    /** The routes on this device; `undefined` = the list could not be
     *  read (the advanced list is then not offered: nothing to show). */
    routes: readonly RouteDisplayRow[] | undefined;
    /** The route in use right now, when something is connected. */
    running?: RouteDisplayRow;
    /** The engine itself is choosing the route (`auto.mode`). Only
     *  meaningful with `running`. */
    engineAuto?: boolean;
    /** Something is running or being tried: a new choice is saved and
     *  used from the next connect, and the page says so. */
    busy: boolean;
    open: boolean;
    onToggle: () => void;
    onPick: (routeId: string) => void;
    onBackToAuto: () => void;
    /** "See all connections" — the Connections page. */
    onManage: () => void;
}

export function routeLabel(r: RouteDisplayRow): string {
    return r.publisherName || r.routeNickname
        ? `${r.publisherName} · ${r.routeNickname}`
        : r.routeId;
}

export default function WayChooser({
    t,
    pinned,
    routes,
    running,
    engineAuto,
    busy,
    open,
    onToggle,
    onPick,
    onBackToAuto,
    onManage,
}: Props) {
    // What is in force right now. With nothing connected that is simply
    // the saved choice. With something connected it is what the engine
    // is doing: choosing by itself, or staying on one way.
    const nowOwn: RouteDisplayRow | null = running ? (engineAuto ? null : running) : pinned;
    const title = nowOwn
        ? t('auto.chooser.pinned').replace('{name}', routeLabel(nowOwn))
        : t('auto.chooser.automatic');
    const hint = nowOwn ? t('auto.chooser.pinned_hint') : t('auto.chooser.automatic_hint');
    // The saved choice, when it is not what is in force.
    const next = !running
        ? undefined
        : pinned && (engineAuto || pinned.routeId !== running.routeId)
        ? t('auto.chooser.next_pinned').replace('{name}', routeLabel(pinned))
        : !pinned && !engineAuto
        ? t('auto.chooser.next_auto')
        : undefined;
    return (
        <div
            style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 8,
                maxWidth: 520,
                marginBlockEnd: 16,
            }}
        >
            <button
                type="button"
                className="d2-conn-route-chip"
                aria-expanded={open}
                onClick={onToggle}
                style={{ marginBlockEnd: 0 }}
            >
                <span>
                    <bdi>{title}</bdi>
                </span>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                     strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                    <path d="m6 9 6 6 6-6" />
                </svg>
            </button>
            <div style={{ fontSize: 12, color: 'var(--ink-soft)', textAlign: 'center' }}>{hint}</div>
            {next && (
                <div data-next style={{ fontSize: 12, color: 'var(--ink-soft)', textAlign: 'center' }}>
                    <bdi>{next}</bdi>
                </div>
            )}
            {pinned && (
                <Button size="sm" variant="secondary" onClick={onBackToAuto}>
                    {t('auto.chooser.back')}
                </Button>
            )}
            {open && (
                <div
                    style={{
                        inlineSize: '100%',
                        border: '1px solid var(--teal-hairline)',
                        borderRadius: 12,
                        padding: 12,
                        textAlign: 'start',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                    }}
                >
                    <ChoiceRow
                        label={t('auto.chooser.automatic')}
                        sub={t('auto.chooser.automatic_hint')}
                        selected={!pinned}
                        onClick={onBackToAuto}
                    />
                    {routes !== undefined && routes.length > 0 && (
                        <>
                            <div style={{ fontSize: 12, color: 'var(--ink-soft)', marginBlockStart: 6 }}>
                                <strong style={{ display: 'block', color: 'var(--paper-dim)' }}>
                                    {t('auto.chooser.advanced')}
                                </strong>
                                {t('auto.chooser.advanced_hint')}
                            </div>
                            {routes.map((r) => (
                                <ChoiceRow
                                    key={r.routeId}
                                    label={routeLabel(r)}
                                    selected={pinned?.routeId === r.routeId}
                                    onClick={() => onPick(r.routeId)}
                                />
                            ))}
                        </>
                    )}
                    {busy && (
                        <div style={{ fontSize: 12, color: 'var(--ink-soft)' }}>
                            {t('auto.chooser.next_time')}
                        </div>
                    )}
                    <div>
                        <Button size="sm" variant="ghost" onClick={onManage}>
                            {t('auto.chooser.manage')}
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
}

function ChoiceRow({
    label,
    sub,
    selected,
    onClick,
}: {
    label: string;
    sub?: string;
    selected: boolean;
    onClick: () => void;
}) {
    return (
        <button
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={onClick}
            style={{
                appearance: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                inlineSize: '100%',
                textAlign: 'start',
                background: selected ? 'rgba(255,255,255,0.06)' : 'transparent',
                border: '1px solid var(--teal-hairline)',
                borderRadius: 10,
                padding: '10px 12px',
                color: 'var(--fg)',
                cursor: 'pointer',
                fontSize: 13,
                minBlockSize: 44,
            }}
        >
            <span aria-hidden style={{ inlineSize: 14, color: 'var(--gold-soft)' }}>
                {selected ? '●' : '○'}
            </span>
            <span>
                <bdi style={{ display: 'block' }}>{label}</bdi>
                {sub && <span style={{ fontSize: 12, color: 'var(--ink-soft)' }}>{sub}</span>}
            </span>
        </button>
    );
}
