// WayChooser — the choice under the headline: "Automatic" (the
// default: Daal chooses the best way) or one route the person picked
// themselves.
//
// The route list is the ADVANCED choice and stays folded away. A
// person who knows nothing about routes sees one word, "Automatic",
// and never has to open it. A person who did pick one sees that they
// did, in words, with the way back right beside it.
//
// Rows are named by their kind of connection ("VLESS Reality", the
// same name Home and Files print, lib/familyName.ts), with the file it
// came from and the engine's grade on this network under it. A file's
// own "r1" / "Way 2" says nothing and is left out (meaningfulNickname).
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
import { sep } from '../../lib/format';
import type { RouteDisplayRow } from '../../contract/D2Contract';
import { Button, StateIcon } from '../../design/primitives';
import { familyLabel, familyName } from '../../lib/familyName';
import { setupText, wayTitles } from '../../lib/fileFacts';
import { gradeText } from '../../lib/measured';
import { effectiveLocale } from '../../lib/i18n';

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
    /** "Open my files" — the Files page. */
    onManage: () => void;
    /** Only the list of choices, for the "Choose the way myself" sheet
     *  (the chip and its hint are the page's business there). */
    bare?: boolean;
}

/** The way's kind, told apart from another of the same kind in its
 *  file ("VLESS Reality · 2"), and its own name when it means something. */
function wayTitle(t: (k: string) => string, r: RouteDisplayRow, routes?: readonly RouteDisplayRow[]) {
    const peers = (routes ?? []).filter((x) => x.publisherId === r.publisherId);
    if (!peers.some((x) => x.routeId === r.routeId)) peers.push(r);
    return wayTitles(t, peers, effectiveLocale()).get(r.routeId) ?? { title: familyName(t, r.family) };
}

/** "Pars Relays · VLESS Reality": the file, then the kind of connection
 *  (with the way's own name only when it means something). */
export function routeLabel(t: (k: string) => string, r: RouteDisplayRow, routes?: readonly RouteDisplayRow[]): string {
    const w = wayTitle(t, r, routes);
    // A kind this app cannot name adds nothing to a label that has the
    // file's name ("Current connection · name not available" stays as is).
    const kind = familyLabel(t, r.family) ? w.title : undefined;
    const label = [r.publisherName, kind, w.nickname].filter(Boolean).join(sep());
    return label || w.title;
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
    bare,
}: Props) {
    // What is in force right now. With nothing connected that is simply
    // the saved choice. With something connected it is what the engine
    // is doing: choosing by itself, or staying on one way.
    const nowOwn: RouteDisplayRow | null = running ? (engineAuto ? null : running) : pinned;
    const title = nowOwn
        ? t('auto.chooser.pinned').replace('{name}', routeLabel(t, nowOwn, routes))
        : t('auto.chooser.automatic');
    const hint = nowOwn ? t('auto.chooser.pinned_hint') : t('auto.chooser.automatic_hint');
    // The saved choice, when it is not what is in force.
    const next = !running
        ? undefined
        : pinned && (engineAuto || pinned.routeId !== running.routeId)
        ? t('auto.chooser.next_pinned').replace('{name}', routeLabel(t, pinned, routes))
        : !pinned && !engineAuto
        ? t('auto.chooser.next_auto')
        : undefined;
    if (bare) {
        // The sheet ("Choose the way myself"): the selected radio is what
        // Home's "Manual" badge says, i.e. the saved pick, or else the way
        // the engine is holding because the person picked it. One line
        // under the list at most: a saved pick that is not in force yet
        // says "from the next time", otherwise the one hint.
        const selectedId = pinned?.routeId ?? nowOwn?.routeId ?? null;
        const pendingPick =
            running && pinned && (engineAuto || pinned.routeId !== running.routeId)
                ? t('auto.chooser.next_pinned').replace('{name}', routeLabel(t, pinned, routes))
                : undefined;
        const hasList = routes !== undefined && routes.length > 0;
        return (
            <ChoiceList
                t={t}
                selectedId={selectedId}
                routes={routes}
                note={pendingPick ?? (hasList ? t('auto.chooser.advanced_hint') : undefined)}
                onPick={onPick}
                onBackToAuto={onBackToAuto}
                onManage={onManage}
                framed={false}
            />
        );
    }
    const list = (
        <ChoiceList
            t={t}
            selectedId={pinned?.routeId ?? null}
            routes={routes}
            note={busy ? t('auto.chooser.next_time') : routes?.length ? t('auto.chooser.advanced_hint') : undefined}
            onPick={onPick}
            onBackToAuto={onBackToAuto}
            onManage={onManage}
            framed
        />
    );
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
            {open && list}
        </div>
    );
}

function ChoiceList({
    t,
    selectedId,
    routes,
    note,
    onPick,
    onBackToAuto,
    onManage,
    framed,
}: Pick<Props, 't' | 'routes' | 'onPick' | 'onBackToAuto' | 'onManage'> & {
    /** The selected way, or null for Automatic. */
    selectedId: string | null;
    /** The one line under the list, if any. */
    note?: string;
    framed: boolean;
}) {
    return (
                <div
                    style={{
                        inlineSize: '100%',
                        border: framed ? '1px solid var(--teal-hairline)' : 0,
                        borderRadius: 12,
                        padding: framed ? 12 : 0,
                        textAlign: 'start',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                    }}
                >
                    <ChoiceRow
                        label={t('auto.chooser.automatic')}
                        sub={t('auto.chooser.automatic_hint')}
                        selected={selectedId === null}
                        onClick={onBackToAuto}
                    />
                    {routes !== undefined && routes.length > 0 && (
                        <>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--muted)', marginBlockStart: 6 }}>
                                {t('auto.chooser.advanced')}
                            </div>
                            {routes.map((r) => {
                                const w = wayTitle(t, r, routes);
                                // Under the kind: which file and the way's own
                                // name if it has one; then how it did on this
                                // network, with the Files tab's disc (only
                                // when the engine graded it); its time to
                                // connect here at the end.
                                const sub = [r.publisherName, w.nickname].filter(Boolean).join(sep());
                                const g = r.measured?.grade;
                                const gradeLine = gradeText(t, r.measured);
                                return (
                                    <ChoiceRow
                                        key={r.routeId}
                                        label={w.title}
                                        sub={sub || undefined}
                                        grade={
                                            gradeLine
                                                ? {
                                                      text: gradeLine,
                                                      state:
                                                          g === 'good' || g === 'ok'
                                                              ? 'ok'
                                                              : g === 'slow'
                                                              ? 'warn'
                                                              : g === 'failing'
                                                              ? 'bad'
                                                              : 'none',
                                                  }
                                                : undefined
                                        }
                                        setup={setupText(t, effectiveLocale(), r.measured?.setupMs)}
                                        selected={selectedId === r.routeId}
                                        onClick={() => onPick(r.routeId)}
                                    />
                                );
                            })}
                        </>
                    )}
                    {note && (
                        <div data-note style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.45 }}>
                            <span>{note}</span>
                        </div>
                    )}
                    <div>
                        <Button variant="link" onClick={onManage} dataButton="chooser-files">
                            {t('auto.chooser.manage')}
                        </Button>
                    </div>
                </div>
    );
}

const GRADE_COLOR: Record<'ok' | 'warn' | 'bad' | 'none', string> = {
    ok: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    none: 'var(--muted)',
};

/** A radio you can see: a 20 px ring, filled at the centre when chosen. */
function Radio({ selected }: { selected: boolean }) {
    return (
        <svg aria-hidden viewBox="0 0 20 20" width={20} height={20} style={{ flexShrink: 0, display: 'block' }}>
            <circle cx="10" cy="10" r="8.6" fill="none" stroke={selected ? 'var(--gold-warm)' : 'var(--muted)'} strokeWidth={1.8} />
            {selected && <circle cx="10" cy="10" r="4.6" fill="var(--gold-warm)" />}
        </svg>
    );
}

function ChoiceRow({
    label,
    sub,
    grade,
    setup,
    selected,
    onClick,
}: {
    label: string;
    sub?: string;
    /** How it did here, with its disc. */
    grade?: { text: string; state: 'ok' | 'warn' | 'bad' | 'none' };
    /** "0.4 s" to connect here. */
    setup?: string;
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
                gap: 12,
                inlineSize: '100%',
                textAlign: 'start',
                background: selected ? 'var(--tint-2)' : 'transparent',
                border: selected ? '1px solid var(--gold-warm)' : '1px solid var(--teal-hairline)',
                borderRadius: 10,
                padding: '10px 12px',
                color: 'var(--fg)',
                cursor: 'pointer',
                fontSize: 13,
                minBlockSize: 44,
            }}
        >
            <Radio selected={selected} />
            <span style={{ flex: 1, minWidth: 0, display: 'grid', gap: 2 }}>
                {/* The block takes the page's direction (a Latin name keeps its
                    own inside the <bdi>), so the rows line up on the start
                    side in Persian too. */}
                <span style={{ display: 'block', fontSize: 14, fontWeight: 600 }}>
                    <bdi>{label}</bdi>
                </span>
                {sub && (
                    <span style={{ display: 'block', fontSize: 12, color: 'var(--ink-soft)' }}>
                        <bdi>{sub}</bdi>
                    </span>
                )}
                {grade && (
                    <span data-grade={grade.state} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: GRADE_COLOR[grade.state] }}>
                        <StateIcon state={grade.state} size={14} />
                        <span>{grade.text}</span>
                    </span>
                )}
            </span>
            {setup && (
                <span style={{ flexShrink: 0, fontSize: 12.5, color: 'var(--fg)', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
                    {setup}
                </span>
            )}
        </button>
    );
}
