// PasteList.tsx — a paste that holds several items (wave 1, lane B).
//
// One row per item (lib/pasteItems.ts), each with a plain label and, at
// the far edge of the row, the item's own name ("Server 1", the host):
//   a way to connect   "Connection link · VLESS"; added with "Add all"
//   a WireGuard conf   added with "Add all", and its row says in one line
//                      that Daal uses it only when the person picks it
//   a Daal file        added with "Add all"; the same signature,
//                      revocation and expiry checks as one pasted file,
//                      and a new publisher still gets the trust question
//   a web address      its own "Add": a link copied for another reason
//                      must not become a subscription because it sat
//                      next to others
//   a messenger proxy  "Open in Telegram" / "Open in Signal", and the
//                      plain fact that it helps only that app
//   not understood     one muted line; it never fails the paste
//
// Each item is added through the existing commands, one at a time, and
// gets its own result. When two or more links were added, "Check them
// now" runs the engine's route survey (lib/routeSurvey.ts), and then
// "Remove the ones that did not answer" removes ONLY the routes the
// check tried and that failed (components/pasteSurvey.ts). The "Keep
// only the ones that work" switch does both after adding. One link
// never reaches this screen (AddSheet keeps its single-link flow).

import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useContract } from '../contract/ContractProvider';
import type { PreviewedBundle } from '../contract/D2Contract';
import { Badge, Button, StateIcon, Toggle } from '../design/primitives';
import { errorText } from '../lib/errorText';
import { effectiveLocale } from '../lib/i18n';
import { localDigits } from '../lib/measured';
import { recordImportOrigin } from '../lib/importOrigin';
import { friendlyError, parseVerdict } from '../lib/importVerdict';
import { importLink } from '../lib/pasteImport';
import { MAX_ITEMS, ROUTE_KIND_NAME, addable, routeLinkCount, type PasteItem } from '../lib/pasteItems';
import { checkAllRoutes, surveyRefusedKey, type SurveyReport } from '../lib/routeSurvey';
import { syntheticSubscriptionFingerprint, subscriptionDisplayName } from '../lib/subscriptionIdentity';
import { importOutcome, trustOutcome } from './ImportResult';
import { checksFor, failedIds, readSurvey, surveyEnded, type RouteCheck, type SurveyRead } from './pasteSurvey';
import TrustPrompt from './TrustPrompt';

type T = (k: string) => string;

type RowState =
    | { at: 'idle' }
    | { at: 'adding' }
    | { at: 'added'; routeIds: string[]; check?: RouteCheck; removed?: boolean }
    | { at: 'refused'; text: string }
    | { at: 'ask'; preview: PreviewedBundle }
    | { at: 'declined' };

interface Props {
    t: T;
    items: PasteItem[];
    truncated?: boolean;
    /** Routes committed: the page reads its list again. */
    onImported?: () => void;
    onConnect?: () => void;
    onClose: () => void;
    /** Told when the paste starts adding, has added, or is checking. */
    onPhase?: (p: PastePhase) => void;
}

/** Text with placeholders filled. */
function fill(s: string, vars: Record<string, string | number>): string {
    const locale = effectiveLocale();
    return Object.entries(vars).reduce(
        (acc, [k, v]) => acc.split(`{${k}}`).join(typeof v === 'number' ? localDigits(v, locale) : v),
        s,
    );
}

/** Plural by count: `${key}_one` for one when the catalog has it. */
function plural(t: T, key: string, n: number): string {
    const one = `${key}_one`;
    const s = n === 1 && t(one) !== one ? t(one) : t(key);
    return fill(s, { n });
}

export { refusalText } from '../lib/pasteImport';

/** Hand a link to the system, which opens the app it belongs to. */
export async function openWithSystem(url: string): Promise<void> {
    try {
        await invoke('open_external_url', { url });
        return;
    } catch {
        /* not in the app shell */
    }
    try {
        window.open(url, '_blank', 'noopener');
    } catch {
        /* nothing to open with */
    }
}

/** The survey poll interval, swapped by tests only. (Links are no
 *  longer paced a second apart: the engine names each pasted route by
 *  a hash of the link, core/abi/share.go URIImport.) */
export const pasteTiming = { pollMs: 1500 };

type CheckState =
    | { at: 'none' }
    | { at: 'checking'; report: SurveyReport | null }
    /** `unchecked`: this paste's routes the check could not reach (a
     *  check the person starts goes past the hourly side-check allowance
     *  and takes the new ones first, but it still has a ceiling, and a
     *  check can stop part way); `none`: not one of them was checked. */
    | { at: 'checked'; failed: string[]; unchecked: number; none: boolean }
    /** Some did not answer and none carried: the network itself may be
     *  why, so nothing is removed. */
    | { at: 'none_answered'; unchecked: number }
    | { at: 'refused'; key: string }
    | { at: 'removing' }
    | { at: 'removed'; n: number; kept: number; unchecked: number };

/** Where the paste is, for the box above it (read-only while busy). */
export type PastePhase = 'review' | 'adding' | 'added' | 'checking';

const POLL_LIMIT_MS = 10 * 60 * 1000;

export default function PasteList({ t, items, truncated, onImported, onConnect, onClose, onPhase }: Props) {
    const contract = useContract();
    const [rows, setRows] = useState<RowState[]>(() => items.map(() => ({ at: 'idle' })));
    const [phase, setPhase] = useState<'review' | 'adding' | 'added'>('review');
    const [keepWorking, setKeepWorking] = useState(false);
    const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
    const [asking, setAsking] = useState<number | null>(null);
    const [check, setCheck] = useState<CheckState>({ at: 'none' });
    const busyChecking = check.at === 'checking' || check.at === 'removing';
    useEffect(() => {
        onPhase?.(busyChecking ? 'checking' : phase);
    }, [phase, busyChecking, onPhase]);
    const alive = useRef(true);
    useEffect(() => {
        alive.current = true;
        return () => {
            alive.current = false;
        };
    }, []);
    const rowsRef = useRef(rows);
    rowsRef.current = rows;

    const setRow = (i: number, s: RowState) => {
        if (!alive.current) return;
        setRows((prev) => prev.map((r, k) => (k === i ? s : r)));
    };

    const links = routeLinkCount(items);
    const bulk = links >= 2;
    const addableSet = new Set(addable(items));
    const toAdd = items.map((it, i) => ({ it, i })).filter(({ it }) => addableSet.has(it));

    const routeIdsNow = async (): Promise<Set<string>> => {
        try {
            const rs = await contract.routesStrict();
            return new Set((rs ?? []).map((r) => r.routeId));
        } catch {
            return new Set();
        }
    };

    /** One link through uri_import (lib/pasteImport.ts, the same reading
     *  as the single-link flow). Resolves with the new route ids. */
    const addLink = async (text: string, known: Set<string>): Promise<RowState> => {
        const r = await importLink(contract, t, text);
        if (!r.ok) return { at: 'refused', text: r.text };
        const after = await routeIdsNow();
        const fresh = [...after].filter((id) => !known.has(id));
        fresh.forEach((id) => known.add(id));
        return { at: 'added', routeIds: fresh };
    };

    /** One Daal file through import_sbp_bytes: the same checks as a
     *  pasted file on its own. */
    const addFile = async (text: string, known: Set<string>): Promise<RowState> => {
        try {
            const v = parseVerdict(await contract.importSbpBytes(text));
            const o = importOutcome(t, v, null);
            if (o.kind === 'trust') return { at: 'ask', preview: o.preview };
            if (o.kind === 'refused') return { at: 'refused', text: o.text };
            recordImportOrigin(v?.Fingerprint, 'paste');
            const after = await routeIdsNow();
            const fresh = [...after].filter((id) => !known.has(id));
            fresh.forEach((id) => known.add(id));
            return { at: 'added', routeIds: fresh };
        } catch (e) {
            return { at: 'refused', text: friendlyError(t, errorText(e)) };
        }
    };

    const addAll = async () => {
        setPhase('adding');
        const known = await routeIdsNow();
        let addedLinks = 0;
        let n = 0;
        setProgress({ done: 0, total: toAdd.length });
        for (const { it, i } of toAdd) {
            if (!alive.current) return;
            setRow(i, { at: 'adding' });
            let res: RowState;
            if (it.kind === 'route') {
                res = await addLink(it.text, known);
                if (res.at === 'added' && !it.manualOnly) addedLinks++;
            } else {
                res = await addFile(it.text, known);
            }
            setRow(i, res);
            n++;
            if (alive.current) setProgress({ done: n, total: toAdd.length });
        }
        if (!alive.current) return;
        onImported?.();
        setPhase('added');
        setProgress(null);
        if (keepWorking && addedLinks >= 2) void runCheck(true);
    };

    const addWeb = async (i: number, url: string) => {
        setRow(i, { at: 'adding' });
        try {
            await contract.subscriptionAdd({
                publisherFingerprint: await syntheticSubscriptionFingerprint(url),
                url,
                displayName: subscriptionDisplayName(url),
            });
            onImported?.();
            setRow(i, { at: 'added', routeIds: [] });
        } catch {
            setRow(i, { at: 'refused', text: t('add.multi.web_failed') });
        }
    };

    /** The routes this paste added that a check may judge. */
    const addedRouteIds = (): string[] =>
        rowsRef.current.flatMap((r, i) => {
            const it = items[i];
            return r.at === 'added' && it.kind === 'route' && !it.manualOnly && !r.removed ? r.routeIds : [];
        });

    const runCheck = async (thenRemove: boolean) => {
        setCheck({ at: 'checking', report: null });
        const start = await checkAllRoutes();
        if (!start.started && start.refused !== 'running') {
            const key = (start.refused && surveyRefusedKey(start.refused)) || 'home.survey.failed';
            if (alive.current) setCheck({ at: 'refused', key });
            return;
        }
        const t0 = Date.now();
        let read: SurveyRead | null = null;
        for (;;) {
            await new Promise((r) => setTimeout(r, pasteTiming.pollMs));
            if (!alive.current) return;
            read = await readSurvey();
            if (read && alive.current) setCheck({ at: 'checking', report: read.report });
            if (read && surveyEnded(read.report)) break;
            if (Date.now() - t0 > POLL_LIMIT_MS) break;
        }
        let routes;
        try {
            routes = await contract.routesStrict();
        } catch {
            routes = undefined;
        }
        const ids = addedRouteIds();
        const checks = checksFor(ids, read && surveyEnded(read.report) ? read : null, routes);
        if (!alive.current) return;
        setRows((prev) =>
            prev.map((r) => {
                if (r.at !== 'added' || r.routeIds.length === 0) return r;
                const cs = r.routeIds.map((id) => checks.get(id) ?? 'unchecked');
                const c: RouteCheck = cs.includes('works')
                    ? 'works'
                    : cs.every((x) => x === 'failed')
                    ? 'failed'
                    : cs.includes('when_used')
                    ? 'when_used'
                    : 'unchecked';
                return { ...r, check: c };
            }),
        );
        const failed = failedIds(checks);
        const unchecked = [...checks.values()].filter((c) => c === 'unchecked').length;
        // PROOF FIRST. `not_carrying` also means "this network carried
        // nothing" (a silent timeout reads the same as a refusal), so a
        // removal needs one route in this check that carried. Links that
        // fail on mobile data often work on home Wi-Fi.
        const ended = read && surveyEnded(read.report) ? read : null;
        const carriedAny = !!ended && (ended.report.carried > 0 || [...ended.results.values()].includes('works'));
        if (failed.length > 0 && !carriedAny) {
            setCheck({ at: 'none_answered', unchecked });
            return;
        }
        if (thenRemove && failed.length > 0) await removeFailed(failed, unchecked);
        else setCheck({ at: 'checked', failed, unchecked, none: unchecked === ids.length });
    };

    const removeFailed = async (ids: string[], unchecked: number) => {
        setCheck({ at: 'removing' });
        const gone = new Set<string>();
        for (const id of ids) {
            try {
                await contract.routeDelete(id);
                gone.add(id);
            } catch {
                /* it stays; the count says how many went */
            }
        }
        if (!alive.current) return;
        setRows((prev) =>
            prev.map((r) =>
                r.at === 'added' && r.routeIds.length > 0 && r.routeIds.every((id) => gone.has(id)) ? { ...r, removed: true } : r,
            ),
        );
        if (gone.size) onImported?.();
        setCheck({ at: 'removed', n: gone.size, kept: addedRouteIds().length - gone.size, unchecked });
    };

    if (asking !== null) {
        const row = rows[asking];
        if (row.at === 'ask') {
            return (
                <TrustPrompt
                    t={t}
                    preview={row.preview}
                    onResolve={(r) => {
                        const i = asking;
                        setAsking(null);
                        const o = trustOutcome(t, r);
                        if (!o) {
                            setRow(i, { at: 'declined' });
                            return;
                        }
                        if (o.kind === 'done') {
                            recordImportOrigin(r.verdict?.Fingerprint || row.preview.fingerprintHex, 'paste');
                            onImported?.();
                            setRow(i, { at: 'added', routeIds: [] });
                        } else if (o.kind === 'refused') setRow(i, { at: 'refused', text: o.text });
                    }}
                />
            );
        }
    }

    const addedAny = rows.some((r, i) => r.at === 'added' && (items[i].kind === 'route' || items[i].kind === 'file') && !r.removed);
    // A WireGuard conf is used only when picked and never checked beside
    // another connection: it does not count toward the bulk check.
    const checkable = (it: PasteItem) => it.kind === 'route' && !it.manualOnly;
    const addedLinkCount = rows.filter((r, i) => r.at === 'added' && checkable(items[i]) && r.routeIds.length > 0).length;

    return (
        <div style={{ display: 'grid', gap: 12 }} data-testid="paste-list">
            <div style={{ fontSize: 13, color: 'var(--muted)' }}>{plural(t, 'add.multi.found', items.length)}</div>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 2 }}>
                {items.map((it, i) => (
                    <ItemRow key={i} t={t} item={it} state={rows[i]} onAddWeb={(u) => void addWeb(i, u)} onAsk={() => setAsking(i)} />
                ))}
            </ul>
            {truncated && <div style={{ fontSize: 13, color: 'var(--muted)' }}>{fill(t('add.multi.truncated'), { n: MAX_ITEMS })}</div>}

            {phase === 'review' && toAdd.length > 0 && (
                <div style={{ display: 'grid', gap: 12 }}>
                    {bulk && (
                        <Toggle
                            checked={keepWorking}
                            onChange={setKeepWorking}
                            label={t('add.multi.keep_working')}
                            subtitle={t('add.multi.keep_working.help')}
                            dataButton="paste-keep-working"
                        />
                    )}
                    <div>
                        <Button onClick={() => void addAll()} dataButton="paste-add-all">
                            {toAdd.length === 1 ? t('add.pasted.add') : fill(t('add.multi.add_all'), { n: toAdd.length })}
                        </Button>
                    </div>
                </div>
            )}

            {phase === 'adding' && progress && (
                <div role="status" style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: 'var(--muted)' }}>
                    <StateIcon state="busy" size={18} />
                    {fill(t('add.multi.adding'), { done: progress.done, total: progress.total })}
                </div>
            )}

            {phase === 'added' && (
                <div style={{ display: 'grid', gap: 10 }}>
                    {addedLinkCount >= 2 && (
                        <CheckBlock
                            t={t}
                            check={check}
                            onCheck={() => void runCheck(false)}
                            onRemove={(ids, unchecked) => void removeFailed(ids, unchecked)}
                        />
                    )}
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {addedAny && onConnect && check.at !== 'checking' && check.at !== 'removing' && (
                            <Button
                                onClick={() => {
                                    onClose();
                                    onConnect();
                                }}
                                dataButton="import-connect"
                            >
                                {t('add.done.connect')}
                            </Button>
                        )}
                        <Button variant="secondary" onClick={onClose} dataButton="paste-close">
                            {t('common.close')}
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
}

function CheckBlock({
    t,
    check,
    onCheck,
    onRemove,
}: {
    t: T;
    check: CheckState;
    onCheck: () => void;
    onRemove: (ids: string[], unchecked: number) => void;
}) {
    const muted = { fontSize: 14, color: 'var(--muted)' } as const;
    const uncheckedLine = (n: number) =>
        n > 0 ? (
            <div style={muted} data-testid="paste-unchecked">
                {plural(t, 'add.multi.unchecked', n)}
            </div>
        ) : null;
    const again = (
        <div>
            <Button variant="secondary" leading="refresh" onClick={onCheck} dataButton="paste-check">
                {t('add.multi.check')}
            </Button>
        </div>
    );
    switch (check.at) {
        case 'none':
            return (
                <div>
                    <Button variant="secondary" leading="refresh" onClick={onCheck} dataButton="paste-check">
                        {t('add.multi.check')}
                    </Button>
                </div>
            );
        case 'checking': {
            const r = check.report;
            const line =
                r && r.total > 0
                    ? fill(t('home.survey.checking'), { done: Math.min(r.done, r.total), total: r.total })
                    : t('home.survey.checking_one');
            return (
                <div role="status" style={{ display: 'flex', alignItems: 'center', gap: 8, ...muted }}>
                    <StateIcon state="busy" size={18} />
                    {line}
                </div>
            );
        }
        case 'refused':
            return (
                <div style={{ display: 'grid', gap: 8 }}>
                    <div role="alert" style={muted}>
                        {t(check.key)}
                    </div>
                    <div>
                        <Button variant="secondary" leading="refresh" onClick={onCheck} dataButton="paste-check">
                            {t('add.multi.check')}
                        </Button>
                    </div>
                </div>
            );
        case 'checked':
            return (
                <div style={{ display: 'grid', gap: 8 }}>
                    {check.failed.length > 0 ? (
                        <div>
                            <Button
                                variant="danger"
                                leading="trash"
                                onClick={() => onRemove(check.failed, check.unchecked)}
                                dataButton="paste-remove-failed"
                            >
                                {plural(t, 'add.multi.remove_failed', check.failed.length)}
                            </Button>
                        </div>
                    ) : (
                        <div style={muted} data-testid="paste-check-result">
                            {check.none ? t('home.survey.failed') : t('add.multi.none_failed')}
                        </div>
                    )}
                    {uncheckedLine(check.unchecked)}
                </div>
            );
        case 'none_answered':
            return (
                <div style={{ display: 'grid', gap: 8 }}>
                    <div role="status" style={muted} data-testid="paste-none-answered">
                        {t('add.multi.none_answered')}
                    </div>
                    {uncheckedLine(check.unchecked)}
                    {again}
                </div>
            );
        case 'removing':
            return (
                <div role="status" style={{ display: 'flex', alignItems: 'center', gap: 8, ...muted }}>
                    <StateIcon state="busy" size={18} />
                    {t('add.multi.removing')}
                </div>
            );
        case 'removed':
            return (
                <div style={{ display: 'grid', gap: 8 }}>
                    <div style={muted} data-testid="paste-check-result">
                        {check.n > 0 ? plural(t, 'add.multi.removed', check.n) : t('add.multi.none_failed')}
                    </div>
                    {uncheckedLine(check.unchecked)}
                </div>
            );
    }
}

function kindLabel(t: T, it: PasteItem): string {
    switch (it.kind) {
        case 'route':
            return fill(t('add.multi.kind.route'), { kind: ROUTE_KIND_NAME[it.route] });
        case 'file':
            return t('add.detect.ok');
        case 'web':
            return t('add.detect.subscription');
        case 'messenger':
            return t(`add.multi.kind.${it.app}`);
        case 'unknown':
            return t('add.multi.kind.unknown');
    }
}

/** A short, safe preview of the item: the host for a link, never its
 *  credential (the userinfo of vless/trojan/hy2 is the password). */
export function itemPreview(it: PasteItem): string {
    if (it.kind === 'file') return '';
    if (it.kind === 'messenger') {
        const m = /server=([^&]+)/.exec(it.open) ?? /#(.+)$/.exec(it.open);
        return m ? decodeURIComponent(m[1]) : '';
    }
    if (it.kind === 'route') {
        if (it.text.startsWith('[')) {
            // A WireGuard conf has no name: its server's host, never a key.
            const ep = /^\s*Endpoint\s*=\s*(\[[^\]]+\]|[^\s:]+)/im.exec(it.text);
            return ep ? ep[1] : '';
        }
        const name = /#(.+)$/.exec(it.text);
        if (name) {
            try {
                return decodeURIComponent(name[1]).slice(0, 48);
            } catch {
                return name[1].slice(0, 48);
            }
        }
        const host = /^[a-z0-9+]+:\/\/(?:[^@/?#]*@)?([^/?#:]+|\[[^\]]+\])/i.exec(it.text);
        return host && it.text.includes('@') ? host[1] : '';
    }
    if (it.kind === 'web') {
        const h = /^https?:\/\/([^/?#]+)/i.exec(it.text);
        return h ? h[1] : it.text.slice(0, 48);
    }
    return it.text.length > 60 ? `${it.text.slice(0, 57)}…` : it.text;
}

function ItemRow({
    t,
    item,
    state,
    onAddWeb,
    onAsk,
}: {
    t: T;
    item: PasteItem;
    state: RowState;
    onAddWeb: (url: string) => void;
    onAsk: () => void;
}) {
    // A kind the engine cannot import yet: named, muted, and said so at
    // once (never counted in "Add all").
    const cannot = item.kind === 'route' && !item.importable;
    const muted = item.kind === 'unknown' || cannot;
    const preview = itemPreview(item);
    return (
        <li
            data-item={item.kind}
            style={{
                display: 'grid',
                gap: 4,
                padding: '8px 0',
                borderBlockEnd: '1px solid var(--line)',
                color: muted ? 'var(--muted)' : 'var(--fg)',
            }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 14, fontWeight: muted ? 400 : 600 }}>{kindLabel(t, item)}</span>
                <RowBadge t={t} state={state} />
                {preview && (
                    // The name sits at the far edge of the row however
                    // short it is: the wrapper takes the rest of the line
                    // and ends it in the page's direction (left in Farsi),
                    // while the name inside keeps its own (Latin) order.
                    <span
                        data-testid="paste-item-name"
                        style={{ flex: '1 1 auto', minWidth: 0, display: 'flex', justifyContent: 'flex-end' }}
                    >
                        <bdi dir="ltr" style={{ fontSize: 13, color: 'var(--muted)', overflowWrap: 'anywhere', minWidth: 0 }}>
                            {preview}
                        </bdi>
                    </span>
                )}
            </div>
            {item.kind === 'route' && item.manualOnly && (
                <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }} data-testid="paste-manual-only">
                    {t('add.multi.manual_only')}
                </div>
            )}
            {item.kind === 'messenger' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 13, color: 'var(--muted)', flex: 1, minWidth: 160 }}>{t(`add.multi.${item.app}.note`)}</span>
                    <Button size="sm" variant="secondary" leading="external" onClick={() => void openWithSystem(item.open)} dataButton={`paste-open-${item.app}`}>
                        {t(`add.multi.${item.app}.open`)}
                    </Button>
                </div>
            )}
            {item.kind === 'web' && state.at === 'idle' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 13, color: 'var(--muted)', flex: 1, minWidth: 160 }}>{t('add.multi.web_note')}</span>
                    <Button size="sm" variant="secondary" onClick={() => onAddWeb(item.text)} dataButton="paste-add-web">
                        {t('add.pasted.add')}
                    </Button>
                </div>
            )}
            {cannot && (
                <div style={{ fontSize: 13, color: 'var(--muted)' }} data-testid="paste-cannot-add">
                    {t('add.multi.refused.no_match')}
                </div>
            )}
            {state.at === 'refused' && <div style={{ fontSize: 13, color: 'var(--red)' }}>{state.text}</div>}
            {state.at === 'ask' && (
                <div>
                    <Button size="sm" onClick={onAsk} dataButton="paste-ask">
                        {t('add.multi.file.ask')}
                    </Button>
                </div>
            )}
        </li>
    );
}

function RowBadge({ t, state }: { t: T; state: RowState }) {
    switch (state.at) {
        case 'adding':
            return <StateIcon state="busy" size={16} />;
        case 'added':
            if (state.removed) return <Badge tone="neutral" size="sm">{t('add.multi.state.removed')}</Badge>;
            if (state.check === 'works') return <Badge tone="good" size="sm">{t('add.multi.state.works')}</Badge>;
            if (state.check === 'failed') return <Badge tone="bad" size="sm">{t('add.multi.state.failed')}</Badge>;
            if (state.check === 'when_used') return <Badge tone="neutral" size="sm" icon={false}>{t('add.multi.state.when_used')}</Badge>;
            return <Badge tone="good" size="sm">{t('add.multi.state.added')}</Badge>;
        case 'refused':
            return <Badge tone="bad" size="sm">{t('add.multi.state.not_added')}</Badge>;
        case 'declined':
            return <Badge tone="neutral" size="sm" icon={false}>{t('add.multi.state.not_added')}</Badge>;
        default:
            return null;
    }
}
