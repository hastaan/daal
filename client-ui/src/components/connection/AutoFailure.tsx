// AutoFailure — the "Details" fold under a failed connect on Home.
//
// The headline ("Couldn't connect"), the one line of what to do, "Try
// again" and the one link are drawn by the page from lib/mainScreen.ts.
// This fold adds how much Daal tried ("Tried 3 ways") and, when the page
// passes them, each try by kind of connection with its reason in plain
// words ("VLESS Reality — the server did not answer"). In developer
// mode it also lists each try the way the engine names it (route id,
// family token, result, category, time) — the only place those words
// are printed, left-to-right and in a fixed-width face, for the person
// helping from the other end.
//
// Under the fold, once Daal's own ways have run out (handoffShown), the
// hand-off card names other organisations' apps that may work right now
// (HandoffCard.tsx). It is outside the fold so it is seen without a tap.
import { sep } from '../../lib/format';
import type { AutoTried } from '../../contract/D2Contract';
import { Disclosure } from '../../design/primitives';
import { autoResultKey } from '../../lib/autoConnect';
import { toFaDigits } from '../../lib/i18n';
import type { TriedRow } from '../../lib/homeFacts';
import { TriedList } from './HomeFacts';
import HandoffCard, { handoffShown } from './HandoffCard';

interface Props {
    t: (k: string) => string;
    locale?: string;
    tried: readonly AutoTried[];
    /** The engine's verdict code, printed in developer mode only. */
    verdict: string;
    /** Developer mode: the per-try lines and the verdict code. */
    dev?: boolean;
    /** Open at first (tests, and the desktop failed panel). */
    defaultOpen?: boolean;
    /** Each try by kind of connection, with its reason in plain words
     *  (lib/homeFacts.ts triedRows). Shown to everyone. */
    rows?: readonly TriedRow[];
    /** The "Other apps that may work right now" card. Shown by default
     *  after a verdict that means Daal's ways ran out; `false` hides it
     *  (a page that draws it elsewhere). */
    handoff?: boolean;
    /** Tor bridge lines this build cannot dial, to pass to Orbot. */
    bridgeLines?: readonly string[];
}

/** One tried route as the engine names it: id, kind, result, category,
 *  then — when the engine said — how long this attempt took and which
 *  route it was tried at the same time as. Developer mode only. */
export function triedCode(x: AutoTried): string {
    return [
        x.routeId,
        x.family,
        x.result,
        x.category,
        x.setupMs !== undefined ? `${x.setupMs} ms` : '',
        x.racedWith ? `with ${x.racedWith}` : '',
    ]
        .filter(Boolean)
        .join(sep());
}

/** "Tried 3 ways" in the page's language, or the line for none. */
export function triedSummary(t: (k: string) => string, locale: string | undefined, n: number): string {
    if (n === 0) return t('auto.details.none');
    const num = locale === 'fa' ? toFaDigits(String(n)) : String(n);
    return t(n === 1 ? 'auto.details.tried_one' : 'auto.details.tried_n').replace('{n}', num);
}

export default function AutoFailure({ t, locale, tried, verdict, dev, defaultOpen, rows, handoff = true, bridgeLines }: Props) {
    return (
        <>
        <Disclosure summary={t('ui.details')} dataButton="failure-details" defaultOpen={defaultOpen}>
            <div style={{ fontSize: 13, color: 'var(--muted)', textAlign: 'start' }}>
                <div>{triedSummary(t, locale, tried.length)}</div>
                {rows && rows.length > 0 && (
                    <div style={{ marginBlockStart: 10 }}>
                        <TriedList rows={rows} />
                    </div>
                )}
                {dev && tried.length > 0 && (
                    <ol data-dev style={{ margin: '6px 0 0', paddingInlineStart: 20 }}>
                        {tried.map((x, i) => (
                            <li key={`${x.routeId}-${i}`} style={{ marginBlockEnd: 4 }}>
                                <span>{t(autoResultKey(x.result))}</span>{' '}
                                <code
                                    dir="ltr"
                                    style={{
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 11,
                                        overflowWrap: 'anywhere',
                                        unicodeBidi: 'isolate',
                                    }}
                                >
                                    {triedCode(x)}
                                </code>
                            </li>
                        ))}
                    </ol>
                )}
                {dev && verdict && (
                    <code
                        data-dev
                        dir="ltr"
                        style={{
                            display: 'block',
                            marginBlockStart: 6,
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            unicodeBidi: 'isolate',
                        }}
                    >
                        {verdict}
                    </code>
                )}
            </div>
        </Disclosure>
        {handoff && handoffShown(verdict) && <HandoffCard t={t} bridgeLines={bridgeLines} />}
        </>
    );
}
