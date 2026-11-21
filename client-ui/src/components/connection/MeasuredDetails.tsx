// MeasuredDetails — "How each way has done on this network", folded
// away under the main screen's chooser.
//
// The main path says one plain phrase about quality at most. This fold
// is for the person helping from the other end: per route, the same
// phrase, then the numbers (how long it takes to connect, how often it
// was tried, worked and failed here) and — left-to-right, fixed width —
// the route id, its kind and the engine's own grade code. It is the
// ONLY place on the main screen where milliseconds or a kind of
// connection are printed.
//
// Offered only when the engine sent a measurement for at least one
// route (lib/measured.ts anyMeasured): no empty box for an engine that
// measures nothing.
import type { RouteDisplayRow } from '../../contract/D2Contract';
import { gradeText, measuredCode, measuredWords } from '../../lib/measured';
import { routeLabel } from './WayChooser';

interface Props {
    t: (k: string) => string;
    locale: string;
    routes: readonly RouteDisplayRow[];
    /** The fold was opened: the page reads the list again, so the
     *  numbers are the ones of this moment. */
    onOpen?: () => void;
}

export default function MeasuredDetails({ t, locale, routes, onOpen }: Props) {
    const rows = routes.filter((r) => r.measured !== undefined);
    const tried = rows.some((r) => r.measured!.grade !== 'unknown');
    return (
        <details
            onToggle={(e) => {
                if ((e.currentTarget as HTMLDetailsElement).open) onOpen?.();
            }}
            style={{
                maxWidth: 520,
                inlineSize: '100%',
                marginBlockEnd: 12,
                color: 'var(--muted)',
                fontSize: 12,
                textAlign: 'start',
            }}
        >
            <summary style={{ cursor: 'pointer', textAlign: 'center' }}>{t('measure.details.title')}</summary>
            <div style={{ marginBlockStart: 6 }}>
                {tried ? t('measure.details.intro') : t('measure.details.none')}
            </div>
            <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
                {rows.map((r) => {
                    const words = measuredWords(t, locale, r.measured!);
                    return (
                        <li key={r.routeId} style={{ marginBlockEnd: 8 }}>
                            <div>
                                <bdi>{routeLabel(t, r, routes)}</bdi>
                                {' — '}
                                {gradeText(t, r.measured)}
                            </div>
                            {words && <div>{words}</div>}
                            <code
                                dir="ltr"
                                style={{
                                    display: 'block',
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 11,
                                    overflowWrap: 'anywhere',
                                    unicodeBidi: 'isolate',
                                }}
                            >
                                {measuredCode(r.routeId, r.family, r.measured)}
                            </code>
                        </li>
                    );
                })}
            </ul>
        </details>
    );
}
