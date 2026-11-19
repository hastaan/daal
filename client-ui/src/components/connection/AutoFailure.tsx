// AutoFailure — what the main screen says when automatic connect found
// no way that works.
//
// The headline above this box already carries the ONE sentence for the
// engine's verdict. This adds what the person can do, a "Try again"
// button, "Add your file" when there is nothing to connect with, and a
// Details fold holding the per-route list — the only place a route id,
// a family name or a category code is printed, left-to-right and in a
// fixed-width face, for the person helping from the other end.
//
// Every button here does something: "Try again" is off (and the wait is
// said) while the ways are resting, is absent where trying again cannot
// change the answer, and "Choose one yourself" / "Disconnect" appear
// where those are the way forward. The same box serves the Android
// "holding" state — the VPN kept closed while Daal retries — where the
// headline is about that and the verdict moves in here (`lead`).
import type { AutoTried } from '../../contract/D2Contract';
import { Button } from '../../design/primitives';
import { autoResultKey } from '../../lib/autoConnect';

interface Props {
    t: (k: string) => string;
    /** The whole "what to do" line, already translated. */
    actionText: string;
    tried: readonly AutoTried[];
    /** The engine's verdict code, printed under Details only. */
    verdict: string;
    /** Absent when trying again cannot change the answer. */
    onRetry?: () => void;
    /** Present when adding a file is the way forward. */
    onAddFile?: () => void;
    /** A sentence above the action line (the verdict, when the headline
     *  is used for something else). */
    lead?: string;
    /** "You can try again in…": the ways are resting. */
    restText?: string;
    /** "Try again" is shown but off: it would do nothing right now. */
    retryOff?: boolean;
    /** Words on the retry button other than "Try again". */
    retryLabel?: string;
    /** Present when choosing a way by hand is the way forward. */
    onChoose?: () => void;
    /** Present when the VPN is being held closed: let go of it. */
    onDisconnect?: () => void;
}

export default function AutoFailure({
    t,
    actionText,
    tried,
    verdict,
    onRetry,
    onAddFile,
    lead,
    restText,
    retryOff,
    retryLabel,
    onChoose,
    onDisconnect,
}: Props) {
    const other = !!onAddFile || !!onChoose;
    return (
        <div
            role="alert"
            style={{
                maxWidth: 520,
                inlineSize: '100%',
                marginBlockEnd: 16,
                padding: '12px 16px',
                borderRadius: 12,
                border: '1px solid var(--teal-hairline)',
                background: 'var(--surface-2, transparent)',
                color: 'var(--fg)',
                textAlign: 'center',
                fontSize: 14,
            }}
        >
            {lead && <div style={{ marginBlockEnd: 8 }}>{lead}</div>}
            <div style={{ marginBlockEnd: 12 }}>{actionText}</div>
            {restText && (
                <div data-rest style={{ marginBlockEnd: 12, color: 'var(--ink-soft)' }}>
                    {restText}
                </div>
            )}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'center', flexWrap: 'wrap' }}>
                {onAddFile && <Button onClick={onAddFile}>{t('auto.add_file')}</Button>}
                {onChoose && <Button onClick={onChoose}>{t('auto.choose_yourself')}</Button>}
                {onRetry && (
                    <Button variant={other ? 'secondary' : 'primary'} onClick={onRetry} disabled={retryOff}>
                        {retryLabel ?? t('auto.try_again')}
                    </Button>
                )}
                {onDisconnect && (
                    <Button variant="secondary" onClick={onDisconnect}>
                        {t('auto.holding.disconnect')}
                    </Button>
                )}
            </div>
            <details style={{ marginBlockStart: 12, color: 'var(--muted)', fontSize: 12, textAlign: 'start' }}>
                <summary style={{ cursor: 'pointer' }}>{t('network.error_details')}</summary>
                <div style={{ marginBlockStart: 6 }}>
                    {tried.length > 0 ? t('auto.details.intro') : t('auto.details.none')}
                </div>
                {tried.length > 0 && (
                    <ol style={{ margin: '6px 0 0', paddingInlineStart: 20 }}>
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
                                    {[x.routeId, x.family, x.result, x.category].filter(Boolean).join(' · ')}
                                </code>
                            </li>
                        ))}
                    </ol>
                )}
                {verdict && (
                    <code
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
            </details>
        </div>
    );
}
