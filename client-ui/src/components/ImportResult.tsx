// ImportResult.tsx — what the add sheet and the scanner show once a file
// has been read (spec C3.5, C3.6, C3.3a key-changed).
//
//   done     "File added", "From {name}", one gold "Connect", "Not now".
//            When the file gave this phone fewer ways than it lists, one
//            fold says so — "Nothing is wrong with your phone." — and the
//            protocol names appear only in developer mode.
//   refused  "This file isn't safe to use" + the reason, and only Close.
//   changed  the publisher's key changed or was withdrawn: "Don't use
//            this file", the warning to check with them in person or by
//            voice, and only Close. Blocking: nothing to accept here.
//
// `importOutcome` is the one reading of an engine verdict that the
// paste, file and scan lanes share: a verdict that needs the trust
// question, one that was refused (and how), or one that was imported.

import type { PreviewedBundle } from '../contract/D2Contract';
import { Button, Disclosure, StateIcon } from '../design/primitives';
import { useDeveloperMode } from '../lib/devMode';
import {
    KIND_REJECTED,
    KIND_TRUST_PROMPT_NEEDED,
    friendlyReason,
    trustFailure,
    trustFromVerdict,
    unavailableLines,
    type ImportVerdict,
    type TrustResolution,
} from '../lib/importVerdict';

type T = (k: string) => string;

/** The two refusals that mean "the person who sent it is not who this
 *  phone trusts any more": blocking, with the check-in-person warning. */
const CHANGED_REASONS = new Set(['publisher_key_changed', 'publisher_revoked']);

export type ImportOutcome =
    | { kind: 'trust'; preview: PreviewedBundle }
    | { kind: 'done'; verdict: ImportVerdict | null }
    | { kind: 'refused'; text: string; changed: boolean };

/** What a verdict from importSbp / importSbpBytes / the scanner means.
 *  A non-JSON answer (an older engine) parses to null upstream and is an
 *  import, as it always was. */
export function importOutcome(t: T, v: ImportVerdict | null, base: PreviewedBundle | null): ImportOutcome {
    if (v && v.Kind === KIND_TRUST_PROMPT_NEEDED) return { kind: 'trust', preview: trustFromVerdict(base, v) };
    if (v && v.Kind === KIND_REJECTED) {
        const reason = v.Reason || '';
        return { kind: 'refused', text: friendlyReason(t, reason), changed: CHANGED_REASONS.has(reason) };
    }
    return { kind: 'done', verdict: v };
}

/** What the answer to the trust question means. `null` = the person
 *  said No: nothing was added and there is nothing to report. */
export function trustOutcome(t: T, r: TrustResolution): ImportOutcome | null {
    if (r.decision === 2) return null;
    const failure = trustFailure(t, r);
    if (failure) {
        const reason = r.verdict?.Kind === KIND_REJECTED ? r.verdict.Reason || '' : '';
        return { kind: 'refused', text: failure, changed: CHANGED_REASONS.has(reason) };
    }
    return { kind: 'done', verdict: r.verdict };
}

interface Props {
    t: T;
    outcome: Exclude<ImportOutcome, { kind: 'trust' }>;
    /** The publisher's name, when known: "From {name}". */
    name?: string;
    /** Present when "Connect" can start a connection from here. */
    onConnect?: () => void;
    onClose: () => void;
}

function Heading({ state, title }: { state: 'ok' | 'bad'; title: string }) {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, textAlign: 'center' }}>
            <StateIcon state={state} size={56} />
            <h2
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 'var(--fs-xl)',
                    fontWeight: 600,
                    margin: 0,
                    color: 'var(--fg)',
                }}
            >
                {title}
            </h2>
        </div>
    );
}

export default function ImportResult({ t, outcome, name, onConnect, onClose }: Props) {
    const dev = useDeveloperMode();
    if (outcome.kind === 'refused') {
        return (
            <div role="alert" data-testid="import-refused" style={{ display: 'grid', gap: 16, padding: '8px 0 4px' }}>
                <Heading state="bad" title={t(outcome.changed ? 'trust.changed.title' : 'add.refused.title')} />
                <p style={{ margin: 0, fontSize: 14, color: 'var(--muted)', textAlign: 'center', lineHeight: 1.5 }}>
                    {outcome.text}
                </p>
                <Button variant="secondary" block onClick={onClose} dataButton="import-close">
                    {t('ui.close')}
                </Button>
            </div>
        );
    }
    const lines = unavailableLines(t, outcome.verdict);
    return (
        <div data-testid="import-done" style={{ display: 'grid', gap: 14, padding: '8px 0 4px' }}>
            <Heading state="ok" title={t('add.done')} />
            {name && (
                <p style={{ margin: 0, fontSize: 14, color: 'var(--muted)', textAlign: 'center' }}>
                    <bdi>{t('add.done.from').replace('{name}', name)}</bdi>
                </p>
            )}
            {lines.length > 0 && (
                <div data-testid="unavailable-routes" style={{ display: 'flex', justifyContent: 'center' }}>
                    <Disclosure summary={t('add.unavailable.title')} dataButton="import-partial">
                        <div style={{ fontSize: 13, color: 'var(--muted)', textAlign: 'start' }}>
                            <div>{t('add.unavailable.fine')}</div>
                            {dev && (
                                <ul data-dev style={{ margin: '6px 0 0', paddingInlineStart: 18 }}>
                                    {lines.map((line, i) => (
                                        <li key={i}>{line}</li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </Disclosure>
                </div>
            )}
            <div style={{ display: 'grid', gap: 4 }}>
                {onConnect && (
                    <Button block onClick={onConnect} dataButton="import-connect">
                        {t('add.done.connect')}
                    </Button>
                )}
                {onConnect ? (
                    <Button variant="link" block onClick={onClose} dataButton="import-later">
                        {t('add.done.later')}
                    </Button>
                ) : (
                    <Button variant="secondary" block onClick={onClose} dataButton="import-close">
                        {t('ui.close')}
                    </Button>
                )}
            </div>
        </div>
    );
}
