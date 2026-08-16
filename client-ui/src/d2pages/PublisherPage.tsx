// PublisherPage — D-2 §3.5 publisher surface. Owns the view state
// machine for the whole publisher IA; the shells mount it with no
// navigation props and that stays true.
//
// This page used to be a SETUP / RECIPIENTS tab switcher. That was the
// wrong shape twice over:
//
//   * Setup is a one-time event. Giving it a permanent tab meant a
//     user with a working relay stared at a 7-step provisioning wizard
//     every time they opened the publisher surface.
//   * The wizard's last step ("distribute") was a second copy of the
//     recipients tab, and its own help text told the user to walk
//     *backwards* through the setup wizard to re-send a pack.
//
// The replacement is a plain state machine. If you have no relays you
// get the wizard, because that is the only thing you can do. If you
// have relays you get the list, because choosing one is the only thing
// you can do. The wizard hands off to relay detail when it finishes and
// is never seen again unless you ask for another relay.

import { useCallback, useEffect, useState } from 'react';
import type { Locale } from '../lib/i18n';
import PublisherWizard from '../publisher/PublisherWizard';
import PublisherRecipientsPage from '../publisher/PublisherRecipientsPage';
import RelayListPage from '../publisher/RelayListPage';
import CustodyGate from '../publisher/CustodyGate';
import { Wizard } from '../publisher/wizardCommands';
import type { OperatorSummary } from '../publisher/wizardCommands';

type View =
    | { k: 'loading' }
    | { k: 'list' }
    | { k: 'wizard'; operatorId?: number }
    | { k: 'relay'; operatorId: number };

interface Props {
    t: (k: string) => string;
    locale?: Locale;
}

export default function PublisherPage({ t, locale: _locale = 'en' }: Props) {
    // 'loading' exists purely so the wizard never flashes on screen for
    // the frame before listOperators resolves. Seeing "Connect your
    // cloud account" and then having it vanish reads as a crash.
    const [view, setView] = useState<View>({ k: 'loading' });
    const [operators, setOperators] = useState<OperatorSummary[]>([]);
    const [bootError, setBootError] = useState<string | null>(null);
    // Bumped whenever we return to the list, so RelayListPage remounts
    // and refetches instead of showing a stale relay it no longer has.
    const [listNonce, setListNonce] = useState(0);

    // Refresh only. Deliberately does NOT touch `view` — routing is a
    // boot-time decision plus explicit user actions; an async refetch
    // landing after a navigation must never yank the user somewhere else.
    const refreshOperators = useCallback(async () => {
        try {
            const ops = await Wizard.listOperators();
            setOperators(ops);
            setBootError(null);
            return ops;
        } catch (e) {
            setBootError(String(e));
            return null;
        }
    }, []);

    useEffect(() => {
        void (async () => {
            const ops = await refreshOperators();
            if (ops === null) {
                // Never trap the user inside a setup wizard because of a
                // transient IPC error — the list can show the error and
                // still offer "+ New relay".
                setView({ k: 'list' });
                return;
            }
            const live = ops.filter((o) => o.status !== 'decommissioned');
            setView(live.length === 0 ? { k: 'wizard' } : { k: 'list' });
        })();
    }, [refreshOperators]);

    const toList = useCallback(() => {
        setListNonce((n) => n + 1);
        setView({ k: 'list' });
    }, []);

    return (
        <div
            // `daal-publisher` (styles.css) lets every descendant shrink and
            // breaks long atomic strings — file names, daal1… addresses,
            // fingerprints — which otherwise widen the page and push the
            // right-hand buttons off screen.
            className="daal-publisher"
            style={{
                // Cyan accent surface treatment per brief §10.1: a faint
                // colored hairline + accent on links/CTAs marks
                // "advanced" so users always know they're in the
                // publisher surface.
                borderTop: '2px solid var(--cyan)',
                minHeight: '100%',
                maxWidth: '100%',
                overflowX: 'hidden',
            }}
        >
            {/* Renders nothing on a healthy device. On one upgrading from
                the PIN build it blocks everything below until the signing
                key is safely under DeviceCustody. */}
            <CustodyGate t={t} operators={operators}>
                {bootError && (
                    <div
                        style={{
                            color: 'var(--red)',
                            fontSize: 12,
                            padding: '10px 16px 0 16px',
                        }}
                    >
                        {bootError}
                    </div>
                )}

                {view.k === 'loading' && (
                    <div
                        style={{
                            padding: '16px',
                            fontSize: 13,
                            color: 'var(--muted)',
                        }}
                    >
                        {t('common.loading')}
                    </div>
                )}

                {view.k === 'list' && (
                    <RelayListPage
                        key={listNonce}
                        t={t}
                        onOpen={(id) => setView({ k: 'relay', operatorId: id })}
                        onNew={() => setView({ k: 'wizard' })}
                        onResume={(id) =>
                            setView({ k: 'wizard', operatorId: id })
                        }
                    />
                )}

                {view.k === 'wizard' && (
                    <PublisherWizard
                        t={t}
                        operatorId={view.operatorId}
                        // The handoff that kills step 7: the wizard's last
                        // act is to name the relay it built and get out of
                        // the way.
                        onDone={(id) => {
                            void refreshOperators();
                            setView({ k: 'relay', operatorId: id });
                        }}
                        onCancel={toList}
                    />
                )}

                {view.k === 'relay' && (
                    <PublisherRecipientsPage
                        t={t}
                        operatorId={view.operatorId}
                        onBack={() => {
                            void refreshOperators();
                            toList();
                        }}
                    />
                )}
            </CustodyGate>
        </div>
    );
}
