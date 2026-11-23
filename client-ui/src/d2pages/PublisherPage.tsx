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
import { errorText } from '../lib/errorText';
import { engineStatus } from '../lib/bridge';
import { parseEngineStatus, publisherBootFailureKey } from '../lib/engineStart';
import { FailureBox } from './PageNotices';
import PublisherWizard from '../publisher/PublisherWizard';
import PublisherRecipientsPage from '../publisher/PublisherRecipientsPage';
import RelayListPage, { relayTitle } from '../publisher/RelayListPage';
import CustodyGate from '../publisher/CustodyGate';
import BackupPage from '../publisher/BackupPage';
import RestorePage from '../publisher/RestorePage';
import AccountsPage from '../publisher/AccountsPage';
import { Wizard } from '../publisher/wizardCommands';
import { notesTickOnce } from '../publisher/addons/wizardAddons';
import type { OperatorSummary } from '../publisher/wizardCommands';
import { useBack } from '../lib/useBack';

export type View =
    | { k: 'loading' }
    | { k: 'list' }
    /** `from: 'list'`: opened from the relay list, so Back at the first
     *  step returns there. Absent: the wizard is the root view (no
     *  relays yet), and Back at the first step leaves the app. */
    | { k: 'wizard'; operatorId?: number; from?: 'list' }
    /** `addPerson`: open with "Add a person" showing (from the wizard). */
    | { k: 'relay'; operatorId: number; addPerson?: boolean }
    | { k: 'backup' }
    | { k: 'restore'; from: 'list' | 'wizard' }
    /** «حساب‌ها»: from the list, or from a relay page (Back returns there). */
    | { k: 'accounts'; from: 'list' | number };

/** Where a restore page goes back to. */
export function restoreBackView(from: 'list' | 'wizard'): View {
    return from === 'list' ? { k: 'list' } : { k: 'wizard' };
}

/** The relay page is an inner page of the list: Back returns there. The
 *  backup, restore and wizard views answer Back themselves (they know
 *  when they are busy). */
export function pageBackTarget(view: View): View | null {
    return view.k === 'relay' ? { k: 'list' } : null;
}

/** Where the Publisher tab opens: always the publisher page (the relay
 *  list, with the tools under it), which is also the "set up a relay"
 *  empty state when there are none. It used to jump straight into a lone
 *  relay (spec C7.0); the owner found that hid the publisher page and
 *  everything on it (2026-11-22). */
export function bootView(_ops: OperatorSummary[] | null): View {
    return { k: 'list' };
}

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
    // The list could not be read: the i18n key of OUR sentence, and the
    // raw error text for the Details fold only. The raw text used to be
    // printed as the sentence — Tauri's "state not managed…" in red.
    const [bootError, setBootError] = useState<{ key: string; detail: string } | null>(null);
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
            // A rejected command may be a string, an Error or an
            // object; String() turns the last into "[object Object]".
            const raw = errorText(e);
            // engine_status never rejects; it says whether this is a
            // start problem (restart) or something to try again.
            const status = parseEngineStatus(await engineStatus());
            setBootError({
                key: publisherBootFailureKey(raw, status),
                detail: status?.publisherStoreError ?? raw,
            });
            return null;
        }
    }, []);

    useEffect(() => {
        void (async () => {
            // Never the wizard by itself: with no relays the list shows
            // what a relay costs and one "Start" (C7.1). A read error
            // also lands on the list, which shows it and still offers a
            // new relay.
            const ops = await refreshOperators();
            setView(bootView(ops));
            // The update notes move with the week: filler at the start
            // of a new one, a reveal kept readable (addon_notes.rs).
            if (ops && ops.length > 0) notesTickOnce();
        })();
    }, [refreshOperators]);

    const toList = useCallback(() => {
        setListNonce((n) => n + 1);
        setView({ k: 'list' });
    }, []);

    // System Back on the relay page: the same as its own Back button.
    useBack(
        pageBackTarget(view) !== null,
        () => {
            void refreshOperators();
            toList();
        },
        'page',
    );

    return (
        <div
            // `daal-publisher` (styles.css) lets every descendant shrink and
            // breaks long atomic strings — file names, daal1… addresses,
            // fingerprints — which otherwise widen the page and push the
            // right-hand buttons off screen.
            className="daal-publisher"
            style={{
                minHeight: '100%',
                // The desktop <main> is a flex row: without a width the
                // page shrinks to its content and looks like a phone card
                // parked in a corner. Full width here; each page caps its
                // own column at --content-max, like Settings and Files.
                width: '100%',
                flex: '1 1 auto',
                maxWidth: '100%',
                overflowX: 'hidden',
            }}
        >
            {/* Renders nothing on a healthy device. On one upgrading from
                the PIN build it blocks everything below until the signing
                key is safely under DeviceCustody. */}
            <CustodyGate t={t} operators={operators}>
                {bootError && (
                    <div style={{ padding: '10px 16px 0 16px' }}>
                        <FailureBox
                            t={t}
                            text={t(bootError.key)}
                            detail={bootError.detail}
                            onRetry={
                                bootError.key === 'pub.boot.unavailable'
                                    ? undefined
                                    : () => void refreshOperators()
                            }
                        />
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
                        onNew={() => setView({ k: 'wizard', from: 'list' })}
                        onResume={(id) =>
                            setView({ k: 'wizard', operatorId: id, from: 'list' })
                        }
                        onBackup={() => setView({ k: 'backup' })}
                        onRestore={() => setView({ k: 'restore', from: 'list' })}
                        onAccounts={() => setView({ k: 'accounts', from: 'list' })}
                    />
                )}

                {view.k === 'accounts' && (
                    <AccountsPage
                        t={t}
                        backLabel={
                            view.from === 'list'
                                ? t('pub.relays.title')
                                : (() => {
                                      const op = operators.find((o) => o.id === view.from);
                                      return op ? relayTitle(op) : t('pub.relays.title');
                                  })()
                        }
                        onBack={() => {
                            if (view.from === 'list') toList();
                            else setView({ k: 'relay', operatorId: view.from });
                        }}
                    />
                )}

                {view.k === 'wizard' && (
                    <PublisherWizard
                        t={t}
                        operatorId={view.operatorId}
                        // The handoff that kills step 7: the wizard's last
                        // act is to name the relay it built and get out of
                        // the way.
                        onDone={(id, addPerson) => {
                            void refreshOperators();
                            setView({ k: 'relay', operatorId: id, addPerson });
                        }}
                        onCancel={toList}
                        // Back at the first step: only when there is a
                        // list to go back to. Never a cancel: an
                        // unfinished relay stays resumable from the list.
                        rootBack={view.from === 'list' ? toList : undefined}
                        onRestore={() => setView({ k: 'restore', from: 'wizard' })}
                    />
                )}

                {view.k === 'backup' && <BackupPage t={t} onBack={toList} />}

                {view.k === 'restore' && (
                    <RestorePage
                        t={t}
                        onBack={() => {
                            if (view.from === 'list') toList();
                            else setView(restoreBackView('wizard'));
                        }}
                        onDone={() => {
                            void refreshOperators();
                            toList();
                        }}
                    />
                )}

                {view.k === 'relay' && (
                    <PublisherRecipientsPage
                        key={view.operatorId}
                        t={t}
                        operatorId={view.operatorId}
                        openAdd={view.addPerson}
                        onBackup={() => setView({ k: 'backup' })}
                        onAccounts={() => setView({ k: 'accounts', from: view.operatorId })}
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
