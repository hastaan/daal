// ScanSheet.tsx — the mount point for the QR-fountain receive lane.
//
// WHY THIS EXISTS INSTEAD OF AddEntryModal
//
// `RecipientImport` had exactly one caller, `AddEntryModal`, and
// `AddEntryModal` was itself imported by nothing: the scanner was
// unreachable from the running app. The fix is NOT to mount
// AddEntryModal — it is a second, older, half-finished copy of the
// intake flow that `AddSheet` already does for real (its own
// `onChooseFile` is an empty stub), and mounting it would give the
// user two different Add screens that disagree.
//
// So the scanner gets a mount of its own, following the exact pattern
// `MyAddressSheet` already established for the other recipient-side
// surface: a thin Sheet wrapper around a `recipient/` component,
// opened from a dedicated action in the Network page header. One
// component, one job, actually reachable.
//
// WHAT THIS SHEET OWNS: THE VERDICT
//
// `RecipientImport` decodes; deciding what a verdict MEANS belongs
// here, and it is the same decision the paste and file lanes make —
// `lib/importVerdict` is the single copy all three read.
//
// This used to be `onVerdict={() => { onImported(); onClose(); }}`:
// the verdict string was discarded. For a bundle that arrives by
// animated QR the normal verdict is Kind 1, first-seen publisher —
// offline distribution means, by construction, a publisher this device
// has never met. The routes do NOT commit until `resolveTrustPrompt`
// is called, so the old code closed the sheet, asked the page to
// reload, and showed the user a list with nothing new in it while the
// bundle sat unresolved in the engine's pending store. A rejected
// bundle looked exactly the same: silent success.

import { useState } from 'react';
import RecipientImport from '../recipient/RecipientImport';
import TrustPrompt from './TrustPrompt';
import { Sheet } from '../design/primitives';
import type { PreviewedBundle } from '../contract/D2Contract';
import {
    KIND_REJECTED,
    KIND_TRUST_PROMPT_NEEDED,
    friendlyReason,
    parseVerdict,
    trustFailure,
    trustFromVerdict,
    type TrustResolution,
} from '../lib/importVerdict';

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    /** Called once routes have actually committed, so the page can
     *  reload its route list. NOT called merely because a scan
     *  finished decoding. */
    onImported?: () => void;
}

export default function ScanSheet({ t, onClose, onImported }: Props) {
    const [awaitingTrust, setAwaitingTrust] = useState<PreviewedBundle | null>(null);
    const [rejected, setRejected] = useState<string | null>(null);

    /** The decoded bundle's verdict, read exactly as the paste and file
     *  lanes read theirs. */
    const onVerdict = (raw: string) => {
        const v = parseVerdict(raw);
        if (v && v.Kind === KIND_TRUST_PROMPT_NEEDED) {
            // Hold the sheet open on the EN+FA word grid. A route that
            // arrived over a camera does not get a quieter trust
            // decision than one that arrived as a file.
            setAwaitingTrust(trustFromVerdict(null, v));
            return;
        }
        if (v && v.Kind === KIND_REJECTED) {
            setRejected(friendlyReason(t, v.Reason || ''));
            return;
        }
        // Imported, or accepted via a valid rotation chain.
        onImported?.();
        onClose();
    };

    /** TrustPrompt has called resolveTrustPrompt and is handing us what
     *  the ENGINE said. That call re-verifies the pending bundle before
     *  committing, so "the user tapped Trust" is not the same as "the
     *  routes committed": a revocation arriving mid-prompt, an expiry,
     *  or a full disk all come back as a rejection here. Reporting
     *  success on the tap alone would make a refused pack and a trusted
     *  pack look identical, on the one screen where that must never
     *  happen. */
    const onTrustResolved = (r: TrustResolution) => {
        setAwaitingTrust(null);
        const failure = trustFailure(t, r);
        if (failure) {
            // Stay on the sheet and say why. Do NOT call onImported.
            setRejected(failure);
            return;
        }
        if (r.decision !== 2) onImported?.();
        onClose();
    };

    return (
        <Sheet title={t('scan.title')} onClose={onClose} width={560}>
            {awaitingTrust ? (
                <TrustPrompt t={t} preview={awaitingTrust} onResolve={onTrustResolved} />
            ) : rejected ? (
                <div role="alert" style={{ marginTop: 18 }}>
                    <h3
                        style={{
                            fontFamily: 'var(--font-display)',
                            fontSize: 16,
                            margin: 0,
                            marginBottom: 6,
                        }}
                    >
                        {t('scan.err.title')}
                    </h3>
                    <p style={{ fontSize: 13, margin: 0 }}>{rejected}</p>
                </div>
            ) : (
                <RecipientImport t={t} onVerdict={onVerdict} onClose={onClose} />
            )}
        </Sheet>
    );
}
