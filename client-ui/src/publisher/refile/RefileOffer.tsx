// RefileOffer — the calm card right after a removal ("Give the others
// new files"), and the hook that decides when "New files for everyone"
// is offered at all (refile.ts). Reads only this phone's ledger and the
// standby code's form: no relay round trip, no cost.
import { useCallback, useEffect, useState } from 'react';
import { Button } from '../../design/primitives';
import type { AddonRow } from '../addons/addonTypes';
import { Addons } from '../wizardCommands';
import { hasStandby, refileAvailable, refileNudge, refileReason } from './refile';

type T = (k: string) => string;

export interface RefileOfferState {
    /** "New files for everyone" belongs in the people ⋯ menu. */
    available: boolean;
    /** The card after a removal is showing. */
    nudge: boolean;
    /** Call after a person was removed: shows the card when the code
     *  went plain. */
    afterRemoval: () => Promise<void>;
    dismiss: () => void;
    /** Why new files are wanted (refileReason). */
    reason: 'code' | 'updates';
}

export function useRefileOffer(operatorId: number, current: number, everyone: boolean, enabled = true): RefileOfferState {
    const [addons, setAddons] = useState<AddonRow[] | null>(null);
    const [nudge, setNudge] = useState(false);

    const readAddons = useCallback(async (): Promise<AddonRow[]> => {
        try {
            const rows = await Addons.list(operatorId);
            setAddons(rows);
            return rows;
        } catch {
            setAddons([]);
            return [];
        }
    }, [operatorId]);

    useEffect(() => {
        if (enabled) void readAddons();
    }, [enabled, readAddons]);

    const facts = { standby: hasStandby(addons), everyone, current };

    const afterRemoval = useCallback(async () => {
        if (!enabled) return;
        const rows = await readAddons();
        const f = { standby: hasStandby(rows), everyone, current };
        let form: 'wrapped' | 'plain' | undefined;
        try {
            form = (await Addons.standbyKey({ operator_id: operatorId })).form;
        } catch {
            form = undefined;
        }
        setNudge(refileNudge(f, form));
    }, [current, enabled, everyone, operatorId, readAddons]);

    return {
        available: enabled && refileAvailable(facts),
        nudge: nudge && enabled && refileAvailable(facts),
        afterRemoval,
        dismiss: () => setNudge(false),
        reason: refileReason(addons),
    };
}

export function RefileOffer({ t, onOpen, onDismiss }: { t: T; onOpen: () => void; onDismiss: () => void }) {
    return (
        <div
            data-testid="refile-offer"
            style={{
                border: '1px solid var(--line)',
                borderRadius: 'var(--r-card)',
                background: 'var(--surface)',
                padding: '12px 14px',
                display: 'grid',
                gap: 8,
            }}
        >
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>{t('pub.refile.offer.title')}</div>
            <div style={{ fontSize: 13, lineHeight: 1.5, color: 'var(--muted)' }}>{t('pub.refile.offer.line')}</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <Button size="sm" leading="refresh" onClick={onOpen} dataButton="refile-open">
                    {t('pub.refile.menu')}
                </Button>
                <Button size="sm" variant="secondary" onClick={onDismiss} dataButton="refile-later">
                    {t('pub.refile.offer.later')}
                </Button>
            </div>
        </div>
    );
}
