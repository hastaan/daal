// relayStatus — the one badge a relay shows (spec C7.1), on the list and
// on its own page, from the same function so the two cannot disagree.
//
// The relay list once showed a green "LIVE" pill directly above the
// sentence "Setup state — not a live health check." Both were drawn
// from the same field: `status`, which is what the app last RECORDED
// about the relay, not something anybody measured. The rule is kept:
// green ("Working") comes only from a health check that said so. What
// the app merely recorded is "Not checked", "Unfinished · may cost
// money" (MUST KEEP 1), "Server gone" or "Retired", never green. Even
// green means "answers from where this phone is"; the health card says
// so under the badge every time (MUST KEEP 7).

import type { BadgeTone } from '../design/primitives';
import type { OperatorSummary, RelayHealth } from './wizardCommands';

export type RelayStateIcon = 'ok' | 'warn' | 'bad' | 'busy' | 'off' | 'none';

export interface RelayLook {
    tone: BadgeTone;
    /** i18n key. */
    labelKey: string;
    /** The StateIcon at the start of the relay's row. */
    icon: RelayStateIcon;
    /** The text must never be cut short ("may cost money"). */
    wrap?: boolean;
    /** True when nothing measured it: the label is only what was recorded. */
    recordedOnly: boolean;
}

/** A relay that has no signed file yet is resumed in the wizard. */
export function relayUnfinished(op: Pick<OperatorSummary, 'status' | 'has_signed_sbp'>): boolean {
    return op.status !== 'decommissioned' && op.status !== 'rebuild_failed' && !op.has_signed_sbp;
}

export function relayLook(
    op: Pick<OperatorSummary, 'status' | 'has_signed_sbp'>,
    health: Pick<RelayHealth, 'overall'> | null,
): RelayLook {
    if (op.status === 'decommissioned')
        return { tone: 'neutral', labelKey: 'pub.relays.status.decommissioned', icon: 'off', recordedOnly: true };
    if (op.status === 'rebuild_failed')
        return { tone: 'bad', labelKey: 'pub.relays.status.rebuild_failed', icon: 'bad', recordedOnly: true };
    if (relayUnfinished(op))
        return { tone: 'warn', labelKey: 'pub.relays.status.unfinished', icon: 'warn', wrap: true, recordedOnly: true };
    if (op.status !== 'provisioned')
        return { tone: 'neutral', labelKey: 'pub.relays.status.unknown', icon: 'none', recordedOnly: true };
    switch (health?.overall) {
        case 'working':
            return { tone: 'good', labelKey: 'pub.relays.status.working', icon: 'ok', recordedOnly: false };
        case 'partly':
            return { tone: 'warn', labelKey: 'pub.relays.status.partly', icon: 'warn', recordedOnly: false };
        case 'not_working':
            return { tone: 'bad', labelKey: 'pub.relays.status.not_working', icon: 'bad', recordedOnly: false };
        default:
            return { tone: 'neutral', labelKey: 'pub.relays.status.not_checked', icon: 'none', recordedOnly: true };
    }
}
