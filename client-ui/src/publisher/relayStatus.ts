// relayStatus — what the badge on a relay may say.
//
// The relay list used to show a green "LIVE" pill directly above the
// sentence "Setup state — not a live health check." Both were drawn
// from the same field: `status`, which is what the app last RECORDED
// about the relay (it finished setting it up), not something anybody
// measured. The caption was right and the badge contradicted it.
//
// The rule now: a badge drawn from the recorded state names that state
// ("Set up") and is never green. "Live", in green, is reserved for a
// reachability check that has just succeeded — `checkedJustNow`. Nothing
// in the app runs such a check yet (the management plane has no health
// verb), so today no relay is shown as live, which is the truth.

export type BadgeTone = 'good' | 'warn' | 'bad' | 'neutral' | 'gold';

export interface RelayBadge {
    tone: BadgeTone;
    /** i18n key. */
    labelKey: string;
    /** True when the label is only what the app last recorded. The
     *  caption saying so is shown exactly when this is true. */
    recordedOnly: boolean;
}

export function relayBadge(status: string, checkedJustNow = false): RelayBadge {
    switch (status) {
        case 'provisioned':
            return checkedJustNow
                ? { tone: 'good', labelKey: 'pub.relays.status.live', recordedOnly: false }
                : { tone: 'gold', labelKey: 'pub.relays.status.provisioned', recordedOnly: true };
        case 'pre-provision':
            return { tone: 'warn', labelKey: 'pub.relays.status.pre_provision', recordedOnly: true };
        case 'decommissioned':
            return { tone: 'neutral', labelKey: 'pub.relays.status.decommissioned', recordedOnly: true };
        case 'rebuild_failed':
            return { tone: 'bad', labelKey: 'pub.relays.status.rebuild_failed', recordedOnly: true };
        default:
            return { tone: 'neutral', labelKey: 'pub.relays.status.unknown', recordedOnly: true };
    }
}
