// accounts.ts — the outside accounts Daal works with (the Accounts page)
// and whether each one is connected on this phone.
//
//   hetzner    — the hosting account key (hosting_account::connect),
//                kept without a relay; a new relay takes a copy. Also
//                connected when a relay holds a key (phones set up
//                before the account existed).
//   cloudflare — a key checked and kept without a relay
//                (addon_cdn::connect); a relay takes a copy the first
//                time it turns "Hide behind Cloudflare" on.
//   google     — Google sign-in deploys per relay, so connecting Google
//                only records how the owner wants to do it; the sign-in
//                itself happens when a relay's switch is turned on.

import { useCallback, useEffect, useState } from 'react';
import { Addons, Wizard } from '../wizardCommands';

export type ServiceId = 'hetzner' | 'cloudflare' | 'google';

/** How Google is used: sign in with Google, or the script by hand. */
export type GoogleChoice = 'signin' | 'manual';

const GOOGLE_KEY = 'daal.d2.accounts.google';

function store(): Storage | null {
    try {
        return typeof localStorage === 'undefined' ? null : localStorage;
    } catch {
        return null;
    }
}

export function googleChoice(): GoogleChoice | null {
    try {
        const v = store()?.getItem(GOOGLE_KEY);
        return v === 'signin' || v === 'manual' ? v : null;
    } catch {
        return null;
    }
}

export function setGoogleChoice(v: GoogleChoice | null): void {
    try {
        const s = store();
        if (!s) return;
        if (v == null) s.removeItem(GOOGLE_KEY);
        else s.setItem(GOOGLE_KEY, v);
    } catch {
        /* not kept: asked again next time */
    }
}

export interface AccountsState {
    /** A Hetzner key Daal can use is on this phone. */
    hetzner: boolean;
    /** That key is the account's own (Disconnect forgets it); false when
     *  only relays hold one. */
    hetznerAccount: boolean;
    cloudflare: { connected: boolean; zone: string };
    google: GoogleChoice | null;
}

export const NO_ACCOUNTS: AccountsState = {
    hetzner: false,
    hetznerAccount: false,
    cloudflare: { connected: false, zone: '' },
    google: null,
};

/** What this phone has connected. A shell that cannot say (an older
 *  build, a browser) reads as "not connected", never as an error. */
export async function readAccounts(): Promise<AccountsState> {
    const [hosting, cf] = await Promise.all([
        Wizard.hostingAccountStatus().catch(() => null),
        Addons.cdnAccount().catch(() => null),
    ]);
    let hetzner = !!hosting?.hetzner?.connected;
    const hetznerAccount = !!hosting?.hetzner?.account;
    if (hosting == null) {
        // A shell older than the account: a relay's key is the account.
        const ops = await Wizard.listOperators().catch(() => []);
        const live = (Array.isArray(ops) ? ops : []).filter((o) => o.status !== 'decommissioned');
        hetzner = live.some((o) => o.has_cloud_token === true);
        if (!hetzner) {
            hetzner = (await Wizard.savedCloudToken('hetzner').catch(() => null)) != null;
        }
    }
    return {
        hetzner,
        hetznerAccount,
        cloudflare: { connected: !!cf?.connected, zone: cf?.zone ?? '' },
        google: googleChoice(),
    };
}

/** `enabled` false: the caller already knows (a test); nothing is read. */
export function useAccounts(enabled = true): { accounts: AccountsState; loaded: boolean; reload: () => void } {
    const [accounts, setAccounts] = useState<AccountsState>(NO_ACCOUNTS);
    const [loaded, setLoaded] = useState(false);
    const [generation, setGeneration] = useState(0);
    const reload = useCallback(() => setGeneration((g) => g + 1), []);
    useEffect(() => {
        if (!enabled) return;
        let gone = false;
        readAccounts()
            .then((a) => {
                if (!gone) {
                    setAccounts(a);
                    setLoaded(true);
                }
            })
            .catch(() => {
                if (!gone) setLoaded(true);
            });
        return () => {
            gone = true;
        };
    }, [enabled, generation]);
    return { accounts, loaded, reload };
}
