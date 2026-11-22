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
//   google     — the account's one update script, added once by hand
//                (or, in a build with the OAuth clients, by signing in)
//                and checked through Google (addon_google::account_attach).
//                Every relay's switch takes a slot in it.

import { useCallback, useEffect, useState } from 'react';
import { Addons, Wizard } from '../wizardCommands';

export type ServiceId = 'hetzner' | 'cloudflare' | 'google';

/** The Google account as the page needs it. */
export interface GoogleState {
    /** The script is added and checked: relays can turn it on. */
    connected: boolean;
    /** The script was copied; the address is not pasted back yet. */
    scriptMade: boolean;
    /** This build may offer "Sign in with Google". */
    signIn: boolean;
}

export const NO_GOOGLE: GoogleState = { connected: false, scriptMade: false, signIn: false };

/** An earlier build kept only a choice here; nothing reads it now. */
const OLD_GOOGLE_CHOICE = 'daal.d2.accounts.google';

function forgetOldChoice(): void {
    try {
        if (typeof localStorage !== 'undefined') localStorage.removeItem(OLD_GOOGLE_CHOICE);
    } catch {
        /* nothing kept to forget */
    }
}

export interface AccountsState {
    /** A Hetzner key Daal can use is on this phone. */
    hetzner: boolean;
    /** That key is the account's own (Disconnect forgets it); false when
     *  only relays hold one. */
    hetznerAccount: boolean;
    cloudflare: { connected: boolean; zone: string };
    google: GoogleState;
}

export const NO_ACCOUNTS: AccountsState = {
    hetzner: false,
    hetznerAccount: false,
    cloudflare: { connected: false, zone: '' },
    google: NO_GOOGLE,
};

/** What this phone has connected. A shell that cannot say (an older
 *  build, a browser) reads as "not connected", never as an error. */
export async function readAccounts(): Promise<AccountsState> {
    forgetOldChoice();
    const [hosting, cf, g] = await Promise.all([
        Wizard.hostingAccountStatus().catch(() => null),
        Addons.cdnAccount().catch(() => null),
        Addons.googleAccount().catch(() => null),
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
        google: { connected: !!g?.connected, scriptMade: !!g?.script_made, signIn: g?.sign_in === true },
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
