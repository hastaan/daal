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
//   github     — a key checked by GitHub and kept without a relay
//                (addon_notes::github_connect); a relay's «Updates through
//                GitHub» switch makes its own repository under it.

import { useCallback, useEffect, useState } from 'react';
import { Addons, Wizard } from '../wizardCommands';

export type ServiceId = 'hetzner' | 'cloudflare' | 'google' | 'github';

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
    /** `extra`: what the kept key can do beyond the five (Cloudflare's
     *  names), present only when there is something; the sheet warns. */
    cloudflare: { connected: boolean; zone: string; extra?: string[] };
    google: GoogleState;
    /** The GitHub account (update notes). Absent in a test that does not
     *  care: read as not connected. */
    github?: GithubState;
}

/** The GitHub account as the page needs it. */
export interface GithubState {
    connected: boolean;
    /** The account's name on GitHub; '' when not connected. */
    login: string;
    /** What the key can do beyond what Daal needs; present only when
     *  there is something. */
    extra?: string[];
    /** RFC 3339, when the key stops working; '' when never. */
    expiresAt?: string;
}

export const NO_GITHUB: GithubState = { connected: false, login: '' };

export const NO_ACCOUNTS: AccountsState = {
    hetzner: false,
    hetznerAccount: false,
    cloudflare: { connected: false, zone: '' },
    google: NO_GOOGLE,
    github: NO_GITHUB,
};

/** What this phone has connected. A shell that cannot say (an older
 *  build, a browser) reads as "not connected", never as an error. */
export async function readAccounts(): Promise<AccountsState> {
    forgetOldChoice();
    const [hosting, cf, g, gh] = await Promise.all([
        Wizard.hostingAccountStatus().catch(() => null),
        Addons.cdnAccount().catch(() => null),
        Addons.googleAccount().catch(() => null),
        Addons.githubAccount().catch(() => null),
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
        cloudflare: {
            connected: !!cf?.connected,
            zone: cf?.zone ?? '',
            ...(cf?.connected && Array.isArray(cf.extra) && cf.extra.length > 0 ? { extra: cf.extra } : {}),
        },
        google: { connected: !!g?.connected, scriptMade: !!g?.script_made, signIn: g?.sign_in === true },
        github: gh?.connected
            ? {
                  connected: true,
                  login: gh.login ?? '',
                  ...(Array.isArray(gh.extra) && gh.extra.length > 0 ? { extra: gh.extra } : {}),
                  ...(gh.expires_at ? { expiresAt: gh.expires_at } : {}),
              }
            : NO_GITHUB,
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

/** Whether the account a switch needs is connected. */
export function accountConnected(acc: AccountsState, s: Exclude<ServiceId, 'hetzner'>): boolean {
    if (s === 'cloudflare') return acc.cloudflare.connected;
    if (s === 'google') return acc.google.connected;
    return acc.github?.connected === true;
}
