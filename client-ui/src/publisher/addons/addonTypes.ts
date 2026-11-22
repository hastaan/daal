// addonTypes.ts — the shapes the optional add-on commands take and
// return. Each mirrors a Rust type in client-shell/tauri/daal-wizard:
// the shared ones `addons.rs`, the rest the add-on's own module
// (`addon_standby.rs`, `addon_cdn.rs`, `addon_google.rs`). When a lane
// changes one of those types it changes its mirror here; the command
// wrappers in ../wizardCommands.ts (`Addons`) pass them through whole.
//
// Every add-on operation answers `E_NOT_BUILT: …` until its lane lands
// (classifyPublisherError).

/** daal_wizard::addons::AddonKind */
export type AddonKind = 'standby' | 'cdn' | 'google';

/** daal_wizard::addons::AddonState */
export type AddonState = 'building' | 'ready' | 'promoted' | 'removing';

/** daal_wizard::addons::AddonRow — one row of the add-on ledger. */
export interface AddonRow {
    id: number;
    operator_id: number;
    kind: AddonKind;
    state: AddonState;
    /** The provider's ids of what Daal created. Never a secret. */
    provider_ids: Record<string, string>;
    /** What the provider bills each month; 0 with '' = nothing Daal knows of. */
    monthly_cost_cents: number;
    cost_currency: string;
    /** The add-on holds a secret on this phone (never shown). */
    has_secret: boolean;
    /** Kind-specific, non-secret state. */
    detail: Record<string, unknown>;
    created_at_unix: number;
    updated_at_unix: number;
}

/** daal_wizard::addons::AddonProgress — on `wizard://addon-progress`. */
export interface AddonProgress {
    operator_id: number;
    kind: AddonKind;
    step: string;
    /** `waiting`: the Cloudflare door, on a relay with nobody on it yet. */
    state: 'running' | 'ok' | 'failed' | 'waiting';
    detail: string;
}

/** daal_wizard::addons::AddonRemoveReport */
export interface AddonRemoveReport {
    addon_id: number;
    removed: boolean;
    still_billing: string[];
    /** Stable words for what the publisher must still do by hand. */
    by_hand: string[];
    warnings: string[];
}

/** daal_wizard::addons::AddonOutcome — one add-on in a relay delete. */
export interface AddonOutcome {
    addon_id: number;
    kind: AddonKind;
    removed: boolean;
    /** Something of it is left and only this relay holds what removes it. */
    keeps_relay: boolean;
    /** `with_relay`: nothing to do first; it goes with the relay (the
     *  standby address is released with the relay's addresses). */
    code: 'removed' | 'not_built' | 'failed' | 'left' | 'with_relay';
    error: string;
}

// ---- standby address (addon_standby.rs) ----

export interface StandbyPriceInput {
    operator_id: number;
}
export interface StandbyPrice {
    monthly_cents: number;
    currency: string;
    vat_included: boolean;
}
export interface StandbyAddInput {
    operator_id: number;
    /** Always 'sealed' from the UI (the engine still knows 'open'). */
    mode?: 'sealed' | 'open';
}
export interface StandbyPromoteInput {
    operator_id: number;
}
export interface StandbyPromoteResult {
    addon: AddonRow;
    /** The 26-character standby key, grouped. */
    key: string;
    refresh_note_published: boolean;
    warnings: string[];
}
export interface StandbyKeyInput {
    operator_id: number;
}
export interface StandbyKey {
    key: string;
}

// ---- way in through Cloudflare (addon_cdn.rs) ----

export interface CdnTokenInput {
    operator_id: number;
    /** Crosses this boundary once, inbound. */
    token: string;
    /** The zone meant, when known. */
    zone?: string;
}
/** The Accounts page: a Cloudflare key checked without a relay. */
export interface CdnConnectInput {
    /** Crosses this boundary inbound: once, or twice when the key sees
     *  several domains (again with the one picked). */
    token: string;
    /** The domain picked from a `pick_zone` answer. */
    zone?: string;
}
/** daal_wizard::addon_cdn::CdnAccount */
export interface CdnAccount {
    connected: boolean;
    /** The zone the key is used on; '' when not connected. */
    zone: string;
    /** What the key can do beyond the five (Cloudflare's names). */
    extra?: string[];
}
export type CdnTokenVerdict =
    | 'ok'
    | 'ok_broad'
    | 'pick_zone'
    | 'invalid'
    | 'no_zone'
    | 'zone_not_visible'
    | 'missing_permission'
    | 'refused';
export interface CdnTokenCheck {
    zones: string[];
    /** The zone checked and to use; '' when none was (pick_zone). */
    zone?: string;
    verdict: CdnTokenVerdict;
    /** Kept on this phone (only when ok or ok_broad). */
    stored: boolean;
    /** Cloudflare's names of the permissions missing / beyond the five. */
    missing?: string[];
    extra?: string[];
}
export interface CdnBuildInput {
    operator_id: number;
    zone: string;
}
export interface CdnPostureInput {
    operator_id: number;
    /** Also a real handshake through the front now (default true). */
    test?: boolean;
}
export interface CdnPosture {
    /** ECH on the zone and accepted in the last test: the zone name is
     *  not on the wire. null: could not be read. */
    name_hidden: boolean | null;
    /** Origin pull on and the firewall open to Cloudflare only. */
    door_closed_to_others: boolean | null;
    last_test_at_unix: number;
    last_test_ok: boolean | null;
    renews_at_unix: number;
    needs_rebuild: boolean;
    hostname?: string;
    zone?: string;
    plain_fallback?: boolean;
    /** Provider words; Details only. */
    notes?: string;
    /** The relay's door waits for the first person on the relay. */
    door_waits?: boolean;
}
export interface CdnPlainFallbackInput {
    operator_id: number;
    allow: boolean;
}

// ---- update channel through Google (addon_google.rs) ----
//
// Google is an account (Accounts → Google): one script per Google
// account, added once; each relay's switch takes a slot in it.

/** daal_wizard::addon_google::GoogleAccount. Local, no secret. */
export interface GoogleAccount {
    /** The script is added and its check passed. */
    connected: boolean;
    /** The script was copied (a key was made) and no address is
     *  connected yet. */
    script_made: boolean;
    /** The script's address; '' when not connected. */
    url: string;
    /** This build may offer "Sign in with Google" (OAuth clients
     *  configured). False: the button is not shown at all. */
    sign_in: boolean;
}
export interface GoogleScript {
    /** Carries the account's write key: copy it, never log it. */
    code_gs: string;
    manifest_json: string;
}
export interface GoogleAccountAttachInput {
    url: string;
}
export interface GoogleOnInput {
    operator_id: number;
}
export interface GoogleCheckInput {
    operator_id: number;
}
export interface GoogleCheck {
    ok: boolean;
    via_front: boolean;
    checked_at_unix: number;
    /** '' when ok. */
    reason:
        | ''
        | 'not_deployed'
        | 'refused'
        | 'stale'
        | 'wrong_content'
        | 'unreachable'
        | 'full'
        | 'bad_address'
        | 'no_address';
    /** The helper's words for a failure; Details only. */
    detail?: string;
}
