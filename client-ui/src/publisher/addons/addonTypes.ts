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
    state: 'running' | 'ok' | 'failed';
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
    code: 'removed' | 'not_built' | 'failed' | 'left';
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
    /** 'sealed' (default) | 'open' (refused while an Everyone file exists). */
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
}
export interface CdnTokenCheck {
    zones: string[];
    verdict: 'ok' | 'too_broad' | 'too_narrow' | 'no_zone';
    stored: boolean;
}
export interface CdnBuildInput {
    operator_id: number;
    zone: string;
}
export interface CdnPostureInput {
    operator_id: number;
}
export interface CdnPosture {
    name_hidden: boolean | null;
    door_closed_to_others: boolean | null;
    last_test_at_unix: number;
    last_test_ok: boolean | null;
    renews_at_unix: number;
    needs_rebuild: boolean;
}
export interface CdnPlainFallbackInput {
    operator_id: number;
    allow: boolean;
}

// ---- update channel through Google (addon_google.rs) ----

export interface GoogleScriptInput {
    operator_id: number;
}
export interface GoogleScript {
    /** Carries the write key: copy it, never log it. */
    code_gs: string;
    manifest_json: string;
}
export interface GoogleSignInInput {
    operator_id: number;
}
export interface GoogleAttachInput {
    operator_id: number;
    url: string;
}
export interface GoogleCheckInput {
    operator_id: number;
}
export interface GoogleCheck {
    ok: boolean;
    via_front: boolean;
    checked_at_unix: number;
    reason: '' | 'api_not_enabled' | 'not_deployed' | 'wrong_content' | 'unreachable';
}
