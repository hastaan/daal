// "More ways to connect" — the opt-in transport families of the build
// wizard.
//
// A toolbox profile offers some families that a relay serves by default
// and some that are off unless asked for (shadowsocks, anytls, tuic in
// iran-default). The only mechanism that turns the second kind on is
// `daal-deploy provision --families …`, which the Rust bridge forwards
// from the pre-provision record's `enabled_families` — and the wizard
// used to hard-code that list to []. Outside a terminal there was no way
// to ask for them (finding FAM-2).
//
// TWO RULES this module exists to hold, both easy to get wrong in a
// component:
//
// 1. `--families` REPLACES the profile's defaults; it is not added to
//    them. Sending ["tuic"] builds a tuic-ONLY relay. So the list sent is
//    always "every default family PLUS what was ticked", never the ticked
//    ones alone — and when nothing is ticked it is [] (use the profile's
//    defaults), which is byte-for-byte what the wizard sent before this
//    control existed.
//
// 2. Nothing here is on by default, and each one says what it costs.
//    Every extra family is one more open port on the relay; none of them
//    is reachable on a network that only passes ordinary web traffic; and
//    anytls forces the connection file into a newer format that an older
//    app refuses WHOLE — not just the anytls route.
//
// The family table itself is not re-declared: it is read from
// TOOLBOX_PROFILES (rebuildPlan.ts), which tools/check-toolbox-profiles
// .mjs holds to publisher/deploy/profiles/*.json.

import { profileBySlug } from './rebuildPlan';

/**
 * Whether the relay software a newly built server downloads can serve the
 * opt-in families at all.
 *
 * MIRROR of `PinnedMgmtServesOptInFamilies` in
 * publisher/deploy/cloudinit/artifacts.go — the constant that sits next
 * to the pinned daal-relay-mgmt hash. It is false while that pinned
 * release predates shadowsocks, anytls and tuic (worldbox F-002): a
 * server built today opens the extra door, nothing answers behind it, the
 * connection file carries no such route, and with anytls named the file
 * is still made in the newer format older apps refuse. All of the cost
 * the screen warns about, none of the benefit.
 *
 * While it is false the switches are SHOWN but cannot be turned on, with
 * one line saying why, and no list this module returns ever names an
 * opt-in family — not even one remembered from an earlier run.
 *
 * Flip it in the same commit that flips the Go constant (which is the
 * commit that bumps the pin). tools/check-toolbox-profiles.mjs and
 * extraFamilies.test.tsx fail when the two disagree.
 */
export const RELEASED_RELAY_SERVES_EXTRA_FAMILIES = true;

/** One opt-in family as the wizard shows it. */
export interface ExtraFamilyOption {
    /** The family string, exactly as `--families` and the profile spell it. */
    family: string;
    /** i18n key of the plain-language name. */
    titleKey: string;
    /** i18n key of the one honest sentence on what it is and costs. */
    bodyKey: string;
    /** True when turning it on makes the connection file one that older
     *  app versions cannot open at all. */
    forcesNewFileFormat: boolean;
}

/** Families whose presence in a pack raises the pack's format version, so
 *  an app that predates the format rejects the whole file. Mirrors
 *  publisher/deploy/relaypack (anytls ⇒ spec_version 5). */
const FORCES_NEW_FILE_FORMAT = new Set(['anytls']);

/** Stable i18n key stem per family: `wiz.more.<stem>.title` / `.body`. */
const KEY_STEM: Record<string, string> = {
    shadowsocks: 'ss',
    anytls: 'anytls',
    tuic: 'tuic',
};

/** The families a relay built from `profileSlug` serves with no list. */
export function defaultFamilies(profileSlug: string): string[] {
    const p = profileBySlug(profileSlug);
    return p ? p.candidates.filter((c) => c.defaultEnabled).map((c) => c.family) : [];
}

/**
 * The opt-in families of a profile, in profile order.
 *
 * A family the profile offers but this build has no wording for is left
 * OUT rather than shown with a blank description: an unexplained switch
 * that opens a port is exactly what this screen must not have.
 */
export function extraFamilyOptions(profileSlug: string): ExtraFamilyOption[] {
    const p = profileBySlug(profileSlug);
    if (!p) return [];
    return p.candidates
        .filter((c) => !c.defaultEnabled && KEY_STEM[c.family] !== undefined)
        .map((c) => ({
            family: c.family,
            titleKey: `wiz.more.${KEY_STEM[c.family]}.title`,
            bodyKey: `wiz.more.${KEY_STEM[c.family]}.body`,
            forcesNewFileFormat: FORCES_NEW_FILE_FORMAT.has(c.family),
        }));
}

/** `selected`, reduced to what the profile really offers as opt-in AND
 *  the released relay software can serve, in profile order, without
 *  duplicates. With `available` false that is nothing.
 *
 *  `available` is a parameter only so both states can be tested; every
 *  product caller leaves it at the build constant. */
export function sanitizeExtraFamilies(
    profileSlug: string,
    selected: readonly string[],
    available: boolean = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
): string[] {
    if (!available) return [];
    const want = new Set(selected);
    return extraFamilyOptions(profileSlug)
        .map((o) => o.family)
        .filter((f) => want.has(f));
}

/** Tick or untick one family. Returns a new, sanitized list. */
export function toggleExtraFamily(
    profileSlug: string,
    selected: readonly string[],
    family: string,
    on: boolean,
    available: boolean = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
): string[] {
    const next = selected.filter((f) => f !== family);
    if (on) next.push(family);
    return sanitizeExtraFamilies(profileSlug, next, available);
}

/**
 * The `enabled_families` list to hand the backend.
 *
 * [] when nothing extra is selected — "use the profile's defaults", the
 * value the wizard has always sent. Otherwise every default family plus
 * the selected extras, because the list replaces the defaults.
 *
 * While the released relay software cannot serve the extras it is always
 * [] — the wizard must not ask a server for what it cannot give.
 */
export function enabledFamiliesFor(
    profileSlug: string,
    selected: readonly string[],
    available: boolean = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
): string[] {
    const extras = sanitizeExtraFamilies(profileSlug, selected, available);
    if (extras.length === 0) return [];
    return [...defaultFamilies(profileSlug), ...extras];
}

/** True when the selection makes the connection file unreadable to
 *  people on an older app. */
export function selectionForcesNewFileFormat(
    profileSlug: string,
    selected: readonly string[],
    available: boolean = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
): boolean {
    return sanitizeExtraFamilies(profileSlug, selected, available).some((f) => FORCES_NEW_FILE_FORMAT.has(f));
}

// ---- remembering the choice across a relaunch ---------------------------
//
// The choice is made on screen 2 and used on screen 3. A relaunch in
// between resumes the wizard from the database, which holds the record
// only once the build has started — so without this a resumed build would
// quietly fall back to the defaults and the operator would get a relay
// without what they ticked. It is a per-device convenience and is treated
// as one: every access is guarded, and a missing or unreadable value is
// "nothing selected", the safe direction (nothing extra is opened).

interface KV {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
}

const storageKey = (operatorId: number) => `daal.wizard.extra_families.${operatorId}`;

function browserStorage(): KV | null {
    try {
        return typeof localStorage === 'undefined' ? null : localStorage;
    } catch {
        return null;
    }
}

export function rememberExtraFamilies(
    operatorId: number,
    profileSlug: string,
    selected: readonly string[],
    storage: KV | null = browserStorage(),
    available: boolean = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
): void {
    if (!storage) return;
    try {
        const clean = sanitizeExtraFamilies(profileSlug, selected, available);
        if (clean.length === 0) storage.removeItem(storageKey(operatorId));
        else storage.setItem(storageKey(operatorId), JSON.stringify(clean));
    } catch {
        /* storage unavailable: the choice simply is not remembered */
    }
}

export function recallExtraFamilies(
    operatorId: number,
    profileSlug: string,
    storage: KV | null = browserStorage(),
    available: boolean = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
): string[] {
    if (!storage || !available) return [];
    try {
        const raw = storage.getItem(storageKey(operatorId));
        if (!raw) return [];
        const parsed: unknown = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];
        return sanitizeExtraFamilies(
            profileSlug,
            parsed.filter((x): x is string => typeof x === 'string'),
            available,
        );
    } catch {
        return [];
    }
}
