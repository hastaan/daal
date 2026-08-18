// Unit tests for the three rungs' decision logic.
//
// The Go-side mirrors (profile JSON, region tables, the recommender's
// wall-clock column) are checked by tools/check-toolbox-profiles.mjs,
// which runs in Node and can read the Go tree. This file stays inside
// the bundler's world and tests what the sheets actually branch on.
import { describe, expect, it } from 'vitest';
import EN from '../i18n/d2/d2-extra.en.json';
import FA from '../i18n/d2/d2-extra.fa.json';
import {
    REBUILD_PROVIDERS,
    REGIONS,
    TOOLBOX_PROFILES,
    planProfileChange,
    planProviderChange,
    planRegionChange,
    profileBySlug,
    projectFamilies,
    formatPlanPrice,
    rebuildDestinations,
    regionsFor,
    serverTypeAvailable,
    zoneFor,
} from './rebuildPlan';

const en = EN as Record<string, string>;
const fa = FA as Record<string, string>;

const iranDefault = profileBySlug('iran-default')!;
const iranTcp443 = profileBySlug('iran-tcp443')!;

// The family set a relay built on iran-default with no explicit family
// choice actually serves. `provision` writes these into the record's
// candidates and that is what every later rebuild is fed.
const DEFAULT_SERVED = ['vless-reality', 'websocket-tls', 'naive', 'hysteria2'];
const TCP443_SERVED = ['vless-reality', 'websocket-tls', 'naive'];

describe('L6 — the profile change', () => {
    it('drops the UDP families when moving to the no-UDP profile', () => {
        const plan = planProfileChange(DEFAULT_SERVED, iranTcp443);
        expect(plan.after).toEqual(TCP443_SERVED);
        expect(plan.removed).toEqual(['hysteria2']);
        expect(plan.removedUdp).toEqual(['hysteria2']);
        expect(plan.added).toEqual([]);
        expect(plan.noWireChange).toBe(false);
    });

    // THE FINDING THIS MODULE EXISTS FOR. The wizard refuses an L6 onto
    // the profile the relay is already on, and that refusal reads like
    // it covers "this rung would change nothing". It does not.
    //
    // The rebuild is fed the relay's CURRENT families and the Go side
    // intersects them with the target profile, so the widening
    // direction adds nothing back: a relay on iran-tcp443 pointed at
    // iran-default keeps exactly the three families it had. The box is
    // deleted, every distributed file dies, the operator pays for a
    // three-minute rebuild, and a censor sees the same wire shape.
    it('refuses the widening direction, which the wizard does not catch', () => {
        const plan = planProfileChange(TCP443_SERVED, iranDefault);
        expect(plan.after).toEqual(TCP443_SERVED);
        expect(plan.added).toEqual([]);
        expect(plan.removed).toEqual([]);
        expect(plan.noWireChange).toBe(true);
    });

    // THE OTHER HALF OF THE SAME REFUSAL, and the worse half. The
    // widening direction removes nothing; this direction leaves
    // nothing. `noWireChange` does not fire — the plan genuinely
    // removes families — so it is `after.length === 0` the sheet has to
    // branch on. Getting it wrong is not a wasted rebuild: Reprovision
    // deletes the box and `CandidatesForProfile` then refuses with
    // "yields no candidates", so the operator ends with no relay.
    it('leaves nothing when every served family is UDP-gated and the target is not', () => {
        const plan = planProfileChange(['hysteria2', 'tuic'], iranTcp443);
        expect(plan.after).toEqual([]);
        expect(plan.removed).toEqual(['hysteria2', 'tuic']);
        // The no-op refusal does NOT cover this one.
        expect(plan.noWireChange).toBe(false);
    });

    it('can never add a family to a provisioned relay', () => {
        for (const served of [DEFAULT_SERVED, TCP443_SERVED, ['vless-reality']]) {
            for (const target of TOOLBOX_PROFILES) {
                expect(planProfileChange(served, target).added).toEqual([]);
            }
        }
    });

    it('mirrors the Go intersection, including the pre-provision empty branch', () => {
        // Empty selection = the target profile's own defaults. Only
        // reachable before a first provision; kept so the mirror does
        // not silently disagree with candidatesForProfile.
        expect(projectFamilies([], iranDefault)).toEqual(DEFAULT_SERVED);
        expect(projectFamilies([], iranTcp443)).toEqual(TCP443_SERVED);
        // A family the target profile does not carry is dropped.
        expect(projectFamilies(['hysteria2', 'naive'], iranTcp443)).toEqual(['naive']);
    });
});

describe('the anytls warning', () => {
    it('does not fire for either profile that exists today', () => {
        for (const served of [DEFAULT_SERVED, TCP443_SERVED]) {
            for (const target of TOOLBOX_PROFILES) {
                expect(planProfileChange(served, target).addsAnyTLS).toBe(false);
            }
        }
    });

    it('does not fire when the relay already serves anytls', () => {
        // Nothing is added, so nobody's client meets a spec_version it
        // has not already met. Warning here would be noise on the one
        // screen that cannot afford any.
        const served = [...DEFAULT_SERVED, 'anytls'];
        expect(planProfileChange(served, iranTcp443).addsAnyTLS).toBe(false);
    });

    it('fires for a profile that would introduce anytls', () => {
        // No such profile ships today, and that is the honest state:
        // the warning is computed from the projected family set, not
        // from a slug allowlist, so it turns itself on the day a
        // profile default-enables the family.
        const hypothetical = {
            slug: 'anytls-forward',
            candidates: [
                { family: 'vless-reality', defaultEnabled: true, udpGated: false },
                { family: 'anytls', defaultEnabled: true, udpGated: false },
            ],
        };
        const plan = planProfileChange(['vless-reality', 'anytls'], hypothetical);
        expect(plan.added).toEqual([]);
        expect(plan.addsAnyTLS).toBe(false);

        const introducing = planProfileChange([], hypothetical);
        expect(introducing.after).toContain('anytls');
        expect(introducing.addsAnyTLS).toBe(true);
    });
});

describe('L4 — the region change', () => {
    it('refuses the relay’s own region', () => {
        expect(planRegionChange('hetzner', 'fsn1', 'fsn1').isSameRegion).toBe(true);
        expect(planRegionChange('hetzner', 'fsn1', 'hel1').isSameRegion).toBe(false);
        // Nothing selected yet is not a no-op claim.
        expect(planRegionChange('hetzner', 'fsn1', '').isSameRegion).toBe(false);
    });

    it('tells a neighbourhood move from a room move', () => {
        expect(planRegionChange('hetzner', 'fsn1', 'nbg1').isSameZone).toBe(true);
        expect(planRegionChange('hetzner', 'fsn1', 'hel1').isSameZone).toBe(false);
        expect(planRegionChange('hetzner', 'fsn1', 'sin').isSameZone).toBe(false);
    });

    it('offers only the current provider’s codes', () => {
        expect(regionsFor('hetzner').map((r) => r.code)).toContain('fsn1');
        expect(regionsFor('hetzner').map((r) => r.code)).not.toContain('vno');
        // Region codes are provider-scoped and collide on purpose.
        expect(zoneFor('vultr', 'fra')).toBe('eu-central');
        expect(zoneFor('hetzner', 'fra')).toBeNull();
        // A provider with no adapter table offers nothing, so the rung
        // cannot be driven into a code the provider never heard of.
        expect(regionsFor('digitalocean')).toEqual([]);
    });

    // `reprovision` deletes the box and `provision` creates the
    // replacement. A target region that cannot host this server type
    // fails the second half with the first already done.
    it('will not call a missing server type available, and says so on no answer', () => {
        expect(serverTypeAvailable([{ id: 'cpx12' }], 'cpx12')).toBe(true);
        expect(serverTypeAvailable([{ id: 'cpx12' }], 'cx22')).toBe(false);
        expect(serverTypeAvailable(null, 'cx22')).toBeNull();
    });
});

describe('L5 — the hosting company change', () => {
    // Every other rung's wrong answer is an error. This one's is a
    // relay: the old server is deleted before the new one is built, so
    // a destination Daal cannot actually create on does not fail the
    // rebuild — it ends it.
    it('offers every live provider except the one the relay is already on', () => {
        expect(rebuildDestinations('hetzner')).toEqual(['vultr']);
        expect(rebuildDestinations('vultr')).toEqual(['hetzner']);
        // The relay's provider is a stored string off its record, not
        // a typed enum, so a stray case or space must not turn the
        // relay's own company back into a destination.
        expect(rebuildDestinations(' Hetzner ')).toEqual(['vultr']);
    });

    it('never offers stark, whose client talks to an example.com API', () => {
        expect(REBUILD_PROVIDERS).not.toContain('stark');
        // And it has a region table, so the omission has to be the
        // destination list's doing — the region list alone would let it
        // through.
        expect(regionsFor('stark').length).toBeGreaterThan(0);
    });

    it('refuses the rung’s no-op, and anything Daal cannot build on', () => {
        expect(planProviderChange('hetzner', 'hetzner').isSameProvider).toBe(true);
        expect(planProviderChange('hetzner', 'vultr').isSameProvider).toBe(false);
        // Nothing picked yet is not a no-op claim — and it is not a
        // known destination either, which is the half that keeps the
        // button unarmed on an empty choice.
        expect(planProviderChange('hetzner', '').isSameProvider).toBe(false);
        expect(planProviderChange('hetzner', '').isKnownProvider).toBe(false);
        expect(planProviderChange('hetzner', 'vultr').isKnownProvider).toBe(true);
        // A provider the wizard collects a token for and `buildProvider`
        // cannot construct an adapter for.
        expect(planProviderChange('hetzner', 'digitalocean').isKnownProvider).toBe(false);
    });

    // The region list belongs to the DESTINATION. Codes are
    // provider-scoped and they collide: "fra" is Vultr's Frankfurt and
    // Hetzner has never heard of it, so offering this relay's own codes
    // would send the create leg a region that does not exist.
    it('takes its region codes from the destination, not from the relay', () => {
        for (const d of rebuildDestinations('hetzner')) {
            expect(regionsFor(d).length, `${d} has no regions`).toBeGreaterThan(0);
        }
        expect(regionsFor('vultr').map((r) => r.code)).toContain('fra');
        expect(regionsFor('hetzner').map((r) => r.code)).not.toContain('fra');
    });

    // The same pre-flight L4 runs, one rung more load-bearing: the plan
    // ids are the DESTINATION's ("cx22" is Hetzner's, Vultr sells
    // "vc2-1c-1gb"), asked of an account Daal has never talked to. An
    // unanswered catalogue is the only thing between the operator and a
    // delete with no rebuild, so it must never read as a yes.
    it('will not call an unanswered catalogue a yes', () => {
        expect(serverTypeAvailable(null, 'vc2-1c-1gb')).toBeNull();
        expect(serverTypeAvailable([], 'vc2-1c-1gb')).toBe(false);
        expect(serverTypeAvailable([{ id: 'vc2-1c-1gb' }], 'vc2-1c-1gb')).toBe(true);
        // A Hetzner plan id on a Vultr catalogue is the shape of the
        // mistake this rung invites.
        expect(serverTypeAvailable([{ id: 'vc2-1c-1gb' }], 'cpx12')).toBe(false);
    });
});

describe('all three sheets render in en and fa', () => {
    // Every key the three rungs use, listed once. A key present in en and
    // missing in fa renders as the raw key id in front of a Farsi
    // speaker, which is how a screen that "works" ships untranslated.
    const KEYS = [
        'pub.danger.rebuild.region.title',
        'pub.danger.rebuild.region.body',
        'pub.danger.rebuild.region.action',
        'pub.danger.rebuild.region.unavailable',
        'pub.danger.rebuild.region.field',
        'pub.danger.rebuild.region.retry',
        'pub.danger.rebuild.region.same_zone',
        'pub.danger.rebuild.region.other_zone',
        'pub.danger.rebuild.region.checking',
        'pub.danger.rebuild.region.type_missing',
        'pub.danger.rebuild.region.type_unknown',
        'pub.danger.rebuild.region.type_ok',
        'pub.danger.rebuild.provider.title',
        'pub.danger.rebuild.provider.body',
        'pub.danger.rebuild.provider.action',
        'pub.danger.rebuild.provider.unavailable',
        'pub.danger.rebuild.provider.field',
        'pub.danger.rebuild.provider.field_token',
        'pub.danger.rebuild.provider.token_help',
        'pub.danger.rebuild.provider.field_region',
        'pub.danger.rebuild.provider.field_type',
        'pub.danger.rebuild.provider.check',
        'pub.danger.rebuild.provider.checking',
        'pub.danger.rebuild.provider.type_none',
        'pub.danger.rebuild.provider.type_detail',
        'pub.danger.rebuild.provider.two_bills',
        'pub.danger.rebuild.profile.title',
        'pub.danger.rebuild.profile.body',
        'pub.danger.rebuild.profile.action',
        'pub.danger.rebuild.profile.field',
        'pub.danger.rebuild.profile.keeps',
        'pub.danger.rebuild.profile.drops',
        'pub.danger.rebuild.profile.drops_udp',
        'pub.danger.rebuild.profile.no_change',
        'pub.danger.rebuild.profile.no_families',
        'pub.danger.rebuild.profile.never_adds',
        'pub.danger.rebuild.profile.anytls',
        'pub.danger.rebuild.confirm.title',
        'pub.danger.rebuild.confirm.destroys',
        'pub.danger.rebuild.confirm.downtime',
        'pub.danger.rebuild.confirm.half_way',
        'pub.danger.rebuild.confirm.count',
        'pub.danger.rebuild.confirm.count_none',
        'pub.danger.rebuild.confirm.by_hand',
        'pub.danger.rebuild.confirm.by_hand_fresh',
        'pub.danger.rebuild.confirm.no_undo',
        'pub.danger.rebuild.confirm.reason',
        'pub.danger.rebuild.confirm.next',
        'pub.danger.rebuild.confirm.back',
        'pub.danger.rebuild.type_name',
        'pub.danger.rebuild.type_name_wrong',
        'pub.danger.rebuild.go',
        'pub.danger.rebuild.working',
        'pub.danger.rebuild.done.title',
        'pub.danger.rebuild.done.body',
        'pub.danger.rebuild.done.by_hand',
        'pub.danger.rebuild.done.by_hand_fresh',
        'pub.danger.rebuild.done.warnings',
        'pub.danger.rebuild.zone.eu-central',
        'pub.danger.rebuild.zone.eu-north',
        'pub.danger.rebuild.zone.us-east',
        'pub.danger.rebuild.zone.us-west',
        'pub.danger.rebuild.zone.apac',
    ];

    it('has every key in both catalogs, non-empty', () => {
        for (const k of KEYS) {
            expect(en[k], `${k} missing from en`).toBeTruthy();
            expect(fa[k], `${k} missing from fa`).toBeTruthy();
        }
    });

    it('has a region name for every region either rung can offer', () => {
        const codes = new Set(Object.values(REGIONS).flat().map((r) => r.code));
        for (const c of codes) {
            expect(en[`pub.danger.rebuild.region.name.${c}`], `${c} en`).toBeTruthy();
            expect(fa[`pub.danger.rebuild.region.name.${c}`], `${c} fa`).toBeTruthy();
        }
    });

    // L5 builds three lines per destination out of the provider id.
    // A destination with no copy renders raw key ids at the exact
    // moment the operator is choosing a legal jurisdiction for the
    // relay — the one place in the app where the fallback is worse than
    // an empty screen.
    it('names, places and jurisdicts every destination L5 can offer', () => {
        const arabic = /[\u0600-\u06FF]/;
        for (const p of REBUILD_PROVIDERS) {
            for (const part of ['name', 'where', 'jurisdiction']) {
                const k = `pub.danger.rebuild.provider.${part}.${p}`;
                expect(en[k], `${k} missing from en`).toBeTruthy();
                expect(fa[k], `${k} missing from fa`).toBeTruthy();
                expect(arabic.test(fa[k]), `${k} has no Farsi in it`).toBe(true);
            }
        }
    });

    it('actually translated the Farsi, rather than copying the English', () => {
        const arabic = /[؀-ۿ]/;
        for (const k of KEYS) {
            expect(fa[k], `${k} was left in English`).not.toBe(en[k]);
            expect(arabic.test(fa[k]), `${k} has no Farsi in it`).toBe(true);
        }
    });

});

// L5 is the only rung that shows the operator a price for a server they
// do not yet own, and it is the only rung where that price is not in
// euro. The Go adapter states the currency for exactly this reason; the
// Rust mirror used to drop it and the copy hard-coded a euro sign, so a
// USD plan was quoted in euros on the sheet that asks the operator to
// take on a second bill.
describe('the price a rebuild quotes', () => {
    it('draws a Hetzner plan in euro', () => {
        expect(formatPlanPrice({ monthly_eur: 3.79, currency: 'EUR' })).toBe(
            '\u20ac3.79',
        );
    });

    it('draws a Vultr plan in dollars, not euro', () => {
        const shown = formatPlanPrice({ monthly_eur: 5, currency: 'USD' });
        expect(shown).toBe('$5.00');
        expect(shown).not.toContain('\u20ac');
    });

    it('treats a missing currency as euro, which is all an older daal-deploy could have meant', () => {
        expect(formatPlanPrice({ monthly_eur: 4.59 })).toBe('\u20ac4.59');
    });

    it('prints an unknown currency as a code rather than guessing a symbol', () => {
        const shown = formatPlanPrice({ monthly_eur: 12, currency: 'gbp' });
        expect(shown).toBe('12.00 GBP');
        expect(shown).not.toContain('\u20ac');
        expect(shown).not.toContain('$');
    });

    it('always shows two decimals, so a plan never reads as a round number it is not', () => {
        expect(formatPlanPrice({ monthly_eur: 5, currency: 'USD' })).toBe('$5.00');
        expect(formatPlanPrice({ monthly_eur: 3.5, currency: 'EUR' })).toBe(
            '\u20ac3.50',
        );
    });

    // The copy must not re-introduce the symbol the formatter exists to
    // choose. A hard-coded sign in either catalogue would silently win.
    it('leaves the currency to the formatter in both languages', () => {
        const key = 'pub.danger.rebuild.provider.type_detail';
        for (const [lang, cat] of [
            ['en', EN],
            ['fa', FA],
        ] as const) {
            const s = (cat as Record<string, string>)[key];
            expect(s, `${lang} is missing ${key}`).toBeTruthy();
            expect(s).toContain('{price}');
            expect(s, `${lang} hard-codes a euro sign`).not.toContain('\u20ac');
            expect(s, `${lang} hard-codes a dollar sign`).not.toContain('$');
            // The Farsi copy used to spell the currency out as a word,
            // which no symbol swap would have caught.
            expect(s, `${lang} names a currency in words`).not.toContain(
                '\u06cc\u0648\u0631\u0648',
            );
            expect(s.toLowerCase(), `${lang} names a currency in words`).not.toContain(
                'euro',
            );
        }
    });
});
