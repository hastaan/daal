// "More ways to connect" (finding FAM-2): the wizard used to hard-code an
// empty family list, so shadowsocks, anytls and tuic could not be turned
// on from the app at all. These tests hold the two rules the control must
// never break — nothing on by default, and the list sent REPLACES the
// profile's defaults so it must always carry them — and the honesty of
// what the screen says.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import EN from '../i18n/d2/d2-extra.en.json';
import FA from '../i18n/d2/d2-extra.fa.json';
import { MoreWaysToConnect } from './MoreWaysToConnect';
import wizardSource from './PublisherWizard.tsx?raw';
import pinSource from '../../../publisher/deploy/cloudinit/artifacts.go?raw';
import * as gated from './extraFamilies';
import { RELEASED_RELAY_SERVES_EXTRA_FAMILIES, defaultFamilies, extraFamilyOptions } from './extraFamilies';
import { TOOLBOX_PROFILES } from './rebuildPlan';

// Whether these families can be turned on at all is a build constant
// that follows the pinned relay release (see "while the released relay
// software cannot serve them" below). The FAM-2 suites that follow hold
// how the control behaves once it CAN be used, so they run with the gate
// open whatever the constant is today; the gated state has its own suite.
type KVStore = Parameters<typeof gated.recallExtraFamilies>[2];
const enabledFamiliesFor = (p: string, sel: readonly string[]) => gated.enabledFamiliesFor(p, sel, true);
const sanitizeExtraFamilies = (p: string, sel: readonly string[]) => gated.sanitizeExtraFamilies(p, sel, true);
const selectionForcesNewFileFormat = (p: string, sel: readonly string[]) =>
    gated.selectionForcesNewFileFormat(p, sel, true);
const toggleExtraFamily = (p: string, sel: readonly string[], f: string, on: boolean) =>
    gated.toggleExtraFamily(p, sel, f, on, true);
const rememberExtraFamilies = (id: number, p: string, sel: readonly string[], s: KVStore) =>
    gated.rememberExtraFamilies(id, p, sel, s, true);
const recallExtraFamilies = (id: number, p: string, s: KVStore) => gated.recallExtraFamilies(id, p, s, true);

const en = EN as Record<string, string>;
const fa = FA as Record<string, string>;
const P = 'iran-default';
const DEFAULTS = ['vless-reality', 'websocket-tls', 'naive', 'hysteria2'];

describe('which families are offered', () => {
    it('offers exactly the profile’s opt-in families, in profile order', () => {
        expect(extraFamilyOptions(P).map((o) => o.family)).toEqual(['shadowsocks', 'anytls', 'tuic']);
        expect(defaultFamilies(P)).toEqual(DEFAULTS);
    });

    it('never offers a default family as an extra, on any shipped profile', () => {
        for (const p of TOOLBOX_PROFILES) {
            const extras = extraFamilyOptions(p.slug).map((o) => o.family);
            for (const c of p.candidates) {
                expect(extras.includes(c.family)).toBe(!c.defaultEnabled);
            }
        }
    });

    it('offers nothing for a profile it does not know', () => {
        expect(extraFamilyOptions('no-such-profile')).toEqual([]);
        expect(enabledFamiliesFor('no-such-profile', ['tuic'])).toEqual([]);
    });

    it('marks anytls, and only anytls, as forcing the newer file format', () => {
        const flagged = extraFamilyOptions(P).filter((o) => o.forcesNewFileFormat).map((o) => o.family);
        expect(flagged).toEqual(['anytls']);
    });
});

describe('the family list handed to the backend', () => {
    it('is empty when nothing is ticked — exactly what the wizard sent before', () => {
        expect(enabledFamiliesFor(P, [])).toEqual([]);
    });

    it('carries every default family as well as the ticked ones (the list REPLACES the defaults)', () => {
        expect(enabledFamiliesFor(P, ['tuic'])).toEqual([...DEFAULTS, 'tuic']);
        expect(enabledFamiliesFor(P, ['tuic', 'shadowsocks', 'anytls'])).toEqual([
            ...DEFAULTS,
            'shadowsocks',
            'anytls',
            'tuic',
        ]);
        for (const o of extraFamilyOptions(P)) {
            const list = enabledFamiliesFor(P, [o.family]);
            for (const d of DEFAULTS) expect(list).toContain(d);
            expect(list).toHaveLength(DEFAULTS.length + 1);
        }
    });

    it('ignores names the profile does not offer as opt-in, and duplicates', () => {
        expect(sanitizeExtraFamilies(P, ['tiuc', 'tuic', 'tuic', 'vless-reality', 'wireguard'])).toEqual(['tuic']);
        // A selection of nothing valid is "nothing ticked", not a list of
        // defaults-only that would look explicit to the backend.
        expect(enabledFamiliesFor(P, ['tiuc', 'naive'])).toEqual([]);
        // Every name sent is one `daal-deploy provision --families` accepts
        // for this profile (it now refuses anything else).
        const offered = TOOLBOX_PROFILES.find((p) => p.slug === P)!.candidates.map((c) => c.family);
        for (const f of enabledFamiliesFor(P, ['shadowsocks', 'anytls', 'tuic'])) {
            expect(offered).toContain(f);
        }
    });

    it('toggles one family at a time', () => {
        let sel: string[] = [];
        sel = toggleExtraFamily(P, sel, 'anytls', true);
        sel = toggleExtraFamily(P, sel, 'shadowsocks', true);
        expect(sel).toEqual(['shadowsocks', 'anytls']);
        sel = toggleExtraFamily(P, sel, 'anytls', true); // ticking twice is not two
        expect(sel).toEqual(['shadowsocks', 'anytls']);
        sel = toggleExtraFamily(P, sel, 'shadowsocks', false);
        expect(sel).toEqual(['anytls']);
        expect(toggleExtraFamily(P, sel, 'not-a-family', true)).toEqual(['anytls']);
    });

    it('knows when the selection makes the file unreadable to older apps', () => {
        expect(selectionForcesNewFileFormat(P, [])).toBe(false);
        expect(selectionForcesNewFileFormat(P, ['shadowsocks', 'tuic'])).toBe(false);
        expect(selectionForcesNewFileFormat(P, ['tuic', 'anytls'])).toBe(true);
    });
});

describe('remembering the choice across a relaunch', () => {
    const mem = () => {
        const m = new Map<string, string>();
        return {
            m,
            getItem: (k: string) => m.get(k) ?? null,
            setItem: (k: string, v: string) => void m.set(k, v),
            removeItem: (k: string) => void m.delete(k),
        };
    };

    it('round-trips per relay and forgets an emptied selection', () => {
        const s = mem();
        rememberExtraFamilies(7, P, ['tuic', 'anytls'], s);
        expect(recallExtraFamilies(7, P, s)).toEqual(['anytls', 'tuic']);
        expect(recallExtraFamilies(8, P, s)).toEqual([]); // another relay's wizard
        rememberExtraFamilies(7, P, [], s);
        expect(s.m.size).toBe(0);
        expect(recallExtraFamilies(7, P, s)).toEqual([]);
    });

    it('treats anything unreadable as nothing selected — never as something extra', () => {
        const s = mem();
        for (const junk of ['not json', '{"a":1}', '"tuic"', '[1,2,null]', '["wireguard","naive"]']) {
            s.m.set('daal.wizard.extra_families.3', junk);
            expect(recallExtraFamilies(3, P, s)).toEqual([]);
        }
        const broken = {
            getItem: () => {
                throw new Error('blocked');
            },
            setItem: () => {
                throw new Error('blocked');
            },
            removeItem: () => {
                throw new Error('blocked');
            },
        };
        expect(recallExtraFamilies(3, P, broken)).toEqual([]);
        expect(() => rememberExtraFamilies(3, P, ['tuic'], broken)).not.toThrow();
        expect(recallExtraFamilies(3, P, null)).toEqual([]);
    });
});

describe('the section on screen', () => {
    const t = (k: string) => en[k] ?? `MISSING:${k}`;
    const render = (open: boolean, selected: string[]) =>
        renderToStaticMarkup(
            <MoreWaysToConnect
                t={t}
                profileSlug={P}
                open={open}
                onToggleOpen={() => {}}
                selected={selected}
                onChange={() => {}}
                available={true}
            />,
        );

    it('is collapsed by default: a title, a one-line state, and no switches', () => {
        const html = render(false, []);
        expect(html).toContain('aria-expanded="false"');
        expect(html).toContain(en['wiz.more.title']);
        expect(html).toContain(en['wiz.more.summary.off']);
        expect(html).not.toContain('type="checkbox"');
        expect(html).not.toContain('MISSING:');
    });

    it('opened, shows three unticked switches, each with its cost', () => {
        const html = render(true, []);
        expect(html).toContain('aria-expanded="true"');
        expect(html.match(/type="checkbox"/g)).toHaveLength(3);
        expect(html).not.toMatch(/checked=""/);
        expect(html).not.toMatch(/disabled=""/);
        expect(html).not.toContain(en['wiz.more.unavailable']);
        for (const o of extraFamilyOptions(P)) {
            expect(html).toContain(en[o.titleKey]);
            expect(html).toContain(en[o.bodyKey].replace(/'/g, '&#x27;'));
        }
        expect(html).toContain(en['wiz.more.intro']);
        // The older-app warning is not shouted until it applies.
        expect(html).not.toContain('role="alert"');
        expect(html).not.toContain('MISSING:');
    });

    it('with anytls ticked, warns that older apps cannot open the file, and counts what is on', () => {
        const html = render(true, ['anytls', 'tuic']);
        expect(html.match(/checked=""/g)).toHaveLength(2);
        expect(html).toContain('role="alert"');
        expect(html).toContain(en['wiz.more.anytls.warn']);
        expect(render(false, ['anytls', 'tuic'])).toContain(en['wiz.more.summary.on'].replace('{n}', '2'));
    });

    it('draws nothing for a profile with no opt-in families it can describe', () => {
        expect(
            renderToStaticMarkup(
                <MoreWaysToConnect
                    t={t}
                    profileSlug="no-such-profile"
                    open={true}
                    onToggleOpen={() => {}}
                    selected={[]}
                    onChange={() => {}}
                />,
            ),
        ).toBe('');
    });
});

describe('the words', () => {
    const keys = [
        'wiz.more.title',
        'wiz.more.summary.off',
        'wiz.more.summary.on',
        'wiz.more.intro',
        'wiz.more.newer',
        'wiz.more.summary.unavailable',
        'wiz.more.unavailable',
        'wiz.more.anytls.warn',
        ...TOOLBOX_PROFILES.flatMap((p) => extraFamilyOptions(p.slug)).flatMap((o) => [o.titleKey, o.bodyKey]),
    ];

    it('exist in English and Persian', () => {
        for (const k of keys) {
            expect(en[k], `en ${k}`).toBeTruthy();
            expect(fa[k], `fa ${k}`).toBeTruthy();
            expect(fa[k], `fa ${k} is untranslated`).not.toBe(en[k]);
            // Persian text is written in Persian script.
            expect(fa[k]).toMatch(/[؀-ۿ]/);
        }
        expect(en['wiz.more.summary.on']).toContain('{n}');
        expect(fa['wiz.more.summary.on']).toContain('{n}');
    });

    it('are plain language: no protocol names, no port numbers', () => {
        const jargon = /shadowsocks|anytls|tuic|quic|udp|tcp|tls|vless|reality|hysteria|protocol|port|\d{3,5}|پروتکل|پورت|[۰-۹]{3,5}/i;
        for (const k of keys) {
            expect(en[k], `en ${k}`).not.toMatch(jargon);
            expect(fa[k], `fa ${k}`).not.toMatch(jargon);
        }
    });

    it('say what each one costs, and say the anytls cost honestly', () => {
        for (const o of extraFamilyOptions(P)) {
            // every option states that it opens something more on the server
            expect(en[o.bodyKey]).toMatch(/one more open door/);
            expect(fa[o.bodyKey]).toMatch(/یک درِ? (?:باز )?دیگر/);
        }
        // anytls: a newer file format that an older app rejects WHOLE.
        expect(en['wiz.more.anytls.body']).toMatch(/newer format/);
        expect(en['wiz.more.anytls.body']).toMatch(/older Daal app cannot open that file at all/);
        expect(en['wiz.more.anytls.body']).toMatch(/not even to use the other ways/);
        expect(fa['wiz.more.anytls.body']).toMatch(/قالب جدیدتری/);
        expect(fa['wiz.more.anytls.body']).toMatch(/اصلاً نمی‌تواند (?:آن|این) فایل را باز کند/);
        expect(en['wiz.more.anytls.warn']).toMatch(/older Daal app/);
        // and nothing promises a way through a web-only network
        expect(en['wiz.more.intro']).toMatch(/none of them gets through a network that only allows ordinary web traffic/);
    });

    // That the client-ui and client-shared copies of these catalogs are
    // byte-identical is held by tools/check-toolbox-profiles.mjs, which
    // can read both trees; this suite stays inside the bundler's world.
});

// Review finding on FAM-2, with F-002 still open: the switches offered
// families that the only relay software a new server downloads cannot
// serve. Ticking anytls bought no anytls route and a connection file
// older apps refuse — the cost the warning describes, none of the
// benefit. Until the pinned release serves them the switches are shown,
// locked, with the reason; and nothing this module returns names one.
describe('while the released relay software cannot serve them', () => {
    const t = (k: string) => en[k] ?? `MISSING:${k}`;
    const ALL = ['shadowsocks', 'anytls', 'tuic'];
    const render = (open: boolean, selected: string[], available?: boolean) =>
        renderToStaticMarkup(
            <MoreWaysToConnect
                t={t}
                profileSlug={P}
                open={open}
                onToggleOpen={() => {}}
                selected={selected}
                onChange={() => {}}
                available={available}
            />,
        );
    const mem = (v: string) => {
        const m = new Map<string, string>([['daal.wizard.extra_families.7', v]]);
        return {
            m,
            getItem: (k: string) => m.get(k) ?? null,
            setItem: (k: string, val: string) => void m.set(k, val),
            removeItem: (k: string) => void m.delete(k),
        };
    };

    it('follows the constant that sits next to the pinned relay release', () => {
        const m = /^const PinnedMgmtServesOptInFamilies = (true|false)$/m.exec(pinSource);
        expect(m, 'PinnedMgmtServesOptInFamilies not found in artifacts.go').not.toBeNull();
        expect(String(RELEASED_RELAY_SERVES_EXTRA_FAMILIES)).toBe(m![1]);
    });

    it('never asks a server for an extra family, whatever was ticked or remembered', () => {
        expect(gated.sanitizeExtraFamilies(P, ALL, false)).toEqual([]);
        expect(gated.enabledFamiliesFor(P, ALL, false)).toEqual([]);
        expect(gated.toggleExtraFamily(P, [], 'anytls', true, false)).toEqual([]);
        expect(gated.selectionForcesNewFileFormat(P, ['anytls'], false)).toBe(false);
        // A choice remembered by a build that offered them is not replayed.
        expect(gated.recallExtraFamilies(7, P, mem('["anytls","tuic"]'), false)).toEqual([]);
    });

    it('still shows the three switches, but locked, unticked and with the reason', () => {
        const html = render(true, ['anytls', 'tuic'], false);
        expect(html.match(/type="checkbox"/g)).toHaveLength(3);
        expect(html.match(/disabled=""/g)).toHaveLength(3);
        expect(html).not.toMatch(/checked=""/);
        expect(html).toContain(en['wiz.more.unavailable']);
        // What each one is stays readable: the section is not hidden.
        for (const o of extraFamilyOptions(P)) expect(html).toContain(en[o.titleKey]);
        // No older-app alarm for a switch that cannot be on.
        expect(html).not.toContain('role="alert"');
        expect(html).not.toContain('MISSING:');
    });

    it('collapsed, says it is not available instead of counting or inviting', () => {
        const html = render(false, ['anytls', 'tuic'], false);
        expect(html).toContain(en['wiz.more.summary.unavailable']);
        expect(html).not.toContain(en['wiz.more.summary.off']);
        expect(html).not.toContain(en['wiz.more.summary.on'].replace('{n}', '2'));
    });

    it('says why in plain words, without promising a date', () => {
        expect(en['wiz.more.unavailable']).toMatch(/cannot turn these on yet/);
        expect(en['wiz.more.unavailable']).toMatch(/nothing behind it/);
        expect(fa['wiz.more.unavailable']).toMatch(/فعلاً نمی‌توانید/);
    });

    it('is what this build ships: with no override, every caller gets the constant', () => {
        const open = RELEASED_RELAY_SERVES_EXTRA_FAMILIES;
        expect(gated.enabledFamiliesFor(P, ['anytls'])).toEqual(open ? [...DEFAULTS, 'anytls'] : []);
        expect(gated.sanitizeExtraFamilies(P, ALL)).toEqual(open ? ALL : []);
        expect(gated.recallExtraFamilies(7, P, mem('["tuic"]'))).toEqual(open ? ['tuic'] : []);
        const html = render(true, ['anytls']);
        expect((html.match(/disabled=""/g) ?? []).length).toBe(open ? 0 : 3);
        expect(html.includes(en['wiz.more.unavailable'])).toBe(!open);
        expect(html.includes('checked=""')).toBe(open);
    });
});

describe('the wizard is wired to it', () => {
    // The original defect was a constant in the wizard. A component test
    // of the whole wizard needs a DOM this suite does not have, so the
    // wiring is held at the source level: the constant is gone and the
    // list the build sends comes from enabledFamiliesFor.
    const src: string = wizardSource;

    it('no longer hard-codes an empty family list', () => {
        expect(src).not.toMatch(/useMemo<string\[\]>\(\(\) => \[\], \[\]\)/);
        expect(src).toMatch(/enabledFamiliesFor\(toolboxProfile, extraFamilies\)/);
        expect(src).toMatch(/<MoreWaysToConnect/);
    });

    it('starts with nothing ticked and the section closed', () => {
        expect(src).toMatch(/useState<string\[\]>\(\[\]\);\s*\n\s*const \[moreWaysOpen, setMoreWaysOpen\] = useState\(false\)/);
    });
});
