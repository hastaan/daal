// The Files tab for links pasted on this phone (wave 2 app leftovers):
// the group has its own plain title (not "My Daal"), each pasted route
// is known by the name in its link (never a piece of its id), and a
// pasted WireGuard conf says it is used only when the person picks it,
// and is never offered for removal as "not working". With the engine's
// fields (manual_only, pasted_by_you, name_from_link) and without them.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../../test/miniDom';
import { createRig, type Rig } from '../../test/rig';
import type { PublisherTreeRow, RouteDisplayRow } from '../../contract/D2Contract';

vi.mock('@tauri-apps/api/core', () => ({ invoke: () => Promise.reject('not mocked') }));

const en = (await import('../../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const fa = (await import('../../i18n/d2/d2-extra.fa.json')).default as Record<string, string>;
const legacyEn = (await import('../../i18n/en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...en };
const t = (k: string) => EN[k] ?? k;
const { fileTitle, isPastedGroup, manualOnly, pastedHere, pastedName } = await import('./pasted');
const { WayRow, FileCard } = await import('./FileParts');
const { checksFor, failingHere } = await import('../pasteSurvey');

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

const ID = 'pasted-20261122T101500Z-a1b2c3d4';

function route(over: Partial<RouteDisplayRow> & Record<string, unknown> = {}): RouteDisplayRow {
    return {
        routeId: ID,
        publisherId: 'self',
        publisherName: 'My Daal',
        routeNickname: 'a1b2c3d4',
        trustClass: 'pinned',
        family: 'vless-reality',
        ...over,
    } as RouteDisplayRow;
}

function tree(routes: RouteDisplayRow[], displayName = 'My Daal'): PublisherTreeRow {
    return {
        publisherId: 'self',
        displayName,
        trustLevel: 'pinned',
        sourceKind: 'file',
        revoked: false,
        routeCount: routes.length,
        cells: [{ routes }],
    } as unknown as PublisherTreeRow;
}

describe('what a pasted route is called', () => {
    it("the engine's own fields win", () => {
        expect(pastedName(route({ routeNickname: 'Server 1', nameFromLink: true, pastedByYou: true }))).toBe('Server 1');
        expect(pastedName(route({ routeNickname: 'Server 1', nameFromLink: false, pastedByYou: true }))).toBeUndefined();
        expect(pastedHere(route({ routeId: 'r-other', pastedByYou: true }))).toBe(true);
    });

    it('an older engine: the id-tail nickname is never shown, a real name is', () => {
        expect(pastedName(route())).toBeUndefined();
        expect(pastedName(route({ routeNickname: ID }))).toBeUndefined();
        expect(pastedName(route({ routeNickname: 'Server 1' }))).toBe('Server 1');
        expect(pastedName(route({ routeNickname: '' }))).toBeUndefined();
    });

    it("a route from someone's file keeps its own title", () => {
        const r = route({ routeId: 'r1-vless', routeNickname: 'Rescue 03', publisherName: 'Pars' });
        expect(pastedHere(r)).toBe(false);
        expect(pastedName(r)).toBeUndefined();
    });
});

describe('the group', () => {
    it('is titled in its own plain words, never "My Daal"', () => {
        const p = tree([route(), route({ routeId: `${ID}x` })]);
        expect(isPastedGroup(p)).toBe(true);
        expect(fileTitle(t, p)).toBe('Links you added');
        expect(fa['files.pasted.group']).toBeTruthy();
        expect(fileTitle(t, tree([route({ routeId: 'r1' })], 'Pars Relays'))).toBe('Pars Relays');
        expect(isPastedGroup(tree([]))).toBe(false);
    });

    it('the file card shows that title', async () => {
        const m = await rig.mount(
            <FileCard t={t} locale="en" p={tree([route()])} state={'untried' as never} summary="" tags={[]} last onOpen={vi.fn()} />,
        );
        expect(m.container.textContent).toContain('Links you added');
        expect(m.container.textContent).not.toContain('My Daal');
    });
});

describe('a pasted WireGuard conf', () => {
    const wg = route({ family: 'wireguard', routeNickname: 'Home WG', checkedWhenUsed: true });

    it('is used only when picked, by the flag or (older engine) by what it is', () => {
        expect(manualOnly(route({ manualOnly: true }))).toBe(true);
        expect(manualOnly(route({ family: 'wireguard', manualOnly: false }))).toBe(false);
        expect(manualOnly(wg)).toBe(true);
        expect(manualOnly(route({ routeId: 'r1', family: 'wireguard' }))).toBe(false);
    });

    it('is never counted as failed or offered for removal', () => {
        const read = { report: {} as never, results: new Map([[ID, 'failed' as const]]) };
        const flagged = route({ manualOnly: true, family: 'vless-reality' });
        expect(checksFor([ID], read, [flagged]).get(ID)).toBe('when_used');
        expect(failingHere([flagged], read, null)).toEqual([]);
        const legacy = route({ family: 'wireguard' });
        expect(failingHere([legacy], read, null)).toEqual([]);
        expect(failingHere([route()], read, null)).toEqual([ID]);
    });
});

async function mountWay(r: RouteDisplayRow) {
    return rig.mount(
        <WayRow
            t={t}
            locale="en"
            r={r}
            title={{ title: 'VLESS Reality', nickname: r.routeNickname }}
            state={'untried' as never}
            open={false}
            onToggle={vi.fn()}
            pinned={false}
            chosenByDaal={false}
            busy={false}
            onUseOnly={vi.fn()}
            onBackToAuto={vi.fn()}
            last
        />,
    );
}

describe('the route row on the Files page', () => {
    it("a pasted route is titled by its link's name, the kind under it", async () => {
        const m = await mountWay(route({ routeNickname: 'Server 1', nameFromLink: true, pastedByYou: true }));
        const text = m.container.textContent ?? '';
        expect(text).toContain('Server 1');
        expect(text).toContain('VLESS Reality');
        expect(text.indexOf('Server 1')).toBeLessThan(text.indexOf('VLESS Reality'));
        expect(byAttr(m.container, 'data-testid', 'way-manual-only')).toBeNull();
    });

    it('a pasted route with no name shows its kind and never the id tail', async () => {
        const m = await mountWay(route());
        expect(m.container.textContent).toContain('VLESS Reality');
        expect(m.container.textContent).not.toContain('a1b2c3d4');
    });

    it('a WireGuard conf says in one line that it is used only when picked', async () => {
        const m = await mountWay(route({ family: 'wireguard', routeNickname: 'Home', nameFromLink: true, pastedByYou: true, manualOnly: true }));
        expect(byAttr(m.container, 'data-testid', 'way-manual-only')?.textContent).toBe(en['files.pasted.manual_only']);
        expect(fa['files.pasted.manual_only']).toBeTruthy();
    });
});
