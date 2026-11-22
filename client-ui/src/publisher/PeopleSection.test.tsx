// The person's ⋯ menu: "Links for other apps" is there for a person who
// is on the relay, and never for one waiting for an answer or removed.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';
import type { ArtifactInfo, RecipientSummary } from './wizardCommands';

vi.mock('@tauri-apps/api/core', () => ({ invoke: () => Promise.reject('not mocked') }));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

const en = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const { DensityProvider } = await import('../design/DensityProvider');
const { PeopleSection, joinPeople } = await import('./PeopleSection');
const t = (k: string) => en[k] ?? k;
const noop = () => {};
const button = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);

function person(id: number, over: Partial<RecipientSummary> = {}): RecipientSummary {
    return {
        id,
        name: `r${id}`,
        display_name: `Person ${id}`,
        address_str: `daal1qqqqqqqqqqqqqqqqqqqq${id}`,
        provisioned_at_unix: 1_763_500_000,
        revoked_at_unix: 0,
        ...over,
    } as RecipientSummary;
}
function file(id: number): ArtifactInfo {
    return {
        kind: 'sbpx',
        path: `/stage/${id}.sbpx`,
        exists: true,
        size_bytes: 900,
        modified_at_unix: 1_763_500_000,
        recipient_id: id,
        recipient_label: `Person ${id}`,
    };
}

async function mount(r: RecipientSummary, onLinks: (r: RecipientSummary) => void, waiting?: Set<number>) {
    return rig.mount(
        <DensityProvider>
            <PeopleSection
                t={t}
                action={{ busy: null, outcome: null }}
                loading={false}
                people={joinPeople([r], [file(r.id)])}
                onAdd={noop}
                onSend={noop}
                onRemake={noop}
                onReplace={noop}
                onRemoveAccess={noop}
                onRemoveFromList={noop}
                waiting={waiting}
                onLinks={onLinks}
            />
        </DensityProvider>,
    );
}

describe('PeopleSection: links for other apps', () => {
    it('is on a live person’s menu and opens the sheet for them', async () => {
        const onLinks = vi.fn();
        const m = await mount(person(1), onLinks);
        await rig.click(button(m.container, 'person-more'));
        const item = button(m.container, 'links');
        expect(item?.textContent).toContain(en['pub.links.menu']);
        await rig.click(item);
        expect(onLinks).toHaveBeenCalledWith(expect.objectContaining({ id: 1 }));
    });

    it('is not offered to a person waiting for an answer', async () => {
        const m = await mount(person(1), vi.fn(), new Set([1]));
        const more = button(m.container, 'person-more');
        if (more) await rig.click(more);
        expect(button(m.container, 'links')).toBeNull();
    });

    it('is not offered to a removed person', async () => {
        const m = await mount(person(1, { revoked_at_unix: 9 }), vi.fn());
        const fold = button(m.container, 'people-removed');
        if (fold) await rig.click(fold);
        const more = button(m.container, 'person-more');
        if (more) await rig.click(more);
        expect(button(m.container, 'remove-from-list')).not.toBeNull();
        expect(button(m.container, 'links')).toBeNull();
    });
});
