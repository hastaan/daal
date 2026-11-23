// The file's sheet on the Files tab (round 3a).
//
//   * "Connect with this file" lets Daal choose among THAT file's ways:
//     it asks for the file's connect (all its ways), never a connect of
//     one way, which used to leave the phone pinned to it ("your
//     choice"). Picking one way on its own row is still a choice of
//     that way.
//   * the muted line naming the file's backup update routes, and the
//     "Check the backup update routes" item in ⋯, only when the file has
//     them and nothing is up;
//   * the check's own sheet: the calm waiting line, then a line per
//     route family, and the sentence for a rate limit.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { all, byAttr, type FakeNode } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';
import type { PublisherTreeRow, RouteDisplayRow } from '../contract/D2Contract';

vi.mock('@tauri-apps/api/core', () => ({ invoke: () => Promise.reject('not mocked') }));

const en = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const legacyEn = (await import('../i18n/en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...en };
const t = (k: string) => EN[k] ?? k;
const { FileSheet } = await import('./NetworkPage');
const { BackupCheckSheet } = await import('../components/files/BackupCheck');
const { parseDrill } = await import('../lib/backupCheck');

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

function route(id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow {
    return {
        routeId: id,
        publisherId: 'b7e1',
        publisherName: 'Test',
        routeNickname: id,
        trustClass: 'trusted',
        family: 'vless-reality',
        familyMaturity: 'stable',
        inCooldown: false,
        ...over,
    };
}

function file(routes: RouteDisplayRow[]): PublisherTreeRow {
    return {
        publisherId: 'b7e1',
        displayName: 'Test',
        trustLevel: 'trusted',
        sourceKind: 'sbpx',
        revoked: false,
        routeCount: routes.length,
        cells: [{ cellIdFpHex: 'default', label: '', families: [], routes }],
    };
}

const BACKUP = ['gittag', 'dns'] as const;

async function mountSheet(over: { p?: PublisherTreeRow; canCheck?: boolean; backup?: readonly ('gittag' | 'dns')[] } = {}) {
    const onConnectRoute = vi.fn();
    const onConnectFile = vi.fn();
    const onCheck = vi.fn();
    const p = over.p ?? file([route('r1'), route('r2'), route('r3', { family: 'hysteria2' })]);
    const m = await rig.mount(
        <FileSheet
            t={t}
            p={p}
            dev={false}
            nowMs={Date.now()}
            pendingId={null}
            verifying="steady"
            activeRouteId={null}
            autoRouteId={null}
            pinnedId={null}
            locale="en"
            onBackToAuto={vi.fn()}
            onClose={vi.fn()}
            onConnectRoute={onConnectRoute}
            onConnectFile={onConnectFile}
            connectingFile={false}
            backupRoutes={over.backup ?? []}
            canCheck={over.canCheck ?? false}
            onCheck={onCheck}
            onDisconnect={vi.fn()}
            onRefresh={vi.fn()}
            onStopUpdates={vi.fn()}
            onRemove={vi.fn()}
            onCool={vi.fn()}
            onBudget={vi.fn()}
        />,
    );
    return { ...m, onConnectRoute, onConnectFile, onCheck };
}

function menuIds(root: FakeNode): string[] {
    return all(root, (n) => n.getAttribute?.('role') === 'menuitem').map((n) => n.getAttribute('data-button') ?? '');
}

describe('Connect with this file', () => {
    it("asks for the file's automatic connect over all its ways, and never a connect of one way", async () => {
        const m = await mountSheet();
        await rig.click(byAttr(m.container, 'data-button', 'file-connect'));
        // The old button called onConnectRoute(best) — a connect by hand,
        // which pinned that one way once it was up.
        expect(m.onConnectRoute).not.toHaveBeenCalled();
        expect(m.onConnectFile).toHaveBeenCalledTimes(1);
        expect(m.onConnectFile).toHaveBeenCalledWith(['r1', 'r2', 'r3']);
    });

    it('a file whose ways are all connected only by hand connects its one way, as before', async () => {
        const m = await mountSheet({ p: file([route('w1', { family: 'wireguard', manualOnly: true })]) });
        await rig.click(byAttr(m.container, 'data-button', 'file-connect'));
        expect(m.onConnectFile).not.toHaveBeenCalled();
        expect(m.onConnectRoute).toHaveBeenCalledWith('w1');
    });

    it('leaves the ways only ever connected by hand out of the automatic choice', async () => {
        const m = await mountSheet({ p: file([route('r1'), route('w1', { family: 'wireguard', manualOnly: true })]) });
        await rig.click(byAttr(m.container, 'data-button', 'file-connect'));
        expect(m.onConnectFile).toHaveBeenCalledWith(['r1']);
    });

    it('picking one way on its own row is still a choice of that way', async () => {
        const m = await mountSheet();
        await rig.click(all(m.container, (n) => n.getAttribute?.('data-button') === 'way-row')[1]);
        await rig.click(byAttr(m.container, 'data-button', 'way-use-only'));
        expect(m.onConnectRoute).toHaveBeenCalledWith('r2');
        expect(m.onConnectFile).not.toHaveBeenCalled();
    });
});

describe("the file's backup update routes", () => {
    it('one muted line names them', async () => {
        const m = await mountSheet({ backup: BACKUP });
        expect(byAttr(m.container, 'data-backup-line')?.textContent).toBe('Backup update routes: GitHub, DNS');
    });

    it('nothing when the file has none', async () => {
        const m = await mountSheet();
        expect(byAttr(m.container, 'data-backup-line')).toBeNull();
        expect(m.container.textContent).not.toContain('Backup update routes');
    });

    it('the check is in ⋯ only when it is offered', async () => {
        const on = await mountSheet({ backup: BACKUP, canCheck: true });
        await rig.click(byAttr(on.container, 'data-button', 'file-more'));
        expect(menuIds(rig.win.document.body)).toContain('check-backup');
        await rig.click(byAttr(rig.win.document.body, 'data-button', 'check-backup'));
        expect(on.onCheck).toHaveBeenCalledTimes(1);
        await rig.unmountAll();

        const off = await mountSheet({ backup: BACKUP, canCheck: false });
        await rig.click(byAttr(off.container, 'data-button', 'file-more'));
        expect(menuIds(rig.win.document.body)).not.toContain('check-backup');
        expect(menuIds(rig.win.document.body)).toContain('remove');
    });
});

describe('the check sheet', () => {
    it('says it can take up to two minutes while it runs', async () => {
        const m = await rig.mount(
            <BackupCheckSheet t={t} locale="en" state={{ name: 'Test', running: true, open: true }} onClose={vi.fn()} />,
        );
        const text = rig.win.document.body.textContent ?? '';
        expect(text).toContain('up to two minutes');
        expect(byAttr(m.container, 'data-check-family')).toBeNull();
    });

    it('a line per route family in plain words', async () => {
        const a = parseDrill(
            JSON.stringify({
                outcome: 'unchanged',
                drill: {
                    github: { result: 'verified' },
                    google: { result: 'nothing_new' },
                    goproxy: { result: 'skipped', reason: 'budget' },
                    jsdelivr: { result: 'failed' },
                    dns: { result: 'skipped', reason: 'no_resolver' },
                },
            }),
        );
        await rig.mount(
            <BackupCheckSheet t={t} locale="en" state={{ name: 'Test', running: false, answer: a, at: Date.now(), open: true }} onClose={vi.fn()} />,
        );
        const body = rig.win.document.body;
        const rows = all(body, (n) => !!n.getAttribute?.('data-check-family'));
        expect(rows.map((n) => n.textContent)).toEqual([
            'GitHubWorks',
            'GoogleAnswered, nothing new',
            'Other mirrorsDid not answer',
            'DNSNot available here',
        ]);
        expect(body.textContent).toContain('Your file is up to date.');
        for (const word of ['ladder', 'carrier', 'note', 'tag', 'epoch', 'goproxy', 'jsdelivr', 'gittag']) {
            expect((body.textContent ?? '').toLowerCase()).not.toContain(word);
        }
    });

    it('the rate limit says when it can be tried again', async () => {
        const at = new Date(2026, 10, 23, 14, 0, 0).getTime();
        await rig.mount(
            <BackupCheckSheet
                t={t}
                locale="en"
                state={{ name: 'Test', running: false, answer: { outcome: 'rate_limited', retryAfterS: 420 }, at, open: true }}
                onClose={vi.fn()}
            />,
        );
        expect(rig.win.document.body.textContent).toContain('You can check again at');
        expect(rig.win.document.body.textContent).toContain('14:07');
    });

    it('names the file it is about', async () => {
        await rig.mount(<BackupCheckSheet t={t} locale="en" state={{ name: 'Relay of Sara', running: true, open: true }} onClose={vi.fn()} />);
        expect(byAttr(rig.win.document.body, 'data-check-file')?.textContent).toBe('Relay of Sara');
    });

    it('a kept answer shows its lines again, and when a new check may run', async () => {
        const a = parseDrill(JSON.stringify({ outcome: 'unchanged', drill: { github: { result: 'verified' } } }));
        const againAt = new Date(2026, 10, 23, 14, 10, 0).getTime();
        await rig.mount(
            <BackupCheckSheet t={t} locale="en" state={{ name: 'Test', running: false, answer: a, at: Date.now(), open: true, againAt }} onClose={vi.fn()} />,
        );
        const body = rig.win.document.body;
        expect(all(body, (n) => !!n.getAttribute?.('data-check-family')).map((n) => n.textContent)).toEqual(['GitHubWorks']);
        expect(byAttr(body, 'data-check-again')?.textContent).toContain('14:10');
    });

    it('a route that came up meanwhile is said plainly', async () => {
        await rig.mount(
            <BackupCheckSheet
                t={t}
                locale="en"
                state={{ name: 'Test', running: false, answer: { outcome: 'tunnel_required', retryAfterS: 0 }, at: Date.now(), open: true }}
                onClose={vi.fn()}
            />,
        );
        expect(rig.win.document.body.textContent).toContain("You're connected now.");
    });
});
