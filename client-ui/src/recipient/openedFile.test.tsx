// A file handed to Daal by Android (spec G.1, this wave): the shell's
// take_opened_file on start, the "daal://opened-file" event while Daal
// runs, and one page — the newest mounted — receives each file. An
// older shell has neither: nothing happens, and nothing breaks.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createRig, type Rig } from '../test/rig';

let opened: string | null = '/staging/from-telegram.sbpx';
let commandExists = true;
let emit: ((e: { payload: unknown }) => void) | null = null;

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string) => {
        if (cmd !== 'take_opened_file' || !commandExists) throw new Error(`unknown command ${cmd}`);
        const p = opened;
        opened = null;
        return p;
    },
}));
vi.mock('@tauri-apps/api/event', () => ({
    listen: async (name: string, cb: (e: { payload: unknown }) => void) => {
        if (name === 'daal://opened-file') emit = cb;
        return () => {};
    },
}));

const React = await import('react');
const { useOpenedFile, _deliverOpenedFile, _resetOpenedFile } = await import('./openedFile');

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

function Probe({ name, got }: { name: string; got: string[] }) {
    useOpenedFile((p) => got.push(`${name}:${p}`));
    return <div />;
}

describe('files handed to Daal', () => {
    it('the file Daal was opened with goes to the page, once; then the event brings the next', async () => {
        const got: string[] = [];
        await rig.mount(<Probe name="home" got={got} />);
        await rig.settle(6);
        expect(got).toEqual(['home:/staging/from-telegram.sbpx']);
        expect(emit).toBeTruthy();
        await React.act(async () => emit!({ payload: { path: '/staging/second.sbp' } }));
        expect(got).toEqual(['home:/staging/from-telegram.sbpx', 'home:/staging/second.sbp']);
    });

    it('only the newest mounted page receives it; a file with nobody listening waits', async () => {
        _resetOpenedFile();
        _deliverOpenedFile('/staging/early.sbp');
        const home: string[] = [];
        const files: string[] = [];
        await rig.mount(<Probe name="home" got={home} />);
        expect(home).toEqual(['home:/staging/early.sbp']);
        const second = await rig.mount(<Probe name="files" got={files} />);
        await React.act(async () => _deliverOpenedFile('/staging/late.sbp'));
        expect(files).toEqual(['files:/staging/late.sbp']);
        expect(home).toEqual(['home:/staging/early.sbp']);
        await second.unmount();
        await React.act(async () => _deliverOpenedFile('/staging/last.sbp'));
        expect(home).toEqual(['home:/staging/early.sbp', 'home:/staging/last.sbp']);
    });

    it('a file arriving while the add sheet is mid-way (a scan, a trust question) waits until the sheet closes', async () => {
        _resetOpenedFile();
        const { useOpenedFileSheet } = await import('./openedFile');
        const opened: string[] = [];
        let api: ReturnType<typeof useOpenedFileSheet> | null = null;
        function Page() {
            const [open, setOpen] = React.useState(false);
            api = useOpenedFileSheet(open, (p) => {
                opened.push(p);
                setOpen(true);
            });
            return <div />;
        }
        await rig.mount(<Page />);
        await React.act(async () => _deliverOpenedFile('/staging/first.sbp'));
        expect(opened).toEqual(['/staging/first.sbp']);
        // The sheet is now holding scanned blocks, or asking the trust question.
        api!.setInProgress(true);
        await React.act(async () => _deliverOpenedFile('/staging/second.sbp'));
        expect(opened).toEqual(['/staging/first.sbp']);
        // Closing it opens the one that waited.
        await React.act(async () => api!.closed());
        expect(opened).toEqual(['/staging/first.sbp', '/staging/second.sbp']);
        // On its three choices (not in progress) a new file replaces it at once.
        api!.setInProgress(false);
        await React.act(async () => _deliverOpenedFile('/staging/third.sbp'));
        expect(opened).toEqual(['/staging/first.sbp', '/staging/second.sbp', '/staging/third.sbp']);
    });

    it('an older shell without the command or the event: nothing arrives, nothing throws', async () => {
        vi.resetModules();
        commandExists = false;
        const fresh = await import('./openedFile');
        const got: string[] = [];
        function P() {
            fresh.useOpenedFile((p) => got.push(p));
            return <div />;
        }
        await rig.mount(<P />);
        await rig.settle(6);
        expect(got).toEqual([]);
    });
});
