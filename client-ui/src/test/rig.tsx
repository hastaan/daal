// rig — mount real components with react-dom in the miniDom fake, and
// drive them: click, type, the system Back. Test helper only.
import { expect } from 'vitest';
import { installMiniDom, FakeEvent } from './miniDom';
import type { FakeNode, FakeWindow } from './miniDom';

export interface Rig {
    win: FakeWindow;
    mount: (el: React.ReactElement) => Promise<{ container: FakeNode; unmount: () => Promise<void> }>;
    settle: (rounds?: number) => Promise<void>;
    back: () => Promise<void>;
    click: (n: FakeNode | null | undefined) => Promise<void>;
    type: (n: FakeNode | null | undefined, value: string) => Promise<void>;
    unmountAll: () => Promise<void>;
}

export function createRig(): Rig {
    const win = installMiniDom();
    const mounted: (() => Promise<void>)[] = [];

    const settle = async (rounds = 4) => {
        const React = await import('react');
        for (let i = 0; i < rounds; i++) {
            await React.act(async () => {
                await new Promise((r) => setTimeout(r, 1));
            });
        }
    };

    const mount = async (el: React.ReactElement) => {
        const React = await import('react');
        const { createRoot } = await import('react-dom/client');
        const { DensityProvider } = await import('../design/DensityProvider');
        const container = win.document.createElement('div');
        win.document.body.appendChild(container);
        const root = createRoot(container as unknown as Element);
        await React.act(async () => {
            root.render(<DensityProvider>{el}</DensityProvider>);
        });
        await settle();
        let gone = false;
        const unmount = async () => {
            if (gone) return;
            gone = true;
            await React.act(async () => root.unmount());
            await settle();
        };
        mounted.push(unmount);
        return { container, unmount };
    };

    const click = async (n: FakeNode | null | undefined) => {
        expect(n, 'element to click').toBeTruthy();
        const React = await import('react');
        await React.act(async () => {
            n!.dispatchEvent(new FakeEvent('click'));
        });
        await settle();
    };

    const type = async (n: FakeNode | null | undefined, value: string) => {
        expect(n, 'element to type into').toBeTruthy();
        const React = await import('react');
        await React.act(async () => {
            n!.value = value;
            n!.dispatchEvent(new FakeEvent('input'));
        });
        await settle();
    };

    const back = async () => {
        win.systemBack();
        await settle();
    };

    const unmountAll = async () => {
        while (mounted.length) await mounted.pop()!();
        win.history.appLeft = false;
    };

    return { win, mount, settle, back, click, type, unmountAll };
}
