// The primitives every screen is built from, rendered in the miniDom
// fake: what they render, what a tap does, what Back and Escape do.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { all, byAttr, byText, FakeEvent } from '../../test/miniDom';
import type { FakeNode, FakeWindow } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';

vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string) => Promise.reject(`not mocked: ${cmd}`),
}));

let rig: Rig;
let win: FakeWindow;
beforeAll(() => {
    rig = createRig();
    win = rig.win;
});
afterEach(async () => {
    await rig.unmountAll();
    win.innerWidth = 400;
});

const React = await import('react');
const P = await import('./index');
const { ICON_NAMES, DIRECTIONAL_ICONS } = await import('./icons');
const mount = (el: React.ReactElement) => rig.mount(el);
const click = (n: FakeNode | null | undefined) => rig.click(n);
const buttons = (root: FakeNode) => all(root, (n) => n.nodeName === 'BUTTON');
const key = async (n: FakeNode | null | undefined, k: string) => {
    expect(n, 'element for keydown').toBeTruthy();
    await React.act(async () => {
        const e = new FakeEvent('keydown') as FakeEvent & { key: string };
        e.key = k;
        n!.dispatchEvent(e);
    });
    await rig.settle();
};
/** Every element under `root` whose inline style says `prop: value`. */
const styled = (root: FakeNode, prop: string, value: string) =>
    all(root, (n) => n.nodeType === 1 && (n.style as Record<string, string>)[prop] === value);

describe('Icon', () => {
    it('draws every name as an svg, hidden from screen readers unless titled', async () => {
        for (const name of ICON_NAMES) {
            const m = await mount(<P.Icon name={name} size={24} />);
            const svg = all(m.container, (n) => n.nodeName === 'SVG')[0];
            expect(svg, name).toBeTruthy();
            expect(svg.getAttribute('width'), name).toBe('24');
            expect(svg.getAttribute('aria-hidden'), name).toBe('true');
            expect(svg.childNodes.length, name).toBeGreaterThan(0);
            await m.unmount();
        }
        const m = await mount(<P.Icon name="lock" title="Protected" />);
        const svg = all(m.container, (n) => n.nodeName === 'SVG')[0];
        expect(svg.getAttribute('role')).toBe('img');
        expect(svg.getAttribute('aria-hidden')).toBeNull();
        expect(m.container.textContent).toContain('Protected');
    });

    it('directional icons, and only they, mirror under RTL', async () => {
        for (const name of ICON_NAMES) {
            const m = await mount(<P.Icon name={name} />);
            const flipped = byAttr(m.container, 'class', 'daal-flip-rtl') !== null;
            expect(flipped, name).toBe(DIRECTIONAL_ICONS.has(name));
            await m.unmount();
        }
        expect([...DIRECTIONAL_ICONS].sort()).toEqual(['back', 'chevron', 'external']);
    });

    it('the Files tab uses the two-sheets glyph', () => {
        expect(P.SECTION_ICONS.network).toBe(P.FilesIcon);
    });
});

describe('Badge and StatusPill', () => {
    it('sentence case in the body font, never uppercase or letter-spaced, never wrapping', async () => {
        const m = await mount(<P.Badge tone="warn">Not backed up</P.Badge>);
        const pill = byAttr(m.container, 'data-badge', 'warn')!;
        expect(pill.style.fontFamily).toBe('var(--font-body)');
        expect(pill.style.textTransform).toBe('none');
        expect(String(pill.style.letterSpacing)).toBe('0');
        expect(pill.style.whiteSpace).toBe('nowrap');
        expect(styled(m.container, 'textOverflow', 'ellipsis').length).toBe(1);
        // warn → alert icon by default
        expect(all(m.container, (n) => n.nodeName === 'SVG').length).toBe(1);
    });

    it('icon by tone; none for neutral; false hides it; pulse is a dot', async () => {
        const count = async (el: React.ReactElement) => {
            const m = await mount(el);
            const n = all(m.container, (x) => x.nodeName === 'SVG').length;
            await m.unmount();
            return n;
        };
        expect(await count(<P.Badge tone="good">Ready</P.Badge>)).toBe(1);
        expect(await count(<P.Badge tone="neutral">Retired</P.Badge>)).toBe(0);
        expect(await count(<P.Badge tone="good" icon={false}>Ready</P.Badge>)).toBe(0);
        const m = await mount(<P.Badge tone="info" pulse>Checking</P.Badge>);
        expect(byAttr(m.container, 'class', 'daal-badge-dot')).not.toBeNull();
    });

    it('a wrapping badge (a must-read warning) is never cut', async () => {
        const m = await mount(<P.Badge tone="warn" wrap>Unfinished · may cost money</P.Badge>);
        expect(styled(m.container, 'textOverflow', 'ellipsis')).toEqual([]);
        expect(byAttr(m.container, 'data-badge', 'warn')!.style.whiteSpace).toBe('normal');
    });

    it('with onClick it is a 44 px button that does not also tap the row it sits in', async () => {
        const row = vi.fn();
        const tap = vi.fn();
        const m = await mount(
            <div onClick={row}>
                <P.Badge tone="neutral" onClick={tap} dataButton="manual">
                    Manual
                </P.Badge>
            </div>,
        );
        const b = byAttr(m.container, 'data-button', 'manual')!;
        expect(b.nodeName).toBe('BUTTON');
        expect(b.style.minWidth).toBe('44px');
        await click(b);
        expect(tap).toHaveBeenCalledTimes(1);
        expect(row).not.toHaveBeenCalled();
    });

    it('StatusPill is a Badge now: the mono capitals are gone at every call site', async () => {
        const m = await mount(<P.StatusPill tone="good" glow>Connected</P.StatusPill>);
        const pill = byAttr(m.container, 'data-badge', 'good')!;
        expect(pill.style.fontFamily).toBe('var(--font-body)');
        expect(pill.style.textTransform).toBe('none');
        expect(byAttr(m.container, 'class', 'daal-badge-dot')).not.toBeNull();
        const gold = await mount(<P.StatusPill tone="gold" dotless>Normal</P.StatusPill>);
        expect(byAttr(gold.container, 'data-badge', 'gold')).not.toBeNull();
        expect(all(gold.container, (n) => n.nodeName === 'SVG')).toEqual([]);
    });
});

describe('Button and IconButton', () => {
    it('every variant is at least 44 px high, carries data-button and is not a submit button', async () => {
        for (const variant of ['primary', 'secondary', 'ghost', 'danger', 'link'] as const) {
            const m = await mount(
                <P.Button variant={variant} size="sm" dataButton={`b-${variant}`}>
                    Go
                </P.Button>,
            );
            const b = byAttr(m.container, 'data-button', `b-${variant}`)!;
            expect(b.style.minHeight, variant).toBe('44px');
            expect(b.getAttribute('type'), variant).toBe('button');
            await m.unmount();
        }
    });

    it('the link variant is a gold text button', async () => {
        const m = await mount(<P.Button variant="link">My Daal address</P.Button>);
        const b = byText(m.container, 'My Daal address')!;
        expect(b.style.color).toBe('var(--gold-warm)');
        expect(b.style.background).toBe('transparent');
    });

    it('`leading` takes an icon name or a node', async () => {
        const m = await mount(<P.Button leading="plus">New relay</P.Button>);
        expect(all(m.container, (n) => n.nodeName === 'SVG').length).toBe(1);
        const n = await mount(<P.Button leading={<i data-x="1" />}>X</P.Button>);
        expect(byAttr(n.container, 'data-x')).not.toBeNull();
        const s = await mount(<P.Button leading="not-an-icon">Y</P.Button>);
        expect(s.container.textContent).toContain('not-an-icon');
    });

    it('IconButton: 44 × 44 by default, named, danger in red', async () => {
        const fn = vi.fn();
        const m = await mount(<P.IconButton icon="trash" label="Remove" tone="danger" dataButton="rm" onClick={fn} />);
        const b = byAttr(m.container, 'data-button', 'rm')!;
        expect(b.style.width).toBe('44px');
        expect(b.style.height).toBe('44px');
        expect(b.getAttribute('aria-label')).toBe('Remove');
        expect(b.style.color).toBe('var(--red)');
        expect(all(b, (n) => n.nodeName === 'SVG').length).toBe(1);
        await click(b);
        expect(fn).toHaveBeenCalledTimes(1);
    });
});

describe('ListRow', () => {
    it('a clickable row is a real button (keyboard reachable), 52 px high, with a mirrored chevron', async () => {
        const open = vi.fn();
        const m = await mount(
            <P.ListRow title="Status" badge={<P.Badge tone="good">Connected</P.Badge>} chevron onClick={open} dataButton="status-row" />,
        );
        const b = byAttr(m.container, 'data-button', 'status-row')!;
        expect(b.nodeName).toBe('BUTTON');
        expect(b.getAttribute('role')).toBeNull();
        expect(byAttr(m.container, 'data-list-row')!.style.minHeight).toBe('52px');
        expect(byAttr(b, 'class', 'daal-flip-rtl')).not.toBeNull();
        expect(byAttr(b, 'data-badge', 'good')).not.toBeNull();
        await click(b);
        expect(open).toHaveBeenCalledTimes(1);
    });

    it('a control in the trailing slot answers alone; a tap on plain trailing content opens the row', async () => {
        const open = vi.fn();
        const send = vi.fn();
        const m = await mount(
            <P.ListRow
                title="Maman"
                onClick={open}
                trailing={
                    <>
                        <P.IconButton icon="share" label="Send" dataButton="person-send" onClick={send} />
                        <span data-plain="1">›</span>
                    </>
                }
            />,
        );
        await click(byAttr(m.container, 'data-button', 'person-send'));
        expect(send).toHaveBeenCalledTimes(1);
        expect(open).not.toHaveBeenCalled();
        await click(byAttr(m.container, 'data-plain'));
        expect(open).toHaveBeenCalledTimes(1);
    });

    it('a ⋯ menu in a clickable row opens only the menu', async () => {
        const open = vi.fn();
        const m = await mount(
            <P.ListRow
                title="Maman"
                onClick={open}
                trailing={<P.OverflowMenu label="More options" dataButton="person-more" items={[{ id: 'remove', label: 'Remove access', tone: 'danger', onSelect: () => {} }]} />}
            />,
        );
        await click(byAttr(m.container, 'data-button', 'person-more'));
        expect(open).not.toHaveBeenCalled();
        expect(byAttr(m.container, 'data-button', 'remove')).not.toBeNull();
        await click(byAttr(m.container, 'data-button', 'remove'));
        expect(open).not.toHaveBeenCalled();
    });

    it('subtitle: one line with ellipsis by default; wraps with wrapSubtitle; meta in the readable grey body font', async () => {
        const m = await mount(<P.ListRow title="A" subtitle="Updated 2 hours ago" meta="3" />);
        expect(styled(m.container, 'textOverflow', 'ellipsis').length).toBe(1);
        const meta = all(m.container, (n) => n.nodeType === 1 && n.textContent === '3' && n.childNodes.length === 1)[0];
        expect(meta.style.fontFamily).toBe('var(--font-body)');
        expect(meta.style.color).toBe('var(--muted)');
        const w = await mount(<P.ListRow title="A" subtitle="long" wrapSubtitle />);
        expect(styled(w.container, 'textOverflow', 'ellipsis')).toEqual([]);
    });

    it('danger puts the title in red; a row without onClick has no button', async () => {
        const m = await mount(<P.ListRow title="Erase Daal from this phone" danger />);
        expect(styled(m.container, 'color', 'var(--red)').length).toBe(1);
        expect(buttons(m.container)).toEqual([]);
    });
});

describe('OverflowMenu', () => {
    const items = (log: string[]) => [
        { id: 'remove', label: 'Remove access', icon: 'trash' as const, tone: 'danger' as const, onSelect: () => log.push('remove') },
        { id: 'replace', label: 'Give a new file', icon: 'refresh' as const, onSelect: () => log.push('replace') },
    ];

    it('with no items it renders nothing at all', async () => {
        const m = await mount(<P.OverflowMenu label="More options" items={[]} />);
        expect(m.container.childNodes.length).toBe(0);
    });

    it('phone: the ⋯ opens a sheet; danger last; choosing closes the sheet first, then acts', async () => {
        const log: string[] = [];
        function Host() {
            const [sheet, setSheet] = React.useState(false);
            return (
                <div>
                    <P.OverflowMenu
                        label="More options"
                        items={items(log).map((it) => ({ ...it, onSelect: () => (it.onSelect(), setSheet(true)) }))}
                    />
                    {sheet && (
                        <P.Sheet title="Next" onClose={() => setSheet(false)}>
                            <span data-next="1" />
                        </P.Sheet>
                    )}
                </div>
            );
        }
        const m = await mount(<Host />);
        const trigger = byAttr(m.container, 'data-button', 'more')!;
        expect(trigger.getAttribute('aria-haspopup')).toBe('menu');
        expect(trigger.getAttribute('aria-expanded')).toBe('false');
        expect(trigger.style.width).toBe('44px');
        await click(trigger);
        expect(byAttr(m.container, 'role', 'dialog')).not.toBeNull();
        const ids = all(m.container, (n) => n.getAttribute?.('role') === 'menuitem').map((n) => n.getAttribute('data-button'));
        expect(ids).toEqual(['replace', 'remove']);
        await click(byAttr(m.container, 'data-button', 'replace'));
        expect(log).toEqual(['replace']);
        // The menu is gone, the sheet the item opened is up, and Back
        // closes that sheet (not a menu that is no longer there).
        expect(byAttr(m.container, 'data-button', 'replace')).toBeNull();
        expect(byAttr(m.container, 'data-next')).not.toBeNull();
        expect(win.history.depth).toBe(1);
        await rig.back();
        expect(byAttr(m.container, 'data-next')).toBeNull();
        expect(win.history.depth).toBe(0);
    });

    it('phone: Back closes the menu sheet without choosing', async () => {
        const log: string[] = [];
        const m = await mount(<P.OverflowMenu label="More options" items={items(log)} />);
        await click(byAttr(m.container, 'data-button', 'more'));
        expect(byAttr(m.container, 'data-button', 'remove')).not.toBeNull();
        await rig.back();
        expect(byAttr(m.container, 'data-button', 'remove')).toBeNull();
        expect(log).toEqual([]);
        expect(win.history.appLeft).toBe(false);
    });

    it('desktop: a popover menu; Escape, Back and a click outside each close it', async () => {
        win.innerWidth = 1400;
        const log: string[] = [];
        const m = await mount(<P.OverflowMenu label="More options" items={items(log)} dataButton="relay-more" />);
        const trigger = byAttr(m.container, 'data-button', 'relay-more')!;
        const isOpen = () => byAttr(m.container, 'role', 'menu') !== null;

        await click(trigger);
        expect(isOpen()).toBe(true);
        expect(byAttr(m.container, 'role', 'dialog')).toBeNull();
        expect(trigger.getAttribute('aria-expanded')).toBe('true');
        const menu = byAttr(m.container, 'role', 'menu')!;
        // Danger last, after a divider.
        const ids = all(menu, (n) => n.getAttribute?.('role') === 'menuitem').map((n) => n.getAttribute('data-button'));
        expect(ids).toEqual(['replace', 'remove']);
        expect(byAttr(menu, 'data-button', 'remove')!.style.color).toBe('var(--red)');

        await key(menu, 'Escape');
        expect(isOpen()).toBe(false);

        await click(trigger);
        expect(isOpen()).toBe(true);
        await rig.back();
        expect(isOpen()).toBe(false);
        expect(win.history.appLeft).toBe(false);

        await click(trigger);
        await React.act(async () => {
            win.document.body.dispatchEvent(new FakeEvent('pointerdown'));
        });
        await rig.settle();
        expect(isOpen()).toBe(false);

        await click(trigger);
        await click(byAttr(m.container, 'data-button', 'remove'));
        expect(isOpen()).toBe(false);
        expect(log).toEqual(['remove']);
    });

    it('a disabled item does nothing', async () => {
        const fn = vi.fn();
        const m = await mount(<P.OverflowMenu label="More" items={[{ id: 'x', label: 'X', disabled: true, onSelect: fn }]} />);
        await click(byAttr(m.container, 'data-button', 'more'));
        await click(byAttr(m.container, 'data-button', 'x'));
        expect(fn).not.toHaveBeenCalled();
    });
});

describe('MenuSheet', () => {
    it('rows with a gold disc for the primary, subtitle and footer; choosing closes first, then acts', async () => {
        const order: string[] = [];
        const m = await mount(
            <P.MenuSheet
                title="Send Maman's file"
                subtitle="Only Maman's phone can open it."
                primaryId="share"
                footer="Check words"
                onClose={() => order.push('close')}
                items={[
                    { id: 'share', label: 'Send with an app', icon: 'share', onSelect: () => order.push('share') },
                    { id: 'qr', label: 'Show QR code', icon: 'qr', hint: 'On their phone', onSelect: () => order.push('qr') },
                ]}
            />,
        );
        expect(m.container.textContent).toContain("Only Maman's phone can open it.");
        expect(m.container.textContent).toContain('Check words');
        expect(m.container.textContent).toContain('On their phone');
        expect(styled(m.container, 'background', 'var(--gold-fill)').length).toBe(1);
        // No Cancel button: only the two items are buttons.
        expect(buttons(m.container).map((b) => b.getAttribute('data-button'))).toEqual(['share', 'qr']);
        await click(byAttr(m.container, 'data-button', 'qr'));
        expect(order).toEqual(['close', 'qr']);
    });
});

describe('Disclosure', () => {
    it('a button with aria-expanded; the children exist only while open', async () => {
        const m = await mount(
            <P.Disclosure summary="Details" dataButton="details">
                <span data-inside="1">hidden</span>
            </P.Disclosure>,
        );
        const b = byAttr(m.container, 'data-button', 'details')!;
        expect(b.nodeName).toBe('BUTTON');
        expect(b.getAttribute('aria-expanded')).toBe('false');
        expect(byAttr(m.container, 'data-inside')).toBeNull();
        expect(all(m.container, (n) => n.nodeName === 'DETAILS')).toEqual([]);
        await click(b);
        expect(b.getAttribute('aria-expanded')).toBe('true');
        expect(byAttr(m.container, 'data-inside')).not.toBeNull();
        await click(b);
        expect(byAttr(m.container, 'data-inside')).toBeNull();
    });

    it('card variant, danger tone, defaultOpen and the controlled form', async () => {
        const m = await mount(
            <P.Disclosure variant="card" tone="danger" icon="shieldAlert" summary="Danger zone" defaultOpen>
                <span data-inside="1" />
            </P.Disclosure>,
        );
        expect(byAttr(m.container, 'data-disclosure', 'card')).not.toBeNull();
        expect(byAttr(m.container, 'data-inside')).not.toBeNull();
        expect(styled(m.container, 'color', 'var(--red)').length).toBe(1);

        const seen: boolean[] = [];
        const c = await mount(
            <P.Disclosure summary="X" open={false} onToggle={(v) => seen.push(v)} dataButton="ctl">
                <span data-c="1" />
            </P.Disclosure>,
        );
        await click(byAttr(c.container, 'data-button', 'ctl'));
        expect(seen).toEqual([true]);
        // Controlled: it stays as the parent says.
        expect(byAttr(c.container, 'data-c')).toBeNull();
    });
});

describe('PageHeader, EmptyState, StateIcon, ProgressRing, Avatar', () => {
    it('PageHeader: one row; the back control is named and found as page-back', async () => {
        const back = vi.fn();
        const m = await mount(
            <P.PageHeader
                title="Advanced"
                back={{ label: 'Settings', onClick: back }}
                badge={<P.Badge tone="warn">Not backed up</P.Badge>}
                actions={<P.OverflowMenu label="More" items={[{ id: 'a', label: 'A', onSelect: () => {} }]} />}
            />,
        );
        const b = byAttr(m.container, 'data-button', 'page-back')!;
        expect(b.getAttribute('aria-label')).toBe('Settings');
        expect(byAttr(b, 'class', 'daal-flip-rtl')).not.toBeNull();
        await click(b);
        expect(back).toHaveBeenCalledTimes(1);
        const h1 = all(m.container, (n) => n.nodeName === 'H1')[0];
        expect(h1.textContent).toBe('Advanced');
        expect(h1.style.fontSize).toBe('24px');
        expect(h1.style.textOverflow).toBe('ellipsis');
    });

    it('EmptyState: icon, title, one line, the action and the link', async () => {
        const m = await mount(
            <P.EmptyState
                icon="files"
                title="No files yet"
                body="Add the file you were sent."
                action={<P.Button dataButton="add-my-file">Add my file</P.Button>}
                secondary={<P.Button variant="link" dataButton="my-address">My Daal address</P.Button>}
            />,
        );
        expect(m.container.textContent).toContain('No files yet');
        expect(byAttr(m.container, 'data-button', 'add-my-file')).not.toBeNull();
        expect(byAttr(m.container, 'data-button', 'my-address')).not.toBeNull();
    });

    it('StateIcon: named when labelled; busy spins', async () => {
        const m = await mount(<P.StateIcon state="bad" label="Failed" />);
        const s = byAttr(m.container, 'data-state', 'bad')!;
        expect(s.getAttribute('role')).toBe('img');
        expect(s.getAttribute('aria-label')).toBe('Failed');
        const b = await mount(<P.StateIcon state="busy" />);
        expect(byAttr(b.container, 'class', 'daal-spin')).not.toBeNull();
        expect(byAttr(b.container, 'data-state', 'busy')!.getAttribute('aria-hidden')).toBe('true');
    });

    it('ProgressRing: percent when known, spinning when not', async () => {
        const m = await mount(<P.ProgressRing value={0.42}>42%</P.ProgressRing>);
        const r = byAttr(m.container, 'role', 'progressbar')!;
        expect(r.getAttribute('aria-valuenow')).toBe('42');
        expect(m.container.textContent).toBe('42%');
        const i = await mount(<P.ProgressRing />);
        expect(byAttr(i.container, 'role', 'progressbar')!.getAttribute('aria-valuenow')).toBeNull();
        expect(byAttr(i.container, 'class', 'daal-spin')).not.toBeNull();
    });

    it('Avatar: the first letter, Persian too', () => {
        expect(P.firstGrapheme('maman')).toBe('M');
        expect(P.firstGrapheme('  مامان')).toBe('م');
        expect(P.firstGrapheme('')).toBe('');
        expect(P.firstGrapheme('👩‍👧 family')).toBe('👩‍👧');
    });
});

describe('Toast', () => {
    it('a status line with a close button; it hides itself', async () => {
        const gone = vi.fn();
        const m = await mount(
            <P.Toast tone="good" onDismiss={gone} autoHideMs={20}>
                Copied
            </P.Toast>,
        );
        const t = byAttr(m.container, 'role', 'status')!;
        expect(t.textContent).toContain('Copied');
        expect(t.style.position).toBe('fixed');
        expect(byAttr(t, 'data-button', 'toast-close')!.getAttribute('aria-label')).toBe('Close');
        await new Promise((r) => setTimeout(r, 40));
        expect(gone).toHaveBeenCalled();
    });

    it('one at a time: a newer toast sends the older one away', async () => {
        const first = vi.fn();
        const a = await mount(
            <P.Toast onDismiss={first} autoHideMs={0}>
                One
            </P.Toast>,
        );
        expect(first).not.toHaveBeenCalled();
        await mount(
            <P.Toast onDismiss={() => {}} autoHideMs={0}>
                Two
            </P.Toast>,
        );
        expect(first).toHaveBeenCalledTimes(1);
        await a.unmount();
    });

    it('useToast: show replaces, close hides', async () => {
        let api: ReturnType<typeof P.useToast> | null = null;
        function Host() {
            const toast = P.useToast();
            api = toast;
            return <div>{toast.node}</div>;
        }
        const m = await mount(<Host />);
        await React.act(async () => api!.show('good', 'Copied', 0));
        expect(m.container.textContent).toContain('Copied');
        await React.act(async () => api!.show('bad', "Couldn't copy the report.", 0));
        expect(m.container.textContent).not.toContain('Copied');
        expect(byAttr(m.container, 'data-toast', 'bad')).not.toBeNull();
        await click(byAttr(m.container, 'data-button', 'toast-close'));
        expect(byAttr(m.container, 'role', 'status')).toBeNull();
    });
});

describe('Segmented, TabBar, SidebarFull, MetricTile', () => {
    it('Segmented: sentence case, 44 px options; iconOnly keeps the names', async () => {
        const fn = vi.fn();
        const m = await mount(
            <P.Segmented
                value="auto"
                iconOnly
                onChange={fn}
                items={[
                    { value: 'auto', label: 'Match phone', icon: 'auto' },
                    { value: 'light', label: 'Light', icon: 'sun' },
                    { value: 'dark', label: 'Dark', icon: 'moon' },
                ]}
            />,
        );
        const opts = buttons(m.container);
        expect(opts.map((b) => b.getAttribute('aria-label'))).toEqual(['Match phone', 'Light', 'Dark']);
        expect(m.container.textContent).toBe('');
        for (const b of opts) {
            expect(b.style.minHeight).toBe('44px');
            expect(b.style.textTransform).toBeUndefined();
            expect(b.style.fontFamily).toBe('var(--font-body)');
        }
        await click(opts[2]);
        expect(fn).toHaveBeenCalledWith('dark');
    });

    it('TabBar: body-font labels, 56 px cells, a gold bar on the active one', async () => {
        const m = await mount(
            <P.TabBar
                active="network"
                onChange={() => {}}
                items={[
                    { id: 'connection', label: 'Connection', icon: P.SECTION_ICONS.connection },
                    { id: 'network', label: 'Files', icon: P.SECTION_ICONS.network },
                ]}
            />,
        );
        const tabs = buttons(m.container);
        for (const b of tabs) {
            expect(b.style.fontFamily).toBe('var(--font-body)');
            expect(b.style.textTransform).toBeUndefined();
            expect(b.style.minBlockSize).toBe('56px');
        }
        expect(byAttr(m.container, 'data-button', 'tab-network')!.getAttribute('aria-selected')).toBe('true');
        expect(styled(m.container, 'blockSize', '3px').length).toBe(1);
    });

    it('SidebarFull: no label row for an empty label, disabled items hidden, shortcuts only on hover', async () => {
        const m = await mount(
            <P.SidebarFull
                active="connection"
                onChange={() => {}}
                sections={[
                    {
                        label: '',
                        items: [
                            { id: 'connection', label: 'Connection', shortcut: 'Ctrl+1' },
                            { id: 'publisher', label: 'Publisher', disabled: true, badge: 'OFF' },
                        ],
                    },
                ]}
            />,
        );
        expect(m.container.textContent).not.toContain('Publisher');
        expect(m.container.textContent).not.toContain('OFF');
        expect(byAttr(m.container, 'data-button', 'nav-connection')).not.toBeNull();
        expect(byAttr(m.container, 'class', 'daal-nav-shortcut')!.textContent).toBe('Ctrl+1');
        // Only the item row: no label row above it.
        expect(all(m.container, (n) => n.nodeName === 'DIV' && n.textContent === '')).toHaveLength(1);
    });

    it('shortcutLabel: ⌘ on a Mac, Ctrl elsewhere', () => {
        const nav = (globalThis as { navigator?: unknown }).navigator;
        const set = (v: unknown) => Object.defineProperty(globalThis, 'navigator', { value: v, configurable: true, writable: true });
        try {
            set({ platform: 'MacIntel', userAgent: 'Mozilla/5.0 (Macintosh)' });
            expect(P.shortcutLabel(2)).toBe('⌘2');
            set({ platform: 'Linux x86_64', userAgent: 'Mozilla/5.0 (X11; Linux)' });
            expect(P.shortcutLabel(2)).toBe('Ctrl+2');
        } finally {
            set(nav);
        }
    });

    it('MetricTile: the value stays on one line and never breaks inside a word', async () => {
        const m = await mount(<P.MetricTile label="Overall" value="Degraded" />);
        const v = all(m.container, (n) => n.nodeType === 1 && n.textContent === 'Degraded' && n.style.whiteSpace === 'nowrap')[0];
        expect(v).toBeTruthy();
        expect(v.style.textOverflow).toBe('ellipsis');
        expect(v.style.overflowWrap).toBeUndefined();
    });
});

describe('primitives source rules', () => {
    const files = import.meta.glob(['./*.tsx', '!./*.test.tsx'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

    it('no uppercase labels and no letter-spacing', () => {
        const bad: string[] = [];
        for (const [path, src] of Object.entries(files)) {
            src.split('\n').forEach((line, i) => {
                if (/textTransform:\s*'uppercase'/.test(line) || /letterSpacing:\s*'0\.\d/.test(line)) bad.push(`${path}:${i + 1}`);
            });
        }
        expect(bad).toEqual([]);
    });

    it('logical properties only: no left/right margins, paddings or text alignment', () => {
        const bad: string[] = [];
        for (const [path, src] of Object.entries(files)) {
            src.split('\n').forEach((line, i) => {
                if (/\b(marginLeft|marginRight|paddingLeft|paddingRight|borderLeft|borderRight)\b|\b(left|right):\s|textAlign:\s*'(left|right)'/.test(line)) {
                    bad.push(`${path}:${i + 1}`);
                }
            });
        }
        expect(bad).toEqual([]);
    });

    it('every primitive is exported from the barrel', () => {
        for (const name of [
            'Badge',
            'OverflowMenu',
            'MenuSheet',
            'Disclosure',
            'EmptyState',
            'StateIcon',
            'PageHeader',
            'Toast',
            'ProgressRing',
            'Avatar',
            'Icon',
            'shortcutLabel',
        ]) {
            expect(typeof (P as Record<string, unknown>)[name], name).toBe('function');
        }
    });
});
