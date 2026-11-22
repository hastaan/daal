// miniDom — just enough of a DOM for react-dom/client to mount, update
// and dispatch clicks in vitest's node environment, for the few tests
// that must see a component react to the system Back (`popstate`).
//
// The UI package has no jsdom or testing library, and adding one is a
// dependency change outside this lane. This is not a browser: no
// layout, no CSS, no forms beyond `value`. Tests use it to mount, find
// by attribute or text, click, and fire `popstate` through the same
// back stack the app uses.

type Listener = { fn: (e: FakeEvent) => void; capture: boolean };

export class FakeEvent {
    type: string;
    bubbles: boolean;
    target: FakeNode | null = null;
    currentTarget: FakeNode | FakeWindow | null = null;
    defaultPrevented = false;
    timeStamp = Date.now();
    private stopped = false;
    constructor(type: string, init: { bubbles?: boolean } = {}) {
        this.type = type;
        this.bubbles = init.bubbles ?? true;
    }
    preventDefault() {
        this.defaultPrevented = true;
    }
    stopPropagation() {
        this.stopped = true;
    }
    get propagationStopped() {
        return this.stopped;
    }
}

class Listeners {
    private map = new Map<string, Listener[]>();
    addEventListener(type: string, fn: (e: FakeEvent) => void, opts?: boolean | { capture?: boolean }) {
        const capture = typeof opts === 'boolean' ? opts : opts?.capture === true;
        const l = this.map.get(type) ?? [];
        l.push({ fn, capture });
        this.map.set(type, l);
    }
    removeEventListener(type: string, fn: (e: FakeEvent) => void, opts?: boolean | { capture?: boolean }) {
        const capture = typeof opts === 'boolean' ? opts : opts?.capture === true;
        const l = this.map.get(type) ?? [];
        this.map.set(
            type,
            l.filter((x) => !(x.fn === fn && x.capture === capture)),
        );
    }
    fire(e: FakeEvent, capture: boolean, self: FakeNode | FakeWindow) {
        for (const l of [...(this.map.get(e.type) ?? [])]) {
            if (l.capture !== capture) continue;
            e.currentTarget = self;
            l.fn(e);
        }
    }
}

export class FakeNode extends Listeners {
    nodeType: number;
    nodeName: string;
    tagName: string;
    namespaceURI: string | null;
    parentNode: FakeNode | null = null;
    childNodes: FakeNode[] = [];
    attributes = new Map<string, string>();
    style: Record<string, string> & { setProperty: (k: string, v: string) => void; removeProperty: (k: string) => void };
    nodeValue: string | null = null;
    ownerDocument: FakeDocument | null;
    // Properties react-dom sets directly.
    [k: string]: unknown;

    constructor(nodeType: number, name: string, doc: FakeDocument | null, ns: string | null = 'http://www.w3.org/1999/xhtml') {
        super();
        this.nodeType = nodeType;
        this.nodeName = name.toUpperCase();
        this.tagName = this.nodeName;
        this.namespaceURI = ns;
        this.ownerDocument = doc;
        const style: Record<string, string> = {};
        this.style = Object.assign(style, {
            setProperty: (k: string, v: string) => {
                style[k] = v;
            },
            removeProperty: (k: string) => {
                delete style[k];
            },
        }) as FakeNode['style'];
    }

    /** A <select>'s options, as react-dom reads them to mark the chosen
     *  one (`node.options[i].value / .selected`). An option's `value`
     *  is its attribute, which is all react-dom writes. */
    get options(): FakeNode[] | undefined {
        if (this.nodeName !== 'SELECT') return undefined;
        const out: FakeNode[] = [];
        const walk = (n: FakeNode) => {
            for (const c of n.childNodes) {
                if (c.nodeName === 'OPTION') {
                    if (c.value === undefined) c.value = c.getAttribute('value') ?? '';
                    out.push(c);
                } else walk(c);
            }
        };
        walk(this);
        return out;
    }

    get firstChild(): FakeNode | null {
        return this.childNodes[0] ?? null;
    }
    get lastChild(): FakeNode | null {
        return this.childNodes[this.childNodes.length - 1] ?? null;
    }
    get nextSibling(): FakeNode | null {
        const p = this.parentNode;
        if (!p) return null;
        return p.childNodes[p.childNodes.indexOf(this) + 1] ?? null;
    }
    appendChild(c: FakeNode) {
        c.parentNode?.removeChild(c);
        c.parentNode = this;
        this.childNodes.push(c);
        return c;
    }
    insertBefore(c: FakeNode, before: FakeNode | null) {
        if (!before) return this.appendChild(c);
        c.parentNode?.removeChild(c);
        c.parentNode = this;
        this.childNodes.splice(this.childNodes.indexOf(before), 0, c);
        return c;
    }
    removeChild(c: FakeNode) {
        const i = this.childNodes.indexOf(c);
        if (i >= 0) this.childNodes.splice(i, 1);
        c.parentNode = null;
        return c;
    }
    setAttribute(k: string, v: string) {
        this.attributes.set(k, String(v));
    }
    setAttributeNS(_ns: string, k: string, v: string) {
        this.setAttribute(k, v);
    }
    getAttribute(k: string) {
        return this.attributes.has(k) ? this.attributes.get(k)! : null;
    }
    removeAttribute(k: string) {
        this.attributes.delete(k);
    }
    removeAttributeNS(_ns: string, k: string) {
        this.removeAttribute(k);
    }
    hasAttribute(k: string) {
        return this.attributes.has(k);
    }
    get textContent(): string {
        if (this.nodeType === 3 || this.nodeType === 8) return this.nodeValue ?? '';
        return this.childNodes.map((c) => c.textContent).join('');
    }
    set textContent(v: string) {
        for (const c of [...this.childNodes]) this.removeChild(c);
        if (v) this.appendChild(this.ownerDocument!.createTextNode(v));
    }
    focus() {}
    blur() {}
    get type(): string {
        return this.getAttribute('type') ?? (this.nodeName === 'INPUT' ? 'text' : '');
    }
    set type(v: string) {
        this.setAttribute('type', v);
    }
    getContext() {
        return null;
    }
    contains(n: FakeNode | null): boolean {
        for (let x = n; x; x = x.parentNode) if (x === this) return true;
        return false;
    }
    dispatchEvent(e: FakeEvent) {
        e.target = this;
        const path: FakeNode[] = [];
        for (let x: FakeNode | null = this; x; x = x.parentNode) path.push(x);
        for (const n of [...path].reverse()) {
            n.fire(e, true, n);
            if (e.propagationStopped) return !e.defaultPrevented;
        }
        for (const n of path) {
            n.fire(e, false, n);
            if (e.propagationStopped || !e.bubbles) break;
        }
        return !e.defaultPrevented;
    }
    click() {
        this.dispatchEvent(new FakeEvent('click'));
    }
}

export class FakeDocument extends FakeNode {
    // react-dom asks `'oninput' in document` once, at load, to pick its
    // change-event strategy.
    oninput = null;
    onchange = null;
    body: FakeNode;
    documentElement: FakeNode;
    constructor() {
        super(9, '#document', null, null);
        this.ownerDocument = null;
        this.documentElement = new FakeNode(1, 'html', this);
        this.body = new FakeNode(1, 'body', this);
        this.appendChild(this.documentElement);
        this.documentElement.appendChild(this.body);
    }
    get activeElement() {
        return this.body;
    }
    createElement(tag: string) {
        return new FakeNode(1, tag, this);
    }
    createElementNS(ns: string, tag: string) {
        return new FakeNode(1, tag, this, ns);
    }
    createTextNode(text: string) {
        const n = new FakeNode(3, '#text', this, null);
        n.nodeValue = text;
        return n;
    }
    createComment(text: string) {
        const n = new FakeNode(8, '#comment', this, null);
        n.nodeValue = text;
        return n;
    }
}

export class FakeHistory {
    depth = 0;
    appLeft = false;
    constructor(private win: FakeWindow) {}
    pushState() {
        this.depth += 1;
    }
    back() {
        if (this.depth === 0) {
            this.appLeft = true;
            return;
        }
        this.depth -= 1;
        // Browsers fire popstate asynchronously.
        setTimeout(() => this.win.fire(new FakeEvent('popstate', { bubbles: false }), false, this.win), 0);
    }
}

export class FakeWindow extends Listeners {
    document = new FakeDocument();
    history: FakeHistory;
    location = { href: 'app://index', search: '', hash: '' };
    innerWidth = 400;
    innerHeight = 800;
    devicePixelRatio = 1;
    HTMLIFrameElement = class {};
    event: unknown = undefined;
    navigator = { userAgent: 'miniDom' };
    constructor() {
        super();
        this.history = new FakeHistory(this);
    }
    matchMedia() {
        return { matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} };
    }
    setTimeout = setTimeout;
    clearTimeout = clearTimeout;
    setInterval = setInterval;
    clearInterval = clearInterval;
    fire(e: FakeEvent, capture: boolean, self: FakeNode | FakeWindow) {
        super.fire(e, capture, self);
    }
    /** WryActivity's back callback: goBack() while it can, else finish. */
    systemBack() {
        if (this.history.depth > 0) this.history.back();
        else this.history.appLeft = true;
    }
}

/** Install the fake as the global window/document. Call before the app's
 *  back stack is first used. */
export function installMiniDom(): FakeWindow {
    const win = new FakeWindow();
    const g = globalThis as unknown as Record<string, unknown>;
    g.window = win;
    g.document = win.document;
    g.HTMLIFrameElement = win.HTMLIFrameElement;
    g.IS_REACT_ACT_ENVIRONMENT = true;
    g.MutationObserver = class {
        observe() {}
        disconnect() {}
        takeRecords() {
            return [];
        }
    };
    return win;
}

export function all(root: FakeNode, pred: (n: FakeNode) => boolean): FakeNode[] {
    const out: FakeNode[] = [];
    const walk = (n: FakeNode) => {
        if (pred(n)) out.push(n);
        n.childNodes.forEach(walk);
    };
    walk(root);
    return out;
}

export function byAttr(root: FakeNode, k: string, v?: string): FakeNode | null {
    return all(root, (n) => n.nodeType === 1 && n.getAttribute(k) !== null && (v === undefined || n.getAttribute(k) === v))[0] ?? null;
}

export function byText(root: FakeNode, text: string, tag = 'BUTTON'): FakeNode | null {
    return all(root, (n) => n.nodeName === tag && n.textContent.includes(text))[0] ?? null;
}
