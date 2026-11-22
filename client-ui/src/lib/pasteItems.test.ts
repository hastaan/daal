import { describe, expect, it } from 'vitest';
import { MAX_ITEMS, addable, classifyItem, pasteItems, refusalCode, routeLinkCount, trimEdges } from './pasteItems';

const kinds = (s: string) => pasteItems(s).items.map((i) => (i.kind === 'route' ? `route:${i.route}` : i.kind));
const texts = (s: string) => pasteItems(s).items.map((i) => i.text);

const VLESS = 'vless://11111111-2222-3333-4444-555555555555@a.example.org:443?security=reality&pbk=abc&sni=www.example.com&fp=chrome#A';
const VLESS2 = 'vless://11111111-2222-3333-4444-555555555555@b.example.org:443?security=tls&type=ws&path=%2Fws#B';
const TROJAN = 'trojan://secret@c.example.org:443?sni=c.example.org&alpn=h2,http/1.1#C';
const HY2 = 'hy2://pass@d.example.org:443,8443-8450/?sni=d.example.org&obfs=salamander#D';
const SS = 'ss://YWVzLTI1Ni1nY206cGFzcw==@e.example.org:8388#E';
const VMESS = 'vmess://eyJhZGQiOiJmLmV4YW1wbGUub3JnIiwicG9ydCI6NDQzfQ==';
const BUNDLE = 'UEsDBBQAAAAIAA' + 'Kx3mQ9vT2bN8pLr4Wc7Zy1Hd6Fg0Js5Ae9Ui2Ok8Tn3Bv7Mq4Xw1Cs6Dp0Ga5Hf9Ej2Il8Ro'.repeat(9);
const SEALED = 'RFNCUAAB' + 'Kx3mQ9vT2bN8pLr4Wc7Zy1Hd6Fg0Js5Ae9Ui2Ok8Tn3Bv7Mq4Xw1Cs6Dp0Ga5Hf9Ej2Il8Ro'.repeat(9);
const CONF = `[Interface]
PrivateKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGU=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = g.example.org:51820`;

describe('splitting', () => {
    it('one link is one item', () => {
        expect(kinds(VLESS)).toEqual(['route:vless']);
        expect(texts(VLESS)).toEqual([VLESS]);
    });

    it('new lines, spaces and tabs always separate', () => {
        expect(kinds(`${VLESS}\n${TROJAN}`)).toEqual(['route:vless', 'route:trojan']);
        expect(kinds(`${VLESS} ${TROJAN}\t${SS}`)).toEqual(['route:vless', 'route:trojan', 'route:shadowsocks']);
        expect(kinds(`${VLESS}\r\n\r\n${VMESS}`)).toEqual(['route:vless', 'route:vmess']);
        // A no-break space from a chat app too.
        expect(kinds(`${VLESS} ${VLESS2}`)).toEqual(['route:vless', 'route:vless']);
    });

    it('a comma or semicolon separates only when a known scheme follows', () => {
        expect(texts(`${VLESS},${TROJAN}`)).toEqual([VLESS, TROJAN]);
        expect(texts(`${VLESS};${SS}`)).toEqual([VLESS, SS]);
        expect(kinds(`${VLESS},https://sub.example.org/x`)).toEqual(['route:vless', 'web']);
        expect(kinds(`${VLESS},tg://proxy?server=p.example.org&port=443&secret=ee00`)).toEqual(['route:vless', 'messenger']);
        expect(kinds(`${VLESS},https://t.me/proxy?server=p.example.org&port=443&secret=dd00`)).toEqual(['route:vless', 'messenger']);
        expect(kinds(`${VLESS},hysteria2://p@h.example.org:443`)).toEqual(['route:vless', 'route:hysteria2']);
        expect(kinds(`${VLESS},wireguard://k@w.example.org:51820`)).toEqual(['route:vless', 'route:wireguard']);
    });

    it('never splits inside a link: port lists and ALPN lists keep their commas', () => {
        expect(texts(HY2)).toEqual([HY2]);
        expect(texts(TROJAN)).toEqual([TROJAN]);
        expect(texts(`${HY2},${TROJAN}`)).toEqual([HY2, TROJAN]);
        const alpn = 'vless://u@h.example.org:443?security=tls&alpn=h2,http/1.1&sni=h.example.org#X';
        expect(texts(alpn)).toEqual([alpn]);
        expect(texts('hysteria2://p@h.example.org:20000-30000,443/?mport=20000-30000,443')).toEqual([
            'hysteria2://p@h.example.org:20000-30000,443/?mport=20000-30000,443',
        ]);
    });

    it('a comma before a Daal file marker separates the file from a link', () => {
        const items = pasteItems(`${VLESS},${BUNDLE}`).items;
        expect(items.map((i) => i.kind)).toEqual(['route', 'file']);
        expect(items[1].text).toBe(BUNDLE);
    });

    it('trims quotes and punctuation around an item', () => {
        expect(texts(`"${VLESS}"`)).toEqual([VLESS]);
        expect(texts(`«${VLESS}»`)).toEqual([VLESS]);
        expect(texts(`(${VLESS}).`)).toEqual([VLESS]);
        expect(texts(`'${SS}',`)).toEqual([SS]);
        expect(texts(`<${VLESS}>`)).toEqual([VLESS]);
        // base64 padding is not punctuation
        expect(texts(VMESS)).toEqual([VMESS]);
    });

    it('keeps a closing bracket that belongs to the link', () => {
        expect(trimEdges('vless://u@h:443#Server(2)')).toBe('vless://u@h:443#Server(2)');
        expect(trimEdges('(vless://u@h:443#Server(2))')).toBe('vless://u@h:443#Server(2)');
        expect(trimEdges('(vless://u@h:443)')).toBe('vless://u@h:443');
    });

    it('drops exact duplicates, first kept', () => {
        expect(texts(`${VLESS}\n${VLESS}\n${TROJAN}\n"${VLESS}"`)).toEqual([VLESS, TROJAN]);
    });

    it('strips invisible marks a Persian chat puts into Latin text', () => {
        expect(texts(`‏${VLESS}‎`)).toEqual([VLESS]);
        expect(texts(`‫${TROJAN}‬`)).toEqual([TROJAN]);
    });

    it('a channel post: links among words, one muted line per run of words on a line', () => {
        const post = `🔥 New servers for today 🔥\n${VLESS}\n${TROJAN}\nJoin our channel @example`;
        const items = pasteItems(post).items;
        expect(items.map((i) => i.kind)).toEqual(['unknown', 'route', 'route', 'unknown']);
        expect(items[0].text).toBe('🔥 New servers for today 🔥');
        expect(items[3].text).toBe('Join our channel @example');
    });

    it('empty or blank text is no items', () => {
        expect(pasteItems('').items).toEqual([]);
        expect(pasteItems('   \n\t ').items).toEqual([]);
    });

    it('reads at most MAX_ITEMS and says so', () => {
        const many = Array.from({ length: MAX_ITEMS + 5 }, (_, i) => `vless://u@h${i}.example.org:443`).join('\n');
        const r = pasteItems(many);
        expect(r.items).toHaveLength(MAX_ITEMS);
        expect(r.truncated).toBe(true);
        expect(pasteItems(VLESS).truncated).toBe(false);
    });
});

describe('a Daal file is one item', () => {
    it('a hard-wrapped blob spanning lines', () => {
        const wrapped = BUNDLE.match(/.{1,40}/g)!.join('\n');
        const items = pasteItems(wrapped).items;
        expect(items).toHaveLength(1);
        expect(items[0]).toMatchObject({ kind: 'file', container: 'sbp' });
    });

    it('a blob with chatter around it: the chatter goes with it', () => {
        const items = pasteItems(`Hi, this is your file:\n${BUNDLE}\nlove, Maman`).items;
        expect(items).toHaveLength(1);
        expect(items[0].kind).toBe('file');
        expect(items[0].text).toContain(BUNDLE);
    });

    it('a sealed file is told apart', () => {
        expect(pasteItems(SEALED).items[0]).toMatchObject({ kind: 'file', container: 'sbpx' });
    });

    it('a file and links in one paste are separate items', () => {
        expect(kinds(`${BUNDLE}\n${VLESS}\n${TROJAN}`)).toEqual(['file', 'route:vless', 'route:trojan']);
    });
});

describe('a WireGuard .conf block is one item', () => {
    it('the whole block, blank line and all', () => {
        const items = pasteItems(CONF).items;
        expect(items).toHaveLength(1);
        expect(items[0]).toMatchObject({ kind: 'route', route: 'wireguard' });
        expect(items[0].text).toContain('[Peer]');
        expect(items[0].text).toContain('Endpoint = g.example.org:51820');
    });

    it('a block followed by links: the links are their own items', () => {
        expect(kinds(`${CONF}\n${VLESS}\n\n${TROJAN}`)).toEqual(['route:wireguard', 'route:vless', 'route:trojan']);
    });

    it('two blocks are two items', () => {
        expect(kinds(`${CONF}\n\n${CONF.replace('g.example.org', 'h.example.org')}`)).toEqual(['route:wireguard', 'route:wireguard']);
    });

    it('a header with no key is not a configuration', () => {
        expect(kinds('[Interface]\nhello there')).toEqual(['unknown', 'unknown']);
    });
});

describe('what each item is', () => {
    it('route kinds by scheme, case-insensitive', () => {
        expect(classifyItem(VLESS)).toMatchObject({ kind: 'route', route: 'vless' });
        expect(classifyItem('VLESS://u@h:443')).toMatchObject({ kind: 'route', route: 'vless' });
        expect(classifyItem(VMESS)).toMatchObject({ kind: 'route', route: 'vmess' });
        expect(classifyItem(TROJAN)).toMatchObject({ kind: 'route', route: 'trojan' });
        expect(classifyItem(SS)).toMatchObject({ kind: 'route', route: 'shadowsocks' });
        expect(classifyItem(HY2)).toMatchObject({ kind: 'route', route: 'hysteria2' });
        expect(classifyItem('hysteria2://p@h:443')).toMatchObject({ kind: 'route', route: 'hysteria2' });
        expect(classifyItem('tuic://u:p@h:443')).toMatchObject({ kind: 'route', route: 'tuic' });
        expect(classifyItem('wg://k@h:51820')).toMatchObject({ kind: 'route', route: 'wireguard' });
    });

    it('a scheme with nothing after it is not a link', () => {
        expect(classifyItem('vless://').kind).toBe('unknown');
    });

    it('a web address', () => {
        expect(classifyItem('https://sub.example.org/api/v1/client/abc').kind).toBe('web');
        expect(classifyItem('http://sub.example.org/x').kind).toBe('web');
        expect(classifyItem('https://localhost').kind).toBe('unknown');
    });

    it('Telegram proxies, every documented form, rebuilt as https from checked parts', () => {
        const a = classifyItem('tg://proxy?server=p.example.org&port=443&secret=ee1234abcd');
        expect(a).toMatchObject({ kind: 'messenger', app: 'telegram', open: 'https://t.me/proxy?server=p.example.org&port=443&secret=ee1234abcd' });
        const b = classifyItem('https://t.me/proxy?server=1.2.3.4&port=8443&secret=dd00ff');
        expect(b).toMatchObject({ kind: 'messenger', app: 'telegram', open: 'https://t.me/proxy?server=1.2.3.4&port=8443&secret=dd00ff' });
        const c = classifyItem('t.me/socks?server=s.example.org&port=1080&user=me&pass=pw');
        expect(c).toMatchObject({ kind: 'messenger', open: 'https://t.me/socks?server=s.example.org&port=1080&user=me&pass=pw' });
        const d = classifyItem('tg://socks?server=s.example.org&port=1080');
        expect(d).toMatchObject({ kind: 'messenger', open: 'https://t.me/socks?server=s.example.org&port=1080' });
        expect(classifyItem('https://telegram.me/proxy?server=p.example.org&port=443&secret=00').kind).toBe('messenger');
    });

    it('a broken Telegram proxy, or one carrying anything extra, is not handed over as it is', () => {
        expect(classifyItem('tg://proxy?server=p.example.org&port=99999&secret=ee').kind).toBe('unknown');
        expect(classifyItem('tg://proxy?server=bad host&port=443&secret=ee').kind).toBe('unknown');
        expect(classifyItem('tg://proxy?server=p.example.org&port=443&secret=e"e').kind).toBe('unknown');
        expect(classifyItem('tg://proxy?port=443&secret=ee').kind).toBe('unknown');
        // Extra parameters do not ride along.
        const x = classifyItem('tg://proxy?server=p.example.org&port=443&secret=ee&evil=%26calc');
        expect(x.kind === 'messenger' && x.open).toBe('https://t.me/proxy?server=p.example.org&port=443&secret=ee');
    });

    it('other Telegram links are not web addresses to check for updates', () => {
        expect(classifyItem('https://t.me/somechannel').kind).toBe('unknown');
        expect(classifyItem('tg://resolve?domain=x').kind).toBe('unknown');
    });

    it('Signal proxy links', () => {
        expect(classifyItem('https://signal.tube/#proxy.example.org')).toMatchObject({
            kind: 'messenger',
            app: 'signal',
            open: 'https://signal.tube/#proxy.example.org',
        });
        expect(classifyItem('sgnl://signal.tube/#proxy.example.org')).toMatchObject({ kind: 'messenger', app: 'signal' });
        expect(classifyItem('https://signal.tube/#not a host').kind).toBe('unknown');
        expect(classifyItem('https://signal.me/#p/+1555').kind).toBe('unknown');
    });

    it('anything else is not understood', () => {
        expect(classifyItem('hello').kind).toBe('unknown');
        expect(classifyItem('socks5://1.2.3.4:1080').kind).toBe('unknown');
    });
});

describe('a mixed paste never fails as a whole', () => {
    it('every item gets a row', () => {
        const mixed = [
            VLESS,
            'garbage words here',
            'tg://proxy?server=p.example.org&port=443&secret=ee00',
            'https://signal.tube/#s.example.org',
            HY2,
            'https://sub.example.org/s',
        ].join('\n');
        expect(kinds(mixed)).toEqual(['route:vless', 'unknown', 'messenger', 'messenger', 'route:hysteria2', 'web']);
        const items = pasteItems(mixed).items;
        expect(routeLinkCount(items)).toBe(2);
        expect(addable(items).map((i) => i.kind)).toEqual(['route', 'route']);
    });
});

describe('refusal codes', () => {
    it('reads the stable token out of an import error', () => {
        expect(refusalCode('vless: type=xhttp: uri: transport_unsupported')).toBe('transport_unsupported');
        expect(refusalCode('engine call returned -1: vless: uri: plaintext_refused')).toBe('plaintext_refused');
        expect(refusalCode('hy2: insecure: uri: insecure_refused')).toBe('insecure_refused');
        expect(refusalCode('vless: missing uuid: uri: link_malformed')).toBe('link_malformed');
        expect(refusalCode('uri: no matching parser')).toBe('no_match');
        expect(refusalCode('uri: something_new')).toBe('other');
        expect(refusalCode('database is locked')).toBe('other');
    });
});

describe('what the engine can import', () => {
    it('only the kinds URIImport takes are importable and counted', () => {
        expect(classifyItem(VLESS)).toMatchObject({ importable: true });
        expect(classifyItem('tuic://u:p@h:443')).toMatchObject({ importable: true });
        for (const l of ['wg://k@h:51820', 'wireguard://k@h:51820', 'amneziawg://k@h:1', 'hysteria://p@h:1', 'naive+https://u:p@h:443', 'brook://x', 'snowflake://x']) {
            expect(classifyItem(l), l).toMatchObject({ kind: 'route', importable: false });
        }
        // A wg:// link has no parser in the engine; a WireGuard CONF does,
        // and is kept as a route used only when picked: added, never
        // counted for the bulk check.
        const items = pasteItems(`${VLESS}\nwg://k@h:51820\n${CONF}`).items;
        expect(items).toHaveLength(3);
        expect(routeLinkCount(items)).toBe(1);
        expect(addable(items)).toHaveLength(2);
        expect(items.find((i) => i.kind === 'route' && i.text.startsWith('['))).toMatchObject({ importable: true, manualOnly: true });
    });
});

describe('words that are not links keep their half-spaces', () => {
    it('a Persian sentence is shown as written (ZWNJ kept), a link is cleaned', () => {
        const items = pasteItems(`این لینک‌ها کار نمی‌شود\n‏${VLESS}‎`).items;
        expect(items[0]).toMatchObject({ kind: 'unknown' });
        expect(items[0].text).toContain('نمی‌شود');
        expect(items[0].text).toContain('لینک‌ها');
        expect(items[1]).toMatchObject({ kind: 'route', text: VLESS });
    });

    it('bidi marks around loose words are still removed', () => {
        const items = pasteItems('‏سلام‏').items;
        expect(items[0].text).toBe('سلام');
    });
});
