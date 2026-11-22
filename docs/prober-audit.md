# Prober's-eye audit (W1-E)

What a censor learns about a Daal relay and its users without any secret: the
ClientHello a phone sends, and what a stranger's full handshake to each relay port
returns. Run 2026-11-22 in worldbox on a relay built from this tree.

```
cd test-rigs/worldbox
WB_GO_MOD=-mod=readonly ./run.sh --mgmt=tree --ops prober clean vless-reality websocket-tls
```

The check is op `prober` (`test-rigs/worldbox/driver/ops_prober.go`, JA4 and the
stranger's handshake in `prober.go`). The full matrix runs it as world `clean.prober`.
Evidence: `results.jsonl` (rows `op:prober`) and `prober-stranger.json` in the run
directory. Run `20261122-172030-616716`: 91 checks, all as expected, 26 s.

**How it looks.**
- *Hello.* The flow tap on the censor's client-side interface keeps the first data
  packets of every flow. The op joins them, strips the record layer, parses the
  ClientHello and computes JA4 as FoxIO's spec defines it
  (`technical_details/JA4.md` in github.com/FoxIO-LLC/ja4). This is what a DPI box on
  the path sees.
- *Stranger.* `wb tlsface` runs from the phone's network namespace, so it sits where a
  prober inside the country sits. It tries every TCP port a stranger could guess: each
  served family's port, the mgmt port, the provisioning health port (9876), 22 and 80.
  On each open port it does four things:
  - waits 1.5 s for bytes sent unasked (a banner);
  - sends a plain-text `GET /`;
  - does three full TLS handshakes: no SNI, the relay's cover name, and an unrelated
    name (`www.example.org`), each offering ALPN `h2,http/1.1`;
  - sends `GET /` over each TLS session that did not choose h2.

  It records the certificate subject, issuer, SANs and validity, the ALPN, and every
  answer. Then it searches all of it for Daal-specific strings (`daal`, `relay-mgmt`,
  `relay-health`). That search is the one judged check, `stranger.<port>`.

## 1. The ClientHello and its JA4

| Route | JA4 | SNI | ALPN offered | Hello | Groups |
|---|---|---|---|---|---|
| vless-reality (443) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | cover name | h2, http/1.1 | 563 B | x25519, P-256, P-384 |
| websocket-tls (8445) | `t13i1515h1_8daaf6152771_d8a2da3f94cd` | **none** | http/1.1 only | 1693 B | X25519MLKEM768, x25519, P-256, P-384 |

Both routes use sing-box 1.13.12 with uTLS `chrome` (metacubex/utls 1.8.4). Both hellos
carry ECH GREASE (`fe0d`) and the new ALPS codepoint (`44cd`); neither carries
`pre_shared_key`.

**Reference.** Chrome over TCP: `t13d1517h2_8daaf6152771_cb7bf5808d99`. Source: the
examples table of the FoxIO JA4 README (github.com/FoxIO-LLC/ja4, `README.md`, read
2026-11-22). The source names neither the Chrome version nor the platform.
**Chrome on Android: unverified.** No labelled Android capture was found, and the FoxIO
JA4 database API did not answer (404 at `ja4db.foxio.io/api/read/`). A secondary search
result attributes our section c (`d8a2da3f94cd`) to "several recent Chrome versions".
That was not confirmed either.

**Comparison.**
- **Section b (cipher suites) matches Chrome on both routes.**
- **Section a**:
  - REALITY has one extension fewer than the reference (16 against 17);
  - websocket-tls has no SNI (`i`) and offers `http/1.1` only (`h1`).
- **Section c (extensions and signature algorithms)** differs from the reference on
  both routes. It is the same on our two routes, so it is the uTLS profile. The
  reference may be an older Chrome, or a hello that resumes a session. That is not
  resolved.

**Findings.**

- **H-1. The REALITY hello claims a current Chrome but has no post-quantum key share.**
  Its extensions (ECH GREASE, ALPS `44cd`) are those of a Chrome that sends
  X25519MLKEM768 by default. The websocket-tls hello, from the same uTLS profile, does
  send it.
  - Cause: sing-box's REALITY client strips X25519MLKEM768 from `supported_groups` and
    `key_share` (sing-box 1.13.12, `common/tls/reality_client.go`, around line 136),
    because REALITY's auth rides the x25519 share.
  - What a prober sees: JA4 hides this, because it does not hash groups. A box that
    reads `key_share`, or only the hello's length (563 B against about 1.7 KB), sees a
    Chrome that does not exist.
  - Applies to every REALITY route Daal mints.
- **H-2. The pinned-TLS tiers send no SNI, as `publisher/deploy/relaypack/client_outbound.go`
  records ("KNOWN, UNFIXED").** This is now seen on the wire: `t13i…`. The pack sets
  `server_name` to the relay's IP, and uTLS drops an IP literal from SNI. The code note
  says the same holds for naive and hysteria2. On websocket-tls the offer is also
  `http/1.1` only. A browser opening WebSocket offers `h2,http/1.1`.

## 2. What a stranger's handshake returns

| Port (what) | Open | Without TLS | TLS (any of the three names) | Daal string |
|---|---|---|---|---|
| 22 (ssh) | closed | — | — | — |
| 80 | closed | — | — | — |
| 443 (vless-reality) | yes | REALITY passes it to the cover host; the lab's cover answers `400 Client sent an HTTP request to an HTTPS server.` | TLS 1.3, h2. The certificate is **the cover host's own**, for whatever name was sent; with no SNI, the cover's default (lab: `CN=cover.invalid`, issued by the lab CA) | none |
| 8444 (naive) | yes | no answer | TLS 1.3, h2, **self-signed** `CN=<cover name>`, SAN `<cover name>, <relay IP>`, 90 days, the **same certificate for all three names** | none |
| 8445 (websocket-tls) | yes | no answer | TLS 1.3, **no ALPN**, the same self-signed certificate as 8444; `GET /` gets `404 Not Found`, empty body, only `Date`, `Content-Length` and `Connection` headers | none |
| 9876 (health) | closed | — | — | — |
| mgmt (random high port) | closed | — | — | — |

No port sent a banner. UDP ports (hysteria2 on 443/udp) were not probed: the stranger
has no QUIC stack. That is a gap. The relay's code says 443/udp serves the same
certificate as 8444.

**Lab caveat on 443.** In worldbox the cover address is a fake that mints a certificate
for any name. On the internet, REALITY passes a stranger's hello to the real cover
site, so the stranger gets whatever that site answers for the name sent: its real
certificate for its own name, and its own default for no name or a foreign one.

**Findings.**

- **S-0. Nothing a stranger can reach names Daal.** No `daal`, `relay-mgmt` or
  `relay-health` in any certificate, banner or answer. The mgmt, health and SSH ports
  are closed to a stranger. The neutral certificate subject works (cloud-init
  `v2.yaml.tmpl`, "THE SUBJECT NAMES NOTHING…"). Relays provisioned before that change
  keep the legacy subject `CN=daal-relay` unless `daal-relay-mgmt` re-issued it
  (`cmd/daal-relay-mgmt/tlscert.go`). This audit ran on the tree relay only and does
  not cover them.
- **S-1. One address shows the cover name twice, with two different certificates.**
  - On 443, REALITY passes the handshake through, so the stranger gets the cover site's
    real, CA-signed certificate.
  - On 8444, 8445 (and, by the code, 443/udp), the same address serves a self-signed
    certificate whose CN and first SAN are that same cover name, with the relay's IP
    beside it.

  This is the strongest correlate found. A scanner that handshakes on two ports sees a
  hostname whose real certificate it can fetch elsewhere, paired with a snakeoil copy.
  That shape is the same on every Daal relay, whatever the cover name.
- **S-2. The websocket-tls port answers like a bare proxy.** It negotiates no ALPN and
  returns an empty-body 404 with three headers to `GET /`. An ordinary HTTPS server
  offers h2 and sends a page or at least a `Server` header. This is weaker than S-1
  but easy to fingerprint.

## 3. Recommendation

In order of what it buys:

1. **S-1: stop the 8444/8445/443-udp certificate naming the cover host.** Give it a
   per-relay name unrelated to the cover (from the same pool, or a plausible hostname
   for the provider's address), and do not put the IP in the SAN. Nothing verifies the
   name except naive, which matches by SAN. The constraint is naive:
   - its pack's trusted root is found by this name, so a change ends naive packs minted
     before it (`tlscert.go`, "THE PRICE");
   - so it needs the same design decision as item 2, and should ship with it.
2. **H-2: give the pinned-TLS tiers a real SNI** (the same per-relay name), as the note
   in `client_outbound.go` already plans. Have websocket-tls offer `h2,http/1.1`, like
   a browser.
   - Measure the hello again with this op after the change. It is the "two-relay
     on-wire check" that note asks for, minus the second relay.
3. **H-1: REALITY without ML-KEM.** Not fixable in Daal's own code. Options:
   - a sing-box release whose REALITY client keeps X25519MLKEM768 (whether one exists
     is **unverified**);
   - or a uTLS profile of a Chrome old enough to have no ML-KEM, *and* no `44cd`/ECH,
     so the hello is at least a Chrome that existed.

   Decide after a capture of a real Chrome on Android against the same cover host
   (needs a phone; not done here).
4. **S-2: make the WebSocket door answer `GET /` like a web server** (a small page, a
   normal header set, h2). Low effort, low value until 1 and 2 are done.
5. **Keep op `prober` in the full matrix.** It catches a Daal string coming back. Add
   a QUIC handshake to `tlsface` so 443/udp is covered. Run it once on the pinned
   release box to see what deployed relays show.

**Open: a real Chrome on Android.** The comparison in §1 uses a reference that does not
name its platform. One capture of Chrome on the spare phone, against a lab cover host,
would settle sections a and c.
