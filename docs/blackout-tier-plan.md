# Daal blackout tier — final plan (adviser, 2026-11-20)

Read-only. Nothing was built or run. This supersedes my draft of the same date. Where the engineers proved the draft wrong I say so inline, marked **CORRECTION**. The owner's premise was right and the earlier study was too pessimistic: for every regime except the 8–18 Jan 2026 total cut, the field evidence shows specific survivors, and in the latest data (net4people #676, 18 Oct 2026) a specific survivor is still standing. But three of the draft's load-bearing assumptions were false, and they change the build order.

**The three corrections that move the plan:**

1. **CORRECTION (Group B).** The draft called the CDN front "an existing design to finish." False. Only Cloudflare's *control plane* exists in the repo; there is **no working data path** — four independent defects each break it end to end (wrong origin port landing on REALITY, origin certs written but never read, a firewall "lock" that locks nothing, and no client outbound at all). P1 is a build, not a finish. And ECH, not derived hostnames, is what hides the name in-band — net4people #676 reports Cloudflare's `wss` survived the Oct-2026 regime **only with ECH**. That makes CDN+ECH the single path with current blackout-grade evidence, so it rises to the top of the tier despite its size.

2. **CORRECTION (Group C).** The draft's recovery story has a hole in today's code: a recipient whose relay IP is null-routed **while the app still shows "connected"** never learns the new address, because the tunnel guard refuses a direct fetch while a route is "active," auto-failover keeps the dead route active, and the backoff can push the next direct try six hours out. A new prerequisite, **C0 (recovery trigger for connected-but-dead)**, must land before any refresh carrier is worth building. Also: the "30–40 byte micro-hint," the "standby addresses already in the pack," the push/FCM carrier, and the "16-byte MAC under a pack secret" were all wrong (details in §3).

3. **CORRECTION (Group A & D).** The forkless injection point is real and *stronger* than the draft said — a Daal-registered custom outbound used as `detour` fragments the ClientHello **below** REALITY/uTLS, with no SNI gate and no sing-box fork. But the dependency is `metacubex/utls` (indirect), **not** refraction-networking/utls; the Google-front data carrier is trending **dead** inside Iran (#676: TCP cut after a few packets, "only ICMP passes reliably"), so it demotes to a *refresh* carrier; and the TTL-decoy family is mechanism-reachable but genuinely **unproven on the phones** — it can be wired and still be a no-op or a connection-killer on a given kernel/ISP.

---

## 1. What Daal can honestly promise

**During a protocol-whitelist / blacklist period** (the June-2025 and post-May-2026 class), Daal can promise a real, usable tunnel: the direct REALITY route with fragmentation/desync in front of the hello, falling back to a CDN-fronted relay with ECH when the direct IP is swept, with per-network path selection and failure-triggered rotation that recovers a burned IP in minutes once C0 lands. **During a NIN-only total blackout** (the 8–18 Jan 2026 class, and the "only ICMP passes" routes of #676), Daal can promise **nothing over the network** and must say so plainly — no data path survives an edge default-deny, and the honest UI state is "no way out right now," not a spinner. Between those poles, during an **allowlist regime with foreign IPs open-but-SNI-filtered** (the 26 Jan–25 May 2026 class), Daal can promise a *degraded, possibly text-only lifeline* — CDN+ECH where the censor keeps Cloudflare open, a Google-fronted or GitHub/DNS refresh channel to hand out fresh addresses, and a human-courier `.sbpx` as the final fallback — but it must be labelled as emergency capacity (slow, may stop, named carrier shown), never as plain "connected," because every survivor in the record was short-lived and per-ISP.

---

## 2. The blackout tier, ranked

Ranked by (empirical evidence of working when everything else was out) × (feasibility on non-root Android, in *this* codebase). Highest product first.

### T1 — CDN-fronted relay with ECH (the name-hider; best current evidence, large build)
- **What:** VLESS over WebSocket/httpupgrade to the publisher's Cloudflare zone, origin = relay, with ECH so the on-wire outer SNI is the shared `cloudflare-ech.com` and the real zone name is encrypted. Edge port 443, origin on a dedicated port via an Origin Rule.
- **Evidence:** Cloudflare/Akamai/GCP ranges are filtered by SNI, not wholesale-blocked, on most ISPs most of the time. **Net4people #676 (18 Oct 2026): Cloudflare `wss` dropped right after the TLS handshake — "points to SNI filtering" — and worked *only with ECH*.** This is the only path in the whole corpus with Nov-2026-adjacent evidence of surviving the current regime. Counter-evidence (keep honest): Irancell blocked *all* Cloudflare IPs on 16 Apr 2023; pooribitwise (Jun 2026, single user) reports CDN domains blocked within 24h and an *unused* root domain blocked; ECH free-zone availability is **UNKNOWN** (sources conflict).
- **CORRECTION vs draft:** this is **not** "finish `cdn_fronted`." The repo has only the control plane. Four defects must be fixed: (1) the proxied A record makes Cloudflare dial origin :443 = the REALITY inbound, and the WS inbound on :8445 is not a Cloudflare-proxied port — need a dedicated `ws-cdn-in` inbound and an **Origin Rule** port override (verified available on Free); (2) `/etc/daal/cdn/origin_ca.*` certs are written by cloud-init but no inbound reads them; (3) the Hetzner "lock" only *adds* permissions and the phone path never passes `--firewall-id`, so it locks nothing; (4) **no CDN client outbound exists** — the renderer still points `server` at the relay IP and pins its self-signed SPKI.
- **CORRECTION vs draft:** **ECH, not daily derived hostnames, hides the name.** Derived hostnames buy little — the zone's `*.zone` cert lands in CT logs the day the zone activates, and an unused root was blocked anyway. Keep derived subdomains only as cheap defence against exact-name rules. The outer SNI *cannot* be swapped for a whitelisted name — the ECHConfig is bound into the HPKE key derivation. So "whitelisted outer SNI + ECH" is impossible; the censor's only in-band answer is to block `cloudflare-ech.com` itself (as Russia did), which is one rule.
- **CORRECTION vs draft:** `fragment: true` alone is a **no-op** in sing-box 1.13.12 — the fragmenter wraps only when `record_fragment` is set. The renderer must set `record_fragment` (and it only splits when a real SNI is present, which the ECH outer provides).
- **Implementation path (verified):** work items B-1 (dedicated `ws-cdn-in` with Origin-CA client auth), B-2 (firewall port param + real firewall id), B-3 (`ProvisionFront`: SSL strict, Origin Rule port override, WebSockets on, ECH on, Origin CA for `zone`+`*.zone`, replace the buggy `apexOf` with `publicsuffix`), B-4 (CDN client outbound: edge IP as server, hostname SNI, WebPKI + shipped roots, Host header, ECH PEM, `record_fragment`), B-5 (publisher-side ECH fetch from abroad → `ECH CONFIGS` PEM into pack+freshness), B-6 (recipient edge-IP selector), B-7 (phone UI — the wizard bindings already exist, no component calls them). Keepalive needed (Cloudflare closes idle WS ~100s).
- **Size:** **L** overall (B-1/B-3/B-4/B-6/B-7 are M each; B-2/B-5 are S). Needs a fresh provision (cloud-init has no upgrade path).
- **Risks:** publisher domain + Cloudflare account = an identity link and a single point of failure (one account ban takes out every recipient); Cloudflare terminates TLS and sees the VLESS header. ECH may not be available on free zones.
- **Tested:** B-8 — a worldbox CDN edge node (TLS-terminating, enforces SNI==Host, optional ECH), with scenarios for edge-IP allowlist, SNI allowlist on open IPs, the 6-packet "grey" budget, and a `cloudflare-ech.com` block. **Caveat (Group A/B):** worldbox has no edge/packet-budget model today and censor-lab's live forger is stubbed — these scenarios are a build, not a toggle.
- **Publisher sets up:** a domain (paid card, or slow free eu.org), a Cloudflare account (email) + scoped API token pasted in-app, zone activation. Zones are consumables (rotate across several per account).

### T2 — ClientHello fragmentation / split / reorder (highest feasibility, forkless)
- **What:** a Daal `net.Conn` wrapper that splits the hello across TCP segments (optionally first segment TTL=1 for disorder), applied to every family including REALITY.
- **Evidence:** the DPI inspects only the first data packet(s) and historically did not reassemble (Bock 2020, IRBlock 2025); Lantern "proxyless" held ~40% in June 2025; named in the April-2026 working composition. Counter: pooribitwise says reassembly is now done on :443 and clean-SNI fragmented hellos are themselves classified. So on its own this is a *protocol-whitelist/blacklist-day* path; its blackout value is as the SNI-splitter in front of T1's ECH outer.
- **CORRECTION vs draft (the engineers made this stronger):** the draft said `tf.Conn` splits only at an SNI and REALITY is never wrapped, so splitting hides the fingerprint, not the name. True of the *stock* path — but a **Daal detour outbound splits on the raw TCP conn *below* uTLS**, with **no SNI gate and no fork**: `dialer.New` honours `Detour`, the detour conn sees the whole ClientHello as its first `Write`, and `outbound.Register`/`box.Context` are exported, so replacing the two `include.Context` call sites with a ~15-line helper registers a `daal-desync` outbound. Protect still applies (the detour's socket goes through `invokeProtect`). This is the smallest, soundest first step.
- **Implementation path (verified):** new `core/desync` package (a `net.Conn` + an `outbound.Register` ctor); call sites `side_singbox.go:173`, `engine_singbox.go:254`. `TCP_NODELAY` + `writeAndWaitAck` via `TCP_INFO`/`tcpi_unacked` compiles and runs under GOOS=android (source-verified; on-device run unproven). **One real risk the engineers flagged:** a post-quantum-sized REALITY hello may exceed one record, so the wrapper must handle a multi-`Write` hello, not assume a single first `Write`.
- **Size:** **M.**
- **Risks:** the fragmentation pattern is itself now a classifiable signature per pooribitwise; use it in the ladder, remembered per network, not as an unconditional default.
- **Tested:** worldbox already proves the *premise* — `censor_dpi.go` has a `Reassemble` toggle, and `sni-rst-stateless.json` carries `split-hello-slips-through`. **CORRECTION/gap (Group A):** that split is a *probe-harness* `countingConn`, **not** Daal's production dialer. The gap to close is a worldbox family/op that stands up the real `core/desync` outbound against `sni-rst-stateless` + a new "first-two-packets, no reassembly" scenario (S).
- **Publisher sets up:** nothing; strategy/offsets ride in the signed pack, overridable by refresh.

### T3 — Fake low-TTL decoy ClientHello (opportunistic; device-unproven)
- **What:** before the real hello, show the DPI a decoy ClientHello carrying a whitelisted SNI with a TTL low enough to die before the server. ByeDPI's non-root trick.
- **Evidence:** worked ~4 days in mid-April 2026 across both variants (#626), inconsistent per-ISP, "fully blocked since 18 Apr" on some ISPs. Killed by a stateful NAT in front of Cloudflare ranges on most ISPs after ~15 Apr.
- **CORRECTION vs draft:** the draft treated the `sendfile`-from-`memfd` sequence-rewind as a known-good mechanism. The engineers could **not** verify ByeDPI's *current* source mechanism from the README (it documents option semantics, not the syscall), and the hard part is not setting TTL (that's a plain `setsockopt` via `x/sys`, no raw socket) — it is making the decoy and the real hello share the same TCP sequence space so the server accepts the real one after the decoy dies. Whether the phone kernel retransmits the *overwritten* bytes, whether `memfd_create`/`sendfile` pass the app seccomp filter, and whether per-segment `IP_TTL` behaves — **all UNKNOWN without an on-device capture.** Treat T3 as genuinely gated, not a formality.
- **Out-of-window injection (true FakeSNI) is confirmed root-only** (`SOCK_RAW`/NFQUEUE/sysctl), **no non-root equivalent** — the draft was right to rule it out. Keep `client_desync` desktop-only; the TTL/disorder/split variants belong under `tls_fragment` (non-root), not `client_desync`. Fix the two modifier specs accordingly.
- **Implementation path:** same `core/desync` conn, TTL/OOB strategy behind on-device gates.
- **Size:** **M** for the plain-TTL decoy, **L** once the sequence-rewind and per-kernel calibration are included.
- **Risks:** if the decoy reaches the server the connection simply fails; use only in the failure ladder. A NAT that terminates/normalises TCP defeats it regardless.
- **Tested:** the stateless-NAT survival (A9), per-ISP TTL calibration (A8) and on-wire reorder on CGNAT (A7) **cannot** be answered in any rig — they need an Iran vantage or an on-device capture. These gate any PASS record. censor-lab's live forger must be implemented (M) before even the stateful-reassembly fixtures become live tests.
- **Publisher sets up:** nothing.

### T4 — DNS-shaped tunnel on 53/udp (longest-surviving, most identifying, slow)
- **What:** a dnstt-class client to the network's own resolver, CNAME/AAAA-encoded.
- **Evidence:** the *last* survivor in multiple reports — "dnstt sole survivor" (Lantern), "one of the very few still functioning" (#561). Limits (#626): outside resolvers lasted 1–2 weeks, then national resolvers only, ~100 KB/s, drops near 1 minute; ICMP fully blocked.
- **CORRECTION vs draft:** national-resolver recursion to a foreign zone is **UNKNOWN** (needs an Iran vantage); one report says only A records return and TXT gets no response. So prefer a **CNAME target carrying base32** (~150 B, ordinary-looking, no RRset-order problem) or **AAAA with an index byte**, not TXT.
- **Implementation path:** `miekg/dns` (indirect dep); resolver addresses from the host (claim 22: `NetworkWatch.Link` reads only subnets/gateways today, so add `dns` to `Link`/`Facts`). Publisher needs NS delegation + 53/udp.
- **Size:** **M** (client) + resolver plumbing (S).
- **Risks:** the most identifying path — queries pass an identity-bound SIM's resolver and logs are retrospective. Text-only lifeline, last resort.
- **Tested:** worldbox has no DNS-resolver/allowlist model; adding one is a work item (M).
- **Publisher sets up:** a delegated zone with 53/udp open.

### T5 — Direct REALITY with fragmentation/desync in front (not a blackout path)
Useful on protocol-whitelist and blacklist days; **useless under IP default-deny** (the Hetzner IP is swept with everything). Cheap once T2's dialer exists. For SNI-whitelist-with-open-IPs phases, the refresh channel should be able to push a new REALITY cover name from the allowlisted set — but note the censor's own plan whitelists by FQDN+IP-prefix+port, which defeats an allowlisted name on a Hetzner address. Keep it in the ladder, not as a blackout promise.

**Demoted from the draft: Google-front *data* carrier (old P4).** The draft ranked it as an emergency data path. **CORRECTION (Group D):** inside Iran it broke repeatedly from mid-April 2026 (#313: a 28-IP scan found one reachable edge), and #676 (Oct 2026) shows TCP cut after a few packets on affected routes — P4-as-data is dead exactly in the regime it was meant for. Also the draft's `Host` leg was wrong (it is `script.google.com`; `script.googleusercontent.com` is the redirect target), its h2 fingerprint would be Go's not Chrome's (the named kill vector), and raw-IP/odd-port fetch from Apps Script is unsupported — the relay must listen on **443 with a hostname**, which re-introduces a DNS asset on the relay and erodes the "Hetzner graylisting stops mattering" claim. The *strong* use of the Google front is as a **refresh carrier** (§3, C5), not a data carrier. If ever built as data, it is Size **L** and allowlist-day-only.

---

## 3. Refresh / rendezvous channel design

### Principle (unchanged, and verified sound)
Credentials, REALITY keys and pinned certs are already in the signed pack, so a new address is only a *hint*: a forged hint can waste a dial but cannot impersonate the relay. Hints are encrypted and their fetch locations derived (HKDF of a per-recipient secret and epoch) so publishing never hands the relay IP to passive DNS.

### CORRECTION: the recovery gap must be closed first (new work item C0)
The draft assumed the recipient would "pick up the change on its own." In today's code it will not, when the IP is burned while the app shows "connected":
- the tunnel guard refuses a direct fetch while a route is active (`core/refresh/dialer.go:119`, `core/abi/tunnel.go:79`);
- auto-failover re-activates the dead route and calls `SetTunnelRequired(true)` (`connect_auto.go:752`), and a silent null-route is "forgiven" as `nothing_answered`;
- the Recover hook uses the same dead tunnel and its pointers are placeholders (W3-1);
- failures double the backoff to a 6h cap, so the first direct try after the user manually disconnects can be hours away;
- no recipient ABI verb triggers a freshness refresh (`RefreshUser` exists but nothing calls it);
- ticks only happen while the app/VPN is alive.

**C0 (S–M, prerequisite to every carrier below):** when a route is failed-but-running and a pass finds nothing, stop the instance (`SetTunnelRequired(false)`), run one immediate direct hint/freshness walk under a new `failureTriggered` refresh kind that bypasses `MinInterval` and the lifeline gate and does not inflate `ConsecutiveFailures`, then restart the pass. Expose `engine_relaypack_refresh(id)` for a user button. Add a worldbox `relay-ip-block` scenario that starts *while connected* (the current rig ticks a disconnected phone, so it never exercises this).

### CORRECTION: the micro-hint, standby addresses, push, and the word code
- **Micro-hint size (claim 23): the draft's "30–40 bytes" is wrong.** An Ed25519-authenticated hint is ~84 B (ver 1 + seq 8 + not_after 4 + IPv4:port 6 + strategy 1 + sig 64), ~100–124 B with AEAD. It fits **one TXT string** or **one CNAME target**, but **not 3 AAAA** (needs 8–9 with index bytes) and **not 12 words** (132 bits can't carry a signature). Drop the word-code idea.
- **CORRECTION: unauthenticated address hints are not safe (claim 24).** The draft said every family authenticates the server from pack material so an address hint is safe. False in two ways: it would break the *locked* `_endpoint` commitment rule (the client refuses an outbound whose server/port differs from the signed commitment — exactly what that rule exists to stop), and Shadowsocks has **no** independent server authentication, so an on-path recipient can impersonate the relay. A forged hint is also a beacon that steers every pack-holder to an attacker IP. **A MAC keyed by a pack secret is forgeable by any one recipient or seized phone** — the draft's "16-byte tag" is unsafe. Fix: authenticate with **Ed25519 under a pinned `hint_pub`** (persist the publisher root pubkey at import, or pin a dedicated key in the signed manifest), and apply a hint as an endpoint override **only** for addresses inside a signed alternates list or carrying a valid hint signature.
- **CORRECTION: the pack secret does not exist (claim 25).** No `pack_secret`/`hint_key` field exists anywhere. It must be added to the **per-recipient** part (the `.sbpx` profile), never the deliberately-public signed skeleton. A leak then exposes only that publisher's hint locations, same as today's mirror URLs.
- **CORRECTION: standby addresses in the pack do not exist (claim 31).** There is no standby concept in code; `FloatingIPProvisioner` reserves a fresh IP at rotation time. A standby must be a Hetzner **Floating IP** (billed, ~€3/mo). Work: sign standby `_endpoint` alternates into the pack marked "dial only after the primary is silent," and teach the auto-pass not to burn passes on unassigned standbys.
- **CORRECTION: push/FCM is non-functional (claim 28).** No Firebase dependency in the Android tree; `EngineDeliverPushPayload` returns -5 because nothing writes the keys it reads; and Play-services traffic rides Daal's own tunnel, so with a dead tunnel FCM is dead too. Drop it from the blackout ladder; keep opt-in and last if ever wired.

### The carrier ladder (order the client tries after a route dies)
Every network carrier today shares one fetcher that is **https-only, FQDN-not-IP, SNI==Host, Go-fingerprinted, HTTP/1.1, no ECH/fragmentation, and `net/http` is banned in `core/`**. **So no carrier works on an SNI allowlist today** — each new carrier is new fetch code, not a new label. "Mirrors provider set is open" is true for the *label* only.

| # | Carrier | Why the censor keeps it | Payload | Build (verified) | Size |
|---|---|---|---|---|---|
| 0 | Standby Floating IP alternates in the pack | no fetch at all | none | C7: signed alternates + auto-pass rule | M |
| 1 | DNS over the network's own resolver (CNAME-base32 or indexed AAAA, not TXT) | 53 passes; allowlisted services need recursion | micro-hint | C6: resolver-from-host (claim 22) + CNAME/AAAA writer in `cloudflare/dns.go` (today only proxied A/AAAA) | M |
| 2 | Google-front fetch (Apps Script `doGet`, served inline) | Google allowlisted | hint or full doc | C5 (see below) | M |
| 3 | `github.com` Atom feed (releases.atom/commits.atom) | GitHub allowlisted | micro-hint / full 2KB doc | C4: `ghfeed` backend via the PAT ghpages already holds + an Atom extractor | S–M |
| 4 | CDN object behind the publisher's zone, fetched via the T1/T2 dialer | Cloudflare ranges | full doc | C9 | M |
| 5 | FCM push | — | — | **non-functional; dropped** | — |
| 6 | Human courier: `.sbpx` file (encrypted), not a word code | works in a NIN-only cut | full profile | C8: wizard "send rotated pack to everyone as `.sbpx`" batch | S |

**Verified carrier facts:** `github.com/<o>/<r>/releases.atom` returns 200 directly (different host/CDN from the `*.github.io` ghpages backend; `/raw` redirects to `raw.githubusercontent.com`, a different SNI). Apps Script `doGet` with "Anyone" access returns byte-identical content through SNI `www.google.com` + Host `script.google.com` from outside today — but `/exec` redirects to `script.googleusercontent.com` and **the fetcher refuses every 3xx**, so a one-hop redirect follow restricted to `*.googleusercontent.com` is required.

### C5 — the Google front as a *refresh* carrier (the recommended Google use)
This is the strongest, safest Google use and far more defensible than the data carrier. A refresh fetch is one `doGet` returning a ≤124-byte hint or the ~2 KB signed `daal/freshness-v2` document — thousands of recipients polling *on failure* sit far under the 20k-UrlFetch/day consumer quota (verified: 20k/day per account shared, 30 concurrent, 6-min runtime, 50 MB body, 300–800 ms RTT). No exit VPS, no raw-TCP framing, no CA — `doGet` returns the bytes. **Build it as an `appsscript` freshness *mirror provider/backend***, which is in-bounds (`mirrors.go` Provider set is open for diversity) and touches no locked invariant — **not** as a rendezvous channel (the 5-channel `core/rendezvous` taxonomy is a closed v1 list; a Google-front *channel* would be a roadmap change — fold it into the existing Google-shaped `amp_cache` slot if ever needed). Reuse `VerifyMirrors` and the tunnel-required guard. It still needs the `metacubex/utls` Chrome hello (the current plain-`crypto/tls` fetcher is a tell) and the SNI≠Host split in `FetchRaw`. Size **M**.

### Required fetcher hardening (C1, M), shared by carriers 1–4
Bounded read (W3-2: today it `io.ReadAll`s then truncates), `metacubex/utls` Chrome hello option (note: **indirect** dep, a fork of refraction-networking/utls — the draft's import path was wrong), SNI/Host split, single-hop allowlisted redirect follow, h2 via `x/net/http2` Framer (no `net/http` import — the opsec grep bans it). The h2 fingerprint will be Go's, not Chrome's; accept that gap for short refresh fetches (the data carrier is where it would be fatal).

### C3 — close the manual step (S)
Today a rotation requires the publisher to **manually upload** the new signed `.sbp` to the pack URL. Have `publish` upload the signed pack to the same mirrors, or inline the pack in the freshness document when it is under ~8 KB. Then a phone rotation is one tap.

### Rotation flow, end to end (after C0+C3)
1. Publisher taps rotate → L3 Floating-IP swap (15 s *budget*, **never measured** — W3-10). 2. Re-sign pack. 3. `publish` uploads document **and pack** to ≥2 mirrors + writes the DNS/GitHub/Google hint carriers. 4. Recipient's route goes silent → C0 fires a failure-triggered direct walk → tries standby alternate (0), then DNS (1), Google-front (2), GitHub (3), CDN object (4), then `.sbpx` courier (6). 5. Realistic publisher→recipient time is **minutes plus propagation** (GH Pages serves `max-age=600`; national DNS may cache longer), not the draft's "1–3 minutes." **Detection gap remains:** the publisher abroad can't see an Iran-side block; proposal unchanged — the relay notices "hint fetches continue, handshakes stopped" and pings the publisher's phone for a one-tap rotation, with no provider token on the relay.

---

## 4. Build waves (parallel lanes, disjoint files)

**Wave 1 — start now.** Two lanes, no shared files:
- **Lane A (desync spine):** T2 — `core/desync` package + `outbound.Register` helper at the two `include.Context` call sites; worldbox production-split op against `sni-rst-stateless` + a first-two-packets scenario; fix `client_desync.md`/`tls_fragment.md` platform lists. Files: `core/desync/*`, `core/engine/{side_singbox.go,engine_singbox.go}`, `test-rigs/worldbox/driver/*`, `specs/modifiers/*`. **This is the first wave to start now** — smallest, forkless, half-proven, and unlocks T3/T5.
- **Lane C0 (recovery spine):** C0 — failure-triggered refresh kind + `engine_relaypack_refresh` verb + worldbox `relay-ip-block`-while-connected. Files: `core/abi/{connect_auto.go,refresh_freshness.go}`, `core/refresh/relaypack_refresh.go`, `core/scheduler/*`, `test-rigs/worldbox/driver/ops_freshness.go`.

(These two share no files and gate everything after them.)

**Wave 2 — after Wave 1.** Three lanes:
- **Lane T1-server:** B-1/B-2/B-3/B-5 (relay inbound, firewall, `ProvisionFront`, ECH fetch). Files: `cmd/daal-relay-mgmt/*`, `publisher/deploy/{relayports,cloudinit,cloudflare}/*`, `providers/hetzner/live_client.go`.
- **Lane hint-format:** C1 (fetcher hardening) + C2 (`daal/hint-v1` Ed25519 format, pinned key persistence, per-recipient secret). Files: `core/bootstrap/fetcher.go`, `core/refresh/{dialer,hint}.go`, `bundle/go/bundle/*`, `core/trust/*`.
- **Lane courier:** C3 (publisher uploads pack) + C8 (`.sbpx` batch). Files: `client-shell/tauri/daal-wizard/src/*`, `publisher/deploy/freshness/*`.

**Wave 3 — after Wave 2.** Depends on T1-server and hint-format:
- **Lane T1-client:** B-4/B-6/B-7 (CDN outbound, edge-IP selector, phone UI) + B-8 (worldbox edge node).
- **Lane carriers:** C4 (GitHub Atom) + C5 (`appsscript` mirror backend) + C6 (DNS) + C7 (standby alternates) — each is a separate backend/file set and can split further.

**Wave 4.** T3 (TTL decoy, behind on-device gates and the two-phone checks) + censor-lab live forger + T4 (DNS tunnel). T3/T4 are last because their payoff is unproven on the phones and against the current NAT, and no rig can close those gates.

Respect the laptop load cap (6 cargo jobs, nice, one heavy job at a time) — the Go engine + Tauri builds are the heavy ones; don't run Lane T1-server and Lane T1-client builds concurrently.

---

## 5. Decisions only the owner can make (with my recommendation)

1. **Domain(s) for the CDN front.** Paid (card + registrant data = identity link, but Cloudflare Registrar skips the nameserver change) vs free eu.org (slow manual approval, hits the `apexOf` multi-label bug). **Recommend:** a cheap paid domain per publisher on Cloudflare Registrar, treated as a consumable; budget several zones per account. The card/identity exposure is a real cost — the owner decides whether that is acceptable for the pilot.
2. **Cloudflare account + scoped API token.** Needs DNS edit, SSL/certs edit (Origin CA), zone settings edit (SSL mode, AOP, ECH, WebSockets), Workers (if the path Worker is kept), and Origin Rules. **Recommend:** a dedicated per-publisher Cloudflare account, token pasted in-app, never reused across publishers (one ban = all recipients). I cannot create accounts — the owner does this in a browser.
3. **Google account for the C5 refresh carrier.** Phone-number-bound; a suspension takes out every recipient under it. **Recommend:** a **dedicated** publisher Google account, used only for refresh (the low-volume `doGet`, which looks far less like a proxy than the data carrier), and make "dedicated account" a hard rule in the wizard. Creating the account and clicking through the one-time "unverified app" screen is the owner's to do (account creation is permission-gated and needs a phone number). This also touches Google's ToS (relay-as-proxy is outside intended use) — an owner/legal call.
4. **GitHub account + PAT for the C4 Atom carrier.** The ghpages backend already holds a PAT. **Recommend:** reuse it, but confirm the ToS posture for using releases/commits as a hint channel — owner/legal.
5. **Hetzner standby Floating IPs** (~€3/mo each, excl. VAT; price may predate the 15 Jun 2026 change). **Recommend:** one standby per active relay for zero-fetch single-IP recovery; no value under IP default-deny, so cap the spend. Renting/holding these is money + a Hetzner action — owner decides (reading the account is fine, renting is not, per the standing rule).
6. **DNS delegation + 53/udp for T4.** **Recommend:** provision only if the pilot needs a text lifeline under allowlist regimes; it is the most identifying path and should ship behind an explicit "emergency text only" consent.
7. **ECH reliance.** Free-zone ECH availability is unverified and Cloudflare can rotate/withdraw it. **Recommend:** build T1 to *prefer* ECH but degrade to `record_fragment` on the outer name, and treat "ECH available on this zone today" as a posture check the publisher runs, not an assumption.

**Items no rig or read-only pass can close — they gate PASS records and need the two phones or an Iran vantage:** TTL-decoy survival against the April-2026 NAT; per-ISP TTL calibration and which Cloudflare /24s + decoy SNIs pass; whether the MLKEM-stripped REALITY hello's JA4 still matches Chrome; national-resolver recursion to a foreign zone; on-device `memfd`/`sendfile`/`TCP_MD5SIG`/per-segment `IP_TTL` behaviour on the Samsung and Sony; and the current (post-Oct-2026) state of the NAT, fragment reassembly, and the Google front, all of which are **UNKNOWN** from here.
---

# Appendix A: verification reports

# desync

# Group A — Non-root desync on Android: claim verification

Read-only. Nothing built or run (laptop load cap honoured). Evidence is repo `file:line`, vendored sing-box at `~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12`, test rigs, and the ByeDPI README (fetched 2026-11-20). Platform/kernel facts that need a device are marked so, matching the adviser's own list A.

## Headline

The adviser's structural claim is **correct and stronger than the draft states**: Daal can register a wrapping dialer *below* REALITY **without forking sing-box**, and the split-ClientHello path is already proven to evade a stateless first-packet SNI box *inside Daal's own test rig*. The TTL/fake-decoy mechanisms are reachable on an ordinary protected socket in principle, but the exact kernel behaviour that makes them work is **UNKNOWN without an on-device capture** — the draft is right to park these in the verification list. True out-of-window injection (FakeSNI) is **confirmed root-only, no non-root equivalent**.

---

## (i) Split the TLS ClientHello into separate TCP segments — for every family incl. vless-reality

**VERIFIED (mechanism) / PARTLY (production wiring: REALITY not wired today)**

**Dialer-chain facts (how sing-box 1.13.12 builds it):**
- VLESS builds `outboundDialer = dialer.New(...)` then `tlsDialer = tls.NewDialer(outboundDialer, tlsConfig)` (`protocol/vless/outbound.go:45,68`). The TLS layer calls `outboundDialer.DialContext` to get the raw conn, then runs the handshake on it. So a wrapping conn returned by the dialer sees the **ClientHello as its first `Write`** — this is exactly the assumption sing-box's own `tf.Conn` already relies on (`common/tlsfragment/conn.go` `Write`, `firstPacketWritten`), so it is sound.
- `dialer.New` honours `Detour`: `dialOptions.Detour != "" → NewDetour(...)` (`common/dialer/dialer.go:45-50`); `DetourDialer.DialContext` just returns the named outbound's conn (`common/dialer/detour.go` `DialContext`). **This is the clean injection point.**
- The existing fragmenter splits only when it finds an SNI: `IndexTLSServerName(b)` gate in `common/tlsfragment/conn.go` `Write`; it sets `TCP_NODELAY` (`SetNoDelay(true)`), writes each segment, and waits for the ACK between segments via `writeAndWaitAck` → `unix.GetsockoptTCPInfo(..., TCP_INFO)` on `tcpi.Unacked` (`common/tlsfragment/wait_linux.go`). Android is a `linux` GOOS, and the stub is `//go:build !(linux||darwin||windows)` (`common/tlsfragment/wait_stub.go`), so **`wait_linux.go` compiles and runs on Android** — answers adviser claim A2 at the source level (on-device run still unproven).

**Why REALITY does not fragment today:** `common/tls/reality_client.go:115-148` builds `utls.UClient` directly on the raw conn and never wraps `tf.NewConn`; it also strips the `X25519MLKEM768` curve and key share (the two `common.Filter` passes before the second `BuildHandshakeState`). `record_fragment`/`fragment` are wired only on the uTLS and std-TLS paths (`common/tls/utls_client.go:61`, `common/tls/std_client.go:53`). Confirms the `tls_fragment.md` field note.

**The important correction to the draft:** a Daal detour outbound makes REALITY fragmentable **without the SNI gate and without forking**, because the split happens on the raw TCP conn *below* uTLS — Daal's conn sees the whole ClientHello bytes and can split at a fixed offset regardless of whether an SNI is present. This sidesteps both limits the draft lists (REALITY never wrapped; `tf.Conn` only splits at an SNI). For REALITY the split hides the **hello fingerprint / shape**, not a name (REALITY already sends an allowed cover name), which is what the draft argues in P3.

**Can Daal register its own outbound without forking? VERIFIED.**
- `outbound.Register[Options]` is exported (`adapter/outbound/registry.go:15`); `box.Context(ctx, inbound, outbound, endpoint, dns, service)` is exported (`box.go:61`); `include.OutboundRegistry()` returns a freshly built `*outbound.Registry` (`include/registry.go:72`).
- Daal today calls `include.Context(ictx)` in two places (`core/engine/side_singbox.go:173`, `core/engine/engine_singbox.go:254`). Replacing that one call with a ~15-line local helper — `reg := include.OutboundRegistry(); outbound.Register(reg, "daal-desync", ctor); box.Context(ctx, include.InboundRegistry(), reg, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())` — registers a Daal outbound used as `detour`. No vendored-tree edit.
- Protect still applies: the detour outbound's own `dialer.New` runs the platform `AutoDetectInterface` path, which appends `ProtectFunc`/`AutoDetectInterfaceFunc` as a `net.Dialer.Control` hook (`common/dialer/default.go:97-119`), i.e. the fd is offered to `invokeProtect` (`core/engine/platform_singbox.go:50`, `core/engine/protect_singbox.go` cgo callback). So a Daal-registered outbound's upstream socket is `protect()`ed like any other.

**Does Android/Linux coalesce the two writes?** With `TCP_NODELAY` set and `writeAndWaitAck` blocking on `tcpi.Unacked==0` between writes (the shipped mechanism), coalescing is defeated at the sender. **On-wire confirmation needs a capture** (adviser A7/A12) — UNKNOWN until then, but the rig can answer it (see (iv)).

**Implementation path:** new pkg `core/desync` (a `net.Conn` wrapper + an `outbound.Register` ctor); call site is the two `include.Context` lines. Strategy/offsets ride in the signed pack. **Size: M.** Blockers: none structural; the one real risk is whether uTLS emits the hello as a single `Write` for post-quantum-sized hellos (>1 record) — the wrapper must handle a multi-Write hello, not assume one.

## (ii) Fake low-TTL ClientHello then the real one (ByeDPI-style)

**PARTLY (reachable on a protected socket in principle) / UNKNOWN (kernel behaviour unproven)**

**How ByeDPI/ByeByeDPI do it non-root (README, fetched 2026-11-20):**
- Runs as a local SOCKS proxy; ByeByeDPI wraps it in Android `VpnService` — same non-root topology as Daal.
- `--fake <pos>`: sends a decoy copy of the first chunk before the real data. `--ttl <num>` (default 8) sets the decoy's TTL so it "reaches DPI but not the server". `--fake-data`, `--fake-sni` customise the decoy.
- `--disorder <pos>`: like `--split` but the first piece is sent with **TTL=1** so it dies in transit; the OS retransmits later, reordering bytes on the wire. `--oob`/`--disoob`: one byte as TCP URG (out-of-band). `--split`/`--tlsrec`: plain segmentation / TLS-record split.
- Kernel-dependent / Linux-only and **not guaranteed on a stock phone kernel**: `--md5sig` (TCP MD5 option on the decoy, "most Linux servers drop it"), `--drop-sack`. These back the adviser's claim A6 (`TCP_MD5SIG`) — settable only if the kernel compiled it in; UNKNOWN on the Samsung/Sony without a device check.

**Can Go do the same on a protected socket?** The TTL/OOB/MD5 options are plain `setsockopt` on a connected TCP socket, reachable from Go via `conn.SyscallConn().Control(func(fd uintptr){ unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, n) })` — `golang.org/x/sys v0.43.0` is already a direct dep (`core/go.mod:155`; sing-box itself uses `unix.GetsockoptTCPInfo` on the same platform). No raw socket needed for the TTL/OOB/split family. So the **decoy-with-low-TTL and the TTL=1 disorder are mechanism-reachable without root.**

**The unresolved core (why this is PARTLY/UNKNOWN, matching adviser A3/A4):** the hard part is not setting TTL, it is making the fake and the real hello occupy the **same TCP sequence space** so the server accepts the real one after the decoy dies. ByeDPI does this with kernel-level tricks (the draft's `sendfile`-from-`memfd` / page-overwrite path, or OOB rewind). Whether the phone kernel actually retransmits the *overwritten* real bytes, whether `memfd_create`/`sendfile` are allowed by the app seccomp filter, and whether `setsockopt(IP_TTL)` takes effect per-segment on a connected protected socket — **none is answerable from source; all need an on-device test.** I could not verify ByeDPI's *current* source mechanism (sendfile vs vmsplice/splice) from the README alone; the README documents option semantics, not the syscall.

**Implementation path:** same `core/desync` conn; add a TTL/OOB strategy behind on-device gates. **Size: M for the plain-TTL decoy, L once the sequence-rewind trick and per-kernel calibration are included.** Blockers: the four device unknowns above (adviser A3, A4, A6, A7) — these are genuine gates, not formalities; the mechanism can be wired and still be a no-op or a connection-killer on a given kernel/ISP.

## (iii) Out-of-window sequence injection (FakeSNI) — raw socket / root?

**VERIFIED: needs root; no non-root equivalent.**

- `research/intel-and-some-working-methods.md` (Project 3, PechenyeRU/FakeSNI, and the DPI section) documents the mechanism: `AF_INET/SOCK_RAW/IPPROTO_TCP` + `gopacket` to forge a segment at `seq = syn_seq+1-len(payload)` (left of the window), an `iptables -j NFQUEUE` rule via `go-nfqueue`, and a **system-wide** `echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal`.
- Non-root Android grants none of these: `SOCK_RAW` needs `CAP_NET_RAW`, NFQUEUE needs `CAP_NET_ADMIN` + iptables, the sysctl write needs root. `specs/modifiers/client_desync.md` already encodes this (platform `["linux-desktop"]`, locked invariant 40, `IMP_MODIFIER_PLATFORM`).
- The ByeDPI `--fake`/`--ttl` decoy is an **in-window, low-TTL** decoy, not out-of-window injection — it is the non-root substitute for the *effect* (poison the SNI extractor) but is a different and weaker mechanism (valid checksum, in-window seq; a NAT that terminates/normalises TCP defeats it). So there is **no non-root equivalent of the true out-of-window trick** — the draft's "impossible without root" list is accurate.

**Implementation path:** none on Android. Keep `client_desync` desktop-only. The modifier spec wording is slightly off and should be split (the draft says so): `client_desync.md` ascribes "raw-socket, Linux-desktop only" to the whole family, true only of the wrong-seq/FakeSNI variant; the TTL/disorder/split variants belong under `tls_fragment` (non-root) not `client_desync`.

## (iv) Which of these are measurable in the test rigs?

**VERIFIED for the stateless-DPI evasion (worldbox, today). FALSE/UNKNOWN for the stateful-NAT and TTL-on-wire cases.**

**worldbox — already models first-packet-vs-reassembly and already has a split-hello probe:**
- `test-rigs/worldbox/driver/censor_dpi.go:40-45` — a `tls_sni` rule has a `Reassemble bool`: `false` = reads the first data packet only (Iran-like), `true` = follows the hello across segments (GFW-like); `dpiMaxPkts = 8`. `parseClientHello` (`:102`) extracts `server_name`.
- `test-rigs/worldbox/driver/censor_probe.go:137-149` — `countingConn` cuts the first write into **two real TCP segments** with a 40 ms gap under `TCP_NODELAY`. The scenario `scenarios/sni-rst-stateless.json` carries the control proofs: `cover-sni-blocked` (one-segment hello → `reset_after_hello`) **and** `split-hello-slips-through` (`split:true` → `ok`), with `"expect": {"vless-reality": "blocked"}` because Daal's REALITY hello is ~600 bytes in one segment.
- **So the rig already proves the premise of claim (i).** BUT the split there is a *probe-harness* `countingConn`, **not Daal's production dialer.** To measure the production path, the rig would need to drive a real Daal engine configured with the `core/desync` outbound. That hook does not exist yet — this is the gap to close: a family/scenario pairing that runs the production split against `sni-rst-stateless`.

**censor-lab — scenarios exist but the live DPI is a stub:**
- `test-rigs/censor-lab/scenarios/stateful-reassembly.json` declares the expectation (`fakesni_pre_isn_injection → tcp_reset`, `plain_tls_to_allowed → ok`) and `tls-in-tls-burst.json` the burst window — but `internal/forgers/forgers.go` is a **kinds enum with no implementations** ("concrete implementations land per scenario as they are exercised on real Linux hosts"), `internal/netns/netns.go` is a stub, and `cmd/lab-driver/main.go:112-115` ships only the offline `replay` path ("live netns runner is staged"). So **censor-lab cannot today exercise a fake-SNI or stateful-NAT scenario against live packets** — it generates fixtures from declared outcomes. The draft's step-1 ask ("a censor-lab scenario for first-two-packets, no reassembly beside stateful-reassembly.json") is partly already present as a *declaration*; what is missing is the live forger.

**What no rig can answer (needs an Iran vantage / a phone):** TTL-decoy survival against the April-2026 stateful NAT (adviser A9), per-ISP TTL calibration and hop count (A8), whether the TTL=1 disorder reorders on the wire on CGNAT (A7), and the JA4 of the MLKEM-stripped REALITY hello vs current Chrome (A11) — all UNKNOWN from here, correctly on the adviser's list.

**Implementation path for measurability:** (S) add a worldbox family/op that stands up the production `core/desync` outbound and runs it against `sni-rst-stateless` + a new first-two-packets scenario; (M) implement the censor-lab `stateful_reassembly` and `first-bytes-whitelist` forgers so the fake-SNI claims stop being declarations. Blocker: the device-only claims above can never be closed in-rig; they gate any PASS record.

---

## Summary table

| Claim | Verdict | Key evidence |
|---|---|---|
| (i) split hello, all families incl. REALITY, no fork | VERIFIED mechanism / PARTLY wired | detour `common/dialer/dialer.go:45`; `reality_client.go:115-148` (not wrapped); `outbound.Register` exported; `include.Context` call sites `side_singbox.go:173`, `engine_singbox.go:254` |
| First-Write=ClientHello assumption | VERIFIED (same one `tf.Conn` ships on) | `common/tlsfragment/conn.go` Write |
| `wait_linux.go`/TCP_INFO runs on Android | VERIFIED at source (build tags) | `wait_linux.go`, `wait_stub.go` tag |
| (ii) low-TTL fake decoy on protected socket | PARTLY / UNKNOWN on-device | ByeDPI README `--fake/--ttl/--disorder/--oob`; `x/sys v0.43.0` (`core/go.mod:155`); seq-rewind + kernel behaviour unproven |
| (ii) `TCP_MD5SIG` decoy | UNKNOWN (kernel-dependent) | ByeDPI `--md5sig` "Linux-only, may be missing" |
| (iii) out-of-window injection non-root | FALSE (root-only, no equivalent) | `intel-...md` FakeSNI; `client_desync.md` platform gate |
| (iv) stateless-SNI evasion measurable | VERIFIED in worldbox (probe, not prod) | `censor_dpi.go:40-45`, `censor_probe.go:137`, `sni-rst-stateless.json` |
| (iv) fake-SNI / stateful-NAT measurable | FALSE today (censor-lab live runner stubbed) | `forgers.go`, `netns.go`, `main.go:112-115` |

**Net:** Group A's non-root split path (i) is real, forkless, and already half-proven in-rig — this is the smallest, soundest first step, as the draft orders it. The TTL-decoy family (ii) is reachable but genuinely unproven on the phones and against the current NAT. Out-of-window injection (iii) is correctly ruled out. The main rig gap is a production-engine split test plus live censor-lab forgers.

# cdn

# Group B: CDN hiding and clean IPs, checked against the code and the field reports

Read-only. Nothing was built or run. Repo paths are relative to `/home/nima/Projects/daal`. sing-box paths are under `~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/`, the version pinned at `core/go.mod:10`. Web sources are listed at the end with their dates. Several of them are community posts or machine-written summaries, and I mark those where I use them.

## Summary

- **The adviser's P1 premise is wrong about the repo.** P1 calls `cdn_fronted` an existing design to finish. In fact only the Cloudflare control-plane calls exist. No working data path exists on the relay, in the firewall or in the client. Four separate defects each break it end to end (section 1).
- **The desync work cannot assume "add `tls.fragment`".** In sing-box 1.13.12, `fragment: true` on its own does nothing. The wrapper is applied only when `record_fragment` is set (`common/tls/utls_client.go:61-62`, `std_client.go:53-54`). The repo already records this in `specs/modifiers/tls_fragment.md:38-43`.
- **The adviser's hostname ideas buy little.** Daily derived hostnames help only against exact-name rules. The zone name shows up in CT logs (the Universal SSL certificate covers `*.zone`) as soon as the zone is active. The pooribitwise report (June 2026) says a root domain that was never used was blocked too.
- **What actually hides the name in-band is ECH.** Its outer SNI is the shared `cloudflare-ech.com`, so the censor's only in-band answer is to block that one name, as Russia did. A whitelisted outer SNI combined with ECH is not possible, because the ECHConfig is bound into the HPKE key derivation (RFC 9849).
- **Cross-zone SNI≠Host is closed on every self-serve CDN that matters.**

## 1. What the repo has for CDN carriage today

| Piece | State | Evidence |
|---|---|---|
| sing-box transports | ws, httpupgrade, grpc, http, quic. No xhttp/splithttp. Without the `with_grpc` build tag only grpc-lite is compiled, and the Android build does not set that tag | `transport/v2ray/transport.go:29-63`; `transport/v2ray/grpc.go:1` (`//go:build with_grpc`); `tools/build-engine-android.sh:81` (no `with_grpc`) |
| ws/httpupgrade ALPN | Forced to `http/1.1` when unset. With the uTLS "chrome" fingerprint the hello therefore carries ALPN http/1.1 only, unlike real Chrome (h2, http/1.1). This is a known v2ray-over-WebSocket tell | `transport/v2raywebsocket/client.go:37-41`, `transport/v2rayhttpupgrade/client.go:33-37` |
| ws Host header | Supported (`headers.Host`; httpupgrade `host`) | `v2raywebsocket/client.go:59-61`, `v2rayhttpupgrade/client.go:40-41` |
| Cloudflare control plane | Zone lookup, Origin CA, AOP, proxied A/AAAA, path-rewrite Worker plus route, rotation of path, hostname and origin, posture check | `publisher/deploy/cloudflare/provider.go:49-262`, `worker.go`, `cf_client_live.go` |
| CLI | `daal-deploy cdn-provision` | `publisher/deploy/cli/cli.go:1789-1862` |
| Phone reachability | Tauri Android bundles `libdaal_deploy.so` (`client-shell/tauri/src-tauri/src/lib.rs:2909-2930`). Commands `wizard_store_cloudflare_token`, `wizard_provision_cdn_front` and `wizard_verify_cdn_posture` exist (`lib.rs:1657-1716`) and are bound in `client-ui/src/publisher/wizardCommands.ts:1489-1508`. **No UI component calls them** | grep of `client-ui/src` |
| Validator | `cdn_fronted` is allowed from phase V1.6. Attestation rules are RP022 and RP023 | `bundle/go/relaypackvalidate/validator.go:18-19,217-228` |
| Firewall-wipe bug (plan W1-D) | **Fixed.** The rule is now merged into the existing set | `providers/hetzner/live_client.go:489-503` |

### The four defects that break the data path

1. **The edge-to-origin port lands on REALITY.** The Cloudflare firewall rule is for 443/tcp (`live_client.go:348`). The proxied A record makes Cloudflare dial the origin on 443, which is the REALITY inbound (`relayports.go:33`, `relayconf.go:193-199`). REALITY hands unknown hellos to its cover site, so Cloudflare gets the cover certificate: error 526 under Full (strict), or the cover site under Full. The WebSocket inbound is on 8445 (`relayports.go:129`). That is not a port Cloudflare proxies (443, 2053, 2083, 2087, 2096, 8443), and `ProvisionFront` creates no Origin Rule. The zone's SSL mode is also never set, so under Flexible Cloudflare would dial port 80.
2. **The origin certificates are written but never used.** cloud-init writes `/etc/daal/cdn/origin_ca.{pem,key}` and `aop_client.pem` (`cloudinit/template.yaml.tmpl:51-68`), but no inbound reads them. `ws-in` uses the self-signed `/etc/daal/tls-cert.pem` and has no `client_authentication` (`cmd/daal-relay-mgmt/singbox_users.go:808-830`). sing-box 1.13.12 does support AOP verification (`option/tls.go:23-26`: `client_authentication`, `client_certificate_path`).
3. **The firewall "lock" locks nothing.**
   - Hetzner rules only add permissions, and 443/tcp (and 8445) are already open to `0.0.0.0/0` (`live_client.go:747-770`).
   - The phone path never passes `--firewall-id` (`client-shell/tauri/daal-wizard/src/cli_bridge.rs:2267-2290`). The CLI therefore creates a new firewall attached to nothing, which the code's own comment warns about (`live_client.go:493-496`).
4. **No client outbound exists for CDN.** The `websocket-tls` renderer sets `server` to the relay IP and pins the relay's self-signed SPKI (`publisher/deploy/relaypack/client_outbound.go:170-182, 495-545`). The only CDN-specific code in the binder is the attestation blob (`candidate_render.go:102-112`). In `core/`, `ExposureMode` is used only for selection and network memory, never for rendering (`core/internal/selection/candidate.go:24`). The study's line "control plane only, no data plane" (`docs/exotic-transports-plan.md:50`) is accurate.

### Smaller issues

- `apexOf` takes the last two labels (`provider.go:236-242`). It breaks on multi-label suffixes such as `x.eu.org` and `.co.uk`, which matters for free-domain options.
- The Origin CA certificate is issued for the exact hostname only (`provider.go:76-78`), so it cannot cover derived subdomains.
- The Worker is uploaded as a raw `application/javascript` service-worker script (`cf_client_live.go:136-150`). Whether Cloudflare's API still accepts that format is **UNKNOWN**. Check it on a real zone.

## 2. Claims 13–20

**13. Cloudflare refuses SNI≠Host across zones — VERIFIED.**
- Cloudflare documents error 421 for an SNI that does not match Host, and 1013 as the SNI/Host mismatch error. A 2019 test found that an empty SNI is refused as well.
- `research/filtering-the-flow.md:205` says Cloudflare fully blocked mismatches in 2020, and that Fastly enforced on 27 Feb 2024 and Azure on 8 Jan 2024.
- `research/intel-and-some-working-methods.md:81` ("some Cloudflare configurations still permit SNI≠Host") is contradicted by both, and should be marked wrong for Cloudflare.
- Akamai and some smaller CDNs: **UNKNOWN** for self-serve accounts. A 2023 survey found 22 of 30 smaller CDNs allowed some fronting (`filtering-the-flow.md:205`). #626 says Akamai edges were usable only through a Psiphon fork, which is not something a publisher can buy.
- What this means for the design: whitelisted SNI plus our Host is available only through desync (group A) or ECH.

**14. Static ECHConfig in the pack — PARTLY.**
- *Engine, VERIFIED:*
  - `ech.config` takes a PEM block of type `ECH CONFIGS` (`common/tls/ech.go:27-48`).
  - uTLS implements the ECH-capable interface (`utls_client.go:77-83, 259-266`). ECH conflicts with REALITY, so it is possible only on the CDN tier.
  - ws and httpupgrade dial through `tls.NewDialer`. Its `dialContext` retries once with the server's retry configs on `ECHRejectionError` (`common/tls/client.go:117-131`), so a stale shipped config costs one extra round trip and is not fatal.
- *Outer SNI, VERIFIED by spec:* the outer SNI is always the config's `public_name` (`cloudflare-ech.com`). It cannot be swapped for a whitelisted name, because the ECHConfig is part of the HPKE info.
- *UNKNOWN:*
  - Free-zone availability. Sources conflict: some community posts say ECH is forced on for free zones, a March 2026 ISC diary doubts it is available at all, and the API toggle is reported to work on all plans.
  - How often Cloudflare rotates its ECH keys.
  - Whether a uTLS Chrome hello with real ECH matches Chrome.
- *Risks:*
  - Iran has not been seen blocking `cloudflare-ech.com` in-band; Niere 2025 found it kills ECH through DNS. Russia blocked exactly that SNI in Nov 2024. One rule can do it.
  - Shipping the config defeats the DNS kill described at `intel:79`.

**15. Wildcard proxied record plus edge certificate for derived subdomains — PARTLY.**
- *Plan level (from my own knowledge, not fetched):* proxied wildcard records and Universal SSL covering `zone` and `*.zone` are available on the free plan.
- *Repo:* only an exact-host record is created (`cf_client_live.go:121-135`), the Worker route is `hostname+path*` (`provider.go:100`), and the Origin CA covers the exact host only. Derived names need a `*.zone` record, a `*.zone/<path>*` route and an Origin CA for `*.zone`.
- *Value, my inference:* low against zone-level blocking. The Universal SSL certificate puts `*.zone` in CT logs the day the zone is activated, and pooribitwise (June 2026, single user, machine-extracted summary) reports a root domain that was never used getting blocked. Treat zones as consumables; derived subdomains only defeat exact-name rules.

**16. `cloudflared` quick tunnels — FALSE as a product path.**
- Cloudflare documents quick tunnels as for testing only, with a 200-concurrent-request limit, no SSE, and a new random hostname each run. An October 2026 changelog adds optional email protection.
- WebSocket over quick tunnels: **UNKNOWN**.
- Every quick tunnel sits under `*.trycloudflare.com`, so one suffix rule ends them all.
- It would also add a new pinned binary to cloud-init, which is the relay staleness problem again.
- Recommendation: do not build.

**17. Telling white from grey Cloudflare IPs — PARTLY.**
- #626 (4 Jun 2026, anecdotal) says "grey" connections could send only about 6 packets, and that during the cut Cloudflare IPs were open "ONLY" for one SNI (`hcaptcha.com`).
- There are two separate dimensions, IP reachability and SNI policy, and a probe has to keep them apart:
  - First, TCP plus TLS with a neutral Cloudflare-hosted SNI, then push more than 10 data packets each way, for example a 32 KB GET on the publisher's path or a WebSocket echo.
  - Only then, one real-SNI attempt on the best IP.
- censor-lab and worldbox model neither an edge node nor a packet budget. Worldbox's `sni-rst` models reassembly only (`test-rigs/worldbox/scenarios/sni-rst.json`). Not buildable as specified yet; see B-8.

**18. Passing Cloudflare /24s and decoy names per ISP — UNKNOWN.** This needs a vantage point inside Iran. Clean-IP lists go stale ("clean IPs go dirty over time", Hiddify guide). The pooribitwise report already used rotated clean IPs and was still blocked by SNI.

**19. Cloudflare DDoS rules leave VLESS-over-WS alone — UNKNOWN.** The only evidence is net4people #429 (2024) via `filtering-the-flow.md:129`. A related risk, from my own knowledge: Cloudflare closes idle WebSockets after about 100 s, so the client needs keepalive.

**20. The edge-range firewall rule can be applied from the phone — PARTLY.**
- The binary and command are present on Android (section 1).
- As wired, the rule is ineffective (defect 3) and is aimed at the wrong port (defect 1).
- `FirewallApplyCloudflareRule` hard-codes `cdnOriginPort = "443"`, so it needs a port parameter and the relay's own firewall ID.

### Related P1 claims

- **"Cloudflare ranges are never wholesale blocked, SNI-only filtering there" (`intel:81`) — PARTLY.**
  - Contradicted by `filtering-the-flow.md:129`: Irancell blocked all Cloudflare IPs on 16 Apr 2023, per-IP blocking persists, and `*.workers.dev` has resolved to a bogon since mid-2023.
  - #626: during the cut only a few Cloudflare IPs gave a SYN-ACK, and later they were open for one SNI only. Cloudflare being the "first foreign range reopened" is not stated there.
- **"CDN domains blocked within 24 h" — PARTLY.** It is a single-user report, and the summary is machine-extracted. It describes DNS hijack to 10.10.34.34 plus RST floods on Cloudflare IPs, and says 10–30 byte fragments were reassembled.
- **#630 (19 Jun 2026; single vantage point):** random non-existent SNIs pass, and no residual block follows a reset — VERIFIED. That study does not cover CDN-fronted connections.
- **Workers or Pages as the CDN path — not recommended.** `*.workers.dev` has been bogon since 2023, and I found no 2025–26 evidence on `pages.dev`. Custom-domain Workers need a zone anyway, so they add nothing over a proxied record.

## 3. What a phone-only publisher would need

1. **A domain.** Options:
   - Paid: cheapest, and Cloudflare Registrar avoids the nameserver-change step, but it needs a card and registrant data. That is the identity link in `exotic-transports-plan.md:198`.
   - Free (eu.org and similar): slow manual approval, and multi-label suffixes hit the `apexOf` bug.
   - A third-party registrar: means a nameserver change and hours of propagation, which is the hardest step for a non-technical publisher.
2. **A Cloudflare account** (email only) and **a scoped API token** created in a mobile browser and pasted into the app.
   - Permissions: DNS edit, SSL and certificates edit (Origin CA), zone settings edit (SSL mode, AOP, ECH, WebSockets/gRPC), Workers scripts edit (account), Workers routes edit, and Origin Rules (rulesets).
   - The exact names of these permissions are **UNKNOWN** here; check them against Cloudflare's token templates.
3. **Origin Rules can override the destination port on Free** (10 rules; Cloudflare docs) — VERIFIED. This lets the client use edge port 443 while the origin listens on a dedicated port.
4. **Costs:** domain about $1–15 a year; Cloudflare free; no Workers quota is needed if the path-rewrite Worker is replaced by the WebSocket path itself, or kept, since each WebSocket connection is one request against the free plan's 100k a day. One account ban takes out every recipient.

## 4. Picking a clean CDN IP on the recipient phone (design, my estimates, not measured)

- **The pack ships seed edges.** The publisher fetches Cloudflare's ranges (it already does in `cloudflare/edge_ranges.go`) and puts a few hundred candidate IPs or /24s in the pack and the freshness document. Recipients never download a range list from inside Iran.
- **Scan only in the failure state.** Cap it at about 20–40 paced probes (one every 1–2 s) and stop at the first 3 that pass the >10-packet test.
- **Cost:** about 30–60 KB per probe and 1–3 MB per scan. The radio stays awake for 30–90 s, which is a small battery cost next to normal use.
- **Detectability:** one phone hitting dozens of Cloudflare IPs in a minute is not browser-like (a browser uses one or two IPs from DNS). Using the publisher's SNI in a scan would hand the censor the name, so scans use neutral SNIs only.
- **Cache per network** in `core/internal/selection/network_memory.go`, keyed like `last_winning_rendezvous_channel`.
- **How the outbound is rendered:**
  - `server` = chosen edge IP;
  - `tls.server_name` = hostname, with WebPKI verification instead of an SPKI pin (Cloudflare edge certificates rotate);
  - transport `headers.Host` / `host` = hostname;
  - `ech.config` if available;
  - `record_fragment: true` plus `fragment: true` together.
- **Root certificates on old phones — UNKNOWN.** Go loads roots from `/system/etc/security/cacerts`, and old Android may lack the newer roots Cloudflare's edges chain to (GTS, ISRG). Shipping a small root set through `tls.certificate` would avoid that.
- **Cloudflare sees inner traffic metadata.** Cloudflare terminates TLS, so it sees the VLESS header (UUID and destination host:port) and any non-TLS inner traffic. That belongs in the threat-model notes and the copy.

## 5. How group A's desync combines with this

The CDN tier is the one place where the hello carries a real, blockable name (the publisher's zone), so this is where hiding the SNI pays off. Order to try:

1. **ECH**, which needs no packet tricks.
2. **`record_fragment` plus `fragment`.** This works on the native 1.13.12 path once the hello has a real SNI (`common/tlsfragment/conn.go` splits only when it finds an SNI). It splits the outer `cloudflare-ech.com` when ECH is on. The pooribitwise report says it was reassembled.
3. **A group-A decoy hello with a whitelisted Cloudflare-hosted SNI before the real hello**, for SNI-whitelist phases. Reported killed by the April 2026 NAT on most ISPs (#626).

ECH and the decoy compose (decoy first, then the ECH hello). Whether that survives the NAT is **UNKNOWN** without a vantage point in Iran.

## 6. Work items

| ID | What | Where | Size | Blockers |
|---|---|---|---|---|
| B-1 | Dedicated `ws-cdn-in` (and optionally `httpupgrade-cdn-in`) inbound on its own port, using the Origin CA certificate and key, with `client_authentication: require-and-verify` against Cloudflare's AOP CA; new port entry; ufw rule from the Cloudflare ranges rendered at provision time | `cmd/daal-relay-mgmt/singbox_users.go`, `publisher/deploy/relayports/relayports.go`, `publisher/deploy/cloudinit/*.tmpl` | M | Fresh provision only (cloud-init has no upgrade path) |
| B-2 | Firewall: port parameter on `FirewallApplyCloudflareRule`, target the relay firewall `daal-relay-<id>`, and pass `--firewall-id` from the wizard; drop the world-open rule for the CDN port | `providers/hetzner/live_client.go:348,504`, `cli/cli.go:1852`, `daal-wizard/src/cli_bridge.rs:2274`, `commands.rs:1399` | S | none |
| B-3 | `ProvisionFront` zone settings: SSL mode strict, Origin Rule port override, WebSockets/gRPC on, optional ECH on; Origin CA for `zone` and `*.zone`; replace `apexOf` with zone lookup by walking labels or using `x/net/publicsuffix`; check the Worker upload format | `publisher/deploy/cloudflare/{provider.go,cf_client_live.go,cf_client.go,cf_client_mock.go}` | M | A Cloudflare account and zone to test against (owner decision) |
| B-4 | `cdn_fronted` client outbound: edge IP as server, hostname SNI, WebPKI plus shipped roots, Host header, public path, early data, ECH PEM, both fragment flags; endpoint commitment; validator matrix row | `publisher/deploy/relaypack/{client_outbound.go,candidate_render.go}`, `bundle/go/bundle/endpoint.go`, `bundle/go/relaypackvalidate/validator.go` | M | B-1 |
| B-5 | Publisher-side ECH fetch: HTTPS-record lookup from abroad, convert to an `ECH CONFIGS` PEM, embed in the pack and the freshness document | `publisher/deploy/cloudflare/` (new `ech.go`), `publisher/deploy/freshness/` | S | Free-zone ECH availability (claim 14) |
| B-6 | Recipient edge-IP selector: seed list in the pack, failure-state probe (two-stage, >10 packets), per-network cache, per-attempt `server` substitution | new `core/edgepick/`, `core/internal/selection/network_memory.go`, `core/abi/connect_race.go` | M | B-4; B-8 for tests |
| B-7 | Phone UI for the CDN front: token paste, zone choice, posture check, Farsi per `farsi/STYLE.md` | `client-ui/src/publisher/` (bindings already in `wizardCommands.ts:1489-1508`) | M | B-1 to B-3 |
| B-8 | Worldbox CDN edge node: TLS-terminating proxy enforcing SNI==Host with optional ECH. Scenarios: edge-IP allowlist, SNI allowlist on edge IPs, 6-packet grey budget, `cloudflare-ech.com` block, reassembling and non-reassembling | `test-rigs/worldbox/{driver,scenarios}/`, `test-rigs/censor-lab/scenarios/` | M | none |
| B-9 | Zones as consumables: several zones per account, hostname rotation across zones through freshness (`RotateHostname` exists); derived subdomains only after B-3's wildcard work | `cloudflare/provider.go:177`, `publisher/deploy/rotation/` | S | Domain cost and identity |
| B-10 | Spec updates: `tls_fragment.md` platform list = CDN tier with both flags; record "SNI≠Host closed on Cloudflare" and the `intel:81` correction in `docs/exotic-transports-plan.md` | `specs/modifiers/`, `docs/` | S | none |
| Not to build | Quick tunnels (claim 16), `workers.dev`/`pages.dev` fronts, classic cross-zone fronting, an Akamai/Fastly tier (no self-serve fronting) | — | — | — |

Ordering: B-2 and B-10 are free. Then B-1, B-3 and B-4 as one change with B-8 alongside. B-5 and B-6 next. B-7 last.

Open blockers:
- The owner's decision on a Cloudflare account and domain (identity, cost).
- A vantage point inside Iran, needed for claims 18 and 19 and for the NAT question.
- Nothing dated after September 2026 was found, so the November state of fragment reassembly and SNI rules on Cloudflare IPs is unknown.

## Sources (fetched 2026-11-20)

- net4people #626, 4–7 Jun 2026 (anecdotal): https://github.com/net4people/bbs/issues/626
- net4people #630, 19 Jun 2026 (single vantage point): https://github.com/net4people/bbs/issues/630
- Lantern corpus (machine-extracted, "review before relying"), source issue dated 10 Jun 2026: https://corpus.lantern.io/findings/2026-pooribitwise-iran-advanced-dpi__iran-sni-blocklist-without-dns-record/ and https://corpus.lantern.io/findings/2026-pooribitwise-iran-advanced-dpi__iran-dual-dns-hijack-rst-flood-blocking/
- Niere et al. 2025, ECH via DNS censorship: https://corpus.lantern.io/findings/2025-niere-encrypted__china-iran-ech-via-dns-censorship/
- Cloudflare error 421 / 1013: https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-421/ , https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1013
- Fronting test (2019): https://digi.ninja/blog/cloudflare_example.php
- Cloudflare network ports: https://developers.cloudflare.com/fundamentals/reference/network-ports/
- Origin Rules (port override on Free): https://developers.cloudflare.com/rules/origin-rules/ , https://developers.cloudflare.com/rules/origin-rules/examples/change-port/
- Quick tunnels: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/ ; changelog 2026-10-02: https://developers.cloudflare.com/changelog/post/2026-10-02-protected-quick-tunnels/
- ECH: https://developers.cloudflare.com/ssl/edge-certificates/ech , https://isc.sans.edu/diary.html?date=2026-03-09 , https://blog.cloudflare.com/announcing-encrypted-client-hello/
- Clean-IP practice: https://hiddify.com/manager/domain-worker-cdn-and-tunneling/Guide-for-finding-a-clean-Cloudflare-IP/ , https://pypi.org/project/cfscanner/
- Cloudflare on Iran partial restoration, May 2026: https://blog.cloudflare.com/iran-internet-partially-restored-may-2026/

Repo files relied on: `/home/nima/Projects/daal/publisher/deploy/cloudflare/{provider.go,types.go,worker.go,dns.go,edge_ranges.go,cf_client_live.go}`, `/home/nima/Projects/daal/publisher/deploy/providers/hetzner/{firewall_cf.go,live_client.go}`, `/home/nima/Projects/daal/publisher/deploy/cli/cli.go`, `/home/nima/Projects/daal/publisher/deploy/relayports/relayports.go`, `/home/nima/Projects/daal/publisher/deploy/relayconf/relayconf.go`, `/home/nima/Projects/daal/publisher/deploy/cloudinit/template.go`, `/home/nima/Projects/daal/publisher/deploy/relaypack/{client_outbound.go,candidate_render.go}`, `/home/nima/Projects/daal/publisher/deploy/profiles/iran-*.json`, `/home/nima/Projects/daal/cmd/daal-relay-mgmt/singbox_users.go`, `/home/nima/Projects/daal/client-shell/tauri/daal-wizard/src/{cli_bridge.rs,commands.rs}`, `/home/nima/Projects/daal/client-shell/tauri/src-tauri/src/lib.rs`, `/home/nima/Projects/daal/client-ui/src/publisher/wizardCommands.ts`, `/home/nima/Projects/daal/bundle/go/relaypackvalidate/validator.go`, `/home/nima/Projects/daal/specs/modifiers/tls_fragment.md`, `/home/nima/Projects/daal/docs/exotic-transports-plan.md`, `/home/nima/Projects/daal/research/{intel-and-some-working-methods.md,filtering-the-flow.md}`, `/home/nima/Projects/daal/test-rigs/worldbox/scenarios/sni-rst.json`, `/home/nima/Projects/daal/test-rigs/censor-lab/scenarios/stateful-reassembly.json`, `/home/nima/Projects/daal/tools/build-engine-android.sh`. sing-box 1.13.12 files: `common/tls/{client.go,utls_client.go,std_client.go,ech.go}`, `common/tlsfragment/conn.go`, `transport/v2ray/{transport.go,grpc.go,grpc_lite.go}`, `transport/v2raywebsocket/client.go`, `transport/v2rayhttpupgrade/client.go`, `option/tls.go`, `option/v2ray_transport.go`.

# refresh

# Group C: reserved refresh and rendezvous channel, checked against the code

Read-only. Nothing was built and no repo files were changed.

I checked the repo files by reading them on 2026-11-20. The few outside-world checks were run this session from a non-Iran vantage point, and each one is marked where it appears. Statements about ports, Google behaviour and similar that come from my own knowledge are marked "(knowledge)".

## 0. Headline: the adviser's recovery model has a gap in today's code

A recipient whose relay IP is burned while the VPN shows "connected" never learns the new address. Three things combine to cause this:

- **The tunnel guard refuses a direct fetch while a route is active.**
  - `core/refresh/dialer.go:119-147` sets the guard.
  - `core/abi/refresh_freshness.go:62-67` applies it to the freshness refresher.
  - `core/abi/tunnel.go:79-115`: while `TunnelRequired()` is true, a fetch either goes through the dead tunnel's SOCKS inlet or is refused.
- **The failover keeps the route "active".**
  - When nothing else carries, auto failover puts the dead instance back (`core/abi/connect_auto.go:550-557` comment, `resumeFailedRouteLocked` at `:760-772`).
  - That restart calls `SetTunnelRequired(true)` (`:752`).
  - Silent timeouts, which is what an IP null-route looks like, are "forgiven" as "nothing_answered" (`autoSettleLocked`, `:485-524`).
- **The Recover hook goes through the same dead tunnel.**
  - `recoverViaBootstrapPointers` (`refresh_freshness.go:103-113`) uses the same dialer rule.
  - Its pointers are placeholders anyway: `core/bootstrap/embedded/fixtures/pointers-primary.json` points to `bootstrap-primary.daal.example`; backlog W3-1.

The product copy already admits this: "picks up the change on its own — once it is not connected" (`client-shared/i18n/d2-extra.en.json:539`, `client-ui/src/i18n/d2/d2-extra.en.json:705`). Three more things make it worse:

- **Failures pile up a long backoff.**
  - Every refused or failed attempt calls `markFailure` (`relaypack_refresh.go`, the `ErrTunnelRequired` branch).
  - The backoff doubles from 5 min up to the 6 h cap (`core/internal/selection/freshness.go:82-102,204-227`).
  - So after hours connected-but-dead, the first direct try after the user disconnects can be up to about 6 h away.
- **No recipient ABI verb triggers a freshness refresh.**
  - `RefreshUser` exists (`relaypack_refresh.go:511`) but nothing in `core/abi` calls it.
  - The only exported refresh verbs are `engine_subscription_refresh`, `engine_revocation_refresh_all`, `engine_bootstrap_refresh` and `engine_pointer_rotation_status`.
- **Ticks only happen while the app runs.**
  - The Tauri 60 s loop (`client-shell/tauri/src-tauri/src/lib.rs:3780-3790`) runs while the app process is alive.
  - The Android pump (`DaalVpnService.kt:1221-1249`) runs only while the VPN service is up.
  - With the app killed and the tunnel down, nothing ticks.
- **The test rig does not cover this case.** Worldbox `ops_freshness.go` ticks a phone that is not connected.

**Work item C0 (S–M, prerequisite to everything below):** add a recovery trigger for "route active, no carry".

- When the liveness loop has a route failed and running, and a pass found nothing, the engine stops the instance (`SetTunnelRequired(false)`). It then runs one hint/freshness walk immediately, with these properties:
  - a new `refresh(ctx, id, failureTriggered=true)` kind that bypasses `MinInterval` and the lifeline-strict gate;
  - it does not add to `ConsecutiveFailures` (or uses a separate counter);
  - it is still direct-only with no tunnel up.
- Then restart the pass.
- Also expose `engine_relaypack_refresh(id)` for a user button.
- Add a worldbox scenario `relay-ip-block` + freshness that starts while connected.
- Files:
  - `core/abi/connect_auto.go` (`autoFallOver` / pass end);
  - `core/abi/refresh_freshness.go`;
  - `core/refresh/relaypack_refresh.go` (`shouldFire`, `markFailure`);
  - `core/scheduler`;
  - `test-rigs/worldbox/driver/ops_freshness.go`.

## 1. What carriers exist today

| Layer | Carrier | Signed by | Size bound | Status |
|---|---|---|---|---|
| Freshness doc `daal/freshness-v2` | 2–6 https FQDN mirrors (R2 `*.r2.dev` or custom domain; GH Pages `*.github.io`); provider label set is open (`publisher/deploy/freshness/mirrors.go:103-118`) | Publisher root or sub-key with an embedded cert; sequence high-water mark, `not_after` 72 h, `supersedes`, mirrors, padded to 2048 B (`publisher/deploy/freshness/document.go:56,68,444`) | Truncated to 64 KB **after** an unbounded `io.ReadAll` (`relaypack_refresh.go:735-737`; `core/bootstrap/fetcher.go:120`; backlog W3-2) | Wired; R2 and GH backends never touched a real endpoint (W3-7) |
| Signed pack fetch (`current_signed_url`) | Any https FQDN; 8 MB cap after read (`relaypack_refresh.go:145,779-783`) | Publisher; merged into held credentials (`bundle/go/importer/endpoint_plan.go:26-33`) | Credential-less pack is about 3–5 KB per route (worldbox output sizes) | **The publisher uploads it by hand**; the app never uploads it (`d2-extra.en.json:561,705`) |
| Bootstrap pointers → directory `.sbp` | https URLs in a project-root-signed set (`core/bootstrap/pointer.go:30-110`); rotation envelope inside the directory (`pointer_rotation.go`, `directory_rotation.go`) | Project root; directory pinned by publisher fingerprint | Under 2 KB set; directory fetch unbounded | Hosts are placeholders (W3-1). It yields **emergency routes**, not a new endpoint set for a private publisher's pack |
| Rendezvous channels (5, closed list) | `domain_fronted_broker`, `sqs`, `amp_cache`, `push`, `offline_hint` (`core/rendezvous/channels.go:35-41`) | Per channel | n/a | Snowflake-shaped `Hint` (OfferSDP/BridgeFP); `rendezvous.New` / Selector is **never constructed outside tests**; all Solicitors are stubs |
| Human courier | `.sbp` / `.sbpx` file import, static QR ≤800 B (`specs/qr-static-v1.md`), fountain QR, LAN share to private-IP literals only (`core/share/lan_target.go:12-31`) | Publisher; `.sbpx` is age-encrypted to the recipient's X25519 key (`specs/sbpx-envelope-v1.md`) | Few KB | **Works today**: every import path goes through the endpoint merge (`endpoint_plan.go` rule 3) |

**Every network carrier today shares the same fetcher.** `bootstrap.FetchRaw` has these properties:

- `https://` only, and the URL host must be an FQDN, not an IP literal (`core/refresh/endpoints.go:139-171`);
- SNI equals the URL host, so there is no front/SNI split (`fetcher.go:106-113`);
- Go `crypto/tls`, which is a Go fingerprint, not Chrome;
- HTTP/1.1 only;
- any 3xx is refused (`fetcher.go:199`);
- no ECH, no fragmentation;
- `net/http` is banned in `core/` by a source grep (`core/opsec_test.go:14-26,214`).

So no carrier works on an SNI allowlist today.

**How a burned IP is replaced today** (wizard, `client-shell/tauri/daal-wizard/src/commands.rs`):

1. L3 floating-IP swap (`:4153-4194`, 15 s budget, unmeasured: `publisher/deploy/rotation/postconditions.go:51`, W3-10).
2. Re-sign the pack.
3. `publish_freshness_after_rotate` (`:4401-4440`): uploads the document to at least 2 mirrors through `daal-deploy publish-freshness`.
4. **The publisher manually uploads the new signed `.sbp` to the pack URL.**
5. The recipient then needs no tunnel, a tick, a passed backoff, a reachable mirror, and a reachable pack URL.

## 2. Claims 21–31

**21. National resolvers recurse to a foreign zone and return TXT or AAAA intact: UNKNOWN.**

- Evidence (outside the repo):
  - Net4people #626 (as the adviser cites it): outside resolvers lasted 1–2 weeks, then national resolvers only.
  - FOCI 2026 (Niere et al., https://www.petsymposium.org/foci/2026/foci-2026-0016.pdf, fetched today): June 2025 data, a single Iranian vantage, DNS/UDP heavily affected after the shutdown; it names later blackouts as 8 Jan–1 Feb 2026 and 28 Feb–25 May 2026.
  - A search-summarised user report says "only A records return, TXT no response" (unconfirmed).
- Needs an Iran vantage. Treat TXT as fragile.
- **Encoding advice:**
  - prefer a CNAME answer whose target label carries base32 (about 150 B of payload, ordinary-looking, no RRset-order problem);
  - or AAAA records with an index byte, since resolvers shuffle RRsets.
- The worldbox has no DNS-resolver or allowlist model; adding one is a work item (M).

**22. The engine can get the underlying network's resolvers while the VPN is up: PARTLY.**

- `NetworkWatch.Link` reads only subnets and gateways (`NetworkWatch.kt:73-80`). `LinkProperties.getDnsServers()` is a public API (knowledge).
- The engine's own sockets are already outside the VPN (`DaalVpnService.kt:414`, `addDisallowedApplication(self)`), so UDP to the ISP resolver from the engine is possible.
- Work (S):
  - add `dns` to `Link`/`Facts`;
  - pass it through `engine_network_facts`;
  - keep it out of logs and diagnostics.
- Caveat: with Android Private DNS set to strict, the ISP resolver may not be the one listed.

**23. A micro-hint fits in 3 AAAA, one TXT string, or 12 words: PARTLY / FALSE.**

- An authenticated hint needs about 84 B: ver 1 + seq 8 + not_after 4 + IPv4:port 6 + strategy 1 + Ed25519 signature 64. With AEAD (24 B nonce, or derived from seq, plus 16 B tag) it is about 100–124 B.
  - One TXT string (≤255): yes.
  - One CNAME target: yes.
  - 3 AAAA (48 B): **no**; it needs 8–9 AAAA with index bytes.
  - 12 words (132 bits): **no**, so it cannot carry a signature.
- The adviser's 16-byte MAC tag fits but is unsafe; see 24/25.
- The word list is still a placeholder (backlog H1, `docs/backlog-post-45.md:232`).
- Human courier: use the existing `.sbpx` file, which is encrypted and so does not reveal the IP to a state-run messenger, or a fountain QR. Do not use a word code.

**24. An unauthenticated address hint is safe for every family: FALSE.**

- **It breaks a locked rule.** The client refuses an outbound whose server or port differs from the signed `_endpoint` commitment (`bundle/go/bundle/endpoint.go` header; `endpoint_plan.go` rules 1, 4 and 5). An address hint would need that check relaxed, which is exactly what the commitment was added to stop.
- **Shadowsocks is admitted to have no independent server authentication** (`endpoint.go` header: someone who is both a recipient and on-path can impersonate the relay).
- **A forged hint is a beacon.**
  - It steers every holder of the pack to an attacker IP, which then lists their addresses.
  - The repo already rejects this class of risk for mirror URLs (`relaypack_refresh.go`, `importedMirrors` comment) and for LAN targets (`lan_target.go:12-24`).
- **A MAC keyed by a pack secret is forgeable** by any one recipient or seized phone.
- **Fix:** authenticate with Ed25519 under a key whose public half the device already holds. This needs a schema step:
  - the store keeps only the publisher **fingerprint**, not the key bytes (`core/refresh/relaypack.go`, `PublisherKeyForFingerprint` comment);
  - so either persist the root public key at import, or pin a dedicated `hint_pub` inside the signed manifest.
  - A sub-key cert is too large for DNS.
- Size: S–M (`bundle/go/bundle`, `core/trust`, a new `core/refresh/hint.go`).

**25. A pack secret for hint keys exists, and a leak exposes only hint locations: FALSE (nothing exists).**

- No such field exists. A grep for pack_secret / hint_key / standby in `bundle/go` and `core` finds nothing.
- **Placement constraint:**
  - The credential-less signed manifest is deliberately public; it sits on the pack URL (`daal-wizard/src/freshness.rs:15-33`).
  - So the hint-location and encryption secret must sit in the per-recipient part (the profile, delivered inside `.sbpx`), not in the signed skeleton.
  - The authentication key (24) can be public.
- A leak gives the holder that publisher's hint locations and the ability to decrypt that publisher's hints, so it reveals the next IP. Other publishers are not exposed. This is the same exposure as today's mirror URLs.
- Size: S.

**26. `github.com` itself serves a fetchable unauthenticated object: VERIFIED from outside, UNKNOWN from Iran.**

- Checked today:
  - `https://github.com/<o>/<r>/releases.atom` → 200 directly (served from 4.225.189.240);
  - `/commits.atom` → 200;
  - `/raw/HEAD/...` → 302 to `raw.githubusercontent.com`, so raw paths and release assets are a different SNI.
- The release body or commit message can hold a hint or even the full 2 KB document.
- The existing ghpages backend uses `*.github.io` (`publisher/deploy/freshness/backends/ghpages/ghpages.go:5,38`), which is a different host and CDN from `github.com`.
- FOCI ref [18] says GitHub stayed reachable on a whitelisted IP in June 2025.
- Work (S–M):
  - a `ghfeed` publisher backend: create a release or commit through the PAT the ghpages backend already holds;
  - a recipient extractor that pulls the signed blob out of the Atom XML.
- The fetcher already handles 200 with chunked transfer encoding.

**27. Apps Script `doGet` with "Anyone" access returns content through the Google front without login: PARTLY.**

- Checked from outside today: a request with SNI `www.google.com` and Host `script.google.com` returned the byte-identical Apps Script response that a direct request gets (7956 B), not www.google.com's own 404 (1590 B). So same-frontend Host routing works from outside as of 2026-11-20.
- `/exec` answers with a redirect to `script.googleusercontent.com` (MHR-RUST guide: "/exec → googleusercontent.com"; knowledge). Our fetcher refuses every 3xx.
- Missing pieces:
  - front SNI ≠ Host in `FetchRaw`;
  - a one-hop redirect follow restricted to `*.googleusercontent.com` under the same front;
  - a Chrome-shaped hello: `metacubex/utls` is in `core/go.mod:67` as indirect;
  - h2: use `x/net/http2` Framer + hpack directly, so no `net/http` import (`core/opsec_test.go` is a source grep).
- Not verified from Iran. Google ToS and suspension risk apply. `mail.google.com` is reported targeted (MHR-RUST guide).
- Size: M (new `core/bootstrap/front` dialer and fetcher, a publisher-side script template, and a phone copy-paste deploy flow).

**28. FCM uses a 443 fallback that an allowlist would pass: FALSE as a Daal carrier today; port detail UNKNOWN in a blackout.**

- FCM uses 5228–5230 with a 443 fallback (knowledge).
- In Daal it does not work:
  - there is no Firebase dependency or messaging service in the Android tree (grep shows none);
  - `EngineDeliverPushPayload` resolves keys from `publisher_pub:<hex>` secrets that nothing writes (`core/abi/rendezvous_gomobile.go:106-116`), so every payload returns -5;
  - Play services traffic goes through Daal's own tunnel (only self is excluded, `DaalVpnService.kt:414`), so with a dead tunnel FCM is dead too.
- Keep it opt-in and last.

**29. Measured wall-clock for the floating-IP swap and for provision to first handshake: UNKNOWN (never measured).**

- The 15 s budget is unmeasured (`postconditions.go:33-51`, W3-10).
- After the swap come the document publish to at least 2 mirrors and a **manual** pack upload.
- GH Pages adds commit-to-serve and CDN cache delay; Pages serves `max-age=600` (knowledge).
- So publisher-to-recipient time is realistically minutes plus a human step, and the recipient side adds C0's gap.
- **Work (S):** have `publish` upload the signed pack to the same mirrors, or inline the pack in the document when it is under about 8 KB. Then a phone rotation is one tap.

**30. Failure-triggered hint fetches run in lifeline-strict and obey the tunnel guard: FALSE.**

- Only two kinds exist:
  - scheduled, which is suppressed in lifeline-strict (`relaypack_refresh.go:306-311`);
  - user-triggered, which has no ABI verb.
- The tunnel guard is obeyed, but in a way that blocks recovery (section 0). Fixed by C0.

**31. Hetzner allows reserved, unattached standby addresses: PARTLY.**

- Hetzner bills unassigned Floating and Primary IPs. Prices: Floating IPv4 €3/month, Primary IPv4 €0.50/month, excl. VAT (docs.hetzner.com IPv4 pricing; may predate the 15 Jun 2026 price change).
- A standby must be a Floating IP, which can be assigned live (knowledge).
- The code has no standby concept. `FloatingIPProvisioner` reserves a fresh IP at L3 time (`rotation/postconditions.go`).
- Work (M):
  - sign standby `_endpoint` alternates into the pack, marked "dial only after the primary is silent";
  - teach the auto pass not to burn passes on unassigned standbys;
  - add a wizard "attach standby" L3 variant.
- Value: zero-fetch recovery for a single-IP burn. No value under IP default-deny.

## 3. Carriers that could survive an allowlist or blackout: order and work items

| # | Work item | Size | Blockers |
|---|---|---|---|
| C0 | Recovery trigger for connected-but-dead, failure-triggered refresh kind, user verb, worldbox scenario | S–M | none |
| C1 | `FetchRaw` hardening: bounded read (W3-2), Chrome uTLS option, SNI/Host split, single-hop allowlisted redirect, h2 via Framer | M | opsec grep rule wording; must not regress the fail-closed guard |
| C2 | Signed micro-hint format `daal/hint-v1`: Ed25519 under a pinned key, seq high-water mark shared with freshness, `not_after`, AEAD under a per-recipient secret, applied as an endpoint override **only for addresses inside a signed alternates list or carrying a valid hint signature**; spec plus test vectors | M | needs a spec decision relaxing the endpoint-commitment rule; publisher pubkey persistence (24) |
| C3 | Publisher uploads the signed pack itself, or inlines it in the document | S | none |
| C4 | `github.com` Atom carrier (publish plus extractor) | S–M | GitHub ToS; PAT custody already exists |
| C5 | Google-front fetch carrier (Apps Script; document served inline), as a freshness mirror provider — not a rendezvous channel, which would need a roadmap change to the closed list of 5 (`specs/rendezvous-channels-v1.md`) | M | Google account, ToS, Iran-side check (27); quotas per MHR-RUST guide: about 20k fetches/day per account, about 30 concurrent, about 2 s per round trip |
| C6 | DNS hint over the ISP resolver: CNAME or AAAA encoding, `miekg/dns` (indirect, `core/go.mod:69`), resolvers from host (22); publisher writes records through `publisher/deploy/cloudflare` (today only proxied A/AAAA, `dns.go:44-69`; needs a TXT/CNAME writer) | M | Iran-side recursion unknown (21); identity-linked SIM resolver logs, so lifeline-only |
| C7 | Standby floating IPs as signed alternates | M | cost; auto-pass behaviour |
| C8 | Human courier: a "send rotated pack to everyone as `.sbpx`" batch in the wizard (`recipient_sbpx.rs`, `recipient_book.rs` exist) | S | Domestic messengers are state-read, so send only `.sbpx`, never the public `.sbp` (it reveals the new IP) |
| C9 | CDN static object behind the publisher's Cloudflare zone, fetched through the group A/B desync dialer | M | depends on the desync work; r2.dev SNI is unlikely to be on an allowlist |
| C10 | Rendezvous spec cleanup: say plainly that the 5 channels are Snowflake-only and unwired; publisher-side hints belong in freshness | S | doc only |

Doc-level corrections to the adviser's draft:

- Carrier 0 ("standby addresses already in the pack") does not exist yet (31).
- Carrier 5 (push) is not functional (28).
- Carrier 6 should be `.sbpx`, not a 12-word code (23).
- "Mirrors provider set is open" is true for labels only. Every mirror must still be an https FQDN fetched with SNI = host, so Google-front, GitHub-feed and DNS carriers all need new fetch code, not just a new label.

## Sources (fetched this session)

- FOCI 2026, "Insights into an Iranian Internet Shutdown": https://www.petsymposium.org/foci/2026/foci-2026-0016.pdf
- MasterHttpRelayVPN-RUST guide: https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/docs/guide.md
- Lantern finding (machine-extracted, "review before relying"): https://corpus.lantern.io/findings/2026-gusgustavo-iran-internet-shutdown__dnstt-sole-survivor-iran-blackout/
- Hetzner IP pricing: https://docs.hetzner.com/general/others/ipv4-pricing/ and https://docs.hetzner.com/cloud/billing/faq/
- Search leads, not relied on: https://digimpactlab.substack.com/p/iran-digital-pulse-code-against-the-blackout , https://tildes.net/~tech/1tz9/accessing_the_internet_through_only_google_com , https://arxiv.org/html/2603.28753v1
- Outside checks run today with curl, read-only GETs: github.com Atom and raw redirect; Google front Host routing for `script.google.com`.


# google

# Group D verification — Google-front emergency carrier (Apps Script relay)

Read-only. Repo facts are file:line in `/home/nima/Projects/daal` or `~/go/pkg/mod`. Field facts are URL + date; several are single-user reports and I mark them. Nothing was built or run.

## Headline corrections to the draft before the claims

- **"refraction-networking/utls is already a dependency" — FALSE as written.** The dependency is `github.com/metacubex/utls v1.8.4 // indirect` (`core/go.mod:67`), a *fork* of refraction-networking/utls pulled transitively by sing-box. The API is compatible but the import path in the draft is wrong, and it is **indirect** — using it directly means adding a direct require and owning a transitive dep that sing-box controls the version of. `golang.org/x/net v0.53.0` (`core/go.mod:152`, also indirect) does carry `http2/`.
- **The draft's "Host `script.googleusercontent.com`" is the wrong leg.** The working tools POST with **`Host: script.google.com`** (GooseRelay default `google_host: 216.239.38.120`, `sni: www.google.com`, `Host: script.google.com`). `script.googleusercontent.com` is where Apps Script's `ContentService` *redirects* the response to (a one-time URL — "content returned by the Content service is redirected to a one-time URL at `script.googleusercontent.com`", developers.google.com/apps-script/guides/content), so the client must follow a redirect to a **second** Host that must *also* route over the same GFE. That round-trip is part of why RTT is 300–800 ms, and it is a second thing the censor can pin.
- **Daal has no fronting fetch path today.** `core/bootstrap/fetcher.go:106-107` builds `tls.Config{ServerName: host}` and `buildRequest` sets `Host: host` (fetcher.go:150-156) — SNI and Host are always the same value, plain `crypto/tls`, HTTP/1.1, no uTLS. So **both** the data carrier and the refresh-only carrier are net-new code; nothing in the current fetcher or refresh dialer can be reused for the SNI≠Host split.

## The claims

### 32. SNI `www.google.com` + Host `script.google(usercontent).com` still routes in 2026, from outside and inside Iran, over HTTP/2 — **PARTLY → trending FALSE for Iran in late 2026**
- The same-GFE Host-routing trick is real and is the documented basis of MasterHttpRelayVPN and GooseRelayVPN (`research/intel-and-some-working-methods.md:103-105`; GooseRelay README defaults above). Google's 2018 domain-fronting shutdown did not close this specific same-front-end Host route.
- **From Iran it broke, repeatedly, starting mid-April 2026.** MasterHttpRelayVPN-RUST issue #313 (opened 27 Apr 2026, github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313): Apps Script fetches went unresponsive from ~12:25 Tehran across six Google accounts / six deployments at once, which the reporters read as the ISP path, not the accounts. Direct `curl` from Iran returned "Connection reset by peer"; a scan of 28 Google front IPs found **only 216.239.38.120 reachable**. Maintainer's final read: RST injection by the Iran ISP and per-Google-edge-IP filtering of Iran-origin traffic, "Not an mhrv-rs bug." No confirmed root cause; some deployments later recovered but slow (throttling). Single-project thread, not independently verified.
- **Late-2026 regime data is worse.** net4people #676 (JohnWatsoon, 18 Oct 2026, github.com/net4people/bbs/issues/676): on the routes measured, TCP/UDP/GRE/ESP Iran→abroad were **cut after a few packets — "Only ICMP passes reliably"** on affected routes; Cloudflare `wss` dropped right after the TLS handshake ("points to SNI filtering") and worked **only with ECH**. Google/Apps Script not measured in that issue, but if a route is TCP-after-few-packets, a Google-fronted TCP flow dies with everything else. This is the regime the draft files under "NIN-only / IP default-deny," and P4 is explicitly dead there.
- HTTP/2 specifically: the tools front over HTTPS/TLS; HTTP/2 to the GFE works where the TCP+TLS path works. No separate evidence that h2 is singled out.
- **Verdict:** works from outside Iran; inside Iran it is intermittent, per-ISP, per-edge-IP and time-varying, and on the allowlist/NIN routes of 2026 it is often dead. Treat as an **opportunistic allowlist-day carrier**, never a blackout guarantee. Current (Nov 2026) state **UNKNOWN** — I found nothing on the Google front dated after Oct 2026.

### 33. `metacubex/utls` Chrome hello + `x/net/http2` gives a JA4 + h2 fingerprint matching current Chrome — **PARTLY (TLS yes, h2 no, out of the box)**
- TLS layer: `metacubex/utls@v1.8.4` ships `HelloChrome_Auto = HelloChrome_133` (`u_common.go:615`), with the `X25519MLKEM768` post-quantum key share (`u_parrots.go:841`) and randomized ALPS (`u_parrots.go:3127`) that current Chrome sends. So a **JA4 TLS match is achievable** and is ahead of what the bootstrap fetcher does today.
- HTTP/2 layer: `golang.org/x/net/http2` exists in the module cache but its SETTINGS values, header-table size, WINDOW_UPDATE and pseudo-header/frame ordering are Go's, **not Chrome's** — Chrome's h2 fingerprint (Akamai-style `|...|...|m,a,s,p`) is not produced by `x/net/http2`. uTLS does not fix the h2 layer. To match Chrome's h2 you must hand-tune the transport (there is no Chrome-h2 preset here) — that is the delta that a JA3/JA4-*plus-h2* classifier on AS15169 (`intel:109`, the named kill vector) would catch.
- Wiring is also non-trivial: you dial a uTLS conn with `NextProtos:["h2"]`, complete the uTLS handshake, then feed the *already-handshaked* conn into `http2.Transport` via a custom `DialTLSContext`. Doable, a known pattern, but not free.
- **Verdict PARTLY.** TLS fingerprint: reachable (metacubex/utls). h2 fingerprint: extra work and still imperfect; the Python original was killed exactly here (`intel:109`), and Daal would be better but not provably Chrome-equal.

### 34. Current free-account quotas and latency — **VERIFIED**
From developers.google.com/apps-script/guides/services/quotas (fetched 2026-11-20):
- **UrlFetch calls/day: 20,000 consumer, 100,000 Workspace.**
- **Simultaneous executions: 30 per user, 1,000 per script.**
- **Script runtime: 6 min per execution.**
- **UrlFetch response and POST body: 50 MB each; 100 headers; 8 KB header size.**
- No numeric per-minute limit published (only "too many times per second" errors).
- Latency: GooseRelay README gives **300–800 ms per round trip**; "real-time apps (Telegram, X) can exhaust the daily quota within a few hours"; 480p comfortable. Quota resets midnight Pacific (≈10:30 IRST).
- The 20k/day is **per Google account, shared by all deployments under it** (GooseRelay README; MHRV `script_ids: [ID1,ID2,ID3]` load-balances across accounts for exactly this reason, `intel:111`). The draft's "20k/day shared by the whole family" is therefore correct and is the hard ceiling on P4 as a *data* carrier.

### 35. Apps Script can reach the relay on a non-standard port by IP with a self-signed/pinned cert (`validateHttpsCertificates`), and its egress IP ranges for a firewall rule — **PARTLY / UNKNOWN**
- `UrlFetchApp.fetch` does expose `validateHttpsCertificates: false` (long-standing option), so a self-signed relay cert can be accepted — this part is plausible-VERIFIED by API surface, not tested here.
- **Non-standard port by raw IP: UNKNOWN and risky.** Apps Script's URL Fetch historically restricts to standard web ports and resolves hostnames; fetching `https://<ip>:<odd-port>/` is not documented as supported and I could not confirm it works in 2026. The relay almost certainly must listen on **443 with a hostname**, which re-introduces a DNS/domain asset on the relay — eroding the draft's "relay only needs to be reachable from Google, Hetzner graylisting stops mattering" claim.
- **Egress IP ranges: UNKNOWN / not stable.** Apps Script egress comes from Google's general ranges (`_cloud-netblocks`/`googleusercontent`), broad and shared, so a tight Hetzner firewall allow-list keyed to Apps Script is impractical — you would allow large Google blocks. Needs a live check against `UrlFetchApp`'s current egress.
- **Verdict PARTLY** — cert-skip yes; IP+odd-port and a tight egress allow-list are unconfirmed and probably not available.

### 36. A publisher can deploy the web app from a phone browser, copy-paste only, no OAuth verification — **PARTLY**
- Via the **Apps Script editor UI** (script.google.com in a browser): paste `Code.gs`, Deploy → Web app, "Execute as: Me", "Who has access: Anyone". `ANYONE_ANONYMOUS`/"Anyone" is the correct setting (developers.google.com projects.deployments reference). This is copy-paste and works on a phone browser, though the editor is desktop-oriented and fiddly on a small screen.
- **The "no OAuth verification" part is only half true.** A script that calls `UrlFetchApp` needs the `external_request` scope; on first authorization Google shows the **"Google hasn't verified this app"** unverified-app screen. Because `Execute as: Me`, the *owner* can click through (Advanced → Go to project) without formal app verification, so recipients never see it — but the publisher does, once, and must know to proceed. No formal OAuth app-verification review is required for owner-executed web apps.
- **Doing it through the Apps Script REST API (`projects.create` + `updateContent` + `deployments.create`) with a phone OAuth token — heavier, PARTLY.** It requires the user to first toggle **"Google Apps Script API: on"** at script.google.com/home/usersettings, a standard GCP project behind the script, and OAuth scopes; **the API does not work with service accounts** (developers.google.com/apps-script/api/concepts). So the API route needs an interactive OAuth grant from the phone and a GCP project — more setup than copy-paste, and more identity linkage. For Daal's non-technical publisher the **editor copy-paste route is the realistic one**; the API route is the automatable one if you later want one-tap redeploy from the publisher app.
- **Verdict PARTLY.**

### 37. Throughput/battery for a messaging workload on the Sony via VpnService, recipients/deployment/day — **UNKNOWN (not answerable read-only; needs the two-phone rig)**
- From quotas + latency: a text-messaging workload (Telegram/Signal text, no media) is small per message; 20k UrlFetch/day at ~1 fetch per batched round trip is **ample for text**, consistent with the draft's "messaging-grade." GooseRelay's "real-time apps exhaust quota in hours" is about *media/streaming*, not text.
- Per-recipient-per-day capacity and battery draw of the long-poll loop under Android VpnService are **not measurable from the repo** — this is exactly a claim for the Sony spare (memory: Sony is free to wipe, `adb -s`). Flag for the on-device list.

### 38. Which GFE IPs / SNI names pass per ISP, `mail.google.com` reported targeted, is an in-app scan of a few dozen enough — **PARTLY (scan needed; "enough" is marginal)**
- #313 (27 Apr 2026): a scan of 28 Google front IPs found **only one (216.239.38.120) reachable** from that vantage — so a scan is mandatory and reachability can **collapse to a single IP**, meaning "a few dozen" is enough to *find* a survivor only when one exists at all. On RST/throttle days none pass.
- `mail.google.com` "targeted in Iran at various times" is a project claim (Rust guide) consistent with the draft; `www.google.com` is the safer default SNI used by both tools.
- Per-ISP and time-varying; needs an Iran vantage. **Verdict PARTLY.**

### 39. An end-to-end framed carrier (no CA install) carries Telegram/WhatsApp TCP — works as a sing-box upstream, not just HTTP — **VERIFIED in design (GooseRelay/MooseRelay), net-new build in Daal**
- GooseRelay/MooseRelay are exactly this: a **SOCKS5** front end → AES-256-GCM-framed raw TCP in batches → Apps Script forwarder (never sees plaintext, ~30 lines) → exit VPS that demuxes by `session_id`, dials the real upstream on SYN, and long-polls responses (pkg.go.dev/github.com/kianmhz/GooseRelayVPN/internal; MooseRelay exit docs). Zstd-compressed, GCM-tag-authenticated, no local CA. This is the design the draft wants and it **does** carry arbitrary TCP.
- Contrast with MasterHttpRelayVPN's *MITM* mode, which installs a local root CA and **breaks Telegram over SOCKS** because SOCKS hands it resolved IPs (`intel:109`, README forces Telegram to HTTP mode). The framed-TCP GooseRelay design is the one to copy precisely because it avoids the CA and the Telegram break.
- **As a sing-box upstream:** the carrier returns a `net.Conn` per session; put it under sing-box the same way the draft proposes for the desync dialer — either (1) a Daal-registered custom outbound used as `detour`, or (2) a loopback SOCKS5 inlet the outbound points at. The draft's own preference for (1) (per-UID isolation on Android, `core/bootstrap/fetcher_dialer.go`) applies identically here. Note the current engine wires outbounds via sing-box's own registration (`core/engine/config.go:180-223`, `tcpOnlyOutboundTypes`); a custom carrier outbound is new registration code, not a config toggle.
- **Verdict VERIFIED (design) / net-new (Daal).** Size **L**: client carrier package (frame/session/long-poll, GCM, Chrome uTLS+h2 front) + an exit endpoint on the relay + the Apps Script forwarder + sing-box integration.

### 40. Google ToS / suspension behaviour; a dedicated-account rule for publishers — **PARTLY VERIFIED (risk is real; policy unquoted)**
- GooseRelay disclaimer: misuse of Apps Script "may lead to suspension of your Google account or deployment"; its threat model lists a **compelled Google account** as an out-of-scope failure. This is relay-as-proxy, clearly outside Apps Script's intended use.
- Consequence for Daal: the publisher's Google account is **phone-number-identity-bound**, and a suspension takes out **every recipient under it at once** (same single-point-of-failure the draft flags for Cloudflare). Google also sees the relay IP and volumes. The draft's "dedicated publisher account" recommendation is sound and should be a hard rule, but note burn-and-replace (≈60 s, `intel:109`) partly offsets a suspension only if the publisher can create fresh accounts — which itself needs a phone number and is an "Explicit permission required: create account" action, not something Daal should automate.
- **Verdict PARTLY** — suspension risk VERIFIED qualitatively; exact Google enforcement thresholds UNKNOWN.

## Group-C-only use: same carrier for the small signed refresh payloads, not data — **feasible, far safer, better fit than P4-as-data**

This is the strongest use of the Google front in Daal, and more defensible than the data carrier.

- **Quota is a non-issue.** A refresh/rendezvous fetch is one `doGet` returning a 30–60-byte micro-hint or the signed `daal/freshness-v2` document (`publisher/deploy/freshness/doc.go`). Even thousands of recipients polling on failure sit far under 20k UrlFetch/day, and failure-triggered (not scheduled) fetches keep volume tiny. The 300–800 ms latency is irrelevant for a hint.
- **No exit VPS, no raw-TCP framing, no CA** — `doGet` returns the bytes directly (optionally `UrlFetchApp` to the relay for a live hint, but a static hint in the script or in Script Properties avoids even that). This removes the whole exit-endpoint and session/framing build that the data carrier needs.
- **Where it plugs in — two options, one clean, one blocked:**
  - **As a freshness mirror provider — clean.** `publisher/deploy/freshness/mirrors.go:106-117` defines `Provider` as an **open** lowercase-token set ("the set is open because the point is provider DIVERSITY") with backends under `publisher/deploy/freshness/backends/` (`ghpages`, `r2`, `ipfs`). Adding an `appsscript` provider/backend that publishes the freshness document to a web app, and a recipient fetch path that fronts it, is **in-bounds** and does not touch a locked invariant. Size **M**.
  - **As a rendezvous channel — roadmap-level, effectively blocked.** `core/rendezvous/channels.go:32-40` is an explicitly **closed v1 taxonomy** of five (`domain_fronted_broker`, `sqs`, `amp_cache`, `push`, `offline_hint`) — "Adding a sixth value is" (comment truncates but the intent is a closed list, enforced by `IsKnownChannel`). So a Google-front *rendezvous channel* is a spec change, not code. The `amp_cache` channel is already a Google-CDN HTTPS fetch (`specs/rendezvous-channels-v1.md:35`), so the taxonomy already has a Google-shaped slot — but it is a broker-solicitation channel (`NewAMPCache(s Solicitor)`, `core/rendezvous/impls.go:48-49`), and none of the five impls are wired to the engine yet (no `New*` caller outside tests). Treat Google-front rendezvous as "fold into the existing `amp_cache`/fronting channel spec," not a new channel.
- **The refresh dialer guard applies and helps.** `core/refresh/dialer.go` fails **closed** while a route is up unless a tunnel-aware dialer is installed (`ErrTunnelRequired`, documented leak of 2026-08-17). A Google-front *refresh* fetch is precisely the "direct fetch only when no tunnel is up" case the draft wants (its Carrier-2 note). The fetch must still obey that guard: when a route is up it rides the tunnel; the Google front is for when the route is **down** (the failure-triggered path), which the draft's lifeline change (allow failure-triggered hint fetches in `lifeline-strict`) is written for.
- **Fingerprint cost is lower for refresh.** A single short request looks far less like "sustained POSTs to 216.239.38.120" (the Python kill signature, `intel:109`) than a data tunnel does. Still should use the metacubex/utls Chrome hello (claim 33) rather than the current plain-`crypto/tls` fetcher.
- **Verdict: feasible and recommended over data-carrier P4.** Build it as an `appsscript` **freshness mirror backend + fronting fetch path**, reuse the existing signed-document verification (`VerifyMirrors`, mirrors.go:465) and the tunnel-required guard. Size **M**. The data carrier (P4 proper) stays **L** and allowlist-day-only.

## Sources fetched today (2026-11-20)
- Apps Script quotas: https://developers.google.com/apps-script/guides/services/quotas
- ContentService redirect to script.googleusercontent.com: https://developers.google.com/apps-script/guides/content
- Web app deploy / execute-as / access: https://developers.google.com/apps-script/guides/web ; projects.deployments (`ANYONE_ANONYMOUS`): https://developers.google.com/apps-script/api/reference/rest/v1/projects.deployments
- Apps Script API needs user opt-in, no service accounts: https://developers.google.com/apps-script/api/concepts
- GooseRelayVPN design/defaults/limits/Android/suspension: https://github.com/kianmhz/GooseRelayVPN and https://pkg.go.dev/github.com/kianmhz/GooseRelayVPN/internal (v1.7.1, 23 May 2026)
- MasterHttpRelayVPN-RUST Iran outage thread: https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/313 (27–28 Apr 2026, single-project)
- Late-2026 Iran regime (TCP cut after few packets, Cloudflare needs ECH): https://github.com/net4people/bbs/issues/676 (18 Oct 2026, single author, unverified)

## On-device / Iran-vantage items this read-only pass could not close
Claim 32 current Nov state; 35 (IP+odd-port fetch, egress ranges); 37 (throughput/battery/recipients — Sony); 38 (which IPs/SNI pass per ISP — Iran vantage); 33 h2-fingerprint capture-and-compare vs current Chrome. Everything dated after Oct 2026 on the Google front is **UNKNOWN**.

## Repo files relied on
`core/go.mod:10,67,69,152`; `core/bootstrap/fetcher.go:80-215` (esp. 106-107, 149-157); `core/refresh/dialer.go` (ErrTunnelRequired, 2026-08-17 leak note); `publisher/deploy/freshness/mirrors.go:100-117,465`; `publisher/deploy/freshness/doc.go`; `publisher/deploy/freshness/backends/{ghpages,r2,ipfs}`; `core/rendezvous/channels.go:32-84`; `core/rendezvous/impls.go:35-49`; `specs/rendezvous-channels-v1.md:19-35`; `core/engine/config.go:180-223`, `core/engine/platform_singbox.go:47-51`; `~/go/pkg/mod/github.com/metacubex/utls@v1.8.4/u_common.go:615`, `u_parrots.go:841,3127`.
# Appendix B: adviser draft


Read-only study: nothing was built or run. Repo facts were read this session. Field facts come from `research/` and from pages fetched today; several of those pages are user reports or machine-extracted summaries, and I mark them. ByeDPI internals and Android kernel behaviour are from my own knowledge, not checked here, so they sit in the verification list.

## 0. The correction to the earlier study

The owner is right that the earlier verdict ("nothing survives", FakeSNI/fronting/Apps Script at NEVER) misread the evidence. It is right about one thing only: 8–18 Jan 2026, when nothing based on ordinary connectivity worked (arXiv 2603.28753, fetched today). For every other period the evidence shows specific survivors.

| Regime | What the censor did | What kept people connected | Source |
|---|---|---|---|
| June 2025 "stealth blackout" | Protocol whitelist (53/80/443 shapes), SNI RST, IPs still routed | VLESS+REALITY; Psiphon over HTTPS (about 1/3 of baseline); Lantern "proxyless" (fragment/desync) kept about 40% | `research/filtering-the-flow.md:119` |
| 8–18 Jan 2026 total cut | Edge default-deny, even NIN briefly cut | Nothing over the network; Starlink and local mesh only | arXiv 2603.28753; `filtering-the-flow.md:121` |
| 26 Jan → 26 May 2026 allowlist / near-total | IP default-deny. Allowlisted: Google, Gmail, Meet, Maps, Bing, Outlook, GitHub, ChatGPT, Apple, Play, Samsung. A subset of Cloudflare IPs open but SNI-whitelisted (e.g. `hcaptcha.com`); other SNIs get about 6 packets. UDP/QUIC/WebRTC dead | (a) fake-ClientHello SNI spoofing to Cloudflare IPs, low-TTL and wrong-sequence variants, about 4 days in mid-April; (b) Akamai/Fastly edge IPs through a Psiphon fork; (c) DNS tunnels, "a week or two" on outside resolvers, then about 100 KB/s with drops near 1 minute on local ones; (d) Google Apps Script relays, viral in this window | net4people #626 (4 Jun 2026); #561; arXiv 2603.28753; `research/intel-and-some-working-methods.md:101,173` |
| After 26 May 2026 | Blacklist plus stronger DPI | REALITY and CDN routes with rotation. One report says 10–30 byte TCP fragments are reassembled and CDN domains are blocked within 24 h. Random SNIs pass, and an RST leaves no residual block | Lantern corpus (pooribitwise, Jun 2026, single user); net4people #630 (19 Jun 2026) |

Three conclusions shape the tier:

1. **In a blackout the gate is the destination IP, not our IP's secrecy.** A privately distributed Hetzner address is default-denied along with everything else (#626: "nearly all IPs blocked"). The tier must therefore end on addresses the censor re-opens: Cloudflare, Google, Akamai/Fastly, GitHub, and its own DNS resolvers.
2. **On those addresses the filter is SNI-based and was beaten at the packet level**, until a stateful NAT was put in front of Cloudflare ranges. That NAT was not on every ISP, and a NAT exit range still accepted fakes on 13 Apr before moving on 15 Apr (#626 comments).
3. **Every survivor was short-lived and per-ISP.** The tier has to be a ladder of independent paths with fast per-network selection and a refresh channel that can change it, not one transport.

## 1. Data paths

### P1. Publisher's own CDN-fronted relay (the foundation)
- **What:** VLESS over WebSocket/httpupgrade to the publisher's Cloudflare zone, origin = the relay. This is the existing `cdn_fronted` design (`publisher/deploy/cloudflare/doc.go`), which the earlier plan left at "build later".
- **Evidence:** Cloudflare, Azure, GCP and Akamai ranges are never wholesale blocked and are filtered by SNI only (`intel:81`). Cloudflare IPs were the first foreign addresses re-opened in the shutdown (#626). Counter-evidence: Irancell blocked all Cloudflare IPs on 16 Apr 2023 and per-IP blocking persists (`filtering-the-flow.md:129`); CDN-fronted domains blocked within 24 h (pooribitwise).
- **Censor must add:** an SNI blocklist entry per zone (it does, in about 24 h), or an SNI whitelist on Cloudflare IPs (it did, in the blackout). So P1 alone is a blacklist-day path. P2 and P3 make it a blackout path.
- **Android:** ordinary sing-box outbound, nothing special.
- **Additions I recommend:**
  - Wildcard proxied record plus a client-derived daily hostname (HMAC of a pack secret and the date), so blocking needs the whole zone, not one name.
  - Ship the ECHConfig inside the signed pack. Iran kills ECH by poisoning the DNS bootstrap, not in-band (`intel:79`); sing-box takes a static `ech.config`.
  - An account-less variant: `cloudflared` quick tunnel on the relay (no domain, no account), with the hostname delivered through the refresh channel. Unverified and against the spirit of Cloudflare's terms.
- **Risk:** needs a domain and a Cloudflare account (identity link, cost); Cloudflare sees traffic metadata; one account ban takes out all recipients.

### P2. Fake-ClientHello desync in front of P1 (the method that worked in April 2026)
- **What:** before the real hello, the DPI is shown a ClientHello with a whitelisted SNI that the server never accepts. The real hello (the publisher's zone) follows on the same connection.
- **Evidence:** SNI-Spoofing family, default target a Cloudflare edge with `auth.vercel.com` (`intel:115-126`). Worked about 4 days in both variants (#626). Worked about 2 days and "fully blocked since 18 Apr" on some ISPs, inconsistent across ISPs (sing-box issue #4044, 14–19 Apr 2026). sing-box 1.14 shipped it as `tls.spoof`, but only for Linux/macOS/Windows with elevated privileges, so upstream gives Android nothing.
- **Censor must add:** per-flow sequence and checksum validation with reassembly in front of the CDN ranges. It did, for Cloudflare, on most ISPs. Or a signature on "extra segment right after the handshake" (`intel:137`).
- **Non-root Android, precisely:**
  - **Impossible without root:** wrong-sequence, wrong-checksum, wrong-ack, wrong-timestamp. All need `SOCK_RAW`/NFQUEUE.
  - **Possible with an ordinary protected socket (to be proven on device):**
    - Low-TTL decoy, the #626 "method 1": ByeDPI's trick. Put the fake bytes in an mmap'd memfd, set `IP_TTL` low, `sendfile()` them (zero-copy, so the kernel's send queue references those pages), overwrite the pages with the real bytes, restore the TTL. The kernel's own retransmission then carries the real hello.
    - MD5-signed decoy: `TCP_MD5SIG` on the fake so a Linux server drops it. This survives a middlebox that rewrites TTL, but depends on the phone's kernel config.
  - TTL calibration without raw sockets: connect with rising `IP_TTL` and note where the handshake first completes; cache per network.
- **Honest limit:** a decoy made this way has a valid checksum and an in-window sequence number, so it is not what the April NAT validated against. But a NAT that terminates TCP or normalises TTL defeats the TTL variant. Treat P2 as opportunistic, tried per network and remembered.
- **Risk:** the pattern is a tool-class signature. If the decoy reaches the server, the connection simply fails. Use it only in the failure ladder, never as the default.

### P3. ClientHello fragmentation, reordering and record splitting
- **What:** split the hello across TCP segments or TLS records; optionally send the first segment with TTL=1 so it arrives out of order.
- **Evidence for:** the DPI inspects the first two data packets and does not reassemble (`intel:77`, Bock 2020, IRBlock 2025). Serverless-for-Iran chains 6-byte and 1-byte fragments (`intel:93`). Lantern proxyless held about 40% in June 2025. It is named in the April 2026 working composition (`intel:173`).
- **Evidence against:** pooribitwise (Jun 2026) says reassembly is now done on port 443; a related corpus note says clean-SNI fragmented hellos were blocked, i.e. the pattern itself is classified. I could not confirm a "July 2026 fragment drop" claim.
- **Censor must add:** reassembly for the first few hundred bytes (cheap), or dropping tiny first segments.
- **Android:** fully non-root: `TCP_NODELAY`, segmented writes, wait for ACK via `TCP_INFO` (sing-box already does this, `common/tlsfragment/wait_linux.go`), `IP_TTL=1` for disorder, `MSG_OOB`.
- **Engine facts read today:** `tf.NewConn` is applied only when `record_fragment` is set (`utls_client.go:61`, `std_client.go:53`), never on REALITY (`reality_client.go` builds the uTLS client on the raw conn), and it splits only when it finds an SNI (`conn.go:48-49`).
- **Why it still matters for REALITY:** REALITY already sends an allowed cover name, so splitting hides the hello's fingerprint, not the name. The sing-box REALITY client strips the X25519MLKEM768 key share (`reality_client.go`, the two filters before the second `BuildHandshakeState`), so its "chrome" hello may no longer match real Chrome. That is a plausible cause of the "REALITY gets RST floods" report and worth one capture.

### P4. Google-front carrier (emergency)
- **What:** TLS to a Google front-end IP with SNI from `{www,mail,drive,docs,calendar}.google.com`, HTTP Host = Apps Script. The script forwards opaque encrypted frames by `UrlFetchApp` to the publisher's relay. GooseRelay-style: end-to-end AES-GCM, no local CA, no MITM.
- **Evidence:**
  - Same-front-end routing still works (`intel:103`).
  - Google was on the 26 Jan allowlist (FilterWatch via arXiv 2603.28753).
  - MasterHttpRelayVPN spread fast in 2026 (`intel:101`); it is the named emergency fallback "when everything else is IP-swept" (`intel:173`).
  - GooseRelayVPN has an Android VpnService client (v1.7.x, May 2026).
  - The Rust port's guide calls `apps_script` the only mode that reliably works in 2026 (project claim). It also notes `mail.google.com` "has been targeted in Iran at various times".
- **Unique property:** the relay only has to be reachable from Google, so Hetzner graylisting and the IP default-deny stop mattering.
- **Censor must add:** block Google (it did not, outside the total cut); fingerprint non-Chrome TLS to AS15169 (`intel:109`); classify the steady POST rhythm; or Google closes the Host-routing quirk.
- **Android:** all ordinary sockets. Requirements: Chrome uTLS (`metacubex/utls` is already in `core/go.mod`), HTTP/2 over it, an IP and SNI scan per network. New code: an in-process carrier exposed to sing-box as a local SOCKS upstream or custom outbound, plus a small exit endpoint on the relay.
- **Limits:** about 20,000 fetches per day per free account, about 30 concurrent, 6-minute executions, roughly 2 s per batch (figures from the Rust port's guide; check Google's quota page). Messaging-grade.
- **Risk:** publisher's Google account (phone-number identity, suspension takes out everyone); Google sees the relay IP and volumes. Recipient-side, the traffic is "Chrome to Google", the least incriminating flow in this report.

### P5. DNS-shaped tunnel on 53/udp
- **Evidence:** dnstt "seems to work (very slow)" (Tor team, 20 Apr 2026, via search summary); "one of the very few still functioning" (#561, 2 Mar 2026, a claim). #626 gives the limits: outside resolvers lasted 1–2 weeks, then national resolvers only, about 100 KB/s and drops near 1 minute. ICMP was fully blocked.
- **Censor must add:** stop national resolvers recursing to non-allowlisted zones, or rate-limit TXT. One change.
- **Android:** ordinary UDP sockets to the network's own resolvers. Needs the pre-VPN DNS servers from the host, an in-process dnstt-class client, and on the publisher side a domain with NS delegation and 53/udp open.
- **Risk:** the most identifying path. Queries pass an identity-bound SIM's resolver, and logs are retrospective. Lifeline only, text only.

### P6. Desync or fragmentation in front of REALITY on the direct VPS
The April 2026 composition (`intel:173`). Useful on blacklist and protocol-whitelist days (June 2025 class), useless under IP default-deny. Same mechanics as P2/P3; cheap once the dialer exists. For SNI-whitelist-with-open-IPs phases, the refresh channel should also be able to push a new REALITY cover name from the allowlisted set. Counter: the censor's own plan whitelists by FQDN + IP prefix + port (`intel:29`), which defeats an allowlisted name on a Hetzner address.

### Where the desync dialer goes in Daal
One small Go package (working name `core/desync`) that returns a `net.Conn` whose first `Write` applies the chosen strategy. Two ways to put it under sing-box:
1. a Daal-registered outbound used as `detour` (the registry is built at `core/engine/side_singbox.go:173` and `engine_singbox.go:254`), or
2. a loopback forwarder the outbound's `server` points at.

Prefer (1): on Android loopback has no per-UID isolation (the repo already notes this in `core/bootstrap/fetcher_dialer.go`). Sockets go through `invokeProtect` (`core/engine/platform_singbox.go`), and the app is also excluded from its own VPN (`DaalVpnService.kt:414`). Strategy and decoy names travel in the signed pack and are overridable by refresh. The winning strategy per network is stored in netmem, like `last_winning_rendezvous_channel`.

## 2. Reserved refresh / rendezvous channel

### Principle: the update says "where", never "who"
REALITY public keys, pinned certificates and user credentials are already in the signed pack, so a new address is only a hint: a forged hint cannot impersonate the relay, it can only waste a dial. That allows a **micro-hint** of about 30–40 bytes: sequence, addresses/ports or hostname, optional strategy id, 16-byte tag, encrypted and authenticated under a key derived from a pack secret. The full path stays the existing signed `daal/freshness-v2` document (`publisher/deploy/freshness/doc.go`: sequence, `not_after`, padding, mirrors). Two rules:
- **Hints must be encrypted and their locations derived** (HKDF of pack secret and epoch). Publishing the relay IP in a public object or A record would hand it to passive DNS and break "our IP is not visible".
- Hints follow the existing rule: direct fetch only when no tunnel is up (`core/refresh` tunnel-required guard).

### Carriers, in the order the client tries them after a route dies
| # | Carrier | Why the censor keeps it | Payload | Build on |
|---|---|---|---|---|
| 0 | Standby addresses already in the pack (reserved floating IPs, not yet used) | No fetch at all | none | relaypack candidates |
| 1 | DNS through the network's own resolver: derived label under the publisher's zone, answer = encrypted hint in TXT, or in 3 AAAA records, which look more ordinary than TXT | 53/udp always passes the whitelister (`filtering-the-flow.md:99`); allowlisted services need recursion | micro-hint | `miekg/dns` is already an indirect dep; `cloudflare/dns.go` writes records |
| 2 | Google-front fetch: Apps Script `doGet` returning the hint or freshness document, fronted as in P4 | Google allowlisted | hint or full document | new freshness provider (`mirrors.go` provider set is open) |
| 3 | GitHub on SNI `github.com` itself (e.g. a commits Atom feed or release page), not `github.io` or `raw.githubusercontent.com`, which are other names | GitHub allowlisted | micro-hint | sibling of `backends/ghpages` |
| 4 | CDN object on Cloudflare (R2 behind the publisher's zone), fetched with the same P2/P3 dialer | Cloudflare ranges | full document | `backends/r2` |
| 5 | Push (FCM) | Google allowlisted; unproven in a blackout | signed hint | `specs/push-rendezvous-v1.md`, stays opt-in |
| 6 | Human-carried code: 12 words or about 30 characters, by SMS, voice, or a domestic messenger | Works in a NIN-only cut | micro-hint | `offline_hint` channel; `.sbpx` import |

Notes:
- Carriers 1–4 are publisher-operated, which respects the locked invariant "project never operates a rendezvous registry" (`specs/rendezvous-channels-v1.md`). The channel list there is closed at five, so adding DNS, Google-front and GitHub as rendezvous channels is a roadmap-level change. Adding them as freshness mirror providers is not.
- The bootstrap pointer hosts are still placeholders (backlog W3-1), and mirrors have never touched a real endpoint (W3-7). Those are prerequisites, not blackout work.
- Carrier 6 is watched by the state. Copy must say so, the code must contain nothing but the encrypted hint, and it should be the last resort.

### Rotation speed (targets, none measured)
- **Standby address in pack:** zero publisher-to-recipient delay; the recipient fails over on its own.
- **Floating-IP swap:** code budget 15 s (`L3FastPathBudget`, `publisher/deploy/rotation/postconditions.go:51`), never measured (backlog W3-10).
- **Hint publish:** one API call per carrier. DNS TTL 60 s, but national resolvers may cache longer.
- **Recipient pickup:** triggered by failure, not by schedule. The ladder above should finish in 1–3 minutes.
- **The gap is detection:** the publisher abroad cannot see an Iran-side block. Proposal: the relay notices "hint fetches continue, tunnel handshakes stopped" and notifies the publisher's phone for a one-tap rotation. Do not put the provider token on the relay.
- **Rotation inside Hetzner has bounded value** ("Hetzner is graylisted", `intel:81`). The hostname or zone on Cloudflare (P1) and the Apps Script deployment (P4) are the assets worth rotating in a blackout; both are API-only or a 60-second redeploy.

## 3. Lifeline in a blackout

Today `lifeline-strict` means a 0.33× cap, a stability-biased ranker, and scheduled refreshes skipped (`specs/lifeline-mode-v1.md`). For a blackout it should mean:
- **Classify first, with four cheap probes:** a domestic anchor, a Google front-end, a Cloudflare IP carrying more than 6 packets of data, and a DNS recursion to a foreign zone. Outcomes: normal, blacklist, allowlist, NIN-only.
- **Paths by class:**
  - allowlist → P4, then P1+P2/P3, then P5;
  - NIN-only → no data path. Say so, back off (doubling, capped), and accept only carrier 6.
- **Refresh gate change:** failure-triggered hint fetches must run in lifeline. Only scheduled polls stay gated.
- **Budgets:** per-device daily request cap on P4 (the publisher's 20k/day is shared by the whole family); byte cap on P5; optional "messengers only" using VpnService per-app allow-listing; no background updates.
- **Honesty:** reuse the non-dismissible "Limited capacity" pill (`specs/bootstrap-tiers-v1.md`). Name the state ("emergency link: text only, slow, may stop"). Never show plain "connected" on P4/P5. Show which carrier is in use. In NIN-only, show "no way out right now" rather than a spinner. Farsi copy under `farsi/STYLE.md`.
- **Scanning discipline:** clean-IP and SNI scans only in the failure state, at most a few dozen paced probes, results cached per network.

## 4. Suggested order
1. `core/desync` dialer with split, record-split and disorder (P3), plus a censor-lab scenario for "first two packets, no reassembly" beside the existing `stateful-reassembly.json`. Smallest step, and it unlocks P2 and P6.
2. Finish `cdn_fronted` (P1) with derived hostnames and pack-shipped ECH.
3. Low-TTL and MD5 decoys on the two phones (P2), behind the device checks in list A.
4. Micro-hint plus the DNS and Google-front carriers; standby addresses in the pack.
5. Google-front data carrier (P4) and blackout lifeline semantics.
6. DNS tunnel (P5) last: largest, most identifying.

The modifier specs must change with this: `client_desync.md` says "raw-socket, Linux desktop only", which is true only of the wrong-sequence family; `tls_fragment.md` is PENDING with an empty platform list.

## 5. Claims to verify before building

### A. Non-root desync on Android
1. A dialer registered as a custom outbound and used as `detour` receives the REALITY/uTLS ClientHello as a single first `Write` in sing-box 1.13.12.
2. `getsockopt(TCP_INFO)` and `tcpi_unacked` work from the app on both test phones (`wait_linux.go` compiles and runs under GOOS=android).
3. `setsockopt(IP_TTL)` on a connected, protected TCP socket takes effect per segment, and a later retransmission uses the restored TTL.
4. The sendfile-from-mmap'd-memfd trick makes the kernel retransmit the overwritten (real) bytes on the phones' kernels; `memfd_create` is allowed by the app seccomp filter (else an unlinked cache file works).
5. ByeDPI's current source does use this mechanism (sendfile versus vmsplice/splice) and its licence allows reuse or reimplementation in a GPLv3 app.
6. `TCP_MD5SIG` is settable unprivileged on the Samsung and Sony kernels, and a Cloudflare edge and a stock Linux relay drop a segment carrying it.
7. A TTL=1 first segment yields the intended reorder on the wire (capture on the relay), on Wi-Fi and on mobile CGNAT.
8. Hop count to a server can be measured unprivileged by rising-TTL `connect()`, and a decoy TTL exists that passes the border hop but dies before a Cloudflare edge on MCI, Irancell and TCI.
9. A TTL-limited or MD5 decoy still passes on an ISP where the April 2026 NAT is deployed (needs an Iran vantage; worldbox cannot answer this).
10. `MSG_OOB` and a small `TCP_MAXSEG` behave as expected from the app, and a clamped MSS limits our own first-flight segment size.
11. sing-box's reality client hello (MLKEM key share stripped) differs from current Chrome's JA4; capture and compare.
12. `record_fragment` on the websocket-tls uTLS path produces the split on the wire once that tier carries a real SNI.

### B. CDN hiding and clean IPs
13. Cloudflare still refuses SNI≠Host across zones (expect 403/421), so a whitelisted SNI with our Host is not available without desync.
14. A Cloudflare free zone accepts a static ECHConfig shipped in the pack, how often that config rotates, and whether sing-box 1.13.12 handles ECH retry configs.
15. A wildcard proxied record plus the edge certificate serves arbitrary derived subdomains over WebSocket on the free plan.
16. `cloudflared` quick tunnels carry WebSocket for hours without an account, and what the terms say.
17. A probe can tell "white" from "grey" (6-packet) Cloudflare IPs by transferring more than 6 data packets; define the probe and its false-positive rate in censor-lab.
18. Which Cloudflare /24s and which decoy names currently pass per ISP (Iran vantage).
19. The Cloudflare free plan's DDoS rules do not flag our VLESS-over-WS pattern (`filtering-the-flow.md:129`, 2024).
20. The Hetzner firewall rule locking the origin to Cloudflare ranges (`edge_ranges.go`) can be applied from the phone flow.

### C. Refresh / rendezvous channel
21. Iranian national resolvers recurse to an arbitrary foreign zone today, and return TXT or multiple AAAA records intact (order, truncation, EDNS size).
22. The host can give the engine the underlying network's resolver addresses while the VPN is up (`NetworkWatch.kt`).
23. A micro-hint (sequence + address + 16-byte tag) fits in 3 AAAA records or one TXT string, and in 12 words of the trust word list (backlog H1 says that list is still a placeholder).
24. Accepting an unauthenticated-origin address hint is safe for every family: each one authenticates the server from pack material (REALITY key, pinned cert) and none trusts the address.
25. Where the pack secret for hint keys comes from, and that a leaked pack exposes only hint locations, not other publishers.
26. `github.com` itself (not `github.io`/`raw.githubusercontent.com`) serves a fetchable, unauthenticated, rate-limit-tolerant object that can hold 60 bytes (Atom feed, release page).
27. Apps Script `doGet` with "Anyone" access returns content through the Google front without login, including the redirect to `script.googleusercontent.com`.
28. FCM delivery uses a 443 fallback that an allowlist would pass.
29. Measured wall-clock for floating-IP swap (W3-10) and for a fresh provision to first handshake.
30. Failure-triggered hint fetches are permitted in `lifeline-strict` and still obey the tunnel-required guard.
31. Hetzner lets a project hold reserved, unattached addresses as standbys, and their cost.

### D. Google-front carrier
32. SNI `www.google.com` with Host `script.google.com`/`script.googleusercontent.com` still routes today, from outside and from Iran, over HTTP/2.
33. `metacubex/utls` Chrome hello plus `x/net/http2` gives a JA4 and h2 settings fingerprint matching current Chrome.
34. Current free-account quotas: UrlFetch calls per day, concurrent executions, execution time, payload size, and the real round-trip latency.
35. Apps Script can reach the relay on a non-standard port by IP with a self-signed or pinned certificate (`validateHttpsCertificates`), and what egress IP ranges it uses for a relay firewall rule.
36. A publisher can deploy the script from a phone browser with copy-paste only, without OAuth verification.
37. Throughput and battery for a messaging workload on the spare Sony through VpnService, and how many recipients one deployment carries per day.
38. Which Google front-end IPs and SNI names pass per ISP (`mail.google.com` is reported targeted), and whether an in-app scan of a few dozen addresses is enough.
39. An end-to-end framed carrier (no CA install) carries Telegram/WhatsApp TCP, i.e. it works as a sing-box upstream, not only for HTTP.
40. Google's terms and suspension behaviour for this use, and a dedicated-account rule for publishers.

## Sources fetched today
- net4people #626, "Internet analysis in the shutdown in Iran", 4–7 Jun 2026: https://github.com/net4people/bbs/issues/626
- net4people #561, shutdown thread, Jan–Sep 2026: https://github.com/net4people/bbs/issues/561
- net4people #630, allowlist study, 19 Jun 2026: https://github.com/net4people/bbs/issues/630
- arXiv 2603.28753, Jan 2026 shutdown, 30 Mar 2026: https://arxiv.org/html/2603.28753v1
- Lantern corpus (machine-extracted, "review before relying"): https://corpus.lantern.io/papers/2026-tuleo1-internet-analysis-shutdown/ and https://corpus.lantern.io/findings/2026-pooribitwise-iran-advanced-dpi__iran-dpi-tcp-reassembly-defeats-fragmentation/
- sing-box issue #4044 (14 Apr–25 Sep 2026) and TLS docs (`spoof`, 1.14, elevated privileges, no Android): https://github.com/SagerNet/sing-box/issues/4044 , https://sing-box.sagernet.org/configuration/shared/tls/
- ByeDPI README (option semantics only): https://raw.githubusercontent.com/hufrea/byedpi/main/README.md
- snix (root-only, wrong_seq/wrong_checksum, scanner): https://pkg.go.dev/github.com/SamNet-dev/snix
- MasterHttpRelayVPN-RUST guide and GooseRelayVPN Android client: https://github.com/therealaleph/MasterHttpRelayVPN-RUST/blob/main/docs/guide.md , https://github.com/Hidden-Node/GooseRelayVPN-AndroidClient

I found nothing dated after September 2026, so the current (November) state of the NAT, of fragment reassembly and of the Google front is unknown.

Repo files relied on: `/home/nima/Projects/daal/research/intel-and-some-working-methods.md`, `/home/nima/Projects/daal/research/filtering-the-flow.md`, `/home/nima/Projects/daal/docs/exotic-transports-plan.md`, `/home/nima/Projects/daal/specs/modifiers/client_desync.md`, `/home/nima/Projects/daal/specs/modifiers/tls_fragment.md`, `/home/nima/Projects/daal/specs/lifeline-mode-v1.md`, `/home/nima/Projects/daal/specs/rendezvous-channels-v1.md`, `/home/nima/Projects/daal/publisher/deploy/freshness/doc.go`, `/home/nima/Projects/daal/publisher/deploy/rotation/postconditions.go`, `/home/nima/Projects/daal/publisher/deploy/cloudflare/doc.go`, `/home/nima/Projects/daal/core/engine/platform_singbox.go`, and sing-box 1.13.12 `common/tlsfragment/conn.go`, `common/tls/utls_client.go`, `common/tls/reality_client.go`.