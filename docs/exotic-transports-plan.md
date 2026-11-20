# Exotic transports for Iran: study, plan and review (2026-11-20)

Read-only study by six analysts over research/ and the code, a lead's plan, and a sceptical review. The review's corrections override the plan where they disagree. Per-candidate analyses: see the cluster sections at the end.

---


**Read this first: the input was cut short.** The JSON I received holds 4 of the 6 clusters: UDP/WireGuard, Tor, CDN/fronting, and TLS/handshake. The TLS cluster stops partway through the FakeSNI entry. Two clusters never arrived, and neither did ShadowTLS v3, Trojan-with-fallback or the REALITY variants. Going by what the analysts point at, the missing clusters are most likely (a) DNS-shaped traffic on 53/udp and (b) whitelisted ports such as 80/tcp or a second IP. Rows marked **(lead)** below are my own provisional reading of research/ and the code. No analyst studied them. Re-run those two clusters before you commit to anything in Wave 3.

Things I checked in the tree myself:
- `bundle/go/uri/vless.go:89-90` writes `spider_x`.
- `bundle/go/uri/hy2.go:18` uses `strconv.Atoi(u.Port())`.
- `live_client.go:383` calls `SetRules`.
- Daal is GPLv3.
- worldbox already has `quic-drop`, `port-whitelist`, `protocol-whitelist`, `relay-ip-block` and `total-blackout`.
- censor-lab already has `amneziawg-signature`, `wireguard-signature`, `ech-bootstrap-fail` and `stateful-reassembly`.

**The fact that shapes the whole ranking.** Our stable four (vless-reality, naive, websocket-tls, hysteria2) all share one Hetzner IP. They fail together when hosting-company IPs are graylisted. The candidates below add new reach in only three ways:
1. A different IP: third-party servers reached through pasted links, Tor, or Google via Apps Script.
2. Surviving a whitelist that lets Google through (Apps Script only).
3. Surviving a filter that blocks only QUIC (salamander, AmneziaWG). This one is worth little, because the censor's stated plan is to block all outbound UDP.

Nothing survives a full NIN-only shutdown like Jan 8-18, 2026. No candidate changes that, and we should say so in the app.

---

## 1. Every candidate

Ind. = fails independently of the stable four. Size: S (small), M (medium), L (large).

| Candidate | Works in Iran (short) | Ind. | Dial / serve in this repo today | Size | Rec. |
|---|---|---|---|---|---|
| Importer: REALITY `spider_x` + missing `fp`, Trojan `fp`/family | Most-shared link format; today it fails to parse but shows a stable badge | y* | dial: broken (strict parse rejects); serve: n/a | S | **W1** |
| Importer: vless/trojan `httpupgrade`/`xhttp`/`splithttp` | CDN links are everywhere; reach varies by CDN | y* | httpupgrade dials; xhttp silently becomes plain TCP | S | **W1** |
| Importer: hy2 port-hopping ranges | Only on days when UDP flows | y* | engine dials it; importer rejects "invalid port" | S | **W1** |
| Importer: AmneziaWG honesty + 2.0 fields | n/a (copy fix); users hold real AWG configs | n/a | downgrade copy promises a connection that can't happen | S | **W1** |
| Hand-off card (Psiphon / Lantern / Orbot) | Psiphon about 9.6M daily users, survives whitelist phases | y | UI only | S | **W1** |
| Honesty copy: hysteria2 Iran caveat, webtunnel "contested", fragment no-op | hy2: QUIC 100% dropped since mid-2025 | n/a | docs and rationale only | S | **W1** |
| Fix `FirewallApplyCloudflareRule` (SetRules wipes all rules) | n/a (latent bug, reachable via `cdn-provision` CLI) | n/a | bug | S | **W1** |
| uTLS JA4 measurement of our hellos | Unknown; may explain June 2026 REALITY resets (single report) | n | measure in worldbox | S | **W1 (measure)** |
| Tor runtime packaging (libtor + one liblyrebird, arm64) | Carries obfs4, Snowflake and WebTunnel, "the main ones for Iran" (Tor, Jan 2026) | y (IP) | dial code exists; no binary shipped | L | **W2 (device spike gate)** |
| Snowflake, built-in default lines | Works outside shutdowns; most Snowflake users are Iranian; dead in shutdowns and under UDP blocks | y (IP), n (UDP) | after packaging | M | **W2** |
| obfs4 / WebTunnel bridge lines (paste, QR, pack) | obfs4 partly; WebTunnel contested | y (IP) | parser done, CM-8 UI unwired | M | **W2** |
| Real SNI on websocket-tls / hysteria2 | No-SNI hello probably fails an SNI allowlist; ws on 8445 is outside the whitelist anyway | n | relay certificate change | M | **W2 (relay bundle)** |
| Hysteria2 salamander + port hopping | Corpus: "largely non-functional"; passes a QUIC-only filter | partly | engine dials; relay needs a second inbound + nftables | M | **W3 spike → W2** |
| AmneziaWG dial (Daal-registered endpoint) | Works on blacklist days on some paths; dead under whitelist | partly | not dialable; MAC1 question unverified | L | **W3 spike** |
| Apps Script end-to-end carrier (GooseRelay-style) | Google stayed allowlisted in Jan 2026; unmeasured for this design | **y** | nothing exists | L | **W3 spike, priority 1** |
| TCP family on 80/tcp, or a second IP on 443 **(lead)** | 80 is in the whitelist; relays have 80 free; TLS-on-80 vs the protocol whitelister unknown | n (IP), y (port) | relayports change | S-M | **W3 spike (worldbox first)** |
| DNS-shaped tunnel on 53/udp (dnstt / slipstream class) **(lead, no analyst)** | Only UDP the stated plan keeps, if it passes the "DNS wire format" check (intel:77); very slow | y | nothing | L | **W3 (rerun analyst)** |
| Finish cdn_fronted (Cloudflare WS/httpupgrade) | Partly; June 2026 single report: domains blocked in about 24h | partly | control plane only, no data plane | L | Later (gated on W3 measurement) |
| ECH on the CDN route | Targets exactly the SNI blocklisting; one SNI rule kills it | n | dials today (static config) | S | W3 spike (needs a CF zone) |
| httpupgrade / gRPC behind CDN | Unmeasured | n | dials today | S | Later (rides on CDN) |
| Workers as the exit | Mostly blocked; highest ToS exposure | partly | dials; Worker upload exists | M | Later |
| Second CDN (Fastly, Gcore) | Fastly fading; Gcore no evidence | partly | no provider abstraction | L | W3 spike (low) |
| XHTTP / SplitHTTP | Thin evidence; not in sing-box 1.13.12 | n | needs a fork or second core | L | W3 (watch upstream) |
| Conjure via Tor | Psiphon uses it; no Tor bridge supply for Iran | y | separate PT binary | M | W3 (watch) |
| AmneziaWG serve | Same as dial | partly | second daemon on relay | L | Later (after dial wins) |
| WARP as relay exit hop | Not circumvention; exit reputation only | n/a | relay outbound | M | Later (only if Hetzner exits get refused) |
| ShadowTLS v3 / Trojan-fallback **(lead)** | Same IP; needs a non-whitelisted port (443 is REALITY's) | n | dials; relay would need a port | M | Later (Trojan fallback may cure the anytls/ss RST tell; not Iran reach) |
| WARP direct (incl. scanned endpoints, noise) | Named block target; vendor claims a 100% signature | n | dials | n/a | **Never** |
| TUIC on 443/udp | Same QUIC drop; socket clash (BUG-14) | n | — | n/a | **Never** |
| Any further QUIC-shaped family | One shared fate | n | — | n/a | **Never** |
| meek | No fronting CDN left | — | — | n/a | **Never** |
| Tor bridge hosted on our relay | Same IP as the stable four, slower | n | — | n/a | **Never** |
| Psiphon Conduit on our relay | Broker hands the relay IP to many clients, censor sensors included | — | — | n/a | **Never** |
| Classic domain fronting | Every self-serve CDN enforces SNI==Host | — | — | n/a | **Never** |
| patterniha MITM / MasterHttpRelayVPN | Root CA on the device; browser-only; plaintext to Google | — | — | n/a | **Never** |
| ArvanCloud front | Sanctioned; cooperates with the censor | — | — | n/a | **Never** |
| Domestic SNI as REALITY cover | The whitelist gate is the IP; SNI/IP mismatch is a tell | n | — | n/a | **Never** |
| TLS fragmentation as a feature | No-op on all our tiers in sing-box 1.13.12; reportedly reassembled | n | — | S | **Never** (close the spec) |
| FakeSNI / out-of-window injection | Needs root on Android; lasted about 4 days in 2026 | n | — | L | **Never** |

\* The importer fixes are real new reach, not just hygiene. A pasted link points at **someone else's server on someone else's IP**. When our relay IP is burned, those routes are the user's only non-Tor way in.

## 2. Ranking: new reach per unit of work

Measured against the censor's plan: block all UDP, ICMP and IPv6; whitelist; national CDN; shutdowns.

1. **Importer fixes (S).** They turn routes users already hold, on IPs we don't share, into working ones. Best ratio by far.
2. **Hand-off card (S).** For a user who has run out of routes, it points to the one network that survives whitelist phases (Psiphon). Honest today.
3. **Tor packaging (L), which unlocks three transports in one binary.** Independent of our IP, and Tor's 2026 reports say these are what Iranians use. It loses to shutdowns and, for Snowflake, to the UDP plan. obfs4 and WebTunnel are TCP and outlive the UDP plan.
4. **Apps Script carrier (L, spike first).** The only candidate that survives a whitelist which keeps Google. Its weak points are cost, ToS, quota and a classifiable traffic rhythm, which is why it stays a spike.
5. **Whitelisted-port tier (S-M, spike).** It adds no new IP, but under `port-whitelist` only one TCP family survives today (vless-reality). A second family on 80 is cheap redundancy against REALITY-specific kills.
6. **Real SNI on ws/hy2 (M).** Hardens existing tiers; the payoff is small while ws sits on 8445.
7. **Salamander hy2, AmneziaWG dial.** Only help against a QUIC-only filter that the censor intends to widen to all UDP. Low.
8. **CDN family (cdn_fronted, ECH, Workers, second CDN).** The 2026 evidence (one report) says domains die in about 24h. Measure before investing.

**About "handshake tricks" as cheap Wave 1 wins.** The analysis shows they mostly do not exist for us. `fragment` is a no-op on every one of our tiers. FakeSNI cannot run on non-root Android. ECH does nothing on a self-hosted relay. The one handshake lever that might pay is the uTLS fingerprint: sing-box's REALITY client strips X25519MLKEM768 from the Chrome 133 parrot, so our REALITY hello matches no real browser. That needs measuring before any change.

## 3. Wave 1 and Wave 2: the work

### Wave 1: build now (all S; no relay change, no pin bump)

**W1-A. Importer honesty bundle. Lane A owns `bundle/go/uri/*`.**
- Changes:
  - `vless.go`: drop `spx`/`spider_x`; default `fp=chrome` when `security=reality`; add the `httpupgrade` case (path, host, `ed=` early data); refuse `xhttp`/`splithttp`/`h2` and any unknown type with a named error; optionally map ws+tls to `websocket-tls`.
  - `trojan.go`: honour `fp`; use one family consistently, aligned with `core/refresh/parse.go:225`.
  - `hy2.go`: parse port ranges and `mport` into `server_ports` + `hop_interval`; confirm the import path skips the signed-pack guard at `bundle/go/bundle/endpoint.go:411-417`.
  - `wireguard.go`: add the AWG 2.0 fields (S3/S4/I1-I5/J1-J3/ITIME) and a compatibility predicate. Only Jc/Jmin/Jmax set: downgrade with today's copy. Otherwise: import as an unselectable `amneziawg` route (it already renders "unsupported").
  - `specs/uri-import-v1.md`.
- Test: fixtures in `uri_test.go`, plus **a new test that feeds every parser's output through `singjson.UnmarshalExtendedContext[option.Options]`**, the same strict parse as `engine_singbox.go:262`, so future drift fails CI instead of a phone.
- UX: no new family names. A refused link shows "this build cannot dial this transport" in en and fa, per farsi/STYLE.md.

**W1-B. Hand-off card. Lane B owns `client-ui/src/components/connection/AutoFailure.tsx` and a harness scenario in `client-ui/src/harness/scenarios.ts`.**
- Content: a section titled "Other tools that may work right now" with one line each for Psiphon, Lantern and Orbot. It states plainly that these are other organisations' networks. It offers "copy bridge lines for Orbot" when the user has tor-bridge routes this build can't dial.
- Test: vitest in `AutoUi.test.tsx` and the harness screen.
- **Blocked by the dirty tree.** `AutoFailure.tsx`, both `d2-extra.*.json` files, `RecipientImport.tsx` and `PublisherWizard.tsx` all have uncommitted changes on `ux-refine`. Start this lane only after ux-refine merges.

**W1-C. Honesty copy and profile order. Lane C owns `core/routestore/family.go` and `derive_tree.ts` (rationale text only, labels unchanged), `docs/transport-family-inventory.md`, `specs/modifiers/tls_fragment.md` and `client_desync.md`, the `bundle/go/publisher/webtunnel.go` comment, and `publisher/deploy/profiles/*.json`.**
- hysteria2 keeps the `stable` label with the copy "blocked in Iran since mid-2025".
- Iran profiles order hysteria2 after the TCP three.
- WebTunnel wording changes from "FAILS in Iran" to "contested".
- Close the fragment spec as an upstream no-op.
- Gate: `tools/check-family-maturity.mjs`.

**W1-D. Firewall bug. Lane D owns `publisher/deploy/providers/hetzner/live_client.go` and its tests.** Change it to add one CDN-port rule from Cloudflare ranges on the relay's own firewall, instead of replacing every rule. Unit test with the mock client.

**W1-E. JA4 measurement. Lane E owns `test-rigs/worldbox` only (new capture check).** Capture the ClientHello for REALITY/chrome, REALITY/safari and ws/chrome and compute JA4 against a real Android Chrome. The output is a decision, not code: diversify the fingerprint per relay, or wait for upstream.

**Parallelism.** A, C, D and E can run at the same time without touching the same files. B starts after the ux-refine merge.
- Shared hotspot: the i18n JSONs (`client-ui/src/i18n/d2/d2-extra.*.json` and the `client-shared` mirror). A and B both add keys. Give each lane its own key block and merge them one after the other, or have one person own the i18n merge.

### Wave 2: new families needing relay or engine work

**W2-T. The Tor stack (one lane, in sequence).**
1. **Device spike (gate, about 1 week).** Build an arm64 `libtor.so` (prefer reusing the tor-browser-build or Guardian tor-android output; add a small PIE launcher if theirs is a JNI library) and **one** `liblyrebird.so`. Put them on the spare Sony (`adb -s`). Prove three things:
   - each PT accepts the `TOR_PT_PROXY` that sing-box always injects (`protocol/tor/outbound.go:131`);
   - Snowflake's SOCKS5-UDP works through the ProxyListener;
   - cold and warm bootstrap fits within `torAttemptTimeout` (90 s at `core/engine/proof_singbox.go:124`).
   **If this fails, stop.** The fallback is Arti in the Tauri shell behind a `socks` outbound, which is a new estimate.
2. Packaging:
   - `tools/build-tor-android.sh`: drop the separate webtunnel and snowflake steps; build arm64-only, plus x86_64 for the emulator.
   - `core/engine/torbin.go:56-61,180-185`: map everything to liblyrebird.
   - Wire the build into the release pipeline and record the hashes in `docs/build-and-release.md`.
   - Only then flip `tor-bridge` to `experimental` in `family.go` and `derive_tree.ts`, serialised after Lane C.
3. Bridge lines:
   - Wire the CM-8 screen in `client-ui/src/recipient/RecipientImport.tsx` using the existing `import.tor_bridge.*` keys.
   - Add a "carry Tor bridge lines" field in `client-ui/src/publisher/PublisherWizard.tsx` (`lint.go:99` already accepts it).
4. Built-in Snowflake:
   - Ship Tor's default lines as a signed built-in route, refreshed through the pack/refresh channel.
   - Place it last in fall-over (it never races).
   - Add a "Last resort: through Tor volunteers — slow, no calls" entry on AutoFailure, with bootstrap % parsed from tor's log.
   - Add a `tor_packaged` diagnostic.
   - **Do not ship this step without talking to Tor's anti-censorship team first** (load on their broker).
- Test: worldbox is hermetic and cannot reach the Tor network. Use the device plus a Linux desktop with the distro tor package for smoke tests. A private Tor network inside worldbox (chutney-style) is optional Wave 3 rig work.
- Relay or provisioning change: **none**. This is the reason it is worth doing.
- UX: family "Tor bridge", sub-labelled Snowflake / obfs4 / WebTunnel; badge `experimental`; copy says "slow, TCP only, may need captchas".
- Load: the Tor C build is a heavy job. Under the G14 cap it runs alone, never next to an Android engine or cargo build.

**W2-R. Relay hardening bundle (one lane, one pin bump).**
- Scope:
  - Real per-relay SNI for websocket-tls and hysteria2 (`relaypack/client_outbound.go:514-539` and the hy2 case, using `publisher/deploy/sni` + `provider/cover_sni.go`).
  - Reissue the ws and hy2 certificates with that SAN in `cmd/daal-relay-mgmt`.
  - If the W3 salamander spike wins, fold it in here:
    - a hy2-obfs inbound and its users in `singbox_users.go`;
    - the port + hop range in `relayports.go` and `FirewallPortsFor`;
    - nftables DNAT in `cloudinit/*.tmpl`;
    - obfs and `server_ports` in `client_outbound.go`;
    - signed hop and obfs fields in `endpoint.go:411-417`, with a `spec_version` gate;
    - a new family value `hysteria2-obfs` marked `experimental`, so it does not inherit hysteria2's stable badge.
- Test: worldbox `--mgmt=tree` `clean` and `sni-drop`/`sni-rst`, plus a check that the ws hello carries an SNI and the two-relay on-wire check asked for at `client_outbound.go:531-537`. For salamander: add `families/hysteria2-obfs.json`; expect pass under `quic-drop`, and blocked under `udp-blackhole`/`port-whitelist`.
- Provisioning: rebuild mgmt, re-sign, bump `cloudinit/artifacts.go`, rebuild `libdaal_deploy.so`. The cloud-init parts (DNAT) reach **only freshly provisioned relays**, which is the third staleness layer. Batch every relay change into this one bump.
- Order: start the SNI part as soon as Wave 1 lands. Hold the salamander part on the spike result.

**Wave 2 parallelism.**
- W2-T and W2-R share no files until step 2's maturity flip (serialise that with C) and step 4's `AutoFailure.tsx` (after B).
- Apps Script and AmneziaWG spike code goes into new directories (`core/transports/appsrelay`, `core/engine/awg` behind a `daal_awg` tag), so it can run alongside both.
- The only shared engine file is `core/engine/config.go`. Whoever productises first owns it.

### Wave 3: spikes, in order of expected value
1. **Apps Script carrier.** Quota maths: about 20k UrlFetch calls a day per account, from project docs, not Google's published limits. Measure latency, then do one run from an Iranian vantage. worldbox cannot emulate Google.
2. **Whitelisted-port tier (lead).** Run worldbox `port-whitelist` and `protocol-whitelist` with a websocket-tls or naive listener on 80/tcp. Then measure in Iran; our rig models the censor, it is not Iran.
3. **DNS-shaped tunnel on 53/udp.** Re-run the missing analyst first.
4. **Salamander hy2.** Hand-built relay plus a pasted `obfs=salamander` link; needs no client code. Measure on MCI, Irancell and TCI.
5. **AmneziaWG dial, option A.** About a week. Settle the MAC1/H1 question against amneziawg-go and interoperate with AWG 1.5 and 2.0. The censor-lab `amneziawg-signature` scenario already exists.
6. **ECH on a Cloudflare zone**, then the decision on the CDN family as a whole.
7. **Watch only:** XHTTP upstream, Conjure via Tor, second CDN.

### Analyst conflicts and how I resolved them
- **WebTunnel.** The inventory says "FAILS in Iran"; Tor's Dec 2025 and Jan 2026 posts say people use it. Resolved as **contested**. The decision does not change: accept the lines, build nothing for it.
- **AmneziaWG.** "Works" (anatomy:101) against "blocked" (Nym, June 2025). Resolved by regime: works on blacklist days, dead under whitelist.
- **DPI reassembly.** Bock 2020 says the DPI reads only the first two packets; one 2026 report says it reassembles. Moot for us, because fragmentation is a no-op on our tiers anyway.
- **TLS analyst rated real SNI "BUILD NOW".** I moved it to W2-R because it needs a relay certificate reissue and a pin bump.

### Weak evidence (do not let it drive a decision alone)
- net4people #628: CDN domains dead in 24h, REALITY reset after handshake, reassembly. One user, June 2026.
- Lantern "pooribitwise": a single user.
- The censor document's "100% WARP signature": a vendor pitch with no measurement.
- FakeSNI's four-day lifetime: one source.
- Amnezia and Windscribe claims: vendor material.
- Fastly reachable in 2026: an unverified forum post.
- GooseRelay quota: the project's own docs.
- All APK sizes are **estimates**: arm64 41 MB → about 50 MB with Tor.
- AWG option B's MAC1 blocker is unverified.

## 4. Questions only you can answer
1. **Iran vantage.** Who measures on MCI, Irancell and TCI, and how often? Without it, W3 items 1, 2, 4 and 6 cannot conclude, and every spike stays open.
2. **Accounts and ToS.** May we use a Google account for the Apps Script spike (ToS, suspension, phone-number identity), and a Cloudflare account + domain for ECH/CDN (cost, registrant identity)? Do we contact Tor's anti-censorship team before step 4 of W2-T?
3. **APK budget.** Accept about +9 MB arm64 for Tor? Ship Tor in arm64 only, dropping it from the 109 MB universal APK?
4. **Hetzner.** Accept a wide UDP hop range (abuse-notice risk) if salamander wins? Accept a second IPv4 (monthly cost) if a second 443 tier is wanted?
5. **Hand-off card.** Are you comfortable naming Psiphon, Lantern and Orbot inside Daal, with no implied endorsement?
6. **AmneziaWG import.** Refuse non-compatible configs outright, or import them as an unselectable "unsupported" route? I recommend the latter.
7. **hysteria2.** Keep `stable` with an Iran caveat (my recommendation), or demote it in Iran profiles only?
8. **Missing clusters.** Re-run the two missing clusters (DNS on 53/udp and whitelisted ports), or accept my provisional rows?

---

# Review of the exotic-transport plan

I checked the plan against research/, docs/transport-family-inventory.md, the importer, relay and engine code, and the vendored sing-box v1.13.12 and bine v0.2.0 sources. I ran nothing except a 5-line `url.Parse` check in the scratchpad. The main problems are three overclaims (Tor, hysteria2, Apps Script), a fleet-wide certificate tell that the plan doesn't mention, a cheaper way to get a second IP that it skips, and importer bugs it misses. Corrections are listed most important first.

## A. Iran effectiveness claims that are overclaimed or contradicted

1. **Tor's value under the plan's own yardstick is close to zero.** The plan says "obfs4 and WebTunnel are TCP and outlive the UDP plan." The repo's research says otherwise:
   - `research/protocol-level-anatomy.md:103-104` gives Iran WebTunnel "Does not work" and obfs4 default bridges "Blocked".
   - `:69` says WebTunnel fails in Iran on TLS-fingerprint and SNI-whitelist filtering.
   - `research/intel-and-some-working-methods.md:77` says the protocol whitelister has killed obfs4 since about 2023.
   - The only Tor transport that works in Iran is Snowflake (`anatomy:102,110`), and Snowflake runs over WebRTC/UDP.
   - So under "block all UDP + whitelist", the Tor stack adds nothing. It helps only on blacklist days, through Snowflake.
   - The "main ones for Iran (Tor, Jan 2026)" quote is external and not in the repo. Rank Tor below the second-provider item (see D1). Keep the inventory's WebTunnel "FAILS in Iran", dated, rather than "contested" on one blog post.
2. **"hy2: QUIC 100% dropped since mid-2025" is not in the research.** What the research says:
   - On TCI (AS58224) the HTTP/3 share fell from about 40% to under 5% by 3 Jan 2026 (`research/filtering-the-flow.md:99`).
   - Otherwise UDP is "often blocked, throttled, or has 50% packet loss" (`:253`).
   - Use that wording in the copy. "Blocked since mid-2025" overstates the non-crisis periods.
3. **The shutdown dates are wrong.** The blackout began 8 Jan 2026. Partial restoration started 26 Jan, and connectivity was still about 1% of baseline at the end of March (`filtering-the-flow:121`, `intel:83`). It was not "Jan 8-18".
4. **Apps Script has two problems.**
   - "Google stayed allowlisted in Jan 2026" has no source in the repo. `intel:109` says only that collateral damage has kept Google off the blocklist in general.
   - The carrier depends on Google-front domain fronting: SNI `www.google.com` with Host `script.googleusercontent.com` (`intel:103`). That contradicts the plan's own "Classic domain fronting: Never", and Google can close it alone.
   - The 20k/day consumer quota and the 50 MB per-fetch cap come from `intel:105`, not "project docs". Check them against Google's quota page.
   - Python-shaped TLS and the POST rhythm are already named as the first thing that would get it detected (`intel:109`).
5. **Psiphon "about 9.6M daily users" can't be traced to anything in the repo.** Drop the number from the card. The repo does support "Psiphon is a residual lifeline" (`filtering-the-flow:253`).
6. **"fragment is a no-op on every tier" is only half true.**
   - True for REALITY: `reality_client.go:119-145` never wraps `tf.NewConn`.
   - True for `fragment` alone on uTLS.
   - False for `record_fragment: true`, which does wrap on the uTLS path ws-tls uses (`common/tls/utls_client.go:61-62`) and on std TLS (`std_client.go:53`).
   - The research says Iran's DPI does not reassemble (`intel:77`, Bock 2020 and IRBlock 2025).
   - So don't "close the spec as an upstream no-op". Record "REALITY cannot fragment; ws-tls can, unmeasured" and leave it PENDING.
7. **The plan contradicts itself on SNI.** The table says a no-SNI hello "probably fails an SNI allowlist", but the Domestic-SNI row says "the whitelist gate is the IP". Pick one. Under the whitelist, a real SNI on a Hetzner IP buys nothing.
8. **The CDN evidence is not only one June 2026 report.**
   - Irancell blocked all Cloudflare IPs on 16 Apr 2023, MCI and TCI followed, and `*.workers.dev` has resolved to a bogon since mid-2023 (`filtering-the-flow:129`).
   - `intel:79` disagrees ("Cloudflare … never wholesale blocked"). That conflict is unresolved and should be listed with the others.
9. **The single-IP risk is already happening.** "Hetzner is graylisted" and "REALITY IPs on MCI burn in 2-7 days" (`intel:81`). That makes IP rotation and a second provider the main lever, not exotic transports (see D1 and D2).
10. **AmneziaWG "dead under whitelist" is the plan's own inference.** The research gives "Works" (`anatomy:100`) and "usable on some paths" (`filtering-the-flow:125`). Mark it as an inference.

## B. Hidden dependencies on a third party, a domain or an account (the phone-only publisher can't set any of these up)

- **Apps Script.** Needs a Google account tied to a phone number, a GCP/OAuth consent for the Apps Script API, and a deployment. No publisher-flow step can do this. The publisher's Google identity becomes linked to the relay, Google sees the VPS destination and the timing, and a suspension can take the account down. This needs a dedicated-account rule, not just question 2.
- **ECH, cdn_fronted, Workers, second CDN, publisher-run WebTunnel.** Each needs a domain, a CDN account, or a public CA certificate.
- **DNS tunnel.** Needs a domain plus NS delegation. It also depends on Iranian recursive resolvers forwarding to foreign authoritative servers, which fails exactly when it is needed (NIN-only).
- **Built-in Snowflake.**
  - It depends on Tor's broker, a fronting CDN for rendezvous, and STUN servers.
  - A "signed built-in route" creates a new central trust root (a Daal build key) in a per-publisher trust model. That needs a spec.
- **"Real SNI" from `publisher/deploy/sni`.**
  - The names come from a pool we don't own, so the SNI resolves to some other IP: the same mismatch tell the plan uses to reject domestic SNI.
  - `intel:81` cites reverse-DNS mapping of cover SNIs (XTLS #3269).
- **Pasted links.** The server belongs to whoever gave out the link, and that person sees every destination. The plan sells these as "new reach" without saying so.

## C. Things that put the user at risk and the plan doesn't mention

1. **Every relay names the app in its certificate. This is the biggest finding.**
   - The data-plane certificate is self-signed with `/CN=daal-relay` (`publisher/deploy/cloudinit/v2.yaml.tmpl:370`).
   - Reissue copies the subject byte for byte (`cmd/daal-relay-mgmt/tlscert.go:117-119`).
   - It is served on 8444, 8445 and 443/udp. Any prober that completes a TLS handshake reads it. That is a fleet-wide tell, worse than the missing SNI.
   - Fix the subject and issuer in W2-R ahead of SNI. Clients pin by SPKI (`client_outbound.go:532-533`), so the name can change. The cloud-init half reaches only freshly provisioned relays.
2. **Tor opens an unauthenticated SOCKS port on localhost.**
   - bine launches tor with `--SocksPort auto` (`bine@v0.2.0/tor/tor.go:251-252`), and sing-box reads `net/listeners/socks` (`protocol/tor/outbound.go`).
   - Any app on the phone can find that port, domestic messengers and banking apps included.
   - Add "SocksPort on a unix socket, or authenticated" as a gate in the W2-T spike.
   - The bootstrap-% parser must not let bridge IPs reach diagnostics (the no-raw-IP invariant, `core/abi/refraction.go`).
3. **Importer: `security=none` VLESS.** The VLESS request header carries each destination address in plaintext to the DPI. W1-A must refuse it or warn loudly, and never map it to a dialable family.
4. **The AmneziaWG to plain-WireGuard downgrade** sends the exact WireGuard handshake the censor throttles and then blocks within minutes (`filtering-the-flow:125`), from an IP tied to the user's SIM identity (`:133`). It must not be raced automatically.
5. **hysteria2 attempts are themselves a signal.** `profiles/loader.go:24-30` says "a QUIC-shaped flow to a graylisted host is itself the distinguishing feature". `iran-default.json:9` still has `default_enabled: true`. Question 7 should lean towards turning hysteria2 off by default in Iran profiles, not keeping `stable` plus a caveat.
6. **"Copy bridge lines for Orbot" puts the lines on the clipboard,** where keyboard apps can read them. Use a share intent or a QR code.
7. **JA4 "diversify per relay".** A Safari or iOS hello over Android's Linux TCP stack is a mismatch across layers. Use only Chrome/Android-plausible fingerprints. Also measure `tls-in-tls-burst`, which censor-lab already has (`test-rigs/censor-lab/scenarios/tls-in-tls-burst.json`; the research warns about it at `anatomy:3`).
8. **TLS on port 80 is unusual traffic** (browsers don't do it), and plaintext on 80 exposes content. Allow only TLS families on 80, and treat it as a possible tell.
9. **Measuring from inside Iran puts a person at risk.** Route it through the existing `daal-probe` spec and its privacy rules (`specs/field-probe-v1.md`, `test-rigs/field-probe/docs/privacy-rules.md`). Question 1 ignores that this spec exists.

## D. Candidates the plan missed

1. **A second provider (Vultr) is the cheapest new IP, and the plan doesn't mention it.**
   - `publisher/deploy/providers/vultr/` is a real adapter: live client, firewall, reserved IP, rollback.
   - It gives a different ASN with no new transport.
   - Caveat: DigitalOcean and OVH are blanket-blocked (`intel:81`) and Vultr's status in Iran is unknown, so measure it. Renting a server needs your OK.
2. **Rotation cadence.** With REALITY IPs burning in 2-7 days, the rotation rungs that have no button (backlog W3-4) matter more than any exotic family.
3. **Sharing port 443** (`relayports.go:89,103`, "still unspiked") is the existing alternative to port 80.
4. **Importer bugs the plan missed:**
   - `vless.go:34-35` writes `encryption`, but sing-box's VLESS outbound has no such field (`option/vless.go:20-26`), so strict parse rejects modern Xray links.
   - The ALPN list is put in as one element (`vless.go:66-67`, `trojan.go:32-33`), giving `["h2,http/1.1"]`.
   - hy2 port ranges fail inside `url.Parse` itself ("hy2: bad URL", invalid port), so the authority must be rewritten before parsing. sing-box also wants `start:end`, not `start-end`.
   - trojan `type=grpc` and `security=reality` are silently ignored.
   - vless `headerType=http` and `flow=xtls-rprx-vision-udp443` must be refused.
5. **Trojan family.** `core/refresh/parse.go:225` maps every trojan link to `websocket-tls`, which gives a stranger's raw trojan our stable badge. Fix parse.go; don't align the importer to it.
6. **Pasted routes expire after 7 days** (`core/abi/share.go:370`). The importer's "new reach" lasts a week unless subscription URLs refresh. Verify what refresh supports for them.
7. **Before shutdowns, hand out packs early** (LAN and QR share already exist in `core/share/lan_target.go`), so routes are already in hand when a whitelist phase eases.
8. **"melli-shekan" in-Iran relay hop** (`filtering-the-flow:99`; the `lifeline_relay` family is already reserved). List it as never Daal-operated and import-only, with a legal-risk note.
9. **Telegram MTProto fake-TLS and Signal TLS proxies** (`anatomy:111`). Same IP, so low priority, but they are a modality the plan doesn't list.

## E. Size estimates

- **W1-A is M, not S.**
  - It needs all the extra parser bugs above plus en/fa strings.
  - The strict-parse test can't live in `bundle/go`, because that module has no sing-box dependency. It goes in `core/engine/*_singbox_test.go` under `//go:build singbox`, like `client_outbound_matrix_singbox_test.go`.
  - Its UI strings are blocked by the uncommitted changes on ux-refine (both `d2-extra.*.json` files). The plan blocks only lane B.
- **W1-C.**
  - hysteria2 is already fourth in `iran-default.json:5-9`, and `iran-tcp443` drops UDP families entirely. The reorder is a no-op.
  - Profiles are embedded in the publisher CLI (`loader.go:17,41`), so any profile change means rebuilding `libdaal_deploy.so` and cutting a release. It is not free of release coupling.
- **W2-R.**
  - Real SNI is a client-pack change only: SPKI pin, `client_outbound.go:532-533`. The certificate reissue the plan lists isn't needed for SNI. It is needed for the CN fix.
  - The salamander obfs password would be shared across the relay, like the shared WS path (backlog W3-8), so revoking one recipient means re-minting every pack.
- **W2-T.**
  - lyrebird doesn't contain Snowflake, so "one liblyrebird.so" is wrong. It takes two Go PT executables or a custom combined `main`.
  - Guardian/IPtProxy ships a gomobile `.aar`, a JNI library with no executable, but sing-box's tor outbound execs a binary.
  - `extractNativeLibs="true"` (`AndroidManifest.xml:37`) means the on-device size is about 2-3x the APK growth. "+9 MB" undercounts both.
  - worldbox needs a `families/*.json` and labclient support for every new family (`test-rigs/worldbox/families/`).

## Corrected Wave 1

1. **W1-A, importer correctness (M).**
   - Drop `spx`, and default `fp=chrome` for REALITY.
   - Drop the `encryption` field, or refuse the link when it isn't `none`.
   - Split ALPN lists properly.
   - Rewrite the hy2 authority before parsing and convert ranges to `start:end`.
   - Add the `httpupgrade` case.
   - Refuse, with named errors: xhttp/splithttp/h2, `headerType=http`, trojan grpc/reality, and vless `security=none`.
   - AWG 2.0 fields: when only Jc/Jmin/Jmax are set, downgrade but never race it automatically; otherwise import as an unselectable route.
   - Fix trojan's family in `parse.go:225` too.
   - Copy: "This server is run by whoever sent you the link."
   - Add the strict-parse test in `core/engine` under the `singbox` tag.
   - Strings land after ux-refine merges.
2. **W1-B, hand-off card (S, after ux-refine merges).** No user-count claims. Send bridge lines to Orbot by share intent or QR, not the clipboard.
3. **W1-C, honesty copy (S).**
   - hysteria2: "often blocked or throttled in Iran; fails in whitelist phases", citing `filtering-the-flow:99,253`.
   - Keep WebTunnel's "fails in Iran", dated.
   - Leave the fragment spec PENDING, noting that REALITY cannot fragment.
   - Drop the reorder. Put "hysteria2 off by default in iran-default" to you as a decision, since it rides a `libdaal_deploy.so` release.
4. **W1-D, firewall `SetRules` fix (S).** Unchanged. Also note that `FirewallAddEphemeralRule` does read-modify-write.
5. **W1-E, prober's-eye audit (S, worldbox only).**
   - JA4 of our hellos against a real Android Chrome.
   - What a stranger's full TLS handshake to 8444, 8445 and 443/udp reveals (CN=daal-relay).
   - `tls-in-tls-burst`.
   - Only Chrome/Android-plausible fingerprints are acceptable outcomes.
6. **W1-F (new), certificate-identity fix (S code, ships in the W2-R pin bump).** A neutral subject and issuer in `v2.yaml.tmpl:370`, and stop copying the subject in `tlscert.go:117-119`. The cloud-init half reaches fresh relays only.
7. **W1-G (new, decision, needs your OK to rent).** One Vultr relay beside the Hetzner one, measured through `daal-probe` from MCI, Irancell and TCI. That tests the single-IP point the plan's ranking rests on, with no new transport.

**Wave 2 order:**
1. W2-R: certificate fix first, then SNI, which is pack-only.
2. W2-T Tor, re-justified as Snowflake on blacklist days only. Its spike gates are: SocksPort exposure, two PT binaries, on-disk size, and the 90 s timeout.
3. Apps Script stays a spike behind a dedicated-account rule and a check on the Google-front fronting.
---

# Appendix: every candidate, by cluster

## DISGUISED WIREGUARD / UDP (AmneziaWG, WARP / WARP-in-WARP, Hysteria2 salamander + port hopping, TUIC on 443/udp, whether UDP deserves more investment)

### AmneziaWG import honesty fix (dial-side copy and 2.0 field detection) — BUILD NOW (S)

- **what:** The WireGuard config importer downgrades an AmneziaWG config to plain WireGuard. This candidate makes that downgrade truthful. It does not add AmneziaWG support; it fixes what the user is told.
- **iran:** Not a transport, so not applicable. It matters because Iranian users hold real AmneziaWG configs from AmneziaVPN, Windscribe's 2026 Iran apps and self-hosted Amnezia servers. Today they paste one and get a route that cannot connect.
- **dial:** Two defects in bundle/go/uri/wireguard.go. (1) The message at :191-196 says the downgraded route 'will still connect where WireGuard is allowed'. That holds only when Jc/Jmin/Jmax are the only AmneziaWG fields set (protocol-level-anatomy.md:79, 'Backward compatibility holds: if only Jc/Jmin/Jmax are set'). With non-default H1-H4 or S1/S2, the server discards a standard type-0x01 148-byte initiation, so the route never connects anywhere. (2) amneziaFields at :19 lists only the 1.x fields. It misses AmneziaWG 2.0's S3, S4, I1-I5, J1-J3 and ITIME (anatomy:79), so DroppedParams under-reports, and a config carrying only 2.0 fields is not flagged as AmneziaWG at all.
- **serve:** n/a: import only.
- **work:** - bundle/go/uri/wireguard.go: field list, a compatibility predicate, and the Downgrade text. - bundle/go/uri/uri_test.go: add 1.x and 2.0 fixtures. - Farsi and English import-warning strings in client-shared/i18n, following farsi/STYLE.md. - specs/uri-import-v1.md: describe the new behaviour.
- **risks:** None technical. Refusing instead of downgrading removes a route some users believed they had; it never worked, so the loss is honest.
- **why:** The current copy promises a connection that cannot happen for most real AmneziaWG configs, which is the exact 'mints but cannot be dialled' failure the inventory exists to prevent.
- **evidence:** bundle/go/uri/wireguard.go:19 (amneziaFields = Jc,Jmin,Jmax,S1,S2,H1..H4 only); bundle/go/uri/wireguard.go:191-196 ('It will still connect where WireGuard is allowed'); research/protocol-level-anatomy.md:79 (H1-H4 replace the type field; backward compatibility only if only Jc/Jmin/Jmax are set; 2.0 adds S3/S4/I1-I5/J1-J3/ITIME); core/routestore/family.go:203-219 (amneziawg unsupported; downgrade rationale)

### Hysteria2 URI import: port-hopping ranges (and obfs pass-through check) — BUILD NOW (S)

- **what:** Accept hysteria2:// links that carry a multi-port or range authority (host:443,20000-50000) or an mport parameter. Map them to sing-box's server_ports plus hop_interval, which 1.13.12 already supports on the outbound.
- **iran:** Partly, and only on non-whitelist days. Port hopping defeats per-5-tuple UDP drops (deep-research-report.md:54, :82, 'UDP five-tuple disruption'), but every hop port is outside the 53/80/443 whitelist (filtering-the-flow.md:99). The real reason to do this is import correctness: subscription channels in Iran publish hysteria2 links (the-build.md:67-69), and port-hopping variants currently fail to import.
- **dial:** Yes. sing-box v1.13.12 option/hysteria2.go:115-116 has ServerPorts and HopInterval on Hysteria2OutboundOptions under the with_quic tag, which tools/build-engine-android.sh:81 already passes. bundle/go/uri/hy2.go:18-20 calls strconv.Atoi(u.Port()), so a range port errors with 'hy2: invalid port'. Obfs is already passed through at hy2.go:37-42.
- **serve:** n/a for import. The guard at bundle/go/bundle/endpoint.go:411-417, which refuses server_ports on signed pack endpoints, must stay, because it protects signed packs. Imported routes are not pack-signed. Confirm that the import path does not run the same check.
- **work:** - bundle/go/uri/hy2.go: parse the range and mport into server_ports and hop_interval. - bundle/go/uri/uri_test.go: fixtures. - specs/uri-import-v1.md. - core/engine/config.go: confirm it serialises server_ports unchanged.
- **risks:** A hopping route from one phone spraying many UDP ports at one Hetzner IP is a volume and entropy anomaly (intel-and-some-working-methods.md:21). This is the user's own imported route, not one Daal recommends.
- **why:** It is a one-file import bug that rejects a format Iranian channels actually emit, and the engine already dials it.
- **evidence:** bundle/go/uri/hy2.go:18-20 (Atoi on port, single port only); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/option/hysteria2.go:115-116 (ServerPorts, HopInterval); bundle/go/bundle/endpoint.go:411-417 (signed packs refuse server_ports); research/the-build.md:67-69 (Iranian subscription formats incl. hysteria2://); research/deep-research-report.md:54,82 (Iran UDP five-tuple drop)

### Hysteria2 hardened: salamander obfs + server-side port hopping (+ optional Brutal) on Daal relays — RESEARCH SPIKE (M)

- **what:** Salamander XORs every QUIC datagram with a key derived from BLAKE2b, so the wire carries no QUIC Initial to decrypt. Port hopping rotates the UDP port every 10-30 s through server-side nftables DNAT. Brutal congestion control sends at a declared rate and compensates for loss.
- **iran:** Bare hysteria2: blocked. Per FOCI 2026, QUIC Initial drops reached 100% of domains about five days before the June 2025 blackout and persisted afterwards; anatomy:98 marks it 'UDP dropped'.  Salamander + port hopping: 'largely non-functional' in Iran (anatomy:99), and the corpus says Iran's post-2025 UDP drop makes it unavailable there (anatomy:55, :111). In crisis mode all UDP except DNS on 53 is dropped (filtering-the-flow.md:253; Nym, June 2025).  Status at 2026-11 is unknown. Cloudflare reports partial restoration in May 2026, and nothing in the corpus measures generic non-QUIC UDP after restoration.
- **independent:** Partly. - Independent of the TCP stable three: yes, because it is a different transport, port and protocol. - Independent of bare hysteria2: yes against a QUIC-specific filter, since salamander output is not QUIC and the Initial-decrypt dropper cannot parse it. That is exactly the filter FOCI 2026 measured. - Independent under UDP-wide drops: no. It dies at the same moment as hysteria2, tuic, wireguard and AmneziaWG.
- **dial:** Yes, with no new code. sing-box v1.13.12 option/hysteria2.go:25-28 has Hysteria2Obfs{type,password}, and sing-quic v0.6.1 hysteria2/client.go:208-209 wraps the connection in NewSalamanderConn. server_ports and hop_interval are at :115-116; up_mbps and down_mbps select Brutal. Build tag with_quic is already shipped, so the binary cost is zero.
- **serve:** Yes on a self-rented relay, with no domain, CDN or third party. The relay needs: (a) a second sing-box hysteria2 inbound with obfs salamander. With salamander on, the inbound rejects un-obfuscated clients and loses the HTTP/3 masquerade, and it cannot share 443/udp with the existing hy2-in (the same one-UDP-socket rule as BUG-14 in relayports.go:36-49). It therefore needs its own UDP port plus a hop range. (b) An nftables DNAT rule mapping the hop range to that port, written by cloud-init. (c) The hop range opened in the Hetzner Cloud firewall (FirewallPortsFor). (d) The salamander password per relay. It is a shared, relay-wide secret, not per recipient: a seized pack exposes that relay's obfs key, while user auth stays per-recipient. It reaches the fleet only through an mgmt rebuild, a pin bump and a fresh provision (the inventory's rows 5-7 caveat).
- **work:** Spike, with no repo code needed: provision one box by hand with a salamander inbound and a nftables hop range, paste a hysteria2:// link with obfs=salamander (hy2.go:37 already parses it), and measure on MCI, Irancell and TCI. Also add a censor-lab or worldbox scenario that drops QUIC Initials but passes other UDP.  If the spike wins: - cmd/daal-relay-mgmt/singbox_users.go: hy2-obfs inbound, users and rotation. - publisher/deploy/relayports/relayports.go: a new port and range. - publisher/deploy/cloudinit/*.tmpl: nftables DNAT. - publisher/deploy/relaypack/client_outbound.go:185: obfs, server_ports, optional up_mbps. - bundle/go/bundle/endpoint.go:411-417: sign the hop range and obfs type in the manifest instead of refusing them. - publisher/deploy/profiles/*.json: a default-off candidate. - Either a family or sub-mode decision with a spec_version gate (like anytls), or keep the hysteria2 family with signed obfs fields. - derive_tree.ts and family.go maturity, kept in sync by tools/check-family-maturity.mjs.
- **risks:** - Detectability: high-entropy UDP spread over thousands of ports to a graylisted Hetzner IP (intel:81) matches the censor's entropy and packet-size monitoring (intel:21) and the 'immediate blocking of simulated VPN connections such as QUIC' rule (intel:47). - Brutal is unfair and volume-heavy, which feeds MCI's volume triggers (anatomy:37). - Operator cost is nil. - User safety: a suspicious-UDP flow is attributable to a mobile subscriber, and the censor plans to 'identify the violator' (intel:29).
- **why:** It is the only cheap UDP change with a real independence argument (it is not QUIC on the wire), but the corpus rates it non-functional in Iran, so measure it before touching the relay.
- **evidence:** research/protocol-level-anatomy.md:55 (salamander wire format; port hopping; fails in Iran 2025+); research/protocol-level-anatomy.md:98-99 (bare hy2: UDP dropped; salamander+hop: largely non-functional in Iran); research/filtering-the-flow.md:191 (Brutal effective on lossy links); research/filtering-the-flow.md:193,253 (whitelist phases: every UDP protocol fails); research/intel-and-some-working-methods.md:37,47,53 (block outbound UDP; block simulated VPN QUIC); research/intel-and-some-working-methods.md:83 (HTTP/3 share 40%->5% before Jan 2026); publisher/deploy/relaypack/client_outbound.go:185-206 (no obfs, no up_mbps today); cmd/daal-relay-mgmt/singbox_users.go:924 (hy2-in: no obfs, no masquerade); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/option/hysteria2.go:25-28,115-119; ~/go/pkg/mod/github.com/sagernet/sing-quic@v0.6.1/hysteria2/client.go:208-209; web: FOCI 2026 'Insights into an Iranian Internet Shutdown' (QUIC 100% blocked pre-June-2025, persisted)

### AmneziaWG — DIAL support in the engine — RESEARCH SPIKE (L)

- **what:** WireGuard's Noise IK with transport obfuscation on top: junk packets before each handshake (Jc/Jmin/Jmax), padded handshakes (S1/S2, plus S3/S4 in 2.0), rewritten or randomised message-type headers (H1-H4), and decoy-protocol packet chains (I1-I5, which can imitate QUIC, DNS, SIP or STUN).
- **iran:** The evidence conflicts, and it is the best-documented UDP option.  For it: - The corpus table rates AmneziaWG 2.0 'Works' in Iran (anatomy:101) and recommends it for always-on use in blackouts (anatomy:112). - It was among the most resilient during the June 2025 stealth blackout (filtering-the-flow.md:119), and was 'usable on some paths' (:125). - Windscribe shipped AmneziaWG for Iran in early 2026. - A 2026 report says the protocol kept working while Amnezia's own infrastructure was blocked.  Against it: - The Nym June 2025 report lists AmneziaWG among the UDP protocols blocked, with only 53/udp left open. - filtering-the-flow.md:253: under whitelist phases every UDP protocol fails. - Windscribe itself says AmneziaWG will not bypass whitelisting.  Scoped reading: it works on normal (blacklist) days and on some carriers; it is dead under the crisis whitelist. 2026-11 status is unknown.
- **independent:** - Independent of the TCP three: yes. - Independent of hysteria2 against a QUIC-specific dropper (FOCI 2026): yes, because it is not QUIC. - Independent of plain WireGuard's 0x01/148-byte signature: yes. - Under the 'block all outbound UDP' plan (intel:37, :53): no. The I1-I5 decoy chain precedes handshakes only, so data packets stay random bytes and fail the 'UDP-DNS wire format' whitelist check (intel:77), even on port 53.
- **dial:** Not in the shipped engine. sing-box v1.13.12 has no AmneziaWG code (core/routestore/family.go:203-207), and upstream issue 4045 requests it. Forks implement it: amnezia-vpn/amnezia-box, Leadaxe/sing-box-lx (AmneziaWG 2.0 via a separate wireguard-go submodule), shtorm-7/sing-box-extended, and getlantern/lantern-box. Three options without adopting a fork wholesale: (A) Register a Daal-owned 'amneziawg' endpoint type. core/engine builds its registries via include.Context (engine_singbox.go:254, side_singbox.go:173; include/registry.go:42-43), so Daal can wrap include.EndpointRegistry() and call endpoint.Register with its own options struct, with no sing-box fork. The implementation would copy sing-box's protocol/wireguard and transport/wireguard (about 1,925 lines, GPLv3, the same licence as Daal) and swap sagernet/wireguard-go for amnezia-vpn/amneziawg-go (MIT), or a sagernet-compatible AmneziaWG patch of it. (B) Keep sagernet/wireguard-go and implement AmneziaWG's wire transform as a packet codec in the conn.Bind (transport/wireguard/client_bind.go). Junk, padding and header rewrite are per-packet and identifiable by type and size. UNVERIFIED blocker: MAC1 is computed over the message including the type field, so rewriting H1 below the device means recomputing MAC1 with the responder's public key. This needs checking against amneziawg-go's source. (C) Run amneziawg-go as a separate in-process device with its own netstack and SOCKS loopback. It pulls in upstream gvisor.dev/gvisor beside sagernet/gvisor (estimated +5-8 MB arm64), and the Android VpnService protect() hook would need wiring into its Bind. Binary cost: A or B about 0.2-1 MB, because the wireguard-go core is already linked under with_wireguard (tools/build-engine-android.sh:81); C is several MB.
- **serve:** Dial support alone has publisher-independent value: it lets the AmneziaWG configs users already hold actually connect. Serving from a Daal relay is the separate candidate below.
- **work:** Spike, about one week: prototype option A in a new core/engine/awg package with a Daal-registered endpoint, behind a build tag such as daal_awg so default builds are unchanged. Interoperate against a stock amneziawg-go server with AmneziaWG 1.5 and 2.0 parameter sets. Measure binary delta and battery use.  Then production: - core/engine/config.go: route the amneziawg family into endpoints[]. - bundle/go/uri/wireguard.go: emit the real fields instead of downgrading. - core/routestore/family.go and client-ui/src/contract/derive_tree.ts: maturity, kept in sync by tools/check-family-maturity.mjs. - core/abi/d2_summaries_proven_test.go: move the 'never widens' exemplar elsewhere. - specs/transport-families-v1.md and the inventory. - Track upstream: re-diff the copied wireguard transport on every sing-box bump.
- **risks:** - Maintenance: a copied sing-box subsystem must be re-diffed on every sing-box pin bump. The inventory says Daal does not fork sing-box; option A avoids a fork but still owns code. - Licences: amneziawg-go is MIT and sing-box is GPLv3, so they are compatible. - Detectability: AmneziaWG's 2.0 randomisation has no universal signature (anatomy:81), but it is still high-entropy UDP; Iran's ML and entropy monitoring is the stated next step (intel:21, :37). - User safety: same as any suspicious UDP flow on a mobile SIM.
- **why:** It is the strongest-evidenced UDP family for Iran, and users already hold configs, but how to dial it without a fork is unproven (the MAC1 question) and it still dies under the whitelist.
- **evidence:** research/protocol-level-anatomy.md:77-81 (WG signatures; AmneziaWG params incl. 2.0; per-install fingerprint); research/protocol-level-anatomy.md:101,112 (AmneziaWG 2.0 'Works' in Iran; always-on in blackouts); research/filtering-the-flow.md:119,125 (June 2025 resilient; 'usable on some paths'); research/filtering-the-flow.md:253 (whitelist: every UDP protocol fails); research/intel-and-some-working-methods.md:37,53,77 (UDP block plan; DNS-format whitelist); core/routestore/family.go:203-219; core/engine/engine_singbox.go:254; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/include/registry.go:42-43; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/transport/wireguard/client_bind.go; web: Nym Iran report June 2025 (AmneziaWG blocked; only UDP/53 left); web: Windscribe 2026 (AmneziaWG won't bypass whitelisting); web: SagerNet/sing-box issue 4045; Leadaxe/sing-box-lx; getlantern/lantern-box

### AmneziaWG — SERVE from a Daal relay — BUILD LATER (L)

- **what:** Run an AmneziaWG server on the publisher's rented relay alongside sing-box, with one WireGuard peer per recipient, minted into the signed pack.
- **iran:** Same as the dial candidate: works on blacklist days on some paths, dead under whitelist or crisis mode. Hetzner ranges are graylisted (intel:81), and 2026 reports say whole cloud subnets get blocked regardless of protocol.
- **independent:** The same independence as dial: not QUIC, not the TCP three, not under a UDP-wide drop.
- **dial:** Depends entirely on the dial candidate landing first.
- **serve:** Yes for a self-hoster, with no domain, CDN or third party, but it is a second data plane. The relay needs: - the amneziawg-go userspace binary, or the DKMS kernel module (about 3% overhead against userspace's larger cost, anatomy:79), installed by cloud-init. sing-box on the relay cannot do it either. - one UDP port. 443/udp is hysteria2's (relayports.go:34) and 51820 is reserved for wireguard (:136); any choice is non-whitelisted. - a tunnel subnet, per-recipient keypairs and addresses, and NAT/masquerade plus ip_forward. - daal-relay-mgmt verbs to add, remove and rotate peers. - a firewall rule. As with tuic/shadowsocks/anytls, it reaches the fleet only by rebuild, pin bump (publisher/deploy/cloudinit/artifacts.go) and a fresh provision.
- **work:** - cmd/daal-relay-mgmt: an AmneziaWG peer store, add/remove/rotate, and identity reporting. - publisher/deploy/cloudinit/*.tmpl: install, unit file, sysctl, nftables. - publisher/deploy/relayports: the port. - publisher/deploy/relaypack/client_outbound.go: render the endpoint. - bundle/go/bundle (endpoint signing for a WG peer, which has no server_port-style single credential), plus a spec_version gate. - publisher/deploy/profiles/*.json: default off. - Rotation and reclaim: an extra daemon is something else that can strand on a half-provisioned box (see the provisioning-rollback memory).
- **risks:** - A second daemon doubles the relay's attack surface and upgrade burden. - A UDP flood on a Hetzner box can draw abuse notices. - Per-recipient tunnel addresses add state that rotation must handle. - The 'publisher's phone provisions it' model must install a kernel module or a userspace binary, signed and pinned like daal-relay-mgmt.
- **why:** Only worth building after the dial spike proves interop and an Iran measurement shows it outliving salamander-hysteria2. Until then it is a large second data plane for a UDP family the censor plans to kill.
- **evidence:** research/protocol-level-anatomy.md:79,81 (kernel vs userspace overhead; AmneziaVPN self-host model); publisher/deploy/relayports/relayports.go:34,49,136 (443/udp hy2, 8443 tuic, 51820 wireguard); docs/transport-family-inventory.md 'Serving rows 5-7 needs a re-release' (pin + fresh provision coupling); research/intel-and-some-working-methods.md:81 (Hetzner graylisted)

### Cloudflare WARP as a direct route (incl. 'warp+'/scanned clean endpoints and WARP-with-noise) — NEVER (n/a)

- **what:** Cloudflare's consumer VPN: WireGuard with a 3-byte 'reserved' client ID to Cloudflare anycast (162.159.192.0/24, UDP 2408 with 443 fallback; filtering-the-flow.md:233). Iranian tools add endpoint scanners for unblocked IP:port pairs and AmneziaWG-style 'noise' junk before the handshake. Cloudflare's own client increasingly uses MASQUE (HTTP/3) instead.
- **iran:** Partly to fully blocked: - 'Partially blocked in Iran since February 2024' (filtering-the-flow.md:233). - The censor document says that in July 2025 WARP leaked when ChatGPT's anycast was opened, and that within 72 h the team built a signature from 'initial handshake pattern, specific sequence numbers, and packet entropy' with '100% blocking capability' (intel:33). It also orders 'immediate blocking of any simulated VPN connections such as QUIC, WireGuard, or WARP' (intel:47).  Scoping the 100% claim: - It is a self-reported figure in a vendor's pitch to the operator, with no measurement. - It is plausible for plain WireGuard-WARP, which carries WireGuard's fixed 0x01 type and 148-byte size (anatomy:77) to a small, known destination prefix. - It says nothing about WARP carried inside another tunnel, where the censor never sees it. - It probably does not cover noise-prefixed handshakes as such, but those still end in a standard WireGuard handshake to known IPs. - WARP over MASQUE is QUIC and dies to the QUIC block (FOCI 2026). During the whitelist or crisis posture it is UDP and dead.
- **independent:** No useful independence. It is plain WireGuard plus a reserved field, so it dies with our experimental wireguard family and with anything that triggers the explicit 'WireGuard or WARP' block rule. Its one distinct property, Cloudflare IPs that are costly to block wholesale (intel:81), is cancelled because the WARP prefix is narrow and separate.
- **dial:** Yes, for plain WARP, today. sing-box v1.13.12 WireGuardPeer.Reserved (option/wireguard.go) is applied per peer in transport/wireguard/endpoint.go:84-88, and the shipped build carries with_wireguard. A wgcf-style config already imports through bundle/go/uri/wireguard.go as a wireguard route; the importer never sets 'reserved'. The noise variant needs AmneziaWG-style junk, which is absent upstream. MASQUE has no outbound (inventory row 13).
- **serve:** Structurally publisher-independent: Cloudflare is the server. There is nothing to rent and nothing a Daal relay contributes. Registration means calling Cloudflare's undocumented client registration API from the recipient device or the publisher, which is a third-party ToS question.
- **work:** None recommended. If anything, add copy to the imported wireguard route saying WARP endpoints are a specific block target, and do not let the family borrow AmneziaWG's track record (already the rule in family.go:183-195).
- **risks:** - Third-party ToS: unofficial registration and key minting against Cloudflare's client API. - Sanctions and compliance posture of a US provider toward Iranian users: unverified. - User safety: the censor's stated method uses a 100% signature to identify users on mobile networks first ('identification of the violator within the first 48 hours', intel:29), so a known-signature route endangers the user more than it helps.
- **why:** It is plain WireGuard to a known prefix that the censor claims to fingerprint, with no Daal relay involved and a ToS dependency.
- **evidence:** research/intel-and-some-working-methods.md:33 (WARP signature, '100% blocking capability'); research/intel-and-some-working-methods.md:47 (block simulated VPN: QUIC, WireGuard, WARP); research/intel-and-some-working-methods.md:29 (identify the violator within 48 h on mobile); research/filtering-the-flow.md:233 (WARP = WG + 3-byte reserved; anycast 162.159.192.0/24; partially blocked in Iran since Feb 2024); research/protocol-level-anatomy.md:77 (WG fixed type/size signature); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/transport/wireguard/endpoint.go:84-88 (reserved supported)

### WARP-in-tunnel (WARP as inner/exit hop after a Daal route) — BUILD LATER (M)

- **what:** Chain WARP after a working outer tunnel (relay to Cloudflare), so traffic exits from Cloudflare's IPs instead of the Hetzner relay's. This is the 'users chain WARP as an inner hop' practice (filtering-the-flow.md:233).
- **iran:** Not applicable to circumvention: the Iranian censor sees only the outer Daal route. Its value is exit-side: services that block or CAPTCHA datacenter IPs, or geo-block, see a Cloudflare exit. The censor document's mention of 'traffic routing through the Azerbaijan network to bypass sanctions' (intel:33) is a different problem.
- **independent:** Not a family. It inherits the outer route's success or failure exactly.
- **dial:** Technically yes: a sing-box wireguard endpoint with reserved bytes, as the detour target of the active outbound. But the pack validator refuses 'detour' on signed endpoints (bundle/go/bundle/endpoint.go:403-409). Where it can run is better: as an outbound on the RELAY (relay sing-box 'outbounds', today only direct, singbox_users.go:927), which needs no client change at all.
- **serve:** Relay-side option: the relay's sing-box gets a WARP wireguard endpoint as its final outbound. It needs WARP registration from the relay (third party) and per-relay keys. Publisher-independent otherwise.
- **work:** - cmd/daal-relay-mgmt/singbox_users.go: optional WARP endpoint and route.final. - cloud-init: a registration step. - Publisher wizard toggle in client-shell/tauri/daal-wizard. - Diagnostics.
- **risks:** - Cloudflare ToS on unofficial registration and on server-side, multi-user use of a consumer product. - Cloudflare can see exit traffic metadata. - Throughput cap and a single dependency. - It adds a failure point that looks like 'Daal is broken' when Cloudflare rate-limits.
- **why:** It solves an exit-reputation problem, not a censorship one; do it only if recipients report sites refusing Hetzner exits.
- **evidence:** research/filtering-the-flow.md:233 (WARP chained as inner hop via Xray wireguard outbound); bundle/go/bundle/endpoint.go:403-409 (signed endpoints refuse detour); cmd/daal-relay-mgmt/singbox_users.go:927 (relay outbounds: direct only)

### TUIC moved to 443/udp — NEVER (n/a)

- **what:** Serve TUIC v5 (QUIC with TLS 1.3, ALPN h3, no obfuscation layer; anatomy:57) on the one UDP port the whitelist sometimes lets through, instead of 8443.
- **iran:** Blocked. It 'fails with Hysteria2' post-June-2025 (anatomy:57), is rated 'UDP blocked' (anatomy:100), and QUIC Initials were 100% dropped and stayed dropped (FOCI 2026).
- **independent:** No. Its QUIC v1 Initial with ALPN h3 is the same object the Iranian QUIC dropper keys on, so moving it to 443 makes it fail at exactly the same moment as hysteria2.
- **dial:** Yes (with_quic), already shipped.
- **serve:** Not on the same relay: 443/udp belongs to hysteria2 and sing-box cannot bind two UDP inbounds on one port (BUG-14, relayports.go:36-49). The alternatives are worse: a relay that serves tuic instead of hysteria2 on 443/udp (trading one QUIC family for an identical-fate one), or a second IPv4 (a Hetzner Primary/Floating IP, an extra monthly cost) just to host a duplicate fate.
- **work:** None. Keep tuic experimental on 8443 as the inventory states, or retire it from the Iran profiles (already absent from the iran-tcp443 L6 profile).
- **risks:** Operator cost (an extra IP) and relay boot failure if two UDP inbounds are ever rendered on 443.
- **why:** It buys no independence: same QUIC Initial, same drop, and it collides with hysteria2's socket.
- **evidence:** research/protocol-level-anatomy.md:57,100 (TUIC no obfuscation; fails with Hysteria2 in Iran); publisher/deploy/relayports/relayports.go:34-49 (443/udp is hy2; BUG-14); publisher/deploy/relaypack/client_outbound.go:207-216 (tuic is diversity, not a lifeline); web: FOCI 2026 QUIC 100% blocked, persisted

### Overall UDP investment (more QUIC-shaped families; hysteria2's Iran label) — NEVER (S)

- **what:** A cross-cutting verdict on whether any UDP family deserves further investment, given the censor's plan to block outbound UDP and the 2025-2026 measurements.
- **iran:** - The crisis and whitelist regime passes only DNS on 53/udp, HTTP on 80 and HTTPS on 443/tcp (filtering-the-flow.md:99; intel:77), and the plan is to make the UDP block permanent (intel:37). - QUIC was 100% blocked before June 2025 and stayed blocked (FOCI 2026); IPv6 announcements collapsed by 98.5% before January 2026 (intel:83). - The non-crisis window, where non-QUIC UDP may pass, is real but unmeasured for 2026.
- **independent:** QUIC-shaped families (hysteria2 bare, tuic, MASQUE, QUIC-v2 variants) share one fate. Non-QUIC UDP (salamander, AmneziaWG) adds exactly one independent failure mode: surviving a QUIC-only filter. No UDP family survives the crisis whitelist.
- **dial:** Everything affordable is already in sing-box 1.13.12 (with_quic, with_wireguard). Only AmneziaWG needs new code.
- **serve:** Every additional UDP family competes for 443/udp or lands on a non-whitelisted port.
- **work:** - core/routestore/family.go and derive_tree.ts: rationale text for hysteria2 (the label can stay stable while the copy says 'blocked in Iran since mid-2025'). - client-ui family-chip copy, Farsi and English. - Iran profile ordering: hysteria2 after the TCP three. - A worldbox censor scenario covering 'QUIC Initial dropped, other UDP passes' so salamander and AmneziaWG can be tested against it. No new QUIC families.
- **risks:** Spending engineering on UDP diverts effort from the TCP/443 work (and DNS-shaped 53/udp, a different cluster) that is the only thing a whitelist lets through. Over-promising UDP routes endangers users who rely on them in a shutdown.
- **why:** No new QUIC-shaped families. Limit UDP work to the salamander and AmneziaWG spikes plus the two importer fixes, and re-scope hysteria2's Iran copy now.
- **evidence:** research/filtering-the-flow.md:99,253; research/intel-and-some-working-methods.md:37,53,77,83; research/protocol-level-anatomy.md:55,98-101,111; research/deep-research-report.md:54,82; publisher/deploy/profiles/loader.go:20-40 (iran-tcp443 drops udp_gated families); web: FOCI 2026 Iranian shutdown paper; Lantern corpus findings on QUIC and UDP blocking


## TOR ECOSYSTEM: tor-bridge runtime packaging, obfs4 (lyrebird), Snowflake, WebTunnel, meek, Conjure-via-Tor, publisher-hosted bridges, and Psiphon/Lantern/Orbot hand-off

### Tor runtime packaging on Android (libtor.so + ONE liblyrebird.so, arm64-only) — RESEARCH SPIKE (L)

- **what:** The prerequisite for every Tor-carried transport. A PIE tor executable and the lyrebird pluggable-transport binary, shipped as jniLibs/lib*.so so sing-box's `tor` outbound can exec them from the extracted native-library directory. This is the Orbot pattern; Daal already does the same for libdaal_deploy.so.
- **iran:** n/a in itself; it carries obfs4, Snowflake and WebTunnel, which Tor's January 2026 update calls "the main ones for Iran". All three were near zero during the January 2026 shutdown and came back above pre-shutdown levels afterwards.
- **dial:** Partly. sing-box v1.13.12 registers `tor` with no build tag (include/registry.go:88). It only execs a binary: bine starts a process, there is no embedded-tor tag, and ProcessCreator is set to nil whenever executable_path is given (outbound.go:61-64). Resolver, config materialiser and importer exist (core/engine/torbin.go, torconfig.go, bundle/go/uri/tor_bridge.go). No artifact exists: jniLibs/arm64-v8a holds only libcronet, libdaal_deploy, libdaalcore and the tauri lib, and build-tor-android.sh:5 says "STATUS: NEVER RUN", with :107 "libtor.so is NOT built". Licences are all permissive: tor, libevent, lyrebird and snowflake BSD; OpenSSL Apache-2.0; zlib. Size (estimated): libtor 5–8 MB plus lyrebird 13–18 MB uncompressed per ABI. Compressed APK about +8–12 MB per ABI (arm64 about 41→50 MB). Installed size counts twice because extractNativeLibs=true keeps both the APK copy and the extracted copy.
- **serve:** Publisher-independent; nothing on the relay. Bridges come from the Tor Project (BridgeDB, its email responder, its Telegram distributor) or from built-in default Snowflake lines.
- **work:** (1) tools/build-tor-android.sh: delete the libwebtunnel.so and libsnowflake.so steps (:102-103) and build one liblyrebird.so from a pinned lyrebird tag that includes webtunnel and snowflake. Cut abis() (:76) to arm64-v8a, plus x86_64 only for the emulator. (2) Get libtor: either reuse tor-browser-build's Android output, or take Guardian Project tor-android. Check whether its libtor.so is a JNI library rather than a PIE executable. If it is, add a ~20-line NDK C launcher (libtorexec.so calling tor_run_main, rpath $ORIGIN). Avoid a local OpenSSL cross-compile on the G14, and run one heavy job at a time. (3) core/engine/torbin.go:56-61: map webtunnel and snowflake to liblyrebird.so; put lyrebird first in desktopBinaryNames :180-185. (4) Device spike on the spare Sony (adb -s): prove that each PT accepts the TOR_PT_PROXY that sing-box always injects (outbound.go:131), and that snowflake's SOCKS5 UDP works through ProxyListener. (5) Measure cold and warm bootstrap against core/engine/proof_singbox.go:124 (torAttemptTimeout 90 s). (6) Call the build script from the release pipeline, record hashes in docs/build-and-release.md, and only then flip tor-bridge to experimental in core/routestore/family.go plus client-ui/src/contract/derive_tree.ts (gated by tools/check-family-maturity.mjs).
- **risks:** Supply chain: a PT sees traffic before tor does, so pin signed tags. If the TOR_PT_PROXY behaviour is incompatible, a PT dies silently inside tor unless Daal parses tor's warn logs. Tor C build engineering and laptop load. APK growth. Google Play: binaries are baked in and nothing is downloaded at runtime, which is the Orbot precedent. tor_api in-process cannot restart, which is why exec is the right shape. Alternative only if the exec path fails: Arti (Rust, MIT/Apache) in the Tauri shell behind a sing-box `socks` outbound.
- **why:** It is the gate for every Tor item, and the two unknowns that decide the cost (an upstream PIE build of libtor, and TOR_PT_PROXY under sing-box) can only be settled on a device.
- **evidence:** docs/transport-family-inventory.md:60 (tor-bridge unsupported: no libtor.so in any ABI); tools/build-tor-android.sh:5,101-103,107; core/engine/torbin.go:56-61,180-185,276; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/include/registry.go:88; protocol/tor/outbound.go:61-64,83,131,153; client-shell/tauri/plugins/daal-platform/android/src/main/java/org/daal/desktop/vpn/DaalVpnService.kt:414 (addDisallowedApplication(self): child PT processes bypass the TUN); core/engine/proof_singbox.go:124; measured: app-arm64-release.apk 40,979,031 B; app-universal-release.apk 108,897,535 B; jniLibs/arm64-v8a/libdaal_deploy.so 14,575,136 B; Lyrebird changelog: 'Add WebTunnel Client Support' v0.2.0 (2024-03-27); tor-browser-build Bug 41111 https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/issues/41111; https://forum.torproject.org/t/webtunnel-through-http-proxy/16851 ; https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/issues/36 (webtunnel and the outgoing proxy); https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/merge_requests/200 (snowflake SOCKS5 forward proxy)

### Snowflake via Tor, built-in default bridge (publisher-free last resort) — BUILD LATER (M)

- **what:** Tor over WebRTC data channels (DTLS/SCTP over UDP) through about 100k churning volunteer proxies, matched by a broker that is reached via domain fronting, the AMP cache or SQS. Daal would ship Tor's public default Snowflake bridge lines, so the route exists with no publisher at all.
- **iran:** WORKS outside shutdowns. The majority of Snowflake users are in Iran (protocol-level-anatomy.md:67,102), and it is the dominant Tor transport during throttling (:112). BLOCKED during total shutdowns: Tor's April 2026 update says limited access was "not enough for Snowflake to work" during the 2026-02-28 to 05-26 shutdown, and the May update says users nearly doubled after it ended. Use spiked again from 2026-01-22 after the January blackout. It depends on UDP, so the censor's crisis rule against UDP kills it (intel-and-some-working-methods.md:53).
- **independent:** YES on the IP and publisher axis: volunteer residential IPs and Tor's bridges, nothing shared with a Hetzner relay, so it survives a burned relay or a publisher who disappeared. NO on the UDP axis (same as hysteria2) and NO in shutdowns or whitelist mode. The broker rendezvous also depends on the fronting CDN not being blocked.
- **dial:** Only after the packaging spike, through liblyrebird.so's snowflake method. Bridge-line parsing already passes the url=/fronts=/ice= parameters through verbatim (bundle/go/uri/tor_bridge.go). Open question: does snowflake's SOCKS5-UDP proxy mode work through sing-box's tor ProxyListener (outbound.go:131)?
- **serve:** Publisher-independent by construction. The only infrastructure is the Tor Project's broker and bridges.
- **work:** After the packaging spike: (1) a signed built-in route whose source is the default snowflake lines from Tor's pt_config.json, refreshable through the existing pack and refresh channel, since Tor rotates fronts and ICE servers. (2) core/abi/connect_race.go: tor never races (:53), so place it last in the fall-over order. (3) Raise or adapt torAttemptTimeout (proof_singbox.go:124) for a cold Snowflake bootstrap. (4) AutoFailure.tsx and NetworkPage copy in en/fa per farsi/STYLE.md. (5) Diagnostics: a tor_packaged flag.
- **risks:** Load on Tor's shared broker and bridges: coordinate with Tor's anti-censorship team before shipping an embedding. Stale built-in fronts. DTLS fingerprint arms race (filtering-the-flow.md:211). Tor usage is visible to the ISP as WebRTC to many peers. Slow and TCP-only.
- **why:** It is the only Daal route that needs no publisher, and Snowflake works in Iran outside shutdowns, but it is blocked on the packaging spike.
- **evidence:** research/protocol-level-anatomy.md:67,102,112; research/filtering-the-flow.md:211; research/intel-and-some-working-methods.md:53; research/deep-research-report.md:150; https://forum.torproject.org/t/snowflake-daily-operations-april-2026-update/21546; https://forum.torproject.org/t/snowflake-daily-operations-may-2026-update/21693; https://forum.torproject.org/t/snowflake-daily-operations-january-2026-update/21186; https://www.techradar.com/vpn/vpn-privacy-security/iranians-are-resilient-they-always-find-ways-to-speak-how-iranians-are-overcoming-unprecedented-internet-censorship

### obfs4 via Tor (private bridge lines delivered by paste, QR or signed pack) — BUILD LATER (M)

- **what:** Lyrebird's obfs4. An Elligator2-hidden ntor handshake with a fully random-looking stream. Unauthenticated probers get a random-delay disconnect, not an instant reset.
- **iran:** PARTLY. Tor's January 2026 update lists obfs4 among the three main Iran transports, recovered above pre-shutdown levels. Default/public bridges are blocked (protocol-level-anatomy.md:104,113). The fully-random shape is weak under protocol whitelisting (deep-research-report.md:148, "Weak in Iran if raw on whitelisted ports"). Near zero during shutdowns.
- **independent:** Partly. It uses bridge IPs Tor chose, not the relay's IP. Its shape (no TLS) fails differently from TLS-in-TLS and SNI filtering. It fails together with everything in whitelist mode, and it shares the fully-random class with our experimental shadowsocks.
- **dial:** After the packaging spike (liblyrebird.so, obfs4 method). The importer and the engine's argv building are done and tested (torconfig.go, tor_bridge_test.go).
- **serve:** Publisher-independent: lines come from BridgeDB, email or Tor's Telegram distributor. A publisher abroad can fetch fresh lines and carry them inside the signed .sbp pack; publisher/lint.go:99 already accepts TransportTorBridge. No relay change.
- **work:** (1) Wire the CM-8 bridge-import screen in client-ui/src/recipient/RecipientImport.tsx using the existing import.tor_bridge.* keys (docs/capability-matrix.md:218). (2) Publisher tab: a 'carry Tor bridge lines' field in PublisherWizard so lines travel in the pack. (3) Nothing in the engine beyond the packaging spike.
- **risks:** BridgeDB and Telegram distribution get enumerated. Getting lines needs Telegram or email, which are themselves blocked or monitored. The FET-style random shape. Pasted lines are untrusted input, so the parser must stay strict.
- **why:** It comes nearly free with lyrebird once packaging exists, and it is a real non-Daal way in outside shutdowns. It is not worth doing ahead of the spike.
- **evidence:** research/filtering-the-flow.md:209; research/protocol-level-anatomy.md:51,104,113; research/deep-research-report.md:94,136,148; docs/capability-matrix.md:218-240 (CM-8); bundle/go/publisher/lint.go:99; https://forum.torproject.org/t/snowflake-daily-operations-january-2026-update/21186

### WebTunnel via Tor (public Tor WebTunnel bridges) — BUILD LATER (S)

- **what:** An HTTPS reverse proxy with a real CA certificate on a real website. The Tor tunnel is a WebSocket upgrade at a secret path, and every other path serves the cover site.
- **iran:** CONTESTED, not 'FAILS'. The research says it does not work (protocol-level-anatomy.md:69,103) or is intermittently unreliable where HTTPS to an unknown SNI is throttled (filtering-the-flow.md:213). Tor's December 2025 post says Iranian users were using WebTunnel bridges handed out via Telegram. Tor's January 2026 update names it among the main Iran transports, recovered after the shutdown.
- **independent:** Only by IP (bridges run by Tor volunteers). By shape it is the same as our websocket-tls and naive (TLS plus WebSocket or HTTP/2 to an unknown SNI), so SNI whitelisting kills them together.
- **dial:** After the packaging spike, at zero extra size: lyrebird has included the WebTunnel client since v0.2.0. Must verify it accepts TOR_PT_PROXY, because standalone webtunnel reportedly did not.
- **serve:** Public Tor bridges are publisher-independent. A Daal-relay-hosted WebTunnel bridge (dormant bundle/go/publisher/webtunnel.go) would share IP and shape with websocket-tls on 8445, so it is never worth it.
- **work:** (1) torbin.go:60 to liblyrebird.so. (2) Correct the inventory row 11 wording and the webtunnel.go:27-32 caveat from 'FAILS in Iran' to 'contested; works for some via Telegram-distributed bridges (Tor, Dec 2025)'. (3) Keep the family value unsupported; it stays reachable only inside tor-bridge.
- **risks:** Bridges get listed: Russia enumerated most of them by June 2025 per Tor. Same shape as our families, so no diversification. Distribution needs Telegram.
- **why:** It costs nothing once lyrebird ships, so accept the lines, but it adds no shape diversity; correct the overstated 'fails' wording now.
- **evidence:** research/protocol-level-anatomy.md:69,103; research/filtering-the-flow.md:213; docs/transport-family-inventory.md:63,174-176; bundle/go/publisher/webtunnel.go:27-32; https://blog.torproject.org/staying-ahead-of-censors-2025/; https://forum.torproject.org/t/snowflake-daily-operations-january-2026-update/21186; https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/issues/41111

### meek (meek_lite) via Tor — NEVER (n/a)

- **what:** Domain-fronted HTTPS polling through a CDN: the allowed front in DNS and SNI, the real backend in the Host header.
- **iran:** BLOCKED or dead. Google and AWS ended fronting in 2018, Azure in 2022–2024, Fastly on 2024-02-27, and Tor retired meek-azure (protocol-level-anatomy.md:71,105; filtering-the-flow.md:205). The censor document treats foreign CDNs as the main tool for unauthorised access and whitelists them only granularly (intel-and-some-working-methods.md:29,47).
- **independent:** n/a: no working fronts exist for Iran.
- **dial:** It would come in the same liblyrebird.so (torbin.go:59) at zero cost, but there are no usable bridge lines.
- **serve:** Structurally impossible for a self-hoster without a CDN that tolerates fronting, which the major CDNs no longer do.
- **work:** None. Leave the mapping; do not surface it.
- **risks:** CDN terms of service and a slow polling transport.
- **why:** There is no fronting CDN left that Iran users can reach.
- **evidence:** research/protocol-level-anatomy.md:71,105,113; research/filtering-the-flow.md:205; research/intel-and-some-working-methods.md:29,47

### Conjure via Tor pluggable transport — RESEARCH SPIKE (M)

- **what:** Refraction networking. The client registers (via DNS, the AMP cache or an API) and then connects to a 'phantom' address in a cooperating ISP's unused space, where a station intercepts the flow. Tor is rolling out a Conjure PT.
- **iran:** PARTLY. It carries heavy Iranian use as Psiphon's CONJURE-OSSH (filtering-the-flow.md:221). Iranian ASes RST-inject on, or pre-block, the phantom subnets, and new /24s get detected in about 3 weeks (filtering-the-flow.md:223). Tor's December 2025 post says it is being distributed in heavily censored places, with no Iran results reported.
- **independent:** YES by design (ISP-side stations, no relay IP), but it depends on a few US university/ISP stations.
- **dial:** No. It is a separate Go PT (the conjure client on gotapdance), not part of lyrebird, so it would be a second Go binary of roughly 10–15 MB. gotapdance has never been in core/go.mod (inventory :67).
- **serve:** Structurally impossible for a self-hoster (inventory :67): it needs a cooperating ISP station.
- **work:** Watch only. Re-evaluate when Tor publishes stable Conjure bridge lines and Iran results; it would add one build_go_pt line and one torbin.go map entry.
- **risks:** Concentrated dependency on the stations. Phantom-subnet blocking. Another binary in the APK.
- **why:** It is genuinely independent of the relay, but there is no public Tor bridge supply for Iran yet, so it should not be built before Tor ships it.
- **evidence:** research/filtering-the-flow.md:217-223; research/deep-research-report.md:106,154; docs/transport-family-inventory.md:67; https://blog.torproject.org/staying-ahead-of-censors-2025/

### Publisher-hosted private Tor bridge (obfs4 or webtunnel) on the Daal relay — NEVER (n/a)

- **what:** Run tor plus lyrebird as an unpublished bridge on the Hetzner relay and hand its line to recipients in the pack.
- **iran:** Same as obfs4 or WebTunnel above.
- **independent:** NO. Same IP as the four stable families, so it is burned with them. WebTunnel would also share the websocket-tls shape.
- **dial:** Yes after packaging (just a bridge line).
- **serve:** Yes technically: a tor daemon plus lyrebird in cloud-init, an extra port, and for webtunnel a domain and certificate. It needs a fresh provision (cloud-init has no upgrade path, inventory :128-133). It is a non-exit bridge; Hetzner's Tor policy is not checked.
- **work:** cloud-init template, relayports and daal-relay-mgmt changes. Not proposed.
- **risks:** Operator cost and complexity. The relay gets a Tor fingerprint. No resilience gain.
- **why:** It shares the relay's fate and is slower than what the relay already serves.
- **evidence:** docs/transport-family-inventory.md:63,128-139,231; bundle/go/publisher/webtunnel.go:1-32; research/filtering-the-flow.md:253 (graylist of hosting-company IPs)

### Hand-off card: Psiphon, Lantern, Orbot/Tor Browser (not hosting) — BUILD NOW (S)

- **what:** When every Daal route fails, show honest pointers to third-party networks that Daal cannot host: Psiphon (with its Conduit volunteer proxies), Lantern, and Orbot/Tor Browser. Orbot also covers imported Tor bridge lines while this build cannot dial tor.
- **iran:** Psiphon WORKS and is the largest by far. It peaked at about 9.6M daily Iranian users, with Conduit above 5M on 2026-02-27 (War on the Rocks, April 2026). It kept about 1.5M during the June 2025 stealth blackout (filtering-the-flow.md:119) and is named a 'residual lifeline' in whitelist phases (:255). Lantern kept about 40% of its traffic in June 2025 (:119). Orbot carries the Tor transports above.
- **independent:** YES: entirely separate infrastructure and transport mixes (filtering-the-flow.md:227,229).
- **dial:** Never inside Daal. psiphon-tunnel-core is GPLv3, has never been in go.mod, and the package was deleted (inventory :66). This is a link or instructions only.
- **serve:** Structurally impossible (third-party networks). Do NOT run Psiphon Conduit on a Daal relay: its broker would hand the relay IP to a large number of clients, including censor sensors.
- **work:** (1) client-ui/src/components/connection/AutoFailure.tsx: add the hand-off section. (2) i18n: client-ui/src/i18n/d2/d2-extra.en.json and .fa.json (plus the client-shared mirror). (3) Optional copy-to-clipboard of bridge lines from NetworkPage tor routes. No engine, relay or build changes.
- **risks:** Third-party trust and privacy (Psiphon and Lantern see traffic metadata). Download pointers can go stale or be blocked; keep them generic and do not bundle third-party APKs. Wording must not imply Daal vouches for them.
- **why:** About 2 days of UI-only work gives a burned-out user a real next step today. That is honest where a tor-bridge badge cannot be yet.
- **evidence:** research/filtering-the-flow.md:119,225-229,255; research/protocol-level-anatomy.md:85; research/deep-research-report.md:104,153; docs/transport-family-inventory.md:66,157-163; https://warontherocks.com/2026/04/irans-other-front-the-war-over-the-internet/


## CDN AND FRONTING: XHTTP/SplitHTTP, httpupgrade/gRPC/WebSocket behind CDNs, classic domain fronting, patterniha/MITM-DomainFronting, masterking32/MasterHttpRelayVPN and Apps Script relays, Cloudflare Workers/Pages, ECH, non-Cloudflare CDNs

### Importer honesty for CDN-style links (ws / httpupgrade / grpc / xhttp / splithttp) — BUILD NOW (S)

- **what:** Parsing vless:// and trojan:// links that carry a CDN transport (type=ws|httpupgrade|grpc|xhttp|splithttp|h2). This is the format Iranian users paste from Telegram channels.
- **iran:** These link formats are everywhere in Iran (filtering-the-flow.md:239; protocol-level-anatomy.md:93-95). How well each one works varies by CDN: some work partly, others are blocked.
- **independent:** Not a new way in. It only makes third-party CDN links truthful.
- **dial:** httpupgrade, ws and gRPC are in sing-box 1.13.12 (option/v2ray_transport.go:24-38; gRPC is the lite version because no build sets with_grpc). xhttp, splithttp and h2-streaming are not. Today bundle/go/uri/vless.go:39-55 has no default case, so an unknown type silently becomes plain-TCP VLESS. Every VLESS link that is not REALITY is labelled family 'other' (vless.go:104-108), and trojan links always are (trojan.go:47).
- **serve:** Nothing to serve. This only concerns links from someone else's server.
- **work:** bundle/go/uri/vless.go and trojan.go: add an httpupgrade case (path, host). Carry ws ?ed= into max_early_data / early_data_header_name. Make the ws/grpc host and sni handling consistent. Reject xhttp, splithttp and anything else unknown with a named error, or import it as an unsupported route; never downgrade it silently. Add tests in uri_test.go. Optionally map ws+tls to websocket-tls so the maturity badge is right (core/routestore/family.go, client-ui/src/contract/derive_tree.ts, tools/check-family-maturity.mjs). Write en and fa copy following farsi/STYLE.md.
- **risks:** None on the protocol side. Refusing xhttp links is a visible 'no' in the UI, but honest, which is the inventory's rule (transport-family-inventory.md:16-18).
- **why:** Right now a pasted xhttp or httpupgrade link becomes a route that can never connect, which the inventory calls 'worse than no family'.
- **evidence:** bundle/go/uri/vless.go:39-55 (switch has only ws and grpc, no default); bundle/go/uri/vless.go:104-108 (non-REALITY VLESS becomes 'other'); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/option/v2ray_transport.go:24-38 (http, ws, quic, grpc, httpupgrade only); grep -ri 'xhttp|splithttp' over sing-box@v1.13.12: no matches; docs/transport-family-inventory.md:16-18

### Finish cdn_fronted: VLESS+WebSocket (or httpupgrade) through Cloudflare to the publisher's relay — BUILD LATER (L)

- **what:** The publisher puts its own domain on Cloudflare. Recipients connect over TLS to a Cloudflare edge with the domain as SNI, and the edge forwards the WebSocket to an Origin-CA-protected inbound on the Hetzner relay. FRP-8 already built the Cloudflare control plane (Origin CA, Authenticated Origin Pulls, path-rewrite Worker, proxied DNS, freshness URL).
- **iran:** Partly working at best, and getting worse: - Irancell blocked all Cloudflare IPs on 2023-04-16 and selective range blocking continues (filtering-the-flow.md:129). - 'Cloudflare fronting is mostly dead' (filtering-the-flow.md:253). - In 2024 Cloudflare's own DDoS rules flagged V2Ray patterns (:129). - A June 2026 user report (net4people #628) says CDN-fronted VLESS+WS domains were blocked within 24h by SNI blocklisting with full TCP reassembly. Rotating clean Cloudflare IPs did not help. - The censor document keeps foreign CDNs closed in stage one (intel-and-some-working-methods.md:47). - On the other side, Cloudflare ranges are never blocked wholesale because of collateral damage; filtering there is SNI-based (intel:81).
- **independent:** Partly. It survives the publisher's Hetzner IP being blocked or graylisted, which takes down all four stable families together. It shares SNI blocklisting with websocket-tls and naive, and it dies with any wholesale Cloudflare range block or a whitelist phase.
- **dial:** Yes, with code already shipped: a vless outbound with transport ws or httpupgrade and TLS using uTLS and real-CA verification. What is missing is a client_outbound branch. Today websocket-tls pins the box's SPKI to the box IP (relaypack/client_outbound.go:171-183, 495-497), which a Cloudflare edge would fail. No extra binary size.
- **serve:** Not today. Only the control plane exists. Missing pieces: (a) An inbound that terminates TLS with /etc/daal/cdn/origin_ca.pem and enforces AOP mTLS. cloud-init writes those files (v2.yaml.tmpl:128-141) and nothing reads them. (b) An origin port. The client must use 443, which is REALITY's port (relayports.go:33), so this needs a Cloudflare Origin Rule port override to a new inbound (for example 2053/tcp) or an equivalent Worker rewrite. (c) A correct firewall rule. Today live_client.go:347-389 either creates an unattached firewall or SetRules-replaces all of an existing firewall's rules with '443/tcp from Cloudflare'. It needs to add a rule for the CDN port only, from Cloudflare ranges, on the relay's own firewall. (d) Getting the new inbound onto relays. cloud-init has no upgrade path (inventory:119-138), so either a fresh provision or a daal-relay-mgmt release with a new hash pin. The publisher needs a domain (about $10/yr, Cloudflare Registrar possible), a free Cloudflare account and a scoped API token. Recipients never see the relay's IP.
- **work:** - publisher/deploy/providers/hetzner/live_client.go: rewrite FirewallApplyCloudflareRule to add or replace one rule on the relay's own firewall. - publisher/deploy/cloudflare: add the Origin Rule (port override) to the CFClient and its live and mock implementations. - cmd/daal-relay-mgmt (families.go, singbox_users.go): add a ws-cdn-in inbound with Origin CA cert and client-CA AOP; relayports.go: new port; v2.yaml.tmpl: set CDNEnabled in the phone flow; artifacts.go: bump the pin. - publisher/deploy/relaypack/client_outbound.go: cdn_fronted branch (server = hostname, server_name = hostname, no pin, Host header). - core/internal/selection already mixes modes (shortlist.go:135-145). - client-ui: wire storeCloudflareToken, provisionCdnFront, listCdnFronts and verifyCdnPosture (W3-5) and rungs L7-L9 (W3-4), with en and fa copy. - Phone flow: open dash.cloudflare.com token creation in the browser (check whether a pre-filled permission template URL is still supported), paste the token, have the wizard verify the zone, then provision. - test-rigs/worldbox: a CDN scenario.
- **risks:** - Detectability: the domain in SNI is what gets blocklisted within about 24h (net4people #628). TLS-in-TLS is not hidden. - Rotation burns domains, which cost money and identity. - Cloudflare ToS: the account can be ended for proxy abuse (filtering-the-flow.md:239), which takes down every recipient on that zone at once. - The domain's registrant is tied to the publisher (privacy and legal exposure). - Operator cost: domain fees plus phone-unfriendly nameserver changes when the domain is not registered at Cloudflare.
- **why:** It adds a failure domain that does not depend on the relay IP, but 2026 evidence says Iran blocks CDN-fronted domains in about a day. Measure from inside Iran before wiring a half-built lane, and fix the firewall bug before anyone gives the wizard a screen for it.
- **evidence:** docs/handovers/frp-8-handover.md:32-43,149-170; publisher/deploy/cloudflare/doc.go:1-27; worker.go:1-60; publisher/deploy/cloudinit/v2.yaml.tmpl:128-141 (certs written; grep finds no reader); publisher/deploy/providers/hetzner/live_client.go:347-389 (Create with no ApplyTo / SetRules replaces all); publisher/deploy/cli/cli.go:1788-1866 (cdn-provision); publisher/deploy/relaypack/client_outbound.go:171-183,495-497; publisher/deploy/relayports/relayports.go:33,129; docs/backlog-post-45.md:384-415 (W3-5, W3-4); research/filtering-the-flow.md:129,239,253; research/intel-and-some-working-methods.md:29,47,81; net4people #628 via https://corpus.lantern.io/papers/2026-pooribitwise-iran-advanced-dpi/ (June 2026, single report)

### httpupgrade and gRPC as alternative carriers behind the CDN — BUILD LATER (S)

- **what:** The same CDN route as above, carried as HTTP/1.1 Upgrade without WebSocket framing (httpupgrade) or as gRPC streams over HTTP/2. These are shape variants for when a CDN or DPI treats WebSocket differently.
- **iran:** No Iran-specific measurement for either, so unknown. Research groups them with WS+TLS: 'Better than raw VMess', but 'Iran: SNI blocking if outer hostname is known' (deep-research-report.md:152).
- **independent:** No. Same fate as CDN-WebSocket at the IP and SNI layers; only the HTTP shape changes.
- **dial:** Yes, in the shipped build. httpupgrade is in transport/v2rayhttpupgrade. gRPC builds as the lite version because no build passes with_grpc (transport/v2ray/grpc_lite.go '//go:build !with_grpc'). No size cost. Adding with_grpc would link google.golang.org/grpc (already an indirect dependency in core/go.mod:163) for little gain.
- **serve:** Same requirements as cdn_fronted: one more transport block on the CDN inbound. Cloudflare passes httpupgrade like WS; gRPC has to be switched on in the zone's network settings.
- **work:** Once cdn_fronted has a data plane: add transport type selection in the relay inbound renderer (cmd/daal-relay-mgmt) and in client_outbound.go, plus a profile flag in publisher/deploy/profiles/*.json.
- **risks:** Same as cdn_fronted. gRPC's HTTP/2 headers (content-type application/grpc) are an easy DPI target where TLS is intercepted, which is not shown in Iran (deep-research-report.md:177).
- **why:** A cheap extra once the CDN data plane exists. It does nothing on its own.
- **evidence:** ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/transport/v2rayhttpupgrade/; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/transport/v2ray/grpc_lite.go:1; tools/build-engine-android.sh:81 (no with_grpc); research/deep-research-report.md:152

### XHTTP / SplitHTTP (Xray) — RESEARCH SPIKE (L)

- **what:** Xray's HTTP transport. It splits a tunnel into ordinary POST uploads and a streaming GET download, or runs it as one HTTP/2 or HTTP/3 stream, with no Upgrade header. It is built to pass CDNs and middleboxes that refuse or flag WebSocket.
- **iran:** Partly working or blocked; the evidence is thin. It was widely recommended in the 2025 community. The June 2026 net4people #628 report lists xHTTP among blocked traffic with no detail. Behind a CDN it still exposes the domain in SNI, which is what is being blocked.
- **independent:** No, not behind a CDN (same SNI and IP fate). Direct-to-VPS XHTTP shares the IP fate of the stable four.
- **dial:** No. sing-box 1.13.12 has nothing for it (grep: no matches; option/v2ray_transport.go:24-38). It exists only in forks (sing-box-lx, sing-box-extended), and the policy here is not to fork sing-box (inventory:116). The other route is Xray-core's splithttp package (MPL-2.0) registered as a custom transport. That is hard because v2ray transports are a closed switch, so it would need a whole custom outbound registered through adapter/outbound.Register before box.Context, and the Xray dependency tree would add several MB to the Android .so.
- **serve:** The relay would need an XHTTP inbound, which the pinned sing-box lacks, so the relay would have to ship Xray-core or a fork: a new hash-pinned artifact, cloud-init and mgmt changes. Direct to the VPS on 443 it would also clash with REALITY.
- **work:** Spike only: track upstream sing-box issues and releases for XHTTP. If it lands, the work is a sing-box pin bump (core/go.mod, relay artifacts.go) plus the CDN inbound. Until then, the importer candidate above rejects xhttp links honestly.
- **risks:** - Maintenance: a fork or a second core. - APK size. - Wire compatibility: Xray has changed XHTTP modes often, so links break. - Detectability: the same SNI exposure behind a CDN.
- **why:** It cannot be dialled without a fork or a second core, and the 2026 evidence does not show it outlasting WS where the domain is the thing being blocked.
- **evidence:** grep -ri 'xhttp|splithttp' ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12: no matches; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/adapter/outbound/registry.go:15 (Register is public); core/engine/engine_singbox.go:254 (include.Context); docs/transport-family-inventory.md:116 (Daal does not fork sing-box); research/protocol-level-anatomy.md:31; https://github.com/Leadaxe/sing-box-lx (fork with XHTTP); net4people #628 via corpus.lantern.io (June 2026)

### Classic domain fronting (SNI = allowed front, Host = real backend) on public CDNs — NEVER (n/a)

- **what:** The meek technique. DNS and SNI name a high-collateral front domain, and the real hostname appears only in the encrypted HTTP Host header, which the CDN uses for routing.
- **iran:** Dead on the big CDNs: - Google and AWS turned it off in April 2018, Cloudflare blocked SNI/Host mismatch in 2020, Azure on 8 Jan 2024, Fastly on 27 Feb 2024 (filtering-the-flow.md:205; protocol-level-anatomy.md:71). - The Iran column reads 'meek / domain fronting ... Dead' (protocol-level-anatomy.md:105). - A 2023 survey found smaller CDNs (Akamai, CDN77, Lumen) still allowing some forms; none of those is a self-serve account a publisher can open from a phone.
- **independent:** It would be independent, but it cannot be served.
- **dial:** Yes, trivially: tls.server_name set to the front plus a ws/httpupgrade Host header. No new code.
- **serve:** Structurally impossible on the CDNs that matter: they enforce SNI==Host now. Where it still works, it needs an enterprise CDN contract.
- **work:** None.
- **risks:** CDN ToS ban fronting explicitly. Results flip without notice.
- **why:** Every self-serve CDN a publisher could sign up for enforces SNI==Host. Google's internal same-edge routing is the one survivor, and it is covered by the Apps Script candidate.
- **evidence:** research/filtering-the-flow.md:205; research/protocol-level-anatomy.md:71,105,113; research/intel-and-some-working-methods.md:81

### patterniha/MITM-DomainFronting (serverless local TLS re-fronting) — NEVER (n/a)

- **what:** An Xray-core recipe with no server. A local root CA terminates the browser's TLS for each site, then re-encrypts with a rewritten SNI to the same CDN edge (Chrome uTLS, 'fromMitm' ALPN), so CDN-hosted sites are reached directly through fronting.
- **iran:** Reported working in April 2026 for CDN-hosted origins when combined with fragmentation (intel-and-some-working-methods.md:173). It stops working when a CDN enforces SNI==Host, when an edge IP is blocked, and on any app that pins certificates (intel:95).
- **independent:** Yes, independent of the relay, but unsafe and browser-only.
- **dial:** No. sing-box 1.13.12 has no MITM inbound (grep: none). It needs Xray-core's fromMitm path or a custom MITM engine. It only reaches sites hosted on fronting-friendly CDNs, so it is not a general tunnel.
- **serve:** Nothing to serve and it does not depend on the publisher. That also means a Daal publisher adds no value to it.
- **work:** None recommended.
- **risks:** - Safety: the user must install a root CA. On Android 7+ apps ignore user CAs (works in browsers only), and a CA whose key lives on the device can be used to MITM every site for that user if the key or the phone is taken. - Teaching Iranian users to accept a 'trust this certificate' prompt is exactly the habit a state attacker exploits. - It contradicts the whole-device VPN model. - It breaks on ECH (intel:95).
- **why:** It needs a root CA on the recipient's device, works only in browsers and on some CDNs, and does not use the publisher at all.
- **evidence:** research/intel-and-some-working-methods.md:87-97,167,173; sing-box@v1.13.12/protocol/ (no mitm)

### masterking32/MasterHttpRelayVPN (Google Apps Script HTTP relay with local MITM) — NEVER (n/a)

- **what:** A Python proxy. It MITMs browser HTTPS with a local CA, serializes each request as JSON, and POSTs it with domain fronting (SNI www.google.com, Host script.googleusercontent.com) to the user's own Apps Script, which runs UrlFetchApp.fetch(url) and returns the response.
- **iran:** Working while Google is allowlisted. It spread fast in a 2026 filtering wave (intel-and-some-working-methods.md:101). Google stayed reachable in the January 2026 tiered phase (FilterWatch via arXiv 2603.28753 §3).
- **independent:** Yes, but unsafe.
- **dial:** No. It is not a tunnel (one HTTP request per call, no sockets), it is browser-only behind a MITM, and Python's TLS fingerprint is weak (intel:109).
- **serve:** Nothing to serve on the VPS. The 'relay' is the user's Google account.
- **work:** None for this design. See the end-to-end-encrypted Apps Script carrier instead.
- **risks:** - Google sees every request's full URL, headers and body in plaintext, and so does whoever controls the Google account (intel:105). - It needs a root CA on the device. - Shared static key with no replay protection (intel:111). - Google ToS; account suspension. - A distinctive pattern of Python-TLS POSTs to Google IPs (intel:109).
- **why:** It hands plaintext to Google and needs a root CA. The useful part, a Google relay that survives whitelisting, can be had without either.
- **evidence:** research/intel-and-some-working-methods.md:99-111,169; https://arxiv.org/html/2603.28753 (Google allowlisted, Jan 2026)

### Apps Script carrier to the publisher's own relay, end-to-end encrypted (GooseRelayVPN-style) — RESEARCH SPIKE (L)

- **what:** The client long-polls batched, AES-GCM-encrypted tunnel frames as HTTPS POSTs to a Google edge (SNI www.google.com) addressed to an Apps Script doPost(). The script forwards the opaque blob with UrlFetchApp to an exit daemon on the publisher's VPS, which decrypts it and dials the internet. There is no MITM and Google only sees ciphertext.
- **iran:** Unmeasured for this exact design. Its building blocks are the strongest in this cluster: - Google is not blocked because of Gmail, Android and Play collateral (intel:109). - Google was allowlisted during the January 2026 tiered phase (arXiv 2603.28753 §3). - The same fronting trick drives the 2026 viral tool (intel:101,169). - GooseRelayVPN v1.7.1 was published 2026-05-23 and has an Android VpnService client. That suggests use, not proof. What kills it: - Iran blocking Google, which it has not done so far. - JA3/JA4 or behavioural classification of long-poll POSTs to AS15169 (intel:109). - Full NIN-only shutdowns, where nothing foreign worked (Jan 8-18, 2026).
- **independent:** Yes. It survives relay-IP blocks, SNI blocklisting of publisher domains, Cloudflare range blocks and whitelist phases that keep Google. It fails only if Google is blocked or classified, or in a total NIN-only shutdown.
- **dial:** Not in sing-box. Two ways: - Run the carrier in-process, listening on loopback SOCKS, and point a sing-box 'socks' outbound at it. There is precedent for an external carrier in the tor route (core/engine/torbin.go). - Register a custom outbound through adapter/outbound.Register on include.OutboundRegistry() before box.Context. It is pure Go. Its TLS must be switched to uTLS Chrome (the module already has a utls fork). Expected size well under 1 MB. Licence MIT (GooseRelayVPN), compatible.
- **serve:** Yes, and it is the only design in this cluster that does not need the relay IP to be reachable from Iran. - The VPS runs an exit HTTP endpoint that only Google's UrlFetch egress needs to reach. Any port works, and Hetzner IP blocking in Iran stops mattering. - New daemon or mgmt-managed inbound, a hash-pinned artifact and a firewall rule. - The publisher needs a Google account and must deploy the script (paste Code.gs, set 'Execute as me / Anyone', copy the deployment ID). Doing that through the Apps Script API needs OAuth scopes that are sensitive and would need verification, so on a phone this is realistically a guided copy-paste in the browser. - Several deployment IDs can be rotated for quota.
- **work:** Spike first (S-M): - Quota maths: about 20k UrlFetch calls per day per consumer account (project docs, not Google's published limits). That is about 14 per minute sustained, so roughly one light messaging user per deployment. - Latency for each doPost call. - One measured run from an Iranian vantage (test-rigs/worldbox cannot emulate Google). If it passes: - core/transports/appsrelay (new): carrier using uTLS; core/engine/config.go (socks hop or custom outbound). - New family enum value in bundle/go/bundle/types.go, gated on spec_version; core/routestore/family.go plus derive_tree.ts as experimental; relayports.go. - cmd/daal-relay-mgmt exit handler; publisher wizard screens for the Google steps (client-shell/tauri/daal-wizard, client-ui/src/publisher) in en and fa. - The recommender treats it as a last-resort tier.
- **risks:** - Google ToS and Apps Script acceptable use: the account can be suspended, and every recipient on that deployment goes down at once. - Quota exhaustion mid-day. - Publisher identity: the Google account is tied to a phone number, and Google can see the VPS IP and traffic volumes. - Detectability: a long-poll POST rhythm to Google from home ISPs is classifiable even with a Chrome fingerprint (intel:109). - Slow, high latency: messaging-grade, not video. - Legal exposure for the publisher is no worse than running the relay.
- **why:** It is the only candidate whose failure does not depend on the four stable families or on the relay IP, and it rides the one foreign service Iran kept allowlisted in 2026. Its quota, ToS and fingerprint costs have to be measured before it is built.
- **evidence:** research/intel-and-some-working-methods.md:101-111,169,173; https://pkg.go.dev/github.com/kianmhz/GooseRelayVPN/internal (MIT, v1.7.1, 2026-05-23, long-poll carrier plus VPS exit); https://arxiv.org/html/2603.28753 (Google allowlisted Jan 2026; nothing worked Jan 8-18); research/intel-and-some-working-methods.md:81 (Hetzner graylisted); core/engine/torbin.go (external-carrier precedent); sing-box@v1.13.12/adapter/outbound/registry.go:15

### Cloudflare Workers / Pages as the relay itself (edgetunnel-style) — BUILD LATER (M)

- **what:** A Worker accepts a VLESS-over-WebSocket upgrade and dials the destination itself through Workers outbound TCP sockets, or chains to a VPS. With a Worker as the exit, no VPS is needed.
- **iran:** Mostly blocked: - *.workers.dev has resolved to 10.10.34.36 since mid-2023 (filtering-the-flow.md:129), so it needs a custom domain. - Cloudflare IPs are selectively blocked (:129). - Cloudflare has closed these setups via ToS and CPU throttling (:239). - Iranian vendors were seen chaining REALITY servers into Workers (net4people #359, filtering-the-flow.md:253). - The same June 2026 24h SNI-blocking report applies to any custom domain on Cloudflare.
- **independent:** It survives VPS-IP blocks. Otherwise the same fate as cdn_fronted.
- **dial:** Yes, with the shipped vless+ws+tls outbound. No size cost.
- **serve:** Does not depend on a VPS when the Worker is the exit, but Workers sockets cannot reach Cloudflare-hosted destinations, so a VPS is still needed for those. The publisher needs a Cloudflare account and a custom domain. The repo can already upload Workers scripts (publisher/deploy/cloudflare/worker.go, cf_client_live.go).
- **work:** As an option inside cdn_fronted: a second Worker script template with VLESS-WS termination and connect() in publisher/deploy/cloudflare/worker.go, plus a provider option and a client_outbound branch. Separately, check the Workers free-plan request limits and the licence of any upstream script before copying one.
- **risks:** - Cloudflare ToS and account termination: high, and the blast radius is every recipient. - Free-plan request caps. - Cloudflare sees all destinations in cleartext when the Worker is the exit. - The same SNI and IP fate as cdn_fronted.
- **why:** It is worth having only as a variant of cdn_fronted that saves the VPS, and only if the CDN route proves itself in Iran. On its own it is the most ToS-exposed option.
- **evidence:** research/filtering-the-flow.md:129,205,239,253; publisher/deploy/cloudflare/worker.go:1-60; research/the-build.md:75 (warns about Iran blocking Workers)

### ECH on the CDN route — RESEARCH SPIKE (S)

- **what:** TLS Encrypted ClientHello (RFC 9849). On a Cloudflare zone the outer SNI becomes cloudflare-ech.com, and the publisher's domain moves into the encrypted inner ClientHello.
- **iran:** Iran kills ECH indirectly by blocking the DoH and HTTPS-RR bootstrap, not in-band (intel-and-some-working-methods.md:79; Niere et al. FOCI 2025; filtering-the-flow.md:41 for the GFW). Russia blocked all Cloudflare ECH since November 2024 (protocol-level-anatomy.md:71). No 2026 Iran measurement found. The June 2026 report's failure, the domain blocklisted from SNI, is exactly what ECH hides.
- **independent:** No. It is a modifier on the CDN route and inherits its Cloudflare IP fate.
- **dial:** Yes, in the shipped build. sing-box 1.13.12 outbound tls.ech takes a static config list (option/tls.go:217-221), so the ECHConfig can travel in the signed pack and no DoH bootstrap is needed. Retry configs on rejection are handled (common/tls/client.go:125-128). ECH cannot be combined with REALITY (utls_client.go:259-261). It needs Go 1.24+ (ech.go build line). No size cost.
- **serve:** Cloudflare enables ECH on zones it proxies. A self-hosted ECH on the Hetzner inbound (InboundECHOptions) adds nothing, because the IP already gives the relay away.
- **work:** Spike (S): one cdn_fronted test zone and an ECH-enabled outbound from an Iranian vantage, with and without fragmentation. If it works, add an ech block in the client_outbound cdn branch and carry the ECHConfig in the pack's family-specific config (bundle/go/bundle/relay_pack.go), refreshed through the freshness document (publisher/deploy/freshness) because Cloudflare rotates keys.
- **risks:** Blocking the single outer SNI cloudflare-ech.com is a nearly free move for the censor, because Iranian browsers already cannot fetch ECH configs, so there is almost no collateral. Cloudflare's key rotation can strand old packs if the retry path fails.
- **why:** It targets the exact 2026 failure (domain SNI blocklisting) at zero dial cost, but one SNI rule could defeat it. Measure before building.
- **evidence:** sing-box@v1.13.12/option/tls.go:217-221 (OutboundECHOptions.Config); sing-box@v1.13.12/common/tls/ech.go:1 (go1.24), ech_tag_stub.go (with_ech obsolete); sing-box@v1.13.12/common/tls/client.go:125-128 (ECH retry); research/intel-and-some-working-methods.md:79; research/protocol-level-anatomy.md:71; https://www.petsymposium.org/foci/2025/foci-2025-0016.php

### Non-Cloudflare CDNs (Fastly, Gcore) as a second front provider — RESEARCH SPIKE (L)

- **what:** The same CDN-fronted VLESS+WS/httpupgrade route through another commercial CDN, so that a block on Cloudflare ranges does not take the CDN lane down too.
- **iran:** Fastly: 'open through much of 2024 for VLESS-over-WebSocket but increasingly shaped and blocked through 2025' (filtering-the-flow.md:129), and Fastly fronting ended 27 Feb 2024 (:205). A 2026 forum post says Fastly stayed reachable when Cloudflare was blocked (unverified). Gcore: no evidence in research/, so unknown.
- **independent:** Independent of a Cloudflare range block. Shares SNI blocking and whitelist-phase fate.
- **dial:** Yes, with the shipped outbounds; the client needs a different hostname or IP set.
- **serve:** The publisher needs an account with that CDN, usually with a credit card, plus a domain. WebSocket passthrough must be enabled. There is no provider abstraction yet: publisher/deploy/cloudflare is Cloudflare-specific and the attestation fields are Cloudflare-shaped (bundle.CDNAttestation).
- **work:** Spike: measure reachability from Iranian ISPs. If it is good, generalize publisher/deploy/cloudflare into a CDN provider interface with a second backend, and widen the RP022 attestation in bundle/go/relaypackvalidate.
- **risks:** Account and KYC friction for publishers. Each CDN's ToS. The same SNI-blocklisting exposure.
- **why:** Spreading across CDNs only matters once a single CDN works. The evidence for Fastly is fading and there is none for Gcore.
- **evidence:** research/filtering-the-flow.md:129,205; bundle/go/bundle/relay_pack.go (CDNAttestation); publisher/deploy/cloudflare/doc.go:1-27

### ArvanCloud (Iranian domestic CDN) as a front — NEVER (n/a)

- **what:** Using Iran's domestic CDN, which is whitelisted and has 'Iran Access' pricing, as the edge in front of a foreign origin.
- **iran:** Reachable inside Iran, often even in shutdowns, but: 'Arvan Cloud fronting suppressed' (filtering-the-flow.md:253). It was sanctioned by U.S. Treasury in August 2024 for supporting censorship (:129). Iranian CDNs 'cooperate with TCI' and are deliberately never used as fronts (intel-and-some-working-methods.md:93). The censor document wants 100% of Iranian sites on the National CDN (intel:45).
- **independent:** It would be, but a front the censor controls is worse than none.
- **dial:** Technically yes with ws/httpupgrade.
- **serve:** The publisher would need an account with an Iranian, OFAC-sanctioned company, which is illegal for most publishers abroad. That company sees and can log all traffic and the origin, and it works with the censor.
- **work:** None.
- **risks:** Sanctions law for publishers abroad. The CDN can hand over recipients' identities and traffic. It is a censor-controlled vantage point.
- **why:** A sanctioned CDN that cooperates with the censor is a trap for the user, not a way in.
- **evidence:** research/filtering-the-flow.md:105,129,253; research/intel-and-some-working-methods.md:45,93


## TLS camouflage and handshake tricks: ShadowTLS v3, Trojan with fallback, REALITY variants (Vision, XTLS, xhttp), uTLS fingerprint, ClientHello fragmentation, FakeSNI, SNI choice, ECH

### REALITY and Trojan import fixes (spider_x, missing fp, Trojan fingerprint and family label) — BUILD NOW (S)

- **what:** Pasted vless:// REALITY links and trojan:// links are the most common configs Iranians share on Telegram (research/the-build.md:69). The importer turns them into sing-box outbounds that the shipped engine cannot run, or into ones with a weak fingerprint.
- **iran:** These are the links people actually use: VLESS+Vision+REALITY was the workhorse, under volume-based blocking on MCI (research/protocol-level-anatomy.md:96; filtering-the-flow.md:251). Today a pasted link with spx= gets the vless-reality family, which carries the stable badge, and then fails when the engine parses its config.
- **independent:** n/a. This is a correctness fix to an existing dial path, not a new family.
- **dial:** Yes, once fixed. sing-box 1.13.12 has vless with Vision flow (sing-vmess vless/protocol.go:19), reality (needs with_utls, which tools/build-engine-android.sh:81 already passes) and trojan. The bugs: - uri/vless.go:90 writes reality.spider_x. OutboundRealityOptions has only enabled, public_key and short_id (option/tls.go:226-230), and Options decoding calls DisallowUnknownFields (option/options.go:31), so the strict parse in engine_singbox.go:262 rejects the whole config. - uri/vless.go:79-81 adds uTLS only when fp= is present, and NewRealityClient errors without it (reality_client.go:55-57). - uri/trojan.go:20-35 ignores fp=, so the hello is Go's crypto/tls fingerprint. - uri/trojan.go:47 labels the route 'other', while the Clash path labels the same thing 'websocket-tls' (core/refresh/parse.go:225).
- **serve:** n/a. These are third-party routes; the publisher is not involved.
- **work:** - bundle/go/uri/vless.go: drop spx/spider_x, and default fp to chrome when security=reality. - bundle/go/uri/trojan.go: honour fp (uTLS block) and pick a consistent family. - core/refresh/parse.go:225: align the Clash trojan mapping with the URI parser. - Add a unit test that runs every uri parser's output through singjson.UnmarshalExtendedContext[option.Options], the same call as engine_singbox.go:262, so future drift fails CI instead of a phone. - Consider an import-time sing-box parse check in core/abi/share.go URIImport.
- **risks:** Very low. Defaulting fp=chrome inherits the REALITY fingerprint question in the next candidate.
- **why:** A dead route showing a stable badge is the exact failure the inventory says is worse than no family, and the fix is a few lines.
- **evidence:** bundle/go/uri/vless.go:87-91 (spider_x written); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/option/tls.go:226-230 (OutboundRealityOptions has no spider_x); sing-box@v1.13.12/option/options.go:29-33 (DisallowUnknownFields); core/engine/engine_singbox.go:262 (strict UnmarshalExtendedContext); bundle/go/uri/uri_test.go:11 (test link has spx=); sing-box@v1.13.12/common/tls/reality_client.go:55-57 (uTLS required); bundle/go/uri/trojan.go:20-47 (no fp, family other); core/refresh/parse.go:225 (trojan mapped to websocket-tls); core/abi/share.go:355-370 (MarshalOutbound bytes go straight into the bundle)

### uTLS fingerprint choice for the REALITY tier — RESEARCH SPIKE (S)

- **what:** Which browser ClientHello our TLS tiers imitate. Daal hardcodes fingerprint chrome (relaypack/client_outbound.go:162,545), which uTLS maps to HelloChrome_133 (utls_client.go uTLSClientHelloID; utls u_common.go:615,646).
- **iran:** Unknown directly. Iran is reported to use JA3/JA4 classification (filtering-the-flow.md:125). A single-user report (Lantern corpus, 2026, pooribitwise) says REALITY connections were reset seconds after the handshake in June 2026. The research also says not imitating X25519MLKEM768 is itself a fingerprint (filtering-the-flow.md:241, 268).
- **independent:** n/a. This tunes a stable tier, not a new one. It matters because it may be why REALITY dies early.
- **dial:** Yes, with_utls is shipped. The defect: the sing-box 1.13.12 REALITY client removes X25519MLKEM768 from both supported_groups and key_share (reality_client.go:134-143). Our REALITY hello is therefore Chrome 133 without ML-KEM, which no Chrome since 131 sends. The websocket-tls hello, built through the normal uTLS path, keeps it. The alternatives are all stale: Firefox_120, Safari_16_0, iOS_14, Edge_85 (u_common.go:605-660). There are no build-size costs.
- **serve:** Client-side only. Nothing changes on the relay.
- **work:** Spike first: 1. Capture the ClientHello of each tier in test-rigs/worldbox (no phone needed) and compute JA4 for REALITY/chrome, REALITY/safari and ws/chrome against a real Android Chrome. 2. If REALITY/chrome is a unique JA4, choose between (a) diversifying the fingerprint per relay in relaypack/client_outbound.go and the mgmt user renderer (cmd/daal-relay-mgmt/singbox_users.go), and (b) waiting for an upstream sing-box that keeps the ML-KEM share in REALITY (the project does not fork sing-box).
- **risks:** Moving to a stale but genuine parrot (Safari 16) swaps a synthetic fingerprint for a rare one. Measure before changing.
- **why:** It is cheap to measure, it may explain early REALITY kills, and any fix is either a config string or an upstream wait.
- **evidence:** sing-box@v1.13.12/common/tls/reality_client.go:134-143 (ML-KEM stripped); sing-box@v1.13.12/common/tls/utls_client.go uTLSClientHelloID (chrome maps to HelloChrome_Auto); metacubex/utls@v1.8.4/u_common.go:605,615,648,656,660; publisher/deploy/relaypack/client_outbound.go:162,545; research/filtering-the-flow.md:125,241,268; research/protocol-level-anatomy.md:61; https://corpus.lantern.io/papers/2026-pooribitwise-iran-advanced-dpi/ (June 2026 report: REALITY reset after handshake; single user)

### Give websocket-tls and hysteria2 a real SNI (choosing SNIs against Iranian lists) — BUILD NOW (M)

- **what:** websocket-tls and hysteria2 put the relay's IP in server_name. Go and uTLS strip an IP literal, so they send a Chrome-shaped hello with no SNI to a hosting-provider address, identical on every relay. naive has already moved to a name derived from its certificate.
- **iran:** Reported in 2026: 'If a site uses an SNI that is not on the whitelist, the connection fails' (Amnezia, Q1 2026, vendor blog). A hello with no SNI is unlikely to be on any allowlist. Iran also checks SNI against IP (it RSTs non-Cloudflare SNIs to Cloudflare IPs; filtering-the-flow.md:129). Under blocklist mode, an innocuous SNI is still better than none.
- **independent:** No. It hardens two stable tiers and removes one fleet-wide correlate.
- **dial:** Yes. It is just a tls.server_name string. Pinning is by SPKI (certificate_public_key_sha256), so the name does not have to match for the client.
- **serve:** The relay certificate should name the same host, so a prober sees something consistent. That reuses the cover-host machinery the naive tier already has (backlog TW-11, docs/backlog-post-45.md:1460-1475). No domain or CDN is needed.
- **work:** - relaypack/client_outbound.go pinnedTLSOpts (:539) and the hysteria2 case: use the per-relay name from publisher/deploy/sni and provider/cover_sni.go instead of p.Server. - cmd/daal-relay-mgmt: reissue the ws and hy2 cert with that SAN. - Run the two-relay on-wire check that the code comment asks for (client_outbound.go:531-537). - Do it in the port-strategy wave.
- **risks:** It changes the wire shape of two shipped tiers. The pool is computable from a single pack (sni/pool.go:66-80), so this removes a free correlate but is not a secret.
- **why:** Sending no SNI is a uniform tell, and the code already names the fix.
- **evidence:** publisher/deploy/relaypack/client_outbound.go:514-537 (recorded, unfixed); publisher/deploy/relaypack/client_outbound.go:426-432 (naive already uses NaiveVerificationName); publisher/deploy/sni/pool.go:1-80; publisher/deploy/sni/rule.go R1-R7; research/filtering-the-flow.md:99-101,129; https://amnezia.org/en/blog/internet-censorship-in-iran-q1-2026-and-forecast

### Domestic or whitelisted Iranian SNI as REALITY cover — NEVER (n/a)

- **what:** Point the REALITY cover (dest and server_name) at a domestic or whitelisted Iranian domain, so the SNI the censor sees is one it allows.
- **iran:** Whitelist mode is real (filtering-the-flow.md:97-101), but the gate is the IP/port tuple: 'if its egress port or destination IP falls outside the allowed tuple set, the packets vanish' (:101). A Hetzner IP serving a domestic site's handshake is the implausible pairing the corpus warns about (protocol-level-anatomy.md:37, 116).
- **independent:** No. Same IP, same port, same tier.
- **dial:** Yes. It is only a server_name value.
- **serve:** Structurally bad for a self-hoster. REALITY must relay the real handshake from the relay to the dest. Domestic sites often refuse foreign source IPs, and an Iranian SNI on a German IP breaks rule R5 (ASN-class match) in publisher/deploy/sni/rule.go. SNI-versus-IP consistency is checked in Iran (filtering-the-flow.md:129).
- **work:** None. Keep R3-R6 in sni/rule.go as they are.
- **risks:** High detectability: an obvious mismatch between SNI and IP. Pool entries tied to Iran would also be politically sensitive.
- **why:** The whitelist gate is the IP, and a domestic name on a foreign IP is a stronger tell than a dull mirror.
- **evidence:** research/filtering-the-flow.md:97-101,129; research/protocol-level-anatomy.md:37,116; publisher/deploy/sni/rule.go R5 (lines 51-78); publisher/deploy/provider/cover_sni.go:16-21

### TLS ClientHello fragmentation and record splitting (sing-box tls.fragment / record_fragment) — NEVER (S)

- **what:** Split the ClientHello across TCP segments (fragment) or TLS records (record_fragment) at the SNI, so a DPI that does not reassemble cannot read the name.
- **iran:** Contested. Older work says Iran's DPI reads only the first two data packets and does not reassemble (intel-and-some-working-methods.md:77). A 2026 single-user report says it does reassemble 10-30 byte fragments and still extracts the SNI (Lantern corpus, pooribitwise 2026). Fragmentation helps only when the problem is a blocked SNI, and our relays already avoid that: REALITY sends an allowed cover name, and ws/hy2 send no SNI.
- **independent:** No. It is a modifier on the same TCP/443 flows.
- **dial:** Partly, and mostly useless for us in sing-box 1.13.12: - The options exist (option/tls.go:114-116). - fragment alone does nothing on std and uTLS clients, which wrap only when record_fragment is set (std_client.go:53; utls_client.go:61). - REALITY never uses the wrapper, because it builds utls.UClient on the raw conn (reality_client.go:128). - naive rejects both (protocol/naive/outbound.go:75). - The wrapper only splits when IndexTLSServerName finds an SNI (common/tlsfragment/conn.go Write), so it is a no-op for our no-SNI tiers. - The route-action tls_fragment (option/rule_action.go:168-184) applies to direct and routed connections, not to our outbound.
- **serve:** Client-side only.
- **work:** - Close specs/modifiers/tls_fragment.md (still PENDING) with this evidence, and note the upstream no-op so nobody 'enables' it. - Optionally let imported third-party profiles keep record_fragment if a link supplies it.
- **risks:** The fragment pattern itself is a fingerprint (specs/modifiers/tls_fragment.md risk notes). Reassembly reportedly defeats it.
- **why:** In the shipped engine it does nothing on Daal's own tiers, and in 2026 Iran reportedly reassembles the fragments anyway.
- **evidence:** sing-box@v1.13.12/option/tls.go:114-116; sing-box@v1.13.12/common/tls/std_client.go:52-57; sing-box@v1.13.12/common/tls/utls_client.go:60-65; sing-box@v1.13.12/common/tls/reality_client.go:119-128; sing-box@v1.13.12/protocol/naive/outbound.go:75-77; sing-box@v1.13.12/common/tlsfragment/conn.go:43-50 (split only when an SNI is present); research/intel-and-some-working-methods.md:77; specs/modifiers/tls_fragment.md; https://corpus.lantern.io/findings/2026-pooribitwise-iran-advanced-dpi__iran-dpi-tcp-reassembly-defeats-fragmentation/

### FakeSNI / out-of-window ClientHello injection (PechenyeRU/FakeSNI and the low-TTL variant) — NEVER (L)

- **what:** Before the real hello, inject a decoy ClientHello with a whitelisted SNI that the server discards: either at a sequence number left of the server's window, or with a TTL too low to reach the server. A stateless DPI then waves the flow through.
- **iran:** It worked briefly. Both the sequence and TTL variants beat Iran's DPI for about four days in 2026, until Iran put Cloudflare IPs behind a stateful NAT that checks sequence numbers and checksums (Lantern corpus, tuleo1 2026). The research warns that one signature kills the whole tool class (intel-and-some-working-methods.md:128). It also only spoofs the SNI; the destination IP must still pass, and in the tool it is a Cloudflare edge, not a Hetzner box (intel:118).
- **independent:** No. It decorates the same flows. For REALITY it adds nothing, because REALITY already sends a real allowed SNI.
- **dial:** Not on Android. The sequence-forging variant needs SOCK_RAW with CAP_NET_RAW, NFQUEUE and a system-wide conntrack sysctl (intel:120-126). A non-root app has none of these: VpnService gives a TUN for app traffic, and the engine's own relay socket is an ordinary protected kernel socket. The low-TTL variant can be done without root, ByeDPI-style (setsockopt IP_TTL plus buffer tricks), but would need a custom pre-proxy below sing-box. The upstream tool has no LICENSE file (intel:142).
- **serve:** Publisher-independent. It is purely a client trick.
- **work:** None. Leave specs/modifiers/client_desync.md as a dormant reserved slot (Linux desktop only), and record the 2026 four-day lifetime there.
- **risks:** A deterministic signature; system-wide side effects on Linux; TTL tuning per carrier; it dies the moment stateful NAT or reassembly is deployed, which has already happened.
- **why:** It cannot run on non-root Android, its 2026 lifespan was about four days, and it solves an SNI problem our relays do not have.
- **evidence:** research/intel-and-some-working-methods.md:112-142,170; specs/modifiers/client_desync.md; development-phases/daal-roadmap-v3.md:834; https://corpus.lantern.io/findings/2026-tuleo1-internet-analysis-shutdown__iran-tcp-sequence-sni-spoof-4-days/

### ShadowTLS v3 (wrapping Shadowsocks-2022) — BUILD LATER (L)

- **what:** The client completes a real TLS 1.3 handshake relayed from a cover site, authenticated by an HMAC in the SessionID, then carries Shadowsocks-2022 framed as application data. Probes see the real site.
- **iran:** No Iran-specific 2025-26 evidence in the research. In China, SS-2022 survives behind ShadowTLS v3 or Cloak (filtering-the-flow.md:251). The roadmap supplement calls it popular in the Iranian community (daal-roadmap-v3-supplement-diaspora-helper.md:1055), and it was removed as a first-class family (:99).
- **independent:** Mostly no: same IP, the same need for 443 (or 80), the same cover-SNI pool, the same relayed-handshake class as REALITY, and the inner TLS-in-TLS remains. One real difference: its hello goes through the normal uTLS path, so it keeps Chrome's ML-KEM share where our REALITY hello has it removed (reality_client.go:134-143; shadowtls/outbound.go:46-61). That only matters if the fingerprint spike shows the hello is what triggers REALITY kills.
- **dial:** Yes, in shipped sing-box: the shadowtls outbound is registered (inventory registry quote) via sing-shadowtls v3_client.go. It needs two outbounds (shadowsocks with detour set to shadowtls), but BuildSingBoxConfig accepts a single profile object (core/engine/config.go:68-115). shadowtls is in tcpOnlyOutboundTypes (config.go:228-233). No size cost.
- **serve:** The shadowtls inbound with handshake set to the cover host. But 443/tcp belongs to REALITY (relayports.go:33), so it needs either a second Hetzner IPv4 (small extra monthly cost) or 80/tcp. A fresh provision is needed, because cloud-init has no upgrade path (inventory).
- **work:** - core/engine/config.go: support an auxiliary detour outbound in the profile. - relaypack/client_outbound.go: add a new case. - cmd/daal-relay-mgmt: add inbound and user rendering. - publisher/deploy/relayports: add the port. - cloud-init templates. - bundle/go/bundle/types.go plus family.go plus derive_tree.ts: add the family (or route it through family_specific_config, as the supplement suggests). - Engine pre-flight tests.
- **risks:** Same probe and TLS-in-TLS exposure as REALITY. Sharing a port is impossible, so it costs a second IP or port 80.
- **why:** It only earns its keep if the fingerprint spike shows our REALITY hello is the trigger. Otherwise it fails exactly when REALITY does.
- **evidence:** sing-shadowtls@v0.2.1-0.20250503051639-fcd445d33c11/v3_client.go; sing-box@v1.13.12/protocol/shadowtls/outbound.go:34-76; sing-box@v1.13.12/option/shadowtls.go; core/engine/config.go:68-115,228-233; publisher/deploy/relayports/relayports.go:33; research/filtering-the-flow.md:251; development-phases/daal-roadmap-v3-supplement-diaspora-helper.md:99,1055

### Trojan with fallback — NEVER (M)

- **what:** TLS with a real or pinned certificate. The first record carries the password hash. Anything else is passed to a fallback web server, so probes see a website.
- **iran:** Raw Trojan TLS: 'Detection + volume threshold' (protocol-level-anatomy.md:94). Exposed to TLS-in-TLS detection and the TrojanProbe implementation fingerprinting (filtering-the-flow.md:181-185). Trojan-Go over a CDN works only with SNI rotation (protocol-level-anatomy.md:95), which needs a domain and a CDN.
- **independent:** No. It is the same failure class as websocket-tls: TLS to the same Hetzner IP. 443 belongs to REALITY.
- **dial:** Yes. The trojan outbound is in sing-box 1.13.12, with no tag or size cost.
- **serve:** Yes technically: the trojan inbound with fallback and fallback_for_alpn (option/trojan.go). It is the only sing-box inbound with a fallback (inventory, probing section). It needs a port: 443 is taken, so it would mean 80 or a second IP. Self-signed with a pin is enough.
- **work:** None as a served family. (The import fixes are in the first candidate.)
- **risks:** TrojanProbe-style fingerprints, a nginx fallback to maintain, and no gain over ws-tls/naive on the same IP.
- **why:** It adds nothing over websocket-tls on the same IP. Its only edge, the probe fallback, is worth less than putting an existing TLS tier on a whitelisted port.
- **evidence:** sing-box@v1.13.12/option/trojan.go; research/protocol-level-anatomy.md:94-95; research/filtering-the-flow.md:181-185; docs/transport-family-inventory.md (probing table; fallback exists on trojan only); publisher/deploy/relayports/relayports.go:33,128-129 (443 taken; ws and naive on 8444/8445)

### REALITY variants: Vision/XTLS, xhttp-reality — NEVER (XL)

- **what:** Vision (xtls-rprx-vision) pads the inner handshake and splices afterwards. xhttp is Xray's split-HTTP transport, usable under REALITY or behind a CDN.
- **iran:** Vision with REALITY was the workhorse through 2024; on MCI, volume-based blocking hits after hours (protocol-level-anatomy.md:27,96). Xue et al. still detect Vision above 70% (protocol-level-anatomy.md:33). xhttp is popular in the Iranian Xray ecosystem but has no Iran measurements in the research.
- **independent:** No. Both run on the same IP and 443 under the same REALITY cover.
- **dial:** Vision is already shipped (client_outbound.go:158; cmd/daal-relay-mgmt/singbox_users.go:434; sing-vmess vless/protocol.go:19). xhttp is not available: sing-box 1.13.12 knows only the transports http, ws, quic, grpc and httpupgrade (constant/v2ray.go:3-9). It exists only in forks (sing-box-extended, sing-box-lx). Getting it would mean shipping Xray-core as a second engine (MPL-2.0, with a large addition to every APK) or forking sing-box, which the project does not do.
- **serve:** Vision: already done. xhttp would need an Xray-core inbound on the relay.
- **work:** None for Vision. For xhttp: none until upstream sing-box ships it.
- **risks:** A second engine doubles the attack surface and the build complexity.
- **why:** Vision is already shipped, and xhttp is not in upstream sing-box while adding nothing on our own IP.
- **evidence:** sing-box@v1.13.12/constant/v2ray.go:3-9; sing-vmess@v0.2.8-0.20250909125414-3aed155119a1/vless/protocol.go:19; publisher/deploy/relaypack/client_outbound.go:158; cmd/daal-relay-mgmt/singbox_users.go:434; research/protocol-level-anatomy.md:27,33,96; research/filtering-the-flow.md:147

### ECH (Encrypted Client Hello) — NEVER (n/a)

- **what:** TLS 1.3 encrypts the inner ClientHello under an outer public name, using an ECHConfig normally fetched from a DNS HTTPS record.
- **iran:** Iran kills ECH at bootstrap by resolving DoH endpoints to bogon addresses, so clients never get an ECHConfig (intel-and-some-working-methods.md:79). Russia blocks the extension in-band (filtering-the-flow.md:41). Under an SNI allowlist the outer name must itself be allowlisted.
- **independent:** No. Same IP, same TCP/443.
- **dial:** Yes. It uses stdlib ECH (Go 1.24+; core/go.mod has go 1.25.0) with no build tag (ech_tag_stub.go). It works on the std and uTLS clients but is rejected together with REALITY ('Reality is conflict with ECH', utls_client.go:259-261). naive's Cronet has its own ECH.
- **serve:** The inbound tls.ech key exists (option/tls.go InboundECHOptions), and the ECHConfig could ship inside the pack to get around Iran's DNS bootstrap block. But a self-hosted public name is our own host: there is no anonymity set, and the inner SNI it would hide is one we do not need to hide. Real value needs a big ECH provider (Cloudflare), which means a CDN account, and Cloudflare ranges are selectively blocked in Iran (filtering-the-flow.md:127-129).
- **work:** None.
- **risks:** The ECH extension is a visible marker. Cloudflare ToS and dependence if pursued through a CDN.
- **why:** For a self-hosted relay ECH hides nothing that matters and adds a marker; its value needs a provider-scale anonymity set we do not have.
- **evidence:** sing-box@v1.13.12/common/tls/utls_client.go:259-264; sing-box@v1.13.12/common/tls/ech_tag_stub.go; sing-box@v1.13.12/option/tls.go (InboundECHOptions, OutboundECHOptions); research/intel-and-some-working-methods.md:79; research/filtering-the-flow.md:41,127-129; research/Protocols.md:79,119,134


## SHUTDOWN SURVIVAL: DNS tunnels, ICMP, in-Iran relays, whitelisted foreign carriers, offline/mesh sharing, honest shutdown behaviour

### Honest shutdown mode: detect a national cut, back off, keep packs (AC-18 / MP-18) — BUILD NOW (M)

- **what:** An observation outside the routes that tells 'Iran's international link is cut' apart from 'this relay is burned'. It is one HTTPS request to a large domestic site plus one to a whitelisted foreign site, both ordinary traffic every Iranian phone makes. On a cut, Daal stops racing, says so plainly, keeps every pack, and backs off to a slow, quiet retry.
- **iran:** This is about the censor's behaviour, not a transport. Every 2025–2026 event split along the NIN/international line: June 2025 kept the NIN (FOCI 2026); Jan 8 2026 cut even the NIN (arXiv 2603.28753); Feb 28–May 25 2026 ran at ~1% of baseline (filtering-the-flow.md:121; protocol-level-anatomy.md:21). The censor document says reopening phases are watched to 'identify the violator within the first 48 hours' (intel:29) and that staged reopening 'makes identifying the user easier' (intel:59). Hammering relays at the moment of reopening is therefore a user-safety problem, not only a battery problem.
- **independent:** n/a. It is not a way in. It stops Daal misreading a shutdown as the failure of all four stable families at once.
- **dial:** No new dialling. It reuses the engine's existing HTTP stack, and the probes go out on the underlying network (protected sockets, core/engine/platform_singbox.go:21-51). It adds nothing to the binary.
- **serve:** Publisher-independent. On the publisher side, the health and rotation surfaces should read the same verdict so a publisher does not rotate or re-rent a relay because of a national cut. This matters for cost: renting has no rollback (memory note on provisioning).
- **work:** core/selection or pathmanager: a 'national_cut' verdict next to network_down/relay_unreachable (backlog AC-18 at docs/backlog-post-45.md:2012-2023, MP-18 at :2396-2399). core/abi: emit the verdict in diagnostics and the main-screen state. specs/failure-taxonomy-v1.md: add the class. Choose the anchors as a design decision written down: at least two domestic and one whitelisted foreign, never a Daal host. client-ui/src/lib/mainScreen.ts and the connection components (AutoFailure.tsx): copy in en/fa. Scheduler: a back-off profile while the verdict holds. Publisher side: health and rotation recommend read the verdict (Wizard.rotateRecommend, capability-matrix.md:104). Size: about 4–5 days.
- **risks:** The probe is a weak fingerprint only if the anchors are odd. Big domestic and whitelisted sites are what every phone already contacts. The anchor list will need updating when the whitelist changes. A false 'cut' verdict on a captive portal must not stop the user from trying, so it is advisory and the button always works.
- **why:** This is the one thing Daal can always do honestly during a shutdown. It protects users at reopening, protects packs from deletion, and saves publishers money, all without a new protocol.
- **evidence:** docs/backlog-post-45.md:2012-2023 (AC-18: a total blackout reads as relay_unreachable); docs/backlog-post-45.md:2396-2399 (MP-18: needs an observation outside the routes); research/intel-and-some-working-methods.md:29 (identify violators within 48 h of reopening); research/intel-and-some-working-methods.md:59 (staged exit 'makes identifying the user easier'); research/filtering-the-flow.md:119-121 (June 2025 stealth blackout; Jan 2026 53+ days); arXiv 2603.28753 (Jan 8 2026 cut included the NIN; Jan 26 allowlist 'new normal'); FOCI 2026 Niere et al. (shutdowns Jan 8–Feb 1 and Feb 28–May 25 2026)

### Share Daal itself offline: signed APK to a nearby phone (Quick Share / Bluetooth / Wi-Fi Direct) — BUILD NOW (S)

- **what:** A 'Give Daal to someone nearby' action. It copies the installed APK to cache and hands it to the Android share sheet through the existing FileProvider, so Quick Share, Bluetooth or Wi-Fi Direct can carry it with no internet. The About screen shows the release-signing certificate's SHA-256 as words, so the receiver can check they got the real app.
- **iran:** Works in every shutdown regime, because it never touches the network. It is needed because the censor plan limits domestic-messenger files to 5 MB per session and bans executable formats outright (intel:25). In crisis mode, file transfer in domestic messengers and uploaders is halted (intel:53). Play Store access cannot be counted on either: it was on the Jan 26 2026 allowlist (arXiv 2603.28753), but Daal is sideloaded. the-build.md:118 calls blackout bootstrap 'the one thing those successful projects have not yet solved'.
- **independent:** Fully independent of every family. It moves the app, not traffic.
- **dial:** n/a. No engine change.
- **serve:** Publisher-independent.
- **work:** client-shell/tauri/plugins/daal-platform/android/.../platform/ (a new ShareApk.kt next to ShareText.kt): read applicationInfo.sourceDir, copy to cacheDir, and add a cache path to @xml/file_paths (the FileProvider already exists at src-tauri/gen/android/app/src/main/AndroidManifest.xml:62-70). Add a JNI and Tauri command in src-tauri (opened.rs pattern), a client-ui button with en/fa strings in client-ui/src/i18n/d2, and a signing-cert fingerprint read via PackageManager.GET_SIGNING_CERTIFICATES. Size: 1–2 days.
- **risks:** Some Samsung Bluetooth stacks refuse .apk files, so offer Quick Share first. Play Protect may warn on install. Carrying the app is already the user's exposure; this adds a second person. The fingerprint check must use the real release key (memory: release-keys/android-device-signing.jks). A wrong-key APK forces an uninstall, which deletes the operator database. The copy must warn that only APKs from people you trust are safe, and that the fingerprint is the check.
- **why:** This is the cheapest shutdown-proof feature in the cluster, and APK distribution is the bottleneck when messengers ban executables.
- **evidence:** research/intel-and-some-working-methods.md:25 (5 MB per session, executable formats completely banned); research/intel-and-some-working-methods.md:53 (crisis mode halts file transfer in domestic messengers); research/the-build.md:71 (Nearby / Bluetooth as Android-to-Android paths); research/the-build.md:118 (blackout bootstrap unsolved); client-shell/tauri/src-tauri/gen/android/app/src/main/AndroidManifest.xml:62-70 (FileProvider present); client-shell/tauri/plugins/daal-platform/android/src/main/java/org/daal/desktop/platform/ShareText.kt (share-sheet pattern to copy)

### DNS tunnel lifeline route (dnstt-class: dnstt, or MasterDnsVPN as the engine) — RESEARCH SPIKE (L)

- **what:** TCP streams carried in DNS queries and answers (base32 query names, TXT answers) through the ISP's own recursive resolver to an authoritative server the publisher runs. dnstt adds KCP, smux and a Noise encryption layer, so the resolver sees only ciphertext labels.
- **iran:** Partly working, in windows. It was reported as the only working method in the Feb 28 2026 shutdown, with users trying different resolvers and ISPs to find a working path (Lantern corpus finding; LLM-extracted, flagged 'review before relying'). The void blog saw a sharp rise in TXT queries after Jan 11 2026 and said it worked because authorities 'did not anticipate it', expecting it to be blocked next time. One aggregator reports dnstt and iodine neutralised once the censor controlled authoritative resolution (Jan 8–9). Structural reason it works: the whitelister always passes UDP/53 (filtering-the-flow.md:99), and as long as Google, Gmail and GitHub are whitelisted by FQDN, national resolvers must recurse abroad. Structural reason it is fragile: the censor plan already forces all resolvers to national DNS (intel:29). Limiting recursion to allowlisted zones or rate-limiting TXT queries kills it in one change. FOCI 2026 measured heavy DNS-over-UDP packet loss after the June 2025 shutdown. Reported throughput is about 42 KB/s for dnstt (samnet guide, third-party).
- **independent:** Yes, strongly. It never connects to the relay's IP from the phone; the resolver does. So it survives relay-IP blocking, the 443 whitelist, TLS-in-TLS detection and SNI filtering, all of which hit the stable four. It fails together with them only when national DNS stops recursing abroad.
- **dial:** Not in sing-box 1.13.12: there is no DNS-tunnel outbound (protocol/ holds anytls, direct, dns, http, hysteria/2, naive, shadowsocks, shadowtls, socks, ssh, tailscale, tor, trojan, tuic, vless, vmess, wireguard; the 'dns' entry is the DNS hijack, not a tunnel; inventory:31-47). The path is the dnstt Go library, public domain/CC0 (verify at pin time), run in-process. Its deps are xtaci/kcp-go v5, xtaci/smux and flynn/noise; none are in core/go.mod today (sagernet/smux is a fork). Estimated cost is about 1.5–3 MB per Android ABI, unmeasured; kcp-go pulls in reedsolomon and extra cipher suites. Wiring: register a custom 'dnstt' outbound in the registry instead of the plain include.Context (core/engine/side_singbox.go:173, engine_singbox.go:254). Its UDP sockets must go through the protect callback (core/engine/platform_singbox.go:21-51), or the queries loop into the TUN. Resolver choice: plain UDP/53 to the underlying network's resolvers, because DoH/DoT have been blocked since Sept 2022 (filtering-the-flow.md:117). That needs a host signal for the pre-VPN DNS servers, plus a small scan list. MasterDnsVPN (Go, same Iranian author as MasterHttpRelayVPN, intel:111) claims better efficiency than slipstream; its licence and code quality are unverified.
- **serve:** Only if the publisher owns a domain. Today's relays have none (no ACME, no domain in hetzner/profile_render.go; 80/tcp is reserved 'for future ACME', live_client.go:520). The relay needs: an NS delegation such as t.<domain> → ns.<domain> → relay IP, which the Cloudflare BYO-zone code can write (publisher/deploy/cloudflare/dns.go; a third-party account and a registrar purchase); 53/udp in the Hetzner firewall and a 'dnstt' entry in relayports (publisher/deploy/relayports/relayports.go:32-136); and a dnstt-server binding the public IP (not 0.0.0.0, which collides with systemd-resolved's 127.0.0.53 stub on Ubuntu). dnstt-server would forward to a new loopback-only vless or ss-2022 inbound, so per-recipient credentials stay those of the existing user machinery (cmd/daal-relay-mgmt/singbox_users.go). That means a new hash-pinned mgmt artifact and a fresh provision, because cloud-init has no upgrade path (inventory:119-134). A publisher-independent variant would be importing community dnstt configs, as users shared public dnstt servers in Feb 2026, but that hands traffic to unknown operators.
- **work:** bundle/go/bundle/types.go: a new TransportFamily value 'dns-tunnel' (spec_version bump). core/routestore/family.go, client-ui/src/contract/derive_tree.ts and tools/check-family-maturity.mjs: label experimental. bundle/go/uri and importer: a dnstt route object (domain, server Noise pubkey, resolver hints). core/engine/config.go: outbound shape. core/engine: the custom outbound plus protect, and a resolver discovery and scan list. Android plugin: expose the underlying network's DNS servers from NetworkWatch.kt. Publisher side: relayports, cloudinit templates, the cmd/daal-relay-mgmt loopback inbound, a cloudflare NS-record writer, and a profiles/*.json option that is off by default. Publisher wizard: a 'have a domain?' step. specs/transport-families-v1.md and docs/transport-family-inventory.md rows. Spike first, 2–3 days: dnstt in-process on the spare Sony phone behind protect(), against a lab authoritative server; measure throughput and battery; compare with MasterDnsVPN and slipstream. The full build is well over a week.
- **risks:** Safety is the main risk. Queries go through the subscriber's ISP resolver with an identity-bound SIM (filtering-the-flow.md:133), so one captured pack reveals the tunnel domain, and resolver logs then list everyone who ever queried it, retrospectively. The traffic is easy to see: the void blog saw the TXT surge from outside, and the censor plan already does entropy and packet-size monitoring (intel:25). The censor can kill it cheaply at national DNS (intel:29). The publisher needs a domain and registrar account, which is an identity link and a cost. Quality is poor: high RTT, about 40 KB/s, no video. Upstream dnstt is a small single-maintainer project.
- **why:** This is the only family with field reports of surviving an international cut, and it fails independently of everything Daal ships. It is also L-sized, needs a publisher domain, and is the most identifying channel in the cluster, so a 2–3 day phone spike should come before any enum value.
- **evidence:** research/filtering-the-flow.md:99 (whitelister permits DNS/UDP 53, HTTP/80, HTTPS/443); research/filtering-the-flow.md:117 (DoH/DoT blocked Sept 20 2022); research/intel-and-some-working-methods.md:29 (all resolvers forced to National DNS; third-party DoH/DoT blocked); research/intel-and-some-working-methods.md:111 (MasterDnsVPN: Go DNS-tunnel L4 VPN needing user-delegated NS); research/intel-and-some-working-methods.md:25 (traffic entropy / packet-size monitoring); docs/transport-family-inventory.md:31-47 (no such outbound in sing-box 1.13.12); docs/transport-family-inventory.md:119-134 (needs a fresh relay); core/engine/platform_singbox.go:21-51 (protect callback); publisher/deploy/cloudflare/doc.go:1-28 (BYO zone surface); Lantern corpus finding 2026 (dnstt the only functioning method, Feb 2026); void blog report-of-state (TXT surge after Jan 11 2026); samnet DNS tunnelling guide (dnstt about 42 KB/s, slipstream about 63 KB/s)

### slipstream (QUIC-over-DNS tunnel) — RESEARCH SPIKE (M)

- **what:** A DNS tunnel that runs QUIC (picoquic) inside DNS messages for congestion control and multi-resolver bandwidth aggregation. It is a faster cousin of dnstt.
- **iran:** Unknown, no independent field data. A vendor blog ranks it speed-first but less stealthy (marketing). One LLM-extracted Lantern note says QUIC-based DNS is not viable in Iran because the censor cuts after the handshake; that note seems to be about QUIC on UDP/443, which is blocked outright (FOCI 2026; filtering-the-flow.md:99), not QUIC wrapped in DNS. Unverified either way.
- **independent:** Same independence as dnstt, and the same failure point: national DNS recursion.
- **dial:** Not in sing-box. It is C (picoquic); a Rust port is reported. Neither is Go, so it would need an NDK-built .so and a local SOCKS bridge, the shape the tor route took, which never shipped (inventory row 8). Licence: verify.
- **serve:** Same as dnstt: a domain, NS delegation and 53/udp on the relay, plus a C server binary in the pinned artifacts.
- **work:** Only as an arm of the dnstt spike: build it on the laptop off the critical path and compare throughput through a lab resolver. Do not build it separately.
- **risks:** A second native toolchain on Android (the APK is already ~92 MB, backlog C1 at docs/backlog-post-45.md:676). Possibly more detectable than dnstt (a larger, more regular query shape). All the dnstt safety risks also apply.
- **why:** It is worth one comparison inside the dnstt spike. It only earns a build if it is clearly faster in a Go-free way Daal can ship, which today it is not.
- **evidence:** research/filtering-the-flow.md:99; FOCI 2026 Niere et al. (QUIC blocked entirely after June 2025; DNS/UDP drops); samnet DNS tunnelling guide (about 63 KB/s vs dnstt about 42 KB/s); endpositive.github.io/slipstream; docs/transport-family-inventory.md:60 (a native-binary family that never shipped)

### iodine (IPv4-over-DNS) — NEVER (n/a)

- **what:** An older C tool that tunnels raw IP packets over DNS, using a tun device on both ends, with a raw mode that skips the resolver.
- **iran:** Reported neutralised alongside dnstt once the censor controlled authoritative resolution (Jan 8–9 2026 aggregator). It has no record of surviving where dnstt failed.
- **independent:** Same failure point as dnstt, with worse traffic shape (NULL/TXT bursts, no Noise layer).
- **dial:** No. It is C and needs its own tun device, which conflicts with Daal's single VpnService TUN. Not in sing-box.
- **serve:** Needs root, tun and 53/udp on the relay, plus a domain.
- **work:** None.
- **risks:** Unencrypted by default, easy to fingerprint, and architecturally incompatible with the Android data plane.
- **why:** dnstt does the same job as an in-process Go library with encryption; iodine adds nothing but problems.
- **evidence:** research/filtering-the-flow.md:99; Lantern corpus / aggregator note: dnstt and iodine neutralised when the censor controlled authoritative NS (Jan 2026)

### DNS-TXT pack courier (fetch a signed pack through national DNS, no tunnel) — BUILD LATER (M)

- **what:** The signed relaypack or freshness document, chunked into TXT records under a publisher's zone and fetched with ordinary resolver queries. It is stateless, needs no server beyond authoritative DNS, and its integrity comes from the existing signatures.
- **iran:** Same survival window as dnstt: it works while national resolvers recurse abroad (filtering-the-flow.md:99; intel:29). It needs a few dozen queries a day per device instead of a stream, so it is far less visible than a tunnel. Its value is in whitelist phases, when the relay IP has burned and the HTTPS mirrors (R2 / GitHub Pages) are blocked. During a full international cut a new pack points at relays nobody can reach, unless it points at a DNS-tunnel route.
- **independent:** Yes for the recovery path. It does not depend on HTTPS mirror reachability (W3-1 pointers are placeholders; W3-7 mirrors have never touched a real endpoint).
- **dial:** No tunnel is needed. miekg/dns is already an indirect dependency (core/go.mod:69), or the system resolver can be used through protected sockets. It adds nothing to the binary.
- **serve:** Publisher-independent of the relay. The records can live in the publisher's Cloudflare zone, written through the existing cloudflare package (dns.go), so Cloudflare's authoritative servers answer. That is a third-party account and a domain. Alternatively the relay can answer as authoritative.
- **work:** publisher/deploy/freshness: a 'dnstxt' provider; the provider set is open (mirrors.go:105-118), so it needs only a new backend next to backends/r2 and ghpages. publisher/deploy/cloudflare/dns.go: a TXT chunk writer. core/refresh/relaypack_refresh.go plus core/bootstrap: a DNS fetcher with a size cap; it must respect the W3-2 unbounded-read lesson (docs/backlog-post-45.md:322-333). Spec in specs/bootstrap-pointer-v1.md or a new section. Size: about 4–5 days, after W3-7/W3-9 are real.
- **risks:** The zone name is an identifier in the same way as the dnstt domain, but each device sends few queries. TXT size limits apply: chunking and EDNS0 are needed and resolvers may truncate. It depends on the publisher having a Cloudflare zone.
- **why:** It is a low-visibility, independent recovery channel built from parts Daal already has, but it only pays off once the HTTPS mirror layer it sits beside actually works.
- **evidence:** publisher/deploy/freshness/mirrors.go:105-118 (open provider set); publisher/deploy/freshness/doc.go:164-167 (r2 and ghpages backends); docs/backlog-post-45.md:308-321 (W3-1 placeholder pointer hosts); docs/backlog-post-45.md:596-603 (W3-7 never touched a real endpoint); docs/backlog-post-45.md:356-367 (W3-3 no manual refresh); research/intel-and-some-working-methods.md:29

### ICMP tunnel (ping tunnel) — NEVER (n/a)

- **what:** Payload carried inside ICMP echo request and reply packets to a server that answers its own echo traffic.
- **iran:** Blocked. The censor plan calls for 'complete and permanent blocking of outbound IPv6, UDP, and ICMP', capping outbound ICMP at about 3 packets per session (intel:37), applied unconditionally in crisis mode (intel:53). The void blog reports home networks at 100% blocked for UDP and ICMP in 2026, and says ICMP tunnelling worked during the late-2024 conflict but no longer does.
- **independent:** It would be, but it is dead first.
- **dial:** Not in sing-box. x/net/icmp exists, and Android allows unprivileged ping sockets, but there is nothing worth wiring.
- **serve:** A raw socket on the relay, with kernel echo disabled.
- **work:** None.
- **risks:** A 3-packet-per-session cap makes it useless, and any volume is an obvious anomaly.
- **why:** The censor's own plan names it and caps it at 3 packets, and 2026 field reports say it is blocked.
- **evidence:** research/intel-and-some-working-methods.md:37 (block ICMP; at most about 3 outbound ICMP packets per session); research/intel-and-some-working-methods.md:53 (crisis mode: unconditional ICMP block); void blog report-of-state (UDP/ICMP near-complete block 2026; ICMP tunnel worked late 2024, blocked now)

### Chain through a relay INSIDE Iran (domestic VPS → foreign relay) — NEVER (n/a)

- **what:** The recipient dials a domestic VPS over the NIN (cheap, unfiltered), and that VPS forwards over whatever international path its datacenter tier has. This is the common Iranian 'Iran–abroad tunnel' seller pattern.
- **iran:** Partly, and worst exactly when it matters. In whitelist phases a datacenter VPS can have a better international tier than a SIM (filtering-the-flow.md:133; business 'International Stable Internet'). But datacenters were disconnected pre-emptively in 2026 because of past datacenter proxy tunnelling (void blog), and on Jan 8 2026 even the NIN was cut (arXiv 2603.28753). Amnezia calls Iranian-server VPNs 'suspicious', some running unencrypted configs.
- **independent:** Only partly. The domestic leg avoids the border DPI, but the domestic-to-foreign leg still needs one of the families that work at the border.
- **dial:** Nothing new. A route pointing at a domestic IP is an ordinary vless-reality or other route; the chaining happens on the domestic box. Imported configs of this shape already work.
- **serve:** Structurally impossible for a publisher abroad to do safely. Iranian hosts require national-ID KYC and identity binding (filtering-the-flow.md:133-137), paying them from abroad raises sanctions problems for the publisher, and Daal's provisioner is Hetzner/Vultr/Stark only (publisher/deploy/providers). A trusted person inside could run it, but they would then operate an unlicensed 'filter breaker' under the Feb 2024 SCC statute (filtering-the-flow.md:137) with their identity on the invoice.
- **work:** None. Do not add a domestic-provider adapter.
- **risks:** Extreme legal risk to whoever rents it. The censor can see and seize the box, and with it every recipient's traffic and credentials. It dies first in a national cut.
- **why:** It puts a named person inside Iran on the hook and fails in exactly the shutdowns it is meant for; client-side it already works with zero code for anyone who brings one.
- **evidence:** research/filtering-the-flow.md:133 (tiered access, business tier, identity binding); research/filtering-the-flow.md:137 (Feb 2024 statute criminalises unlicensed filter-breakers); research/protocol-level-anatomy.md:19 (Feb 2024 tiered-internet statute); void blog report-of-state (datacenters pre-emptively disconnected 2026); arXiv 2603.28753 (NIN cut on Jan 8 2026); Amnezia Q1 2026 (Iranian-server VPNs suspicious)

### Whitelisted foreign services as DATA carriers (Google Apps Script relay / MasterHttpRelayVPN pattern) — NEVER (n/a)

- **what:** Traffic serialised into HTTPS calls to a Google Apps Script web app, fronted as SNI www.google.com with Host script.googleusercontent.com on Google's anycast. The script fetches the real URL with UrlFetchApp, or POSTs onward to the publisher's relay.
- **iran:** Partly, as an emergency fallback in 2026. It went viral on Iranian Telegram during a 2026 filtering wave (intel:101), and the April 2026 composition lists it as the fallback 'when everything else is IP-swept' (intel:173). It is brittle: the first JA3/JA4 classifier on AS15169 kills every install at once (intel:109); Google may close the same-front quirk; and the void blog says Google 'blocks Iranian IPs entirely' for some services. The censor plan whitelists by FQDN, IP prefix and port with full DPI (intel:29,47).
- **independent:** Yes. It depends on Google staying whitelisted, not on the relay's IP or the 443 families.
- **dial:** Not in sing-box. A meek-style byte tunnel over Apps Script would be new code: uTLS Chrome fingerprint and polling. The original tool is HTTP-only, with a local MITM CA (intel:103), which a system-wide VPN cannot use without breaking every pinned app (intel:95,161).
- **serve:** Needs the publisher's Google account (identity link, ToS) and an HTTP endpoint on the relay for UrlFetchApp to reach.
- **work:** None for a data path.
- **risks:** Google ToS and account bans, with multi-account load-balancing as outright abuse. The publisher's identity is tied to the relay. The quota makes it unusable for a whole-device VPN. It is one-signature fragile (intel:109). A MITM CA is unacceptable for user safety.
- **why:** Quota, ToS and the MITM model make it unfit as a whole-device data path; its one good use, carrying a tiny signed object, belongs in the courier candidate below.
- **evidence:** research/intel-and-some-working-methods.md:101-111 (MasterHttpRelayVPN mechanism, quota, failure modes); research/intel-and-some-working-methods.md:169,173 (most brittle to a single DPI upgrade; emergency fallback); research/intel-and-some-working-methods.md:29,47 (FQDN + prefix + port whitelisting, full DPI on CDN flows); void blog report-of-state (Google blocks Iranian IPs for some services)

### Whitelisted services as PACK / UPDATE couriers (Gmail/Outlook attachment, GitHub, Apps Script doGet, Drive) — RESEARCH SPIKE (S)

- **what:** Small signed objects (the .sbpx pack, the freshness document, an APK pointer or hash) carried by services the censor keeps whitelisted. These are delivery channels for signed objects, not tunnels.
- **iran:** Promising, but which hostnames is unknown. The Jan 26 2026 allowlist named Google, Bing, Meet, Gmail, Outlook, ChatGPT, GitHub, Play Store and App Store (arXiv 2603.28753, citing FilterWatch). GitHub stayed reachable on a whitelisted IP during the June 2025 shutdown (FOCI 2026). The censor's crisis mode keeps 'only email and basic search' (intel:53). A caveat from Amnezia: an SNI not on the whitelist fails, so github.io (Fastly) and raw.githubusercontent.com are not the same as github.com, and api.github.com allows only 60 unauthenticated requests an hour per IP, which a CGNAT exhausts.
- **independent:** Yes. It depends on the whitelist, not on relay reachability.
- **dial:** No engine change. Email already works today with zero code: the publisher shares the .sbpx through the Android share sheet into Gmail, and the recipient opens it through the existing file import ('Save a pack to the device', capability-matrix.md:154; specs/sbpx-import-v1.md). New mirror hosts reuse core/bootstrap's HTTPS fetcher.
- **serve:** Publisher-independent of the relay. It needs the publisher's account on that service (identity link). The ghpages backend already exists (publisher/deploy/freshness/backends/ghpages) but serves github.io, which may not be on the whitelist.
- **work:** Spike, 1–2 days: from the published allowlists, decide which exact FQDNs to target (github.com release assets redirect to objects.githubusercontent.com; Apps Script doGet behind the www.google.com front; Drive). Then a freshness provider per surviving host (mirrors.go:105-118 is an open set). Copy now: en/fa publisher and recipient hints for the email path, under farsi/STYLE.md. Depends on W3-7/W3-9 for the mirror half.
- **risks:** Third-party ToS (Apps Script is the weakest). The service sees the recipient fetch (Google/GitHub logs, not the censor). The whitelist changes without notice, so a mirror must never be the only path. Domestic messengers must be named explicitly as unsafe.
- **why:** The email path already works and only needs copy. Mirror hosts on the whitelist could close the 'last courier step' gap, but which hostnames actually pass must be established first.
- **evidence:** research/intel-and-some-working-methods.md:53 (crisis mode keeps only email and basic search); research/filtering-the-flow.md:113 (domestic apps with server-side state access); publisher/deploy/freshness/mirrors.go:105-118; publisher/deploy/freshness/doc.go:164-167; docs/capability-matrix.md:154 (save pack to device), 113 (LAN share CLI-only); docs/backlog-post-45.md:335-355 (W3-9 manual upload, last courier step); arXiv 2603.28753 (Jan 26 2026 allowlist); FOCI 2026 Niere et al. (GitHub on a whitelisted IP, June 2025); Amnezia Q1 2026 (non-whitelisted SNI fails)

### Ride the ChatGPT / Cloudflare-WARP shared anycast (July 2025 episode) — NEVER (n/a)

- **what:** In July 2025, opening ChatGPT also opened Cloudflare WARP, because both share anycast. The idea is to carry traffic on whatever anycast a whitelisted AI service shares.
- **iran:** Blocked for WARP. The censor says a dedicated WARP signature (handshake pattern, sequence numbers, entropy) was built within 72 hours with '100% blocking capability without disrupting ChatGPT' (intel:33). The void blog says ChatGPT's initial IP was later moved to other Cloudflare-linked ranges. Cloudflare fronting is mostly dead in Iran (filtering-the-flow.md:129,253), and a non-whitelisted SNI fails (Amnezia).
- **independent:** No. Any CDN-fronted variant is the fronting cluster's question, not a shutdown answer.
- **dial:** WARP is WireGuard-based: Daal's wireguard family is experimental and plain WireGuard is an immediate-block target (inventory:61). The CDN-fronted route already has a publisher surface (publisher/deploy/cloudflare).
- **serve:** WARP is a third party's network (Cloudflare), not something a publisher serves.
- **work:** None in this cluster. Hand the 'whitelisted-SNI on shared CDN anycast' question to the fronting/CDN analyst.
- **risks:** One-off windows that close within days. The censor explicitly prepares signatures before each reopening stage (intel:33,47).
- **why:** The censor closed it in 72 hours and now prepares signatures before each reopening stage; whatever remains of the idea is CDN fronting, not shutdown survival.
- **evidence:** research/intel-and-some-working-methods.md:33 (WARP signature built in 72 h, 100% block); research/intel-and-some-working-methods.md:47 (immediate blocking of QUIC/WireGuard/WARP on whitelisted CDNs); research/filtering-the-flow.md:129 (Cloudflare IP blocking history); docs/transport-family-inventory.md:61 (wireguard experimental; plain WG blocked on sight); void blog report-of-state (ChatGPT IP moved to other Cloudflare ranges)

### LAN hotspot handout: serve the APK and packs to nearby phones over Wi-Fi (finish lan-share) — BUILD LATER (M)

- **what:** One phone turns on its hotspot and serves a tiny local page: the APK for phones without Daal (any browser can download it), and the pinned .sbp share for phones with Daal. This finishes the half-built LAN share, which exists Go-side but has no UI, has a no-op mDNS advertiser, and has an empty browse list.
- **iran:** Works in every shutdown regime (no WAN). It reaches people with any phone and no Daal yet, which the APK share sheet cannot do across OEMs.
- **independent:** Fully. It does not use the network.
- **dial:** n/a. Code exists in core/share (lan_sender.go, lan_receiver.go, spki.go, token.go, fountain_session.go) with SPKI pinning and a PIN token (specs/lan-share-v1.md).
- **serve:** Publisher-independent.
- **work:** Add #[tauri::command] wrappers for engine_share_begin/end/pull (capability-matrix.md:113: 'no #[tauri::command] at all'; allowlisted in check-plumbing.mjs rule 4). Add an APK resource next to /bundle.sbp in core/share's HTTP surface; a plain-HTTP APK download must state that the integrity check is the signing fingerprint shown on both phones. Android: hotspot IP discovery and keep-awake. Leave mDNS browse out (it returns {services:[]}, capability-matrix.md:114). en/fa copy. Size: about 4–5 days.
- **risks:** A plain-HTTP APK can be swapped by anyone on the same Wi-Fi, so the signing-fingerprint check is mandatory copy. A visible hotspot name in public is a physical risk, so suggest a neutral SSID. Battery use.
- **why:** It is shutdown-proof and reuses code already written, but the share-sheet APK hand-off covers the common Android-to-Android case for a fraction of the work, so do that first.
- **evidence:** docs/capability-matrix.md:113-114 (LAN share CLI-only; mDNS browse hardcoded empty); specs/lan-share-v1.md:9-17 (implementation status; QR-URL fallback); core/share/lan_sender.go, core/share/spki.go; research/the-build.md:71,100 (LocalSend-style LAN share, fountain QR); research/intel-and-some-working-methods.md:25 (executables banned in domestic messengers)

### Share my working connection with nearby phones (hotspot proxy) — BUILD LATER (M)

- **what:** A recipient who has a working lifeline (a DNS tunnel, a white or business SIM's Daal route, or a lucky route) exposes a local SOCKS/HTTP proxy on the hotspot interface so friends' phones can use it. This is the 'one phone gets out, the room shares it' mesh.
- **iran:** Works whenever the sharer's route works. It multiplies a scarce working path, which matters in whitelist phases at about 1% of baseline (filtering-the-flow.md:121).
- **independent:** No. It inherits the sharer's route; its value is multiplying a working route, not finding a new one.
- **dial:** Yes. sing-box has a 'mixed' inbound (protocol/mixed) next to tun, and Daal's config builder would add one bound to the hotspot address with a PIN user. Android VpnService does not route tethered clients by itself, which is why a proxy is needed.
- **serve:** Publisher-independent. It does use the publisher's relay capacity and anything that counts bytes per recipient (per-recipient credentials).
- **work:** core/engine/config.go: an optional mixed inbound with an auth user, bound to the hotspot interface only (never 0.0.0.0). An ABI toggle and Android hotspot-IP discovery (NetworkWatch.kt). UI with en/fa copy and a byte cap, which depends on B4 budget enforcement (capability-matrix.md:216). Size: about 1 week.
- **risks:** All traffic carries the sharer's identity (SIM and address), and with it the legal exposure. It breaks the publisher's per-recipient accounting and possibly their trust model. Many devices behind one tunnel look different to the censor. It can drain a DNS lifeline in minutes.
- **why:** It is useful only once a lifeline route exists to share, and it shifts risk onto the sharer, so it should follow a decision on the DNS lifeline and on byte budgets.
- **evidence:** research/filtering-the-flow.md:121 (about 1% of baseline connectivity); research/deep-research-report.md:110 (mesh moves traffic locally to an uplink; needs a trusted exit); docs/capability-matrix.md:216 (byte caps never enforced, B4); sing-box v1.13.12 protocol/mixed (in module cache)


## Other obfuscation stacks and extensibility: mieru, Cloak, brook, gost, sing-box mux/padding, traffic shaping against flow/timing analysis, the dormant WASM transport_module, lifeline_relay, MASQUE, post-quantum handshakes

### mieru — NEVER (L)

- **what:** A proxy protocol (TCP or UDP) whose traffic is random from the first byte. It uses XChaCha20-Poly1305 with keys derived per minute from user and password, random padding tuned to the length and printable-character tests, and responses to failed decryption that vary unpredictably to frustrate probe classifiers.
- **iran:** UNKNOWN in the field. No 2025-2026 Iran report was found. It is structurally exposed: in heavy mode the filter keeps only flows that open like DNS, HTTP verbs or a TLS 0x16 record and silently drops the rest (intel:77). That is the same filter that killed obfs4 and plain shadowsocks (intel:81). The 'resilient' list from June 2025 names Shadowsocks-2022 only 'with plugins', meaning wrapped (filtering-the-flow.md:119).
- **independent:** Independent of the four TLS/QUIC families. NOT independent of our experimental shadowsocks route, which is the same class (fully random, no TLS) and dies under the same whitelist rule. It would be a second copy of a tier we already have.
- **dial:** NO in sing-box 1.13.12: the protocol directory has no mieru, and upstream sing-box has none. It exists only in forks (enfein/mbox, guterben/sing-box) and in mihomo. Library: github.com/enfein/mieru/v3 apis/client, GPL-3.0 (compatible with Daal's GPLv3). It could be wired as a custom outbound with outbound.Register (sing-box adapter/outbound/registry.go:15) and a registry built in core/engine/engine_singbox.go:254 in place of include.Context. Android binary cost is an estimated 1-2 MB; not measured.
- **serve:** Yes in principle. The relay runs the mita server daemon, or a forked sing-box inbound we refuse to carry. It needs any TCP/UDP port (443/tcp to fit the whitelist, which collides with REALITY on 443 unless a second IP is added), no certificate, no domain, and clock sync within ±1 minute. That means a new daemon in cloud-init, a new pinned artifact, and a fresh provision (inventory:119-138).
- **work:** core/engine: custom outbound registration; bundle/go/bundle/types.go: new enum value (wire-breaking at pack level); cmd/daal-relay-mgmt plus publisher/deploy/cloudinit templates: a mita unit; relaypack client_outbound.go; routestore/family.go and derive_tree.ts maturity entries; worldbox rig scenario.
- **risks:** A new out-of-tree crypto dependency maintained by one author. Its probe responses differ from any ordinary service, the same kind of tell as our shadowsocks/anytls resets (inventory:91-92). It costs operators a second IP if run on 443. Its UDP mode is dead under the censor document's UDP block (intel:53).
- **why:** It duplicates the fully-random tier that Iran's whitelist already kills, at the cost of a new daemon and a new dependency.
- **evidence:** research/filtering-the-flow.md:201 (mieru design); research/intel-and-some-working-methods.md:77 (first-two-packets DPI + protocol whitelist); research/intel-and-some-working-methods.md:81 (entropy-fingerprinted protocols dead); research/filtering-the-flow.md:119 (June 2025 resilient set); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/protocol/ (no mieru); ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/adapter/outbound/registry.go:15; https://github.com/enfein/mieru (README: mihomo and the mbox fork are the only sing-box-family hosts)

### Cloak — NEVER (L)

- **what:** A plugin for Shadowsocks, OpenVPN or Tor that disguises traffic as browser TLS. A sealed token sits in the ClientHello SessionID, unauthenticated connections are reverse-proxied to a real cover site (RedirAddr), and it multiplexes several sessions (NumConn, default 4).
- **iran:** No current Iran data. Its mechanism is a weaker REALITY: the research describes it as TLS 1.2 mimicry (filtering-the-flow.md:201), while REALITY is a real TLS 1.3 handshake with a borrowed certificate chain (filtering-the-flow.md:153-157). Probes hitting it would see the cover site, as with REALITY.
- **independent:** NO. It is TLS on 443/tcp to a Hetzner IP, so it shares SNI filtering, IP and volume heuristics (intel:81) and TLS-in-TLS with vless-reality.
- **dial:** NO. Not in sing-box 1.13.12. The library is github.com/cbeuw/Cloak (GPL-3.0); it would need a custom outbound. Not in the module cache.
- **serve:** Yes: ck-server on 443/tcp with a RedirAddr. That collides with REALITY's 443 on the same IP, so it needs a second IP or an SNI-demultiplexing front. No certificate is needed. CDN mode needs a CDN account.
- **work:** Custom outbound in core/engine; a new daemon and pinned artifact on the relay; enum value; family maturity entries.
- **risks:** Upstream maintenance has slowed. The TLS 1.2-era mimicry is likely a fingerprint gap against Chrome 133, whose ClientHello carries an ML-KEM key share. Extra IP cost for operators.
- **why:** It is strictly dominated by vless-reality, which we already serve on the same port with a stronger handshake.
- **evidence:** research/filtering-the-flow.md:201; research/protocol-level-anatomy.md:73; research/filtering-the-flow.md:153-157 (REALITY mechanism); research/intel-and-some-working-methods.md:81

### brook — NEVER (n/a)

- **what:** txthinking's proxy application, GPL-3.0. Its native mode is ChaCha20-Poly1305 with per-connection nonces (a random stream). It also has ws, wss and QUIC modes, multiplexed with smux.
- **iran:** No Iran-specific data. The native random stream falls under the whitelist (intel:77), wss is plain WebSocket over TLS, and QUIC falls under the HTTP/3 and UDP collapse (filtering-the-flow.md:101; intel:53).
- **independent:** NO. Its modes map onto shadowsocks (random), websocket-tls (wss) and hysteria2/tuic (QUIC).
- **dial:** NO. Not in sing-box 1.13.12. It is an application rather than a clean library, so it would need a custom outbound.
- **serve:** Possible with the brook server binary, but there is no reason to.
- **work:** None recommended.
- **risks:** A single-maintainer application, and no new property.
- **why:** Each of its modes is a worse copy of a family we already have.
- **evidence:** research/filtering-the-flow.md:201; research/filtering-the-flow.md:241 (brook uses smux); research/intel-and-some-working-methods.md:77

### gost — NEVER (n/a)

- **what:** go-gost, MIT licence: a 'Swiss-army' proxy-chaining framework (SOCKS5, SS, Trojan, KCP, QUIC, obfs4, h2, gRPC, WebSocket, SSH, ICMP tunnel) built from chainable listeners, handlers and dialers. It is a toolbox, not a protocol.
- **iran:** Depends on whichever transport is chained. The options it adds beyond sing-box are KCP, which runs over UDP (dead under the UDP block, intel:53), and an ICMP tunnel (dead, because the censor document orders ICMP blocked in a crisis, intel:53).
- **independent:** NO. Anything Iran-relevant it offers is already in sing-box 1.13.12 (ws, h2/http, gRPC, httpupgrade, quic, ss, ssh) or dies with UDP/ICMP.
- **dial:** NO, and not needed.
- **serve:** n/a
- **work:** None. At most a lab tool for the worldbox rig.
- **risks:** n/a
- **why:** A chaining framework adds no new appearance on the wire that sing-box lacks.
- **evidence:** research/filtering-the-flow.md:201; research/intel-and-some-working-methods.md:53 (block UDP/ICMP/IPv6 in crisis)

### sing-box multiplex + padding (h2mux) on the TLS families — BUILD NOW (S)

- **what:** Packs many app flows onto one TLS connection (sing-mux h2mux, padded framing, 64 streams), so the nested-TLS classifier from Xue et al. (USENIX Security 2024) gets far fewer samples. The research reports a detection drop of more than 70%.
- **iran:** Already SHIPPED for vless-reality and websocket-tls, gated on the relay reporting mux_inbound. No Iran field result yet. Note that the identified Iranian threats are the whitelist, SNI, JA3/JA4 and volume heuristics (filtering-the-flow.md:125; intel:81). Multiplexing reduces connection count; it does not reduce per-IP volume.
- **independent:** It is a hardening layer on existing families, not a family.
- **dial:** YES: sing-box 1.13.12 VLESS options carry Multiplex (protocol/vless/outbound.go:93), and sing-mux v0.3.4 is in the module graph.
- **serve:** YES: cmd/daal-relay-mgmt/singbox_users.go:231 ensureMultiplexInbounds stamps the inbound block. Packs emit the client block only when the relay reports mux_inbound (publisher/deploy/cloudinit/artifacts.go:53-57).
- **work:** Verification only: 1. Run a worldbox rig capture comparing the record-size and direction bursts of vless-reality with Vision alone against Vision plus h2mux. Today both are emitted together (client_outbound.go:158 plus addMultiplex in multiplex.go:189-200). Xray forbids this pairing. In sing-box the inner stream becomes h2mux, so Vision's inner-TLS padding and splice probably never fire. 2. Write the decision (keep mux, or drop it on reality and keep it on websocket-tls) into multiplex.go and specs. 3. Confirm the fleet's relays actually report mux_inbound.
- **risks:** The silent loss of Vision's benefit is unmeasured. Head-of-line blocking under Iranian packet loss (around 40% during the 2024 disruption, filtering-the-flow.md:105).
- **why:** The code is done. One cheap measurement settles whether Vision plus mux on REALITY helps or hurts, and it is the only documented defence against the TLS-in-TLS classifier.
- **evidence:** publisher/deploy/relaypack/multiplex.go:1-40,112-160,189-200; publisher/deploy/profiles/iran-default.json:6-7; publisher/deploy/relaypack/client_outbound.go:158; cmd/daal-relay-mgmt/singbox_users.go:86-124,231; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/protocol/vless/outbound.go:55-63,93; research/filtering-the-flow.md:160,241; research/protocol-level-anatomy.md:119

### Flow/timing shaping beyond mux (inter-arrival timing, packet-size morphing, cover traffic); first-flight ClientHello fragmentation as the adjacent in-tree lever — BUILD LATER (S)

- **what:** Hiding a flow's timing and size profile: obfs4-style inter-arrival modes, packet-size morphing, chaff. The first-flight alternative splits the TLS ClientHello across TCP segments or TLS records, so a DPI that reads only the opening packets never sees the SNI.
- **iran:** No evidence that Iran runs timing classifiers. Its DPI is stateless, reads the first two data packets and does not reassemble (intel:77). It leans on SNI, JA3/JA4 and statistical traffic analysis (filtering-the-flow.md:125), with volume heuristics on REALITY (intel:81). Timing obfuscation has been abandoned elsewhere because it costs throughput and censors key on content entropy (filtering-the-flow.md:209). ClientHello fragmentation, by contrast, targets the no-reassembly property directly, and Iranian serverless setups use chained fragmentation (intel:93).
- **independent:** A hardening layer, not a family. Fragmentation matters most where our SNI is our own relay domain (websocket-tls). REALITY's SNI is already an allowed name.
- **dial:** Timing morphing: NO in sing-box 1.13.12, which has no timing-obfuscation option. The anytls padding scheme exists and is already randomised per relay (cmd/daal-relay-mgmt/singbox_anytls.go:146). Fragmentation: YES. option/tls.go:114-116 (fragment, fragment_fallback_delay, record_fragment) is honoured by common/tls/std_client.go:201 and utls_client.go:258. The REALITY client (common/tls/reality_client.go:49,80) wraps the uTLS config, but whether its handshake goes through the fragmenting connection is unverified.
- **serve:** Client-side only. Nothing changes on the relay.
- **work:** Timing morphing: none. Fragmentation: 1. Fill in the PENDING tls_fragment modifier (publisher/deploy/modifiers/registry_gen.go:23-30; specs/modifiers/*.md) with the reference option/tls.go:114. 2. Emit `fragment` on the websocket-tls tls block in publisher/deploy/relaypack/client_outbound.go behind the modifier. 3. Use worldbox censor_probe.go to check that a sensor reading two segments without reassembly misses the SNI. 4. Verify the REALITY path. Coordinate with the DPI-evasion cluster, which probably owns this.
- **risks:** Tiny first segments can themselves become a tell, or get dropped by middleboxes. The fallback delay adds latency. Timing morphing would cut throughput on already-throttled links for no evidenced gain.
- **why:** Timing morphing has no Iranian threat to answer. Fragmentation is real and already in the engine, but it belongs to the DPI-evasion lane; hand it there rather than building it twice.
- **evidence:** research/intel-and-some-working-methods.md:77,81,93; research/filtering-the-flow.md:125,209; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/option/tls.go:114-116; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/common/tls/utls_client.go:258; publisher/deploy/modifiers/registry_gen.go:23-30; cmd/daal-relay-mgmt/singbox_anytls.go:146; test-rigs/worldbox/driver/censor_probe.go:195

### WASM transport_module (core/wasm, wazero v1.11.0) — RESEARCH SPIKE (L)

- **what:** A sandboxed wazero runtime meant to load signed WASM transport modules from a pack, so new obfuscations could ship without an app update, as Lantern does with WATER (filtering-the-flow.md:229).
- **iran:** n/a as a family; its value is agility. When a family burns, a new byte transform could reach every recipient through a pack rather than a new APK, and sideloading an APK through a censored network is the expensive path. Any module is still bound by the whitelist: it must open like TLS or HTTP on 443/tcp (intel:77).
- **independent:** Only as independent as the transform a module implements. Under the locked host ABI a module gets raw TCP to port 443 only (core/wasm/wasm.go:92-99, 342-372). To pass Iran it must either produce a Chrome-identical TLS handshake itself, which is impractical inside a 4 MiB module, or ride inside a host-provided uTLS/REALITY layer. In the second case it shares that family's SNI and IP fate and can change only the inner shape.
- **dial:** NO production path: - `core/wasm.Dial` (dial.go:25-93) makes one call bounded by a 5 s timeout and 1e9 fuel. `_start` runs at instantiate (wasm.go:257). Nothing pumps bytes for the life of a session, and nothing turns a module into a sing-box outbound. - The ABI the spec calls 'WATER v1' (specs/wasm-transport-v1.md:34-38; host functions water_transport_dial/read/write/close; module export water_transport_dial_target) is NOT upstream WATER v1, which uses watm_*_v1 exports with WASI file descriptors and a watm_start_v1 worker. So upstream modules and SDKs cannot be used. - Enabler: sing-box 1.13.12 lets the app register its own outbound type (adapter/outbound/registry.go:15). The engine currently uses include.Context (core/engine/engine_singbox.go:254), which can be replaced by box.Context with a custom outbound registry (include/registry.go:43). No fork is needed. - wazero (Apache-2.0) is already linked, so the binary cost is already paid.
- **serve:** Needs the relay too. Every new transform needs its server half, so daal-relay-mgmt must gain a wazero host and an inbound that loads server modules pushed over the management API. That is one pinned-artifact release plus a fresh provision (inventory:119-138). After that, both halves could ship without app updates: the client module in the pack, the server module pushed by the publisher's phone.
- **work:** Spike (2-4 days): (1) Prototype a custom outbound 'daal-wasm' that runs a module as a stream transform over a `detour` to an existing uTLS outbound. (2) Choose the ABI: adopt upstream WATER v1, so the Go and Rust watm SDKs work, versus fixing the homegrown one. (3) Measure throughput and memory on the spare Sony phone. iOS Network Extension memory is a concern at 16 MiB per instance. (4) Decide whether a module buys anything that pack-level config (SNI, ports, fragmentation, anytls padding scheme) cannot already change. The full build (L) would touch core/wasm (streaming ABI, drop the single-dial model), core/engine (registry), core/routestore/family.go plus derive_tree.ts, bundle/go/publisher/wasm.go, cmd/daal-relay-mgmt (server host and inbound), cloudinit, and worldbox scenarios.
- **risks:** Module authorship and trust: publishers cannot vet modules, so the project would sign them, which makes the project a de facto module channel. Supply-chain blast radius if the signing key or a module is compromised. App Store guideline 2.5.2 on downloaded code; Play allows interpreted code with no direct API access, and Daal ships sideloaded APKs. Per-byte overhead on mid-range phones. The relay-side update cannot be avoided.
- **why:** It is the only item in the cluster that could shorten the time from a burned family to a fix for every recipient. But today's code has no data path and a non-standard ABI, so prove the value before any build.
- **evidence:** core/wasm/dial.go:25-93; core/wasm/wasm.go:1-60,92-99,215-275,299-417; specs/wasm-transport-v1.md:34-38; docs/transport-family-inventory.md:68; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/adapter/outbound/registry.go:15; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/include/registry.go:42-43; core/engine/engine_singbox.go:254-273; research/filtering-the-flow.md:229 (Lantern WATER); https://water.refraction.network/transport-module/spec/v1.html (watm_dial_v1 / watm_start_v1 exports)

### lifeline_relay — NEVER (n/a)

- **what:** A partner-operated server that fetches allowlisted public web pages for the client and returns them as compressed reader-mode or raw HTML. It is a content-fetch service, not a tunnel, and the project never operates one.
- **iran:** Unknown, and it hinges on reachability. The client still needs a transport to reach the partner, so it adds no new way through the filter. In a nationwide shutdown where only domestic traffic works, a fetch service abroad is just as unreachable.
- **independent:** NO. It rides whatever transport reaches the partner.
- **dial:** NO: core/lifelinerelay does not exist (inventory:69). The ABI symbols engine_lifeline_relay_fetch and engine_lifeline_relay_status were never added.
- **serve:** Structurally not by a self-hoster; it is partner-operated by design. Blocked on all five preconditions: signed agreement with a partner, partner liability, external audit, threat model, kill-switch soak test (26-phase-3g-lifeline-relay.handover.md:12-30).
- **work:** None. Keep the enum value reserved (removing it is a wire break). If a shutdown-time option is wanted, it is a different design (a bridge hosted inside the national network) for another cluster.
- **risks:** The operator sees all traffic, legal liability lands on the partner, and the audit burden is large.
- **why:** It is not a transport, it needs a partner that does not exist, and it does not help in the shutdown case.
- **evidence:** development-phases/26-phase-3g-lifeline-relay.md:20-90; development-phases/26-phase-3g-lifeline-relay.handover.md:12-30; docs/transport-family-inventory.md:69; bundle/go/bundle/types.go:194

### MASQUE (CONNECT-UDP/CONNECT-IP over HTTP/3 or HTTP/2) — NEVER (n/a)

- **what:** An IETF method for proxying UDP or IP packets over HTTP (RFC 9298, RFC 9484), usually over HTTP/3. Its censorship value comes from big providers (Cloudflare WARP, iCloud Private Relay) whose huge user base hides each user.
- **iran:** HTTP/3 over UDP 443 is blocked or throttled: Cloudflare Radar shows the HTTP/3 share on AS58224 falling from about 40% to under 5% by 2026-01-03 (filtering-the-flow.md:101; intel:83). The censor document orders UDP blocked in a crisis (intel:53). The one large MASQUE crowd, WARP, got a dedicated censor signature with '100% blocking capability' in July 2025 (intel:33), and WARP is partly blocked since February 2024 (filtering-the-flow.md:231).
- **independent:** NO. The HTTP/3 variant shares fate with hysteria2 (QUIC on 443/udp). The HTTP/2 variant is HTTP/2 extended CONNECT over TLS on 443/tcp, the same surface as naive, but without naive's exact Chrome fingerprint.
- **dial:** NO in sing-box 1.13.12 or stable 1.14.4. REFUTES the inventory's 'never was' as a forward claim: sing-box 1.15.0-alpha.7 adds masque-client and masque-server ENDPOINTS (CONNECT-IP, versions 1/2/3 with version fallback). Note they are endpoints, which config.go can already hold (core/engine/config.go:40). The dormant core/transports/masque package stays unusable.
- **serve:** REFUTES 'structurally no': a self-hosted relay could run the 1.15 masque-server endpoint, which needs a TLS certificate (a domain or self-signed with pinning), 443/udp for HTTP/3 or 443/tcp for HTTP/2, and an address prefix for the tunnel. What IS structural is that a one-tenant VPS gets none of the provider crowd that gives MASQUE its value (core/transports/masque/masque.go:16-24). So 'structurally redundant', not 'structurally impossible'.
- **work:** None now. Text-only fix: change the reason on the enum value in bundle/go/bundle/types.go, the inventory rows (docs/transport-family-inventory.md:65,157-165) and the core/transports/masque header to say 'servable from sing-box 1.15 on; redundant with hysteria2 (HTTP/3) and naive (HTTP/2)'. Keep CM-6 inert.
- **risks:** An alpha-quality upstream, and a fingerprint gap on the HTTP/2 path compared with naive.
- **why:** It can be built after the 1.15 pin, but every variant shares fate with a family we already serve better, and its anonymity-set advantage does not exist for self-hosters or under Iran's WARP signature.
- **evidence:** docs/transport-family-inventory.md:65,157-165; core/transports/masque/masque.go:1-40; research/filtering-the-flow.md:101,231; research/intel-and-some-working-methods.md:33,53,83; https://sing-box.sagernet.org/changelog/ (1.15.0-alpha.7 adds MASQUE client/server; latest stable 1.14.4); https://sing-box.sagernet.org/configuration/endpoint/masque-server/; https://sing-box.sagernet.org/configuration/endpoint/masque-client/

### Post-quantum handshakes (X25519MLKEM768 hybrid, ML-DSA REALITY cert, VLESS encryption) — NEVER (S)

- **what:** A hybrid key exchange (X25519 plus ML-KEM-768) that protects against recording traffic now and breaking it with a quantum computer later. Not sending it is itself a fingerprint, because Chrome sends it by default (filtering-the-flow.md:243).
- **iran:** Neutral for blocking, and required for blending in: a Chrome-like ClientHello without the ML-KEM share stands out. ML-KEM ClientHellos also exceed one segment (worldbox censor_probe.go:195 already models this).
- **independent:** n/a; it is a property of the TLS stack, not a family.
- **dial:** ALREADY SHIPPED, by inheritance: - uTLS 'chrome' maps to HelloChrome_Auto = HelloChrome_133 (metacubex/utls@v1.8.4 u_common.go:615), whose spec lists X25519MLKEM768 first in groups and key shares (u_parrots.go:884-940). Daal renders fingerprint 'chrome' (relaypack/client_outbound.go:162,545). - Naive uses Chrome's BoringSSL. - hysteria2/tuic use Go 1.25 crypto/tls through quic-go, which defaults to the hybrid share. - sing-box exposes curve_preferences including X25519MLKEM768 (option/tls.go:141-148). Not available in sing-box: Xray's ML-DSA-65 REALITY certificate signature and VLESS-encryption ML-KEM wrapper (filtering-the-flow.md:147).
- **serve:** ALREADY: the REALITY server path in metacubex/utls performs the ML-KEM encapsulation (reality.go:221-233,372-373). The websocket-tls and naive servers on Go 1.25 negotiate it by default.
- **work:** (1) Add a guard test in publisher/deploy/relaypack that no rendered TLS block sets curve_preferences without X25519MLKEM768 and the fingerprint stays 'chrome'. (2) Optional: when choosing REALITY cover sites, weigh certificate-chain size, since the research says a borrowed chain must exceed about 3,500 bytes to match Chrome's post-ML-KEM size distribution (filtering-the-flow.md:163).
- **risks:** A future profile edit that pins curve_preferences, or an older fingerprint (for example chrome_120), would quietly remove the share and create a fingerprint.
- **why:** No new PQ protocol work is needed because the shipped stack already negotiates the hybrid. What remains is a small guard test, not a feature.
- **evidence:** ~/go/pkg/mod/github.com/metacubex/utls@v1.8.4/u_common.go:615; ~/go/pkg/mod/github.com/metacubex/utls@v1.8.4/u_parrots.go:884-940; ~/go/pkg/mod/github.com/metacubex/utls@v1.8.4/reality.go:221-233; ~/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12/option/tls.go:20,106,141-148; publisher/deploy/relaypack/client_outbound.go:162,545; research/filtering-the-flow.md:147,163,243; test-rigs/worldbox/driver/censor_probe.go:195

