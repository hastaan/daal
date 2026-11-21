# Adaptive cover names for Daal — final design

*Final adviser design. Folds in the engineer's verification; every correction below is one that reading the repo or the vendored sing-box 1.13.12 / utls 1.8.4 proved against the first draft. Nothing was built or run.*

## For the owner, in one paragraph

Your idea is right, and it's a better fit for Daal than the tools that inspired it. Instead of shipping one hard-coded fake name (the way FakeSNI ships `auth.vercel.com` and the SNI-spoofing family ships fixed lists), the client carries a short list of *candidate* cover names, learns on each network which one actually moves data past the censor right now, sticks with the winner, and quietly rotates to the next when the winner stops working. Because every relay is ours and the client proves the relay by its REALITY key or a pinned certificate — never by the name — the "fake name" can just be the real name in the real handshake. No forged packet, no raw socket, no root. The honest limit: the name only helps *after* the destination IP is already allowed through. On a blacklist day, and for a REALITY relay's cover name, this wins. On a full IP-allowlist day against a plain Hetzner address, the name buys little or nothing — the evidence says the gate there is the IP, not the name. The one place the name clearly beats an allowlist is a shared CDN address, and Daal has no CDN-fronted tier today. So this is a strong blacklist-day and cover-name lever, built now, with the CDN payoff left as a later, separate piece.

## 1. The mechanism

### 1.1 Where the name is used — corrected order

The first draft led with the pinned-cert TLS families (websocket-tls, anytls). Verification killed that ordering: those listen on 8445 and 8447, which are **not** whitelisted egress (`publisher/deploy/relayports/relayports.go:107-125`; the file itself says 8447 is "worth ZERO inside Iran", and `docs/exotic-transports-plan.md:44,84` says the same for ws). Under the 53/80/443 port whitelist a perfect name on those ports buys nothing. The only TCP-on-443 family is vless-reality (`relayports.go:33`). So the corrected order is:

| Rank | Use | Who sees the name | Server must answer for it? | Non-root Android? | Verdict |
|---|---|---|---|---|---|
| **1** | **REALITY `serverName` (use B)** — on 443 | censor, relay, borrowed cover site | yes — relay's `handshake.server` must give a believable answer | client yes; relay change needed | **First real lever in a whitelist phase.** Publisher-driven; per-client freedom is small. |
| **2** | **Real SNI on a pinned-cert family (use A)** — ws-tls/anytls | censor; our relay ignores it | no — client pins SPKI | pack-only once W2-R lands | **Hygiene / blacklist-day only.** Ports aren't whitelisted egress, so no help under a port+IP allowlist. |
| **3** | **CDN front SNI (use C)** — SNI ≠ Host on a CDN edge | censor + CDN | CDN must hold a cert for it and route by Host | yes | **Highest value under an allowlist — but no Daal tier exists for it yet.** Depends on the CDN tolerating SNI≠Host (already refused by Azure/Google/AWS). |
| **4** | **Fake ClientHello / desync (use D)** | censor only | no | no on the phone | **Experiment, desktop-Linux only** (see 1.3). |
| — | Split hello "first-segment name" (use E) | — | — | — | **Not a cover-name mechanism.** Splitting hides the real name; it can't present a different one, and Iran now reassembles small fragments. Dropped. |

### 1.2 Why the premise needs qualifying

The draft's premise was "under an allowlist the DPI must see a name it likes." The field evidence narrows that hard:

- The LunarCanvas study (~26 May 2026) found random non-existent SNIs **passing** on allowlisted IPs, ~half of allowlisted IPs doing no SNI filtering at all, and the outer gate being **source + destination IP**.
- The "grey, cut after ~6 packets unless whitelisted" behaviour (net4people #626) is reported **only for allowed Cloudflare IPs**. Amnezia's Q1-2026 forecast explicitly *assumes* a domain whitelist "within CDN subnetworks."

So: **on a VPS address the IP decides and the name only has to stay off the blocklist; the "must be a liked name" rule is a CDN-prefix phenomenon.** This strengthens, rather than weakens, the design's own "hard limit." The decisive open question is unchanged (claim 14 below), but expect the answer to be "prefix-keyed / IP-gated."

### 1.3 The real-hello mechanism (uses A/B) — what actually gets built

There is **no** per-connection SNI hook in sing-box 1.13.12, and you can't rewrite the SNI inside an already-written hello — that would break the TLS 1.3 transcript and REALITY's AAD. The draft's proposed remedy (a sibling outbound per name) is **unnecessary**: the engine already starts a whole instance per route and spins side instances for racing (`core/abi/connect_race.go:47-60`). A name variant is therefore just a **JSON-patched copy of the route's outbound** (`tls.server_name` swapped) offered as another `autoCandidate` (`core/abi/connect_auto.go:829-943`). Cost is one instance start plus a reachability proof — measure the full start on the phone (the 0.3 s figure in the comments is the hand-over proof, not a cold start).

The desync path (use D) would need a Daal-owned dialer below TLS (a custom outbound type plus `detour`). sing-box **1.14.0** does add outbound TLS `spoof`/`spoof_method`, but the docs require elevated privileges (`CAP_NET_RAW` + `CAP_NET_ADMIN` on Linux) — **unusable on non-root Android even after a pin bump**, and detoured routes lose racing. #626 also saw both spoof variants die after ~4 days once Cloudflare ranges sat behind a stateful NAT. Verdict: **desktop-Linux experiment only; the "Never on the phone" rule stands.**

### 1.4 Discovery: the route attempt *is* the probe

No standalone scanner — scanning is what makes you visible. Candidates are tried as ordinary connect attempts, a few at a time, learned from. Sources, in trust order:

1. **Signed seed list** in the pack / refresh channel: name, class (foreign-whitelisted / CDN-co-hosted / mirror), which CDN or prefix it lives on, audited date.
2. **Names the relay can answer for** (use B): the cover site's SANs and default-vhost behaviour, published per relay.
3. **Names co-hosted on the target's CDN** (uses C/D).
4. **The user's own resolved traffic: never persisted or reused.** At most an in-memory count of seed-list names seen working in passthrough.
5. **No domestic names, ever** — a domestic name at the international gateway is anomalous by itself, decoy or not. (Fix the contradictory decoy example at `specs/modifiers/client_desync.md:12-13`, which currently names "a major Iranian domain.")

### 1.5 Probe signal

The attribution machinery the draft hoped for **already exists**: `AutoRefinedNameBlocked` / `AutoRefinedAddressBlocked` (`core/abi/connect_auto_verdict.go:93-94,184-201`), with `stoppedAtHello` and `pastHandshake`. A hello-stop is refined to "name" when a different-named route to the same host:port gets past the handshake. It never fires for Daal today only because each family has its own port — **name variants of one route are exactly what makes it fire.**

What is missing and must be added:
- **Timing fields** — `connect_ms` and `hello_to_fail_ms` in the proof path (`core/engine/proof_singbox.go`), so an injected RST (arriving faster than the SYN/SYN-ACK RTT) can be told from a server RST. The RST's TTL is not readable from an unprivileged socket, so timing is the only on-device signal; treat it as a heuristic (CGNAT/border hops can blur it).
- **A "grey cap" category** — handshake completes, then reset/stall with very few bytes. Caveat from #626: it doesn't say which packets the 6 counts, and a TLS 1.3 + first proxied request may not fit in 6 packets each way, so "grey" may surface as a *handshake* timeout rather than a post-handshake stall. Needs byte counts in the proof path and a new entry in the closed taxonomy (`specs/failure-taxonomy-v1.md`).

Error classification itself is already fine: `core/diagnostics/observe.go:103-125` reads the error chain (`errors.Is` on ECONNRESET/EPIPE/EOF/deadline) before any string match; `classify.go:130` is only the legacy string table. Add one engine test that a sing-box-wrapped uTLS reset still satisfies `errors.Is(ECONNRESET)`.

Budget: at most **2 extra names per route per attempt**, sequential (the race already forbids two probes to the same address:port, `connect_race.go:28-44`), no parallel fan-out, no background scans. Count trials through the existing in-memory `sideProbesPerHour = 12` (`connect_race.go:76-78`) plus a per-(network, relay) **lifetime cap of ~3 names**.

### 1.6 Memory and rotation

Keep it inside the existing `RouteMemory` rather than a new map — this is cheaper than the draft proposed and keeps plaintext names out of the blob. Key each variant as `routeID + "#" + index-into-signed-list`, reusing ranking, fail-streaks, grading (`core/netmem/measure.go`) and the 30-day sweep (`store.go:28`). `ForgetRoute` (`store.go:266`) must also drop the variants. netmem keys cell networks by carrier (`core/netmem/hash.go:26-45`), which is the right grain — MCI, Irancell, TCI differ.

- **Ranking:** carried-last beats failed-last; a name-shaped fail streak of 2 demotes a name; one success resets it.
- **Decay (new logic):** halve confidence after 24 h with no fresh success; expire a "blocked" mark after 72 h so a re-opened name gets retried. Today `FailedSince(cutoff)` is the only ageing, so this is a small addition.
- **Quick switch:** on a name-shaped failure of a live route, re-dial once with the next-ranked variant before declaring the route dead — as a fresh `autoCandidate`, not a reload.
- **Attribution:** a name failure must never cool the relay or the family. "Name died" = another name works on the same relay; "relay died" = none does.

### 1.7 Sharing

- **Down:** the per-route candidate list rides inside the signed pack as a **new sibling key in the route's `family_specific_config` / `_relaypack` container — not inside `Endpoint`** (the endpoint decoder is strict, `bundle/go/bundle/endpoint.go:167` `DisallowUnknownFields`). Covered by the pack signature, ignored by old builds.
- **Up:** nothing automatic. Only the manual, user-reviewed field-probe report, after a schema revision — and it must carry **no carrier numeric ID and no per-device order** (both would correlate two reports, which `test-rigs/field-probe/docs/privacy-rules.md` forbids). Label by network *kind* or a user-chosen bucket.
- **Passive relay learning:** a relay can count successful handshakes per SNI, aggregated per relay (never per recipient key), opt-in. Weak value while there's one name per relay.

## 2. What is verified buildable, and the cost

| Item | Verdict | Where / size |
|---|---|---|
| REALITY takes exactly one server name; a second SNI is forwarded to the cover host, not authenticated | **Verified (code)** `reality_server.go:90`; utls `reality.go:360` | behavioural check in worldbox. S |
| Pinned-SPKI families ignore the SNI; client never checks the name; std server serves its cert whatever the SNI | **Verified client-side; relay side expected** `utls_client.go:170-177`, `std_client.go:114-121`, `client_outbound.go:514-552` | pack-only change (plan W2-R). **Do the cert-CN fix first** — every relay serves `CN=daal-relay` (`cloudinit/v2.yaml.tmpl:370`, `cmd/daal-relay-mgmt/tlscert.go:117-119`), which an active prober reads regardless of SNI. S; M with the on-wire check; fresh provision for the cloud-init half |
| Name variant = JSON-patched outbound copy as an `autoCandidate`; no sibling outbounds, no reload | **Verified** `connect_auto.go:829-943`, `connect_race.go:47-60` | one instance start + proof; measure cold start on phone. S–M |
| Name-vs-relay attribution exists | **Verified** `connect_auto_verdict.go:184-201` | reuse; extend `pastHandshake` to accept "carried past the cap" once the grey category exists. S |
| Timing + grey-cap category + byte counts | **Partly / gap** `observe.go` has no timing fields | add to proof path; new taxonomy entry. M; blocked on a real field capture of the cap |
| Variant memory in `RouteMemory`; 24 h/72 h decay | **Verified feasible** `hash.go`, `snapshot.go:71-73`, precedent `network-memory-v1.md:270-337` | variant keying + `ForgetRoute` fix + short spec section + new decay logic. S–M |
| Trial budget via `sideProbesPerHour` + per-relay name cap | **Verified** `connect_race.go:76-78,132` | count through `sideNoteLocked`; no new ABI symbol. S |
| Candidate list in the signed pack | **Partly** additive precedent `relaypack-v1.md:284-290`; strict endpoint decoder | new sibling key outside `Endpoint`; `bundle/go/bundle` types + `derive_tree.ts`; publisher-side `libdaal_deploy.so` rebuild. S–M |
| 1.14 TLS `spoof` on the phone | **False** — needs `CAP_NET_RAW`+`CAP_NET_ADMIN` | desktop-Linux only; pin bump is L (release coupling). Not for the phone |
| Multi-name REALITY relay | **Nothing exists; costly** one `server_name` → one-entry map; two 443 listeners refused (BUG-14); project doesn't fork sing-box (`exotic-transports-plan.md:727`) | either fork/patch (against policy) or an SNI-peeking demux on 443 in front of several loopback REALITY inbounds — cloud-init + mgmt + relayports, fresh provision, and it breaks the one-name-per-relay invariant in `provider/cover_sni.go`. **L — defer** |

## 3. How it is tested

Build the rigs in **worldbox** (NFQUEUE DPI), not censor-lab (its live netns runner is staged, `lab-driver/cmd/lab-driver/main.go:113-115`). worldbox's `DPIRule` (`driver/censor_dpi.go:33-58`) today does `when: tls_sni` + exact name list + `drop`/`rst` + `reassemble` + a single exact `dst`. Add four things: `sni_not` (default-deny allowlist), `dst_prefix` (CIDR), `action: "cap"` with `max_pkts`, and a scenario-level `timeline: [{at_s, rules}]` the engine swaps atomically. Then:

- **Allowlist flips at t=60 s:** live route dies → next variant tried within the same pass → dead name gets `name_blocked` → `RouteMemory` shows `route#old` failed, `route#new` carried → base route and family **not** cooled down.
- **SNI+prefix allowlist:** expected verdict `address_blocked` for every variant, attempt count bounded by the per-relay cap and `sideProbesPerHour` — i.e. the feature correctly gains nothing and the client stops rather than cycling the list.
- One engine unit test for the wrapped-reset `errors.Is` path; one for the grey-cap detector once byte counts land.

## 4. Risks and mitigations

- **Probing as a signal** — several names to one IP in a minute is a scanner. → ≤2 extra names/attempt, sticky winners, no fan-out, no background scans.
- **Many SNIs for one IP over time** → cap the lifetime set per (network, relay) at ~3; prefer names that are SAN-siblings on one cert.
- **Standalone fetches touch third-party sites** → off by default; foreign names only; never domestic.
- **DNS exposure** — resolving candidates writes them to the ISP resolver's log. → don't resolve at all for uses A/B/D (the name is only a string in the hello); resolve only for the optional standalone fetches.
- **A shared seed list is itself a fingerprint** → per-device locally-seeded shuffle, per-pack differing lists — and that shuffle must never appear in a field-probe report.
- **Legal / seizure** — a name list on a seized phone is extra evidence. → lives in the encrypted netmem blob, covered by panic-wipe.
- **Collateral** — a cover name blocked because of us hurts that site's Iranian users. → prefer large multi-tenant names; retire a name fleet-wide when it starts failing.
- **Over-promising** — the UI must not imply a learned name brings a Hetzner relay back in a full whitelist phase. It usually won't.

## 5. How it plugs into the blackout tier

- **Desync in front of REALITY:** keep it as a desktop-Linux experiment only; it's privileged and short-lived, and on the phone it's out. The blackout-tier value on the phone is use B's adaptive cover name, not a forged hello.
- **CDN front SNI:** this is the one path that genuinely beats an SNI allowlist, because the name really lives on the CDN. Daal has no CDN-fronted tier today, so this is the hook for a future tier, not this build — but the candidate-name machinery (seed list, per-network memory, rotation, attribution) is exactly what that tier will reuse.
- **Refresh channel:** the signed pack already carries per-route config additively; the candidate list ships there as a new sibling key, and a relative abroad updates the seed list from the manual field-probe reports. No schema break.

## 6. First build lane

1. **Cert-CN fix + real SNI on the pinned tiers** (S) — hygiene; stop every relay answering an active prober with `CN=daal-relay`.
2. **Name variants as auto-pass candidates**, ranked in `RouteMemory`, budgeted through `sideProbesPerHour`, using the existing `name_blocked` attribution, with the signed candidate list in the pack (S–M). This is the whole of the owner's idea for the two uses that are real today (blacklist-day cover, REALITY's cover name).
3. **Timing + grey-cap category** (M) — needed before the rig scenarios can assert "carried past the cap," and blocked on one real field capture of the 6-packet behaviour.
4. **Hold** multi-name REALITY relays (L) and phone desync (L, likely impossible) until **claim 14 is measured in the field**: white name → own relay IP vs white name → its real CDN IP, on MCI / Irancell / TCI. The evidence leans to "IP-gated," in which case steps 1–3 are the entire worthwhile scope on VPS addresses, and step 4 waits for a CDN tier.

*Fix-ups to land alongside the code, found during verification: the race-spacing spec drift (`specs/selection-v1.md:197-204` says 3 racemates / 400 ms; code is ≤2 in flight / 150–450 ms in `connect_race.go`); the domestic-decoy example in `client_desync.md:12-13`; and confirm the XTLS #3269 primary thread before any text leans on it (the repo cites it three inconsistent ways). `hcaptcha.com` is a web-sourced example only — keep it out of shipped defaults; the repo's own fixed-name example is `auth.vercel.com`.*

---

# Appendix A: verification

# Verification: adaptive cover names for Daal

I read the repo files listed below and the vendored sing-box 1.13.12 / metacubex utls 1.8.4. Web sources were the Lantern corpus summaries (net4people #626 and #628, and the LunarCanvas allowlist study), the Amnezia Q1 2026 blog, the sing-box 1.14 TLS docs and the ByeDPI READMEs. Nothing was built or run. I did not go into packet-level desync mechanics beyond what the verdicts need.

## Headline corrections to the design

1. **Use A is "best first target" only on blacklist days.** websocket-tls listens on 8445 and anytls on 8447 (`publisher/deploy/relayports/relayports.go:107-125`). The file itself says 8447 "is NOT whitelisted egress… worth ZERO inside Iran", and the plan says the same for ws (`docs/exotic-transports-plan.md:44,84`). Under the 53/80/443 port whitelist a good name on those ports buys nothing. Only vless-reality is a TCP family on 443 (`relayports.go:33`), so in a whitelist phase the name lever is **use B (REALITY) or nothing**, until port sharing on 443 lands. Fix the order: B first (publisher-driven), A as hygiene.
2. **The evidence says the SNI layer is a blocklist, except on CDN ranges.** In the LunarCanvas study (around 26 May 2026), random non-existent SNIs passed on allowlisted IPs, about half of the allowlisted IPs had no SNI filtering at all, and the outer gate was the **source and destination IP** (0.017%→0.07% of Iranian source IPs; about 2.8% of global /24s reachable). The "grey, 6-packet" allowlist behaviour (#626) is reported only for **allowed Cloudflare IPs**. Amnezia explicitly *assumes* a domain whitelist "within CDN subnetworks". So the design's premise "under an allowlist the DPI must see a name it likes" holds only on shared CDN prefixes. On a VPS address the IP decides, and the name only has to avoid the blocklist. This strengthens the design's own "hard limit". Claim 14 is still the decisive measurement, but expect "prefix-keyed / IP-gated".
3. **The pieces are in other places than the design says.**
   - Race spacing lives in `core/abi/connect_race.go`, not `core/scheduler`. The scheduler is a refresh ticker (`core/scheduler/doc.go`). The race uses at most 2 in flight, a 150–450 ms random delay, and **never two probes to the same address and port** (`connect_race.go:28-44,69-82`). That last rule already forces name variants of one route to run sequentially, which is good.
   - `specs/selection-v1.md:197-204` still says 3 racemates at 400 ms. That is spec/code drift.
4. **Name-vs-relay attribution already exists.** `AutoRefinedNameBlocked` / `AutoRefinedAddressBlocked` are in `core/abi/connect_auto_verdict.go:93-94,184-201`. A hello-stop is refined to "name" when another route to the same host and port, with a different name, gets past the handshake. Today it never fires for Daal packs, because every family has its own port. Name variants of one route are exactly what would make it fire.
5. **The modifier spec contradicts "never domestic".** `specs/modifiers/client_desync.md:12-13` gives "a major Iranian domain" as the example decoy SNI. Fix that text whatever the verdict.
6. **The XTLS #3269 citation is inconsistent across the repo.**
   - `intel:81`: reverse-DNS mapping of cover SNIs.
   - `protocol-level-anatomy.md:27`: MCI blocks REALITY after about 2 h of heavy traffic (#2778, #3269).
   - `worldbox/scenarios/sni-drop.json`: a cover SNI landing on a blocklist.
   - Check the primary thread before the design leans on it.
7. **The tool name "hcaptcha.com" is web-sourced, not in the repo.** #626 names hcaptcha.com as a whitelisted domain. The repo's fixed-name example is only `auth.vercel.com` (`intel:121,145`).

## Claims

| # | Verdict | Evidence | Implementation path / size / blockers |
|---|---|---|---|
| 1 | **VERIFIED** (code) | `sing-box@v1.13.12/common/tls/reality_server.go:90` builds a one-entry `ServerNames`. `metacubex/utls@v1.8.4/reality.go:360`: a name not in the map, or non-TLS 1.3, falls to the copy/forward path, not to auth. | Behavioural check in worldbox: a REALITY probe with a second SNI should get the cover host's chain. S. |
| 2 | **VERIFIED client-side; relay side expected** | Pinning sets `InsecureSkipVerify=true` plus `verifyPublicKeySHA256` (`common/tls/utls_client.go:170-177`, `std_client.go:114-121`), so the name is never checked. `pinnedTLSOpts` puts the relay IP in `server_name`, and Go/uTLS strip it, so no SNI goes out (`publisher/deploy/relaypack/client_outbound.go:514-552`). The std server uses its configured cert whatever the SNI (`std_server.go`, no SNI gate). anytls uses the same `pinnedTLS` (`client_outbound.go:397`). | Pack-only change in `pinnedTLSOpts` (plan W2-R, `exotic-transports-plan.md:307-308`). **Do the cert CN fix first**: every relay serves a self-signed cert with `CN=daal-relay` (`cloudinit/v2.yaml.tmpl:370`, `cmd/daal-relay-mgmt/tlscert.go:117-119`), which an active prober reads whatever SNI is sent. S code; M with the on-wire check. Fresh provision is needed for the cloud-init half. |
| 3 | **VERIFIED, but the proposed remedy is unnecessary** | No per-connection hook. `defaultDialer` reuses one `Config` (`common/tls/client.go:95-131`). `SetServerName` is called only by grpc credentials (`transport/v2raygrpc/tls_credentials.go:37,84`). Rewriting the SNI inside a written hello would break the TLS 1.3 transcript and the REALITY AAD, so a wrapping dialer cannot do it. | No sibling outbounds needed. The engine already starts a whole instance per route (`connectRouteLocked`; side instances for racing, `connect_race.go:47-60`). A name variant is just a JSON-patched copy of the route's outbound (`tls.server_name`) offered as another `autoCandidate` (`core/abi/connect_auto.go:829-943`, `profileRelay` :957). Cost is one instance start plus a proof. The comment cites 0.3 s for the hand-over proof on the phone, so measure a full start. S–M. |
| 4 | **PARTLY**: true for 1.13.12, false upstream | `common/` has `tlsfragment` and no spoof package (local listing). **sing-box 1.14.0 adds outbound TLS `spoof` / `spoof_method`** (wrong-sequence by default, plus wrong-checksum/ack/md5/timestamp; route-rule actions added in alpha.21). The docs say "Only supported on Linux, macOS, and Windows, and requires elevated privileges", with `CAP_NET_RAW` + `CAP_NET_ADMIN` on Linux. | Unusable on non-root Android even after a pin bump. Desktop-Linux-only at best, matching `client_desync.md` ("Linux desktop only"). The pin bump itself is L (release coupling). |
| 5 | **UNKNOWN for Daal; plausible for the TTL variant only** | ByeDPI-Android says "All application features work without root", and ByeDPI documents a low-TTL decoy mode. Its README says the md5sig mode may be disabled on some kernels (<3.9, Android). Setting IP_TTL on one's own socket needs no capability. Not tested on Daal's `protect()`ed socket. | Would need a Daal-owned layer under sing-box's TLS. Practical route: a custom outbound type registered in a Daal-built registry (today `include.Context` builds fixed registries, `core/engine/engine_singbox.go:254`), used as `detour`. **Cost:** detoured routes are not side-probeable (`connect_race.go:47-52`, `core/engine/side.go:88`), so they lose racing. #626 says both variants died after about 4 days behind a stateful NAT on Cloudflare ranges. L. Keep the "Never / experiment-only" verdict for the phone. |
| 6 | **VERIFIED** | `common/tlsfragment/conn.go:43-50`: splits only when `IndexTLSServerName` finds a name. `reality_client.go:119-128` builds `utls.UClient` on the raw conn; `utls_client.go:61-62` wraps only when `record_fragment` is set. `specs/modifiers/tls_fragment.md:35-43` says the same. | None. |
| 7 | **VERIFIED; design is out of date** | `core/diagnostics/observe.go:103-125` reads the error chain first (`errors.Is` ECONNRESET/EPIPE, deadline/`net.Error.Timeout`, `io.EOF`/`ErrUnexpectedEOF`), with string fallbacks, and separately maps Cronet codes (:225-260). `classify.go:130` is only the legacy string table. | Nothing new. Add one engine test that a sing-box-wrapped uTLS reset still satisfies `errors.Is(ECONNRESET)`. S. |
| 8 | **PARTLY** | RST TTL cannot be read by an unprivileged TCP socket: true. The research shows Iran's injected TCP packets do have distinctive TTLs (53–55, FOCI 2026 "Insights into an Iranian Internet Shutdown"), but only a capture sees that. Timing is the only on-device signal: connect() duration ≈ SYN/SYN-ACK RTT, and hello→reset time. Neither is recorded today; `Observation` has no timing fields (`observe.go:57-89`). | Record `connect_ms` and `hello_to_fail_ms` in the proof path (`core/engine/proof_singbox.go`), then add an `Injected` hint to `Observation`. It must not become a raw-timestamp leak (field-probe rule "no timestamps finer than the hour" applies to reports, not in-memory use). M. Unvalidated heuristic: CGNAT and the border hop may make the two RTTs close. |
| 9 | **PARTLY / gap confirmed** | No "grey cap" category. PhaseCarry with Timeout/Closed maps to `Unknown`; Reset maps to `TCPReset` (`observe.go:198-207`). **Caveat:** #626 does not say which packets the 6 counts. A TLS 1.3 / REALITY handshake plus the first proxied request may not fit in 6 packets in both directions, so "grey" may show up as a PhaseHandshake timeout, not a post-handshake stall. | New category in the closed taxonomy (`specs/failure-taxonomy-v1.md`, `core/diagnostics`). Detector: completed handshake, then reset or stall with very few bytes (needs byte counts in the proof path). M. Blocker: no field capture of the cap. |
| 10 | **VERIFIED (mechanism exists)** | `connect_auto_verdict.go:184-201`, `stoppedAtHello` :145-150, `pastHandshake` :137-143. Verdict rollup :256-259. | Reuse it: name variants share host and port by construction. Extend `pastHandshake` to also accept "carried past the cap" once claim 9 exists. S. |
| 11 | **VERIFIED** | `core/netmem/hash.go:26-45` hashes carrier+ssid, so cell networks bucket by carrier. `snapshot.go:71-73` says "adding a field is allowed". `specs/network-memory-v1.md:270-272,279-337` gives the 3B/3C additive-widening precedent. | Cheaper than a new map: key name variants in the existing `RouteMemory` as `routeID + "#" + index-into-signed-list`. That reuses ranking, streaks, grading (`measure.go`) and the 30-day sweep (`store.go:28`), and keeps plaintext names out of the blob. `ForgetRoute` (`store.go:266`) must also drop the variants. A short spec section is still needed. S–M. The design's 24 h decay / 72 h expiry is new logic: today `FailedSince(cutoff)` (`snapshot.go:170`) is the only ageing. |
| 12 | **PARTLY: the budget exists, in a different place** | No per-network trial budget in netmem; `BudgetUsage` is per-route **bytes** per hour (`snapshot.go:87-92`, `core/budget/caps.go`). The per-network hourly *probe* budget is `sideProbesPerHour = 12`, **in memory**, in `core/abi/connect_race.go:76-78,105-123`. It counts side probes only; tunnel-instance attempts are never refused. | Count name trials through `sideNoteLocked` (`connect_race.go:132`) and add a per-(network, relay) lifetime cap of about 3 names. No ABI symbol needed. A restart forgets the count (documented); persist it only if that matters. S. |
| 13 | **UNKNOWN** | Pool hosts are mirrors / provider-service hosts chosen by R1–R7 (`publisher/deploy/sni/rule.go`, `pool.go`). There is no record of default-vhost or unknown-SNI behaviour. | Add a measured field to the pool entry (R7 "dated" discipline) with an `openssl s_client -servername <other>` check per host, publisher-side. S. Moot unless claim 15 is done. |
| 14 | **UNKNOWN; evidence leans to "IP-gated"** | See headline 2. #626 / Amnezia tie the name allowlist to CDN ranges. LunarCanvas shows random SNIs pass on allowlisted non-filtered IPs and that the outer gate is IP. No carrier split published. | Field probe: white name → own relay IP vs white name → its real CDN IP, on MCI / Irancell / TCI. Needs a `specs/field-probe-v1.md` revision first (privacy rules forbid the carrier numeric ID, so label by network kind or a user-chosen bucket). M. |
| 15 | **VERIFIED that nothing exists; design understates the cost** | One `server_name` → one-entry map (`reality_server.go:90`). Two listeners on 443/tcp are refused (`relayports.go:55-72`, BUG-14). The plan says the project does not fork sing-box (`exotic-transports-plan.md:727`). REALITY forwards non-authenticating hellos to the cover **host**, not a local sibling (`relayports.go:96-104`). | Options: (a) fork or patch sing-box, against policy; (b) put an SNI-peeking demux on 443 in front of several REALITY inbounds on loopback, each with its own `handshake.server` (cloud-init + `cmd/daal-relay-mgmt` + relayports change, fresh provision only). L. Also breaks the invariant in `provider/cover_sni.go` (one name per relay, stamped in two places) and the `ReuseCoverSNI`/`NextCoverSNI` rotation logic. |
| 16 | **PLAUSIBLE, not present** | No per-SNI counter in mgmt today. | Would need a sing-box hook or a log parse of the inbound's SNI. Must stay opt-in, aggregated per relay, and never per recipient key. M. Weak value when there is one name per relay (claim 15). |
| 17 | **PARTLY** | Refresh fetches a whole signed `.sbp` and verifies it before apply (`core/refresh/relaypack_refresh.go`). Additive precedent: `_cdn_attestation` inside the per-candidate `_relaypack` slot with no `spec_version` bump (`specs/relaypack-v1.md:284-290`). **But** the endpoint commitment decoder is strict (`bundle/go/bundle/endpoint.go:167` `DisallowUnknownFields`). Freshness v1→v2 was a breaking change (`relaypack-v1.md:316-321`). | Put the per-route candidate list as a new sibling key in the route's `family_specific_config` / `_relaypack` container, **not** inside `Endpoint`. Covered by the pack signature, ignored by old builds. Spec note plus `bundle/go/bundle` types plus `derive_tree.ts`. S–M. Publisher-side, embedded profiles mean a `libdaal_deploy.so` rebuild (`exotic-transports-plan.md:303-305`). |
| 18 | **PARTLY** | worldbox `DPIRule` (`test-rigs/worldbox/driver/censor_dpi.go:33-58`) has `when` (tls_sni / first_data / first_bytes_not), `sni` (exact names), `reassemble`, `dst` (**exact single address**), `port`, and `action` drop/rst. So SNI plus destination is expressible for one address, not a prefix. Missing: a negated list (allowlist default), a packet or byte cap action, time-varying rules (rules are static per scenario). censor-lab has only `block_list` (`censor-lab/scenarios/stateless-sni-rst.json`), and its live netns runner is "staged" (`lab-driver/cmd/lab-driver/main.go:113-115`). | Build in **worldbox**, not censor-lab: add `sni_not` (default-deny), `dst_prefix` (CIDR), `action: "cap"` with `max_pkts`, and a scenario-level `timeline: [{at_s, rules}]` the NFQUEUE engine swaps atomically. M. |
| 19 | **UNKNOWN (rig not built)** | Depends on 18 and 3. | After the timeline flip at t=60 s, the scenario should check four things: (1) the live route dies; (2) the next variant is tried as a fresh candidate within the same pass; (3) the dead name gets `name_blocked` (`connect_auto_verdict.go:196`); (4) RouteMemory shows `route#old` failed, `route#new` carried, and the base route and family are not cooled down. M. |
| 20 | **UNKNOWN (rig not built)** | Depends on 18 (`dst_prefix`). | Expected verdict is `address_blocked` for all variants (`connect_auto_verdict.go:200,256`), with the attempt count bounded by the per-relay cap and `sideProbesPerHour`. S once 18 exists. |

## Specific questions

- **Setting the fake or first-segment SNI per connection.**
  - For the real hello (uses A/B), no per-connection mechanism is needed or possible inside sing-box. Swap the outbound JSON per candidate at the abi layer (claim 3).
  - A fake hello (D) would need a Daal-owned dialer below TLS (custom outbound type plus `detour`). It needs privileges on 1.14 upstream and is unverified unprivileged, and it costs racing.
  - "First-segment name" is not a cover mechanism. Agreed (`tlsfragment/conn.go` only splits the real name).
- **Network identity and rankings.**
  - netmem's key is `SHA-256(kind|carrier|ssid)[:8]`; raw values are discarded at `core/abi.NetworkChanged` (`specs/network-memory-v1.md:27-40,51-60`).
  - Per-network rankings fit in the existing `RouteMemory`, keyed by variant (claim 11). The blob is encrypted (routestore age identity) and covered by panic-wipe.
- **Seed list shipping.**
  - Down: inside the signed pack, per route (claim 17).
  - Up: only through the manual field-probe report, after a schema revision. `test-rigs/field-probe/docs/privacy-rules.md` forbids browsing destinations and the carrier numeric ID, and requires "no field that would let an observer correlate two reports". A per-device shuffled order must therefore never appear in a report.
- **Modelling a changing allowlist.** Use worldbox's NFQUEUE DPI with the four additions in claim 18. censor-lab's live runner is not functional today.
- **"Domestic SNI: Never" re-examined for desync.** The verdict stands. The server-mismatch argument does not apply to a decoy, but:
  - the gateway-anomaly argument does;
  - LunarCanvas shows random foreign names already pass the SNI layer on allowlisted IPs, so a domestic decoy buys nothing there;
  - on CDN ranges the allowlisted names reported (e.g. hcaptcha.com) are foreign.
  - Fix the contradictory example in `client_desync.md:12-13`.

## Net recommendation (adjusted)

1. Ship the cert-CN fix and real SNI on the pinned tiers (S), as hygiene.
2. Name variants as candidates in the auto pass, ranked in `RouteMemory`, budgeted through `sideProbesPerHour`, with the existing `name_blocked` attribution (S–M). This pays on blacklist days and for REALITY's cover name.
3. Spend no effort on multi-name REALITY relays (L) or desync on the phone (L, likely impossible or short-lived) until claim 14 is measured.
4. The only place the idea plausibly beats an allowlist is shared CDN prefixes, and Daal has no such tier today.

## Sources

- Repo: `research/intel-and-some-working-methods.md:29,77-83,113-145`; `research/filtering-the-flow.md:97-101,107-111,127-133,251-253`; `research/protocol-level-anatomy.md:27,35-37,113`; `docs/exotic-transports-plan.md:44,69-71,84,238,253-264,300-312,733-779`; `specs/modifiers/client_desync.md`; `specs/modifiers/tls_fragment.md`; `specs/network-memory-v1.md`; `specs/selection-v1.md:187-205`; `specs/relaypack-v1.md:284-321`; `test-rigs/field-probe/docs/privacy-rules.md`; `core/abi/connect_race.go`; `core/abi/connect_auto.go`; `core/abi/connect_auto_verdict.go`; `core/diagnostics/observe.go`, `classify.go`; `core/netmem/{hash,snapshot,measure,store}.go`; `core/engine/{platform_singbox,protect_singbox,engine_singbox,side}.go`; `publisher/deploy/relaypack/client_outbound.go`; `publisher/deploy/relayports/relayports.go`; `publisher/deploy/provider/cover_sni.go`; `publisher/deploy/sni/{rule,pool}.go`; `bundle/go/bundle/endpoint.go:167`; `test-rigs/worldbox/driver/censor_dpi.go`; `test-rigs/worldbox/scenarios/{sni-rst-stateless,sni-drop}.json`; `test-rigs/censor-lab/scenarios/*.json`.
- Vendored: `sing-box@v1.13.12/common/tls/{reality_server.go:90, reality_client.go:119-143, utls_client.go:60-65,170-177, std_client.go:114-121, client.go:72-131}`; `common/tlsfragment/conn.go:43-50`; `metacubex/utls@v1.8.4/reality.go:360`.
- Web (fetched 2026-11-20; corpus pages are LLM-extracted summaries):
  - [net4people #626 summary: 6-packet cap on allowed Cloudflare IPs, about 4-day spoof lifetime, stateful NAT, hcaptcha.com whitelisted](https://corpus.lantern.io/papers/2026-tuleo1-internet-analysis-shutdown/)
  - [LunarCanvas, "A Swift Look into the Internet Allowlist in Iran": IP allowlist both directions, SNI blocklist on about half the allowlisted IPs, random SNIs pass](https://corpus.lantern.io/papers/2026-lunarcanvas-swift-look-into/)
  - [Its SNI-layer finding](https://corpus.lantern.io/findings/2026-lunarcanvas-swift-look-into__iran-sni-blocklist-layered-on-allowlist/)
  - [net4people #628 summary: reassembly claim, REALITY RST after handshake, 24 h CDN domain blocks (single user, June 2026)](https://corpus.lantern.io/papers/2026-pooribitwise-iran-advanced-dpi/)
  - [Amnezia Q1 2026: domain whitelist assumed within CDN subnets](https://amnezia.org/en/blog/internet-censorship-in-iran-q1-2026-and-forecast)
  - [sing-box TLS docs: `spoof` / `spoof_method` since 1.14.0, needs CAP_NET_RAW + CAP_NET_ADMIN](https://sing-box.sagernet.org/configuration/shared/tls/)
  - [sing-box v1.14.0-alpha.13 notes ("Add TLS spoof")](https://newreleases.io/project/github/SagerNet/sing-box/release/v1.14.0-alpha.13)
  - [ByeDPI README: TTL decoy, md5sig may be disabled on Android](https://raw.githubusercontent.com/hufrea/byedpi/main/README.md)
  - [ByeDPIAndroid README: no root](https://raw.githubusercontent.com/dovecoteescapee/ByeDPIAndroid/master/README.md)
  - [FOCI 2026, "Insights into an Iranian Internet Shutdown": injected-packet TTLs 53–55](https://www.petsymposium.org/foci/2026/foci-2026-0016.pdf)


---

# Appendix B: adviser draft

# Adaptive cover names for Daal — design and verdict

Read-only study; nothing built or run. Items marked **[code]** I read in the repo or the vendored sing-box 1.13.12; **[report]** are 2026 field reports, mostly single-user and LLM-summarised in the Lantern corpus; **[inference]** is my reasoning.

## 0. Verdict

The owner's idea makes sense, and it matters more now than a year ago.

- **Why it matters now.** On blacklist days, hiding the name (fragmentation) is enough. Under an allowlist, a hello with no readable name is treated as "grey", so the DPI must *see a name it likes*. A 2026 report says a non-whitelisted SNI to an allowed Cloudflare IP is cut after exactly 6 packets, while a whitelisted SNI has no cap [report].
- **Why fixed names fail.** A hard-coded name (`auth.vercel.com`, `hcaptcha.com`) becomes the tool's signature and one list edit kills it.
- **The Daal-specific shortcut.** Every relay is ours, and clients authenticate by REALITY key or SPKI pin, not by name. So the "fake name" can simply be the SNI of the *real* hello. No fake packet, raw socket or root is needed, and nothing is out-of-window for a stateful NAT to reject.
- **The hard limit.** The name only helps where the IP already passes. The censor's own plan says whitelisting is "FQDN + IP prefix + port" (`research/intel-and-some-working-methods.md:29`). If that is how it is keyed, a white name on a Hetzner address buys nothing in a whitelist phase; it only pays on shared CDN prefixes. Whether the key is SNI alone or SNI+prefix is the most important thing to measure (claim 14).
- **Recommendation.** Build it as "adaptive SNI on the real hello, learned per network", with the route attempt itself as the probe. Keep packet-level desync as a post-V2 experiment for CDN paths only. Keep "never domestic names" for everything that crosses the international gateway.

## 1. Where the name is used, and why the risk differs

| Use | Who sees the name | Must a server answer for it? | Works on non-root Android? | Verdict |
|---|---|---|---|---|
| **A. Real SNI on a pinned-cert TLS family** (websocket-tls, anytls) | Censor; our relay ignores it | No. Client pins SPKI (`client_outbound.go:532-533`); TLS 1.3 hides the certificate from a passive observer | Yes, pack-only once the real-SNI work (plan W2-R) lands | **Best first target.** Weak point: an active prober sending that SNI gets our self-signed cert |
| **B. REALITY serverName** | Censor, relay, and the borrowed site | Yes. The relay's `reality.handshake.server` must produce a believable answer for that name | Yes on the client; relay change needed | **Second target, publisher-driven.** Per-client freedom is small |
| **C. CDN front SNI** (SNI ≠ Host on a CDN edge) | Censor and the CDN | The CDN must hold a certificate for it and still route by Host | Yes | **Highest value under an allowlist**, but Daal has no CDN-fronted tier today, and it depends on the CDN tolerating SNI≠Host |
| **D. Fake ClientHello (desync)** | Censor only; the server never receives it | No | Sequence-forging variant: no (raw sockets). TTL-limited variant: possibly, unverified (claim 5) | **Experiment only.** One report says both variants died after about 4 days once Cloudflare ranges went behind a NAT that validates sequence numbers and checksums |
| **E. Split hello, "first-segment name"** | Censor | — | Record fragmentation exists on the ws path only | **Not a cover-name mechanism.** Splitting hides the real name; it cannot show a different one. Useless under an allowlist; a 2026 report says Iran now reassembles 10–30 byte fragments |

Notes:

- **REALITY today takes one name.** sing-box builds `ServerNames = map[string]bool{options.ServerName: true}` (`common/tls/reality_server.go:90`) **[code]**. A client that changes its REALITY SNI on its own is rejected and forwarded to the cover site. Daal's invariant says the same: client `server_name` and relay `handshake.server` must be one string (`publisher/deploy/provider/cover_sni.go`).
- **REALITY cannot be fragmented or wrapped** in this engine (`specs/modifiers/tls_fragment.md`), so use B is name choice only.
- **Re-examining "Domestic SNI: Never"** (`docs/exotic-transports-plan.md:69`). For desync the mismatch-at-the-server argument does not apply, since no server sees the fake. But a different argument does, and it is stronger: domestic sites are served inside the national network, so a domestic name appearing at the *international* gateway is anomalous by itself, for a fake hello as much as a real one. The verdict stands for all five uses. The useful pool is **whitelisted foreign names**, ideally ones co-hosted on the destination's own prefix.
- **The plan's self-contradiction** (its review item 7: "no-SNI fails an allowlist" vs "the gate is the IP") is resolved by the layered picture in the 2026 measurements: an IP allowlist first, then an SNI layer on top [report]. Both are true; the name matters only after the IP passes.

## 2. Discovering allowed names on the device

### Principle: the route attempt is the probe

Standalone scanning is what makes a scanner visible. The only ground truth is "did the real connection, carrying this name, move data past the cap". So candidates are tried *as connect attempts*, a few at a time, and learned from. Separate probing is the exception.

### Candidate sources, in order of trust

1. **Signed seed list in the pack / refresh channel.** Each entry: name, class (foreign-whitelisted, CDN-co-hosted, mirror), which CDN or prefix it lives on, audited date. Same discipline as `publisher/deploy/sni/rule.go` (evidence fields measured, not remembered).
2. **Names the relay can answer for** (use B): the SANs and default-vhost behaviour of the relay's cover site, published by the publisher per relay.
3. **Names co-hosted on the target's CDN** (uses C, D): from the seed list, tagged by CDN.
4. **The user's own traffic: do not use.** The engine sees every name the user resolves, and those are the best evidence of what is open, but storing or reusing them breaks the "no browsing destinations" rule (`test-rigs/field-probe/docs/privacy-rules.md`) and would put a user's own habits into Daal's wire signature. At most keep an in-memory, never-persisted count of "seed-list names seen working in passthrough traffic".
5. **No domestic names** (see section 1).

### Signals

| Observation | Meaning | Cost |
|---|---|---|
| System resolver returns 10.10.34.34–36 for the name | Name is blacklisted; drop it without a TLS attempt | One DNS query, but the ISP resolver logs it |
| RST arriving faster than the SYN/SYN-ACK round trip, right after the hello | Injected by the middlebox: name blocked on this path | Free if it happens on a route attempt |
| Hello sent, then silence | In-path drop: name blocked, or IP/protocol whitelist. Disambiguate with a second name on the same IP | Slow (timeout) |
| Handshake completes, flow dies after ~6 packets | "Grey": name not on the allowlist | Needs real payload, so only a carried route shows it |
| Handshake completes and more than ~50 KB flows | Name is white on this network, for this IP | The real connection |
| RST flood right after a REALITY handshake completes | Not a name problem; REALITY itself is fingerprinted there [report]. Do not burn the name | — |

"Allowed at the name's own IP" does not prove "allowed at our relay's IP". Only the last two rows are evidence for a route.

### Probe budget and shape

- **At connect failure:** try at most 2 further names per route per attempt, sequentially, with the normal Happy-Eyeballs-like spacing the scheduler already uses. Never parallel-fan a list.
- **On network change:** no probing. Load the remembered ranking for that network and use its top name.
- **Periodically:** none in the background. A rename is tested only when a connection is about to be made anyway.
- **Standalone fetches (optional, off by default):** at most 3 per hour per network, each a real HTTPS GET of a small real page from the name's own address, with the same uTLS fingerprint as the route. That is browsing, not a scan: one name, one address, port 443, full page.
- Count every trial against the existing per-network hourly budget in netmem.

## 3. Memory, rotation, sharing

- **Key.** netmem keys a network as `SHA-256(kind|carrier|ssid)` truncated to 8 bytes (`core/netmem/hash.go:36`) **[code]**. Cell networks bucket by carrier, which is the right grain: MCI, Irancell and TCI have different lists.
- **What to store.** A new per-network map, parallel to `RouteMemory`: `(route family, relay, name) → carried count, failed count, fail streak, last-carried hour, last-failed hour, failure category`. Hour buckets only, as today. This widens the locked v1 snapshot shape, so it needs a spec change in `specs/network-memory-v1.md` (the 3B/3C widenings are the precedent).
- **Ranking.** Reuse `RouteMemory`'s logic: carried-last beats failed-last; a fail streak of 2 with a name-shaped category (`tcp_reset` right after hello, `tls_sni_or_cert_block_suspected`, grey-cap) demotes the name; one success resets it.
- **Decay.** Whitelists change by the day in crisis mode. Halve confidence after 24 h without a fresh success; a "blocked" mark expires after 72 h so a re-opened name gets retried; the existing 30-day sweep removes the rest.
- **Quick switch.** On a name-shaped failure of a live route, re-dial once with the next-ranked name before declaring the route failed. This needs the engine to swap the outbound's `server_name`; sing-box fixes it per outbound in config, so each candidate name is a pre-materialised sibling outbound or a reload (claim 3).
- **Attribution.** A name failure must not burn the relay or the family (same spirit as locked invariant 41). Distinguish "name died" (another name works on the same relay) from "relay died" (no name works).
- **Sharing.**
  - Down: the publisher's signed refresh carries the candidate set and, per relay, the names that relay can answer for. Everyone in a pack gets the same list, so the list reveals nothing about one recipient.
  - Up: nothing automatic. The only path off the device is the manual, user-reviewed field-probe report. Add an optional field "names from the seed list that carried, per network kind", with no carrier ID and hour-bucketed, which the user reads before sharing. The relative abroad then updates the seed list.
  - The relay can also learn passively: it sees which SNI each successful connection used. Aggregated per relay (not per recipient key) this tells the publisher which names work, with no client upload. This must be opt-in and counted, not logged per user.

## 4. What the censor must do to defeat it, and how fast

| Counter | Kills | Effort for them | My estimate |
|---|---|---|---|
| Block the specific names on the list | Nothing lasting; rotation absorbs it | Trivial | Hours, repeatedly; this is the game the design is built for |
| Key the allowlist on FQDN **and** destination prefix | Uses A, B, D on our own VPS addresses | Already in their written plan | Likely already true in crisis mode; defeats the idea outside CDN space |
| Check SNI against DNS for the destination IP | A and B everywhere; C survives (the name really lives there) | Offline batch job, then graylist | Weeks. `sni/rule.go` R5 already concedes this flags 100% of relays today |
| Active-probe the relay with the observed SNI | A (self-signed answer). B survives if the cover site's answer is what the relay forwards | Moderate; they have done it before | Weeks |
| Terminate or normalise TCP on CDN ranges | D completely | Done once already on Cloudflare [report] | Already deployed on some ranges |
| CDN enforces SNI == Host | C | Not the censor's choice; CDN policy | Unknown; already true on Azure, Google, AWS |
| Cap bytes or lifetime even for white names; whitelist client IPs (tiered access) | Everything | Policy decision | Crisis mode only |
| Statistics: one client rotating SNIs toward one IP | The adaptivity itself | Easy to compute | This is why rotation must be slow (section 5) |

Net: adaptivity converts "one edit kills the fleet" into "they must change how the allowlist is keyed". That is a real gain on blacklist days and on CDN space, and none on a VPS address under a prefix-keyed whitelist.

## 5. Risks to the user and mitigations

- **Probing as a signal.** Several names to one IP in a minute is a scanner. Mitigation: at most 2 extra names per attempt, sticky winners (never rotate a working name), no parallel fan-out, no background scans.
- **Many SNIs for one IP over time.** A single address seen under five names is odd. Mitigation: cap the lifetime set per (network, relay) at about 3 names; prefer names that are siblings on one certificate.
- **Contacting servers that log.** Standalone fetches touch third-party sites. Mitigation: off by default; foreign names only; never domestic servers, which log to the state by law.
- **DNS exposure.** Resolving candidates through the ISP resolver writes the list into the resolver's logs. Mitigation: do not resolve candidates at all for uses A/B/D (the name is only a string in the hello); resolve only for standalone fetches.
- **A shared seed list is a fingerprint.** If every Daal client tries the same names in the same order, the order is the signature. Mitigation: per-device shuffled order seeded locally; per-pack lists that differ between publishers.
- **Legal exposure.** Unchanged in kind (unlicensed VPN use is already criminalised), but a name list on a seized phone is extra evidence. Mitigation: it lives in the encrypted netmem blob and is covered by the existing panic-wipe.
- **Collateral.** A cover name that gets blocked because of us harms that site's Iranian users. Mitigation: prefer large multi-tenant names; retire a name fleet-wide when it starts failing.
- **Over-promising.** In a full whitelist phase this probably does not bring a Hetzner relay back. The UI must not suggest it does.

## 6. Numbered claims to verify

**Engine and sing-box**

1. sing-box 1.13.12's REALITY inbound accepts exactly one server name (`common/tls/reality_server.go:90`). **Read and confirmed**; verify behaviourally that a second name is forwarded to the cover site rather than authenticated.
2. A pinned-SPKI websocket-tls / anytls outbound still verifies when `tls.server_name` is an arbitrary hostname, and the relay's TLS inbound accepts any SNI. Depends on W2-R real-SNI work; today the pack puts the relay IP there and the hello has no SNI.
3. `tls.server_name` cannot be changed per connection on a live outbound; switching names requires a sibling outbound per name or an engine reload. Measure the reload cost on the phone.
4. No fake-hello or "spoof" facility exists in 1.13.12 (there is no `common/tlsspoof`; only `common/tlsfragment`) **[code]**. Check whether a later upstream release adds one and what privileges it needs.
5. On non-root Android, a `protect()`ed TCP socket can set `IP_TTL` mid-connection and/or `TCP_MD5SIG`, which is what a TTL-limited fake would need. Unverified; SELinux may refuse. If both fail, use D is impossible on the phone and the existing "Never" stands unchanged.
6. `tf.NewConn` splits only when it finds a server name and never reaches REALITY (`common/tlsfragment/conn.go`, `specs/modifiers/tls_fragment.md`). **Read and confirmed** for the split-on-SNI part.

**Platform signals**

7. A Go socket behind `protect()` reports RST, FIN and timeout distinctly (`ECONNRESET` vs `io.EOF` vs deadline). Expected true; `core/diagnostics/classify.go:130` currently matches the string "connection reset by peer", so confirm the error survives sing-box's and uTLS's wrapping.
8. RST-after-hello latency can be compared with the SYN/SYN-ACK round trip (or `TCP_INFO` rtt) to tell an injected reset from a server reset, without raw sockets. The RST's TTL is not observable to an unprivileged TCP socket.
9. The 6-packet "grey" cap is detectable as: handshake completes, then a reset or stall before ~10 KB. Needs a new failure category distinct from `tls_handshake_failed`.
10. The engine can attribute a failure to the name rather than the relay (a second name succeeds on the same relay within the same attempt).

**Memory**

11. netmem keys cell networks by carrier only (`core/netmem/hash.go:36`) **[confirmed]**; adding a per-name map changes the locked v1 snapshot shape and needs the same widening procedure as Phase 3B/3C.
12. The per-network hourly budget can count name trials without a new ABI symbol.

**Relay and publisher**

13. A REALITY cover site answers an unknown SNI with its default certificate rather than a fatal alert; only such sites allow more than one accepted name per relay. Measure each pool host in `publisher/deploy/sni/pool.go`.
14. **Field, decisive:** in a whitelist phase, is a white name honoured on *any* destination IP, or only on that name's own prefixes? Test: white name → own relay IP vs white name → its real CDN IP, on MCI, Irancell and TCI.
15. Accepting several names on one relay needs either a one-line patch to the REALITY server or an SNI demultiplexer in front of several inbounds; neither exists in the cloud-init template today.
16. The relay can count successful handshakes per SNI without per-recipient logging.
17. The signed refresh can carry a candidate-name list per relay without a pack schema break.

**Rigs**

18. worldbox's DPI rules today express `when: tls_sni` + a name list + `rst`/`drop` + `reassemble` (`test-rigs/worldbox/scenarios/sni-rst-stateless.json`, `sni-drop.json`) **[confirmed]**. Missing for this work: an allowlist rule (default action for names *not* listed), a packet-count cap action, a list that changes on a schedule, and an SNI+prefix key. censor-lab's scenario schema (`test-rigs/censor-lab/scenarios/stateless-sni-rst.json`) has only `block_list`.
19. A rig scenario "allowlist flips at t=60 s" should show: live route dies, engine re-dials with the next name within one attempt, netmem records the old name as failed and the new one as carried, and the relay is not marked failed.
20. A rig scenario "SNI+prefix allowlist" should show the feature gaining nothing, and the client stopping after its 2-name budget rather than cycling the list.

## Sources

- Repo: `research/intel-and-some-working-methods.md` (lines 29, 47, 77–83, 113–145), `research/filtering-the-flow.md` (Parts 2 and 4), `research/protocol-level-anatomy.md`, `docs/exotic-transports-plan.md` (lines 69, 71, 88, 238, 772–779), `specs/modifiers/client_desync.md`, `specs/modifiers/tls_fragment.md`, `specs/network-memory-v1.md`, `specs/field-probe-v1.md`, `test-rigs/field-probe/docs/privacy-rules.md`, `core/netmem/hash.go`, `core/netmem/measure.go`, `core/diagnostics/classify.go`, `publisher/deploy/sni/rule.go`, `publisher/deploy/sni/pool.go`, `publisher/deploy/provider/cover_sni.go`, `publisher/deploy/relaypack/client_outbound.go`, `test-rigs/worldbox/scenarios/*.json`, `test-rigs/censor-lab/scenarios/*.json`.
- sing-box 1.13.12 at `/home/nima/go/pkg/mod/github.com/sagernet/sing-box@v1.13.12`: `common/tls/reality_server.go`, `common/tlsfragment/conn.go`, `option/tls.go`, `route/conn.go`.
- Web (all corpus pages are LLM-extracted summaries of net4people threads; treat as leads):
  - [Six-packet cap, stateful NAT, 4-day lifetime of SNI spoofing (net4people #626 summary)](https://corpus.lantern.io/papers/2026-tuleo1-internet-analysis-shutdown/)
  - [SNI blocklist layered on the IP allowlist](https://corpus.lantern.io/findings/2026-lunarcanvas-swift-look-into__iran-sni-blocklist-layered-on-allowlist/)
  - [Reassembly, REALITY RST flood, 24-hour CDN domain blocks (net4people #628 summary)](https://corpus.lantern.io/papers/2026-pooribitwise-iran-advanced-dpi/)
  - [Hiddify Reality Scanner — the existing manual "find a working SNI" practice](https://github.com/hiddify/Hiddify_Reality_Scanner/)
  - [ByeDPI for Android — non-root desync under VpnService](https://cdn.jsdelivr.net/gh/dovecoteescapee/byedpiandroid@master/README.md) (which fake-packet options work without root was not confirmed)