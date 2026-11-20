# Optional add-ons for publishers: standby IP, CDN front, Google update channel

Adviser design, 2026-11-20. Read-only: nothing was built or run. This builds on `docs/blackout-tier-plan.md` (T1, C0–C8, Groups B/C/D) and does not repeat its evidence; where I change one of its decisions I say so. Web facts were checked today and are cited in section 9. Items marked **GATE** are unknown until tried on the real accounts.

## 0. Decisions in one page

| | Standby IP | CDN front | Google update channel |
|---|---|---|---|
| What it is | A second Hetzner address, attached to the relay from day one, not advertised | The relay reachable through the publisher's own Cloudflare zone, with ECH | A tiny Apps Script web app that serves the signed "the relay moved" note |
| Rescues | One blocked address | A blocked address, a blocked Hetzner range, an SNI filter on the relay's cover name | Nothing by itself: it delivers the fix for the other two when the ordinary refresh addresses are blocked |
| Does not rescue | Range or ASN block, SNI or protocol block, allowlist, blackout | SNI allowlist phases, Cloudflare IP block, blackout | Blackout; routes where Google itself is cut |
| Cost | €3.00/month per relay excl. VAT (€3.57 incl. 19%) | Domain, about $9–11/year; Cloudflare free | Free |
| Ties to the publisher | Nothing new (same Hetzner account) | Cloudflare account email, card and registrant data at the registrar; Cloudflare sees every recipient's IP and each connection's destination | A Google account (phone-number bound); with "Sign in with Google", also a record at Google that this account authorised the Daal app |
| Carries user traffic | Yes (it is the relay) | Yes | No, and it should stay that way (section 3.7) |
| In the pack from day one | Only a hash of it (sealed), by default | Yes, dialed last | Yes |
| Size | M | L | M + M (publisher side + recipient fetcher) |

Five decisions that shape everything below:

1. **The standby is attached and live from the start, and sealed.** Hetzner routes a Floating IP to a server alongside its primary address, so no swap is needed at failure time; the only event is telling recipients. The pack carries a signed *hash* of the standby address. The reveal is a 16-byte key that needs no signature of its own, because the pack already committed to it. That key fits one AAAA record or 26 typed characters, which fixes the "a signed hint is 84 bytes" problem from the blackout plan (claim 23) for this one case.
2. **The CDN route is in the pack from day one and is tried last.** Its whole value is working with no fetch when the address is swept. ECH keeps the zone name off the wire, so a censor holding a pack cannot block it by SNI; without ECH it can, and the UI says which state the zone is in.
3. **The Google channel is a freshness mirror, updated by a plain HTTPS POST with a write key, not by OAuth.** "Sign in with Google" is used once, to create and deploy the script, and the token is then thrown away. The manual copy-the-script path produces the identical deployment. No long-lived Google credential sits on the phone.
4. **The Cloudflare Worker is dropped.** The existing path-rewrite Worker adds two token permissions and an upload format nobody has verified, and buys nothing the WebSocket path does not already give. The token shrinks to five zone-scoped permissions on one zone.
5. **Daal never spends money through the Cloudflare API.** Cloudflare can now register domains by API (beta since 15 Apr 2026), but that means holding a token that bills the publisher's card. The publisher buys the domain in the dashboard.

## 1. Add-on 1: Standby IP

### 1.1 What it gives recipients, and when

- **Rescues:** the relay's single address being null-routed. That is the common death: REALITY addresses on MCI are reported burning in 2–7 days (`research/intel-and-some-working-methods.md`, "Protocol status").
- **Does not rescue:** a Hetzner range or ASN sweep (the standby is a Hetzner address too; Hetzner is described as graylisted), an SNI block on the cover name (same name), a protocol block, any allowlist or blackout phase.
- **Honest framing for the UI:** a spare tyre. If the first address was burned by traffic heuristics, the standby will burn the same way some days later. It buys days and a recovery that needs no hosting company to be reachable, for €3 a month.

### 1.2 Mechanism

- At setup Daal creates one Floating IPv4 in the relay's home location, assigns it to the server, and binds it on the box. The box then answers on both addresses on the same ports with the same keys. Nothing advertises the second one.
- Each route's signed `family_specific_config` gains a reserved `_standby` member, next to `_endpoint`:
  - sealed (default): `{"v":1,"mode":"sealed","commit":"<base64 SHA-256>"}` where `commit = SHA-256("daal/standby-v1" ‖ salt ‖ ipv4)`, salt 12 random bytes.
  - open: `{"v":1,"mode":"open","server":"203.0.113.20"}`.
- **Standby key** = `salt ‖ ipv4` = 16 bytes. Shown as 26 base32 characters in five groups. It is not a secret once used; it is only an address. A forged key cannot match the signed commit, so it can steer nobody anywhere.
- The endpoint rule ("refuse an outbound whose server differs from the signed commitment") becomes: the server must equal `_endpoint.server`, **or** equal the open standby, **or** be the address inside a standby key that matches the sealed commit. Port, name and server-authentication material never change. Nothing signed is relaxed.
- `_standby` holds an address in open mode, so it is **not** added to `EngineFamilyConfigKeys` (`bundle/go/bundle/family_config.go`); it stays with the stored endpoint in the encrypted half of the store.

**When the address is revealed.**

| Mode | Reveal | Good for | Weakness |
|---|---|---|---|
| Sealed (default; forced when an Everyone file exists) | After the primary dies: the publisher taps "Switch to standby". Daal re-signs with the standby as the endpoint and publishes through freshness, and shows the 26-character key to send by any means | Any pack that may reach a censor | Needs one carrier or one human message to get through |
| Open (offered only when every file is for a named person) | Never needed: recipients already hold it | A family circle of a few trusted people | A censor holding a pack blocks both addresses on day one |

Recommendation: sealed by default. The publisher abroad still cannot see an Iran-side block (the detection gap in the blackout plan stands), so in sealed mode recovery starts when a recipient says "it died" or the health panel shows handshakes stopping.

### 1.3 Publisher flow (phone)

Relay page → **Add-ons** → Standby address.

1. Card: "A second address for this relay, kept back. If the first one is blocked, people switch to this one. €3.00 a month plus tax, charged by Hetzner to the account you already use. Adds nothing new about you." Button: Rent standby.
2. Confirm sheet with the monthly price read live from the Hetzner pricing API (`pricing_lookup` exists) and "Stops when you remove it or delete the relay."
3. Progress: renting → attaching → checking it answers (the mgmt TLS pin is checked over the new address) → signing. Any failure rolls back and releases the address (`ReleaseFloatingIP` deletes only what Daal created).
4. Result: "Standby ready. Files you make from now on can use it. People who already have a file get it the next time their app refreshes; nobody needs a new file." (The new signed skeleton goes out by the normal freshness publish; the merge keeps credentials.)
5. When the primary dies: relay page shows **Switch to standby**. One tap: re-sign with endpoint = standby, publish, show the 26-character key with Copy and Share. Then offer "Rent a new standby (€3.00/month)". The burned primary costs nothing extra and cannot be released without deleting the server.

### 1.4 What Daal provisions

- Hetzner Cloud API, the token already pasted, no new permission: `POST /v1/floating_ips` (`type: ipv4`, `home_location`, ownership labels), `POST /v1/floating_ips/{id}/actions/assign`, read back, and `DELETE` on removal. All four calls exist in `publisher/deploy/providers/hetzner/floating_ip.go`.
- On the box: the mgmt address verb binds the extra address and persists it (`cmd/daal-relay-mgmt/address.go` already does this for L3). The change: bind **without** making it the advertised address.
- No cloud-init change, so it works on relays already running, if their pinned relay binary has the address verb.

### 1.5 Recipient ladder

Position 3 in the combined order (section 4). Rules:

- Open mode: a route whose attempt failed in an address-shaped way (TCP connect timeout, refined `address_blocked`, or unanswered at the hello on every TCP route of that relay) gets one **address variant**: the same outbound with `server` swapped to the standby. It runs before any refresh fetch. A name-shaped stop (reset at the hello, `name_blocked`) does not trigger it; the cover-name ladder runs instead.
- Sealed mode: no dial until a key or a new signed pack arrives through the C0 walk, a typed key, or a file.
- A standby that carried is remembered per network like any other variant. One that failed is marked blocked for 72 h like any other variant.
- Budget: the address variant counts against the existing per-pass and per-hour side-probe limits in `connect_ladder.go`.

### 1.6 Teardown and billing

- Billed by Hetzner per hour up to the monthly cap, assigned or not, until deleted.
- "Remove standby": re-sign **without** `_standby` and publish first, then unbind on the box, then delete the Floating IP. Order matters: a released address goes back to Hetzner's pool and a stale commit would send recipients to a stranger's server (the handshake fails for every key-pinned family, but shadowsocks is weaker; see 1.7).
- Relay delete releases it with everything else (`ReleaseRelayAddresses`). The account check sheet lists it as a billed item.

### 1.7 Risks and identity

- Identity: none new.
- A censor holding an open-mode pack burns both addresses at once. Hence the default.
- A stale `_standby` after the address is released (publisher removed it but a recipient never refreshed): the recipient may dial a stranger. REALITY, pinned TLS and naive fail closed. Shadowsocks has no independent server authentication; mitigation: the address variant is never offered for shadowsocks routes.
- Hetzner's per-project Floating IP limit on new accounts is undocumented. **GATE S-1:** read the limit on the real account; on `resource_limit_exceeded` say "Hetzner has not allowed this account a second address yet" with the support link.
- Promotion time is still unmeasured (blackout plan W3-10). With the address pre-attached there is no provider call on the critical path, only sign + publish.

### 1.8 Work items

| ID | What | Files | Size |
|---|---|---|---|
| S1 | `_standby` type, parser, commit and key functions, test vectors; spec text | `bundle/go/bundle/standby.go` (new), `specs/relaypack-v1.md` | S |
| S2 | Importer and guard accept a standby server; store the key when one arrives; refuse for shadowsocks | `bundle/go/importer/endpoint_plan.go`, `core/abi/endpoint_guard.go` | S |
| S3 | Provider: `EnsureStandby` (create + assign + read back, no `PublicIP` change), `PromoteStandby`, `RemoveStandby` | `publisher/deploy/providers/hetzner/standby.go` (new), `publisher/deploy/provider/types.go` (two record fields) | S |
| S4 | Box: bind an extra address without adopting it | `cmd/daal-relay-mgmt/address.go` | S |
| S5 | Binder writes `_standby` into every route; CLI verbs `standby add / promote / remove` | `publisher/deploy/relaypack/endpoint.go`, `publisher/deploy/cli/cli_addon_standby.go` (new) | S |
| S6 | Wizard: add-on row, commands, rollback journal entry | `client-shell/tauri/daal-wizard/src/addon_standby.rs` (new) | S |
| S7 | Engine: address variant in the ladder; typed-key verb `engine_standby_key(pack, key)` | `core/abi/connect_ladder.go`, `core/abi/standby.go` (new) | M |
| S8 | UI: add-on card, switch sheet, key display; recipient "I was sent a code" field | `client-ui/src/publisher/addons/StandbyCard.tsx` (new), recipient import screen | S |

**Tests.**
- Worldbox, mocks only (fakecloud already serves the Floating IP API and routes pool addresses): new op `standby-open` on `relay-ip-block.json` started *while connected*: expect recovery with zero fetches. New op `standby-sealed`: block the address, expect no dial; inject the key; expect recovery. New op `standby-stale`: release the address, expect the variant to fail closed.
- Unit: commit/key vectors; guard refuses a key that does not match; shadowsocks refusal.
- Real account (owner approves the spend; reading is fine, renting is not): one rent → attach → mgmt pin check over the standby → promote → remove on the test relay; GATE S-1. Sony phone: block the primary with a local firewall rule and watch the open-mode switch.

## 2. Add-on 2: CDN front (Cloudflare)

### 2.1 What it gives recipients, and when

- **Rescues:** the relay address being blocked; Hetzner ranges being graylisted or swept while Cloudflare ranges stay open; an SNI filter on the direct route's cover name. With ECH the wire shows only the shared name `cloudflare-ech.com`. Net4people #676 (18 Oct 2026, one author) reports Cloudflare `wss` cut right after the handshake and working only with ECH. That is the only path in the record with evidence close to today.
- **Does not rescue:** SNI *allowlist* phases (#626: Cloudflare addresses open for one name only; `cloudflare-ech.com` is not on such a list); a wholesale Cloudflare block (Irancell did it on 16 Apr 2023); a block of `cloudflare-ech.com` itself (one rule; Russia did it in Nov 2024); a blackout.
- **Counter-evidence to keep in the copy's tone:** one user (June 2026) reports CDN domains blocked within a day. So the zone is a consumable, and the UI calls it "a way in that may stop working", never a guarantee.
- **Speed:** slower than direct. One more hop, and idle WebSockets are closed after about 100 s, so the client sends keepalives.

### 2.2 Mechanism

The four data-path defects listed in the blackout plan (Group B, section 1) are the build. Summary of the fixed design:

- Relay: a dedicated inbound `ws-cdn-in` (VLESS over WebSocket) on its own port, serving the Cloudflare Origin CA certificate and **requiring** Cloudflare's Authenticated Origin Pull client certificate. The Hetzner firewall opens that port to Cloudflare's ranges only.
- Cloudflare: proxied A record for `<label>.<zone>`; SSL mode Full (strict); Origin Rule that overrides the destination port for that hostname; WebSockets on; AOP on; ECH left on.
- Pack: one more route, family `websocket-tls`, exposure `cdn_fronted`, with a new endpoint shape: hostname instead of an address, WebPKI instead of a key pin, plus seed edge addresses and the ECH config.
- No Worker. The WebSocket path is a random 16-byte value, the same for all recipients of the route, rotated by re-signing.

**What goes in the signed endpoint of the CDN route** (`_endpoint` v1 gains optional members; old clients refuse unknown members, which is the safe reading):

```
{"v":1, "server":"<label>.<zone>", "port":443, "server_name":"<label>.<zone>",
 "cdn":"cloudflare", "edge_seeds":["104.16.0.0/13", ...],
 "ech_config":"<base64 ECHConfigList>", "tls_roots_sha256":["..."]}
```

- `edge_seeds`: a few prefixes from Cloudflare's published ranges, fetched by the publisher abroad. Recipients never resolve the hostname through Iranian DNS (it would return 10.10.34.x) and never download a range list.
- `ech_config`: the publisher's app reads the hostname's HTTPS record over DoH from abroad at sign time and at every freshness publish. It is the same for every Cloudflare site, so it identifies nobody. A stale one costs one extra round trip (the server returns retry configs).
- Server authentication is WebPKI for the committed hostname against roots shipped in the app. That is weaker than a key pin in one way, said plainly: Cloudflare terminates TLS, so Cloudflare can read the VLESS header (the recipient's UUID and each destination host:port). Payloads that are themselves TLS stay opaque.

**When the front is revealed.** In the pack from day one. Reasons: its job is zero-fetch recovery; with ECH the name is not on the wire; and passive DNS never sees it because recipients do not resolve it. A censor holding a pack can still (a) block the zone by SNI on networks where ECH fails and the client falls back to a plain hello, (b) report the zone to Cloudflare. Mitigations, in order of cost:

1. Tried last, so the name and the Cloudflare pattern are shown on a network only when the direct routes have failed there.
2. Plain-hello fallback is **off** by default for the CDN route. Order is ECH, then ECH with the outer hello split (`record_fragment` + `fragment`), then stop. A per-pack signed flag turns plain fallback on for publishers who accept the name being seen.
3. Hostname rotation inside the zone through freshness (`RotateHostname` exists) for exact-name blocks.
4. A second zone, bought when the first is burned, delivered as a new signed pack through freshness or the Google channel. Not pre-bought: a sealed reserve domain costs money and still sits in CT logs from the day it activates.

### 2.3 Publisher flow (phone)

Relay page → Add-ons → **Way in through Cloudflare**. Card: "A second way in that hides behind Cloudflare. Needs a web address of your own (about $10 a year) and a free Cloudflare account. Cloudflare will know your email and can see who connects and where they go. Slower than the direct way."

1. **Account.** "Make a free Cloudflare account" opens the sign-up page in the browser. Advice line: use an email used for nothing else.
2. **Domain.** "Buy an address inside Cloudflare (simplest)" opens Cloudflare Registrar. Advice line: any plain name, nothing about you or Daal, `.com` is fine. Second option, collapsed: "I already have one elsewhere" with the nameserver-change steps and "this can take hours".
3. **Token.** "Create the key" opens a pre-filled token page (permissions in 2.5). The publisher picks the one zone, taps Create, copies, returns, pastes. Daal verifies the token, lists the zones it can see, and refuses a token that can do more than needed ("This key can do more than Daal needs. Make it again with the button above.").
4. **Build.** Progress: certificate → relay door → Cloudflare settings → firewall → test from this phone (a real WebSocket handshake through the front, with ECH). Any failure rolls back what it created.
5. **Posture line** on the card afterwards, refreshed on open: "Name hidden: yes / no" (ECH on the zone and accepted in the test), "Only Cloudflare can reach the door: yes / no", and the last test time.
6. Result: "People who already have a file get this way in when their app next refreshes. New files include it."

A relay built before this ships needs a rebuild to gain the inbound (cloud-init has no upgrade path). The card says so and offers the existing rebuild flow.

### 2.4 What Daal provisions, through which API

Cloudflare API v4, bearer token:

| Step | Call | Permission used |
|---|---|---|
| Find zone and account | `GET /zones?name=` | Zone Read |
| Origin certificate for `<zone>` and `*.<zone>` | `POST /certificates` | SSL and Certificates Edit |
| AOP on, fetch client CA | `PATCH /zones/{id}/settings/tls_client_auth` | SSL and Certificates Edit |
| SSL mode strict, WebSockets on, read ECH state | `PATCH /zones/{id}/settings/{ssl,websockets}`, `GET .../settings/ech` | Zone Settings Edit |
| Proxied A record | `POST /zones/{id}/dns_records` | DNS Edit |
| Port override for the hostname | `PUT /zones/{id}/rulesets/phases/http_request_origin/entrypoint` | Origin Rules Edit |

Hetzner API: firewall rule on the relay's own firewall, CDN port from Cloudflare's ranges only. Relay: mgmt verb installs the certificate, key and AOP CA and enables `ws-cdn-in`.

### 2.5 Owner prerequisites

- **Cloudflare account**, free plan, dedicated email, two-factor on.
- **Domain.** Recommendation: **Cloudflare Registrar**. No nameserver step, at-cost price (API samples today show `.com` at $8.57, `.dev` $10.11, `.app` $11.00), registrant data redacted in WHOIS by default. It needs a card and real contact data held by Cloudflare. That is the identity link; a registrar that takes anonymous payment trades it for the nameserver step and a slower setup. For the pilot, Cloudflare Registrar.
- **Can the API register the domain?** Yes since 15 Apr 2026 (Registrar API beta: `GET .../registrar/domain-search`, `POST .../registrar/domain-check`, `POST .../registrar/registrations`; a subset of TLDs; bills the account's default payment method; needs the registration agreement accepted in the dashboard and a default contact). **Do not use it.** A token that can charge the card is not one to keep on a phone, and the dashboard step is three taps.
- **API token: exactly these, Zone resources = the one zone, no account permissions:**
  - Zone — Zone — Read
  - Zone — DNS — Edit
  - Zone — SSL and Certificates — Edit
  - Zone — Zone Settings — Edit
  - Zone — Origin Rules — Edit
- Pre-filled link (user token; Cloudflare silently drops keys it does not recognise, so **GATE C-1** is to confirm the five short keys on the real dashboard): `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=[{"key":"zone","type":"read"},{"key":"dns","type":"edit"},{"key":"ssl_and_certificates","type":"edit"},{"key":"zone_settings","type":"edit"},{"key":"origin_rules","type":"edit"}]&accountId=*&zoneId=all&name=daal` (URL-encoded). The link cannot pre-select one zone; the screen tells the publisher to pick it.
- **ECH.** Cloudflare's page says ECH is available on Free zones and on by default. That settles the blackout plan's open question on paper. **GATE C-2:** read `settings/ech` on the real zone and complete an ECH handshake to it with the engine's uTLS hello.

### 2.6 Teardown and billing

- Cloudflare free plan: no charge. Domain: yearly, auto-renew is the publisher's choice in the dashboard; Daal shows the renewal date if the token can read it and otherwise says "check in Cloudflare".
- "Remove this way in": re-sign without the route and publish; delete the DNS record and origin rule; revoke the origin certificate; close the firewall rule; disable the inbound. The token is deleted from custody. Daal tells the publisher to delete the token in Cloudflare too, and that the domain keeps billing until they cancel it.
- Relay delete does the Cloudflare cleanup first, and reports anything it could not remove, like the address release report does today.

### 2.7 Risks and identity

- **Identity:** email at Cloudflare; card and legal contact at the registrar; the domain's existence in CT logs from activation. Cloudflare knows the origin address, so one legal request or abuse report links zone → relay → Hetzner account.
- **One ban ends it for everyone.** Proxying a VPN through the free plan is against the spirit of Cloudflare's terms for non-HTML content. Treat the account as losable. Never reuse one Cloudflare account across publishers.
- **Cloudflare sees** recipients' addresses, UUIDs and destinations. The direct route shows none of that to a third party. The card says so before purchase.
- **Fingerprint:** sing-box WebSocket forces ALPN `http/1.1`, which a Chrome hello does not send alone. `httpupgrade` has the same tell. Accept it for v1 and record it as known.
- **Old phones** may lack the roots Cloudflare's edge chains to. Ship the small root set in the app and commit its hashes in the endpoint.
- Unknown from here: which Cloudflare prefixes pass per ISP today. The edge picker (C6 below) is what copes with that; it cannot be validated without a vantage inside.

### 2.8 Work items

IDs B-1 to B-8 are the blackout plan's; changes are noted.

| ID | What | Files | Size |
|---|---|---|---|
| B-1 | `ws-cdn-in` inbound, Origin CA cert, AOP required; port entry; mgmt verb to install and enable | `cmd/daal-relay-mgmt/singbox_cdn.go` (new), `publisher/deploy/relayports/relayports.go`, `publisher/deploy/cloudinit/v2.yaml.tmpl` | M |
| B-2 | Firewall: port parameter, the relay's real firewall id, no world-open rule for the CDN port | `publisher/deploy/providers/hetzner/{firewall_cf.go,live_client.go}` | S |
| B-3 | `ProvisionFront` rewritten: strict SSL, origin rule, WebSockets, ECH read, wildcard Origin CA, zone lookup by label walk (replaces `apexOf`); **remove the Worker calls**; token scope check | `publisher/deploy/cloudflare/{provider.go,cf_client.go,cf_client_live.go,cf_client_mock.go}`, delete `worker.go` | M |
| B-4 | CDN endpoint shape and client outbound (edge address as server, hostname SNI and Host, WebPKI with shipped roots, ECH, split flags, keepalive); validator row | `bundle/go/bundle/endpoint.go`, `publisher/deploy/relaypack/{client_outbound.go,candidate_render.go}`, `bundle/go/relaypackvalidate/validator.go` | M |
| B-5 | Publisher-side ECH fetch over DoH; into the endpoint and re-published with freshness | `publisher/deploy/cloudflare/ech.go` (new) | S |
| B-6 | Edge picker: seeds from the endpoint, failure-state probe with a neutral name and a >10-packet exchange, per-network memory | `core/edgepick/` (new), `core/internal/selection/network_memory.go` | M |
| B-6b | Ladder: CDN route last; ECH → ECH+split → stop; plain fallback only with the signed flag | `core/abi/connect_ladder.go`, `core/abi/connect_race.go` | S |
| B-7 | Phone UI: card, three setup steps, posture line, removal | `client-ui/src/publisher/addons/CdnCard.tsx` (new), `client-shell/tauri/daal-wizard/src/addon_cdn.rs` (new; moves the existing `provision_cdn_front` family out of `commands.rs`) | M |
| B-8 | Worldbox CDN edge: TLS-terminating proxy that enforces SNI == Host, speaks ECH with a lab key, requires AOP toward the origin; fake Cloudflare API | `test-rigs/worldbox/driver/{fakecdn.go,fakecf_api.go,ops_cdn.go}` (new), scenarios below | M |

**Tests.**
- Worldbox scenarios (new files): `cdn-relay-ip-block.json` (direct address dead, edge open: CDN route carries), `cdn-sni-block-ech.json` (zone name on a blocklist: carries with ECH, fails without, and the client does not fall back to plain), `cdn-ech-outer-block.json` (`cloudflare-ech.com` blocked: route reported dead, no plain fallback), `cdn-grey-budget.json` (6-packet budget on some edge addresses: picker moves on), `cdn-edge-allowlist.json` (only some prefixes open).
- Censor-lab: reuse `ech-bootstrap-fail.json` to prove the pack-shipped ECH config removes the DNS dependency.
- Mock Cloudflare API covers provisioning, rollback, scope refusal and teardown.
- **Real account needed for:** GATE C-1, GATE C-2, origin-rule port override end to end, AOP actually refusing a non-Cloudflare client, a 30-minute WebSocket soak for the idle close, and whether Cloudflare's free plan interferes with long VLESS-over-WebSocket flows (blackout plan claim 19, still unknown).
- Phones: Sony through the real zone on a normal network; old-root check on the oldest phone available.

## 3. Add-on 3: Google update channel

### 3.1 What it gives recipients, and when

- It carries only the signed note and the credential-less signed pack. It rescues no block on its own. It makes the *recovery* from an address block (and delivery of a new CDN hostname or a standby key) reach people when the ordinary refresh addresses (R2, GitHub Pages) are blocked or SNI-filtered, because Google is the name most often left open.
- **Honest limits from the record:** the Google front broke repeatedly from Iran from mid-April 2026 (#313: one of 28 Google addresses reachable; resets), and on the routes in #676 (Oct 2026) TCP was cut after a few packets. A 3–8 KB fetch is one short exchange, far more likely to fit through than a tunnel, but on a cut route it fails with everything else. In a blackout it does nothing. State after October 2026: unknown.
- Recipients fetch only after a route has died and only with no tunnel up (the C0 walk), so on an ordinary day a recipient's phone never touches the script.

### 3.2 Mechanism

**The script** (about 40 lines, shipped in the app, identical for both setup paths):

- `doGet` returns the stored blob as plain text. A request without the right path token gets a bland page.
- `doPost` accepts `{seq, blob, mac}`, checks `mac = HMAC-SHA256(write_key, seq ‖ blob)` and `seq` greater than the stored one, and stores the blob in Script Properties (chunked; 9 KB per value).
- It uses ContentService, PropertiesService and Utilities only. No `UrlFetchApp`, so Google never sees a fetch to the relay and the script asks for no external-request permission.
- `write_key` is generated by Daal and embedded in the script source at setup; Daal keeps it in device custody. It only prevents vandalism; recipients trust the publisher's signature, never the script.

**The blob** is a small container, `daal-refresh-v1`: the freshness document, the signed credential-less pack inline, and optionally a standby key. Each part authenticates itself. Inlining the pack closes the manual-upload step (C3) for this channel.

**Publishing** an update is one HTTPS POST from the publisher's phone to the `/exec` URL. No Google sign-in, no token. It runs inside the existing freshness publish as one more backend.

**What goes in the pack.** One entry in the signed mirror set (`trust/freshness-mirrors.json`): provider `appsscript`, URL `https://script.google.com/macros/s/<deployment id>/exec?<path token>`. Revealing it early is safe in a way the other two add-ons are not: the URL travels inside TLS to Google, so a censor holding a pack cannot block it separately from Google. What they can do is report the script to Google. A takedown costs the channel, not the relay.

**Recipient fetch** (new code; today's fetcher cannot do it):

1. Connect to a Google front address (system DNS for `www.google.com`, then a short shipped list), SNI `www.google.com`, Chrome-shaped hello, HTTP/2, `:authority script.google.com`, GET the `/exec` path.
2. Follow exactly one redirect, only to `script.googleusercontent.com`, over the same front.
3. Bounded read (64 KB), parse the container, hand the parts to the existing verification.
4. If the fronted attempt fails, one plain attempt with SNI `script.google.com`. Never more than two connections to Google per walk.

### 3.3 Publisher flow (phone)

Relay page → Add-ons → **Update channel through Google**. Card: "When your relay moves, people's apps look here for the new address. Free. Needs a Google account. Use one made only for this, never your own. Google can close it without warning."

**Path A: Sign in with Google (default where available).**

1. "Use a Google account made only for this." Link: make one (opens Google sign-up; the publisher does this themselves, it needs a phone number).
2. One-time switch: "Turn on *Google Apps Script API*" opens `script.google.com/home/usersettings`. Daal cannot do this step; the API refuses until it is on.
3. "Sign in with Google". The Google sheet shows the app name, the "Google hasn't verified this app" warning, and two permissions (manage Apps Script projects; manage deployments). The screen before it shows a picture of the warning and says "Tap Advanced, then Continue".
4. Daal creates the project, uploads the script and manifest, creates a version and a web-app deployment, then **discards the token**.
5. Daal POSTs the current blob and fetches it back the way a recipient would. "Working. People who already have a file learn this address the next time their app refreshes."

**Path B: by hand (always offered; the only path on a phone without Google Play services, and the right one for a publisher who does not want Google to link the account to Daal).**

1. "Copy the script" (Daal has already put the write key in it).
2. "Open Apps Script" → New project → paste over everything → Deploy → New deployment → Web app → Execute as: Me → Who has access: Anyone → Deploy. Shown as six numbered pictures; the editor is awkward on a phone and the screen says so.
3. Paste the web-app address back. Daal checks its shape, POSTs, fetches back, same result line.

Both paths end in the same state: a URL and a write key in custody.

### 3.4 What Daal provisions, through which API

Path A only, Apps Script API v1 with the user's short-lived access token:

- `POST /v1/projects` (scope `script.projects`)
- `PUT /v1/projects/{id}/content` with `Code.gs` and `appsscript.json` containing `"webapp": {"access": "ANYONE_ANONYMOUS", "executeAs": "USER_DEPLOYING"}` (`script.projects`)
- `POST /v1/projects/{id}/versions` (`script.projects`)
- `POST /v1/projects/{id}/deployments` (`script.deployments`)

Everything after that, in both paths, is the plain POST and GET to `/exec`.

### 3.5 Owner prerequisites

- **A dedicated Google account** per publisher. Hard rule in the UI text. It is phone-number bound; that is the identity link.
- **One Google Cloud project, owned by the Daal project (the owner), not by publishers.** In it:
  - Enable **Apps Script API**.
  - OAuth consent screen: user type **External**; app name neutral (it is shown to publishers and logged by Google); scopes `https://www.googleapis.com/auth/script.projects` and `https://www.googleapis.com/auth/script.deployments`.
  - Publishing status **In production, unverified**. Effect: the warning screen, and a cap of 100 users for the life of the project until verified. Enough for a pilot. "Testing" status instead would force the owner to list every publisher's Google address in the project and expires refresh tokens after 7 days; the second does not matter here (no refresh token is kept), the first is a list of publishers in one place, so avoid it.
  - Verification (to lift the cap and the warning) needs a public homepage and privacy policy on a domain the owner proves, and a review. Whether these two scopes are classed "sensitive" could not be confirmed today; assume yes. That is a decision to make only when the project is ready to be publicly tied to a Google developer identity.
- **OAuth clients (two):**
  - **Android** type: package name plus the SHA-1 of the release signing certificate (`release-keys/android-device-signing.jks`). Used through Play services' authorization client, which returns an access token with no secret and no redirect. Google no longer supports custom URI schemes on Android and has deprecated loopback for Android clients, so this is the supported route. A debug-signed build needs its own client or uses Path B.
  - **Desktop app** type: system browser, loopback `http://127.0.0.1:<random port>`, PKCE. The client secret Google issues for this type is not confidential and may ship in the binary.
- The Apps Script API does not work with service accounts, so there is no server-side shortcut; each publisher signs in.
- **GATE G-1:** a web app created and deployed purely through the API, by an owner who never opened the editor, answers anonymous `doGet`/`doPost` while using PropertiesService. If Google demands a one-time authorization for PropertiesService, fall back to a script with the blob embedded in the source; updates then go through the API and Path A must keep a refresh token in custody (and Path B becomes "paste again on every change", which is poor: so settle this gate first).
- **GATE G-2:** fronted fetch (SNI `www.google.com`, authority `script.google.com`, one redirect) returns the blob from outside Iran over HTTP/2 with the engine's hello. Verified with curl for `doGet` on 2026-11-20 in the blackout plan; not yet with this client.

### 3.6 Teardown, billing, risks, identity

- Free. Quotas that matter: 30 simultaneous executions per account, so recipients add 0–120 s of jitter before fetching; no UrlFetch quota is consumed because the script fetches nothing.
- "Remove": re-sign the mirror set without it and publish; POST an empty blob; tell the publisher to delete the project at script.google.com (Daal has no token to do it, by design). Path A can offer "sign in again to delete it".
- **Identity:** Google holds the account's phone number and, for Path A, a record that it authorised the Daal OAuth client. One request to Google for "who authorised this client" lists every Path A publisher. Path B leaves no such record. The blob contains the relay's address, as every mirror does today.
- **Suspension:** using Apps Script this way is outside its intended use. One suspension silences the channel for every recipient of that publisher. Volume here is tiny and looks nothing like the relay tools that draw attention, but the account is losable.
- **Fingerprint:** the TLS hello can match Chrome (metacubex/utls); the HTTP/2 layer will be Go-shaped. Acceptable for one short fetch on failure; it is the reason not to carry data this way.
- **The two-mirror rule.** Daal refuses a mirror set with fewer than two providers (`MinMirrors = 2`). A publisher with only this add-on has one. The stated reason for the rule (a short unique address that is easy to watch and block) does not hold for a fronted Google URL. **Recommendation (owner decision D-3):** allow a single-mirror set when its one provider is `appsscript`, and say in the card that a Google suspension stops updates. The alternative is to require a second refresh address (GitHub or R2) before this add-on counts.

### 3.7 Should it later carry data? No.

- It died from Iran exactly when it was needed (#313, #676), and a sustained POST stream to one Google address is the signature that killed the original tool.
- Free quota is 20,000 fetches a day per account shared by all recipients; messaging apps exhaust it in hours.
- It needs an exit endpoint on the relay on 443 with a hostname, a session/framing layer, and a Chrome-grade HTTP/2 fingerprint Daal does not have. Size L.
- Abuse of the data path gets the account suspended, and the account is the update channel. If it is ever built, it must use a different Google account and script from the update channel.
- Revisit only if the network test (field probe) shows, on two or more ISPs, the Google front carrying where CDN+ECH does not.

### 3.8 Work items

| ID | What | Files | Size |
|---|---|---|---|
| G1 | Script and manifest templates, write-key embedding, container format `daal-refresh-v1`, test vectors | `publisher/deploy/freshness/backends/appsscript/{script.go,Code.gs,appsscript.json,container.go}` (new) | S |
| G2 | Publisher backend: POST update, fetch-back check; Apps Script API client for Path A (create, content, version, deploy) with a mock | `publisher/deploy/freshness/backends/appsscript/{appsscript.go,api.go,api_mock.go}` (new), provider constant in `freshness/mirrors.go` | M |
| G3 | Sign-in: Android authorization client in the platform plugin; desktop loopback + PKCE; both return a one-shot access token to the wizard and nothing is stored | `client-shell/tauri/plugins/daal-platform/android/.../GoogleAuth.kt` (new) + plugin `build.gradle.kts`, `client-shell/tauri/daal-wizard/src/addon_google.rs` (new) | M |
| G4 | Fetcher hardening (blackout plan C1): bounded read, Chrome hello, SNI/authority split, one allowlisted redirect, HTTP/2 by Framer with no `net/http` | `core/bootstrap/front.go`, `core/bootstrap/h2mini.go` (new), small change in `fetcher.go` | M |
| G5 | Recipient side: `appsscript` mirrors go through the front fetcher; parse the container; apply doc, inline pack, standby key; jitter; single-mirror exception if D-3 is accepted | `core/refresh/{relaypack_refresh.go,relaypack.go,frontmirror.go (new)}` | M |
| G6 | UI: card, Path A and Path B screens with pictures, fetch-back result, removal | `client-ui/src/publisher/addons/GoogleCard.tsx` (new) | M |
| G7 | Worldbox fake Google front: one TLS listener for `www.google.com` that routes by authority, serves `/macros/s/<id>/exec` with the redirect to a second authority, and accepts the POST; fake Apps Script API | `test-rigs/worldbox/driver/{fakegfe.go,fakegas_api.go,ops_gfe.go}` (new) | M |

**Tests.**
- Worldbox scenarios (new): `refresh-google-only.json` (address blocked while connected; R2 and GitHub Pages names blocked; `www.google.com` open; `script.google.com` SNI blocked: expect recovery through the front), `refresh-google-rst.json` (Google front reset: expect the walk to end cleanly, no retry storm, at most two connections), `refresh-google-rollback.json` (script serves an older `seq`: refused).
- Unit: container parsing limits; MAC and `seq` check in a JS test of `Code.gs`; redirect allowlist; the opsec grep still passes (no `net/http` in `core/`).
- Mock Apps Script API covers Path A, partial-failure cleanup, and the "API not turned on" error text.
- **Real account needed for:** GATE G-1, GATE G-2, the consent screen wording and the 100-user behaviour, Path B walked on the Sony from start to finish with a stopwatch, and a JA4 capture of the fetch next to Chrome's.

## 4. One ladder for all three

Order the recipient engine follows when a route dies. Positions 1–2 and 5 exist today.

1. The variant remembered as working on this network.
2. Direct routes, with the existing connect ladder for hello-shaped stops (desync presets, signed cover names).
3. **Open standby address** (add-on 1), for address-shaped stops only.
4. **CDN route** (add-on 2): edge pick, ECH, then ECH with split hello.
5. **C0 walk** with the tunnel down: mirrors in random order, the Google mirror (add-on 3) through the front. A result is applied (new endpoint merged, or standby key accepted) and the pass restarts at 1.
6. Human: a 26-character standby key typed in, or an `.sbpx` file.

Why this order: zero-fetch before fetch; a path no third party sees before one Cloudflare sees; the name-revealing path only after the quiet ones failed on this network. When all three add-ons are on, a single address block is handled at 3 or 4 without the publisher doing anything, and 5 delivers whatever the publisher changed.

UI honesty: a connection on 4 is labelled as the slower Cloudflare way in, not plain "connected", and Home says when the app is at 5 ("looking for a new address").

## 5. Shared pieces (build first)

| ID | What | Files | Size |
|---|---|---|---|
| X1 | Add-on ledger: table `relay_addons` (relay, kind, state, provider ids, monthly cost, created), migration, list/remove plumbing, inclusion in relay delete and in the backup | `client-shell/tauri/daal-wizard/migrations/`, `client-shell/tauri/daal-wizard/src/addons.rs` (new), `publisher_backup.rs` | S |
| X2 | Command stubs for all three add-ons registered once (Rust `lib.rs`, TypeScript `wizardCommands.ts`, CLI dispatch in `cli.go`), each returning "not built" | those three files | S |
| X3 | Add-ons section shell on the relay page and at the end of the build wizard, three cards with the cost and "what this ties to you" lines, English and Farsi per `docs/style/farsi.md` | `client-ui/src/publisher/addons/{AddonsSection.tsx,addonText.ts}` (new), `RelayListPage.tsx`, i18n files | S |
| X4 | Endpoint and spec groundwork so later lanes do not collide: `_standby` reserved key, CDN endpoint members, `appsscript` provider, `daal-refresh-v1` | `specs/relaypack-v1.md`, `specs/optional-addons-v1.md` (new) | S |

X2 exists so that the three shared registration files are edited once, by one lane, and every later lane only fills in files it owns.

## 6. Build order and lanes

Rule for the laptop: lanes run scoped `go test ./<their packages>/...` and `vitest` freely; the Android engine build, the Tauri build and a worldbox run are heavy and go through **one queue, one at a time** (6 cargo jobs, niced). Checkpoint the tree with `.git/daal-checkpoint.sh` between waves.

**Wave 0 (one lane, serial, short):** X1–X4.

**Wave 1 (four lanes, disjoint files):**

| Lane | Items | Owns |
|---|---|---|
| L-bundle | S1, S2, B-4 (endpoint part) | `bundle/go/**`, `core/abi/endpoint_guard.go` |
| L-standby-pub | S3, S4, S5, S6 | `providers/hetzner/standby.go`, `cmd/daal-relay-mgmt/address.go`, `relaypack/endpoint.go`, `cli_addon_standby.go`, `addon_standby.rs` |
| L-cdn-server | B-1, B-2, B-3, B-5 | `publisher/deploy/cloudflare/**`, `relayports`, `cloudinit`, `cmd/daal-relay-mgmt/singbox_cdn.go`, `providers/hetzner/{firewall_cf.go,live_client.go}` |
| L-google-pub | G1, G2, G3 | `freshness/backends/appsscript/**`, `GoogleAuth.kt`, `addon_google.rs` |

L-standby-pub and L-cdn-server both sit in `providers/hetzner` and `cmd/daal-relay-mgmt` but in different files. `relaypack/endpoint.go` (standby) and `relaypack/client_outbound.go` (CDN, wave 2) are different files in one package: L-standby-pub must not touch the outbound renderer.

**Wave 2 (four lanes):**

| Lane | Items | Owns |
|---|---|---|
| L-fetch | G4, G5 | `core/bootstrap/**`, `core/refresh/**` |
| L-ladder | S7, B-4 (outbound part), B-6, B-6b | `core/abi/connect_*.go`, `core/abi/standby.go`, `core/edgepick/**`, `relaypack/{client_outbound.go,candidate_render.go}` |
| L-rig | B-8, G7, standby ops, all new scenarios | `test-rigs/worldbox/driver/{fakecdn,fakecf_api,fakegfe,fakegas_api,ops_cdn,ops_gfe,ops_standby}.go`, `test-rigs/worldbox/scenarios/*` |
| L-ui | S8, B-7 (UI part), G6 | `client-ui/src/publisher/addons/**`, `addon_cdn.rs` |

L-fetch status (2026-11-20): G4 and G5 built against a local fake front (`core/bootstrap/{front,h2mini,hpack_tables}.go`, `core/refresh/frontmirror.go`); D-3 enforced in `refresh.ValidateMirrorSet`. The Google mirror is walked last, and only by the direct unscheduled walks. The jitter is bounded by the walk's slack, not by the full 120 s. Still open: wiring `abi.StandbyKeySink` into the refresher, and gate G-2.

L-ladder status (2026-11-20): S7, B-4 (outbound part), B-6 and B-6b built and unit-tested on the stub driver, plus `core/trust` SaveImport keeping `_standby`. `engine_standby_key` (`core/abi/standby{,_export,_gomobile}.go`) and the store hook `abi.StandbyKeySink`. The address variant `a:standby` (`connect_standby.go`) runs on address-shaped stops only, after the direct routes and before the CDN route, also in the engine's own fall-over. The CDN route (`connect_cdn.go`) goes last. Its hello order is ECH, then `h:split`, then `h:plain` only with `plain_fallback`. Its edge is picked in `core/edgepick` (deterministic candidates inside the seeds, a probe under a neutral name with four HTTP round trips, per-network memory) only after the edge in use stops answering. The guard runs again on every moved outbound. The minter (`relaypack/client_pack.go`) mints the wrapped CDN outbound from `ClientConnParams.CDNWSPath` and the shipped roots in `relaypack/cdnroots/`. Still open: the `.so` rebuild for the new export, and gate C-2 for the probe's neutral name.

L-rig status (2026-11-20): B-8, G7 and the standby ops built in `test-rigs/worldbox` (README, "The publisher add-ons"). Stand-ins: `wb fakecf` (Cloudflare API v4 with permission- and zone-scoped tokens, a lab Origin CA, faults, the published ranges, DoH with the lab ECH config), `wb fakecdn` (an edge answering on all of 198.19.8.0/24: SNI == Host, proxied hosts only, the origin rule's port, Full (strict), origin pull with the zone's certificate, real ECH with a lab key), `wb fakegoogle` (a front that routes by authority, Apps Script's 302, Code.gs's rules on the script actually deployed or pasted, the Apps Script API and OAuth). New censor rules `budget` (cut after N client packets), `tls_sni_not` (SNI allowlist) and CIDR `dst`; new probes `ech` and `exchange`. Eleven scenarios (`cdn-*`, `refresh-google-*`) and ten ops (`standby`, `standby-promote`, `standby-sealed`, `standby-open`, `standby-stale`, `standby-google`, `cdn-provision`, `cdn`, `google-channel`, `google-refresh`), run by `./e2e.sh addons` and in `full`. What waits on another lane records one SKIPPED line naming it and starts running by itself when the code is in the tree. Still waiting: the CDN route end to end (no verb opens the relay's door through mgmt `CDNDoorEnable`; `users-pack-sbp` installs only the shipped roots, so a lab edge can never verify).

L-ladder is the one lane with two add-ons in one file (`connect_ladder.go`); keep it a single agent. L-rig writes against the wave-1 interfaces and can start as soon as wave 1's types compile.

**Wave 3 (serial, heavy queue):** full worldbox run of every new scenario; Android build; then the real-account gates in this order: S-1 (cheapest), C-1 and C-2, G-1 and G-2. Then the two-phone checks.

**Shippable order if time runs out:** standby (waves 0–2 without the CDN and Google lanes) is useful alone and smallest. Google channel second: it also gives the standby key and future CDN hostname changes a carrier. CDN last: largest, and the only one that needs a relay rebuild.

## 7. Real accounts versus mocks

| | Mock is enough | Needs the real account |
|---|---|---|
| Standby | Whole flow, rollback, ladder behaviour, stale-commit safety | Account limit (S-1), real routing of a second address, price string |
| CDN | Provisioning sequence, scope refusal, teardown, ladder order, ECH logic against a lab key | Token key names (C-1), ECH on a free zone (C-2), origin rule and AOP end to end, WebSocket idle behaviour, any Cloudflare interference with VLESS-over-WebSocket |
| Google | Script logic, container, front fetch and redirect, Path A call sequence | PropertiesService without authorization (G-1), front routing with our client (G-2), consent screen, Path B on a phone |
| No rig can answer | | Which Cloudflare prefixes and which Google addresses pass per ISP today; whether `cloudflare-ech.com` is blocked in-band; all post-October-2026 state. These need a phone inside. |

## 8. Owner checklist and decisions

To create (the owner does these in a browser; Daal automates none of them):

1. Cloudflare account on a dedicated email, two-factor on.
2. One domain bought at Cloudflare Registrar on that account, plain name.
3. One API token with the five permissions in 2.5, limited to that zone.
4. A dedicated Google account for the test publisher.
5. A Google Cloud project: Apps Script API enabled, consent screen External / In production, the two scopes, one Android client (release package + signing SHA-1), one Desktop client.
6. Approval to rent one Floating IP on the Hetzner test account (€3.00/month, deleted after the test).

To decide:

- **D-1** Standby default sealed, open offered only without an Everyone file. Recommended: yes.
- **D-2** CDN route with no plain-hello fallback unless the publisher turns it on. Recommended: yes.
- **D-3** A single `appsscript` mirror satisfies the two-mirror rule. Recommended: yes, with the suspension warning.
- **D-4** Ship "Sign in with Google" at all, given it records every Path A publisher against one OAuth client and adds Play services' auth library to the Android app. Recommended: yes for the pilot, with Path B always visible and described as the more private one. If G-1 fails, Path A becomes the only path with painless updates and must keep a refresh token in custody; decide again then.
- **D-5** Remove the Cloudflare Worker code. Recommended: yes.

## 9. Sources checked 2026-11-20

- Hetzner Floating IP price €3.00/month excl. VAT (€3.57 incl. 19%), page last changed 2025-11-19; no evidence the 15 Jun 2026 adjustment touched it: https://docs.hetzner.com/cloud/floating-ips/overview , https://docs.hetzner.com/general/others/ipv4-pricing/
- Hetzner Floating IPs must be configured inside the server OS; reassignable within a network zone: https://docs.hetzner.com/cloud/floating-ips/faq/
- Cloudflare API token permission names and scopes: https://developers.cloudflare.com/fundamentals/api/reference/permissions/
- Cloudflare pre-filled token URL (`permissionGroupKeys`; unknown keys silently dropped for user tokens): https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/
- Cloudflare Registrar API beta, 15 Apr 2026 (search, check, register; default payment method; subset of TLDs; redaction default): https://developers.cloudflare.com/registrar/registrar-api/ , https://developers.cloudflare.com/changelog/post/2026-04-15-registrar-api-beta/ , https://blog.cloudflare.com/registrar-api-beta
- Cloudflare ECH: available on Free and on by default there; shared outer name `cloudflare-ech.com`: https://developers.cloudflare.com/ssl/edge-certificates/ech/
- Apps Script API: must be enabled by the user; no service accounts: https://developers.google.com/apps-script/api/concepts ; `deployments.create` scope `script.deployments`: https://developers.google.com/apps-script/api/reference/rest/v1/projects.deployments/create
- Google unverified apps: warning screen and 100-user cap until verified: https://support.google.com/cloud/answer/13464323 ; Apps Script client verification: https://developers.google.com/apps-script/guides/client-verification
- Google OAuth for installed apps: custom URI schemes no longer supported on Android, loopback deprecated for Android clients, loopback + PKCE for desktop: https://developers.google.com/identity/protocols/oauth2/native-app
- Not re-fetched today, taken from `docs/blackout-tier-plan.md` and its sources: net4people #626, #630, #676; MasterHttpRelayVPN-RUST #313; Apps Script quotas; the 7-day refresh-token expiry in Testing status (from my own knowledge of Google's OAuth documentation, not a page fetched today).
- Not confirmed anywhere today: the exact `settings/ech` API path, the sensitivity class of the two Apps Script scopes, Hetzner's per-project Floating IP limit, whether PropertiesService needs an authorization step. Each is a gate above.
