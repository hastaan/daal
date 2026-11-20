# Optional add-ons v1: standby address, CDN front, Google update channel

## Status

Reserved 2026-11-20. Design: `docs/optional-addons-plan.md` (approved by
the owner; its section 0 decisions D-1 to D-5 are taken as recommended).

**Built (Wave 0):** the add-on ledger (§2), the whole command surface as
stubs (§6), the Add-ons section of the publisher UI with every add-on
shown as "in development" (§6.4), and the wire formats reserved in
`specs/relaypack-v1.md`. **Built (Wave 1, L-bundle):** the recipient
side of both pack members — `_standby` (parser, commitment, key text and
DNS forms, import, set-route guard; S1, S2) and the CDN-fronted
commitment `_cdn_endpoint` (format, check, merge, import, guard; B-4
endpoint part) — and the publisher's signing check for both
(`relaypackvalidate.ValidateForSigning`, RP026/RP027). **Not built:**
everything else an add-on does. Every add-on operation answers
`E_NOT_BUILT` until its lane lands (§6.1).

**Compatibility rule for every add-on member (owner's requirement:
families may stay on an older build for a long time).** A pack that
carries add-on data must cost a phone on an older build nothing it had:
its other routes import and the freshness merge still moves them. So
add-on data is carried where older builds ignore it — sibling members
of `family_specific_config` (never inside `_endpoint`, whose strict
decoder refuses the whole pack), and for a route whose outbound older
builds must not see, the outbound wrapped in the profile under
`_daal_cdn_outbound` with no top-level `type`. Signatures cover it all
(`family_specific_config` is inside the signed manifest). Proved by
`bundle/go/importer/compat_old_test.go` against a frozen copy of the
rules of 079ef96 (`bundle/go/importer/internal/oldrules`).

The wire formats are normative in `specs/relaypack-v1.md`:

| Add-on | Section there |
|---|---|
| Standby address | "`_standby` key" |
| Way in through Cloudflare | "The CDN-fronted endpoint" (inside "Endpoint commitment") |
| Google update channel | "Mirror provider `appsscript`" and "The `daal-refresh-v1` container" |

This document holds what is not a wire format: the ledger, the command
surface, the engine call, the recipient order and the open items.

## 1. The three add-ons and the decisions behind them

| | Standby address | Way in through Cloudflare | Google update channel |
|---|---|---|---|
| Kind (ledger) | `standby` | `cdn` | `google` |
| Rescues | one blocked relay address | a blocked address or Hetzner range; an SNI filter on the cover name | nothing alone; carries the fix when the usual refresh addresses are blocked |
| Cost | €3.00/month per relay excl. VAT, billed by Hetzner | a domain, about $10/year; Cloudflare free | free |
| Ties to the publisher | nothing new | Cloudflare account email; card and contact data at the registrar; Cloudflare sees recipients' addresses and destinations | a phone-bound Google account; with Path A, a record at Google that it authorised the Daal client |
| In the pack | a commitment (sealed, default) or the address (open) | yes, tried last | yes, one mirror |

- **D-1** Standby is sealed by default; open is offered only while the
  relay has no Everyone file.
- **D-2** The CDN route never falls back to a plain hello unless the
  signed `plain_fallback` flag is set.
- **D-3** A mirror set whose only provider is `appsscript` satisfies the
  two-mirror rule; the card warns that a Google suspension stops updates.
- **D-4** "Sign in with Google" (Path A) ships for the pilot; the by-hand
  Path B is always visible and described as the more private one.
- **D-5** The Cloudflare Worker code goes. The token is five zone-scoped
  permissions on one zone; Daal never spends money through Cloudflare.

## 2. The ledger

`relay_addons` (daal-wizard migration V019, module `addons.rs`). One
row per add-on Daal created for a relay.

| Column | Meaning |
|---|---|
| `id` | the add-on's id |
| `operator_id` | the relay; `ON DELETE CASCADE` |
| `kind` | `standby` \| `cdn` \| `google` |
| `state` | `building` (started, not finished) \| `ready` (live and in the signed pack) \| `promoted` (standby only: now the relay's advertised address, still billed) \| `removing` (removal started; the pack was already signed without it) |
| `provider_ids_json` | JSON object of string to string: the provider's ids of what Daal created. Never a secret |
| `monthly_cost_cents`, `cost_currency` | what the provider bills per month, as read when made; `0`/`''` = nothing Daal knows of |
| `secret_alias` | device-custody alias of the add-on's own secret, `''` when none |
| `detail_json` | kind-specific, non-secret state, owned by the kind's module |
| `created_at_unix`, `updated_at_unix` | |

Rules:

- At most one row per relay and kind whose state is not `promoted`
  (a partial unique index). A promoted standby is the relay's address
  now; a new standby may be rented beside it.
- The table holds no secret. An add-on's secret is in device custody
  under `secret_alias`; by convention `daal.addon.<id>.<kind>`
  (`addons::secret_alias`). The UI is told only `has_secret`. The
  Cloudflare token already has a home, `daal.cloudflare.<relay id>.token`
  (backed up and wiped today); B-7 either keeps it there and leaves
  `secret_alias` empty, or moves it.
- `addons::forget` deletes the row, then forgets the secret (both
  stores). The order means a failed delete leaves the secret for the
  retry.
- **Backup.** `relay_addons` is an included table of the publisher
  backup and `secret_alias` an alias column, so a new phone gets both the
  rows and the secrets. A backup made before V019 has no such table and
  restores as if it were empty; the table counts in the backup staleness
  digest only once it has rows, so an app update does not make every
  existing backup look out of date (`publisher_backup::LATER_TABLES`).
- **Panic wipe** finds every `secret_alias`
  (`OperatorDb::list_all_keystore_aliases`).
- **Relay delete, cloud path** (`relay_destroy_with`): before the server
  is deleted, each add-on's kind is asked to take it down
  (`on_relay_delete`). One that was taken down is forgotten. One whose
  outcome says `keeps_relay` keeps the relay row, marked decommissioned
  with `retry_needed`, exactly like an address that could not be
  released: the server still goes, and the same call is the retry.
  Every outcome is in `DestroyReport.addons`.
- **Relay delete, local only** ("forget it here"): no provider is asked;
  every add-on is reported `left` (it keeps running and billing), its
  secret is forgotten and its row goes with the relay.

## 3. Standby address

### 3.1 Publisher

Rent (create a Floating IPv4 in the relay's home location, assign it,
bind it on the box without adopting it, check the management pin over
it, sign); roll back on any failure. Switch (sign with the standby as
`_endpoint.server`, publish, show the key). Remove (sign without
`_standby` and publish first, then unbind, then delete the Floating IP).
Hetzner bills per hour up to the monthly cap until the Floating IP is
deleted; `decommission --release-addresses` releases it with the relay
once the record names it (S3).

### 3.2 What is signed

`_standby` on every route of the relay except shadowsocks
(`specs/relaypack-v1.md`), the same object on each; the binder (S5) runs
`relaypackvalidate.ValidateForSigning` (RP027) before signing.

What the recipient keeps (built): the importer passes the signed object
as `importer.RouteInput.Standby` (nil when the route may use none). The
store keeps it at `bundle.StandbyStoreKey(route)` = `standby:<route>`
and removes it — and any key at `bundle.StandbyKeyStoreKey(route)` =
`standby-key:<route>`, 16 raw bytes — when a newer commitment carries
none. **That store write is `core/trust` SaveImport and is not built
yet** (no lane owned it in wave 1); until it is, no standby reaches the
guard and nothing is dialled at one. The set-route guard accepts an
outbound at the committed server, the open standby, or the address of a
held key that matches the commitment; `routeStandbyAddress` in
`core/abi/endpoint_guard.go` is the address S7's variant uses.

### 3.3 Recipient: the address variant

- Open mode: a route whose attempt failed in an address-shaped way (TCP
  connect timeout, refined `address_blocked`, or no answer at the hello
  on every TCP route of the relay) gets one variant — the same outbound
  with `server` replaced by the standby — before any refresh fetch. A
  name-shaped stop (reset at the hello, `name_blocked`) does not trigger
  it; the cover-name ladder runs instead.
- Sealed mode: no standby dial until a matching key is held.
- A variant that carried is remembered per network; one that failed is
  marked blocked for 72 h, like any variant. It counts against the
  existing per-pass and per-hour side-probe limits.

### 3.4 Engine call

```c
int engine_standby_key(const char* relay_pack_id, const char* key, void* out, int out_len);
```

`relay_pack_id` `""` means every held file. Checks `key` (the text
form, `bundle.ParseStandbyKeyText`) against the `_standby.commit` of the
held routes (`Standby.Matches`) and keeps it on every route it matches,
as 16 raw bytes at `bundle.StandbyKeyStoreKey(route)`. Writes JSON to `out` via `copyOut`:
`{"outcome":"accepted|no_match|malformed|no_standby","routes":<n>}`.
Never echoes the key or the address. Returns the number of bytes, or
-1 when the engine is not initialised. Optional symbol: the desktop core
binds it if present (`Engine::standby_key`), and the shell command
`recipient_standby_key` answers "not in this engine library" until it
exists. S7 adds it to `specs/engine-abi-v1.md` with its export.

## 4. Way in through Cloudflare

- Relay: a dedicated inbound `ws-cdn-in` (VLESS over WebSocket) on its
  own port, serving the Cloudflare Origin CA certificate and requiring
  Authenticated Origin Pull; the relay's firewall opens that port to
  Cloudflare's ranges only. A relay built before this needs a rebuild.
- Cloudflare: proxied record `<label>.<zone>`, SSL Full (strict), an
  Origin Rule overriding the destination port for the host name,
  WebSockets on, AOP on, ECH left on. No Worker.
- The token has exactly these permissions on the one zone and nothing
  at account level: Zone Read, DNS Edit, SSL and Certificates Edit, Zone
  Settings Edit, Origin Rules Edit. A token that can do more is refused
  and not stored (`CdnTokenCheck.verdict = too_broad`).
- What is signed: one more `websocket-tls` route, exposure `cdn_fronted`,
  whose commitment is the sibling member `_cdn_endpoint` (no
  `_endpoint`), with `_cdn_attestation` and the RP005/RP006 tags as
  before; a recipient's outbound for it is wrapped in the profile
  (`bundle.WrapCDNOutbound`) and installs the listed roots as
  `tls.certificate` (`specs/relaypack-v1.md`, "The CDN-fronted
  endpoint"). The binder runs `ValidateForSigning` (RP026).
- Removal: sign without the route and publish; delete the record and
  the origin rule; revoke the origin certificate; close the firewall
  rule; disable the inbound; forget the token; tell the publisher to
  delete the token in Cloudflare and that the domain bills until
  cancelled. Relay delete does this before the server goes.

## 5. Google update channel

- The script (shipped in the app, the same for both paths): `doGet`
  returns the stored container as plain text when the request carries
  the right `k`, and a bland page otherwise; `doPost` checks the MAC and
  `seq` (`specs/relaypack-v1.md`, "The `daal-refresh-v1` container") and
  stores the blob in Script Properties, chunked at 9 KB per value. It
  uses ContentService, PropertiesService and Utilities only — no
  `UrlFetchApp`, so it asks for no external-request permission.
- Path A: the user's one-shot access token (scopes
  `https://www.googleapis.com/auth/script.projects` and
  `https://www.googleapis.com/auth/script.deployments`) is used for four
  Apps Script API calls — create project, put content (`Code.gs`,
  `appsscript.json` with `"webapp": {"access": "ANYONE_ANONYMOUS",
  "executeAs": "USER_DEPLOYING"}`), create version, create deployment —
  and dropped. On Android the shell obtains it from the platform plugin
  (`PlatformHandle::google_authorize`) so it never reaches the page; on
  desktop the wizard signs in through the system browser (loopback +
  PKCE). Nothing is stored.
- Path B: the publisher pastes the script (write key already in it),
  deploys it by hand and pastes the web-app address back.
- Both end in the same state: a URL in the signed mirror set and the
  write key in custody. Publishing an update is one more backend of the
  existing freshness publish.
- Removal: sign the mirror set without it and publish; POST an empty
  container; forget the write key; tell the publisher to delete the
  project at script.google.com (Daal holds no token to do it).
- It never carries user traffic (plan §3.7).

## 6. The command surface

### 6.1 Errors and events

- `E_NOT_BUILT: <what> is not built yet` — an add-on operation whose
  code has not landed. Nothing was changed. Not retryable. Rust
  `commands::E_NOT_BUILT` / `addons::not_built`; TypeScript
  `classifyPublisherError` → `'E_NOT_BUILT'`.
- `daal-deploy` add-on verbs exit **8** with a first stderr line starting
  `E_NOT_BUILT:` until built. Never exit 2: the app reads exit 2 with
  "unknown subcommand" as "this helper is older than the app".
- Steps stream on the Tauri event `wizard://addon-progress` as
  `AddonProgress {operator_id, kind, step, state: running|ok|failed,
  detail}` (`onAddonProgress` in TypeScript). `detail` is provider or
  relay text and never a token.

### 6.2 Tauri commands

Every add-on command takes one argument `input` (an object whose type
is defined in the add-on's own Rust module and mirrored in
`client-ui/src/publisher/addons/addonTypes.ts`) and returns one value.
The shell passes them through whole, so a lane changes its types and its
module and never `src-tauri/src/lib.rs`. All run on the blocking pool.

| Tauri command | Rust (daal-wizard) | TypeScript | Lane |
|---|---|---|---|
| `wizard_addons_list(operatorId)` | `addons::list` | `Addons.list` | built |
| `wizard_addon_remove(addonId)` | `addons::remove` → the kind's `remove` | `Addons.remove` | built (dispatch) |
| `wizard_addon_standby_price(input)` | `addon_standby::price` | `Addons.standbyPrice` | L-standby-pub (S6) |
| `wizard_addon_standby_add(input)` | `addon_standby::add` | `Addons.standbyAdd` | L-standby-pub (S6) |
| `wizard_addon_standby_promote(input)` | `addon_standby::promote` | `Addons.standbyPromote` | L-standby-pub (S6) |
| `wizard_addon_standby_key(input)` | `addon_standby::key` | `Addons.standbyKey` | L-standby-pub (S6) |
| `wizard_addon_cdn_set_token(input)` | `addon_cdn::set_token` | `Addons.cdnSetToken` | L-ui (B-7) |
| `wizard_addon_cdn_build(input)` | `addon_cdn::build` | `Addons.cdnBuild` | L-ui (B-7) |
| `wizard_addon_cdn_posture(input)` | `addon_cdn::posture` | `Addons.cdnPosture` | L-ui (B-7) |
| `wizard_addon_cdn_set_plain_fallback(input)` | `addon_cdn::set_plain_fallback` | `Addons.cdnSetPlainFallback` | L-ui (B-7) |
| `wizard_addon_google_script(input)` | `addon_google::script` | `Addons.googleScript` | L-google-pub (G3) |
| `wizard_addon_google_sign_in(input)` | `addon_google::sign_in` (+ `PlatformHandle::google_authorize`) | `Addons.googleSignIn` | L-google-pub (G3) |
| `wizard_addon_google_attach(input)` | `addon_google::attach` | `Addons.googleAttach` | L-google-pub (G3) |
| `wizard_addon_google_check(input)` | `addon_google::check` | `Addons.googleCheck` | L-google-pub (G3) |
| `recipient_standby_key(relayPackId, key)` | daal-desktop-core `commands::standby_key` → `Engine::standby_key` → `engine_standby_key` | `enterStandbyKey` (`client-ui/src/lib/standbyKey.ts`) | L-ladder (S7) for the export; L-ui (S8) for the field |

Relay delete calls each kind's `on_relay_delete(ctx, row) -> AddonOutcome`
(`addon_standby`, `addon_cdn`, `addon_google`); the stubs answer
`not_built` with `keeps_relay`.

The older FRP-8 commands (`wizard_store_cloudflare_token`,
`wizard_provision_cdn_front`, `wizard_list_cdn_fronts`,
`wizard_verify_cdn_posture`) stay until B-7 retires them.

### 6.3 `daal-deploy` verbs

Driven from the wizard through the generic `CliRunner::run_addon`
(`cli_bridge.rs`): argv verb first, secrets as 0600 temp files named by
a flag (`AddonCliRequest.secret_files`) or on stdin, `--progress-json`
lines on stderr forwarded as progress, stdout returned and wiped when
dropped. `MockRunner.addon_reply` answers it in tests. No add-on lane
adds a `CliRunner` method.

| Verb | File | Lane |
|---|---|---|
| `standby price \| add \| promote \| remove` | `publisher/deploy/cli/cli_addon_standby.go` | L-standby-pub (S5) |
| `cdn-token-check`, `cdn-test`, `cdn-posture`, `cdn-remove` | `publisher/deploy/cli/cli_addon_cdn.go` | L-cdn-server (B-3) |
| `cdn-provision` (existing, rewritten in place) | `publisher/deploy/cli/cli.go` → `cloudflare.ProvisionFront` | L-cdn-server (B-3) |
| `appsscript-script`, `appsscript-deploy`, `appsscript-check`, `appsscript-clear` | `publisher/deploy/cli/cli_addon_google.go` | L-google-pub (G1/G2) |

Publishing to the Google channel is not a verb: it is one more backend
of `publish-freshness`.

### 6.4 The UI shell

`client-ui/src/publisher/addons/` (owned by L-ui from wave 2):
`AddonsSection.tsx` — a folded card on the relay page (below People) and
at the end of the build wizard; one block per add-on with what it helps
with, its cost and what it ties to the publisher; off by default.
`addonText.ts` — the copy keys (`pub.addons.*`, English and Persian in
`client-shared/i18n/d2-extra.*.json`) and `ADDON_BUILT`, which keeps a
block "in development" (switch off and disabled) until its lane sets it
true. The setup sheets (`StandbyCard.tsx`, `CdnCard.tsx`,
`GoogleCard.tsx`) are the lanes' to add.

## 7. One order on the recipient

When a route dies (plan §4): 1 the variant remembered as working on this
network; 2 direct routes with the existing connect ladder; 3 the open
standby, for address-shaped stops only; 4 the CDN route (edge pick, ECH,
ECH with a split hello); 5 the refresh walk with the tunnel down, the
`appsscript` mirror through the Google front among the mirrors — a
result is applied and the pass restarts at 1; 6 a person: a typed
standby key or a file. A connection on 4 is shown as the slower
Cloudflare way in, and Home says when the app is at 5.

## 8. Open items

- **CDN compatibility — settled (wave 1).** The CDN commitment is the
  sibling `_cdn_endpoint` and the outbound is wrapped, so builds before
  it skip that one route ("not offered") and keep the rest of the pack
  and the freshness merge. A `_cdn_endpoint` this build cannot read
  costs that route (`needs_newer_app`), not the pack. The import screen
  has no Persian/English line for `needs_newer_app` yet (it falls back
  to the generic sentence): L-ui.
- **Standby store write.** `core/trust` SaveImport must write
  `RouteInput.Standby` to `standby:<route>` (and delete it and
  `standby-key:<route>` when nil), atomically with the commitment. No
  lane owns `core/trust` in wave 1.
- **Signing check wiring.** The binder (`relaypack/binder.go`) must call
  `relaypackvalidate.ValidateForSigning` after `Validate`; the minter
  (`relaypack/client_pack.go` RewriteProfilesForRecipient) must render a
  `cdn_fronted` route through `bundle.ParseCDNEndpoint` →
  `bundle.CheckCDNOutbound` → `bundle.WrapCDNOutbound` instead of the
  `_endpoint` path (today it marks such a route unavailable).
- **The freshness endpoint table** (`daal-wizard/src/freshness.rs`,
  V013) accepts only `r2` and `ghpages`. The Google channel needs an
  `appsscript` kind there and its write key passed to
  `publish-freshness`. No lane owns that file in the plan; L-google-pub
  should, in wave 1.
- **The account check** lists the standby Floating IP as a billed item
  (plan §1.6); `setup_recovery.rs` is not in any lane's list. L-standby-pub.
- **The relay delete sheet** does not yet show `DestroyReport.addons`.
  L-ui.
- **Real-account gates**, in order: S-1 (Floating IP limit on the
  account), C-1 (token permission keys), C-2 (ECH on a free zone), G-1
  (PropertiesService without an authorization step), G-2 (fronted fetch
  with the engine's hello).
