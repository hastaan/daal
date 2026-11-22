# Optional add-ons v1: standby address, CDN front, Google update channel

## Status

Reserved 2026-11-20. Design: `docs/optional-addons-plan.md` (approved by
the owner; its section 0 decisions D-1 to D-5 are taken as recommended).

**Built (2026-11-20, waves 0–2 and the integration pass): all three
add-ons, end to end against the lab's stand-ins.**

- Shared: the add-on ledger (§2), the command surface (§6), the Add-ons
  section of the publisher UI with the three setup cards (§6.4), the
  wire formats in `specs/relaypack-v1.md`, and the publisher's signing
  check (`relaypackvalidate.ValidateForSigning`, RP026/RP027).
- Standby address: provider, box, binder, verbs, wizard, card (S1–S6,
  S8); the recipient's store write (`core/trust` SaveImport), address
  variant and `engine_standby_key` (S7); a standby key carried by the
  Google channel is kept by the refresh walk (`abi.StandbyKeySink`) and
  counts as a new address for the route.
- Way in through Cloudflare: the relay's door (`ws-cdn-in`, mgmt
  `POST /cdn`, which also opens the box firewall), Cloudflare and the
  provider firewall (`cdn-provision`), the door verb (`cdn-door`),
  posture, test and removal, the signed route (the binder reads the
  record's `cdn_front` member), the minted outbound, the edge picker and
  the ladder (B-1 to B-8).
- Google update channel: script, container, Path A and B, the
  `appsscript` mirror in `publish-freshness`, the recipient's front
  fetcher and container walk (G1–G7). Since 2026-11-22 one script per
  Google account with a slot per relay (§5).

**Not built:** nothing an add-on needs answers `E_NOT_BUILT` any more
(the mechanism stays, §6.1). What is still open is in §8: the
real-account gates, which no lab can answer, and a few edges.

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
| Ties to the publisher | nothing new | Cloudflare account email; card and contact data at the registrar; Cloudflare sees recipients' addresses and destinations | a phone-bound Google account (one script for all of the publisher's relays); with Path A, a record at Google that it authorised the Daal client |
| In the pack | a commitment (sealed, default) or the address (open) | yes, tried last | yes, one mirror |

- **D-1** Standby is sealed by default; open is offered only while the
  relay has no Everyone file.
- **D-2** The CDN route never falls back to a plain hello unless the
  signed `plain_fallback` flag is set.
- **D-3** A mirror set whose only provider is `appsscript` satisfies the
  two-mirror rule; the card warns that a Google suspension stops updates.
- **D-4** "Sign in with Google" (Path A) ships for the pilot; the by-hand
  Path B is always visible and described as the more private one.
  Amended 2026-11-22: until the OAuth clients exist, Path A is hidden
  completely and Path B is the only way, at account level (§5).
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
none. That store write is `core/trust` SaveImport (built). Both
secrets are the route's and go with it on a hard delete
(`routestore.perRouteSecretKeys`). The set-route guard accepts an
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
exists. It is in the ledger of `specs/engine-abi-v1.md` (release
surface 70).

A key also arrives without a person: a `daal-refresh-v1` container from
the Google channel may carry one (`standby_key`), and the engine's
refresher hands it to the same store write (`abi.StandbyKeySink`,
`refresh.RelayPackRefresher.StandbyKeys`; never called with `Core.mu`
held). A walk whose key was kept reports `updated`, like a walk that
applied a new pack, and the route is checked again. The publisher's
container builder reads the key the way the engine does
(`bundle.ParseStandbyKeyText`: the grouped form `standby promote`
prints, any case, `-` or spaces) and carries the one canonical form.

## 4. Way in through Cloudflare

- Relay: a dedicated inbound `ws-cdn-in` (VLESS over WebSocket) on its
  own port, serving the Cloudflare Origin CA certificate and requiring
  Authenticated Origin Pull. Both firewalls open that port to
  Cloudflare's ranges only: the provider firewall by `cdn-provision`
  (the relay's own firewall, by id or by its name
  `daal-relay-<server id>`), the box firewall (ufw) by the door itself
  when it is opened (`daal-relay-mgmt` `POST /cdn` with `edge_ranges`,
  `specs/daal-relay-mgmt-v1.md`), and both close again on removal.
  **Building a relay contacts nobody but the hosting company**: the app
  passes no `--cdn-edge-ranges` to `provision`, so no relay needs
  Cloudflare's list at first boot and none needs a rebuild to take the
  add-on later. A relay whose management binary predates the door (no
  `cdn` capability; relay releases before relay-v1.6.0) needs a rebuild
  (`cdn-door` exit 3, `E_CDN_NEEDS_REBUILD`). The door opens only once
  the relay has at least one person on it (sing-box refuses an inbound
  with no users).
- The order the app runs: `cdn-token-check` (the token is kept only
  when it is exactly right), `cdn-provision` (Cloudflare, then the
  provider firewall; a firewall failure takes the Cloudflare side down
  again), `cdn-door --action enable`, `cdn-test` (a real handshake
  through the edge, with ECH), then the signature with the route in it.
  Any failure after `cdn-provision` closes the door and runs
  `cdn-remove`.
- Cloudflare: proxied record `<label>.<zone>`, SSL Full (strict), an
  Origin Rule overriding the destination port for the host name,
  WebSockets on, AOP on, ECH left on. No Worker.
- The token Daal asks for has exactly these permissions on the one zone
  and nothing at account level: Zone Read, DNS Edit, SSL and
  Certificates Edit, Zone Settings Edit, Origin Rules Edit. Only a token
  that does not work, sees no zone or lacks one of the five is refused
  (`missing_permission` names what is missing). A token that can do more
  is kept with a warning naming the extra (`ok_broad`); one that sees
  several zones asks which one (`pick_zone`), and the zone picked is the
  one checked and used (2026-11-22, the owner: "it should reject if it
  is restricted, not broad").
- What is signed: one more `websocket-tls` route, exposure `cdn_fronted`,
  whose commitment is the sibling member `_cdn_endpoint` (no
  `_endpoint`), with `_cdn_attestation` and the RP005/RP006 tags as
  before; a recipient's outbound for it is wrapped in the profile
  (`bundle.WrapCDNOutbound`) and installs the listed roots as
  `tls.certificate` (`specs/relaypack-v1.md`, "The CDN-fronted
  endpoint"). The binder runs `ValidateForSigning` (RP026).
- Where the signature gets it: while the way in is live the operator
  record carries `cdn_front` (the front record `cdn-provision` printed,
  plus the signed `plain_fallback` flag). `bind-and-sign` reads that
  member when no `--cdn-front` is given; the edge seeds are the widest
  of the Cloudflare ranges `cdn-provision` read (`FrontRecord.edge_ranges`,
  v4 first, at most 8; `cloudflare.EdgeSeedsFromRanges`), the roots are
  the ones the app ships (`relaypack.CDNShippedRootDigests`).
  `--cdn-edge-seeds`, `--cdn-roots-file` and `--cdn-plain-fallback`
  override. The minter takes the door's WebSocket path from the creds
  file's `cdn_ws_path` (the app copies `cdn_front.origin_path` into it)
  or `users-pack-sbp[x] --cdn-front`, and installs the shipped roots, or
  the bundle `--cdn-roots-file` names (the lab's edge CA).
- Removal: sign without the route and publish; close the door
  (`cdn-door --action disable`: the inbound, its files and the box
  firewall rules); delete the record and the origin rule; revoke the
  origin certificate; close the provider firewall rule (`cdn-remove`);
  forget the token; tell the publisher to delete the token in Cloudflare
  and that the domain bills until cancelled. Relay delete does the
  Cloudflare part before the server goes (the door goes with the
  server). `cdn-remove` closes the door itself when given the relay's
  record, key and helper address (the CLI's one-verb removal).

## 5. Google update channel

Amended 2026-11-22 (owner, on a real phone: "it just works like a
toggle and nothing else"): **Google is an account, like Cloudflare.**
One script per Google account serves every relay of the publisher, each
in its own slot (protocol `daal-refresh-v2`, `specs/relaypack-v1.md`).
The first build's one-script-per-relay shape was never deployed for
real and is gone everywhere (publisher, recipient, lab).

- The script (shipped in the app, the same for every path and relay):
  `doGet` returns a slot's container as plain text when the request
  carries `?s=<slot>&k=<the slot's read token>`, and `Nothing here.`
  otherwise (wrong key, unknown or never-written slot); `doPost` checks
  the MAC (it covers the slot, `seq` and the blob) and that `seq` is
  greater than the slot's stored one, and stores the blob in that
  slot's Script Properties, chunked at 9 KB per value, other slots
  untouched. The read token is derived from the account's write key and
  the slot, so the script keeps no list. It uses ContentService,
  PropertiesService and Utilities only — no `UrlFetchApp`, so it asks
  for no external-request permission. Script Properties hold about
  500 KB in all, which bounds how many relays one account carries; a
  refused write answers `full`.
- **Accounts → Google** (`addon_google::account_*`): copy the script (the
  account's write key is already in it; made on the first copy, the same
  on every later one), open the Apps Script editor, paste, deploy as a
  web app (Execute as: Me; Who has access: Anyone), paste the `/exec`
  address back. Daal writes a container with a fresh nonce to the test
  slot `connectTest` and reads it back through the Google front, the way
  recipients fetch (`appsscript-account-check`). Only then is the
  account connected («✓ وصل است»). The write key is in custody under
  `daal.google.account.write_key` and the address beside it under
  `daal.google.account.url`; the publisher backup carries both
  (`publisher_backup::account_aliases`). Disconnect forgets them and
  says that the script stays in Google until the publisher deletes it.
- **Sign in with Google** (Path A) is the same account step done through
  the Apps Script API: the user's one-shot access token (scopes
  `https://www.googleapis.com/auth/script.projects` and
  `https://www.googleapis.com/auth/script.deployments`) is used for four
  calls — create project, put content (`Code.gs`, `appsscript.json` with
  `"webapp": {"access": "ANYONE_ANONYMOUS", "executeAs":
  "USER_DEPLOYING"}`), create version, create deployment — and dropped;
  then the same connect check. On Android the shell obtains the token
  from the platform plugin (`PlatformHandle::google_authorize`) so it
  never reaches the page; on desktop the wizard signs in through the
  system browser (loopback + PKCE). Nothing is stored. **It is hidden
  completely** unless the build has the OAuth clients
  (`DAAL_GOOGLE_ANDROID_CLIENT_ID`, `DAAL_GOOGLE_DESKTOP_CLIENT_ID` /
  `_SECRET`): `GoogleAccount.sign_in` is false and the sheet shows no
  trace of it. Tested against mocks only.
- **A relay's switch** (relay page «محافظت بیشتر», and the wizard's
  extras step) works only with the account connected; otherwise it opens
  the Accounts Google sheet and carries on once connected. On
  (`addon_google::turn_on`): a random slot, the relay's copy of the
  account key under its row's alias (as a relay copies the Cloudflare
  account key, so a disconnected account leaves the relays that use it
  working and removable), the slot's address registered as the relay's
  `appsscript` freshness mirror, the first update (the last signed
  document, or the slot's empty container) sent and read back; then
  «روشن». A failed send or read-back takes the mirror out again and
  leaves the row `building`; turning it on again is the retry and keeps
  the slot. No per-relay step happens in Google.
- Off (`addon_google::remove`): sign the mirror set without it and
  publish; clear the slot (its empty container); forget the row and the
  relay's copy of the key. The account and its script stay.
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
| `wizard_addon_standby_price(input)` | `addon_standby::price` | `Addons.standbyPrice` | built (S6) |
| `wizard_addon_standby_add(input)` | `addon_standby::add` | `Addons.standbyAdd` | built (S6) |
| `wizard_addon_standby_promote(input)` | `addon_standby::promote` | `Addons.standbyPromote` | built (S6) |
| `wizard_addon_standby_key(input)` | `addon_standby::key` | `Addons.standbyKey` | built (S6) |
| `wizard_addon_cdn_set_token(input)` | `addon_cdn::set_token` | `Addons.cdnSetToken` | built (B-7) |
| `wizard_addon_cdn_build(input)` | `addon_cdn::build` | `Addons.cdnBuild` | built (B-7) |
| `wizard_addon_cdn_posture(input)` | `addon_cdn::posture` | `Addons.cdnPosture` | built (B-7) |
| `wizard_addon_cdn_set_plain_fallback(input)` | `addon_cdn::set_plain_fallback` | `Addons.cdnSetPlainFallback` | built (B-7) |
| `wizard_google_account()` | `addon_google::account` (+ `PlatformHandle::google_sign_in_configured`, `addon_google::desktop_sign_in_configured` for `sign_in`) | `Addons.googleAccount` | built (2026-11-22) |
| `wizard_google_account_script()` | `addon_google::account_script` | `Addons.googleAccountScript` | built (2026-11-22) |
| `wizard_google_account_attach(input)` | `addon_google::account_attach` | `Addons.googleAccountAttach` | built (2026-11-22) |
| `wizard_google_account_sign_in()` | `addon_google::account_sign_in` (+ `PlatformHandle::google_authorize`) | `Addons.googleAccountSignIn` | built, hidden without OAuth clients |
| `wizard_google_account_disconnect()` | `addon_google::account_disconnect` | `Addons.googleAccountDisconnect` | built (2026-11-22) |
| `wizard_addon_google_on(input)` | `addon_google::turn_on` | `Addons.googleOn` | built (2026-11-22) |
| `wizard_addon_google_check(input)` | `addon_google::check` | `Addons.googleCheck` | built (G3) |
| `recipient_standby_key(relayPackId, key)` | daal-desktop-core `commands::standby_key` → `Engine::standby_key` → `engine_standby_key` | `enterStandbyKey` (`client-ui/src/lib/standbyKey.ts`) | built (S7, S8) |

Relay delete calls each kind's `on_relay_delete(ctx, row) -> AddonOutcome`
(`addon_standby`, `addon_cdn`, `addon_google`). `AddonOutcome::not_built`
remains for a kind a build does not know.

The account check's items carry the add-on they are
(`AccountItem.addon`, `monthly_cost_cents`, `cost_currency`; mirrored in
`wizardCommands.ts`), and `FreshnessStatus.google_only` says the only
refresh address is the Google channel (D-3).

The older FRP-8 commands (`wizard_store_cloudflare_token`,
`wizard_provision_cdn_front`, `wizard_list_cdn_fronts`,
`wizard_verify_cdn_posture`) are still registered; retiring them waits.

### 6.3 `daal-deploy` verbs

Driven from the wizard through the generic `CliRunner::run_addon`
(`cli_bridge.rs`): argv verb first, secrets as 0600 temp files named by
a flag (`AddonCliRequest.secret_files`) or on stdin, `--progress-json`
lines on stderr forwarded as progress, stdout returned and wiped when
dropped. A verb that refuses or whose check fails exits **4** with the
JSON that says why on stdout; `run_addon` keeps that stdout at the head
of the failure text (`cli_bridge::ADDON_REFUSED_RC`).
`MockRunner.addon_reply` answers it in tests. No add-on lane adds a
`CliRunner` method.

| Verb | File | Lane |
|---|---|---|
| `standby price \| add \| promote \| remove` | `publisher/deploy/cli/cli_addon_standby.go` | L-standby-pub (S5) |
| `cdn-token-check`, `cdn-test`, `cdn-posture`, `cdn-remove` | `publisher/deploy/cli/cli_addon_cdn.go` | L-cdn-server (B-3) |
| `cdn-door --record-file F --operator-record R --token-file H --action enable\|disable --priv-key - --helper-ip IP` | `publisher/deploy/cli/cli_addon_cdn.go` → `mgmt.CDNDoorEnableWithFW` / `CDNDoorDisableWithFW`; exit 3 = the relay's management has no door | integration |
| `cdn-provision` (existing, rewritten in place) | `publisher/deploy/cli/cli.go` → `cloudflare.ProvisionFront`; `--firewall-id` takes the id or the name | L-cdn-server (B-3) |
| `users-pack-sbp[x] --cdn-front F --cdn-roots-file P` | `publisher/deploy/cli/cli_users_pack.go`: the CDN route's door path and roots for the minter | integration |
| `appsscript-script`, `appsscript-deploy`, `appsscript-account-check`, `appsscript-slot`, `appsscript-check`, `appsscript-clear` | `publisher/deploy/cli/cli_addon_google.go` (the account's script, its connect check, a relay's slot URL, a slot's update and clear) | L-google-pub (G1/G2), account form 2026-11-22 |

Publishing to the Google channel is not a verb: it is one more backend
of `publish-freshness`.

### 6.4 The UI shell

`client-ui/src/publisher/addons/` (owned by L-ui from wave 2):
`AddonsSection.tsx` — a folded card on the relay page (below People) and
at the end of the build wizard; one block per add-on with what it helps
with, its cost and what it ties to the publisher; off by default.
`addonText.ts` — the copy keys (`pub.addons.*`, English and Persian in
`client-ui/src/i18n/d2/d2-extra.*.json`) and `ADDON_BUILT`, which keeps a
block "in development" (switch off and disabled) while false; all three
are true. The account sheets (Hetzner, Cloudflare, Google) are in
`AccountSheets.tsx`, opened from the Accounts page and from a switch
whose account is missing; the build wizard's extras step and its
finishing screen are `WizardAddons.tsx` (a failed extra there is one
line and «تلاش دوباره», the raw text under Details; the status wraps
under the title on a narrow screen).

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

Settled since wave 1: the CDN compatibility rule (the sibling
`_cdn_endpoint` and the wrapped outbound; an import costs the route,
`needs_newer_app`, never the pack, and the import screen says so in both
languages); the standby store write; the signing check in the binder and
the CDN route in the minter; the `appsscript` kind of the freshness
table; the standby item in the account check; `DestroyReport.addons` on
the relay delete sheet; the door verb and the CDN route in the signature
(integration pass).

Still open:

- **Real-account gates**, in order: S-1 (Floating IP limit on the
  account), C-1 (token permission keys), C-2 (ECH on a free zone, and
  the edge probe's neutral name), G-1 (PropertiesService without an
  authorization step), G-2 (fronted fetch with the engine's hello; Google
  may answer 421 to `script.googleusercontent.com` on a connection opened
  with the `www.google.com` name).
- **The relay release.** The door's box-firewall half and `POST /cdn`
  ride relay-v1.6.0, which the owner cuts; every relay needs a fresh
  provision to gain it.
- **A door before the first person.** `POST /cdn` refuses while the relay
  has no recipient (409), so the way in through Cloudflare cannot be set
  up on a relay nobody is on yet; the build rolls back and says why. (A
  door the last person left is parked and opens again for the next one.)
- **What a block of `cloudflare-ech.com` does.** Plan §2.1 says the add-on
  does not rescue it. In the lab the route still carries, on the second
  rung (the ECH hello split across TLS records), because the lab's boxes,
  like the measured real ones, do not join TLS records
  (`cdn-ech-outer-block*`). Against a box that does, the route is dead and
  no plain hello is sent. Which one Iran's boxes are is unknown.
- **Google-only signing for older builds** (`mirror_args`): a one-mirror
  set waits until the builds in people's hands accept it.
- **The FRP-8 CDN commands** are still registered beside the add-on's.
