# Per-recipient credentials — v1

**Status:** locked at FRP-14. **Spec version:** 1.
**Owner packages:**
* `cmd/daal-relay-mgmt/` (on-box service routes + sing-box rewriter)
* `publisher/deploy/mgmt/` (Helper-side mgmt client)
* `client-shell/tauri/daal-wizard/` (recipient DB + wizard commands)

This document locks the contract that lets a single Daal relay box
serve N named recipients, each with their own sing-box credentials,
revocable independently.

## 1. Why

Pre-FRP-14, a Daal relay served a single bundle of credentials baked
into the sing-box config. Every recipient who held the `.sbp` used the
same UUID/short_id/password. Consequences:

* No per-recipient revocation. The only way to remove access was to
  rotate everything via L1 (`/rotate-credentials`), which kicks every
  other user too. **Historical only.** Wave 3 Step 7 re-scoped that
  route: `/rotate-credentials` now names exactly one recipient,
  a missing `name` is a `400` rather than "everyone", and the
  box-wide REALITY keypair moved to a separate operation. See
  `specs/daal-relay-mgmt-v1.md` §4.1 for the shape that ships, and
  §4.1.1 for recognising a box that still implements the old one.
* No accountability if a credentials leak happens — the operator
  cannot tell which recipient leaked.
* No room for per-recipient TOS / quota / channel-specific UX in the
  future.

FRP-14 separates the user table from the data-plane config, exposes a
small CRUD over the existing mgmt-plane, and re-shapes the publisher
wizard's Step 7 around the resulting recipient list.

## 2. Sing-box config shape

The V2 cloud-init template emits a sing-box config whose inbound
arrays start empty (zero users at first boot). Each recipient added
via the mgmt API appends one row per transport family.

```jsonc
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "0.0.0.0", "listen_port": 443,
      "users": [
        { "uuid": "<uuid>", "name": "r17", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "<sni>",
        "reality": {
          "enabled": true,
          "private_key": "<reality-priv>",
          "short_id":    ["<8-hex-per-user>"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "0.0.0.0", "listen_port": 8443,
      "users": [
        { "name": "r17", "password": "<22-char-b64url>" }
      ]
    },
    {
      "type": "naive",
      "tag": "naive-in",
      "listen": "0.0.0.0", "listen_port": 8444,
      "users": [
        { "username": "r17", "password": "<22-char-b64url>" }
      ]
    },
    {
      "type": "vless",
      "tag": "ws-in",                   // ONE shared WS inbound, all recipients
      "listen": "0.0.0.0", "listen_port": 8445,
      "users": [
        { "uuid": "<uuid>", "name": "r17" },
        { "uuid": "<uuid>", "name": "r18" }   // …every recipient
      ],
      "transport": {
        "type": "ws",
        "path": "/r<first>/<8-hex>"          // minted once, then reused
      },
      "tls": { "enabled": true, "server_name": "<sni>" }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
```

### 2.1. The shared WS inbound

**Amended 2026-08-17.** This section originally specified **one inbound
per recipient**, tagged `ws-r<id>`, each owning exactly one
`transport.path` and one user, all sharing listen port 8445 on the
assumption that sing-box routes by path rather than by listen port.

**That assumption was wrong and the design does not work.** Two inbounds
cannot bind the same port; the second recipient collided on 8445 and
crashed sing-box.

The shipped design is **one shared `ws-in` inbound** for the whole
server, with one `transport.path`, and every recipient appended as a row
in its `users[]`. The path is minted from the first recipient and reused
verbatim for every recipient thereafter
(`cmd/daal-relay-mgmt/singbox_users.go:33` `tagWS = "ws-in"`, the reuse
at `:59-68`, `appendWSUser` at `:363`).

**Privacy cost — deliberate, and it is a real weakening.** Because the
path is shared, a single leaked pack discloses the WS path that *every*
recipient on that relay uses. Only the credentials (UUID, passwords)
remain per-recipient; the WS path does not, and revoking a recipient
does not rotate it. Any reasoning elsewhere in this spec that assumes
per-recipient WS isolation is void. Rotating the shared path for
everyone at once is the mitigation, and it is not implemented.

### 2.2. Other transports — shared inbound, append users

VLESS-Reality, Hysteria2, and Naive each have a single inbound whose
`users[]` array grows by one row per recipient. Reality's `short_id`
array also grows by one entry. All are stable additive ops; no other
inbound or outbound is touched.


### 2.3. Which inbounds a relay has: its family set

**Added 2026-11-18 (worldbox finding FAM-4, backlog W5-1).** The config
above shows the four default families. A relay does not necessarily
serve those four, and it must not carry an inbound — or a credential, or
an open port — for a family it was not provisioned to serve.

The family set is resolved once, by the publisher, at provision time
(`relayconf.ServedFamilies`: the toolbox profile's defaults, or the
`--families` list). Four things are derived from that one list and
nothing else:

| what | where | rule |
|---|---|---|
| inbounds baked at first boot | `/etc/sing-box/config.json` (cloud-init) | `vless-in` iff `vless-reality`; `hy2-in` iff `hysteria2`; `tuic-in` iff `tuic`. None is unconditional. A relay serving only on-first-use families boots with an empty `inbounds[]`. |
| the box's own copy of the set | `/etc/daal/families`, one family name per line (cloud-init) | written whenever the provider resolved a set |
| inbounds created on first recipient | `daal-relay-mgmt` | `naive-in`, `ws-in`, `ss-in`, `anytls-in` are created **only** for families named in `/etc/daal/families`; a user row is appended to a baked inbound only if its family is named there |
| open data-plane ports | cloud-provider firewall and box-side `ufw` | exactly `relayports.FirewallPortsFor(<set>)` — 443/tcp only with `vless-reality`, 443/udp only with `hysteria2`, and so on |

`/etc/daal/families` semantics on the box:

* **absent** — the box predates the file. The daemon behaves as it did
  before it existed (every family it knows is created on first use).
* **present, naming at least one family** — obeyed exactly. Names the
  daemon does not recognise are ignored (a newer publisher, an older
  daemon); the publisher already refuses to mint a route whose
  credential the box did not return.
* **present but empty or unreadable** — `/users/provision` answers
  `500` and changes nothing. A declared set must never degrade to
  "serve everything".
* a provision that would leave the recipient with **no row in any
  inbound** is `500`, not a `200` with empty credentials.

The **user registry** — what `/users/list`, the duplicate-name check and
the `MaxRecipientsPerServer` cap read — is the union of user names over
every managed inbound. It used to be `vless-in`'s `users[]` alone, which
is empty on a relay that does not serve `vless-reality`.

`/users/provision` and `/rotate-credentials` return a credential **only
for a row that exists in the live config after the write**:
`vless_uuid` iff the recipient has a row in `vless-in` or `ws-in`,
`reality_short_id` iff in `vless-in`, `ws_path` iff in `ws-in`,
`hy2_password` iff in `hy2-in`, `naive_password` iff in `naive-in` — the
same "a value the box does not send is the signal" rule the `tuic_*`,
`ss_*` and `anytls_password` fields already followed. An empty field is
a family this relay does not serve, never a failed write.

On a relay with no REALITY inbound, first boot generates no REALITY key:
`/etc/daal/reality.pub` and `/etc/daal/cover-sni` are not written and
`reality_public_key` / `cover_sni` come back empty.

Changing a relay's family set is a reprovision: both firewalls and the
baked inbounds are written once, at first boot.

**How the set is chosen (`daal-deploy provision --families`, worldbox
finding FAM-3).** With no `--families`, the relay serves the toolbox
profile's `default_enabled` families. With it, the list **replaces**
those defaults — it is not added to them — and:

* every name must be a family the chosen profile offers. Anything else
  (a misspelling, or a real family of a different profile) stops the
  command with exit status 2 **before any cloud call**, naming each bad
  value and the profile's valid set. It used to be dropped silently.
* what the relay will and will not serve is stated before the cloud is
  called: a line on stderr, or — with `--progress-json` — one
  `provision_families` event carrying `families`, `dropped_defaults`,
  `added_opt_in` and `unserved_by_release`.
* the app's wizard therefore always sends "every default family plus
  the ones ticked", or an empty list when nothing is ticked
  (`client-ui/src/publisher/extraFamilies.ts`).

**The released relay software gates the opt-in families (worldbox
F-002).** The box's half of `shadowsocks`, `anytls` and `tuic` is
`daal-relay-mgmt`, which a relay downloads as a pinned release artefact
(`publisher/deploy/cloudinit/artifacts.go`), not from the publisher's
tree. Whether the pinned artefact serves them is one build constant
beside the pin, `cloudinit.PinnedMgmtServesOptInFamilies`. While it is
`false`:

* the wizard shows the opt-in families but does not let them be turned
  on, says why in one line, and always sends an empty list — a choice
  remembered from another build is ignored
  (`RELEASED_RELAY_SERVES_EXTRA_FAMILIES`, the mirror of the constant);
* `provision --families` naming one of them is still accepted (a relay
  may run a daemon newer than the pin: a release in progress, the
  end-to-end rig), but the statement reads "will be **asked** to serve"
  rather than "will serve", names the families the release cannot
  serve, and says what that means — no credential and no route for
  them, and with `anytls` named a connection file that is still
  `spec_version` 5. `unserved_by_release` lists them; it is `[]` when
  the pin serves everything asked.

The constant is flipped in the commit that bumps the `daal-relay-mgmt`
`Sha256`/`SigHex` to an artefact that serves them; a unit test fails on
a bump without the flip and on a flip without a bump.

The L6 rung (rebuild on a different toolbox profile) still intersects
the relay's families with the new profile, but no longer inside
`provision`: `daal-deploy reprovision --new-toolbox-profile` refuses an
empty intersection before deleting anything (unchanged), and then
narrows the record's candidates to what the new profile offers and says
what the rebuild drops, so the `provision --families <record's
families>` that follows passes the check above.

## 3. On-box surface — additions to `daal-relay-mgmt`

Per FRP-14 the "exactly three routes" invariant lifts to **exactly six
routes**. The publisher redesign lifts it once more, to **exactly seven**:
`/whoami` is specified in `specs/daal-relay-mgmt-v1.md` §4.7 and is not
part of the per-recipient surface.

### 3.1. `POST /users/provision`

Auth required (Ed25519 op-token, op = `users-provision`).

Request body:
```json
{ "name": "r17" }
```

Constraints on `name`:
* Matches `^r[0-9]{1,12}$`.
* MUST NOT collide with any existing user (returns 409 Conflict if
  it does — caller chooses a fresh id).

Side effects:
1. Generate fresh credentials via `crypto/rand`:
   * VLESS UUID v4.
   * Reality short_id: 4 random bytes hex-encoded (8 chars).
   * Hy2 password: 16 random bytes base64-url (22 chars, no padding).
   * Naive password: same shape as Hy2.
   * WS path: `/r<id>/<8 hex chars>` — minted only for the FIRST
     recipient on the server. Every later recipient reuses the existing
     `ws-in` path (§2.1); the value is still returned in their creds
     because the client needs it.
2. Surgically rewrite `/etc/sing-box/config.json` per §2 above.
3. Atomic file swap (`tmp file → rename`).
4. `systemctl reload sing-box.service`.
5. Return creds:

```json
{
  "name":               "r17",
  "vless_uuid":         "<uuid>",
  "reality_short_id":   "<8 hex>",
  "hy2_password":       "<22 chars>",
  "naive_password":     "<22 chars>",
  "ws_path":            "/r17/<8 hex>",
  "provisioned_at_unix": 1748090000
}
```

The on-box service stores **no** state about which recipient a name
maps to in the human sense. The `name` is opaque. Mapping name →
person is the publisher app's responsibility.

### 3.2. `POST /users/revoke`

Auth required (op = `users-revoke`).

Request body:
```json
{ "name": "r17" }
```

Side effects (**hard revoke**):
1. Remove the user's row from every managed inbound's `users[]` array
   that carries one (`vless-in`, `hy2-in`, `naive-in`, `ws-in`, and on
   relays that serve them `tuic-in`, `ss-in`, `anytls-in` — see §2.3
   for which exist on a given relay). Note this is a **user
   removal, not an inbound removal** — `removeWSUser`
   (`singbox_users.go:415`) drops the row; the shared `ws-in` inbound
   itself disappears only when its last user is revoked. The shared WS
   path is NOT rotated by a revoke (§2.1).
2. Remove the recipient's `short_id` from the Reality array.
3. **Apply, exactly once.** Invoke `/usr/local/lib/daal/singbox-kick.sh`,
   which is the one way the box applies a rewritten config:
   ```sh
   #!/bin/sh
   set -eu
   systemctl reload sing-box.service || systemctl restart sing-box.service
   ```
   `reload` is the unit's `ExecReload=/bin/kill -HUP $MAINPID`. sing-box
   1.13 handles SIGHUP in-process (`cmd/sing-box/cmd_run.go`): it
   re-checks the config on disk, **keeps the running instance if that
   check fails**, and otherwise closes the instance — every inbound, and
   through the connection manager every live connection — and starts a
   new one. That close is what evicts the revoked recipient's
   established session; it reconnects, fails auth (no row in the table),
   and stays disconnected. `restart` is the fallback for a unit file with
   no `ExecReload=` and has the same effect on sessions.

   **Amended 2026-11-18 (worldbox finding INT-O1).** This step used to be
   a "force-kick" — `SIGUSR2`, a sleep, then the reload — followed by a
   second reload, with a temporary 1 s idle-window "drain" around them.
   None of it did what it said: sing-box registers handlers for SIGINT,
   SIGTERM and SIGHUP only, the Go runtime ignores an unhandled SIGUSR2,
   and the drain knob was never implemented. The observable behaviour was
   a 2 s sleep and **two** restarts of the relay per revoke, each one
   disconnecting every other recipient. One reload is the whole
   mechanism; a caller that applies twice is a defect
   (`TestUsersRevoke_RemovesAndReloadsExactlyOnce`,
   `TestRotateCreds_ReloadsExactlyOnce`,
   `TestRenderV2_ApplyWrapperIsOneReloadAndNoSleep`).
4. Return:
```json
{ "revoked_at_unix": 1748100000 }
```

**Bound:** revoke is effective for new connections immediately and
for already-open connections within ≤ 10 s. Documented in the FRP-14
phase doc as invariant 4.

### 3.3. `GET /users/list`

Auth required (op = `users-list`).

Response:
```json
{
  "users": [
    { "name": "r17", "provisioned_at_unix": 1748090000 },
    { "name": "r23", "provisioned_at_unix": 1748100000 }
  ]
}
```

Used by the publisher app on Step 7 entry to detect drift between
the wizard DB and the on-box truth. No credentials are returned —
the publisher app already has them in its own DB.

### 3.4. Token op-binding

`validOps` in `cmd/daal-relay-mgmt/main.go` extends to:
```go
{"rotate-credentials", "rotate-tls",
 "users-provision", "users-revoke", "users-list",
 "whoami"}
```

The op string in the token MUST match the URL path. A token signed
for `users-provision` against `/users/revoke` is rejected.

Timestamp window unchanged: `[-300 s, +60 s]`.

## 4. Helper-side mgmt client

`publisher/deploy/mgmt/client.go` extends with three methods:

```go
type Client interface {
    RotateCredentials(...) (*RotateResp, error)         // FRP-10
    RotateTLS(...)         (*RotateResp, error)         // FRP-10
    Health(...)            error                        // FRP-10

    ProvisionUser(ctx context.Context, name string)  (*UserCreds, error)  // FRP-14
    RevokeUser(ctx context.Context, name string)     error                // FRP-14
    ListUsers(ctx context.Context)                   ([]UserMeta, error)  // FRP-14
}

type UserCreds struct {
    Name             string `json:"name"`
    VLESSUUID        string `json:"vless_uuid"`
    RealityShortID   string `json:"reality_short_id"`
    Hy2Password      string `json:"hy2_password"`
    NaivePassword    string `json:"naive_password"`
    WSPath           string `json:"ws_path"`
    ProvisionedAtUnix int64 `json:"provisioned_at_unix"`
}

type UserMeta struct {
    Name              string `json:"name"`
    ProvisionedAtUnix int64  `json:"provisioned_at_unix"`
}
```

Each call follows the existing FRP-10 wrap:
1. Open ephemeral firewall: `Provider.SetEphemeralFirewallRule(serverID, callerIP, mgmtPort, 300)`.
2. `defer` removal of the rule.
3. Mint Ed25519 op-token.
4. TLS-pinned HTTPS call.
5. Parse JSON.

## 5. Wizard database — `recipients` + `operator_recipients`

Migration V015:

```sql
-- A person the operator can send relay packs to. Address-keyed.
CREATE TABLE recipients (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  display_name    TEXT    NOT NULL,
  daal_address    TEXT    NOT NULL UNIQUE,    -- bech32m daal1...
  pub_key_b64     TEXT    NOT NULL,           -- 32-byte X25519 pub, base64-url
  created_at_unix INTEGER NOT NULL,
  notes           TEXT    NOT NULL DEFAULT ''
);

-- Per-server-per-recipient credentials row, mirrors the on-box
-- sing-box users[] entry.
CREATE TABLE operator_recipients (
  operator_id      INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
  recipient_id     INTEGER NOT NULL REFERENCES recipients(id),
  server_user_name TEXT    NOT NULL,          -- 'r<recipient_id>' on the box
  vless_uuid       TEXT    NOT NULL,
  reality_short_id TEXT    NOT NULL,
  hy2_password     TEXT    NOT NULL,
  naive_password   TEXT    NOT NULL,
  ws_path          TEXT    NOT NULL,
  provisioned_at   INTEGER NOT NULL,
  revoked_at       INTEGER NOT NULL DEFAULT 0,
  last_sbpx_sha256 TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (operator_id, recipient_id)
);

CREATE INDEX idx_operator_recipients_active
  ON operator_recipients(operator_id)
  WHERE revoked_at = 0;
```

### 5.1. `server_user_name` convention

`server_user_name = "r" + recipient_id` (the wizard DB's autogenerated
PK on the `recipients` table). Stable across renames of the friendly
display name; never re-used.

### 5.2. Recipient-pack history

`last_sbpx_sha256` records the SHA-256 of the most recently produced
`.sbpx` for that recipient on that operator. Used by the UI to:
* Show "Last shared 3 days ago" with a stable hash diff.
* Detect "this `.sbpx` is stale" if the user re-shares from a cached
  copy (not implemented at V1.6; the field is reserved).

## 6. Wizard Rust commands

New commands in `client-shell/tauri/daal-wizard/src/commands.rs`:

```rust
recipient_add(operator_id, display_name, daal_address) -> i64       // recipient_id
recipient_revoke(operator_id, recipient_id)             -> ()
recipient_resend(operator_id, recipient_id)             -> PathBuf   // path of fresh .sbpx
recipient_list(operator_id)                             -> Vec<RecipientView>
address_book_list()                                     -> Vec<Recipient>
```

`recipient_add` is the orchestration:
1. Insert recipient (or look up existing) in `recipients` table.
2. Open ephemeral firewall.
3. Call `mgmt.ProvisionUser(name = "r<id>")` → creds.
4. Persist `operator_recipients` row.
5. Build per-recipient manifest (substitute creds into the operator's
   manifest scaffold; recompute `bundle.recipient_fp_hex`).
6. Sign manifest (existing `bind-and-sign` path, with new flag).
7. age-encrypt to recipient's X25519 pub.
8. Write `<staging>/share/<display>.sbpx`.
9. Return.

UI then calls the platform share dispatcher.

## 7. Bootstrap and back-compat

* Step 5 (provisioning) emits an empty user table — the server is
  parked.
* Step 6 (sign) still produces an unsigned-manifest scaffold but does
  not produce a final `.sbp` file with credentials yet; the per-
  recipient credentials get filled at recipient-add time.
* The wizard's UI distinguishes "Server ready · 0 recipients" from
  "Server ready · 3 recipients" — both are valid completion states.
* V1.5 operators in an existing wizard DB carry no recipients; the
  UI shows a one-time migration banner (see FRP-14 phase doc).

## 8. Invariants

1. **Exactly seven routes** in `daal-relay-mgmt`: the FRP-10 three, the
   FRP-14 per-recipient trio, and `/whoami` (added by the publisher
   redesign; see `specs/daal-relay-mgmt-v1.md` §4.7).
   Pinned by `TestExactlyNRoutes` (n=7).
2. **Per-recipient credentials are independent.** Adding or revoking
   recipient X never modifies the on-box credentials of recipient Y.
   Pinned by `TestUsersProvision_Isolation` and
   `TestUsersRevoke_DoesNotTouchOtherUsers`.
3. **Recipient name is stable.** `r<recipient_id>` does not change
   over the lifetime of the recipient. Pinned by the DB schema (PK
   on `recipients.id` is autogenerated, never re-used).
4. **Revoke effective within ≤ 10 s.** Documented bound; tested by
   the FRP-14 integration soak (sets up two users, opens a long
   download via user A, revokes A, asserts the socket closes
   within 10 s).
5. **Empty user table at first boot.** **UNPINNED** — this cited
   `TestRenderV2_EmptyUsers`, which does not exist anywhere in the tree
   (verified 2026-08-17). The behaviour is asserted indirectly by
   `publisher/deploy/cloudinit/template_test.go`, but nothing pins this
   invariant by name. Write the test or downgrade the invariant.
6. **Per-recipient credentials never appear in clear in the inner
   `.sbp`'s manifest.** They appear only in the per-recipient
   `profiles/*.json` sing-box configs and the encrypted `.sbpx`
   envelope.

   **UNPINNED, and partially superseded.** Two separate problems:

   a. `TestManifestNoCreds` does not exist anywhere in the tree
      (verified 2026-08-17). This invariant has never been pinned.

   b. The invariant did not anticipate the **shared-pack** path, which
      is now the default share flow: `publisher/deploy/cli/cli_users_pack.go`
      builds a plaintext shared `.sbp` carrying `r0`'s live credentials
      with no age envelope. That does not violate the letter of this
      invariant (the credentials are in `profiles/*.json`, not the
      manifest), but it inverts the threat model
      `specs/sbpx-envelope-v1.md:16-31` states as the justification for
      `.sbpx` existing at all. **The shared-`.sbp` model has no spec.**
      Resolve that before treating this invariant as meaningful.
7. **Recipient count cap.** Hard cap **128 recipients** per server
   (`cmd/daal-relay-mgmt/users.go:35 MaxRecipientsPerServer`). Warning
   at 32. This was written as a cap on *inbounds* when the design was
   one WS inbound per recipient; there is exactly one WS inbound now
   (§2.1), so it is and always was enforced as a recipient cap. Pinned
   by `TestUsersProvision_CapEnforced`.

## 9. Test surface

| File | Tests |
|---|---|
| `cmd/daal-relay-mgmt/main_test.go` | provision append, revoke remove, revoke kicks via wrapper, list, op-binding, `TestExactlyNRoutes` (n=**7**), isolation, idempotency, 128-cap |
| `cmd/daal-relay-mgmt/singbox_users_shortid_test.go`, `singbox_users_tls_test.go` | golden config diffs for VLESS append/remove, Hy2 append/remove, Naive append/remove, shared `ws-in` user add/remove. *(There is no `singbox_rewriter_test.go`; that name was cited here and never existed.)* |
| `publisher/deploy/mgmt/client_test.go` | new methods round-trip, ephemeral firewall ordering for users routes |
| `publisher/deploy/cloudinit/template_test.go`, `families_test.go` | empty users[] at boot; the apply wrapper is one `reload || restart` with no SIGUSR2 and no sleep; `ExecReload` on the unit; `/etc/daal/families`; ufw opens exactly the served families' ports |
| `client-shell/tauri/daal-wizard/src/recipient_book.rs` | insert/dedupe by address, FK cascade on operator delete, soft-revoke status |
| `client-shell/tauri/daal-wizard/src/commands.rs` | recipient_add success, dup-address handling, revoke, resend |

## 10. Carry-overs

* **Cell aggregation.** Sending one pack to many recipients in one
  shot lives in FRP-11 (`specs/cell-v1.md`).
* **Per-recipient bandwidth quotas / metering.** Post-V2.
* **Multi-operator-from-one-publisher.** A single publisher can run
  many relays; the recipient table is global, but
  `operator_recipients` rows are per-operator. The UI lets a user
  add the same recipient to multiple operators in separate flows
  (each gets its own credentials slot on its own box).
