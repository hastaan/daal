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
  other user too.
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
      "tag": "ws-r17",                  // per-recipient WS inbound
      "listen": "0.0.0.0", "listen_port": 8445,
      "users": [
        { "uuid": "<uuid>", "name": "r17" }
      ],
      "transport": {
        "type": "ws",
        "path": "/r17/<8-hex>"
      },
      "tls": { "enabled": true, "server_name": "<sni>" }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
```

### 2.1. Per-recipient WS inbound

sing-box does not multiplex multiple WS paths on a single inbound's
`transport.path`. We instead add **one inbound per recipient** for
the WebSocket-TLS family, tagged `ws-r<id>`. All WS inbounds share
listen port 8445 — sing-box routes by path, not by listen port — but
each inbound owns exactly one `transport.path` and one user.

Bounded growth: §8 invariant.

### 2.2. Other transports — shared inbound, append users

VLESS-Reality, Hysteria2, and Naive each have a single inbound whose
`users[]` array grows by one row per recipient. Reality's `short_id`
array also grows by one entry. All are stable additive ops; no other
inbound or outbound is touched.

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
   * WS path: `/r<id>/<8 hex chars>`.
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
1. Remove the user from the four inbounds (`vless-in.users[]`,
   `hy2-in.users[]`, `naive-in.users[]`, and the entire `ws-r<id>`
   inbound block).
2. Remove the recipient's `short_id` from the Reality array.
3. Set the VLESS inbound's connection idle window to 1 s temporarily
   (a "drain" knob via sing-box config; restored after step 5).
4. **Force-kick:** invoke `/usr/local/lib/daal/singbox-kick.sh`, which:
   ```bash
   #!/bin/sh
   set -e
   systemctl kill -s USR2 sing-box.service || true
   sleep 1
   systemctl reload sing-box.service
   ```
   SIGUSR2 in sing-box ≥ v1.10 triggers a graceful drop of all
   inbound connections; the immediate reload then re-establishes
   inbounds for the remaining users. Sessions held by the revoked
   user reconnect, fail auth (no UUID in the table), and stay
   disconnected.
5. Restore `max_idle_time` to the default after the drain (server
   does this in-memory; the on-disk config is restored to its
   default settings via the same rewriter pass).
6. Return:
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
 "users-provision", "users-revoke", "users-list"}
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
   Pinned by `TestUsersProvisionIsolated` and `TestUsersRevokeIsolated`.
3. **Recipient name is stable.** `r<recipient_id>` does not change
   over the lifetime of the recipient. Pinned by the DB schema (PK
   on `recipients.id` is autogenerated, never re-used).
4. **Revoke effective within ≤ 10 s.** Documented bound; tested by
   the FRP-14 integration soak (sets up two users, opens a long
   download via user A, revokes A, asserts the socket closes
   within 10 s).
5. **Empty user table at first boot.** Pinned by
   `TestRenderV2_EmptyUsers`.
6. **Per-recipient credentials never appear in clear in the inner
   `.sbp`'s manifest.** They appear only in the per-recipient
   `profiles/*.json` sing-box configs and the encrypted `.sbpx`
   envelope. Pinned by `TestManifestNoCreds`.
7. **WS-per-recipient inbound count cap.** Hard cap 128 inbounds per
   server. Warning at 32. Pinned by
   `TestUsersProvisionCapEnforced`.

## 9. Test surface

| File | Tests |
|---|---|
| `cmd/daal-relay-mgmt/main_test.go` | provision append, revoke remove, revoke kicks via wrapper, list, op-binding, exactly-6-routes, isolation, idempotency, 128-cap |
| `cmd/daal-relay-mgmt/singbox_rewriter_test.go` | golden config diffs for VLESS append/remove, Hy2 append/remove, Naive append/remove, WS inbound add/remove |
| `publisher/deploy/mgmt/client_test.go` | new methods round-trip, ephemeral firewall ordering for users routes |
| `publisher/deploy/cloudinit/template_test.go` | empty users[] at boot, kick-wrapper present, sing-box v1.10 pinned |
| `client-shell/tauri/daal-wizard/src/recipient_db.rs` | insert/dedupe by address, FK cascade on operator delete, soft-revoke status |
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
