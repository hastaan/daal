---
name: subscription-v1
phase: 1.5A
status: draft
---

# subscription-v1 — first-class subscription objects

## Status

Draft, Phase 1.5A.

## Purpose

A **subscription** is a long-lived URL the user (or their friend) trusts
to deliver a recurring set of routes. The Phase 1.5A engine pulls the
URL through the active tunnel (or direct, when no tunnel is up), parses
the body, wraps it into a synthetic .sbp signed by the device delegate
key, and feeds it through the existing importer.

Subscriptions never appear on the wire as URLs leaving the engine to the
host. The URL lives only in the age-encrypted secrets KV under the key
`subscription-url:<subscription_id>`. The host UI manages a subscription
by display name and refresh history.

## On-device shape

`subscriptions` table (see `routestore-v1.md`):

| Column                  | Type    | Notes |
|---|---|---|
| `subscription_id`       | TEXT PK | locally-generated `sub_<24hex>` |
| `publisher_id`          | TEXT    | publisher this subscription belongs to (soft FK) |
| `display_name`          | TEXT    | user-supplied label |
| `url_secret_key`        | TEXT    | `subscription-url:<sub_id>` — points into secrets_kv |
| `profile_update_min`    | INT     | minutes between refreshes; clamped [60, 10080] |
| `profile_title`         | TEXT    | parsed from sip008/clash metadata |
| `support_url`           | TEXT    | parsed from subscription-userinfo |
| `last_refresh_bucket`   | TEXT    | RFC3339Z hour bucket of last attempt |
| `last_refresh_outcome`  | TEXT    | `ok` or failure category |
| `last_good_refresh_bkt` | TEXT    | hour bucket of last `ok` refresh |
| `imported_at`           | TEXT    | RFC3339Z creation time |

## Recognized body formats

The Phase 1.5A parser recognizes three on-the-wire formats and rejects
everything else as `bundle_corrupted`:

1. **base64 / URI list**: a base64-encoded (or raw) newline-separated
   list of `vless://`, `vmess://`, `trojan://`, `ss://`,
   `hysteria2://`, `tuic://` URIs. Parsed via `bundle/go/uri.ParseURI`.
2. **SIP008 JSON**: `{ "version": 1, "title": "...", "servers": [...] }`
   per the Shadowsocks spec.
3. **Clash YAML**: the `proxies:` section in either inline-flow or
   block-flow form. The Phase 1.5A parser is hand-rolled and does NOT
   pull a YAML dependency; it recognizes the standard `name`, `type`,
   `server`, `port`, `cipher`, `password`, `uuid` keys.

## Synthetic .sbp wrapper

Every successful refresh produces a transient signed .sbp:

- `spec_version: 2`
- `publisher.name = display_name (or profile_title)`
- `publisher.key_fingerprint_hex = device delegate fingerprint`
- `publisher.trust_class = "tofu_friend"` (matches the per-device share
  identity)
- `bundle.type = "friend_share"` (so the existing importer cache code
  path applies)
- `bundle.id = "subscription-<sub_id>-<timestamp>"`
- `bundle.expires_at = now + 7d`

The synthetic .sbp is signed by the **device-local delegate key** that
already lives in `secrets_kv` under `share/identity:v1` (introduced in
Phase 1C). No new key material is generated.

## Atomic profile cache

Each Refresh runs the importer's `SaveImport` in a single sqlite
transaction. If the network fetch fails, the previous set survives
untouched. If the parse fails, no rows are touched. If the COMMIT fails,
the previous set survives. There is no shadow table.

## OPSEC invariants

- The URL is age-encrypted at rest.
- The URL is NEVER returned by any ABI function, NEVER logged, NEVER
  written to `refresh_audit` (only `subscription_id` is recorded).
- Subscription refreshes prefer the active tunnel (`viaTunnel=true`);
  the direct dialer is the fallback. Phase 1.5A wires only the direct
  dialer; Phase 1.5B's TunnelDialer attaches the engine's local SOCKS5
  inlet to the same `Refresher`.
- The CLI / UI surfaces refresh outcomes by category (`ok`,
  `subscription_unreachable`, `bundle_corrupted`), never the URL.
