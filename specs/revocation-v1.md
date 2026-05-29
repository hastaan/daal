---
name: revocation-v1
phase: 1.5A
status: draft
---

# revocation-v1 — per-publisher signed revocation lists

## Status

Draft, Phase 1.5A.

## Purpose

A revocation list lets a publisher invalidate one or more of their own
routes (or the publisher's own key) in the field, between bundle
publishes. The on-the-wire format was already specified in
`publisher-cli-v1.md`; Phase 1.5A adds the **distribution mechanism**.

## Distribution

Phase 1.5A is **per-publisher**: each publisher hosts their own
revocation list, and the URL is pinned in the publisher's own bundle
manifest (v2, additive):

```json
{
  "publisher": {
    ...
    "revocation_url": "https://provider-x.example/revocation.json",
    "revocation_fingerprint_hex": "<64-char raw hex of the revocation signing key>"
  }
}
```

There is intentionally NO central revocation registry; pulling each
publisher's list directly avoids creating a single chokepoint that a
censor could block to suppress key rotations across all publishers.

## Verification

`bundle/go/publisher.VerifySignedRevocationBytes` is the canonical
verifier. The signed body must:

1. Be a valid JSON `SignedRevocation` payload (`v == 1`).
2. Carry `issued_at` and `reason`.
3. Verify under the ed25519 public key whose raw hex appears in
   `revocation_fingerprint_hex`. (Phase 1.5A treats the field as a key
   pin rather than a SHA-256 of the key. This avoids a separate
   "fetch the revocation key" step.)

A tampered or misissued list is dropped silently; no revocations are
applied; the next 6h tick re-tries.

## Effect of a successful refresh

For each fingerprint in `revoked_publishers`: every route under that
publisher_id is set to `trust_state = revoked`. The publisher row is
**not** deleted — historical audit must remain queryable.

For each id in `revoked_routes`: that single route's `trust_state` is
set to `revoked`. A revoked route can never be activated again.

## Cadence

- **Default:** every 6 hours, opportunistically through the active
  tunnel.
- The cadence MUST NOT exceed once per hour per publisher under any UI
  trigger; the "Refresh now" affordance writes a `refresh_audit` row
  with `via_tunnel=true|false` so investigators can later confirm the
  call did happen.

## OPSEC invariants

- Only `https://` URLs are accepted.
- The fetch reuses `core/bootstrap.FetchRaw` — no `net/http`, no
  `User-Agent`, no cookies, no redirects.
- The publisher_id, hour bucket, and outcome are written to
  `refresh_audit`; the URL is not.
