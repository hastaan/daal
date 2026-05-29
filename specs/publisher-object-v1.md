# Publisher Runtime Object v1

## Status

Draft for V0 freeze.

## Purpose

`Publisher` stores local trust state for each publisher key the user has encountered.

## Schema

```json
{
  "publisher_id": "ed25519-fingerprint-hex",
  "display_name": "Provider or friend name",
  "trust_level": "official|trusted_provider|tofu_friend|unknown|revoked",
  "first_seen": "2026-04-25T12:00:00Z",
  "last_seen_bundle": "2026-04-25T12:00:00Z",
  "key_status": "active|rotated|compromised|revoked",
  "rotation_chain": ["previous-fingerprint"],
  "revocation_sources": ["official-list"],
  "user_assigned_label": ""
}
```

## Local Audit History

Trust transitions must be append-only logged locally so the user can answer when and why a publisher became trusted.

## Trust Rules

- First-seen publisher keys are not silently trusted.
- User confirmation is required for durable trust.
- Valid key rotation informs the user but does not require starting trust from scratch.
- Unexpected key change blocks import or trust escalation.
- Revocation overrides prior trust.

## Privacy Rules

- Publisher trust history is local.
- No telemetry reports publisher trust state.
- User-assigned labels never leave the device automatically.
