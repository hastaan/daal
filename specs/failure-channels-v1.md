# Failure Channels v1

## Status

**Phase 1.5C.** Formal taxonomy of the **distribution channels** the
Daal rig models. Cross-references `failure-taxonomy-v1.md` (which
enumerates per-attempt failure categories), `bootstrap-tiers-v1.md`,
`subscription-v1.md`, `revocation-v1.md`, `pointer-rotation-v1.md`.

## Purpose

The Phase 0C scenario language declares "channels" — abstract
distribution paths a censor can independently attack. Phase 1.5C makes
them executable: the soak rig operates an in-process fake-origin
server per channel and toggles per-channel state to model an
adversary's day-by-day strategy.

## Channels

| Channel | Maps to | Allowed responses | Example scenario |
|---|---|---|---|
| `subscription` | the user's subscription URL (`subscription-v1`) | allow, drop, timeout | `subscription-url-unreachable` |
| `revocation` | per-publisher revocation URL (`revocation-v1`) | allow, drop, timeout | `publisher-revocation-url-unreachable` |
| `directory` | Tier-3 directory bundle (`bootstrap-tiers-v1`) | allow, drop, timeout | `bootstrap-directory-mirror-unreachable`, `project-domain-unreachable`, `cdn-unreachable`, `app-store-unreachable` |
| `ipfs` | IPFS gateway as Tier-1 fallback pointer (`bootstrap-pointer-v1`) | allow, drop, timeout | `ipfs-gateway-unreachable` |
| `telegram` | Telegram channel listing (V0 distribution) | allow, drop | `telegram-unreachable` |
| `github` | GitHub releases / raw / api | allow, drop | `github-unreachable` |

The mapping `block string → channels` is locked in
`internal/censor/censor.go::blockToChannel` so adding a scenario
requires updating either:

- An existing channel — declare the new block string, map it to the
  channel it most directly tests.
- A new channel — also extend `internal/origin` with a sixth fake-origin
  binding and update this spec.

## Scenarios

A scenario file is the existing JSON shape from Phase 0C:

```json
{
  "id": "subscription-url-unreachable",
  "channel": "subscription-url",
  "description": "...",
  "blocks": ["subscription-url"]
}
```

`blocks` is the list of strings consumed by `blockToChannel`. The rig
applies a scenario by setting every channel implied by `blocks` to
`StateDrop` and every other channel to `StateAllow`.

## Per-attempt failure categories vs channels

Channels are the **what is blocked**. Per-attempt failure categories
(`failure-taxonomy-v1.md`) are the **what does the engine see**. They
are related but not identical:

| Channel | Expected per-attempt category under `StateDrop` |
|---|---|
| `subscription` | `subscription_unreachable` (or `tcp_reset` on the wire) |
| `revocation` | `subscription_unreachable` for the per-publisher fetch |
| `directory` | `subscription_unreachable` for the directory fetch |
| `ipfs` | `subscription_unreachable` |
| `telegram` | observed at the **distribution** layer; not a per-attempt category for engine |
| `github` | observed at the **distribution** layer |

The soak rig asserts these mappings via `ruleRefreshOutcomeMapped` in
`internal/invariants/invariants.go`.

## Privacy invariants

- A scenario's JSON file declares only the abstract channel names; it
  never embeds real CDN IPs or real URLs.
- The fake origins bind on loopback; the rig does not touch any
  external network.
- The redact subcommand drops both IP literals and URL literals from
  every artifact before the public bundle is sealed.
