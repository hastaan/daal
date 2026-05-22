# Rendezvous Channels V1 — Multi-Channel Broker Abstraction

## Status

**Locked at the start of Phase 3B.** This spec defines the
channel abstraction the Snowflake transport (3B), and any
later transport that wants ephemeral-relay rendezvous (3D
Conjure decoy registration, 3E WASM modules), MUST consume.
Channel IDs are a CLOSED list; a sixth channel is a roadmap-
level decision.

Implementation: `core/rendezvous/` package.

## Roadmap coverage

V3.2 ("Snowflake-like ephemeral relays"). The roadmap calls
the rendezvous-channel abstraction "the architecturally
interesting V3 piece" and lists four discovery channels:
domain-fronted broker, SQS / AMP-cache, push notification,
and offline-bundled hints. This spec adds a fifth — AMP-cache
and SQS were combined into "SQS / AMP-cache" in roadmap
prose; we list them as separate channels here because their
operational and trust profiles differ.

## Channel taxonomy

The set of valid channel IDs is a CLOSED list of 5 entries.
The bundle parser rejects unknown values with
`bundle_corrupted` at import time.

| Channel ID | Privacy posture | Network surface | Notes |
|---|---|---|---|
| `domain_fronted_broker` | Fronted-HTTPS to upstream Snowflake broker | TCP/443 + DNS | Default top of priority on most networks |
| `sqs` | AWS SQS queue request via fronting | TCP/443 + DNS | FOCI 2024 paper |
| `amp_cache` | Google AMP-cache HTTPS request | TCP/443 + DNS | Operationally similar to fronting |
| `push` | Inbound only — FCM (Android) / APNS (iOS) | platform native | OPT-IN, default OFF; see `push-rendezvous-v1.md` |
| `offline_hint` | Zero network — reads pre-bundled signed hint | none | Always available; last resort |

`offline_hint` is structurally different from the other four:
it never opens a network socket. The 3B selector treats it as
an always-available fallback; bundle priority decides whether
it sits at the bottom (the common case) or near the top (an
operator who knows the user's network is severely degraded).

## Rendezvous interface

```go
package rendezvous

// Hint is the structured response a Channel returns on
// success. The fields are deliberately Snowflake-flavoured
// at v1; future transports MAY consume `Extra` for non-
// Snowflake payloads.
type Hint struct {
    ChannelID  string          // the channel that returned this hint
    OfferSDP   string          // Snowflake WebRTC offer
    AnswerSDP  string          // Snowflake WebRTC answer (if applicable)
    BridgeFP   string          // bridge fingerprint
    Extra      json.RawMessage // family-specific payload (3D/3E may consume)
    ReceivedAt time.Time       // when the hint arrived; never logged off-device
}

// Request is the per-Solicit input.
type Request struct {
    PublisherKeyHex string         // for verification of inbound signed hints
    NetworkID       string         // hashed; consumed by Selector for netmem bias
    Now             time.Time
    BundleParams    map[string]any // channel-specific knobs (broker URL, queue URL, ...)
}

type Channel interface {
    ID() string
    Solicit(ctx context.Context, req Request) (Hint, error)
}
```

### Selection algorithm (hedged)

The Selector races channels in a HEDGED order:

1. **t = 0** fire the **preferred** channel:
   - If the per-network netmem records a `last_winning_rendezvous_channel`
     for the active network and that channel is in the active priority list,
     fire it first.
   - Else if the per-engine override (set via
     `engine_set_rendezvous_priority`) is non-empty, fire its
     `priority[0]`.
   - Else fire the bundle-supplied `routes[].rendezvous_priority[0]`.
   - If none of the above resolves a candidate, fire `offline_hint`.
2. **t = 4 s** if no winner, fire **all remaining** channels in
   the active priority list in parallel.
3. First successful Solicit wins. The Selector cancels every
   in-flight context for the rest.
4. All-fail returns `ErrAllChannelsFailed`. The route burns
   under the standard 2G classifier as `rendezvous_unavailable`.

The 4-second hedge interval is locked at v1; tuning is a
3-Soak deliverable.

### Selection invariants

- The Selector MUST cancel losing contexts on first success.
- A channel that returned an error in this Solicit MUST NOT
  be retried within the same Solicit (the hedge fires the
  *remaining* channels, not all of them).
- The winning channel ID is recorded **per-route** in the
  routestore (via `last_winning_rendezvous_channel`) AND
  **per-network** in netmem.
- `last_winning_rendezvous_channel` is read on the next
  Solicit on the same network, biasing the t=0 fire toward
  the historically successful channel — but bundle/override
  priority MAY still demote it if the publisher has rotated
  their channel topology.

## Per-route persistence (Phase 3B)

Routestore widens with one additive column on `routes`:

```sql
ALTER TABLE routes ADD COLUMN
    last_winning_rendezvous_channel TEXT NOT NULL DEFAULT '';
```

Set by the pathmanager on a successful Solicit; cleared only
by an explicit user route-reset. Survives session epochs.

## Per-network persistence (Phase 3B)

The 2C netmem subsystem widens with a per-network field
`last_winning_rendezvous_channel`. Same hashing rules as the
existing per-network records: never the raw SSID, never the
raw carrier+plan; consumes the same `network_id` token 2C
already produces.

The Selector consults netmem via an injected callback. The
`core/rendezvous` package does NOT import `core/netmem` (no
import cycle); the engine layer wires the callback at Init
time.

## Privacy invariants

- Each channel's request MUST NOT carry user-identifying
  information beyond what the channel's protocol structurally
  requires (SDP for Snowflake; queue ID for SQS; AMP token
  for AMP-cache; FCM/APNS device token for push;
  publisher-key-hex for offline_hint signature verification).
- Diagnostics surface the WINNING channel ID enumerable
  (`rendezvous_channel`); never URLs, IPs, broker addresses,
  SDP, or device tokens.
- The Selector NEVER logs full Hint contents; only channel ID
  and outcome.
- The per-engine override (`engine_set_rendezvous_priority`)
  is per-engine, NOT per-network — same privacy reasoning as
  the 3A experimental gate. Allowing per-network overrides
  would expose a censor-side fingerprinting cross-product.

## Failure category mapping

The 3B selector maps Solicit failures into the existing
`failure-taxonomy-v1.md` set (no new V0 category):

| Failure | Category | Notes |
|---|---|---|
| TCP reset / TLS error from fronting | `tcp_reset` / `tls_handshake_failed` | per-channel; surfaces as a route-level failure when ALL channels failed |
| AMP-cache returns 4xx | `subscription_unreachable` | semantics: rendezvous content unreachable |
| Push opt-in disabled | not a failure | the channel returns `ErrChannelDisabled`; Selector skips silently |
| Offline-hint expired or absent | not a failure | Selector skips silently |
| All channels failed | route burns | classifier reason: `rendezvous_unavailable` (cosmetic mapping; underlying category is whatever the *last* channel returned) |

## Soak coverage

Three new scenarios at 3B; see
`test-rigs/distribution-failure/scenarios/`:

- `snowflake-rendezvous-fallback.json` — drives the priority
  channel as blocked; asserts hedge fires at t=4s and a lower-
  priority channel wins.
- `snowflake-broker-burn.json` — all channels fail; asserts
  the route burns under 2G and auto-promotion fires per the
  2G thresholds.
- `push-rendezvous-opt-in.json` — drives the push opt-in
  toggle through default-OFF / ON / vault-profile-rejected.

`--scenarios v2-superset` whitelist widens 14 → 17 at 3B.

## ABI surface change (Phase 3B)

3B adds **two** release ABI symbols:

```
engine_set_rendezvous_priority(const char* json_array) -> int
engine_set_push_rendezvous_enabled(int enabled)        -> int
```

Both persist in secrets KV (`rendezvous_priority` and
`push_rendezvous_enabled`). Both default to "use bundle" /
"OFF" at engine_init. The flags survive session epochs.
`engine_set_push_rendezvous_enabled` returns -1 in the
`vault` storage profile (high-risk users; hard rule, not
togglable).

`engine_export_diagnostics` widens at 3B with:
- `rendezvous_priority: [string]` — always present.
- `rendezvous_channel: string` — winning channel for the
  active route, OR absent for non-Snowflake routes.
- `push_rendezvous_enabled: bool` — always present.

Release surface: 42 → **44**. Engine version bumps to
`daal-core 0.7.1+v3-transport`.

## Locked invariants

- Channel taxonomy is a closed list of 5; new channels are
  roadmap-level decisions.
- Hedged selection at 4 s is locked at v1.
- Per-engine override is per-engine, not per-network.
- Per-route AND per-network winning-channel persistence.
- Push channel default OFF; vault profile rejected.
- Project never operates a rendezvous registry; all channels
  are publisher-operated.
- The Selector is pure (no global state outside the netmem
  callback); the engine layer wires it.

## Carry-overs

- 4-second hedge interval tuning → 3-Soak.
- Per-channel cooldown ledger → 3-Soak.
- Sixth channel (e.g., LibP2P pubsub, BitTorrent-DHT) → V4
  research track.
- WASM-loaded channels → 3E (`transport_module` family may
  ship its own channel impls).
