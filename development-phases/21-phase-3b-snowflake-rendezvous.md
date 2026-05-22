# Phase 3B — Multi-Rendezvous Library + Snowflake Integration

## Roadmap Coverage

V3.2 ("Snowflake-like ephemeral relays"). Two separable parts:
direct Snowflake integration AND a Daal-specific
multi-rendezvous library that abstracts "rendezvous channel"
so ephemeral relays can be discovered through several
fallback channels. Converts "the Snowflake broker is blocked"
from a fatal failure to a degraded mode.

## Goal

Vendor `snowflake/client` and ship a `snowflake` route family
that rendezvouses through any of: domain-fronted broker,
SQS / AMP-cache, push notification (FCM/APNS for diaspora-
operated relays), or offline-bundled rendezvous hints. Treat
the rendezvous-channel abstraction as the architecturally
interesting V3 contribution.

## Scope

### Engine

- **`snowflake` transport family** — uses WebRTC + DTLS + SCTP
  DataChannel. Vendored from upstream `snowflake/client`. The
  family is added to the Phase 3A taxonomy; defaults to
  experimental-gated on first release, promoted to
  general-availability after a V3 measurement window.
- **`core/rendezvous/` package** — new internal package
  providing the `Rendezvous` interface with implementations:
  - `DomainFrontedBroker` — fronted HTTPS request to the
    upstream Snowflake broker URL.
  - `SQSBroker` — per the FOCI 2024 paper; rendezvous via AWS
    SQS queues.
  - `AMPCacheBroker` — Google AMP-cache fronting.
  - `PushNotificationBroker` — opt-in FCM/APNS channel for
    diaspora-operated relays. Disabled by default.
  - `OfflineHintBroker` — reads pre-bundled signed rendezvous
    hints from the active `.sbp`.
- **Selection algorithm.** The engine tries channels in the
  order specified by the bundle's `rendezvous_priority` list.
  First success wins. All-fail returns the standard
  `ErrRouteUnavailable` and the route burns under the 2G
  classifier.

### Bundle format

- New entry type: `rendezvous_hints[]` — signed pre-bundled
  hints that the offline broker can use without any network
  call. Documented in `specs/bundle-format-v1.md`.
- `routes[].family = "snowflake"` accepted.
- `routes[].rendezvous_priority` — optional list of channel
  IDs in selection order.

### Publisher tooling

- `daal-publish snowflake-rendezvous-hint` subcommand
  produces a signed offline hint from a broker URL + signed
  key.
- Documented in `specs/publisher-cli-v1.md`.

### Trust UI

- Snowflake routes show the Experimental badge from 3A on
  first release.
- Diagnostics surface (read-only) shows the active
  rendezvous channel name when a Snowflake route is in use,
  e.g. `rendezvous_channel: domain_fronted_broker`. Absent
  for non-Snowflake routes.

### Push-notification rendezvous (opt-in)

- Off by default. Settings toggle "Receive route hints over
  push" — explicit opt-in.
- The token is registered with a publisher-operated relay
  endpoint, NOT with the project's infrastructure. The user's
  device token is published only to the publisher they
  trust — the project does not run a token registry.
- The push payload is a signed `rendezvous_hint`; decryption
  and verification happen entirely on-device.
- Documented in `specs/rendezvous-channels-v1.md` privacy
  section.

### Soak

- New scenario `snowflake-rendezvous-fallback.json` — drives
  the broker as blocked / rate-limited / clean and asserts
  the engine falls through the channel priority list
  correctly.
- New scenario `snowflake-broker-burn.json` — asserts that
  when ALL rendezvous channels fail, the route burns under
  the standard classifier and auto-promotion fires per the
  2G thresholds.
- `--scenarios v2-superset` whitelist widens 14 → 16.

## Out of scope

- A Snowflake bridge / proxy (Daal is a client; bridges are
  upstream).
- Conjure or refraction (3D).
- Rendezvous channel discovery via app-store search (V4).

## Implementation Details

### ABI surface

Phase 3B adds **zero** release ABI symbols. Snowflake plugs
into the existing path manager and route activation surfaces.
Diagnostics widen additively with `rendezvous_channel`.

Release surface stays at **42**. Engine version stays at
`daal-core 0.7.0+v3-transport`.

### Spec deliverables

- **New:** `specs/rendezvous-channels-v1.md` — the
  `Rendezvous` interface, the locked v1 channel list, the
  selection algorithm, the privacy posture for each channel.
- **New:** `specs/snowflake-route-v1.md` — Snowflake route
  fields, the WebRTC + DTLS + SCTP shape, classifier
  behaviour, the experimental-promotion criteria.
- **Amend:** `specs/bundle-format-v1.md` (rendezvous-hint
  entry type, `rendezvous_priority` field).
- **Amend:** `specs/publisher-cli-v1.md` (rendezvous-hint
  subcommand).
- **Amend:** `specs/transport-families-v1.md` (snowflake
  added to the experimental band).

### Privacy invariants

- **Push-notification rendezvous opt-in.** Off by default.
  When enabled, the token is registered with the publisher,
  not the project.
- **No project-operated rendezvous registry.** All rendezvous
  channels are publisher-operated.
- **Diagnostics `rendezvous_channel` is enumerable**, never
  contains URLs, IPs, or broker addresses.
- **Offline hints are signed by the publisher's key**, same
  trust ladder as the rest of the bundle.

## Testing Requirements

- Engine unit tests: each `Rendezvous` impl, selection
  algorithm, fallback ordering, all-fail behaviour.
- Bundle parser tests: `rendezvous_hints` round-trip; signed
  hint verification; mixed family + hints `.sbp`.
- Publisher CLI tests: `snowflake-rendezvous-hint` subcommand
  generates expected output and signs correctly.
- Soak: both new scenarios PASS in both modes.
- All previous V1/V2 tests green.
- All 3A tests green.

## Exit criteria

1. `core/rendezvous/` package shipped with all 5 channel
   impls.
2. `snowflake` family registered in the 3A taxonomy.
3. Publisher CLI subcommand shipped.
4. Both new soak scenarios PASS.
5. `specs/rendezvous-channels-v1.md` and
   `specs/snowflake-route-v1.md` shipped; existing specs
   amended.
6. `nm` count remains **42**.

## Handover to 3C

Phase 3C receives:
- The taxonomy and experimental gate from 3A.
- The Snowflake working pattern as a reference for adding
  WebRTC-style transports.
- The rendezvous-channel abstraction (3C does NOT use it
  — MASQUE is a single-family ladder — but 3D and 3E may).
