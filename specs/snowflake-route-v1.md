# Snowflake Route V1

## Status

Locked at Phase 3B. Second V3 transport family (after
WebTunnel at 3A). Vendored from `snowflake/client` upstream
at the version pinned in the engine's `go.mod`. Driven by the
`core/rendezvous` Selector defined in
`specs/rendezvous-channels-v1.md`.

## Roadmap coverage

V3.2 ("Snowflake-like ephemeral relays"). Verbatim from the
roadmap: *"Vendor `snowflake/client` Go library. Uses WebRTC +
DTLS + SCTP DataChannel. A Daal route of family `snowflake`
rendezvouses through the broker (domain-fronted or AMP-cache
or SQS, as per upstream)."* 3B respects the roadmap caveat: a
blocked broker is no longer a fatal failure because the
rendezvous-channel abstraction (3B) routes around it.

## Wire shape

A Snowflake route is a WebRTC + DTLS + SCTP DataChannel
session to an ephemeral browser-volunteer relay, set up via a
rendezvous Hint solicited from one of the v1 channels.

```
client                        rendezvous channel             snowflake proxy (volunteer)
  |  Solicit (channel-specific)        |                             |
  |---------------------------------->|                             |
  |                                    |  forward to broker          |
  |                                    |--------------------------->|
  |  Hint{ offer, answer, bridge_fp }  |                             |
  | <----------------------------------|                             |
  |  ICE candidates exchange (in-Hint)                              |
  |  DTLS handshake over UDP                                         |
  | <===============================================================|
  |  SCTP DataChannel carries Tor cells                              |
  | <===============================================================>
```

## Bundle fields

`transport_family: "snowflake"` is accepted in SBP-v1
manifests per the family taxonomy widening in
`transport-families-v1.md` (already widened at 3A).

The route's `family_specific_config` object MAY contain:

- `snowflake_max_peers: int` — number of concurrent volunteer
  relays. Default 1; max 5; values outside the range are
  clamped at parse time.
- `snowflake_keep_local_addresses: bool` — keep ICE local-
  candidate addresses in offer. Default false (privacy).
- `snowflake_unsafe_log: bool` — REJECTED at parse time. The
  upstream library has a field for verbose logging; we
  refuse it.

The route's `rendezvous_priority: [string]` field
(SBP-v1 widening at 3B; see `sbp-v1.md`) lists channel IDs
in fire order. If absent, the engine defaults to
`["domain_fronted_broker", "amp_cache", "sqs", "offline_hint"]`.
`push` is NEVER in the default list — it is opt-in per
`push-rendezvous-v1.md` and only added to the priority list
when the user has opted in AND the bundle declared a push
hint.

A Snowflake route MUST have `scarcity_class` set to one of:
`emergency`, `lifeline-only`, `low`, `normal`, `experimental`.
`bulk-capable` is REJECTED at parse time — Snowflake's
volunteer-relay model is not capacity-rated for bulk traffic.

## Engine handler

Vendored from upstream `snowflake/client` at the engine's
pinned go.mod version. The handler exposes the standard
sing-box outbound interface; no Daal-specific protocol
extensions.

The handler is unconditionally compiled per the 3B
size-budget decision. A future build tag `-tags no_snowflake`
MAY exclude it for size-constrained builds; if so, every
Snowflake route is filtered as-if `experimental_min_engine_version`
failed, identical to the 3A WebTunnel `-tags no_webtunnel`
precedent.

## Failure category mapping

Snowflake-specific failures map to the existing
`failure-taxonomy-v1.md` categories:

| Failure | Category | Cooldown |
|---|---|---|
| All rendezvous channels failed | `tcp_connect_timeout` | route 5 min, family 30 min |
| Hint received, ICE failed | `udp_unavailable` | UDP-family-on-network 2 h |
| ICE OK, DTLS failed | `tls_handshake_failed` | family-on-network rotate |
| DTLS OK, SCTP setup failed | `engine_crash` | restart once |
| Volunteer relay vanishes mid-session | `tcp_reset` | route 30 min |
| Bridge fingerprint mismatch | `auth_failed` | NO cooldown — surface to UI |

## Iranian region caveat

Same gate as WebTunnel: experimental-gated by 3A. UDP
suppression in Iran's stricter phases means Snowflake will
fail-fast at the ICE step with `udp_unavailable`. The
diagnostics surface should make this expected outcome legible.

3B does NOT ship a separate Iranian region caveat for
Snowflake — the generic experimental-family caveat from 3A
applies. A per-route `caveat_fa_ir` (3A field) MAY be set by
publishers who want to override.

## Publisher CLI

`daal-publish snowflake-rendezvous-hint` — see
`publisher-cli-v1.md` 3B amendment. Generates a single
`rendezvous_hints[]` entry signed by the publisher key,
ready to splice into a manifest's top-level
`rendezvous_hints[]` slot.

## Trust posture

Snowflake routes inherit the bundle publisher's trust class
without modification. There is NO project-operated Snowflake
broker — the project consumes the upstream Tor Project
broker, OR a publisher's own broker if the bundle declares
one.

The Experimental badge from `transport-families-v1.md` rides
on top — a "Trusted Provider" Snowflake route still shows
the Experimental badge on first ship. Promotion to
Promotion-candidate or Stable is a roadmap-level decision
after V3 measurement evidence.

## Soak coverage

`snowflake-rendezvous-fallback.json` and
`snowflake-broker-burn.json` at 3B; locked in
`rendezvous-channels-v1.md` test-rig section.

## Privacy invariants

- ICE local-address candidates are NOT included in the offer
  by default (`snowflake_keep_local_addresses: false`).
- The bridge fingerprint NEVER appears in user-shareable
  diagnostics.
- DataChannel payload is opaque to the Daal layer; the engine
  treats it as a pipe.
- A Snowflake route's failure category is recorded in the
  same redacted format every other family uses.

## Out of scope

- Operating a Snowflake bridge ourselves. Daal is a client.
- Running a Snowflake proxy (the volunteer-relay role) inside
  the Daal app. That is a separate program and a separate
  threat model.
- Promotion of `snowflake` out of Experimental maturity.
  That is a roadmap-level decision.
