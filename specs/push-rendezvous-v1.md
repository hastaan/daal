# Push Rendezvous V1 — FCM/APNS Channel

## Status

Locked at Phase 3B. The fifth rendezvous channel in
`specs/rendezvous-channels-v1.md`. Off by default; opt-in;
hard-disabled in the `vault` storage profile (high-risk user
class).

## Roadmap coverage

V3.2 fragment: *"Push notification (FCM/APNS for diaspora-
operated relays)."* The roadmap names the channel but defers
the threat model to the implementing phase. This spec is that
threat model.

## Why opt-in and not default

A push-notification rendezvous channel registers a device
identifier (FCM token / APNS device-token) with a third party
(Google / Apple) and a publisher-operated registry. Three
properties make this a higher-risk channel than the others:

1. **Identifier persistence.** FCM/APNS tokens are stable
   across reboots and persist until the platform invalidates
   them. A subpoena or cooperative request to Google/Apple
   could reveal the device-to-publisher mapping.
2. **Platform-side metadata.** Push payload delivery is
   logged by the platform vendor. The PAYLOAD is encrypted
   end-to-end (the publisher signs; the engine verifies),
   but the FACT of delivery is observable.
3. **Vendor cooperation risk.** Both Google and Apple have
   precedent for honouring nation-state requests in target
   geographies.

The roadmap's threat model does not allow these risks to be
default-on. 3B locks: opt-in, vault-rejected, publisher-
operated registry only.

## Protocol

### Registration (opt-in flow)

1. User toggles push rendezvous ON via the platform UI. The
   platform calls `EngineSetPushRendezvousEnabled(1)` (gomobile
   facade) or `engine_set_push_rendezvous_enabled(1)` (cshared).
2. The engine refuses if `storage_profile == "vault"`. Returns
   -1; UI shows an explanatory error.
3. The platform layer obtains a fresh FCM (Android) or APNS
   (iOS) device token via the platform SDK.
4. The platform hands the token to the engine via a NEW
   gomobile-only entry point `EngineSetPushDeviceToken(string)`.
   The engine stores it in secrets KV under
   `push_device_token`. The token is NEVER logged, NEVER
   appears in diagnostics, NEVER round-trips through cshared.
5. The engine reads the active bundle's
   `rendezvous_hints[].push_registry_url` (publisher-operated)
   and registers `(token, publisher_key_hex)` with that URL
   over the active tunnel.
6. Registration is best-effort and idempotent. A failed
   registration is retried at the next 1.5A subscription
   refresh.

The platform never communicates directly with the registry —
the engine does, through the active tunnel. This avoids
out-of-tunnel observability and ensures the registry sees a
tunneled IP, not the user's real IP.

### Inbound rendezvous

1. The publisher operator sends a push notification with a
   small payload: a base64-encoded `RendezvousHintEntry`
   (channel_id + payload + signature_hex) per
   `sbp-v1.md`'s top-level `rendezvous_hints[]` shape.
2. The platform layer hands the payload to the engine via
   `EngineDeliverPushPayload([]byte)`.
3. The engine verifies the signature against the SAME
   publisher key that signed the active bundle. Mismatched
   keys are silently dropped; verified hints land in the
   `push` channel's pending-hint slot, ready for the next
   Solicit.

### Deregistration

1. User toggles push OFF. Engine deletes
   `push_device_token` and `push_rendezvous_enabled` keys
   from secrets KV.
2. Engine sends a deregistration request to the registry
   (best-effort) over the active tunnel.

## Hard rules (any violated = ABI returns -1)

- The flag is rejected in the `vault` storage profile.
- The token is NEVER logged.
- The token NEVER appears in `engine_export_diagnostics`.
- The token is NEVER round-tripped through the cshared ABI.
  The setter is gomobile-only because the cshared surface is
  consumed by toolchains we don't fully audit (Tauri sidecar,
  embedded; FCM/APNS native bindings live above the gomobile
  layer).
- The PROJECT does not run a registry. Every registry URL is
  publisher-supplied through `rendezvous_hints[].push_registry_url`.
- Publishers MAY require the registry URL to be a TLS-pinned
  endpoint; the engine honours TLS pins from the bundle.
- Inbound payloads not signed by a key present in the
  current trust set are dropped silently.

## Engine vendoring

3B vendors:

- **Server-side helpers (registration handshake protocol):**
  `firebase.google.com/go/v4/messaging` — provides struct
  definitions for the FCM topic-message shape we register
  against. The engine itself is the CLIENT; it does not run
  an FCM server. We use the library only for shape parity
  with publishers' server code.
- **APNS payload verifier:** `github.com/sideshow/apns2` — for
  shape parity with Apple's notification format. The engine
  never connects to APNS; it only DECODES inbound payloads
  the platform layer hands it.

Both libraries are isolated to `core/rendezvous/push.go` and
its test files. They are NOT compiled into release builds
that omit push (`-tags no_push_rendezvous`); in such builds
the channel returns `ErrChannelDisabled` and is silently
skipped by the Selector.

## Bundle fields

`rendezvous_hints[]` entries with `channel_id == "push"`
carry an additional field:

- `push_registry_url: string` — publisher-operated
  registration endpoint. Validated as `https://` at parse
  time.
- `push_topic: string` — FCM topic / APNS topic. Free-form
  string; no engine-side validation beyond non-empty.

## Diagnostics

Always-present:
- `push_rendezvous_enabled: bool`

Never present (privacy):
- The device token.
- The FCM/APNS topic.
- Inbound payload contents.

## Failure mapping

| Failure | Engine behaviour | User-visible |
|---|---|---|
| Push opt-in disabled | Channel skipped silently | nothing |
| Vault profile + opt-in attempt | ABI returns -1 | UI error: "Push rendezvous is unavailable in high-security mode." |
| Registry URL not reachable | Retry at next refresh; route burns through other channels | nothing (transparent) |
| Inbound payload signature invalid | Dropped silently | nothing (silent drop is the security posture) |
| Token expired (FCM/APNS rejected) | Engine clears token; UI prompts re-opt-in | "Push rendezvous expired — re-enable in Settings." |

## Soak

`push-rendezvous-opt-in.json` scenario at 3B drives:
- Default-OFF posture.
- Opt-in flips ON; assert persistence across simulated session
  epoch.
- Vault storage profile + opt-in attempt asserts ABI returns -1.
- Inbound signed payload is accepted; mismatched key dropped.

## Privacy invariants

- The vault profile is hard-rejected; this is not togglable.
- The token is gomobile-only; no cshared exposure.
- The registry is publisher-operated; the project never runs
  one.
- All registry traffic goes through the active tunnel.
- Inbound payloads use the same trust ladder as bundles.

## Out of scope

- A project-operated push registry (never).
- Web Push (W3C) — different threat model; V4 research.
- Removing the FCM/APNS vendor dependencies — 3B accepts the
  size cost; future hardening MAY extract them.

## Carry-overs

- 3-Soak measurement of push delivery latency vs
  domain-fronted broker latency.
- Token rotation cadence — currently relies on platform
  invalidation; explicit rotation is a V4 deliverable.
