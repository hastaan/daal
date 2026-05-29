# WebTunnel Route V1

## Status

Locked at Phase 3A. First V3 transport family. Implements Tor
Project's WebTunnel PT (Pluggable Transport) inside the engine
layer. Vendored from `webtunnel` upstream at the version pinned
in the engine's go.mod.

## Roadmap coverage

V3.1 ("WebTunnel-style routes"). Note the roadmap caveat
verbatim: *"WebTunnel currently does not work in Iran (TLS
fingerprint filtering). Either ship it as opt-in for users in
regions where it works, or wait for upstream Tor Project
mitigations. Do not promise it works in Iran in V3 if it does
not."*

3A respects this: WebTunnel ships at Experimental maturity
under `transport-families-v1.md`'s gate, with the locked
Iranian region caveat banner. The user must explicitly opt in
twice — toggle the experimental gate, then accept the
caveat — before WebTunnel routes are selectable in `fa-IR`.

## Wire shape

A WebTunnel route is a TCP/443 HTTPS handshake to a
publisher-chosen endpoint with a publisher-chosen secret URL
path, followed by a WebSocket Upgrade. The path manager treats
WebTunnel as a `tcp-443` family (same UDP-not-required posture
as `vless-reality`).

```
client                                            bridge
  |  TCP SYN -> :443                                |
  |---------------------------------------------- > |
  |  TLS ClientHello (SNI = webtunnel_sni)          |
  |  ALPN = webtunnel_alpn (default ["http/1.1"])   |
  |---------------------------------------------- > |
  |  TLS handshake completes                        |
  |  HTTP/1.1 GET /<webtunnel_secret_path> HTTP/1.1 |
  |  Upgrade: websocket                             |
  |  Sec-WebSocket-Version: 13                      |
  |---------------------------------------------- > |
  |  HTTP/1.1 101 Switching Protocols               |
  | <---------------------------------------------- |
  |  WebSocket frames carry Tor cells               |
  | <===========================================> |
```

If any step before the 101 fails, the route burns under the
2G classifier.

## Bundle fields

`transport_family: "webtunnel"` is accepted in SBP-v1 manifests
per the family taxonomy widening in
`transport-families-v1.md`.

The route's `family_specific_config` object MUST contain:

- `webtunnel_secret_path: string` — the path component the
  bridge expects in the GET line. Validated as URL-path-safe;
  rejected at parse time if it contains `?`, `#`, or `\`.

And MAY contain:

- `webtunnel_sni: string` — SNI sent in the ClientHello.
  Defaults to the route's hostname if absent.
- `webtunnel_alpn: [string]` — ALPN list. Defaults to
  `["http/1.1"]`.

A WebTunnel route MUST have `scarcity_class` set to one of:
`emergency`, `lifeline-only`, `low`, `normal`, `experimental`.
`bulk-capable` is REJECTED at parse time — the WebTunnel
bridge model is not capacity-rated for bulk traffic, and the
roadmap is explicit that WebTunnel is opt-in for the regions
where it works at all.

## Engine handler

Vendored from upstream `webtunnel/main/client` at the engine's
pinned go.mod version. The handler exposes the standard
sing-box outbound interface; no Daal-specific protocol
extensions.

The handler is conditionally compiled. A `-tags no_webtunnel`
build excludes the dependency entirely; in such builds, every
WebTunnel route is filtered as-if `experimental_min_engine_version`
failed (the route is skipped with reason
`family_handler_unavailable`, surfaces in diagnostics, never
crashes).

## Failure category mapping

WebTunnel handshake failures map to the existing
`failure-taxonomy-v1.md` categories — no new categories at
3A:

| Failure | Category | Cooldown |
|---|---|---|
| TCP SYN unanswered | `tcp_connect_timeout` | route 5 min |
| RST mid-TCP-handshake | `tcp_reset` | route 30 min, family 5 min |
| TLS handshake error | `tls_handshake_failed` | family-on-network rotate |
| TLS resets after ClientHello | `tls_sni_or_cert_block_suspected` | family 1 h on this network |
| 101 not received within 5 s after TLS | `tls_handshake_failed` | family-on-network rotate |
| Server returns 4xx/5xx instead of 101 | `auth_failed` | **NO cooldown** — surface to UI |
| WebSocket frame mismatch after 101 | `engine_crash` | restart once; if persistent, fall back family |

The `tls_sni_or_cert_block_suspected` case is the canonical
"WebTunnel doesn't work in Iran" failure mode — the bridge's
TLS fingerprint is filterable by Iranian DPI as of V3 start.
A user opting into WebTunnel from `fa-IR` will most likely see
this category first; the trust-UI explainer modal warns them
of this expected outcome.

## Iranian region caveat (locked en + fa)

```
EN:
  "WebTunnel routes have limited effectiveness in Iran today.
   Iran's DPI filters the WebTunnel TLS fingerprint as of V3
   release. Use only if your other routes are blocked, and
   expect WebTunnel routes to fail fast."

FA:
  «مسیرهای WebTunnel در حال حاضر در ایران اثربخشی محدودی
   دارند. DPI ایران از زمان عرضهٔ V3 اثرانگشت TLS مربوط به
   WebTunnel را فیلتر می‌کند. تنها در صورتی استفاده کنید که
   مسیرهای دیگر شما مسدود شده باشند، و انتظار داشته باشید
   مسیرهای WebTunnel به‌سرعت شکست بخورند.»
```

The banner is informational, not blocking. It is shown ONCE
per WebTunnel route on the route detail screen the first time
the user opens it; never again on that route. The user can
still enable.

## Publisher CLI

`daal-publish webtunnel-bridge` subcommand:

```
daal-publish webtunnel-bridge \
    --hostname bridge.example.com \
    --port 443 \
    --bridge-fingerprint <hex-sha1-of-bridge-cert> \
    --secret-path-bytes 16 \
    --output route.json
```

Output: a `routes[]` JSON object ready to be embedded in an
`.sbp` manifest under `transport_family: "webtunnel"`. The
`secret-path-bytes` flag generates a URL-safe random path of
the requested byte length (default 16). The `bridge-fingerprint`
is the bridge's certificate SHA-1 used in the TLS pinning
clause Tor Project's WebTunnel client requires.

The CLI refuses to mix unsigned and signed routes in the same
manifest (existing publisher-cli-v1 invariant — restated here
for clarity).

## Trust posture

WebTunnel routes inherit the bundle publisher's trust class
without modification. There is NO project-operated WebTunnel
bridge — every WebTunnel route in a Daal bundle is operated
by the publisher who signed the bundle.

A WebTunnel route's trust ladder is identical to any other
1B-era route: Official → Trusted Provider → TOFU friend →
Unknown. The Experimental badge from
`transport-families-v1.md` rides on top — a "Trusted
Provider" WebTunnel route still shows the Experimental badge
on first ship.

## Soak coverage

`webtunnel-handshake.json` scenario at 3A — models the
WebSocket Upgrade handshake under three conditions:

1. **Clean.** Handshake succeeds, route runs normally. Soak
   asserts the route is selectable when the experimental gate
   is on, and shortlist-filtered when the gate is off.
2. **TLS-fingerprint-filtered.** Handshake fails fast at the
   `tls_sni_or_cert_block_suspected` mark. Soak asserts the
   route burns under the 2G classifier and the family enters
   the 1-hour family-on-network cooldown — but does NOT
   classify as bulk-capable for auto-promotion purposes.
3. **Intermittent.** Handshake succeeds 30% of the time;
   classifier eventually burns. Soak asserts the family-level
   cooldown does not over-cooldown when failures are
   intermittent.

The scenario is included in `--scenarios v2-superset` (12 → 14
at 3A) and in the V3 success-metric soak's family-mix table.

## Privacy invariants

- The WebTunnel SNI / ALPN / secret path are publisher-supplied
  and NEVER appear in user-shareable diagnostics.
- The WebSocket Upgrade does not leak any device identifiers.
- A WebTunnel route's failure category is recorded in the
  same redacted format every other family uses — no
  family-specific privacy lever.

## Out of scope

- Operating a WebTunnel bridge ourselves. Daal is a client.
- WebTunnel-over-non-443 ports. The roadmap's posture is
  TCP/443 by default; non-443 ports are a publisher-side
  decision but the engine handler accepts the configured port
  blindly.
- Promotion of `webtunnel` out of Experimental maturity. That
  is a roadmap-level decision after V3 measurement evidence.
