# URI Import v1

## Status

Phase 1C deliverable. Implementation: `bundle/go/uri/`.

## Goal

Accept every external route format the V0 internal-route spec lists, and
produce a sing-box outbound JSON that the engine driver and route store
can consume — without ever leaving the importer/trust path.

## Recognized inputs

Per the user's Phase 1C scope decision:

- Single-URI schemes: `vless://`, `vmess://`, `trojan://`, `ss://`,
  `hysteria2://`, `hy2://`, `tuic://`.
- Multi-line / envelope: base64-encoded multi-line subscription bodies
  (mixed schemes); plain multi-line text with one URI per line.
- Document formats:
  - Clash / mihomo YAML (a minimal hand-rolled YAML reader covering the
    `proxies:` block; we deliberately do not depend on a full YAML
    library).
  - SIP008 JSON (Outline / Shadowsocks).
  - WireGuard `.conf` (wg-quick style).
  - AmneziaWG `.conf` (auto-detected via the `Jc/Jmin/Jmax/S1/S2/H1..H4`
    fields in `[Interface]`).
  - Plain Tor `bridge` lines (obfs4, webtunnel).

## Output shape

Each parser returns a `Profile`:

```go
type Profile struct {
    TransportFamily string         // bundle.TransportFamily strings
    Outbound        map[string]any // sing-box outbound JSON
    Tag             string         // human label parsed from the URI's # fragment
}
```

Plus a `Provenance` describing the input scheme and any vendor extensions
detected (`HadReality`, `HadAmnezia`, etc.).

## Family mapping

| Source                                              | TransportFamily |
|-----------------------------------------------------|-----------------|
| `vless://...security=reality...`                    | `vless-reality` |
| `vless://` without Reality                          | `other`         |
| `vmess://`                                          | `other`         |
| `trojan://`                                         | `other`         |
| `ss://`                                             | `shadowsocks`   |
| `hy2://` / `hysteria2://`                           | `hysteria2`     |
| `tuic://`                                           | `tuic`          |
| Clash entry `type: vless` w/ `network: reality`     | `vless-reality` |
| WireGuard `.conf` without Amnezia fields            | `wireguard`     |
| WireGuard `.conf` with any `Jc/S1/H1..H4`           | `amneziawg`     |
| Tor `bridge` line                                   | `tor-bridge`    |

UDP-gated families (Hysteria2, TUIC, MASQUE, WireGuard, AmneziaWG) are
flagged downstream by `engine.BuildSingBoxConfig`.

## Trust handling for pasted URIs

A pasted URI has no publisher signature. The receiver path
`engine_uri_import`:

1. Parses the URI.
2. Wraps it in a one-route `.sbp` signed by the device's per-app sharing
   identity.
3. Hands it to the importer.

On the importer's first encounter with that identity, the trust prompt
fires with the badge "Pasted by you" (UI label). Subsequent pastes are
silent.

## Subscription header passthrough

`uri.ParseSubscriptionHeaders` extracts the V1-relevant headers from an
HTTPS subscription response when one is fetched: `Subscription-Userinfo`,
`Profile-Title`, `Profile-Update-Interval`, `Support-URL`,
`Moved-Permanently-To`. These are stored alongside the imported routes
for the diagnostics screen; the data does not affect trust or family
classification.

## Privacy invariants

- Parsers are pure functions of their input; they perform no I/O, no DNS
  lookups, no network calls.
- The full URI is preserved in the importer's pending bundle (so the user
  can confirm before import); only the *clipboard preview* in
  `core/share.DetectURIs` is redacted. The redacted preview is surfaced in
  the confirmation UI; the unredacted URI is never logged.
