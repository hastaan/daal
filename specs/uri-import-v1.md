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
  - AmneziaWG `.conf` (auto-detected, case-insensitively, via the 1.x
    `Jc/Jmin/Jmax/S1/S2/H1..H4` or 2.0 `S3/S4/I1..I5/J1..J3/ITIME`
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
| `vless://...security=tls...`                        | `other`         |
| `vless://` with `security=none` or no `security`    | refused (`plaintext_refused`) |
| `vmess://` (`security` none/zero only with TLS)     | `other`         |
| `trojan://`                                         | `other`         |
| `ss://` (method `none`/`plain` refused)             | `shadowsocks`   |
| `hy2://` / `hysteria2://`                           | `hysteria2`     |
| `tuic://`                                           | `tuic`          |
| Clash entry `type: vless` with a REALITY public key | `vless-reality` |
| Clash entry `type: trojan`                          | `other` (both `bundle/go/uri` and `core/refresh`) |
| Clash entry `type: vmess` (tls, network and opts carried) | `other`    |
| WireGuard `.conf` without Amnezia fields            | `wireguard`     |
| AmneziaWG `.conf`, junk fields only (see below)     | `wireguard`, notice `amneziawg_downgraded` |
| AmneziaWG `.conf`, any other Amnezia field          | `amneziawg` (unsupported), notice `amneziawg_unsupported` |
| Tor `bridge` line                                   | `tor-bridge`    |

`other` is never selected by the automatic connect (`core/abi`
`autoCandidatesLocked`, refused `manual_only`); it connects when the
person picks it. `amneziawg` is refused even when picked
(`connect_refused: family_unsupported`): every attempt would be a plain
WireGuard handshake to a server that drops it.

A Trojan server reached through a pasted link is never `websocket-tls`:
that family is Daal's own VLESS+WebSocket tier and carries its
`stable` badge. `core/refresh`'s Clash reader converts entries with
`uri.ProfileFromClashEntry`, so a Clash subscription gets the same
outbound and family as the URI importer.

UDP-gated families (Hysteria2, TUIC, MASQUE, WireGuard, AmneziaWG) are
flagged downstream by `engine.BuildSingBoxConfig`.

## Engine compatibility (sing-box 1.13.12)

Every outbound the importer emits must pass the engine's strict option
parse (`singjson.UnmarshalExtendedContext[option.Options]`, unknown
fields rejected). `core/engine` `TestEveryImportedOutboundParses`
(`-tags singbox`) runs every accepted vector in
`bundle/go/uri/testdata/import_vectors.json` through it. The rules:

- REALITY: `spx` (spiderX) is dropped (`OutboundRealityOptions` has no
  such field; the server never checks it). `fp` defaults to `chrome`
  (the REALITY client requires uTLS). `pbk` must be a 32-byte
  base64url key and `sid` at most 8 hex bytes, or the link is refused
  (`link_malformed`).
- VLESS `encryption`: never written. `none` is accepted; anything else
  (Xray VLESS encryption) is refused (`encryption_unsupported`).
- `flow`: only `xtls-rprx-vision` is carried, and only with no
  transport block (raw TCP under TLS or REALITY); over ws, grpc or
  httpupgrade it fails at dial and is refused. `xtls-rprx-vision-udp443`
  and every other flow are refused (`flow_unsupported`).
- VMess `scy` (Clash `cipher`): `auto` (default), `aes-128-gcm`,
  `chacha20-poly1305`, `aes-128-cfb` are carried; `none` and `zero`
  (no encryption; `zero` also no authentication) only under TLS,
  otherwise refused (`plaintext_refused`); anything else is refused
  (`encryption_unsupported`). VMess `tls` other than `tls`/empty is
  refused (`transport_unsupported`).
- Shadowsocks method `none`, `plain` or `dummy` is refused
  (`plaintext_refused`; SIP008 and Clash entries are skipped and
  counted). A Clash `ss` entry with a `plugin` is refused
  (`transport_unsupported`): dropping the plugin would dial bare
  Shadowsocks.
- Clash REALITY `short-id` gets the same hex, at most 8 bytes, check as
  `sid`.
- `alpn`: split on commas (`h2,http/1.1` is two protocols).
- `fp`: honoured on VLESS, Trojan and VMess TLS. An unknown name becomes
  `chrome`; `none` means no uTLS (except REALITY).
- `type`: `tcp`/`raw` (no transport block), `ws` (`path`, `host`, Xray
  early data `?ed=N` in the path or as `ed=` becomes `max_early_data` +
  `early_data_header_name: Sec-WebSocket-Protocol`), `httpupgrade`
  (`path`, `host`; `?ed=` stripped, sing-box has no early data there),
  `grpc` (`serviceName`; VLESS only). Refused
  (`transport_unsupported`): `xhttp`, `splithttp`, `h2`, `http`, `quic`,
  `kcp` and any unknown value, and Trojan `type=grpc`. A transport the
  engine cannot carry is never downgraded to plain TCP.
- `headerType=http` on TCP is refused (`header_type_unsupported`).
- Trojan `security=reality` and VLESS legacy `security=xtls` are refused
  (`transport_unsupported`); Trojan `security=none` is refused
  (`plaintext_refused`).
- Hysteria2 port hopping: a port list or range in the authority
  (`host:443,20000-50000`) or `mport=` becomes `server_ports` entries
  `"start:end"` (the only shape sing-quic's `ParsePorts` accepts), with
  `server_port` set to the first port and `hop_interval` from
  `hop_interval`/`hopInterval` (seconds or a Go duration), default
  `30s`, raised to `5s` (Hysteria's floor) when lower. The authority is rewritten before `url.Parse`, which cannot
  read a port list. The signed-endpoint guard that refuses
  `server_ports` (`bundle.CheckOutbound`) applies only to RelayPack
  routes; a pasted link is wrapped in a non-RelayPack share bundle and
  never meets it.
- Hysteria2 `insecure=1`/`true` is refused (`insecure_refused`):
  certificate checking off lets anyone on the path be the server.
  `pinSHA256` is not mapped: Hysteria pins the whole certificate,
  sing-box's `certificate_public_key_sha256` the key. Clash
  `skip-cert-verify` is ignored (the check stays on).

## Refusals

A refused link returns an error wrapping one of the `uri.Err*`
sentinels; `uri.RefusalCode(err)` gives its stable token:

| Token                     | Meaning |
|---------------------------|---------|
| `transport_unsupported`   | this build cannot dial the link's transport |
| `header_type_unsupported` | TCP HTTP-header camouflage |
| `flow_unsupported`        | a VLESS flow other than `xtls-rprx-vision` |
| `encryption_unsupported`  | VLESS encryption other than `none` |
| `plaintext_refused`       | no TLS (or a cipher that encrypts nothing): every destination would cross the network in clear |
| `insecure_refused`        | the link turns certificate checking off |
| `link_malformed`          | missing or unusable key, port or port list |

Error text never quotes the link, a credential or a host: every scheme
parses through `parseLink`, which reduces `url.Parse` errors to their
class, and link values that reach an error (a `type=`, `headerType=`,
`flow=` value) pass through `safeToken`. In a multi-line subscription a
refused line is counted in `Provenance.WarningCount` and skipped.

## AmneziaWG

sing-box 1.13.12 has no AmneziaWG support. A server accepts a plain
WireGuard handshake only when the conf's Amnezia fields are junk-only:
`Jc/Jmin/Jmax`, with any `S1..S4` at `0` and `H1..H4` at `1..4`
(WireGuard's own values). Such a conf is imported as `wireguard` with
`Provenance.Notice = "amneziawg_downgraded"`. It connects only where
WireGuard is not blocked, and every attempt sends a WireGuard
handshake, so it must not be tried automatically; this build has no
per-route "only when the person picks it" flag (today the only thing
keeping it out of automatic connects is that `wireguard` is
experimental). Every other conf (non-neutral `S`/`H`, or any 2.0 field)
is imported as `amneziawg`, which this build labels unsupported, with
`Provenance.Notice = "amneziawg_unsupported"`. Both carry
`DroppedParams` and an English `Downgrade` sentence.

## Who runs the server

A pasted link, subscription or conf points at someone else's server.
Whoever runs it sees every destination the route carries. The import
screen says so: "This server is run by whoever sent you the link."

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
