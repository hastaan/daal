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
person picks it. A route stored manual-only (a pasted WireGuard conf)
is refused before that, as `chosen_only`. `amneziawg` is refused even when picked
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
`bundle/go/uri/testdata/import_vectors.json` through it, and
`TestEverySubscriptionRouteParses` does the same for what
`core/refresh` stores from a subscription body (base64, URI list,
Clash, SIP008) built from the same vectors. The rules:

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
  `skip-cert-verify: true` on a `hysteria2` or `tuic` entry is refused
  the same way.
- TUIC `allow_insecure=1` / `insecure=1` (or `true`) is refused
  (`insecure_refused`) for the same reason. TUIC and Clash
  hysteria2/tuic `alpn` is split like every other ALPN list.
- VLESS (`security=tls`), Trojan and VMess (with TLS) links that turn
  the certificate check off are refused (`insecure_refused`), for the
  reason hy2 `insecure=1` is: `allowInsecure`, `allow_insecure` or
  `insecure` set to `1`, `true` or `yes` (VMess: the same keys in its
  JSON, as a string, a bool or a number), and VMess
  `skip-cert-verify`. Clash `skip-cert-verify: true` on a `trojan`
  entry, a non-REALITY `vless` entry, or a `vmess` entry with
  `tls: true` is refused the same way. Where there is no certificate
  to check the switch means nothing and is ignored: a REALITY link
  (the server is checked by its REALITY key), a VMess link without TLS.
  `allowInsecure=0` / `false` is not a refusal.

## Refusals

A refused link returns an error wrapping one of the `uri.Err*`
sentinels; `uri.RefusalCode(err)` gives its stable token. The token is
also in the error TEXT as `uri: <token>` (for example
`vless: type=xhttp: uri: transport_unsupported`), so a host that only
sees the error string (`engine_uri_import`) can read it by matching
`uri: ([a-z_]+)$`. The tokens are stable: renaming one breaks every
host that shows it (`TestRefusalCodesAreStable`). An input that is not
a link of any known kind is not a refusal: it is `uri.ErrNoMatch`
("not understood"), with no token.

| Token                     | Meaning | Raised for |
|---------------------------|---------|------------|
| `transport_unsupported`   | This build cannot dial the link's transport. | `type=` xhttp, splithttp, h2, http, quic, kcp or any unknown value; Trojan `type=grpc`; Trojan `security=reality`; VLESS `security=xtls` or any unknown security; VMess `tls` other than tls; a Clash `ss` plugin |
| `header_type_unsupported` | The link disguises TCP as HTTP (`headerType=http`), which this build cannot do. | `headerType=` anything but `none` on raw TCP |
| `flow_unsupported`        | The link uses a VLESS flow this build cannot dial. | any flow other than `xtls-rprx-vision`, including `xtls-rprx-vision-udp443`; Vision over ws/grpc/httpupgrade |
| `encryption_unsupported`  | The link uses an encryption mode this build does not have. | VLESS `encryption` other than `none`; an unknown VMess cipher |
| `plaintext_refused`       | The link has no encryption: every site you visit would cross the network in clear. | VLESS or Trojan `security=none` (or absent for VLESS); VMess `none`/`zero` without TLS; Shadowsocks `none`/`plain`/`dummy` |
| `insecure_refused`        | The link turns off the server's certificate check, so anyone on the path could pose as the server. | hy2 `insecure=1`; TUIC `allow_insecure=1`; VLESS (tls), Trojan, VMess (tls) `allowInsecure`/`allow_insecure`/`insecure` on; Clash `skip-cert-verify: true` on hysteria2, tuic, trojan, vless (not REALITY), vmess (tls) |
| `link_malformed`          | The link is incomplete or damaged (a key, port or port list is missing or unusable). | bad URL, missing credential, bad port, bad REALITY key or short id, bad hy2 port list or hop interval |
| `manual_only`             | The route may be dialled only when the person picks it, and this build has nowhere to keep that. | Reserved and stable. Not raised by `core/abi` URIImport since wave 2: it stores the flag (see "Pasted WireGuard confs"). A host that cannot store it raises it. |

`ParseURI` lower-cases the scheme before dispatch (`VLESS://…` is
`vless://…`; RFC 3986 §3.1): messengers and phone keyboards capitalise
the first letter of a pasted line. Only the scheme changes.

Error text never quotes the link, a credential or a host: every scheme
parses through `parseLink`, which reduces `url.Parse` errors to their
class, and link values that reach an error (a `type=`, `headerType=`,
`flow=` value) pass through `safeToken`. In a multi-line subscription a
refused line is counted in `Provenance.WarningCount` and skipped. A
subscription read by `core/refresh` lists one token per refused entry,
in body order, in `ParsedSubscription.Refusals`; the refused entry
keeps its positional route id so the ids after it do not move.

## AmneziaWG

sing-box 1.13.12 has no AmneziaWG support. A server accepts a plain
WireGuard handshake only when the conf's Amnezia fields are junk-only:
`Jc/Jmin/Jmax`, with any `S1..S4` at `0` and `H1..H4` at `1..4`
(WireGuard's own values). Such a conf is imported as `wireguard` with
`Provenance.Notice = "amneziawg_downgraded"`. It connects only where
WireGuard is not blocked, and every attempt sends a WireGuard
handshake, so it must not be tried automatically: the profile carries
`Profile.ManualOnly = true` ("dial only when the person picks it"). The
family stays `wireguard` because that is what goes on the wire. A host
that stores the route must keep the bit and the path manager must skip
the route in an automatic connect even with experimental routes on; a
host that cannot store it must not import a ManualOnly profile as an
ordinary route. Every other conf (non-neutral `S`/`H`, or any 2.0 field)
is imported as `amneziawg`, which this build labels unsupported, with
`Provenance.Notice = "amneziawg_unsupported"`. Both carry
`DroppedParams` and an English `Downgrade` sentence.

## Pasted WireGuard confs (wave 2)

`engine_uri_import` accepts, besides one link, one pasted conf: text
whose first line that is not blank or a comment is `[Interface]` (any
case) goes through `uri.ParseAny(…, "wireguard")` and must hold exactly
one route. A conf the parser cannot read is refused `link_malformed`
(the parser's own text, which can quote a value, is not passed on).

- Every pasted WireGuard conf (plain, or AmneziaWG downgraded:
  `ManualOnly`) is stored **manual-only**: `core/routestore` column
  `routes.manual_only` (migration: `INTEGER NOT NULL DEFAULT 0`;
  `RouteRow.ManualOnly`). The flag is written BEFORE the import, in
  the route's meta (`secrets_kv` `route-meta:<route_id>`,
  `routestore.RouteMeta`), and `UpsertRoute` ORs it into the row, so
  the row is never stored without it whichever path finishes the
  import (at once, after the trust prompt, after a restart). It is
  sticky: no upsert clears it. If the meta cannot be written the paste
  is refused.
- `core/abi` `autoCandidatesLocked` refuses a manual-only route first,
  before the family and experimental rules, with `chosen_only`
  (experimental routes on or off). The person can still pick it. The
  route summary carries `manual_only: true`.
- An `amneziawg_unsupported` conf is refused `transport_unsupported`:
  this build cannot dial it. Nothing of it is kept.

## A pasted route's name (wave 2)

The link's own name (`Profile.Tag`: the `#fragment`, VMess `ps`) is kept
in the same meta, cleaned by `routestore.CleanRouteName` (control, bidi
and other format characters removed, the zero-width joiner kept for
emoji; white space collapsed; at most 48 characters), and shown as the
route's `route_nickname` (`name_from_link: true`) instead of a piece of
the route id. It is used for nothing but display: not in the route id,
the logs, the ordering or any decision. The meta is removed with the
route; a name left by a paste whose import never finished is dropped
after 31 days (a manual-only meta is kept until its route is stored or
deleted). Routes whose publisher is this phone's own sharing identity
carry `pasted_by_you: true`; the identity's fixed display name ("My
Daal") is what `publisher_name` says, and the app titles that group
itself.

## Who runs the server

A pasted link, subscription or conf points at someone else's server.
Whoever runs it sees every destination the route carries. The import
screen says so: "This server is run by whoever sent you the link."

## Trust handling for pasted URIs

A pasted URI has no publisher signature. The receiver path
`engine_uri_import`:

1. Parses the URI (or the WireGuard conf).
2. Writes the route's meta (manual-only, the link's name) when it has
   one.
3. Wraps it in a one-route `.sbp` signed by the device's per-app sharing
   identity.
4. Hands it to the importer.

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
