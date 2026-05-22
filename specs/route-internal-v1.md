# Internal Route Representation v1

## Status

Draft for V0 freeze.

## Purpose

Every imported route format normalizes into:

1. sing-box outbound JSON, and
2. a Daal metadata wrapper.

sing-box JSON is canonical because it can express the required transport families without inventing a new tunnel protocol.

## Daal Metadata Wrapper

```json
{
  "route_id": "local-uuid",
  "transport_family": "vless-reality",
  "engine": "sing-box",
  "source_type": "trusted_provider",
  "publisher_id": "fingerprint-hex",
  "scarcity_class": "normal",
  "modes_allowed": ["lifeline", "normal"],
  "expires_at": "2026-05-25T12:00:00Z",
  "config": {}
}
```

## Supported Import Families

The representation must be broad enough for:

- sing-box outbound JSON,
- Clash/mihomo YAML,
- base64 multiline subscriptions,
- `vless://`,
- `vmess://`,
- `trojan://`,
- `ss://`,
- `hysteria2://` and `hy2://`,
- `tuic://`,
- SIP008,
- WireGuard `.conf`,
- OpenVPN `.ovpn` where supported by policy,
- AmneziaWG extensions,
- Tor bridge lines.

## Transport Families

Initial enum values:

```text
vless-reality
naive
websocket-tls
hysteria2
tuic
snowflake
webtunnel
masque
shadowsocks
tor-bridge
wireguard
amneziawg
other
```

UDP-first families must be markable as UDP-gated. This includes Hysteria2, TUIC, MASQUE/H3, WireGuard, and AmneziaWG.

## Security Constraints

- Do not store full subscription URLs in the route object.
- Do not store destinations visited through the route.
- Do not store exact timestamps where hour buckets are sufficient.
- Preserve publisher provenance.
- Keep trust score separate from network score.
