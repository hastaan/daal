# TunnelDialer v1

## Status

**Phase 1.5B.** Implemented in `core/refresh/dialer.go` (Go side) and
`core/abi/tunnel.go` (ABI side). Wired via the new ABI function
`engine_set_tunnel_socks` (33rd function; append-only).

## Goal

Route subscription and revocation refresh fetches through the active
sing-box tunnel when one is up, and through direct TCP when one is not.

## Mechanism

1. The host (Tauri Rust on desktop, VpnService glue on Android) starts
   a sing-box sidecar with a SOCKS5 inlet on a loopback port.
2. The host calls `engine_set_tunnel_socks(host="127.0.0.1",
   port=<random>, "", "")`.
3. The Go side installs a process-wide `globalDialer` factory in
   `core/refresh/dialer.go`. Every subsequent
   `Refresher.Refresh` / `RevocationRefresher.RefreshAll` constructs
   a `bootstrap.TunnelDialer` pointed at that endpoint.
4. The host calls `engine_set_tunnel_socks("", 0, "", "")` to clear
   the override (reverts to direct dial).

## ABI signature

```c
int engine_set_tunnel_socks(const char* host, int port,
                            const char* username, const char* password,
                            char* out, int out_len);
```

| Param | Notes |
|---|---|
| `host` | IPv4/IPv6 literal or hostname. Empty string clears the override. |
| `port` | 1..65535. Zero is rejected unless host is also empty. |
| `username`, `password` | Reserved for V2; Phase 1.5B's local SOCKS inlet is unauthenticated on loopback. The fields are accepted but ignored. |

Response JSON (always written to `out`, even on success):

```json
{ "applied": true, "endpoint": "127.0.0.1:17891" }
```

Cleared:

```json
{ "applied": true, "endpoint": "" }
```

## Privacy invariants

- The function NEVER accepts or returns a destination URL.
- `username` and `password` are not logged.
- Cleared on `engine_shutdown` so a subsequent `engine_init` in the
  same process starts fresh.
- Audit rows still record `via_tunnel: bool` (existing behavior); they
  do not record the SOCKS endpoint.

## Failure modes

| Outcome | When | Caller behavior |
|---|---|---|
| `applied=true, endpoint=""` | host empty | refreshes use direct dial |
| `applied=true, endpoint="..."` | host non-empty, port valid | refreshes use TunnelDialer |
| return code -1 | port out of range | UI surfaces "invalid port" |

The `bootstrap.TunnelDialer` itself falls back to its DirectFallback
when SOCKS connect fails, so a transient sing-box restart does not
permanently break refresh.

## Test coverage

- `core/refresh/dialer_test.go::TestRefreshHonorsGlobalDialer` —
  installs a global dialer, runs a real `Refresher.Refresh` against a
  canned vless body, asserts `ViaTunnel=true` and that the per-instance
  Dialer field was NOT consulted.
- `core/abi/tunnel_test.go::TestSetTunnelSocksInstallsAndClearsDialer`
  — walks the install/clear lifecycle and asserts the response JSON
  shape.
- `core/abi/tunnel_test.go::TestTunnelDialerRoutesThroughSocks` —
  spins up a tiny SOCKS5 listener, calls `SetTunnelSocks`, then dials
  through the installed global dialer and confirms the listener
  observed a SOCKS5 handshake (proves traffic does NOT go direct).
- `client-shell/tauri/daal-desktop-core/tests/engine_load.rs::engine_loads_and_sets_tunnel_socks`
  — dlopens the actual `libdaalcore.so` from CI and exercises the
  full Rust → C ABI → Go refresh-dialer plumbing.

## Future work (1.5C)

- Wire Android's VpnService to call `engine_set_tunnel_socks` once
  it brings up its own SOCKS5 inlet on `127.0.0.1`. The Compose
  Subscriptions screen will then show `via_tunnel: true` for the same
  reason desktop does.
- V2: per-process SOCKS5 auth tokens (the fields are already in the
  ABI for forward compatibility).
