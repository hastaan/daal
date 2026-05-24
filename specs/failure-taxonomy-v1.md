# Failure Taxonomy v1

## Status

Draft for V0 freeze. Locked enumeration; new categories require a spec revision.

## Purpose

Every failure surfaced in diagnostics, every cooldown trigger, every "Why this route?" explanation refers back to this list.

## Categories

| Category | Meaning | Path-manager behavior | App-facing label |
|---|---|---|---|
| `dns_poisoned` | Resolver returned RFC1918 / known sinkhole / mismatched answer | Mark resolver suspect; switch to bundled DoT/DoH | "DNS appears blocked" |
| `dns_timeout` | Resolver did not respond in 5 s | Try alternate resolver; if all fail → `network_offline` | "DNS not responding" |
| `tcp_connect_timeout` | TCP SYN unanswered for 10 s | Cooldown route 5 min; try next in shortlist | "Connection timed out" |
| `tcp_reset` | RST mid-handshake | Cooldown route 30 min, family 5 min | "Connection blocked" |
| `tls_handshake_failed` | TLS error before app data | Try alternate transport family on same network | "Secure connection failed" |
| `tls_sni_or_cert_block_suspected` | TCP works, TLS resets immediately after ClientHello | Cooldown family 1 h on this network | "Encrypted connection blocked" |
| `udp_unavailable` | UDP probe to known echo target failed | Disable UDP-based families on this network for 2 h | "UDP not available on this network" |
| `quic_unavailable` | UDP works but QUIC handshake fails | Disable QUIC families specifically; keep raw UDP | "QUIC not available" |
| `auth_failed` | Server reachable, credentials rejected | **No cooldown** — surface to UI | "Authentication failed — check credentials" |
| `route_expired` | `valid_until` passed | Disable route; offer refresh path | "Route expired" |
| `publisher_revoked` | Publisher key on revocation list | Mark all publisher's routes revoked; warn | "Provider revoked" |
| `publisher_key_changed` | Bundle signed by new key, no rotation chain | Block import; require user re-confirmation | "Provider key changed unexpectedly" |
| `subscription_unreachable` | Refresh URL not reachable | Use cached profiles; suggest tunneled refresh | "Cannot refresh subscription" |
| `engine_crash` | Engine reported error or died | Restart once; if persistent, fall back family | "Engine error" |
| `bundle_signature_invalid` | `.sbp` signature verification failed | Reject; never auto-retry | "Bundle signature invalid — do not import" |
| `bundle_corrupted` | Bundle parse error | Reject | "Bundle is corrupted" |
| `network_offline` | No network at all | Halt route attempts | "No internet connection" |
| `unknown` | None of the above match | No automatic action; surface raw diagnostic | "Unknown error — see details" |
| `skipped_lifeline_strict` | Refresh attempt skipped because the engine is in `lifeline-strict` and the call is not user-triggered | None — recorded in audit ledger and dropped | not user-facing (audit-only) |

## Critical Rules

- `auth_failed` must never trigger censorship cooldown.
- Categories are not free-form strings; code must reference these constants.
- Adding a category requires a spec revision and a fixture under `test-rigs/censor-lab/fixtures/failures/<category>/`.

## Cross-References

- Censor lab: `specs/censor-lab-v1.md`.
- Field probe: `specs/field-probe-v1.md`.
- Bundle library error mapping: `bundle/go/bundle/errors.go`.
- Distribution channels (Phase 1.5C): `specs/failure-channels-v1.md`.
  The `subscription_unreachable` category is the per-attempt outcome
  produced by the rig's `subscription`, `revocation`, `directory`, and
  `ipfs` channels under StateDrop; it must NEVER cascade into
  `auth_failed` (rule `no_auth_failed_from_blackout` in the soak's
  invariant ledger).
- Per-family failure mapping (Phase 3A and later V3 sub-phases):
  every new transport family MUST map its handshake / runtime
  failure modes onto the categories above; no V3 sub-phase
  introduces a new category. WebTunnel's mapping is canonical
  in `specs/webtunnel-route-v1.md` "Failure category mapping"
  and serves as the template for 3B–3G.
- Snowflake's mapping (Phase 3B) lives in
  `specs/snowflake-route-v1.md` "Failure category mapping".
  Multi-channel rendezvous failures map onto the existing
  categories with NO new V0 category: an "all rendezvous
  channels failed" outcome surfaces as
  `tcp_connect_timeout` (the conservative aggregate) and is
  cosmetically annotated `rendezvous_unavailable` in
  diagnostics for operator legibility — the cooldown ledger
  uses the underlying V0 category. A future spec revision
  MAY promote the cosmetic annotation to a V0 category;
  3B does not.
- MASQUE's mapping (Phase 3C) lives in
  `specs/masque-ladder-v1.md` "Failure taxonomy". The three
  sub-mode failures map onto existing V0 categories with NO
  new V0 category at 3C:

  | Cosmetic surface          | V0 category             | When it fires                                                |
  |---------------------------|-------------------------|--------------------------------------------------------------|
  | `masque_h3_blocked`       | `udp_unavailable`       | h3_quic Dial fails because UDP is suppressed mid-session.    |
  | `masque_h2_blocked`       | `tls_handshake_failed`  | h2_connect Extended-CONNECT fails at TLS or HTTP/2 layer.    |
  | `masque_lifeline_blocked` | `tcp_reset`             | lifeline-rung TCP socket is reset by the censor.             |

  As with 3B, the cosmetic labels surface in the diagnostics
  ring buffer; the V0 category is what the path manager
  consumes for cooldown + trust state machinery.
- The Phase 3D refraction families (psiphon + conjure) map
  onto existing V0 categories with **no new V0 category at
  3D** (locked decision 6 in the 3D spec — cosmetic-only
  widening). Failure surfaces:

  | Cosmetic surface         | V0 category             | When it fires                                                                |
  |--------------------------|-------------------------|------------------------------------------------------------------------------|
  | `psiphon_handshake_fail` | `tls_handshake_failed`  | upstream psiphon-tunnel-core fails its protocol handshake.                  |
  | `psiphon_excluded`       | `route_unsupported`     | route activated on a build with `-tags no_psiphon` (vendor tree absent).    |
  | `conjure_register_fail`  | `tcp_connect_timeout`   | gotapdance fails to register the session through the decoy pool.            |
  | `conjure_phantom_drop`   | `tcp_reset`             | phantom-IP socket is reset by the censor or upstream after binding.         |

  As with 3B/3C, the cosmetic labels surface in the
  diagnostics ring buffer; the V0 category is what the path
  manager consumes for cooldown + trust state machinery.
- The Phase 3E WASM transport family maps onto existing V0
  categories with **no new V0 category at 3E** (locked
  decision 9 in the 3E spec — cosmetic-only widening).
  Failure surfaces:

  | Cosmetic surface              | V0 category             | When it fires                                                                |
  |-------------------------------|-------------------------|------------------------------------------------------------------------------|
  | `wasm_fuel_exhausted`         | `tcp_connect_timeout`   | the module's per-dial fuel budget (1e9 ops) is consumed before connecting.  |
  | `wasm_memory_cap`             | `tcp_connect_timeout`   | the wazero instance hits its 16 MiB memory cap.                              |
  | `wasm_dial_timeout`           | `tcp_connect_timeout`   | the host-side wall-clock dial timeout (5 s) fires.                           |
  | `wasm_host_callback_error`    | `tls_handshake_failed`  | the host-side `dial`/`read`/`write`/`close` callback returns an error.      |
  | `wasm_excluded`               | `route_unsupported`     | route activated on a build with `-tags no_wasm` (wazero compiled out).      |
  | `wasm_kill_switched`          | `route_unsupported`     | the module's sha256 is in the killed-set; refuses to load.                  |
  | `wasm_module_missing`         | `route_unsupported`     | the route's `transport_module_slug` is absent from the loaded bundle.       |

  The dial-outcome cosmetic surfaces (`wasm_fuel_exhausted`,
  `wasm_memory_cap`, `wasm_dial_timeout`,
  `wasm_host_callback_error`) match the closed-enum entries
  exposed in the `last_wasm_module_dial_outcome`
  diagnostic field; `wasm_kill_switched` and
  `wasm_module_missing` fire pre-dial and surface only as
  diagnostics ring-buffer entries.

  Locked at 3E: fuel exhaustion is NOT classified as a
  censorship signal. The route's `consecutive_failures`
  counter increments (the path manager treats it like any
  other `tcp_connect_timeout`), but `wasm_kill_switched_count`
  does NOT increment — a fuel-exhausted module is unloaded
  for the rest of the session, not project-killed.
