# MASQUE Ladder — v1

**Phase:** 3C
**Status:** Locked at 3C.
**Roadmap line:** V3.3 — "MASQUE ladder (HTTP/3 → HTTP/2 → Lifeline)."
**Engine version:** `daal-core 0.7.2+v3-transport`.
**ABI release surface:** 44 → **45** (one new symbol, append-only).

---

## Scope

Adds `masque` as a **single transport family with three sub-modes**. The
engine selects a sub-mode per route per session through a private,
deterministic cascade that consults: an optional per-engine override, the
user's mode (2D), the per-network MASQUE sub-mode hint (netmem), the
2C UDP probe outcome on the active network, and the 2G burn classifier.

MASQUE is **opportunistic**. The engine never auto-promotes a network
whose only available family is `masque`; the auto-promotion detector
(2G) ignores masque-only networks. MASQUE coexists with the existing
families and the path manager's standard trust + budget rules apply
unchanged.

---

## Sub-mode taxonomy (closed at v1)

The set is closed at v1. A 4th value is a roadmap-level decision and
requires:

1. A new entry in `core/transports/masque.AllSubmodes()`.
2. A widening of the chooseSubmode cascade.
3. A fresh soak run.

| ID                  | Substrate                                             | Notes                                                              |
|---------------------|-------------------------------------------------------|--------------------------------------------------------------------|
| `masque_h3_quic`    | HTTP/3 over QUIC (RFC 9298 UDP-over-HTTP/3)           | Best path when the active network passes the 2C UDP probe.        |
| `masque_h2_connect` | HTTP/2 Extended CONNECT (RFC 8441 + MASQUE extension) | Falls back here when UDP fails or h3_quic burns.                  |
| `masque_lifeline`   | TCP-only, byte-clamped, bulk refused                  | Bottom rung; integrates with `lifeline-strict` budget rules (2D). |

The diagnostics surface emits the chosen value via the
`masque_submode` field; the engine-pinned override (or empty)
appears under `masque_submode_override`. Both fields are
**always present** in `engine_export_diagnostics`; both are
enumerable (one of three values + `""`); neither carries a URL
or IP.

---

## Sub-mode chooser cascade

The cascade is a private switch inside
`core/transports/masque/masque.go::chooseSubmode`. It is a pure
function — no I/O, no clock, deterministic given inputs.

**Inputs:**
- `route.Mode` — current user mode from 2D.
- `route.UDPProbeOK` — 2C per-network UDP probe outcome.
- `route.LastUsedSubmode` — netmem hint (3C addition, see
  `specs/network-memory-v1.md`).
- `route.H2Burned` — 2G classifier signal for `masque_h2_connect`
  on this route in the current session.
- `override` — engine-pinned value from
  `engine_set_masque_submode_override` (empty = "no override").

**Order:**

1. **Override set + valid** → use override. The lifeline-strict
   clamp at step 2 still applies: a user who pins `masque_h3_quic`
   while in `lifeline-strict` is clamped down to `masque_lifeline`.
2. **`mode == "lifeline-strict"`** → hint `masque_lifeline`. The
   override wins if set; otherwise this step pins the rung.
3. **Netmem hint in v1 list** → start at the recorded sub-mode.
   Out-of-list values are silently dropped (defence in depth).
4. **`UDPProbeOK == true`** → `masque_h3_quic`.
5. **`UDPProbeOK == false`** → `masque_h2_connect`.
6. **Post-pick adjustment.** If `H2Burned == true` AND
   `mode ∈ {lifeline, lifeline-strict}` AND chosen ==
   `masque_h2_connect` → drop to `masque_lifeline`.

The choice is **per-route per-session**. On disconnect the engine
discards the in-session pick; the netmem hint (step 3) survives
session epochs and biases the next session's start rung.

---

## Engine ABI

Phase 3C adds **one** new release ABI symbol.

```
engine_set_masque_submode_override(submode: string) -> int
```

- Returns `0` on success, `-1` on engine-not-initialised, `-3` on
  unknown sub-mode.
- Empty string CLEARS the override (engine returns to the auto
  cascade).
- Persisted in secrets KV under `masque_submode_override`;
  survives session epochs.
- Accepted in BOTH the `keystore` and `vault` storage profiles.
  MASQUE has no FCM/APNS surface, so the 3B vault-rejection
  pattern does not apply.
- Per-engine, NOT per-network. The cross-product would be a
  fingerprint surface (same reasoning as 3A's experimental gate
  and 3B's rendezvous priority override).

The gomobile facade is `EngineSetMasqueSubmodeOverride`. There
are no gomobile-only symbols at 3C.

Release surface count: **45** (3A: 42 → 3B: 44 → 3C: 45).

---

## Bundle format (sbp-v1)

Adds one optional field on `manifest.routes[]`:

```jsonc
{
  "id": "mq-example",
  "transport_family": "masque",
  "scarcity_class": "experimental",
  "config_path": "profiles/mq-example.json",
  "valid_from": "2026-04-28T13:00:00Z",
  "valid_until": "2026-05-05T13:00:00Z",
  "masque_endpoint": "https://m.example.com/.well-known/masque/udp"
}
```

**Validation:**

- `masque_endpoint` MUST NOT appear on routes whose
  `transport_family` is anything other than `"masque"`. Defence
  in depth — keeps the routes[] shape unambiguous. Rejection:
  `ErrMasqueEndpointOnNonMasqueRoute`.
- When present, the URL MUST parse, the scheme MUST be
  `"https"`, the host MUST be non-empty, and the path MUST be
  non-empty (`"/"` alone is rejected). Rejection:
  `ErrMasqueEndpointMalformed`.
- Empty / absent on a `masque` route is NOT a validation error.
  The engine treats it as "no usable endpoint" and filters the
  route at activation time. Matches 3A's
  `family_specific_config` rule.

The rust bundle library mirrors this behaviour at parity time.

---

## Routestore

Adds one column via additive ALTER:

```sql
ALTER TABLE routes ADD COLUMN masque_endpoint TEXT NOT NULL DEFAULT '';
```

`UpsertRoute` carries the field through; old data round-trips
with the empty default. There is no separate persistence column
for the chosen sub-mode at 3C — per-route history is held in
secrets KV under key `masque_submode:<routeID>` (engine-recorded
on every successful Dial), and the dimension that matters for the
chooser cascade is per-network, which lives in netmem.

---

## Network memory

Adds one field to `Snapshot`:

```go
LastUsedMasqueSubmode string `json:"last_used_masque_submode,omitempty"`
```

- Empty string means "no record on this network."
- Restricted to the v1 closed list at write time by the engine
  layer; `core/netmem` itself accepts any value so old data
  round-trips.
- Read by `chooseSubmode` at step 3 of the cascade.
- Written by `core/abi.RecordChosenMasqueSubmode` on every
  successful Dial.
- Participates in `Snapshot.Empty()` so a fresh write does not
  bypass the 30-day Sweep.

---

## Diagnostics

Two new fields (both always present):

```jsonc
{
  "masque_submode": "masque_h3_quic",
  "masque_submode_override": ""
}
```

Empty string for `masque_submode` means "no MASQUE route activated
yet this session." Empty for `masque_submode_override` means "no
override set — auto cascade in effect."

Neither field carries URLs, IPs, or any user-identifying data.
The fields are enumerable: one of three constants + `""`.

---

## Failure taxonomy

The new failure surfaces are **cosmetic mappings** under existing
V0 categories — no new V0 categories are created. Phase 3C
locks:

| Cosmetic surface          | V0 category mapped to     | When it fires                                                |
|---------------------------|---------------------------|--------------------------------------------------------------|
| `masque_h3_blocked`       | `udp_unavailable`         | h3_quic Dial fails because UDP is suppressed mid-session.    |
| `masque_h2_blocked`       | `tls_handshake_failed`    | h2_connect Extended-CONNECT fails at TLS or HTTP/2 layer.    |
| `masque_lifeline_blocked` | `tcp_reset`               | lifeline-rung TCP socket is reset by the censor.             |

The cosmetic labels surface in the diagnostics ring buffer; the
V0 category is what the path manager consumes for cooldown +
trust state machinery.

---

## Locked invariants for 3C

1. **ABI append-only.** +1 release symbol; 0 removed; 0 renamed.
2. **MASQUE is opportunistic.** Auto-promotion (2G) NEVER promotes
   a network whose only available family is `masque`.
3. **Sub-mode is per-route-per-session.** Netmem only biases the
   *start* rung of the next session.
4. **Override is per-engine, NOT per-network.** Same fingerprint-
   surface argument as 3A and 3B.
5. **Lifeline rung respects 2D's `lifeline-strict` budgets.** Bulk
   refused; byte caps tighter; the strict mode clamps even an
   explicit override down to the lifeline rung.
6. **Closed sub-mode list (3).** A 4th value is a roadmap decision.
7. **`UpsertRoute` MUST NOT clobber engine-recorded state.** The
   per-network netmem hint and per-route secrets-KV record are
   never overwritten by a bundle re-import.
8. **Diagnostic `masque_submode` is enumerable.** Never URLs / IPs.

---

## Tests

| Package                         | New tests | Notes                                                          |
|---------------------------------|-----------|----------------------------------------------------------------|
| `core/transports/masque`        | ~7        | chooseSubmode cascade, override clamping, dialer routing.      |
| `core/routestore`               | +1        | 3C round-trip + UpsertRoute non-clobber.                       |
| `core/netmem`                   | +1        | RecordLastUsedMasqueSubmode + Empty() + 3B/3C coexistence.     |
| `core/abi`                      | ~7        | symbol 45, override daaltion, diagnostics shape, RecordChosen.|
| `bundle/go/bundle`              | ~5        | endpoint round-trip, non-MASQUE rejection, malformed URL.      |
| `bundle/go/publisher`           | ~4        | `masque-bridge` subcommand.                                    |
| Soak driver                     | builds    | 2 new scenarios; v2-superset 17 → 19.                          |

All previous V1 / V2 / 3A / 3B tests stay green.

---

## Handover to 3D

Phase 3D receives:
- A MASQUE substrate Conjure-class transports can ride on (Conjure
  registers the user's flow as MASQUE-shaped traffic the censor's
  middleboxes treat as innocuous HTTP).
- The single-family-multiple-submodes pattern (3 sub-modes, private
  switch) as a reference for refraction's similar shape.
- The `core/transports/masque/` package as a template for `core/transports/<name>/`.

If 3D / 3E end up needing a generalised "ladder" abstraction, the
private chooseSubmode switch lifts out into `core/ladder/` cleanly
(decision deferred at 3C; 3B's hedged-Race + cooldown-ledger seam
in `core/rendezvous/` is the prior art).
