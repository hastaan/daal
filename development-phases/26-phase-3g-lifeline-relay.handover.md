# Phase 3G — Optional Partner-Operated Lifeline Relay — Handover

**Status: NOT-SHIPPING (Track A).**
**Date:** 2026-04-28.
**Engine version (unchanged):** `daal-core 0.9.0+v3-share`.
**ABI release surface (unchanged):** **48** (the 3F locked surface).
**Outcome class:** EXPECTED per roadmap §V3.7 — "If no partner is
ready, the relay simply does not ship; Daal continues to function
fully without it."

## 1 Why 3G did not ship

Phase 3G is gated on **five hard pre-conditions** (locked spec
§3). All five are unmet today.

| # | Pre-condition | Verification artifact (expected location) | Today's status |
|---|---|---|---|
| 1 | Partner identified — signed MOU on file | `docs/partner-mou-{partner}.md` | **MISSING** |
| 2 | Partner accepts liability — clause cited verbatim in spec | `specs/lifeline-relay-v1.md` § "MOU clause" | **MISSING** (spec itself does not yet exist) |
| 3 | External audit complete — report URL referenced | `client-desktop/docs/lifeline-relay-audit-summary.md` | **MISSING** |
| 4 | Threat model document published | `specs/lifeline-relay-threat-model-v1.md` | **MISSING** |
| 5 | Kill-switch tested in lab — soak scenario PASSES | `test-rigs/distribution-failure/scenarios/relay-kill-switch.json` + canonical regression `signed_delta_disables_partner` | **MISSING** |

Filesystem verification (`Glob` against the five expected paths,
2026-04-28) returned zero matches. No partner has been identified at
the time of this handover, so the upstream pre-conditions (audit,
threat-model, kill-switch test) cannot be reached either; the failure
chain terminates at pre-condition 1.

This is the EXPECTED outcome of the roadmap when no partner is ready.
The locked spec at `26-phase-3g-lifeline-relay.md` is implementation-
ready; the moment a partner appears and the five pre-conditions flip
true, 3G can be picked up without re-locking.

## 2 What landed in this cycle

```
phases of development/26-phase-3g-lifeline-relay.md          REPLACED (locked spec; Mixed-track shape)
phases of development/26-phase-3g-lifeline-relay.handover.md NEW (this doc)
```

No code changes. No new files in `specs/`. No new soak scenarios. No
engine version bump. No `routes` or `secrets_kv` schema changes. The
3F shipped surface is unmodified.

## 3 Invariants preserved through 3G

- ABI append-only: surface stays at **48** (the 3F locked surface).
  No symbols added, none removed.
- Engine `Version` unchanged: `daal-core 0.9.0+v3-share`.
- 3F's six new bundle errors, three new diagnostics fields, single
  routestore ALTER (`redistribution_policy`), and `core/delegate`
  package — all unchanged.
- Trust ladder unchanged: no `partner_relay` class today; partner-
  trust is a Track-B-only addition.
- `secrets_kv` namespaces unchanged: no `relay_killed:*`, no
  `relay_partner_pinned:*` today.
- Position B (no telemetry) preserved.
- V0 failure category set unchanged.

## 4 Build matrix at 3G close (Track A)

| Command | Result |
|---|---|
| `cd core && go build ./...` | green (3F matrix, re-confirmed) |
| `cd core && go build -tags no_delegate_share ./abi/...` | green |
| `cd core && go build -tags "no_psiphon no_wasm no_delegate_share" ./abi/...` | green |
| `cd core && go test ./...` | green |
| `cd bundle/go && go build ./... && go test ./...` | green |
| `cd cmd/daal-soak-engine && go build -tags soak ./...` | green |
| `cd test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...` | green |
| `nm /tmp/libdaalcore.so \| grep ' T engine_' \| wc -l` | **48** (locked target; unchanged from 3F) |

Re-running the full 3F matrix at 3G close serves only as a sanity
check that the 3G research cycle touched no code; the matrix has not
moved since 3F's regression sweep.

## 5 What a future Track-B execution must do

A future cycle that picks up 3G when pre-conditions flip true MUST,
in order:

1. Document the five pre-condition artifacts (links to MOU, audit
   report, threat-model document; soak scenario added; partner key
   minted via hardware-token in CC.4 ceremony).
2. Execute sub-tasks 2 → 11 from the locked spec §5 in order.
3. Bump engine `Version` to `daal-core 0.10.0+v3-relay` (NOT
   `0.9.1`; the additional release surface justifies a minor bump per
   the existing convention at 3E).
4. Add the two release ABI symbols (`engine_lifeline_relay_fetch`,
   `engine_lifeline_relay_status`); confirm
   `nm libdaalcore.so | grep ' T engine_' | wc -l` = **50**.
5. Ship the 4 new soak scenarios and widen `--scenarios v2-superset`
   from **26** to **30**.
6. File a fresh handover overwriting this doc, status `SHIPPED
   (Track B)`.

The locked spec is intentionally append-only relative to 3F: a future
Track-B execution does not re-open any 3F invariant, does not
reshape any 3F-shipped surface, and does not require migrating any
existing routestore data.

## 6 Handover to 3-Soak

3-Soak (V3 success-metric soak) inherits from this handover:

- ABI release surface: **48** (the 3F locked surface).
- Engine version: `daal-core 0.9.0+v3-share`.
- v2-superset scenario count: **26** (the 3F locked count).
- Trust ladder: unchanged from 3F.
- The relay surface does not exist today; 3-Soak runs without
  consulting any partner.

3-Soak proceeds with V3 closing at 3F. The roadmap's V3 success
metric ("a new transport family ships to all platforms via a signed
`.sbp` bundle without an app update; iOS, Android, and desktop pick
it up within 24 hours of publication, gated behind the Experimental
flag; existing trust UI works correctly for the new family; no
regression on V1/V2 metrics") was already met at 3E (WASM transport
slot) and reinforced at 3F (one-tap delegate-share). The relay was
always optional.

## 7 Reopening 3G

If a partner organisation later signs an MOU and the audit completes,
3G can be reopened by:

1. Re-reading `26-phase-3g-lifeline-relay.md` (the locked spec; not
   re-locking).
2. Confirming all 5 pre-conditions in §3 of the locked spec.
3. Executing sub-tasks 2 → 11.
4. Filing a fresh handover that overwrites this doc with `SHIPPED
   (Track B)` status and the corresponding `nm = 50` line.

No re-spec is required at reopening. The locked spec is binding.

End — Track A not-shipping handover, filed at 3G close.
