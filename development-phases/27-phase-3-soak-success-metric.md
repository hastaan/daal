# Phase 3-Soak — V3 Success-Metric Soak

**Status:** LOCKED at 3-Soak kickoff (post-3F SHIPPED, post-3G Track A filed). Ready for implementation.
**Roadmap line:** V3 success metric — "A new transport family ships to all platforms via a signed `.sbp` bundle without an app update. iOS, Android, and desktop pick it up within 24 hours of publication, gated behind the Experimental flag. Existing trust UI works correctly for the new family. No regression on V1/V2 metrics."
**Engine version (target):** `daal-core 0.9.0+v3-share` (UNCHANGED — verification-shaped phase).
**ABI release surface (target):** **48** (UNCHANGED from 3F).
**Maturity:** Verification gate that closes V3.

## 1 Strategic frame (verbatim from the roadmap)

> "V3 success metric: A new transport family ships to all platforms via a signed `.sbp` bundle without an app update. iOS, Android, and desktop pick it up within 24 hours of publication, gated behind the Experimental flag. Existing trust UI works correctly for the new family. No regression on V1/V2 metrics."

3-Soak is the **verification gate**, not a new transport. It runs the full V3 transport surface (3A→3F, with 3G absent per Track A) through a 1k-client × 30-day burn soak across **three real platform stubs** (Linux, Android, iOS), publishes a fresh `transport_module` mid-soak, and asserts the **5-metric V3 aggregate** (primary + 4 secondaries; mirror of 2G's shape).

## 2 Locked answers

| Question | Locked answer |
|---|---|
| Shipping shape | **C** — Full pre-spec: verification + 5 new V3 scenarios + threshold A-vs-B comparison memo |
| Stub mix | **C** — Build real Android + iOS soak-engine stubs |
| V3 success metric | **C** — 5-metric aggregate mirroring 2G shape (primary + 4 secondaries) |
| V3 closure record | **A** — `specs/v3-closure-v1.md` formal closure record |

## 3 Locked decisions (16 invariants)

1. **No new release ABI symbols.** Surface stays at **48** (the 3F locked surface). 3-Soak is verification only.
2. **Engine `Version` unchanged.** Stays at `daal-core 0.9.0+v3-share`.
3. **Three real platform stubs.** Linux + Android + iOS soak-engine stubs are real binaries; **60% / 35% / 5%** mix.
4. **5-metric V3 aggregate.** Primary + 4 secondaries, all independent. See §6.
5. **Formal V3 closure record.** New `specs/v3-closure-v1.md` records locked surface (48), engine version (0.9.0+v3-share), shipped phases (3A→3F), 3G Track-A not-shipped record, V4 carry-overs.
6. **v2-superset stays at 26.** v3-superset is a NEW selector that subsumes v2-superset and adds 5 V3 scenarios (26 → **31**).
7. **Soft-validation discipline preserved.** A scenario referring to a compiled-out family is skipped, not failed.
8. **`UpsertRoute` non-clobber discipline preserved.**
9. **Auto-promotion threshold A-vs-B carry-over.** Two threshold sets in parallel; produces comparison memo; does NOT change 2G locked defaults at this phase. Memo informs V4 freeze.
10. **Burn-classifier real-DPI mode is OPTIONAL.** Stays simulated if no partner-lab integration exists.
11. **Bulk-capable opt-in cross-product.** 25% ON, 75% OFF.
12. **Experimental-gate cross-product.** 50% ON, 50% OFF.
13. **`State` field removal.** Deprecated `State` diagnostics field removed; consumers on three platforms must read `posture` only. ABI-neutral (field removal does not change symbol count).
14. **No new bundle errors, no new diagnostics fields.**
15. **Position B preserved.** No new telemetry. Soak rig writes locally; nothing leaves the rig host.
16. **V3 closure is the gate to V4.** When 3-Soak passes, V3 is formally closed by `specs/v3-closure-v1.md`; project enters V4+ continuous-research posture.

## 4 Sub-task breakdown (12 sub-tasks)

| #  | Task |
|----|------|
| 0  | Replace pre-spec at `27-phase-3-soak-success-metric.md` with this locked spec |
| 1  | `cmd/daal-soak-engine-android/` — Android stub binary (real Go program; same `core/abi`; GOMEMLIMIT 200 MiB; cellular-jitter sim; doze-mode wake gating) |
| 2  | `cmd/daal-soak-engine-ios/` — iOS stub binary (real Go program; same `core/abi`; GOMEMLIMIT 50 MiB per 2E NE budget; NE wake-transition sim) |
| 3  | `internal/load/platform_mix.go` — 60/35/5 dispatcher; `--platform-mix linux:600,android:350,ios:50` flag |
| 4  | `internal/v3verifier/` — V3 5-metric aggregate verifier (~12 unit tests) |
| 5  | `internal/threshold_compare/` — auto-promotion threshold A-vs-B harness; produces `comparison-memo.md` |
| 6  | 5 new V3 soak scenarios: `v3-cross-platform-pickup`, `v3-experimental-gate-cross-product`, `v3-bulk-capable-cross-product`, `v3-auto-promotion-threshold-A-vs-B`, `v3-mixed-family-directory` |
| 7  | `--scenarios v3-superset` selector (26 → **31**) in `cmd/soak-driver/main.go`; legacy + v2-superset selectors retained verbatim |
| 8  | `core/abi`: remove deprecated `State` diagnostics field; ABI-neutral |
| 9  | Specs: 1 NEW (`specs/v3-success-metric-v1.md`) + 1 NEW closure (`specs/v3-closure-v1.md`) + 1 AMENDED (`specs/blackout-soak-rig-v1.md`) |
| 10 | Comparison memo at `phases of development/27-phase-3-soak-threshold-comparison.md` |
| 11 | Run-as-release-cut: `--scenarios v3-superset` × 3 platforms × `--mode in-engine`; v3-superset GREEN end-to-end |
| 12 | Handover doc + final regression sweep: `nm` count = **48** unchanged; v3-superset GREEN; V3 formally closed |

## 5 Three-platform stub mix

| Platform | Binary | GOMEMLIMIT | Behavioural shape |
|----------|--------|------------|-------------------|
| Linux desktop | `cmd/daal-soak-engine` (existing) | none | desktop refresh; on-demand bundle pull |
| Android | `cmd/daal-soak-engine-android/` (NEW) | **200 MiB** | cellular-jitter sim; doze-mode wake gating; refresh on Wi-Fi only by default |
| iOS | `cmd/daal-soak-engine-ios/` (NEW) | **50 MiB** (per 2E NE budget) | NE wake-transition sim per 2E `engine_lifecycle_event`; aggressive memory caps |

The two NEW binaries import the same `core/abi`; do not fork the engine; build under `-tags soak`; are not shipped to end users; conform to the iOS smoke harness's `--expected-abi-surface 48`.

## 6 V3 5-metric aggregate

### Primary: cross-platform pickup ≤ 24 simulated hours
A `transport_module` published into the directory at simulated time T is activatable on every platform stub by T+24h. "Activatable" = `loaded_wasm_modules` contains the slug AND the route is in `routes[]` with `trust_state ∈ {tofu, trusted, tofu_friend}`.

### Secondary 1: experimental-gate cross-product
Half clients gate-OFF: zero activations of experimental families (`webtunnel`, `psiphon`, `conjure`, `transport_module`). Half gate-ON: at least one activation by end of soak.

### Secondary 2: trust-UI parity
Experimental badge surfaces correctly for every client × family. Per-route diagnostics MUST equal the family's locked maturity per `specs/transport-families-v1.md`.

### Secondary 3: no V1/V2 regression
The full v2-superset (26 scenarios) MUST pass. Inherits 2G's verifier path.

### Secondary 4: per-family burn rate
No transport family burns faster than its directory's natural rotation cadence — same metric 2G's primary used, applied per-family.

## 7 Five new V3 soak scenarios

| Scenario | Duration | Purpose |
|----------|----------|---------|
| `v3-cross-platform-pickup.json` | ~14 days | Drives the primary metric. Mid-soak the publisher rig publishes a fresh `transport_module`; rig asserts every Linux + Android + iOS stub picks it up within 24 simulated hours. |
| `v3-experimental-gate-cross-product.json` | ~14 days | 50% gate-ON, 50% gate-OFF; asserts secondary 1. |
| `v3-bulk-capable-cross-product.json` | ~14 days | 25% bulk-capable opt-in ON, 75% OFF; asserts no regression on either subset. |
| `v3-auto-promotion-threshold-A-vs-B.json` | ~14 days | Two parallel runs with different threshold sets (locked-A: 3 families × 30 min × ladder ≥ 3, the 2G default; tightened-B: 4 families × 20 min × ladder ≥ 4); produces comparison memo. |
| `v3-mixed-family-directory.json` | ~14 days | Route directory carries the locked V3 family mix; asserts the path manager respects per-family budgets, scarcity classes, and trust ladder under load. |

## 8 V3 family-mix in the route directory

| Family | % of routes | Maturity |
|--------|-------------|----------|
| TCP-443 / VLESS-Reality | 30% | GA |
| Hysteria2 | 15% | GA |
| WireGuard | 10% | GA |
| WebTunnel (3A) | 10% | Experimental |
| Snowflake (3B) | 10% | Experimental |
| MASQUE (3C) | 10% | Experimental |
| Psiphon (3D) | 5% | Experimental |
| Conjure (3D) | 5% | Experimental |
| transport_module (3E) | 5% | Experimental |

(Lifeline-relay routes are absent — 3G filed Track A.)

## 9 V3 closure spec content

`specs/v3-closure-v1.md` records:
- **Locked surface**: 48
- **Locked engine version**: `daal-core 0.9.0+v3-share`
- **Shipped phases**: 3A WebTunnel, 3B Snowflake, 3C MASQUE, 3D Psiphon+Conjure, 3E WASM transport, 3F One-tap delegate-share
- **Not-shipped phases**: 3G partner-relay (Track A; locked spec ready for execution if pre-conditions flip)
- **V3 success metric**: PASSED at 3-Soak under the 5-metric aggregate
- **Carry-overs to V4**: auto-promotion threshold tuning per memo; real-DPI burn classifier; partner-relay revisit; per-recipient delegate sub-keys (V4 unlinkability); ML-research transports behind feature flags; UPGen-style experiments
- **What did NOT change at 3-Soak**: ABI surface, engine version, bundle format, routestore schema, trust ladder

## 10 Build matrix at 3-Soak exit

- `cd core && go build ./...` — green
- `cd core && go build -tags no_delegate_share ./abi/...` — green
- `cd core && go build -tags "no_psiphon no_wasm no_delegate_share" ./abi/...` — green
- `cd core && go test ./...` — green
- `cd bundle/go && go build ./... && go test ./...` — green
- `cd cmd/daal-soak-engine && go build -tags soak ./...` — green
- `cd cmd/daal-soak-engine-android && go build -tags soak ./...` — green (NEW)
- `cd cmd/daal-soak-engine-ios && go build -tags soak ./...` — green (NEW)
- `cd test-rigs/distribution-failure/soak-driver && go build ./... && go test ./...` — green
- `nm libdaalcore.so | grep ' T engine_' | wc -l` = **48** (unchanged)
- `soak-driver run --scenarios v3-superset --mode in-engine --platform-mix linux:600,android:350,ios:50` — GREEN end-to-end
- `cmd/daal-ios-smoke --expected-abi-surface 48` — GREEN

## 11 Spec deliverables

**2 NEW:**
- `specs/v3-success-metric-v1.md`
- `specs/v3-closure-v1.md`

**1 AMENDED:**
- `specs/blackout-soak-rig-v1.md`

## 12 Out of scope (deferred to V4+)

- Real on-device runs across 1k devices (operationally unrealistic).
- Real OONI / Censored Planet API integration (live-API integration is V4).
- Auto-promotion threshold change at 3-Soak (memo only; V4 freezes new defaults).
- Partner-relay (3G) — Track A filed; revisit when pre-conditions flip.
- Per-recipient delegate sub-keys (V4 unlinkability work; deferred per 3F locked decision 2).

## 13 Soak run identity

```
run-id = ts-$EPOCH-clients-1000-days-30-seed-42-platforms-linux600-android350-ios50
```

Reruns at `--seed 42` produce byte-identical per-route ledgers (modulo wall-clock noise) on each platform stub.

## 14 Handover to V4+

V4 receives:
- The locked V3 surface (48) and engine version (`daal-core 0.9.0+v3-share`).
- The V3 closure spec at `specs/v3-closure-v1.md` (canonical source of truth for what V3 delivered).
- The auto-promotion threshold comparison memo at `phases of development/27-phase-3-soak-threshold-comparison.md`.
- The 1k × 30d × 3-platform soak ledger as a release artifact.
- The carry-over list (real-DPI burn classifier; partner-relay revisit; per-recipient delegate sub-keys; ML transports; UPGen experiments; refraction partnerships).

V3 closes when 3-Soak's v3-superset is GREEN end-to-end on three platforms AND the closure spec is shipped. The roadmap's V4 section is unchanged.

End — locked at 3-Soak kickoff.
