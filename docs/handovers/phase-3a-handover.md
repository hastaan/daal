# Phase 3A Handover — WebTunnel + transport-family scaffold

**Status:** DONE.
**Engine version:** `daal-core 0.7.0+v3-transport` (was `0.6.0+v2-soak`).
**ABI surface:** release = 42 (was 41); soak = 45.
**New release symbol at 3A:** `engine_set_experimental_families_enabled` at `0x5b4280`.

V3 transport-agility line opens here. 3A delivers the closed
family taxonomy, the experimental gate, the WebTunnel route
shape end-to-end, and the SBP-v1 widening for the four reserved
3B–3G families. ABI is append-only; no removed symbols, no
spec_version bump, no schema migration outside additive ALTERs.

## What shipped

### Specs
- `specs/transport-families-v1.md` (NEW). Closed family
  taxonomy with maturity ladder
  (Experimental / Promotion-candidate / Stable). Per-engine,
  default-OFF experimental gate. Family-level kill-switch
  reservation. Trust-UI rules.
- `specs/webtunnel-route-v1.md` (NEW). WebTunnel wire shape,
  bundle fields, failure-category mapping, Iranian region
  caveat banner (en + fa-IR), publisher CLI shape.
- 8 amendments to existing v1 specs (engine-abi, sbp,
  route-object, routestore, route-budgets, publisher-cli,
  failure-taxonomy, trust-ui).

### Engine (Go)
- `core/routestore/family.go`. Maturity enum +
  `familyMaturity` map. Helpers `FamilyMaturity`,
  `IsExperimentalFamily`, `IsSelectableFamily`,
  `KnownFamilies`. 9 stable + 7 experimental + 1 unhandled.
- `core/routestore/schema.go`. Three additive ALTERs:
  `family_specific_config_json` (default `{}`), `caveat_fa_ir`,
  `experimental_min_engine_version`.
- `core/abi/experimental.go`. `Core` widened with
  `experimentalFamiliesEnabled bool` + `experimentalRoutesSkipped int`.
  Setter / getter / `loadExperimentalFamiliesEnabled` Init
  daaltor. Persists in `secrets_kv` under
  `experimental_families_enabled` ("0"/"1"). Survives session
  epoch and mode change.
- `core/abi/experimental_export.go` (cshared). New release ABI
  symbol `engine_set_experimental_families_enabled(int)`.
- `core/abi/experimental_gomobile.go` (gomobile facade).
- `core/abi/abi.go`. Diagnostics widened with always-present
  `experimental_families_enabled` and snapshot
  `experimental_routes_skipped`.
- `core/pathmanager/family_filter.go`. Pure
  `ExperimentalFilter` + `RankWithExperimentalGate` composing
  the filter step BEFORE trust / budget / network-memory.
  Predicate is injected to keep pathmanager free of routestore
  imports.

### Bundle parser (Go)
- `bundle/go/bundle/types.go`. Family enum widened with
  `psiphon`, `conjure`, `transport_module`, `lifeline_relay`.
  3 new optional `RouteManifestEntry` fields:
  `FamilySpecificConfig` (`json.RawMessage`), `CaveatFAIR`,
  `ExperimentalMinEngineVersion`. New top-level `KillSwitches []KillSwitchEntry`
  reserved slot.
- `bundle/go/bundle/sbp.go`. `validate3AFields`:
  family_specific_config object-shape, semver pin parsing,
  WebTunnel `bulk-capable` parse-time rejection.
- `bundle/go/bundle/errors.go`. Three new errors:
  `ErrFamilySpecificConfigShape`, `ErrInvalidExperimentalMinVersion`,
  `ErrWebTunnelBulkCapable`.

### Publisher CLI
- `bundle/go/publisher/webtunnel.go`. `WebTunnelBridge` helper
  emitting a route stub with locked WebTunnel keys
  (`webtunnel_secret_path` / `webtunnel_sni` / `webtunnel_alpn`).
- `bundle/go/cmd/daal-publish/main.go`. New subcommand
  `daal-publish webtunnel-bridge --url … --out …`. Validity
  default 7d. ALPN default `http/1.1`. Optional caveat /
  min-version overrides.

### Soak rig
- `test-rigs/distribution-failure/scenarios/experimental-gate-respected.json` (NEW).
- `test-rigs/distribution-failure/scenarios/webtunnel-handshake.json` (NEW).
- v2-superset whitelist widened from 12 → 14.
- Soak engine: new `set-experimental-families-enabled`
  JSON-RPC verb; soak driver: new `set_experimental_families_enabled`
  engine-action.

## Locked invariants (carried into 3B)

1. **ABI append-only.** No symbol removals. No flag-byte changes.
2. **Default-OFF experimental gate.** First-run users see only
   stable-maturity routes. Persists across session epochs;
   neither mode change nor network change clears it.
3. **WebTunnel rejects `bulk-capable` at parse time.** A
   bundle that violates this fails verify with
   `ErrWebTunnelBulkCapable` before the engine sees it.
4. **`kill_switches[]` reserved at 3A.** Parser accepts an empty
   array; engine ignores entries until 3E. No spec_version
   bump at 3E because the slot is already reserved.
5. **Experimental skips do NOT enter `SkippedFamilies()`.** The
   2G burn-pressure detector's failure-driven ledger remains
   uncontaminated by gate-OFF filtering. Test:
   `core/abi/experimental_burn_test.go::TestBurnPressureIgnoresExperimentalSkips`.
6. **Iranian caveat banner shown ONCE per route on first
   detail open.** Locale en + fa-IR. UI-side; no engine
   memory mutation.
7. **Closed family taxonomy.** 16 named families + V0 `other`
   carry-over. The path manager refuses to select `other`.
8. **Per-engine, NOT per-network.** A per-network experimental
   decision was deliberately rejected to avoid a censor-side
   privacy-fingerprint cross-product.

## Tests added

- `core/routestore/family_test.go` — 5 tests
- `core/routestore/store_test.go` — 2 tests (3A round-trip + backward compat)
- `bundle/go/bundle/v3a_test.go` — 8 tests
- `core/abi/experimental_test.go` — 6 tests
- `core/abi/experimental_burn_test.go` — 1 test
- `core/pathmanager/family_filter_test.go` — 6 tests
- `bundle/go/publisher/webtunnel_test.go` — 3 tests

All `core`, `bundle/go`, and `soak-driver` test suites GREEN.

## Carry-overs into 3B and beyond

- **3B (Snowflake + multi-rendezvous).** The taxonomy already
  reserves `snowflake`. 3B promotes it to Promotion-candidate
  once a soak signal lands. Implementation lands in
  `core/transports/snowflake/` (TBD).
- **3C (MASQUE ladder).** Reserves `masque` already.
- **3D (refraction hooks).** `psiphon` + `conjure` reserved.
- **3E (WASM transport slot).** `transport_module` reserved.
  Locks `kill_switches[]` semantics here without a
  spec_version bump.
- **3F (one-tap share + delegate keys).** Already implemented
  upstream of 3A (commit 46323f3); 3A does not touch its surface.
- **3G (lifeline relay).** `lifeline_relay` reserved.
  Conditional gate per `phases of development/26-...`.
- **3-Soak.** V3 success-metric soak. Auto-promotion threshold
  tuning vs. OONI / Censored Planet remains a 3-Soak deliverable.

## Known gaps (deliberate, deferred)

- **Real WebTunnel handshake.** The soak scenario exercises the
  surface (gate, ranking, diagnostics) but does NOT yet stand
  up a real WebTunnel origin. End-to-end handshake against a
  partner-operated bridge lands in 3-Soak.
- **`other` family selectability.** Unhandled at the route
  store; not selectable. V0 forward-compat: parser still
  accepts it.
- **Per-route caveat surfacing in client UIs.** The route
  store carries `caveat_fa_ir`; client-android and
  client-desktop trust-UI work to render it ships in the
  client phases (not engine).

— End 3A handover.
