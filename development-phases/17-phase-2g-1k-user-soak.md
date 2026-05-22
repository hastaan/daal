# Phase 2G — V2 Success-Metric Soak (1k Synthetic Clients, Directory-Rotation Comparison)

## Roadmap Coverage

V2 success metric, verbatim from `daal-roadmap-v3.md`:

> Over a 30-day soak test in the lab simulating 1,000 concurrent
> users on an emergency-pool directory of ~50 routes (refreshed
> every 48 hours through a working tunnel), no route is burned
> (defined as: classifier-detected and dropped by the simulated
> DPI) faster than the directory's natural rotation cadence. The
> path manager rotates routes correctly, enforces budgets, and
> surfaces understandable failure reasons. iOS TestFlight build is
> live, re-sign-survivable, and re-distributable through AltStore.

2G is the lab artifact that proves the first sentence. Validates
2A/2A-Polish/2B/2C/2D in aggregate at scale.

A previous draft of this phase doc (April 2026) introduced
hand-picked X/Y/Z thresholds (`X=200MB Y=50 Z=60min`) as the V2
success metric. Those thresholds were **invented in the draft, not
in the roadmap**. The roadmap's actual metric is the
*directory-rotation comparison*: the per-route burn lifetime must
be ≥ the directory's refresh cadence. That is what this rewrite
asserts.

## Goal

**Add** a scale tier on top of the 1.5C blackout-soak rig — do
NOT replace the existing run. The rig now supports two
complementary tiers:

- **Parity tier (regression gate, ALREADY GREEN at 2A):** 5
  scenarios × 2 clients × 30 simulated days × in-engine
  scheduler. Run via `soak-driver run-30d --mode in-engine`. This
  tier stays in CI as a regression gate and MUST keep passing
  through every V2 sub-phase. It is what locks down the
  byte-identical replay parity that 2F's scheduler depends on.
- **Load tier (V2 ship gate, NEW in 2G):** 1000 synthetic
  clients on a shared simulated wall-clock, sharing a 50-route
  emergency-pool directory that refreshes every 48 simulated
  hours, with a DPI-burn classifier. Run via `soak-driver
  run-burn --clients 1000 --duration 30d --directory-refresh 48h
  --pool-size 50`. The pass criterion is the roadmap's:

> **For every route in the directory across the 30-day soak:
> classifier-detected burn time ≥ directory refresh cadence (48 h).**

A route burned at hour 47 is a fail. A route never burned across
the 30 days is a pass. A route burned at hour 49 is a pass (the
client has already received a fresh directory by then).

The path manager must also satisfy the second sentence's three
sub-clauses:

- **Rotates routes correctly** — when a route enters
  `Cooldown:tcp_reset` (or any V0.3 cooldown), the rig observes
  the FSM transition to `Recovery` and successful selection of a
  next route within the shortlist racing window.
- **Enforces budgets** — across all 1000 clients, no client
  exceeds its emergency-class hourly cap (50 MiB) without entering
  `BudgetExhausted`. Aggregate: zero cap violations.
- **Surfaces understandable failure reasons** — every cooldown
  event in `route_health[]` carries a V0.3 category from the
  taxonomy; no `unknown` reasons except in the categories
  explicitly designated for them by the taxonomy.

## Scope

- **`internal/load/`** package — synthesises N clients, each with
  its own scratch state dir and its own soak-engine subprocess.
  Linux process limits already accommodate ~1000; the rig spawns
  in batches of 64 with a back-pressured pool.
- **`internal/burn/`** package — DPI burn classifier. Watches
  per-route `Cooldown:tcp_reset`,
  `Cooldown:tls_handshake_failed`, and
  `Cooldown:tls_sni_or_cert_block_suspected` counters across all
  clients; tags a route as "burned" when the aggregate failure
  rate exceeds 50% on the simulated DPI within a sliding
  10-minute window AND the corresponding simulated-DPI sandbox
  has flipped that route's classifier verdict to "blocked." The
  classifier runs in the rig, not the engine. ABI surface stays
  at **37**.
- **`run-burn`** subcommand — `soak-driver run-burn --clients 1000
  --duration 30d --directory-refresh 48h
  --pool-size 50`. Defaults match the roadmap V2 success metric.
  Other knobs:
  - `--burn-injection-rate` — rate at which the simulated DPI
    decides to burn a route per simulated hour (default
    matches the IRBlock-modelled 1/route/72h).
- **Burn-event driver** — the simulated DPI sandbox burns routes
  on its own cadence (NOT a single-instant burn event). Each
  burn flips that route's classifier from `Healthy` to
  `BlackHole+TLSReset+HandshakeStall` for the rest of the
  simulated soak. Clients observe per-V0.3 cooldowns and the
  pathmanager rotates.
- **Per-route metric ledger** — JSONL: each route's first-burn
  time relative to its first-publication time in the directory.
  This is the column the verifier compares against the
  `--directory-refresh` cadence.
- **Per-client metric ledger** — JSONL: each client's mode
  transitions, total bytes survived, observed cooldowns by V0.3
  category, FSM posture transitions across the 30 days.
- **Aggregate verifier** — `soak-driver verify-burn --in <runDir>`
  computes:
  - **Primary metric (roadmap-canonical):** for every route, the
    interval `firstBurn - firstPublish` MUST be ≥ the directory
    refresh cadence (48 h by default). Any route that fails this
    fails the run.
  - **Secondary metric (rotation correctness):** for every
    client, every observed cooldown MUST be followed within
    `pathmanager.shortlistRaceTimeout` (default 8 s) by either a
    successful next-route selection or a transition to
    `NoRoute` / a permitted terminal posture.
  - **Tertiary metric (budget enforcement):** zero cap violations
    across all 1000 clients across the 30 days.
  - **Quaternary metric (failure-reason coverage):** every
    cooldown event carries a V0.3 category; no `unknown` outside
    the V0.3-permitted slots.
  Exits non-zero if ANY of the four metrics is missed.
- **No new release ABI**. Surface stays at **37**.
- **Spec**: new `specs/v2-success-metric-v1.md`; amend
  `specs/blackout-soak-rig-v1.md` to document the scale tier.

## Out of scope (deferred)

- **Real-network testing** (live DPI sandboxes). Roadmap V4.
- **GPU / parallel scenario sharding**. The 1000-client / 30-day
  soak takes about 90 minutes on a developer laptop in simulated
  time; further speedup is unnecessary at this stage.
- **Mobile clients** in the 1000-client soak. Linux only at 2G.
- **Auto-promotion to `lifeline-strict` on burn detection.** A
  follow-up phase or a 2G-Polish item; the roadmap does not
  require it for the V2 success metric. The 1000-client soak
  measures the *engine's* survivability, not the *user's*
  decision to escalate posture.
- **The X/Y/Z thresholds** that an earlier draft proposed
  (`X=200MB Y=50 Z=60min`) are explicitly NOT part of this phase.
  They were not in the roadmap; introducing them would move the
  goalposts from the directory-rotation comparison to a
  fixed-magnitude bar.

## Implementation Details

### Load harness

```go
package load

type Pool struct {
    ConcurrencyLimit int      // default 64
    Engine           string   // path to daal-soak-engine -tags soak binary
    StateDirRoot     string
    Clock            *clock.Clock
}

func (p *Pool) Spawn(n int) ([]*client.Client, error)
func (p *Pool) Shutdown() error
```

Per-client state dirs: `<StateDirRoot>/c-NNNN/`. Process pool is
back-pressured via a semaphore so no more than `ConcurrencyLimit`
soak-engine processes are alive at once.

### Burn classifier

```go
package burn

type Detector struct {
    WindowMinutes      int      // sliding window, default 10
    AggregateFailRate  float64  // default 0.50
}

type RouteVerdict struct {
    RouteID         string
    FirstBurnAt     time.Time   // simulated wall-clock
    FirstPublishAt  time.Time   // when the directory first listed it
    BurnInterval    time.Duration
}

type Aggregate struct {
    DirectoryRefreshCadence time.Duration
    RouteVerdicts           []RouteVerdict
    PassByDirectoryRotation bool          // primary metric
    RotationCorrectnessPass bool          // secondary
    BudgetEnforcementPass   bool          // tertiary
    FailureReasonCoverage   bool          // quaternary
}
```

The detector consults the engine's `engine_export_diagnostics`
output (already exposed) and the rig's simulated-DPI sandbox
classifier verdicts. A route is "burned" when the per-route
aggregate failure rate exceeds the threshold AND the simulated DPI
has flagged the route as blocked (so we don't false-positive on a
client-side network blip).

### Burn event (continuous, not single-instant)

```go
// internal/burn/sandbox.go
type Sandbox struct {
    BurnRatePerRoutePerHour float64 // default ~0.014 (1/72h, matching IRBlock model)
    Style                   string  // "tls-reset" | "handshake-stall" | "blackhole" | "all"
}
```

The sandbox decides each simulated hour whether to burn each
not-yet-burned route, with a rate-tunable Bernoulli draw.

### Verifier

```
soak-driver verify-burn --in <runDir>
```

Walks the per-route ledger; for every route asserts
`burnInterval >= directoryRefreshCadence`. Walks the per-client
ledger; asserts the secondary, tertiary, and quaternary metrics.
Writes `aggregate.json` and exits non-zero on any failure.

### Output layout

```
<runDir>/burn/
  config.json                  # the run config (cadence, pool size, burn rate)
  c-0001/                      # per-client artifacts (existing)
  ...
  c-1000/
  routes/
    route-NNNN.json            # per-route burn ledger
  aggregate.json               # the verifier's output
  metrics.csv                  # per-route + per-client rows for spreadsheet analysis
  README.md                    # auto-generated summary
```

The `redact` subcommand handles the new layout (it already strips
IPs and URLs; metrics.csv has neither).

## Testing Requirements

- `internal/load/` unit tests — pool back-pressure, deterministic
  client IDs, clean shutdown.
- `internal/burn/` unit tests:
  - Detector with synthetic FSM logs; threshold tuning regression
    test (hard-coded canned input asserts exact verdict).
  - Sandbox with seeded RNG produces a reproducible burn schedule
    for parity comparison.
- Smoke run: `soak-driver run-burn --clients 100 --duration 7d
  --directory-refresh 48h --pool-size 50` finishes in < 10
  minutes, all four aggregate metrics pass.
- Full run: `soak-driver run-burn --clients 1000 --duration 30d
  --directory-refresh 48h --pool-size 50` is the V2
  entry-criterion run; documented but not CI-gated. A green
  result is required to ship V2.
- All previous tests green.
- `nm` count still **37**.

## Exit criteria

1. `internal/load`, `internal/burn` packages green.
2. `run-burn --clients 100 --duration 7d` smoke green; all four
   aggregate metrics pass.
3. **`run-burn --clients 1000 --duration 30d` ALL FOUR METRICS
   PASSED** on a developer machine. Run output ships as
   `runs/v2-success-metric-<date>.tar.zst` (redacted).
4. The primary metric — `for every route, burn interval ≥
   directory refresh cadence` — is verifiably the criterion the
   verifier checks; no hand-picked X/Y/Z replaces it.
5. **The existing parity tier still PASSES.** `soak-driver
   run-30d --mode in-engine` ALL 5 SCENARIOS PASSED, on the
   same engine binary that produced the load-tier run. The
   parity tier is a regression gate, not optional; if it
   regresses, 2G does not exit even if the load tier passes.
6. `specs/v2-success-metric-v1.md` shipped; rig spec amended.
7. CI's existing soak smoke unchanged (no new CI cost). The
   load-tier run is documented but NOT CI-gated.

## Handover to Phase 2E

Phase 2E receives:
- A V2 metric whose iOS bring-up can reuse the same
  directory-rotation comparison (the same 48 h cadence applies on
  iOS after `Libbox.xcframework` lands).
- A burn classifier that already understands FSM transition logs;
  iOS just plumbs the same diagnostics through
  `NEPacketTunnelProvider`.
- The closing soak before the V2 ship gate. Cross-cutting items
  CC.1 / CC.2 / CC.7 / CC.8 are scheduled around the 2G run.

## Provenance note

The earlier draft of this doc proposed `X=200MB / Y=50 / Z=60min`
as the V2 success metric. Those thresholds were not in the
roadmap. They were a reasonable interpretation of "lifeline-mode
behaviour under burn pressure" — but the roadmap's actual metric
is **the directory-rotation comparison**, which is what this
rewrite asserts. The X/Y/Z thresholds, if useful at all, belong
in a *secondary* dashboard for human inspection, not as the ship
gate.
