# Telemetry audit — what the engine measures, what it invents, and what selection will need

Compiled 2026-08-18 on branch `solidify-before-selection`, ahead of the
smart-route-selection wave. Line references point at the tree at the time of
writing; re-grep before trusting them.

**The question this document answers is not "do we have telemetry".** It is:
*when the selector is wired, will it be deciding on measurements or on
decoration?* A selector fed absent or fabricated signals does not fail
quietly — it produces a confident wrong answer and then renders its reasoning
to the user, which is worse than no selector at all.

**The short answer: PARTLY, and it was NOT partly before this pass.** Two of
the three inputs `selection.Decide` reads had no producer anywhere in the
tree. One of them now does. The gap list is in §5.

*Reconciled 2026-08-18 against `docs/capability-matrix.md` (reachability),
`docs/platform-reality.md` (per-OS truth) and `docs/backlog-post-45.md`
(what is owed). This file is authoritative for "is this number measured";
the others defer to it on that question and it defers to them on theirs.
Where any of the four disagrees with the tree, the tree is right.*

---

## 1. The inventory

### 1.1 Legend

| Column | Meaning |
|---|---|
| **Produced** | the code that computes the value |
| **Stored** | where it lives |
| **Restart** | does it survive the process dying |
| **Read by** | production consumers only — tests and fixture generators do not count |

### 1.2 Connection outcomes — the load-bearing signal

| Signal | Produced | Stored | Restart | Read by |
|---|---|---|---|---|
| connect success | `abi.SetRoute` → `pm.Connected()` | pathmanager map **+ `routes.last_success_bucket` (NEW)** | **yes (NEW)** | `d2_summaries.observeRoute`, `RouteSummaryDisplay.Proven`, `AvailableRoutes` sort |
| connect failure + V0.3 category | `abi.SetRoute` → `diagnostics.Classify` → `pm.Failed()` | pathmanager maps **+ `routes.last_failure_{bucket,category}`, `consecutive_failures`, `cooldown_until` (NEW)** | **yes (NEW)** | as above, plus `abi.activeNetworkSignals` (NEW) |
| per-route cooldown expiry | `pathmanager.perRouteCooldown` | pathmanager map **+ `routes.cooldown_until` (NEW)** | **yes (NEW)** | `observeRoute`, `pm.CanAttempt`, `pm.NextRoute` |
| per-family cooldown + ladder step | `pathmanager.Failed` → `FamilyCooldownStep` | `Manager.familyCooldown` / `familyEscalation` (memory) | **no** | `SkippedFamilies()` → diagnostics, `burnpressure.Evaluate` |
| posture (8-state) | `pathmanager.SetPosture` | memory | no | diagnostics `posture`, GUI connect badge |

Before this pass every row above said "memory / no". The engine classified a
failure on every attempt and **threw the classification away at process exit**.
That is why `health_pct` was `null` and `proven` was `false` on every route in
every install, forever — see the honesty note at the top of
`core/abi/d2_summaries.go`, which correctly predicted that "the moment the
Wave-3 outcome hook lands, this starts returning true and the number lights up
on its own." This pass is that hook.

### 1.3 Refresh / scheduler

| Signal | Produced | Stored | Restart | Read by |
|---|---|---|---|---|
| subscription refresh outcome | `refresh/subscription.go:272` | `subscriptions.last_refresh_{bucket,outcome}`, `last_good_refresh_bkt` | yes | `scheduler.Plan` cadence gate, `abi.ListSubscriptions` → GUI |
| revocation check time | `refresh.RevocationRefresher` | `publishers.last_revocation_check` | yes | `scheduler.Plan` |
| last bootstrap refresh | `refreshExecutor.RefreshBootstrap` (success only) | `secrets_kv["scheduler:last-bootstrap-refresh"]` | yes | `scheduler.Plan` |
| last budget reset | `refreshExecutor.RefreshBudgetReset` | `secrets_kv["scheduler:last-budget-reset"]` | yes | `scheduler.Plan` |
| per-RelayPack freshness state (successes, failures, consecutive-failure count, jitter) | `core/refresh` relaypack path | `secrets_kv["freshness:<id>"]` | yes | `scheduler.Plan` via `selection.ShouldAttemptRefresh` |
| **last netmem sweep (NEW)** | `refreshExecutor.SweepNetworkMemory` | `secrets_kv["scheduler:last-netmem-sweep"]` | yes | `scheduler.Plan` |
| tick count / last tick | `scheduler.Tick` | memory | no | `engine_scheduler_status` |

This is the **healthiest** part of the telemetry surface. Every cadence gate
reads a value some executor actually wrote, and the values survive restart —
which matters on a phone, where the process is killed constantly.

**Backlog B3 was already fixed and the backlog was wrong about it.** The claim
"`core/abi/scheduler.go:167` — no real last bootstrap refresh timestamp;
cadence is approximate" was a stale *code comment* that said the timestamp was
not persisted, sitting three screens above a `PutSecret` on the same key that
had been on the production path all along. The comment is corrected on this
branch. B3 should be struck as **done-by-inspection**, not scheduled.

### 1.4 Diagnostics classification

`core/diagnostics/classify.go` maps a free-form driver error onto a closed
~22-value taxonomy. Two production callers: `engine.Stub.Start` /
`engine_singbox.Start` (into an `Event`), and `abi.SetRoute` (into the FSM and,
now, into the routestore). The mapping is deterministic and well tested.
`IsCensorshipClass` correctly excludes `auth_failed` and `origin_unhealthy`.

**This is the single best-measured thing in the engine, and until this pass its
output was durable nowhere.**

### 1.5 Budgets

| Signal | Produced | Stored | Restart | Read by |
|---|---|---|---|---|
| per-route hourly bytes | `budget.Engine.Add` | `routes.bytes_used_this_hour` + `secrets_kv` cursor | yes | `Engine.Snapshot` → diagnostics `budgets[]`, `pathmanager.Rank` |
| per-session bytes | `budget.Engine.Add` | memory (session IS the boundary — correct) | no | diagnostics |
| budget exhaustion | `budget.Engine.Add` → `ErrExhausted` | FSM `StateBudgetExhausted` | no | `RouteSummaryDisplay.BudgetExhausted` |

**All three are structurally zero in every install.** `budget.Engine.Add` has
exactly one caller in the tree — `proxy.Pipe` — and `proxy.Pipe` has **zero**
production callers (`core/engine/inlet.go:49` mentions it in a comment). The
byte-charging middleware the whole budget subsystem was designed around was
never inserted into a data path.

Consequences, all currently invisible because everything reads zero:
`consumed_bytes` is always 0, `exhausted` is always false, `BudgetExhausted`
never fires, `pathmanager.Rank`'s `consumedFraction` term is always 0, and the
hourly `KindBudgetReset` action rolls over an empty counter every hour of
every day.

### 1.6 Per-network memory (`core/netmem`)

| Field | Written by | Read by |
|---|---|---|
| `Mode` | `abi.captureAndPersist` | `abi.NetworkChanged` step 3 — **real** |
| `BudgetUsage` / `BudgetBucket` | `abi.captureAndPersist` | `budget.Engine.RestoreNetwork` — real, but restores zeros (§1.5) |
| `RouteHealth` | `abi.captureAndPersist` | **nobody.** `NetworkChanged`'s comment says "RouteHealth restore is intentionally additive (see note below)"; there is no note and no restore code |
| `RouteFamilyStats` (incl. FRP-2 `ByRelayPack`) | **nobody** — `selection.Apply` has zero production callers | `selection.LookupHint`, `rankCandidate` |
| `UDPProbeOK` / `UDPProbeAt` / `DNSPoisoned` | **nobody** | nobody |
| `LastWinningRendezvousChannel` | `abi.RecordRendezvousWinner` — which itself has **no caller and no ABI export** | `LookupWinningRendezvousChannel` — **no caller** |
| `LastUsedMasqueSubmode` | `abi.RecordChosenMasqueSubmode` — same, no caller, no export | `LookupLastUsedMasqueSubmode` — **no caller** |

Plus two structural problems above the field level:

**(a) The network ID is a constant.** `netmem.HashID` is correct and privacy-
preserving, but its only production caller is `client-ui/src/App.tsx:147`,
which fires `contract.networkChanged('unknown', '', '')` on the browser
`online` and `offline` events — the same three arguments in both cases. So
`HashID` is evaluated on constant input and returns one fixed bucket for every
network the device has ever joined. There is **no Kotlin or Rust caller at
all**: `grep -rn network_changed --include=*.kt` is empty, so Android — the
platform where Wi-Fi↔cellular roaming is the entire point of the feature —
never supplies a real network identity either. Per-network memory is currently
per-*device* memory wearing a hash.

**(b) Snapshots are written only on a network *change*.** There is no periodic
write and no write on `Shutdown`, so on the far more common path (app killed
while still on the same network) everything captured since the last roam is
lost. Combined with (a), which makes changes almost never fire, the netmem
write path barely executes.

### 1.7 Display summaries (`core/abi/d2_summaries.go`)

The Wave-1 honesty pass already did the right thing here: `in_cooldown`,
`budget_exhausted` and `health_pct` are nullable pointers, `null` meaning "the
engine has observed nothing", and the UI renders "not tested yet". That
contract is intact and this pass does not weaken it — it **fills** it: after
the durable-outcome hook, `health_pct` becomes non-null for routes that have
actually connected, and stays null for routes that have not.

`ThroughputSnapshot` was the remaining hole on this file (counters that
nothing incremented, rendered as a live `0 B/s` readout and a flat sparkline
while a tunnel was pumping). **Fixed in a parallel lane on this same branch**
via `engine.HasByteAccounting` and a nullable `up_bps`/`down_bps`; not
duplicated here.

### 1.8 Fields that are always zero, by construction

These are already documented as such in code and are listed for completeness,
not as new findings:

- `experimental_routes_skipped` — the gate that would increment it
  (`pathmanager.RankWithExperimentalGate`) has no production caller. The
  in-code comment explicitly warns a reader not to conclude "the gate ran and
  skipped nothing" from the 0.
- `engine_probe_dns` / `engine_probe_tcp443` — return the
  `ProbeUnimplemented` (-1000) sentinel; the UI renders "unavailable". Honest,
  and the reason the 4 probe-derived selector signals cannot exist yet (§5).
- `wasm_kill_switched_count`, `delegate_share_counters`,
  `psiphon_active_route`, `conjure_*` — session-scoped counters for subsystems
  with no production dial path.

---

## 2. MEASURED vs INVENTED

"Invented" here means: a number a user sees or a decision consumes that is a
constant, a default, or derived from a source that never updates. The bar is
not "is it wrong" — it is "could it be right".

| Value | Verdict | Note |
|---|---|---|
| `route_health[].cooldown_reason` / `until` | **MEASURED** | real classification, real FSM clock |
| `skipped_families[]` + ladder step | **MEASURED** | session-scoped only |
| `posture` | **MEASURED** | |
| subscription `last_refresh_outcome` | **MEASURED** | |
| freshness `next_due` per pack | **MEASURED** | escalation + jitter now carried through (fixed in the Wave-3c sweep) |
| burnpressure verdict | **MEASURED** | derived from real `SkippedFamilies`; returns `evaluated:false` rather than a confident "no pressure" when it has no input |
| `proven` / `health_pct` | **MEASURED (as of this pass)** | was structurally always `false`/`null` — no writer existed for the three columns behind them |
| `network_signals` in the diagnostics explanation | **MEASURED (as of this pass)** for the 5 error-derived signals; **ABSENT** for the other 4 | was always `[]` |
| `budgets[].consumed_bytes` / `exhausted` | **INVENTED** — structurally 0 | `budget.Engine.Add`'s only caller `proxy.Pipe` has no production caller |
| `current_network_id` | **INVENTED** — a constant | single caller passes `('unknown','','')`; no Android caller at all |
| netmem `memory_hint` in an explanation | **INVENTED** — always nil | `RouteFamilyStats` has no writer |
| `experimental_routes_skipped` | **INVENTED** — structurally 0 | already documented in code |
| `engine_probe_*` | honestly **UNAVAILABLE** | correct: a sentinel, not a fake success |
| `up_bps` / `down_bps` | was **INVENTED** (always 0, rendered as a live readout) | fixed on this branch in the data-plane-honesty lane |
| `stats_redacted.bytes_in` / `bytes_out` | was **INVENTED** — the *same* absent counter, one surface over, in the blob a user exports and hands to a helper, where `0` reads as the finding "the tunnel carried nothing" | fixed at reconciliation: same `engine.HasByteAccounting` gate, emits `null`; `core/abi/byte_accounting_test.go` guards both surfaces. The counter itself is backlog **CM-1** |
| desktop "Connected" | was **INVENTED** — the Stub returns success without a socket | fixed on this branch: `SetRoute` now fails closed on a build with no data plane |
| `cellLabelGet/Set` | not telemetry — an in-memory cache | user labels are silently lost on restart; a UX bug, not a fake number |

---

## 3. B2, head-on

> *"No live NetworkSignals feed; `netmem.Sweep` unscheduled."*

### 3.1 What `NetworkSignals` actually is

A frozen 9-value vocabulary in `core/internal/selection/signals.go`
(invariant 25 — adding is allowed, renaming or removing is a spec bump). Two
disjoint halves:

- **5 error-derived**: `dns_bogon_detected`, `udp_collapsed`, `quic_collapsed`,
  `sni_rst`, `origin_unhealthy`. Each is *the same fact* as a
  `diagnostics.Category` the classifier already produces.
- **4 probe-derived**: `protocol_whitelist_mode`, `cdn_hostname_blocked`,
  `cdn_wide_failure`, `stateful_reassembly_present`. These are cross-candidate,
  cross-network *aggregations* — `cdn_wide_failure` is specified as "2+
  candidates failed across 3+ networks". No single classified error implies any
  of them.

### 3.2 What `selection.Decide` reads

Exactly three things, and nothing else (`selection.Input`, `pipeline.go:12`):

1. `Routes []routestore.RouteRow` — **real**, the store is populated.
2. `NetMem *netmem.Snapshot` — consumed by `rankCandidate` for a ±2000-point
   swing (`LookupHint` → `OutcomeSuccess`/`OutcomeClassifiedFailure`) and by
   `Explanation.MemoryHint`. **Had, and still has, no producer**:
   `selection.Apply` — the function that writes `RouteFamilyStats` — has zero
   production callers, so the branch is unreachable.
3. `NetworkSignals []NetworkSignal` — consumed by `rankCandidate` (a -500
   penalty on UDP-gated candidates under `udp_collapsed` /`quic_collapsed` /
   `protocol_whitelist_mode`) and by `PlanRace` /`RaceShortlistSize`. **Had no
   producer.**

The only production `Decide` caller is `abi.DiagnosticsExplain`
(`core/abi/refresh.go:238`; the `Decide` call itself is at `:254`) and it
passed neither 2 nor 3. So every `Decide`
call that has ever run in production ran with both memory and signals empty —
which silently disables the UDP-collapse penalty and the degraded race plan,
and makes the ranking a pure function of `probing_risk_class`.

### 3.3 What was made real in this pass

1. **The connect outcome is now durable.** `routestore.RecordSuccess` /
   `RecordFailure` write the five history columns the schema has always had and
   nothing ever wrote. Wired at the two points in `abi.SetRoute` where the
   engine already knew the answer.
2. **The 5 error-derived signals now have a producer.**
   `selection.SignalForCategory` / `SignalsFromCategories` convert the closed
   category vocabulary into the closed signal vocabulary, and
   `abi.activeNetworkSignals` derives the live set from routes whose durable
   failure sits in the current or previous hour bucket. It is passed to the one
   production `Decide` call, so `network_signals` in the diagnostics export is
   real instead of always-empty.

   **Two corrections made at repair, both load-bearing for the selection
   wave.** (a) *Recovery.* `RecordSuccess` deliberately leaves the failure
   bucket and category in place — that is what makes "flaky vs solid"
   readable — so reading them raw kept emitting a failure signal about a
   route that had since carried a tunnel. A route that failed at 14:05 and
   connected at 14:30 asserted `udp_collapsed` until 16:00, which is the app
   demoting its own working routes and explaining why. The derivation now
   skips any route whose most recent recorded outcome was a success. The
   ordering test is **`consecutive_failures == 0`**, not a bucket comparison:
   hour buckets cannot order a success and a failure inside the same hour,
   and that hour is exactly when recovery matters. `RecordSuccess` resets the
   counter and `RecordFailure` increments it, so it already carries the
   answer at instant precision **without storing an instant** — no new
   column, no new timestamp, no migration, no privacy delta.
   `TestActiveNetworkSignals_SuppressedAfterRecovery` pins it, including the
   re-arm on a later failure in the same bucket. (b) *Scope.* The comment
   above `signalWindow` claimed a signal was "a claim about the network the
   device is on RIGHT NOW". There is no network scoping in the function at
   all. The comment now states plainly that freshness bounds **when**, never
   **where**, and that §1.6a / B2-a is a precondition for these signal names
   meaning what they say.

   **And one thing this does NOT do, which the selection wave must plan for:**
   `abi.SetRoute` is the only writer, so outcomes accrue only to routes the
   user connected to **by hand**. There is no prober and no race, so on a
   fresh install one route carries history and every other route carries
   none — the evidence is a consequence of the user's choices, not an
   independent measurement of the route. A selector that ranks on history
   will therefore entrench the first route that happened to work unless it is
   explicitly designed against that cold start.

   **Nothing in the UI reads `network_signals`.** The value is produced,
   carried in `engine_diagnostics_explain`, and dropped by the TS adapter:
   `WhyThisRouteSummary` has no signals field, `abi.ExportDiagnostics` emits
   no such key, and `StatusPage` truncates the raw blob to 600 chars. This
   document only ever claimed the value was *measured*, which is true and
   remains true; `docs/capability-matrix.md` §3 briefly claimed it was
   *visible*, which was false and is corrected there. Tracked as **CM-5**.
3. **`netmem.Sweep` is scheduled.** New `scheduler.KindNetmemSweep` on a 24 h
   cadence, executor binding `refreshExecutor.SweepNetworkMemory`, stamped in
   `secrets_kv["scheduler:last-netmem-sweep"]`, visible in
   `engine_scheduler_status`.
4. **The two unbounded local history tables are bounded.** See §4.

### 3.4 What a real feed still requires

For the **4 probe-derived signals**, an active prober that does not exist:

| Signal | What it needs |
|---|---|
| `protocol_whitelist_mode` | probe several ports/protocols to a benign host, observe only 80/443 answering |
| `cdn_hostname_blocked` | dial the same CDN edge under two different SNIs and compare |
| `cdn_wide_failure` | ≥2 candidates failed on the same `cdn:*` tag across ≥3 **distinct networks** — needs real per-network identity (§1.6a) *and* cross-network aggregation |
| `stateful_reassembly_present` | timing/fragmentation probe |

`engine_probe_dns` / `engine_probe_tcp443` are the intended home (they return
`ProbeUnimplemented` today). **Do not synthesise these four from anything
less.** `cdn_wide_failure` in particular escalates a cooldown to every sibling
route carrying a `cdn:*` tag (`PropagateCooldown`); manufacturing it from one
failed dial would burn a user's whole relay set on one bad coffee-shop AP.

For `NetMem`, in order:

1. **Real network identity** — a platform observer that supplies
   `(kind, carrier, ssid)`. Without it every "per-network" fact is per-device
   and `cdn_wide_failure`'s "across 3+ networks" clause is unsatisfiable in
   principle. Android needs a `ConnectivityManager.NetworkCallback` in
   `DaalVpnService`/the plugin; desktop needs the OS-info path.
2. **A writer for `RouteFamilyStats`** — `selection.Apply` + a `netmem.Put`
   after a race outcome. This is *selection's own* write-back and belongs in
   the selection wave, not here.
3. **A write on shutdown**, not only on roam.

---

## 4. Privacy and retention

This is a censorship-circumvention client for devices that get seized. Every
signal is judged twice: "is it useful" and "what does it say about its owner in
an interrogation".

### 4.1 Rules applied to everything added here

- **Hour buckets, never instants.** `routes.last_success_bucket` /
  `last_failure_bucket` use `routestore.HourBucket`. A row cannot place the
  user on the network at 14:37.
- **Closed vocabularies, never free text.** `last_failure_category` holds a
  `diagnostics.Category` value. An error *string* would carry hostnames, IPs
  and ports; a category carries one of ~22 words.
- **No new identifiers.** Everything is keyed by `route_id`, which the store
  already holds in the clear.
- **One row per route, overwritten in place.** There is no per-attempt log.
  This is the single most important line in this document.
- **Bounded counters.** `consecutive_failures` saturates at 99. Unbounded it
  would leak a rough count of how many times the user tried to reach the
  network, and would make a recovered route take absurdly long to look healthy.

### 4.2 Signals deliberately NOT added

- **A per-attempt connect log** (timestamp, route, outcome). It is the single
  most useful thing a selector could have — real success *rates*, real latency
  distributions, time-of-day patterns — and it is precisely a browsing-adjacent
  session history on a seized device. `(route → server)` is already known to an
  adversary holding the device; `(route → when, how often, for how long)` is
  not, and it is what turns a device into evidence about behaviour. **Not
  added, and should not be added later without an explicit threat-model
  decision.** The aggregated one-row-per-route form in §4.1 gets most of the
  selector value at a fraction of the exposure.
- **Latency / RTT samples.** Real per-route latency would materially improve
  selection. Stored as a series it is a timing fingerprint of the user's
  connectivity. If this is ever wanted, store a single decayed aggregate per
  route, not samples.
- **Raw SSID / BSSID / carrier.** Already forbidden and already correctly
  handled: `netmem.HashID` is the only entry point and it forgets its inputs
  immediately. `TestSSIDDoesNotLeakIntoDiagnostics` guards it.

### 4.3 Retention — two unbounded tables, now bounded

Two append-only tables had **no cap, no prune, and no production reader**:

- **`refresh_audit`** — one row per refresh attempt
  (`kind, ref_id, bucket, outcome, bytes_in, via_tunnel`), inserted by
  `recordAudit` on the scheduler's path. Grepping the whole tree finds the
  `INSERT` and nothing else: no `SELECT`, no `DELETE`. On a device running the
  60 s tick it accumulates for the life of the install, and what it accumulates
  is an hour-resolution record of when this device was switched on and reaching
  the network.
- **`diagnostics_explain`** — upserted per hour bucket by
  `abi.DiagnosticsExplain`, which the Android UI calls **every 500 ms**. The
  upsert collapses within an hour, so it grows at one row per hour, forever.
  Its only reader, `LatestDiagnosticsExplain`, has zero callers.

Both are now bounded by `routestore.LocalHistoryWindow` = **72 hours**,
enforced **on the write path** rather than on a scheduler tick. That choice is
deliberate: this codebase has just finished paying for a 30-day TTL whose sweep
had no caller, and a retention bound that depends on a tick pump is only as
reliable as the pump. Pruning where the row is born means the bound holds on
any host.

**Correction made at repair: the write-path prune alone does not deliver the
property this section claimed.** Rows age out only when a new row is *born*,
so what a write-path prune actually guarantees is "these tables span at most
72 hours" — not "nothing here is older than 72 hours". The difference is the
entire forensic question, and it fails in exactly the case the bound exists
for. The refresh path is driven by `DaalVpnService.startSchedulerPump`, which
runs only while the tunnel is up, so a user who disconnects — **or whose
phone is taken** — freezes the table with its last 72 hours intact,
indefinitely. A device seized in March would still have carried an
hour-resolution record of the last three days it was reaching the network.

`routestore.PruneLocalHistory(now)` closes it, called from `abi.Init` beside
the existing `sweepPendingPrompts`. It is the same DELETE without a preceding
INSERT, hung off the one event that happens regardless of ticks, tunnels and
pumps: the app starting. The clock is the caller's (`abi.nowUTC`), so the
engine's single clock seam still governs and a simulated-time test cannot be
surprised. `TestPruneLocalHistory_AgesOutAStoreNobodyIsWritingTo` pins the
case by closing and reopening a store a week later with nothing writing to it.
The write-path prune stays — it is the cheap, host-independent half — and the
two together are what make the sentence in this section true as written.

Why a *time* bound and not "keep the last N rows": a count bound is a promise
nobody can state — "we keep 500 refreshes" is a different span on every device
— whereas 72 hours is one sentence a user can be told and a reviewer can check.
Three days spans a weekend (long enough to answer "have my refreshes been
failing, and since when") and is short enough that what survives describes an
incident rather than a routine.

`netmem` blobs are the third accumulator: `netmem.TTL` is 30 days, `Sweep`
enforces it, and until this pass **nothing called `Sweep`**. Each blob is a
hashed network the device has joined; no single blob names an SSID, but the
*set* and its *size* are a coarse travel record. A bound nothing enforces is
not a bound. Now scheduled — see §3.3.

`trust_audit` is append-only but bounded in practice (rows only on a
user-driven trust-state change) and is pruned on publisher delete. Acceptable
as-is.

---

## 5. The gap list, prioritised

Ordered by "how badly does this corrupt a selection decision".

1. **P0 — the network ID is a constant.** Until a platform observer supplies a
   real `(kind, carrier, ssid)`, every per-network structure in the engine is
   per-device: netmem blobs, the `(family, network)` escalation ladder key,
   the rendezvous and MASQUE hints, and — decisively —
   `cdn_wide_failure`'s "across 3+ networks" clause, which is unsatisfiable in
   principle. Cost: an Android `ConnectivityManager.NetworkCallback` in the
   daal-platform plugin plus a desktop OS-info path, both calling the existing
   `engine_network_changed`. The engine side is already built and correct.
2. **P0 — no byte accounting anywhere.** `proxy.Pipe` has no production caller,
   so the whole budget subsystem reads zero: caps never trip, `Rank`'s
   consumption term is inert, the hourly rollover rolls nothing. Any selector
   term that reads consumption is reading a constant. Cost: insert the
   charging middleware into the data path, or read sing-box's clash tracker in
   `engine_singbox.Stats` (`platform_singbox.go`'s `bytesIn`/`bytesOut` are
   declared "reserved for the stats follow-up phase" and never written).
3. **P1 — `RouteFamilyStats` has no writer, so `NetMem` scoring is
   unreachable.** `selection.Apply` is the intended writer and has zero
   callers. This is the selector's own write-back loop and belongs in the
   selection wave — but it must be **in** that wave, or `rankCandidate`'s
   largest term (±2000) stays dead while the code reads as though it works.
4. **P1 — the 4 probe-derived signals have no prober.** See §3.4. Wire
   `engine_probe_*` for real, or accept a 5-of-9 vocabulary and make the
   absence explicit in the explanation rather than indistinguishable from
   "probed and negative".
5. **P2 — netmem snapshots are written only on roam.** Add a write on
   `Shutdown` (and consider one on the daily tick). Today the common path —
   app killed on the same network — loses everything since the last roam.
6. **P2 — `snap.RouteHealth` is written and never read.** `NetworkChanged`
   captures it and the restore step referenced by its own comment does not
   exist. Either restore it or stop writing it; with §3.3's durable cooldown
   column it is now largely redundant, which argues for stopping.
7. **P2 — session-scoped family cooldowns.** The escalation ladder and the
   3-failures-in-1h window live only in `Manager`'s maps and reset on every
   process start, which on Android is constant. A family that is being
   systematically blocked restarts at ladder step 1 several times a day.
8. **P3 — inert per-network hints.** `abi.RecordRendezvousWinner` and
   `abi.RecordChosenMasqueSubmode` have no Go caller and **no ABI export**;
   their netmem `Lookup*` counterparts have no caller either. The whole
   `core/transports/{masque,snowflake,…}` layer is off the production dial
   path. Either wire the transports or mark this telemetry dead — it currently
   reads as a working feature.
9. **P3 — `cellLabelGet/Set` is an in-memory cache.** Not telemetry, but user
   data silently lost on restart (already tracked under Trust/labels).

---

## 6. Changes actually made in this pass

Verified with `go build ./... && go vet ./... && go test ./...`,
`go test -race ./scheduler/ ./refresh/ ./abi/ ./routestore/ ./internal/selection/`,
`tools/check-diagnostics-redaction.sh`, `tools/check-phase.sh`.
**No hardware was involved and nothing here is claimed to be device-verified.**

| Change | Files |
|---|---|
| `RecordSuccess` / `RecordFailure` — the first writers the five route-history columns have ever had; hour-bucketed, closed-vocabulary, one row per route, saturating counter | `core/routestore/store.go`, `core/routestore/outcome_test.go` |
| Wire both into the connect path at the two points the engine already knew the answer; durable cooldown read from the FSM rather than re-derived | `core/abi/abi.go`, `core/abi/outcome_durability_test.go` |
| `SignalForCategory` / `SignalsFromCategories` — the pin between the diagnostics taxonomy and the frozen selector vocabulary; refuses to synthesise the 4 probe-derived signals | `core/internal/selection/signals.go`, `signals_test.go` |
| `activeNetworkSignals` — first producer of `Input.NetworkSignals`; 2-hour freshness window; fed to the one production `Decide` caller so the diagnostics explanation stops reporting an empty signal set | `core/abi/refresh.go`, `core/abi/outcome_durability_test.go` |
| `KindNetmemSweep` — netmem's 30-day TTL is now enforced by a scheduled, restart-surviving, status-visible action instead of a doc comment | `core/scheduler/plan.go`, `scheduler.go`, `core/abi/scheduler.go`, `core/abi/netmem_sweep_test.go`, tests, `specs/scheduler-v1.md`, `specs/network-memory-v1.md` |
| 72-hour retention bound on `refresh_audit` and `diagnostics_explain`, enforced on the write path | `core/routestore/subscriptions.go`, `core/routestore/retention_test.go` |

**Added by the repair pass** (same verification standard; still no hardware):

| Change | Files |
|---|---|
| A recovered route no longer emits its old failure signal. Ordering decided by `consecutive_failures == 0`, which orders a same-hour success and failure that the hour buckets cannot — and stores no new instant, so no privacy delta | `core/abi/refresh.go`, `core/abi/outcome_durability_test.go` |
| The `signalWindow` comment stopped claiming network scope the function does not have; freshness bounds *when*, never *where* | `core/abi/refresh.go` |
| `PruneLocalHistory` — the retention bound now also runs on a path that needs no write, so a store nobody is writing to (disconnected, or seized) still ages out | `core/routestore/subscriptions.go`, `core/abi/abi.go`, `core/routestore/retention_test.go` |
| `ThroughputSnapshot` no longer reaches `mustCore()`. It is polled on a timer including during the init window, and a panic on a gomobile-bound thread is fatal to the process; unreachable today only because `HasByteAccounting` is false, and **CM-1 exists to flip that** | `core/abi/d2_summaries.go` |
| The `d2_summaries.go` header no longer says the route-history columns have no writer — the claim this same wave falsified two files away | `core/abi/d2_summaries.go` |
| B3's stale comment corrected (the timestamp was always persisted) | `core/abi/scheduler.go` *(a parallel lane landed this; see `docs/backlog-post-45.md` §11 item 4)* |

### Backlog deltas this document justifies

*(All three landed at reconciliation; `docs/backlog-post-45.md` now reflects
them. Kept here as the reasoning behind the edits, not as outstanding asks.)*

- **B2** — half done, **now `[~]` with the remainder split into B2-a…d.**
  `netmem.Sweep` is scheduled and the 5 error-derived signals have a real
  producer; what is left is the constant network ID (B2-a), `RouteFamilyStats`
  having no writer (B2-b), the absent prober (B2-c) and snapshots being
  written only on a network change (B2-d). It is **not** closed.
- **B3** — **struck as done.** The code was right; the comment was stale.
- **New** — items 1, 2, 5, 6, 7, 8 of §5 were not in `backlog-post-45.md` at
  all; they are now **B4, B5, B6** and, for the byte counter, **CM-1**
  (the display side, filed by the capability sweep) read together with **B4**
  (the decision side — `budget.Engine.Add`'s only caller is `proxy.Pipe`,
  which has no production callers). Item 2, no byte accounting anywhere, is
  the largest single "the code is right and nothing calls it" left in the
  engine, and CM-1/B4 must be fixed **together**: a byte count that reaches
  the UI but not the budget engine would leave `pathmanager.Rank` still
  deciding on zeros.
