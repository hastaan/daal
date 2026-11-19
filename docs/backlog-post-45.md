# Daal — post-Phase-45 backlog

**Re-verified 2026-08-18 against `247f659`.** Every open item below was
checked by reading the cited file at the cited line *today*. Line refs are
current as of this commit; re-grep before trusting them next week.

**How to use this file.** Pick from the top. Ordering is: (1) what the
NEXT wave consumes, (2) what the app currently tells the user that is not
true, (3) recovery-path correctness, (4) reachability, (5) release/CI,
(6) items honestly sized as waves of their own. Sizes are stake-money
estimates, not aspirations.

**Sizes:** `1h` `½d` `1d` `2-3d` `wave` (its own multi-day effort with a
design decision inside it). A size of `wave` on an item that reads like a
one-liner is the most important thing on that line.

**Reconciled 2026-08-18, after the fact.** This revision was first written
while three other owners were changing the same worktree (a capability sweep,
a telemetry audit and a platform/data-plane lane), and it carried a notice
saying to believe the tree over the file on B2, C3 and D1. **That notice is
now discharged**: a reconciliation pass re-read every item whose subject any
lane had touched, ran the full gate suite green, and folded the results back
in. B2 is `[~]` with the remaining work split into B2-a…d; D1's honesty half
is closed as `[x] D0`; C3 is unchanged and still open. The three companion
documents — `docs/capability-matrix.md` (reachability),
`docs/platform-reality.md` (per-OS truth) and `docs/telemetry-audit.md`
(measured vs invented) — were checked against this file and against the code,
and no longer contradict it. **Where any document disagrees with the tree,
the tree is right.**
Everything in §11 (this pass's own changes) is unaffected.

**2026-11-18 — the "truth wave".** The worldbox end-to-end rig
(`test-rigs/worldbox/`, `./daal e2e`) found 30-odd defects and observations
in seams no unit test crosses; this wave fixed most of them in the tree.
**§13 at the end of this file** lists what that closed here, and the items it
opened (TW-1…TW-14: one relay re-release, one Android library rebuild, the
wizard's signing order, and the phone checks nothing on a laptop can do).
The per-finding record is `test-rigs/worldbox/FINDINGS.md`; items above §13
that the wave touched carry a one-line *2026-11-18* note.

---

## 0. Landed — evidence kept, do not re-litigate

Compressed from the previous revision. Each of these was individually
re-verified today; the full narrative lives in the commits.

**Workstream E — sharing model & publisher** (all four closed)
- **E1** plain `.sbp` connects (`eb42f28` pipeline, `d06be4c` wizard, `d80c638`).
- **E2** publisher simplification: PINs *eliminated* not unified (Device
  Custody v1, `pin_lockout.rs` deleted), `helperIp.ts` auto-detects,
  roster de-duplicated into `RelayListPage.tsx` (`d80c638`).
- **E3** real app icon (`5a8b063`). **E4** delete routes/publishers +
  real teardown + provision rollback (`05d0e30`, `58f3fb8`).

**Workstream A — UI honesty** (A1-A5, A7 closed; A6 partial, see §4)
- **A1/A2** `proven` flag; the 30/90 fabrication is gone (`98edc81`).
- **A3** `ProbeUnimplemented` (-1000) → "unavailable", not fake success (`45b54b2`).
- **A4** real clipboard export + surfaced errors (`b4eb23f`).
- **A5** per-route connected state + one-tap Disconnect (`3fae4e5`);
  refs today are `NetworkPage.tsx:69 activeRouteId`, `:116 onDisconnect`,
  rendered `:249-250` and `:334`.
- **A7** zero `Coming soon` / `fountain` in `client-ui/src/publisher/*.tsx`.

**Closed this pass, as already-done:**
- **B3 — persist a real "last bootstrap refresh" timestamp. DONE, and it
  was done before this pass; only the comment lied.**
  `core/abi/scheduler.go` reads `scheduler:last-bootstrap-refresh` in
  `storeSource.LastBootstrapRefresh` and *writes* it in
  `refreshExecutor.RefreshBootstrap` (only on a successful
  `bootstrap.Provider.Refresh`). Both halves are on the production path —
  `ensureScheduler` constructs `storeSource` and `refreshExecutor` with
  the same `c.store`. The item existed because the read carried a comment
  reading "We do not yet persist a top-level last bootstrap refresh",
  written before the write half landed and never updated. Comment
  corrected this pass. **Cadence is exact, not approximate.**
- **C4 — tag bump. DONE.** `git describe --tags` = `v0.2.0-dev-13-g247f659`;
  `v0.2.0-dev` exists locally *and* on origin (`ed7d79b`). Branch
  `fix/android-dataplane-exclude-self` no longer exists locally or on
  origin — merged and deleted.
- **Phase-45 exit gate: drop `libsing_box.so`. DONE.** No `libsing_box.so`
  in the staged tree: `gen/android/app/src/main/jniLibs/*/` contains only
  `libdaalcore.so`, `libdaal_desktop_tauri_lib.so`, `libdaal_deploy.so`
  and (arm64 only) `libcronet.so`.
- **Trust/labels: `burnpressureVerdict` is no longer a deterministic
  stub.** `client-ui/src/backends/tauri.ts:803` derives it from
  `rawSkippedFamilies()` — real engine data — and returns
  `evaluated:false` when the engine did not answer, rather than a
  confident "no burn pressure" over an empty list. The `cellLabel*` half
  of that item is still open (§4). Old ref `:353` was stale; the contract
  lines are now `D2Contract.ts:456,459,460`.

**Fixed this pass (see §7 for what changed):**
- **Known-red `bundle/go TestSubkeySignedSampleArtefact` — GREEN, and
  now actually asserting.** It was already not red (a previous pass had
  softened it to a loud skip), but a skip is not a test: the fixture was
  going unverified. Fixed properly with a Go clock seam.
- **`AddSheet` showed the user a fingerprint phrase Daal invented.**
  Found this pass, fixed this pass. Details in §7.

---

## 1. What the SELECTION wave consumes — do these first

Selection reads signals. Wiring a selector onto absent signals produces
confident wrong answers, and the UI explains its reasoning, so a wrong
answer arrives with a rationale attached. These two are the gate.

> Full inventory, MEASURED-vs-INVENTED table, gap list and privacy
> reasoning: **`docs/telemetry-audit.md`** (compiled 2026-08-18). Read it
> before starting the selection wave. Headline: `selection.Decide` reads
> exactly three inputs, and **two of the three had no producer anywhere in
> the tree**. One of them now does.

- [~] **B2. No live `NetworkSignals` feed; `netmem` is never swept.**
  *(Half closed 2026-08-18 — see §11.)* **DONE:** the sweep is now a real
  scheduler action (`KindNetmemSweep`, 24 h, stamped in
  `secrets_kv["scheduler:last-netmem-sweep"]`, visible in
  `engine_scheduler_status`), so netmem's 30-day TTL is enforced instead of
  merely documented; and the **5 error-derived** signals now have a genuine
  producer — `abi.activeNetworkSignals` reads the newly-durable
  `routes.last_failure_category` through `selection.SignalsFromCategories`
  and feeds the one production `Decide` call, so the diagnostics explanation
  stops reporting an empty signal set on every device.
  **What is left is the part the original entry was right to call a `wave`,
  now split into the four things that actually block a selector:**
  - [ ] **B2-a. The network ID is a constant, so "per-network" is
    per-device.** `engine_network_changed`'s only production caller is
    `client-ui/src/App.tsx:147`, which fires
    `contract.networkChanged('unknown','','')` — the *same three arguments*
    — on both the browser `online` and `offline` events, and
    `grep -rn network_changed --include=*.kt` is **empty**, so Android, where
    Wi-Fi↔cell roaming is the entire point, never supplies an identity at
    all. `netmem.HashID` is correct and privacy-preserving and is being
    evaluated on constant input. Everything keyed on network is therefore
    keyed on nothing: netmem blobs, the `(family, network)` escalation ladder,
    the 3B/3C hints — and decisively `cdn_wide_failure`, specified as "2+
    candidates failed across **3+ networks**", which is unsatisfiable in
    principle until this lands. Needs an Android
    `ConnectivityManager.NetworkCallback` in the daal-platform plugin plus a
    desktop OS-info path; **the engine side is already built and correct**.
    Size: `1d`.
  - [ ] **B2-b. `RouteFamilyStats` has no writer, so the selector's largest
    scoring term is unreachable.** `rankCandidate` swings ±2000 on
    `LookupHint`, which reads `netmem.Snapshot.RouteFamilyStats`;
    `selection.Apply` is the only thing that writes that map and has **zero
    production callers**. This is the selector's own write-back loop, so it
    must land *inside* B1 rather than after it — otherwise `rankCandidate`
    reads as though it works while its dominant term is dead. Size: `½d`
    (within B1).
  - [ ] **B2-c. The 4 probe-derived signals have no prober.**
    `protocol_whitelist_mode`, `cdn_hostname_blocked`, `cdn_wide_failure`,
    `stateful_reassembly_present` are cross-candidate/cross-network
    aggregations; no single classified error implies any of them.
    `engine_probe_dns`/`engine_probe_tcp443` are the intended home and return
    the `ProbeUnimplemented` sentinel. **Do not synthesise these from a lesser
    fact.** `cdn_wide_failure` propagates a cooldown to every sibling carrying
    a `cdn:*` tag (`PropagateCooldown`), so one fabricated instance burns a
    user's whole relay set on one bad café AP. Either build the prober — and
    then decide the battery and traffic-fingerprint cost the original entry
    correctly flagged — or ship 5-of-9 and make the absence explicit in the
    explanation rather than indistinguishable from "probed and negative".
    Size: `wave`.
  - [ ] **B2-d. netmem snapshots are written only on a network CHANGE.**
    `abi.captureAndPersist` runs from `NetworkChanged` and nowhere else —
    there is no periodic write and none on `Shutdown` — so the common path
    (app killed on the same network, which on Android is constant) loses
    everything since the last roam. Compounded by B2-a, which means the
    change almost never fires. Related and cheap: `snap.RouteHealth` is
    written by `captureAndPersist` and **never read back**; the restore its
    own comment references ("intentionally additive — see note below") does
    not exist and there is no note. With the durable `routes.cooldown_until`
    column added this pass it is now largely redundant, which argues for
    deleting the write rather than adding the read. Size: `½d`.
  *2026-11-18 (truth wave, CEN-1/CEN-2):* the engine now has one real
  producer of failure signals from the data plane — a connect is proved by a
  round trip, a failed proof is classified by phase and recorded
  (`RecordFailure` + cooldown), and a connected route is re-proved every
  ~3 min and on a network change (`abi.CheckActiveRoute`). It is per-route
  only; the network-wide categories still need a second observation
  (TW-5).
- [ ] **B1. The selection engine's only production caller is diagnostics.**
  `core/internal/selection/` is fully built and tested — `Decide`
  (pipeline.go:68), `PlanRace` (race.go:37), `Shortlist` (shortlist.go:28)
  — and the single production call site is
  `core/abi/refresh.go:253`, inside a diagnostics explanation. Wire it into
  connect / SetRoute. Size: `wave`. **Do not start this before B2**: a
  selector fed by B2's absent feed is worse than no selector.

- [ ] **B4. Nothing charges the byte counter, so the whole budget subsystem
  reads zero.** *(New, from the telemetry audit.)* `budget.Engine.Add` has
  exactly one caller in the tree — `proxy.Pipe` — and **`proxy.Pipe` has zero
  production callers** (`core/engine/inlet.go:49` mentions it only in a
  comment). The charging middleware the subsystem was designed around was
  never inserted into a data path. So `budgets[].consumed_bytes` is 0 and
  `exhausted` is false in every install and always will be;
  `pathmanager.Rank`'s `consumedFraction` term is inert; `StateBudgetExhausted`
  can never be entered; and the hourly `KindBudgetReset` action rolls over an
  empty counter every hour of every day. This is the same root cause as CM-1
  (§2) seen from the decision side rather than the display side — **fix them
  together**, because a byte count that reaches the UI but not the budget
  engine would leave `Rank` still deciding on zeros. Size: `1d` + hardware to
  assert on. **Selection wants this**: consumption is the only "am I about to
  burn this route" input the ranker has.
- [ ] **B5. The 3B/3C per-network hints are inert in both directions.**
  *(New, from the telemetry audit.)* `abi.RecordRendezvousWinner` and
  `abi.RecordChosenMasqueSubmode` are documented as "the engine-side hook for
  the callback" and have **no Go caller and no ABI export** — they are not in
  any `*_export.go` or `*_gomobile.go`, so no host can reach them either.
  Their read counterparts `netmem.LookupWinningRendezvousChannel` /
  `LookupLastUsedMasqueSubmode` likewise have no caller, and the whole
  `core/transports/{masque,snowflake,…}` layer is off the production dial
  path. Four fully-tested per-network memory fields therefore describe a
  feature that cannot execute. Either wire the transports or mark the
  telemetry dead in the doc comments — as written it reads as working.
  Size: `½d` to mark, `wave` to wire.
- [ ] **B6. Family cooldowns and the escalation ladder are session-scoped.**
  *(New, from the telemetry audit.)* `pathmanager.Manager`'s `familyCooldown`,
  `familyEscalation` and the 3-failures-in-1h `failures` window live only in
  in-memory maps and reset on every process start — which on Android is
  constant. A family that is being systematically blocked restarts at ladder
  step 1 several times a day, so the V2.3 5min/15min/1h/4h/24h ladder never
  reaches its upper rungs in practice. The durable route-level columns added
  this pass do not cover this: the ladder is per `(family, network)`, not per
  route. Size: `½d` (persist beside the route history, keyed by the same
  hashed network — which needs B2-a to be worth anything).

---

## 2. Things the app currently tells the user that are not true

- [ ] **H1. The trust word-grid falls back to placeholder words.**
  `client-ui/src/lib/importVerdict.ts` `trustFromVerdict` fills
  `fingerprintEN/FA` from the engine verdict's `HexEN`/`HexFA`, and falls
  back to `base?.fingerprintEN` when the verdict carries none. `base` comes
  from `previewBundle` → desktop-core `preview_bundle`
  (`daal-desktop-core/src/commands.rs:59-60`), which renders with a **four-word
  placeholder list** (`["alpha","bravo","charlie","delta"]` /
  `["یک","دو","سه","چهار"]`). So a verdict with empty `HexEN` puts invented
  words into the grid the user reads aloud to the publisher — the one
  screen whose entire job is that the two sides see the same thing.
  The common path is safe (the engine does supply words, and
  `AddSheet.tsx:191` prefers them); this is the fallback.
  The right behaviour is to **fail closed** — refuse to render a grid
  without engine words — which needs a refusal state and copy in en+fa.
  Size: `½d`. **Related root cause:** RS1 below.
- [ ] **RS1. `preview_bundle`'s recovery-phrase preview uses placeholder
  wordlists.** `daal-desktop-core/src/commands.rs:59-60`. The
  authoritative lists are `publisher.DefaultWordlists()` on the Go side and
  Rust has no binding to them. This is the source of H1, and it is why the
  preview panel could not show words at all (see §7). Fixing it properly
  means either an ABI export for the wordlists or embedding them in
  bundle-rs with a gate proving the two copies are byte-identical (the same
  discipline the i18n copies already get). Size: `1d`.
- [ ] **W3-11. The L3 button is enabled on relays that cannot do L3.**
  `AddressSwap.tsx:141` — `const available = canReserve || currentFloatingIpId !== '';`
  — consults the provider's reservation capability and whether a floating IP
  is already attached, and **never** whether the relay's mgmt binary can bind
  an address, which since Wave 3c is the deciding fact. `rotation.ActionForProvider`
  (`publisher/deploy/rotation/action.go:153`, refusing with
  `AvailabilityUnsupported` at `:227` on `!caps.BindAddress`) computes exactly
  this, and is unreachable for the reason in W3-5: `Wizard.rotateRecommend`
  has no caller. The press is *safe* — `daal-deploy assign-fip` probes the box
  first and the sheet renders `pub.rotate.too_old` — but a rung that can only
  fail should be disabled with the reason showing. Size: `½d` (needs
  `rotateRecommend` reachable first, which is W3-5's smallest slice).
- [ ] **T1. `cellLabelGet`/`cellLabelSet` are in-memory stubs AND unreachable.**
  `contract/D2Contract.ts:459-460`; implementations in
  `backends/tauri.ts:817,824` are a `Map` that dies with the process. The
  engine side exists (`core/trust/labels.go:33 LabelStore`,
  `:44 MemoryLabelStore`) and is not wired. No `.tsx` calls either method,
  so nothing is currently lying to a user — this is a stub waiting for a
  surface, not a false claim. Size: `1d` (store + ABI + wrappers + a
  surface). Low priority precisely because it is invisible.
- [ ] **CM-1. Nothing counts the bytes that cross the tunnel.**
  Found by the capability sweep (`docs/capability-matrix.md` §2); the *lie* is
  fixed, the *measurement* is not. `abi.ThroughputSnapshot` used to divide
  `throughputCounters.upBytes/downBytes` by the window, and **no code in the
  repository ever incremented either field** — so `ConnectionPage` printed
  `↑ 0 B/s ↓ 0 B/s` for the entire life of every connected session on every
  platform, and `StatusPage` drew a sparkline through it. That is now reported
  as `null` (unmeasured) end to end, gated on the new
  `engine.HasByteAccounting`. What remains is the real counter:
  `core/engine/platform_singbox.go:36-37` declares `bytesIn`/`bytesOut`
  `// reserved for the stats follow-up phase` and nothing writes them, so
  `singBox.Stats()` returns `(0,0,nil)` on a tunnel moving megabytes.
  *(Reconciliation update: `engine_stats_redacted` used to marshal that
  straight through as `bytes_in: 0` into the blob a user exports to a helper —
  where a zero reads as the finding "the tunnel carried nothing" rather than
  as a missing measurement. It now emits `null` behind the same
  `HasByteAccounting` gate, and `core/abi/byte_accounting_test.go` guards both
  surfaces. The **lie** is now fixed on both; the **counter** is still this
  item.)* Wiring it means reading sing-box's clash tracker from
  the platform interface on the tunnel's own goroutine.
  Size: `1d`, **and it cannot be closed from this machine** — the assertion is
  "the number on the phone moves while traffic flows".
  Flipping `HasByteAccounting` to `true` in the same change makes the UI start
  rendering numbers with no UI edits. **Selection wants this**: per-route
  observed throughput is the most direct "is this route actually working"
  signal there is, and it is absent.

---

## 3. Recovery-path correctness — the layer beneath freshness

These are what a censored device falls back to. All five re-verified true.

- [ ] **W3-1. The bootstrap pointer hosts are placeholders, so the layer
  beneath freshness is inert in production.**
  `core/abi/refresh_freshness.go`'s `recoverViaBootstrapPointers` is what
  runs when every freshness mirror in a pack is blocked. It walks the
  embedded pointer list, and that list ships pointing at
  `https://bootstrap-primary.daal.example/dir.sbp` and its fallback twin
  (`core/bootstrap/embedded/fixtures/pointers-{primary,fallback}.json`,
  embedded at `embedded.go:22`; both signed, both `valid_until`
  2027-05-07). Those are genfixtures placeholders, not hosts. Needs, per
  pointer: a project-controlled domain on infrastructure whose blocking is
  expensive for the censor, serving a directory `.sbp` signed by a Tier-1
  publisher, with the pointer set re-signed by the project root before
  `valid_until` lapses. **Do not substitute plausible-looking hostnames** —
  a placeholder fails visibly, a wrong hostname fails like censorship.
  Size: `wave` (it is an infrastructure + key-ceremony job, not a code job).
- [ ] **W3-2. `FetchRaw` reads the response body unbounded.**
  `core/bootstrap/fetcher.go:120` is `io.ReadAll(tlsConn)` with a deadline
  as the only limit. Wave 3b widened exactly this path: it is now polled on
  a schedule against N publisher-supplied mirror URLs, over the plain
  network, from the user's real address. A hostile or seized mirror can
  stream until the timeout and OOM-kill the app on a phone — at the moment
  the recovery channel is being used. Left unfixed deliberately: the cap is
  a design decision. It must clear the V3 bundle ceiling (`core/wasm`:
  ≤4 MiB/module, ≤16 MiB/bundle) or large but legitimate packs start
  failing indistinguishably from blocking. Size: `½d` once the number is
  chosen; choosing it is the work.
- [ ] **W3-9. The self-healing loop still has a manual upload in the middle.**
  Daal signs and publishes the freshness *document* to the mirrors
  (`freshness::publish` → `PublishAll`), but it never uploads the re-signed
  `.sbp` to the download address that document points at. `pack_url` is a
  field the operator types
  (`daal-wizard/src/freshness.rs:414 set_pack_url`, stored at
  `operator_db.rs:884`, emitted as `current_signed_url` at
  `freshness.rs:730`). The recipient fetches `doc.CurrentSignedURL`
  (`core/refresh/relaypack_refresh.go:619`), so if the operator has not put
  the pack there, every device gets a 404 or a digest mismatch and stays on
  the burned relay. Copy names the step in both languages; the *capability*
  — publish the pack through the same mirror credentials that already work,
  and verify the digest at `pack_url` before reporting success — is not
  built. **This is the last courier step in the "no courier" path.**
  Size: `2-3d`. Highest-value item in this section: the backends already
  work (W3-7), this is reusing them for a second object.
  *2026-11-18 (truth wave, LC-2):* what the document points at is now
  usable — the file `bind-and-sign` writes (the signed, credential-less
  pack whose digest the app publishes) is MERGED into a polling phone's own
  credentials, so after L2 and L3 a phone recovers with no new file. Before
  this, hosting that file broke every polling recipient. The upload is still
  the operator's, so this item stands as written.
- [ ] **W3-3. Recipients have no manual "check for a new pack now".**
  `core/refresh.RelayPackRefresher.RefreshUser`
  (`core/refresh/relaypack_refresh.go:511`) exists, is tested, and has
  **zero production callers** — only `core/abi/freshness_rotation_wire_test.go`
  and `core/refresh/relaypack_refresh_test.go` reach it. There is no
  `engine_relaypack_refresh` export (compare `SubscriptionRefresh`,
  `core/abi/refresh.go:137`, same shape, wired end to end). So the only
  thing that ever drives a freshness poll is the 60 s scheduler tick, which
  runs while the app is open or the tunnel is up. Under blackout — tunnel
  down, user staring at a dead relay — the one action a user would reach for
  does not exist. Size: `1d` (ABI export + cshared/gomobile symbol + JNI +
  Tauri command + button + en/fa ×2 copies).
- [ ] **W3-8. The shared WS path is not per-recipient and no rotation exists.**
  `specs/per-recipient-credentials-v1.md` §2.1, re-read today: the shipped
  design is ONE shared `ws-in` inbound whose `transport.path` is minted from
  the first recipient and reused verbatim
  (`cmd/daal-relay-mgmt/singbox_users.go:33,59-68,363`). A single leaked
  pack therefore discloses the WS path *every* recipient on that relay uses;
  revoking a recipient does not rotate it; "rotating the shared path for
  everyone at once is the mitigation, and it is not implemented". The spec
  is explicit that this is a deliberate, real weakening. Interacts with
  W3-4: L2 is the rung that would move `ws_path`, and L2 has no button.
  Size: `2-3d`.

---

## 4. Reachability — code that is right and nothing calls it

- [ ] **W3-5. Fourteen wizard wrappers exist and no component calls them.**
  `Wizard.rotateHistory`, `rotateRevert`, `rotateRecommend`,
  `finalizePreProvision`, `getSbpPath`, `listCdnFronts`, `pricingLookup`,
  `provisionCdnFront`, `publisherKeyimport`, `storeCloudflareToken`,
  `subkeyActive`, `subkeyHistory`, `subkeyRotate`, `verifyCdnPosture` each
  appear **exactly once** in all of `client-ui/src` — in their own
  declaration in `wizardCommands.ts`.
  *Corrected this pass: the list was fifteen. `qrRender` came off it —
  Wave 4 wired it, `QrSendSheet.tsx:97` calls it.* The user-visible
  consequence is live: `pub.danger.address.field.reason` is labelled "Why
  (kept in this relay's history)", the reason really is persisted, and
  there is no screen that can read it back.
  This class is invisible to `tools/check-plumbing.mjs` by construction:
  the gate is satisfied by the `invoke()` wrapper existing, and never asks
  whether a component calls the wrapper.
  Size: `wave` for the whole list (each needs a surface and en+fa copy);
  `½d` for the smallest useful slice — make `rotateRecommend` reachable,
  which also unblocks W3-11.
  **Teaching check-plumbing the second hop is a separate `1d`**, and it
  cannot be a bare rule addition: switching it on today fails the build on
  all fourteen, so it needs a reasoned allowlist in the same style as the
  four entries the gate already carries.
- [ ] **W3-4. Eight of the nine rotation rungs have no button.**
  `rotate_execute` (`daal-wizard/src/commands.rs:2424`) implements L1, L2,
  L4, L5, L6, L7_CDN_PATH, L8_CDN_HOSTNAME, L9_CDN_ORIGIN. The **only**
  `Wizard.rotateExecute` call site in the entire UI is
  `AddressSwap.tsx:157`, and it passes the literal `'L3'` at `:159`.
  (Step 7's `rotate_credentials` / `rotate_tls` are separate box endpoints
  and *are* wired.) Each missing rung needs its own confirm sheet,
  consequence copy in en+fa, and inputs for region / provider / profile.
  Size: `wave` — this is a design job, not plumbing.
- [ ] **W3-12. A reused server keeps a name that no longer identifies it,
  and a guard silently stopped guarding.** Observed on live hardware.
  Hetzner server names are derived from (publisher pubkey, region)
  (`derivedServerName`, `providers/hetzner/provider.go:799`), and the
  wizard's "choose an existing server" path rebuilds in place, keeping the
  old name while issuing a fresh publisher key. Floating-IP ownership stays
  self-consistent (labels and `ownsFloatingIP` both derive from the current
  key), so nothing is mislabelled and no delete guard is weakened. The gap
  is NAME-based lookups. `resolveServerID` (`:639` — *the item previously
  called this `serverIDForRecord`; that function does not exist*) is safe
  only because it short-circuits on `rec.ServerID` at `:640` and never
  reaches the name lookup. But `sweepEphemeralKeys` (`:664`) uses
  `ServerByName(derived)` at `:676` as a **liveness proof** — "if a server
  still carries that name, that relay is alive and its provisioning key is
  not ours to remove" — and on a reused server that proof answers "not
  alive" for a relay that is very much alive.
  Consequence is low (deleting a one-shot provisioning key does not break a
  running box) but the next name-based lookup somebody adds inherits it.
  Size: `1d`, **not the one-liner it looks like.** Keying liveness off
  `ServerID` needs a `ServerByID` on the `hcloudClient` interface
  (`client.go:18`) plus `liveClient`, `dryRunClient` and every test fake —
  and it lands in the teardown path, where a wrong answer deletes a live
  server. The tempting cheap fix (preserve the key when liveness cannot be
  proved) is **wrong**: a preserved ephemeral key blocks the next provision,
  which is a failure mode this project already has.

- [ ] **CM-3. Six recipient-side contract methods have no screen.**
  Same class as W3-5, one layer down and on the *recipient* side, so W3-5's
  wizard-only list does not cover them. Each is fully implemented in Go, Rust
  and TypeScript and called by nothing (`docs/capability-matrix.md` §1):
  `routeDelete` (you can delete a whole publisher from `NetworkPage` but not
  one of its routes — an asymmetry a user will hit), `revocationRefreshAll`,
  `setRendezvousPriority`, `redistributeRoute`, and `cellLabelGet`/`cellLabelSet`
  (already tracked as T1, and additionally a `Map` with no engine behind it).
  Size: `½d` each for `routeDelete` and `revocationRefreshAll` — both are one
  row action on a page that already hosts their siblings. `1d` for
  `setRendezvousPriority`, which needs an ordered-list control and a decision
  about what "order" means to a user. `wave` for `redistributeRoute`, which has
  no recipient-side sharing surface to attach to at all.
- [ ] **CM-4. `check-plumbing.mjs` cannot see the second hop, and now there is
  a measured count of what that hides.** The gate's four rules are satisfied by
  an `invoke()` wrapper existing anywhere in `client-ui/` —
  `wizardCommands.ts`, `tauri.ts` and `bridge.ts` all qualify — so a capability
  can be green while no component calls it. The sweep counted **20** such wrappers
  (14 `Wizard.*` = W3-5, 6 `D2Contract` methods = CM-3), verified mechanically:
  each of the 14 appears exactly once in all of `client-ui/src` — its own
  declaration — and each of the 6 has zero `.tsx` callers. A fifth rule
  ("every exported wrapper has a caller outside its own module and outside
  tests") is mechanical; switching it on today fails on all 20, so it lands
  with a reasoned allowlist in the same style as the four entries the gate
  already carries. Size: `1d`. Do it *after* the cheap slices of W3-5 and
  CM-3, so the allowlist starts short.

- [ ] **CM-5. `network_signals` is measured, emitted, and read by no UI.**
  Filed at reconciliation, after `docs/capability-matrix.md` §3 was
  corrected: it had claimed the set was visible on `StatusPage` → "why this
  route", and it is not. The Go side is real —
  `selection.SignalsFromCategories` → `abi.activeNetworkSignals` →
  `engine_diagnostics_explain` emits `"network_signals": [...]` — and then it
  stops. `WhyThisRouteSummary` (`client-ui/src/contract/D2Contract.ts`) has
  no signals field, so `backends/tauri.ts`'s `parseExplanation` drops the
  value; `abi.ExportDiagnostics` does not emit the key either, and
  `StatusPage` truncates the raw blob to 600 chars, so there is no fallback
  path. **This is the Wave-2 cover-SNI shape** — a value crosses three
  layers and a struct in the middle discards it — and it is the exact
  surface the selection wave will need, because a selector that explains
  itself must be able to show what drove the decision. Size: `½d` (add
  `signals?: string[]` to `WhyThisRouteSummary`, carry it through
  `parseExplanation`, render it in the "why this route" panel with en+fa
  labels for the 5 categories). Do it *with* the selection wave, not
  before — the labels should describe what the selector did with each
  signal, not just that it existed.

- [ ] **CM-6. The MASQUE sub-mode override is stored and never read.**
  `SettingsPage.tsx:564-572` → `set_masque_submode_override` →
  `abi.SetMasqueSubmodeOverride` (`core/abi/masque.go:42`) validates and
  persists into `secrets_kv`, and **`abi.MasqueSubmodeOverride()`
  (`masque.go:62`) has zero production callers.** The intended consumer is
  `masque.WithOverrideFn` (`core/transports/masque/masque.go:192`), whose
  own doc comment describes a closure nobody writes; `masque.NewHandler`
  (`:211`) has no production caller either. So a user who pins `h2` to get
  out from under a QUIC block sets a value that survives restarts and
  changes nothing. Size: `½d` for the wiring *if* a MASQUE handler is
  actually constructed on a live path — which it is not, so the honest size
  is "blocked on the MASQUE transport having a production caller at all".
  Until then the right change may be to disable the control and say why,
  which is `1h`. See `docs/capability-matrix.md` §4b.

- [ ] **CM-7. The experimental-families toggle cannot change the family set.**
  `pathmanager.RankWithExperimentalGate` (`family_filter.go:80`) has no
  production caller — only tests. The tree already *knew*: both
  `core/abi/abi.go:96` and `core/routestore/family.go:117` say so in code
  comments. It reached the capability matrix as SHIPPED anyway, which is
  the reconciliation failure worth remembering here — the finding existed
  and was not carried across. Size: `½d` to route the ranking call through
  the gate, or `1h` to disable the toggle honestly. See
  `docs/capability-matrix.md` §4b.
  *2026-11-18:* confirmed by the rig on all three opt-in families
  (worldbox O-4), unchanged.

---

- [x] **W5-1. The box binds two listeners for families the relay does not serve.**
  *DONE in the tree 2026-11-18 (worldbox FAM-4), NOT yet on any relay: it needs
  the planned relay re-release (new `daal-relay-mgmt`) and a fresh provision (new
  cloud-init).* cloud-init now writes the relay's family set to
  `/etc/daal/families`; `daal-relay-mgmt` creates inbounds, rows and credentials
  for those families only; `vless-in`/`hy2-in` are baked only when their family
  is served; and both firewalls open exactly `relayports.FirewallPortsFor(set)`
  (443 included — it was unconditional). Contract:
  `specs/per-recipient-credentials-v1.md` §2.3. Rig: world `narrow-relay`, and
  `listener_on_box: false` in `mint/* not_served` on default relays (O-3). The
  original entry follows for the record.
  `cmd/daal-relay-mgmt/singbox_users.go:167,175` calls `appendSSUser` and
  `appendAnyTLSUser` unconditionally, so `ss-in` and `anytls-in` are created for
  every recipient even on a relay whose profile enables neither — and both are
  `default_enabled: false` in every shipped profile. Their firewall ports were made
  opt-in on 2026-08-18 (`relayports.ExtraFirewallPortsFor`), so the fleet-wide
  *reachable* exposure is gone; what remains is two local sockets and credentials
  for them sitting in the sing-box config of a relay that advertises no such route.
  `appendTUICUser` shows the right pattern — append only to an inbound cloud-init
  already wrote — which ss/anytls cannot copy as-is, because both are documented as
  never existing with an empty `users[]` (an inbound nobody can authenticate to is a
  listener that only serves probes). The fix is for the box to learn its own family
  set: an `/etc/daal` file written at first boot and read before appending. That
  changes what the box boots with, on a box with no SSH where rescue mode is the
  only way back, and it needs a fresh provision to test. Deliberate change, with
  Step 7's capability-probe discipline — not a drive-by.

## 5. L3 — measured, released, proven

- [ ] **W3-6. L3's code and pin have landed; it has never run end-to-end
  on real hardware.** *Re-scoped this pass — half of this item is done.*
  DONE: the guest-OS half shipped (`41ab5cc`), the artefact was rebuilt,
  re-signed and re-pinned (`3c32f79`, `0340fb8`), and
  `publisher/deploy/cloudinit/artifacts.go` now records
  `ADDRESS BINDING (Wave 3c). RESOLVED 2026-08-18`, with `v2.yaml.tmpl:148,207`
  carrying `AmbientCapabilities=CAP_NET_ADMIN`.
  STILL OPEN, and it is not code:
  (a) **there is no upgrade path** — `AmbientCapabilities` is written once,
  at first boot, so every relay in the field must be **provisioned fresh**
  from this tree before L3 can work at all; a relay handed only the new
  binary correctly reports `bind-address` unavailable and refuses cleanly;
  (b) `libdaal_deploy.so` must be rebuilt for the publisher half to reach it
  from the phone (see C3);
  (c) it has never been exercised against a live box.
  Size: `½d` of human release work, then one live run. **W3-10 gets its
  measurement for free from that run.**
  *2026-11-18 (truth wave):* (c) is now half answered — the rig drives the
  real `assign-fip` → `/bind-address` → re-mint → connect, and
  `floating-ip release`, against the pinned release artefacts on a lab box
  (world `release.lifecycle`, op `l3`; worldbox LC-O4), and found and fixed
  the naive half of it (LC-3; needs a fresh provision). Still never against
  a real provider or real hardware, and the rig's box holds `CAP_NET_ADMIN`
  by construction, so (a) is NOT exercised there.
- [ ] **W3-10. The L3 15-second budget was never measured, and the window
  it bounds grew in Wave 3c.** `L3_FAST_PATH_BUDGET`
  (`daal-wizard/src/commands.rs:2295`, asserted at `:5708`),
  `rotation.L3FastPathBudget` (`publisher/deploy/rotation/postconditions.go`,
  asserted at `postconditions_test.go`) and the soak rig's
  `v1-5-l3-fast-path` scenario (`specs/blackout-soak-rig-v1.md:392`) all
  pin 15 s, and all three assert it against an *injected* `Duration`.
  The subprocess it bounds used to be reserve → attach → readback → TCP
  probe. It is now capability probe (a full ephemeral-firewall window:
  provider read-modify-write of the rules, TLS handshake, `GET /health`,
  blocking removal in a defer) → reserve → attach → readback → **bind** (a
  second full window, plus its own capability re-check and a
  `POST /bind-address` that configures the address and writes its
  persistence) → reachability probe → re-sign. The number was not moved for
  it. A "fast path" that quietly becomes 30 s is an outage nobody was
  warned about. **Measure the real elapsed time on the first live L3**
  (W3-6's run gives it for free), then decide, once, whether the budget or
  the step count moves. The two firewall windows are the obvious saving:
  the capability probe cannot join the bind's window (it must refuse
  *before* anything is reserved), but the bind re-probes capabilities inside
  its own window with the answer already in hand. Size: `½d` after W3-6.
  **Wave 6 re-examined this and did not move it**, deliberately: collapsing
  the two rotation executors did not measure anything, and moving an
  unmeasured product promise in either direction is guessing. The exact
  measurement that would settle it is written down in
  `docs/decisions/0004-one-rotation-executor.md` ("The budget: verdict").
- [ ] **W3-7. R2 and GH Pages are implemented and have never touched a real
  endpoint.** `publisher/deploy/freshness/backends/r2` (AWS SigV4) and
  `.../ghpages` (contents API) are on the live publish path, and every
  upload assertion in the tree is an `httptest.NewServer`
  (`r2_test.go:70`, `ghpages_test.go:47,94`). There is a third backend,
  `.../ipfs`, in the same state. Partially retired: Hetzner floating-IP
  create/assign **was** exercised against the real API at `6a7903c` (it
  succeeded at the API layer — that run is what produced W3-6). Size: `½d`
  of credentialed manual runs; the code is not the work.

---

## 6. Release, CI and packaging

- [x] **C0. A stale `libdaal_deploy.so` now fails the build instead of
  silently provisioning from an old manifest.** Twin of C3 below: because
  `tauri android build` only *packages* whatever `.so` is already in the
  gitignored `gen/android/.../jniLibs/`, editing
  `publisher/deploy/cloudinit/artifacts.go` and rebuilding the APK
  shipped an app that provisioned relays from the **previous** artefact
  manifest, with no warning. That has already cost one full debugging
  cycle. New gate **`tools/check-deploy-so-manifest.sh`** (wired into
  `tools/hooks/pre-push:93`): the manifest is Go source compiled into the
  binary, so every `Sha256`/`SigHex` literal in `artifacts.go` must
  appear verbatim in the `.so`'s `.rodata` — which `-ldflags "-s -w"`
  does not strip, and which needs no execution, so it works on an
  Android arm64 binary from a Linux host. Skips cleanly when no `.so`
  has been built. Verified both directions in-tree: passes on all three
  ABIs; flipping one pin makes all three fail with exit 1. (Note this is
  gated by C2 — but only for the *CI* half: pre-push **is** installed on
  this checkout via `core.hooksPath=tools/hooks`, so the gate runs on
  every push from here. It does not run in CI, and it does not run on a
  clone that never set `core.hooksPath`.)

- [ ] **C2. There is no CI for Android, and no CI runs the static gates.**
  *Substantially re-scoped this pass — the previous framing was wrong in
  both directions.*
  - The repo has **no `.github/` directory at all.** CI is **AppVeyor**
    (`appveyor.yml`, 524 lines) and it builds desktop bundles only:
    Windows nsis/msi, macOS app/dmg, Linux. `test_script` runs `./daal test`
    on the macOS image and explicitly skips the others.
  - `grep -c 'tools/check' appveyor.yml` → **0**. None of
    `check-hardcoded-strings`, `check-diagnostics-redaction`,
    `check-tokens`, `check-phase`, `check-plumbing`, `check-qr-send` runs in
    CI. They run **only** from `tools/hooks/pre-push` (lines 93-107).
  - **Correction, made at reconciliation.** This item previously concluded
    "`.git/hooks/` contains no non-sample hook, so on this checkout that
    file is not installed — every gate this project relies on is currently
    opt-in and manual." **That is false, and it was reached by looking in
    the wrong directory.** `git config --get core.hooksPath` returns
    `tools/hooks`, which is *why* `.git/hooks/` holds nothing but samples:
    git is looking elsewhere. The pre-push gate **does** run on every push
    from this checkout. In a document whose stated contract is "the tree
    wins", a conclusion drawn from the wrong path is the same error class
    this wave exists to remove, so it is corrected here rather than
    quietly edited.
  - What survives, and it is still the highest-leverage item here: **the
    gates do not run in CI** (`grep -c 'tools/check' appveyor.yml` → 0), so
    they protect only developers who ran the one-line install. And
    `core.hooksPath` is **per-clone local config, not tracked state** — a
    fresh clone, a CI checkout, and a second machine all start with the
    gates off and nothing says so. The remaining local-side item is
    therefore much smaller than the one previously written: a bootstrap
    check (e.g. `./daal` refusing, or warning once, when
    `core.hooksPath != tools/hooks`), not "install the gates".
  - `patch-android-mainactivity.sh` **is** wired, contrary to the old item:
    `client-shell/tauri/package.json:12` `android:patch` runs it (plus
    manifest, icons, signing) and both `android:dev` and `android:build`
    depend on it.
  - `build-deploy-android.sh` is **not** wired into anything (that is C3).
  Size: `1d` — an AppVeyor job that runs the six gates, plus installing the
  pre-push hook. The Android *build* job is separate and larger.
- [ ] **C3. `libdaal_deploy.so` is not built by any build script.**
  `tools/build-deploy-android.sh` builds it for arm64-v8a, armeabi-v7a and
  x86_64 (`:60-62`) and nothing invokes it — not `android:patch`, not
  `android:build`, not AppVeyor. It has been produced ad-hoc on-device.
  **This is the coupling that makes W3-6 undeliverable**: the publisher's
  Tier-2 code reaches the phone only through this `.so`.
  Size: `1h` to add it to `android:patch`; the value is that W3-6 stops
  being blocked on somebody remembering.
- [ ] **C1. APK size, and a fourth ABI that cannot work.**
  Installed universal APK is ~92 MB (4 ABIs × libdaalcore 39 MB +
  libcronet 24 MB + libdaal_deploy 13 MB + tauri 12 MB). Two concrete
  findings from the staged tree today (`gen/` is gitignored build state,
  so treat these as "what the next APK would ship", not as committed truth):
  - `jniLibs/x86/` contains **only** `libdaal_desktop_tauri_lib.so` — no
    `libdaalcore.so`, no `libdaal_deploy.so`. Neither build script targets
    `x86` at all (both do arm64-v8a / armeabi-v7a / x86_64). So the
    universal APK carries an x86 slice that can install and cannot run.
    Dropping `x86` from the Tauri ABI list is free size and removes a
    crash-on-launch device class.
  - ~~`libcronet.so` is present **only** under `arm64-v8a`.~~ *2026-11-18
    (TW-3):* `build-engine-android.sh` now builds it for all three ABIs it
    builds an engine for, stripped (arm64 12.8 MB, was 24 MB unstripped;
    armeabi-v7a 8.3 MB; x86_64 13.4 MB), and the gate fails a set where
    some ABIs have it and others do not.
  Size: `½d` for the per-ABI split and the x86 drop.

---

## 7. Desktop data plane

> Platform truth for this whole section — per-platform evidence, build
> flags read off real artefacts, and honest sizing for D1/D2 — is in
> **`docs/platform-reality.md`** (OWNER PLATFORM lane, 2026-08-18).

- [x] **D0. The desktop could say "Connected" with traffic in the clear.**
  Not previously on this list, and it outranked everything that was.
  `engine.Stub.Start()` returns `nil` and publishes
  `Event{state:"Connected"}` without opening a socket
  (`core/engine/engine.go:48`); `SetRoute` then called `pm.Connected()`
  and advanced the posture to `ImportedActive`, which
  `client-ui/src/backends/tauri.ts:122` maps to `'connected'` and
  `ConnectionPage` renders as **"Connected · Routing"**, eagle live,
  throughput polling. Confirmed on the artefact the desktop actually
  dlopens: `go version -m .../src-tauri/resources/libdaalcore.so` →
  `-tags=cshared`, and `strings | grep -c sagernet/sing-box` → 0.
  **Fixed by refusing, not by flipping the driver (that is still D1):**
  `engine.HasRealDataPlane` twinned per build tag (+ twin tests in
  `driver_selection_{stub,singbox}_test.go`), `core/abi/dataplane.go`
  with `ErrNoDataPlane`, `SetRoute` failing closed *before* it touches
  any state (`TestSetRoute_FailsClosedWithoutDataPlane`), `data_plane`
  in the diagnostics blob so a GUI can warn before the user presses
  anything, and a ConnectionPage alert + Connect refusal in en/fa.

- [ ] **D1. The desktop has no real data plane.** `core/abi/abi.go`'s
  `Init` builds the `Core` with `driver: newEngineDriver()` (`:234`), and
  the desktop build carries no `singbox` tag, so it links `engine.NewStub()`.
  Everything above it — routes, trust, freshness, rotation, the whole
  publisher — works on desktop. Nothing tunnels.
  **Size: `wave`. Do not attempt this as a task.** The flip itself is a
  build tag; what makes it a wave is everything the tag exposes: a real
  in-process sing-box driver on three OSes, TUN acquisition per OS
  (Linux via `tun_helper::unix`, Windows blocked on D2, macOS unstarted),
  retiring `daal-desktop-core/src/singbox.rs` sidecar + the Clash REST
  path, and a per-OS `libcronet` for the naive tier (D3). It also has no
  hardware to prove it on beyond one Linux desktop. Sizing it as a wave is
  the finding; the previous entry read like a plumbing change.
- [ ] **D2. Windows TUN-fd handoff is a stub.**
  `daal-desktop-core/src/tun_helper.rs` — the `win` module's `ping` returns
  `"Windows TUN-helper IPC not implemented in 1.5B scaffold"`; needs the
  named-pipe `windows-sys` implementation. Size: `2-3d`. Blocks the Windows
  third of D1.
  **Under-scoped as written (2026-08-18).** Two things the entry hides:
  (a) the `win` module has *only* `ping` — no `open_fd` equivalent, so
  there is nothing for a caller to call even once the pipe works; and
  (b) **the server side does not exist at all** — `daal-win-service`,
  named in the module doc, appears exactly twice in the repo (that
  comment and an ASCII diagram in `specs/desktop-architecture-v1.md:18`).
  There is also no such thing as a TUN *file descriptor* on Windows:
  Wintun returns a `HANDLE` with a ring-buffer session API while
  `engine_set_tun_fd` takes a `c_int`, so the handoff is an **ABI
  decision**, not a port of the Linux transport. `2-3d` buys the pipe
  client; the privileged service, its installer/service registration and
  its code signing are the actual job.

- [ ] **D4. Nothing stages `daal-tun-helper` into `/usr/libexec/daal/`,
  and the failure is silent.** `client-shell/tauri/packaging/linux/deb/postinst`
  chowns/chmods `4755` on that path, guarded by `if [ -e "$HELPER" ]`, so
  on every build to date it exits 0 having done nothing.
  `tauri.conf.json` bundles only `resources/*`; `daal-tun-helper` is a
  workspace member no packaging step copies. Same shape as the
  `tools/patch-android-*` scripts before Wave 4: a documented step
  nothing enforces. Blocks the Linux third of D1 — and must NOT be fixed
  ahead of it, or the installer ships a setuid binary nothing uses.
  Size: `1d`.
- [ ] **D3. Naive/Cronet on desktop needs a per-OS
  `libcronet.{so,dylib,dll}` sidecar.** No desktop copy exists in the tree
  (the only `libcronet.so` outside Android build output is the relay's own,
  under `dist-release/`). Size: `2-3d`, mostly build plumbing. Part of D1.
  *2026-11-18 (truth wave, FAM-5):* the loader half is fixed — off Android
  the engine now lets cronet-go search beside its own binary, and on
  linux/amd64 the library is the one inside the `cronet-go/lib` Go module
  (that is how the rig runs naive). Packaging a per-OS sidecar is still
  this item.

---

## 7b. iOS — the roadmap was carrying an assumption (new 2026-08-18)

Evidence in `docs/platform-reality.md` §2.

- [ ] **I1. `client-ios/` does not exist in this repository.** `ls
  client-ios` fails. `specs/ios-build-v1.md:5` ("**Implementation:**
  `client-ios/`"), `specs/wireguard-subengine-v1.md:5,80`,
  `development-phases/18-phase-2e-ios.md` and
  `docs/handovers/frp-6-handover.md:90` — whose stated verification step
  is a `rg` over that directory — all describe a `DaalApp` SwiftUI target
  and a `DaalTunnel` `NEPacketTunnelProvider` extension that are not
  here. Either restore the Xcode project or amend the specs; today the
  roadmap credits iOS with an implementation it does not have.
  Size: `1d` to amend the docs; restoring the project is a wave.

- [ ] **I2. There is no iOS data plane, and the current build cannot
  grow one.** What CI produces (`appveyor.yml:400-470`) is an ordinary
  Tauri iOS app: `tauri ios init` scaffolding into gitignored
  `gen/apple`, a genuinely singbox-tagged `libdaalcore.dylib` from
  `tools/build-engine-ios.sh`, signing stripped by
  `tools/patch-ios-signing.sh`, `xcodebuild -exportArchive` *expected to
  fail*, and the `.app` hand-zipped into `Daal_<version>_unsigned.ipa`.
  No Network Extension target → no packet-tunnel fd → no traffic capture
  is even possible. iOS does at least fail honestly and always has:
  `singBox.Start` refuses with "TUN fd not set"
  (`core/engine/engine_singbox.go:109`). A tunnelling client needs an
  extension target **and** a paid Apple Developer account — the
  `packet-tunnel-provider` entitlement is not granted to free personal
  teams. Size: `wave`, with a procurement dependency.

- [ ] **I3. One orphaned Swift file.**
  `client-shell/tauri/plugins/daal-platform/ios/PacketTunnelProvider.swift`
  — the plugin README labels it "preserved from client-ios; not yet
  wired", and no Xcode target references it. Wire it or delete it.
  Size: `1h` to delete, otherwise part of I2.

---

## 8. Rust shell / recipient plumbing

- [ ] **RS2. Pre-Tier-2 box packs ship an empty `reality_public_key`.**
  `daal-wizard/src/recipient_book.rs:153-156, 195, 435-438, 682-685` —
  the rewrite fails closed when the field is empty. Resolved for freshly
  provisioned boxes; what is open is **verifying the guard messaging says
  something an operator can act on**, since the only remedy is
  "provision a new relay". Size: `1h`.
- [ ] **RS3. iOS share of `.sbpx` is a placeholder.**
  `client-ui/src/publisher/wizardCommands.ts:542` ("iOS is a TODO");
  Android and desktop return a staged file path. Size: `1d`, and it is
  moot until there is an iOS build to run it in.

---

## 9. Partial / carried

- [~] **A6. Unify the two connect surfaces.** The active route now
  reflects across both — `NetworkPage.tsx:69` shares the same 2 s
  `connectionSummary` poll (`:96`), so the two surfaces no longer disagree
  about what is connected. The second half is open: two connect surfaces
  still exist and have not been collapsed to one model. Size: `2-3d`, and
  it is a design decision before it is code.

---

## 10. Phase-45 exit gate — needs hardware, not code

Both re-read today. The code is present and reads correctly; neither can be
closed from this machine, because closing them means watching a phone.

- [ ] **P1. VPN consent dialog + foreground notification on first Connect.**
  Implemented: `DaalPlatformPlugin.kt:48` `VpnService.prepare(activity)`,
  `:129` `startForegroundService`; `DaalVpnService.kt:412-419` creates the
  channel, `:400,405` `startForeground`. **On-device re-verify only.**
- [ ] **P2. Clean disconnect tears down VPN network + notification.**
  Implemented: `DaalVpnService.kt:215-229` — `stopSchedulerPump`, then
  `setTunnelRefresh(false)` *before* `clearRoute`/`clearTunFd` (deliberate
  ordering, commented), then `stopForeground(STOP_FOREGROUND_REMOVE)`.
  **On-device re-verify only.**

*(The third housekeeping bullet — drop `libsing_box.so`, tag bump — is
closed; see §0.)*

---

## 11. What this pass changed in the code

All verified building and passing (`go build ./... && go vet ./... &&
go test ./...`, `-race` on the touched packages,
`check-diagnostics-redaction`, `check-phase`). **Nothing here was verified
against hardware.**

1. **`bundle/go/bundle/sbp.go` — added `VerifyBundleAt(b, now)`**, the Go
   twin of bundle-rs's `verify_bundle_at` (`bundle-rs/src/sbp.rs:135`).
   `verifyBundleCore` and `validateRoute` now take an explicit `now`;
   `VerifyBundle` and `VerifyBundleFor` pass `time.Now().UTC()`, so **no
   production path changed**. Three wall-clock reads became one injected
   parameter; nothing is skipped or widened.
2. **`bundle/go/bundle/sbp_subkey_e2e_test.go` — the time-bomb fixture is
   now pinned.** `TestSubkeySignedSampleArtefact` verified a fixture with a
   fixed 90-day window against the wall clock, so it went red on
   2026-08-01 on every machine, forever, un-fixable here because
   regenerating needs `samples/keys-A/publisher.priv` which is deliberately
   not in this repo. A previous pass softened it to a loud skip — which
   stopped the noise and also stopped the test. It now verifies at
   `subkeySamplePinnedNow` = the generator's own `pinnedNowUnix`
   (`cmd/bundle-subkey-sample/main.go:44`, 2026-05-03T00:00:00Z), plus two
   new guards so the seam cannot rot:
   `TestSubkeySignedSamplePinMatchesCert` reads the window out of the
   artefact and asserts the pin falls inside it (catches a regenerated
   sample), and `TestSubkeySignedSampleRejectedOutsideWindow` verifies the
   same artefact one second after its cert lapses and requires
   `ErrSubkeyCertOutOfWindow` (proves the seam did not disable the check).
   All three pass; `go build ./... && go test ./...` green for `bundle/go`.
3. **`client-ui/src/components/AddSheet.tsx` — stopped showing an invented
   fingerprint phrase.** *(New defect, found this pass.)* `:444` rendered
   `preview.fingerprintEN` in the pre-import preview panel. That value comes
   from `previewBundle` → `preview_bundle`, which renders with the
   four-word placeholder list. The panel was therefore teaching the user a
   publisher fingerprint phrase that Daal made up — and it is the phrase
   they are about to compare against the publisher's. It now renders
   `preview.fingerprintHex`, which is computed by
   `bundle_rs::publisher_fingerprint` over the real publisher key and is
   identical on both sides. No new user-visible strings, so no i18n change;
   `check-hardcoded-strings` and `check-plumbing` pass. The trust decision
   itself was already made on the engine's word grid and is untouched — the
   remaining fallback hazard is tracked as H1.
4. **`core/abi/scheduler.go` — corrected the comment that generated B3.**
   `LastBootstrapRefresh` carried "We do not yet persist a top-level last
   bootstrap refresh", written before `RefreshBootstrap`'s `PutSecret`
   landed. The comment now describes the actual round-trip and says why the
   write is success-gated.
5. **`core/routestore` — the connect outcome is now durable.** *(Telemetry
   lane; full reasoning in `docs/telemetry-audit.md`.)* The five route history
   columns (`last_success_bucket`, `last_failure_bucket`,
   `last_failure_category`, `consecutive_failures`, `cooldown_until`) have
   existed since the first schema and had **no writer** — `UpsertRoute`
   hard-codes them to NULL/0 and nothing ever updated them — while
   `abi.SetRoute` classified an outcome on every single attempt and dropped it
   at process exit. That is why `proven` was false and `health_pct` null on
   every route in every install. New `RecordSuccess` / `RecordFailure`, wired
   at the two points in `SetRoute` where the engine already knew the answer,
   with the durable cooldown read back from the FSM rather than re-derived so
   the column and the in-memory state cannot disagree. Privacy shape: hour
   buckets (never instants), closed-vocabulary category (never an error
   string, which carries hostnames and ports), one row per route overwritten
   in place (**no per-attempt log**), counter saturating at 99.
6. **`core/internal/selection` + `core/abi` — `NetworkSignals` has a producer
   for the first time.** `SignalForCategory` / `SignalsFromCategories` pin the
   diagnostics taxonomy against the frozen 9-value selector vocabulary and
   deliberately refuse to map the 4 probe-derived signals;
   `abi.activeNetworkSignals` derives the live set from routes whose durable
   failure sits in the current or previous hour bucket (a deliberately short
   window — a day-old `sni_rst` describes yesterday's café) and passes it to
   the one production `Decide` call. `network_signals` in the diagnostics
   export was `[]` on every device before this.
7. **`core/scheduler` + `core/abi` — `netmem.Sweep` is scheduled.** New
   `KindNetmemSweep` (24 h) with executor binding
   `refreshExecutor.SweepNetworkMemory`, stamped unconditionally so a failed
   sweep cannot turn into a per-tick re-decrypt of every stored blob. Specs
   updated (`scheduler-v1.md`, `network-memory-v1.md`). This is a privacy
   control before it is housekeeping: each blob is a hashed network the device
   has joined, and the *set* of them is a coarse travel record. The TTL was
   the bound on that record and nothing enforced it.
8. **`core/routestore` — two unbounded append-only tables are now bounded.**
   `refresh_audit` (one row per refresh attempt) and `diagnostics_explain`
   (one row per hour, written from a surface the Android UI polls at 2 Hz) had
   no cap, no prune, **and no production reader** — `refresh_audit` is never
   `SELECT`ed anywhere in the tree and `LatestDiagnosticsExplain` has zero
   callers. What accumulated was pure liability: an hour-resolution record of
   when this device was switched on and reaching the network, for the life of
   the install. Both are now bounded by `LocalHistoryWindow` = 72 h, enforced
   **on the write path** — a retention bound that depends on a tick pump is
   only as reliable as the pump, and this tree has just finished paying for a
   30-day TTL whose sweep had no caller.

### Reconciliation addendum — two more code fixes

Found while making the four documents agree, both the same class as
everything else in this wave (a number that is not measured, and a type that
promises it is):

9. **`core/abi/abi.go` `StatsRedacted` — the diagnostics blob still said
   `bytes_in: 0`.** The throughput fix (item 3 of the capability sweep,
   `docs/capability-matrix.md` §5) gated `ThroughputSnapshot` on
   `engine.HasByteAccounting` and stopped one function short.
   `engine_stats_redacted` reads the *same* `driver.Stats()` and marshalled it
   straight out, so the JSON a user exports and hands to a helper carried a
   flat zero. That is worse than the Connection page's readout, because a
   helper reads `0` as a conclusion. Now `null` behind the same gate.
   Reachability note: this one matters specifically **on Android**. On desktop
   `driver.Stats()` errors out (nothing is ever connected, by design, since
   D0), but Android's tunnel is genuinely up and its counters are the
   reserved-and-never-written `platformInterface.bytesIn/bytesOut`.
10. **`core/abi/byte_accounting_test.go` (new) and
    `client-ui/src/lib/bridge.ts`.** The throughput fix shipped with **no
    test** — in a wave whose thesis is that unwitnessed code rots, that is the
    same hole one layer up. The new test asserts both surfaces against
    `engine.HasByteAccounting` rather than a literal, so it follows the
    constant when CM-1 lands instead of going red; it was verified to fail on
    the pre-fix code. Separately, `bridge.throughputSnapshot()` still typed
    `up_bps: number` over a value Go now sends as `null`, and its doc still
    described counters that had been deleted. Both corrected. (That wrapper
    has no caller — `backends/tauri.ts` invokes the command directly — which
    is now stated in place; it is one of the CM-4 rows.)

---

## 12. Tally for this pass

Started: 29 open items.

- **Closed as already-done (evidence in tree, no work needed):** 3 —
  B3 (timestamp persisted; only the comment was stale), the `libsing_box.so`
  / tag-bump housekeeping bullet (and with it `[~] C4`), and half of the
  Trust/labels item (`burnpressureVerdict` is real).
- **Closed by fixing:** 1 — the known-red `TestSubkeySignedSampleArtefact`,
  which was already a skip rather than a red, and is now green *and*
  asserting, with two new guards.
- **Fixed outside the backlog:** 1 new defect found and fixed
  (`AddSheet` fabricated fingerprint phrase), plus one stale comment.
- **Re-scoped:** 7 — D1 (plumbing → `wave`), C2 (wrong in both directions:
  the Android patch script *is* wired, and there is no CI for gates at all),
  W3-6 (code and pin landed; what remains is fresh provisioning + a live
  run), W3-5 (fifteen unreachable wrappers → fourteen; `qrRender` is wired),
  W3-12 (function renamed, and the "one-liner" is a `1d` interface change in
  the teardown path), Trust/labels (halved), Phase-45 P1/P2 (code present;
  hardware re-verify only).
- **Deleted:** 2 struck-through entries that were already resolved — the
  freshness `next_due` escalation/jitter note and the "live subscription
  hosting stubbed to filesystem" note, both fully superseded by W3-7/W3-9
  and both training readers to skim.
- **Added:** 2 open items — H1 (trust word-grid falls back to placeholder
  words) and the x86 dead-ABI finding folded into C1.

**Then open: 27.** That number was written before the other three lanes
finished, and it is no longer the count — see the reconciled tally below.

### Reconciled count (2026-08-18, all four lanes landed)

Reproduce it, do not trust it:

```
grep -c '^- \[ \]'   docs/backlog-post-45.md   # 39  top-level open
grep -c '^  - \[ \]' docs/backlog-post-45.md   # 4   B2-a…d, nested under B2
grep -c '^- \[~\]'   docs/backlog-post-45.md   # 2   B2, A6 — part-closed
grep -c '^- \[x\]'   docs/backlog-post-45.md   # 2   D0, C0 — opened AND closed this wave
```

**39 open top-level items, plus 2 part-closed, plus B2's 4 sub-items.**
Started at 29. The rise is honest and is the product of the wave: the pass was
commissioned to find capabilities and numbers that were not what the tree
claimed, and it found more than it closed. Where the 27 became 39:

| Change | Δ | Items |
|---|---|---|
| Closed as already-done (evidence in tree) | −3 | B3, the `libsing_box.so`/tag-bump housekeeping bullet (taking `[~] C4` with it), half of Trust/labels |
| Closed by fixing | −1 | known-red `TestSubkeySignedSampleArtefact` |
| Deleted as superseded | −2 | freshness `next_due` escalation/jitter; "live subscription hosting stubbed to filesystem" |
| Added — backlog lane | +2 | H1, and the x86 dead-ABI finding folded into C1 |
| Added — capability sweep | +3 | CM-1, CM-3, CM-4 |
| Added — telemetry audit | +3 | B4, B5, B6 (B2's own remainder became B2-a…d, not new items) |
| Added — platform lane | +4 | D4, I1, I2, I3 |
| Added — repair pass (review findings verified against the tree) | +3 | CM-5 (`network_signals` reaches no UI), CM-6 (MASQUE override never read), CM-7 (experimental-families gate never called) |
| Opened **and closed** in-wave | ±0 | `[x] D0` (the desktop "Connected" lie), `[x] C0` (the stale-`.so` gate) |

**Re-scoped, not counted above (7):** D1 (plumbing → `wave`), C2 (wrong in
both directions: the Android patch script *is* wired, and there is no CI for
gates at all), W3-6 (code and pin landed; what remains is fresh provisioning
plus a live run), W3-5 (fifteen unreachable wrappers → fourteen; `qrRender` is
wired), W3-12 (function renamed, and the "one-liner" is a `1d` interface
change in the teardown path), Trust/labels (halved), P1/P2 (code present;
hardware re-verify only). D2 was re-scoped by the platform lane in place.

**Fixed outside the backlog (4):** `AddSheet`'s fabricated fingerprint phrase;
one stale comment in `core/abi/scheduler.go`; `StatsRedacted`'s `bytes_in: 0`
and `bridge.ts`'s non-nullable `up_bps` (§11 addendum).

**One item was drafted and deleted unwritten.** CM-2 — "the desktop offers
Connect as if it would work", `data_plane` emitted by Go and read by nothing
above it — was being typed when the platform lane landed it in this same
worktree. `ConnectionPage.tsx:183` reads `conn.dataPlane === 'none'` and
refuses the gesture with `conn.no_data_plane.*` in en+fa. It is `[x] D0`.
CM-4 supersedes the "teaching check-plumbing the second hop" note inside W3-5
and carries the measured count (**20** wrappers the gate cannot see).

**Top of the list, if you want the order defended:** B2 before B1, because
selection without signals is the failure this whole pass exists to prevent;
C2 next, because the gates do not run in CI and the defect found in §7 is
exactly the class a gate catches (note the *local* half of C2 was corrected
at repair — `core.hooksPath=tools/hooks` is set here, so the gates are not
"opt-in and manual" on this checkout); then W3-9, because the backends
already work and it closes the last courier step.

### Repair-pass addendum (2026-08-18)

An independent review of this wave was run against the tree and its findings
verified rather than accepted. Outcome: **13 of 16 confirmed, 1 corrected in
the reviewer's favour and against the wave's docs, 2 partly false.** What
changed as a result is listed in `docs/capability-matrix.md` §5 and
`docs/platform-reality.md` §4c; the backlog effects are the three CM items
above plus the C2 correction. Two reviewer findings did **not** survive
verification and are recorded so they are not re-filed:

- *"The trust prompt says six-word, the renderer emits four."* Half true.
  `trust.body` in the catalogue the app actually loads
  (`client-ui/src/i18n/{en,fa}.json`) already said **four**-word in both
  languages; only `onboarding.p4.body` was genuinely wrong on a shipped
  screen, and the stale "six" survived in `client-shared/i18n/{en,fa}.json`,
  which `lib/i18n.ts` does not import. Fixed in all copies anyway, so the
  two catalogues stop giving different answers.
- *"A developer who checks out this branch gets a startup panic from the
  stale `libdaalcore.so`."* The consequence is right and worse than the docs
  said (see below), but the premise is not: `libdaalcore.*` is **gitignored**
  (`.gitignore:81`, and `resources/README.md` explains the 2026-08-17
  untracking). A fresh clone has no artefact and `./daal build` is the
  documented first step. The hazard is a **stale local artefact**, which is
  precisely the case nothing could see — now gated by
  `tools/check-engine-so-manifest.sh`.

---

## 13. The truth wave (2026-11-18) — closed, and opened

Source of truth: `test-rigs/worldbox/FINDINGS.md` (ids below are its ids).
Gate at close: `bash tools/hooks/pre-push` green; `./daal e2e full` green
twice (5095 checks, 18 worlds; the only reds are the open findings CEN-4,
F-002 and — on the pinned box — LC-1). **Everything below is in the working
tree only: nothing has been released, re-minted, rebuilt for Android or
tried on a phone.** TW-1…TW-4 are what turns it into something a user has.

**Release-ready wave, closed 2026-11-19.** Ten review findings repaired
on top of the above (BOOT-1 and REV-1…REV-9 in FINDINGS; each is noted on
the item it belongs to below). **The ordered steps the owner performs —
release, pin-bump commit, native libraries + APK + signature, a fresh
relay, the phone checklist — are `docs/release-runbook.md`.**

**Pin moved 2026-11-19 — TW-1 is done.** GitHub releases `relay-v1.5.1`
and `relay-v1.5.1-mirror` are published, byte-identical to the candidate
the rig proved, and `publisher/deploy/cloudinit/artifacts.go` pins them
(both family constants `true`; `known-findings.json` holds CEN-4 only).
`./daal e2e full` on this tree: `PASS — 5388 checks`, 18 worlds, the
pinned worlds `release`, `release.lifecycle`, `release.all-families`
green. **Nothing has run on a phone or on a rented relay yet** (runbook
Part 2 onwards; TW-3, TW-4 below).

Gate at close, the tree as it stood BEFORE the pin moved:

- `bash tools/hooks/pre-push`: every step green except `daal e2e quick`,
  which fails on ONE check — world `release` (pinned box) `STOPPED at
  provision/verb.provision` — 1482 checks, 15 of 16 worlds green. That
  red is REL-1/BOOT-1: this tree cannot build a relay from the pinned
  release, and stays red until the pin-bump commit. Not excused, on
  purpose.
- `./daal e2e full` twice, identical: `RESULT: FAIL — 2 unexpected red
  check(s), 0 known finding(s) that did not reproduce, of 4386 checks` —
  the two are `release.lifecycle` and `release.all-families` stopping at
  the same check; the 16 tree worlds are green; KNOWN is CEN-4 ×14 only.
- **The same tree with the pin bump applied** (a scratch copy: the
  candidate re-staged today, `tools/release/pin-bump.py`, the golden
  re-pinned to `141280b3…`; nothing uploaded): `./daal e2e full` twice,
  `RESULT: PASS — 5388 checks; nothing unexpected (1 known finding(s)
  reproduced…)` — 18 worlds, `release.all-families` green on all seven
  families, `release.lifecycle` green through recipients / revoke / L1 /
  L3 / L2 / mgmtauth / freshness; KNOWN is CEN-4 only. `publisher/deploy`
  and `cmd/daal-relay-mgmt` unit tests green there too.
- Android: `build-engine-android.sh`, `build-deploy-android.sh`, both
  `.so` gates, `npm run android:build` with `keystore.properties`
  pointing at `release-keys/android-device-signing.jks`: exit 0, signer
  digest `6026ec39…` (the phone's). That APK was deleted again — it was
  built before the pin bump and must not be installed. Nothing was put on
  a device.

### Closed in the tree

- [x] **A route that carries nothing is no longer "Connected"** (CEN-1,
  CEN-2, CEN-3, CEN-5, CEN-6, O-2). Connected means one real round trip
  through the route; a failed connect is an error with words (en+fa), a
  slow one says slow, a lost one says it is retrying; failures are
  classified by where they happened; disconnect no longer hangs 5 s on a
  dead relay. Spec: `engine-abi-v1.md`, `failure-taxonomy-v1.md` rev 2.
- [x] **A pack's server addresses and keys are signed** (F-004, F-006,
  LC-4). Every RelayPack route carries a signed endpoint; an outbound that
  disagrees is refused at import and again at connect; a plain bundle
  cannot replace a committed route; an old public pack cannot roll a route
  back. Spec: `relaypack-v1.md`, `sbp-v1.md`. **Format change: every pack
  signed before this is refused** (nothing is fielded; all fixtures were
  migrated).
- [x] **The freshness channel heals instead of breaking** (LC-2, LC-3). The
  signed pack is merged into the phone's own credentials; L2 and L3 need no
  new file on a polling phone; naive survives an address move on relays
  provisioned from this tree.
- [x] **Routes the minter dropped are not routes** (F-003): not stored, not
  listed, not selectable; the import verdict names them.
- [x] **Families** — FAM-1 (names resolve on naive/tor), FAM-2 (the wizard
  has the opt-in switches — unlocked by TW-1, 2026-11-19), FAM-3 (`--families` refuses
  a typo and says what it drops), FAM-4 + **W5-1** (a relay binds and opens
  only what it serves), FAM-5 (Cronet loads off Android).
- [x] **Relay daemon** — LC-1 (mutating mgmt tokens are single-use), INT-2
  (naive ALPN race), INT-O1 (one in-process reload per verb, no restart).
  All three are in relay-v1.5.1 (TW-1, done 2026-11-19); INT-O1's
  `ExecReload` unit is cloud-init, so it needs a fresh provision.
- [x] **INT-1** — the Cronet use-after-free that killed the engine process:
  `cronet-go` bumped. Linux proven (0 deaths in 1040 sessions, was 3 in
  520); Android is TW-3.
- [x] **F-001** — the artefact verifier works across mounts and says why a
  mirror failed.

### Opened — do these, roughly in this order

- [x] **TW-1. Re-release `daal-relay-mgmt` and re-pin it** (F-002; release
  key). **Done 2026-11-19, relay-v1.5.1**: published as GitHub releases
  `relay-v1.5.1` and `relay-v1.5.1-mirror` (sing-box 1.13.12
  `989e8486…`, health `407581d6…`, mgmt `4f13e453…`), byte-identical to
  the proven candidate; pins moved, both constants `true`, the four
  known-findings entries deleted, F-002 / F-005 / REL-1 marked fixed in
  FINDINGS; `./daal e2e full` → `PASS — 5388 checks`, 18 worlds, the
  three pinned worlds green. **Not yet done:** any relay provisioned from
  it on a real provider, any phone (TW-3, TW-4, TW-16 b). The rest of
  this item is the plan as it was written. One release carries: shadowsocks/anytls/tuic on the box (F-002),
  the family set (FAM-4/W5-1), single-use tokens (LC-1), the naive ALPN key
  (INT-2), the single reload (INT-O1). In the SAME commit as the pin bump:
  set `PinnedMgmtServesOptInFamilies` (`publisher/deploy/cloudinit/
  artifacts.go`) and `RELEASED_RELAY_SERVES_EXTRA_FAMILIES`
  (`client-ui/src/publisher/extraFamilies.ts`) to `true` — a test fails on
  either half alone — and delete the `F-002`, `LC-1`, `INT-2` and `F-005` entries
  from `test-rigs/worldbox/known-findings.json` (the run fails with "did
  not reproduce" until they go). Acceptance: `./daal e2e full`, world
  `release.all-families` all green. Then every relay must be provisioned
  FRESH (cloud-init has no upgrade path). Size: `½d` of release work.
  **Prepared, not published (2026-11-18), and now MANDATORY before
  anything ships:** the release also carries token format v2 (TW-12), the
  certificate re-issue (TW-11) and `GET /identity`; with v2 this tree's
  publisher cannot authenticate to the pinned daemon at all (finding
  REL-1 — every pinned rig world stops at `mint` with an UNEXCUSED red
  check, so `./daal e2e` and the pre-push hook fail until the pin-bump
  commit; on purpose). The tag
  is **relay-v1.5.1** (new bytes never go under a pinned URL):
  `bash tools/release/relay-v1.5.1.sh` stages the candidate, and
  `tools/release/README.md` ("The pin bump") is the full list of what the
  one commit changes — the two constants, the known-findings entries
  **F-002, LC-1, INT-2, F-005**, every `relay-v1.5.0` path, the cloud-init
  golden — and the order (prove with the rig, upload, push);
  `tools/release/pin-bump.py` does the mechanical part. Proven on a
  scratch copy with the candidate as the pinned box: `release.all-families`
  all green, 7 families. Re-run the script if `cmd/daal-relay-mgmt`
  changes again before the release (the pins are a hash of it).
  **Since 2026-11-19 the release also carries `daal-relay-health`'s half of
  the authenticated bootstrap (TW-15 / BOOT-1): the staged
  `dist-release/relay-v1.5.1/` candidate predates it and must be re-staged
  (`bash tools/release/relay-v1.5.1.sh`) before the pin bump** — a relay
  built with the older health binary fails at provisioning, and until the
  bump every pinned rig world stops at `provision` rather than `mint`.
  **Re-staged 2026-11-19 after the last repair** (go1.26.8; health
  `407581d6…`, mgmt `4f13e453…`, sing-box `989e8486…`) and proven on a
  pin-bumped scratch copy: `./daal e2e full` ×2 `PASS — 5388 checks`.
  The release now also carries: tokens bound to the relay (TW-12), the
  query-string refusal (TW-12), and a re-issued certificate that names
  no address it did not already name (TW-11). **Do it by
  `docs/release-runbook.md` steps 1–10.**
- [x] **TW-15. The pin every relay reply is believed on is authenticated**
  (BOOT-1, high; found in review). The management-TLS fingerprint was
  learned from a plain-HTTP health reply, so a machine on the path at
  provisioning could have its own keys signed into a pack — then, through
  the automatic re-sign, at any later time. Closed in the tree: the health
  token (cloud-init user-data, provider HTTPS) is never sent; the URL
  carries a value derived from it and the fingerprint comes back with a
  MAC under it, checked inside the poller for all three providers; no
  fallback (spec `daal-relay-mgmt-v1.md` §2.1). And the wizard refuses,
  instead of re-signing, when a relay that was not rebuilt states a
  different REALITY key or TLS pin (`E_RELAY_KEYS_CHANGED`, en+fa).
  **Released with TW-1** (relay-v1.5.1, 2026-11-19). **Left:** (a) Hetzner still reads the record's
  REALITY key / TLS pin over SSH without checking the host key —
  outranked by `/identity` on a current relay, but give the box's SSH
  host key the same treatment or stop reading them; (b) the rebuild path
  sends Hetzner's root password down that same unchecked SSH session;
  (c) no rig world has an attacker between publisher and relay; (d) the
  refusal is shown in plain words on the recipients screen only — the
  Sign step, the disguise change and the address swap show the coded
  English line. Size: (a)+(b) `½d`, (c) `½d`.
- [x] **TW-2. The app signs a relay before it has what a signed endpoint
  needs** (F-005, high). **Closed in the tree, both halves.** (1) The
  relay states its public identity over the management plane — a tenth,
  read-only route `GET /identity` (`cmd/daal-relay-mgmt/identity.go`,
  `specs/daal-relay-mgmt-v1.md` §4.9) — and the wizard asks before every
  signature on every provider (`daal-deploy relay-identity` →
  `bind-and-sign --relay-identity`; `relay_identity.rs`). The
  provider-specific SSH read is now a fallback. (2) The wizard stores
  what the pack commits to and signs again + republishes the refresh
  note when a later relay reply disagrees: the first recipient on a
  relay that serves shadowsocks, the in-place disguise change
  (`rotate_tls` used to leave both to the operator), a rebuild. The rig
  mints in the app's order (`mint verb.*before-first-recipient`,
  `resign.after-first-recipient`). **Released with TW-1** (2026-11-19):
  the released `daal-relay-mgmt` serves `/identity` since relay-v1.5.1;
  the fallback (keys from the record, or from the reply to adding the
  shared `r0`) is left for a relay too old to answer, and none is in
  service. **Still not done:** the desktop
  app was not run; `rotate_tls` cannot upload the newly signed file to
  the download address (Daal publishes the note, never the file) — the
  result panel tells the operator to; `recipient_provision` builds no
  file when a needed re-sign fails and says so only through the existing
  "Rebuild" state. *Review repair 2026-11-19 (REV-2):* one failed
  automatic re-sign used to latch — the reply was marked handled before
  the signature existed, so every later file was built from a pack known
  to be wrong, silently. It is marked handled only after
  `resign_and_republish` returns Ok; the next reply tries again
  (`a_failed_automatic_resign_is_tried_again_on_the_next_reply`,
  daal-wizard). Not seen in a window.
- [ ] **TW-3. Rebuild Android `libcronet.so` for every shipped ABI, then
  the APK** (INT-1). The `cronet-go` bump changed the library's C ABI; an
  old `.so` beside the new wrapper is undefined behaviour.
  *2026-11-18, the library half is done and the guards have run against
  NDK r27* (detail: `docs/platform-reality.md` §4a-2):
  - `tools/build-engine-android.sh` now makes the pair itself: for each of
    arm64-v8a / armeabi-v7a / x86_64 it relinks the `libcronet.a` of the
    `cronet-go/lib/android_*` module `core/go.mod` pins (about a second
    per ABI) whenever the staged library is missing or does not match,
    and fails if it cannot. **No Chromium toolchain**: the arm64 archive
    needs an lld ≥ LLVM 20 (NDK r27's is 18 — "relocation 315"), and the
    one inside the Rust toolchain is used. The stubs had to change too:
    the new archive carries the real pre-freeze trimmer, so the old strong
    stubs were duplicate symbols (they are weak now).
  - the library says in its own bytes which archive it was linked from;
    the stamp beside it adds the `.so`'s sha256; the engine binary says
    which cronet-go it was compiled against.
    `tools/check-android-so-manifest.sh` compares all three and is run by
    both `check-engine-so-manifest.sh` and `check-deploy-so-manifest.sh`
    (pre-push). The guard at the start of the wave accepted a May library
    with a version file copied beside it; that is a self-test case now.
  - everything Go-built is linked for 16 KB pages (it was 4 KB).
  - the APK builds from the whole tree (`build-engine-android.sh`,
    `build-deploy-android.sh`, then `npm run android:build`: universal
    APK and AAB, exit 0), with the Rust library linked for 16 KB pages
    too (`client-shell/tauri/src-tauri/.cargo/config.toml`; the gate now
    fails on a 4 KB copy of it). Without `keystore.properties` the APK is
    signed with the Android DEBUG key — it must not go onto the phone
    (wrong key ⇒ uninstall ⇒ the operator database is gone).
  **Still open:** (a) re-run `build-engine-android.sh` and
  `build-deploy-android.sh` before every `npm run android:build` — they
  compile the working tree, and the publisher library embeds the relay
  pins, so it must be rebuilt now that the TW-1 pin bump is done
  (2026-11-19); (b) sign with
  `release-keys/android-device-signing.jks`; (c) **nothing was loaded on
  a device** — that the relinked library `dlopen()`s and carries a naive
  session is TW-4 (c)/(d); (e) the `x86` slice with no engine in it is
  still staged and packaged (C1).
- [ ] **TW-4. Phone checks nothing here could do.** (a) Connect on a good
  route, a dead route (button returns an error within ~8 s, says "Could not
  connect on this route"), and a route that dies while connected
  ("Connection lost. Trying again…") — `engine_set_route` now blocks for
  the proof and the Kotlin/Rust callers were not run; (b) the proof against
  the DEFAULT public targets (the lab has no internet); (c) naive with
  Private DNS off, open a site by name; same on tor (FAM-1); (d) naive for
  a day after TW-3, then `adb logcat -b crash` (INT-1); (e) import a pack
  with a dropped route; (f) the wizard's "More ways to connect" section in
  a real window. Size: `½d` with a phone and a relay from TW-1.
  **The full list, with what "pass" looks like per line, is now
  `docs/release-runbook.md` Part 5 (P1–P19).** It adds what the
  release-ready wave needs seen: an old file's route refused in words,
  also while another route is connected (P3, P4); the dead route's reason
  surviving the service's teardown (P5); the cooldown sentence (P6);
  Cancel during the check with no freeze (P7); the first real
  provisioning through the authenticated bootstrap, token v2 and
  `/identity` (runbook steps 18–19); revoke (P14); the disguise change
  saying who needs a file, and naive after it (P15, P16).
- [ ] **TW-5. The second observation** (CEN-4, medium). One route cannot
  tell network-wide UDP loss from one dead address, or a name-keyed reset
  from an address-keyed one; the engine says the coarser true thing
  (`udp_no_reply`, `tls_sni_or_cert_block_suspected`). The prober of the
  selection wave supplies it (`abi.CheckActiveRoute`,
  `diagnostics.ClassifyObservation` are the plug points). Belongs with
  B1/B2. Acceptance: the `CEN-4` known-findings entry goes stale.
- [x] **TW-6. The import screens show which routes were left out**
  (F-003 remainder). The file, paste and QR lanes render the verdict's
  `Unavailable` list on the screen that says "Imported."
  (`components/UnavailableRoutes.tsx`; the QR sheet now stays open when
  there is something to read). Every word is ours: the reason is one of
  four closed codes or the generic sentence, the family a known family
  name or "One way to connect" — `not_offered` is decided by an unsigned
  marker in the profile, so the file may pick the code and never the
  text. **Not verified:** on a phone (TW-4 e); nothing renders the page
  in a test, the component is rendered to markup.
- [x] **TW-7. A tap stops whatever is running** (CEN-5 remainder). On the
  Connection page and the Network page a route that is still being
  checked, or lost and being retried, now offers Cancel / Disconnect
  (`lib/routeCheck.ts` `tapAction`); and the engine ends a failed
  connect's error when the cooldown it started runs out
  (`route_check` → `""`, posture → `NoRoute`; `expireFailedConnect`). A
  failure with no cooldown stays until the person acts. For the two
  whose headline says to try again or wait for the server to be fixed
  (`path_too_slow`, `relay_no_egress`) the main button now connects the
  same route again instead of opening the recovery sheet, which has no
  retry in it (`tapAction`'s `category`; review finding, REV-6).
- [x] **The Network page says why, in words** (review findings, REV-4 and
  REV-5). A connect refused while ANOTHER route was connected showed
  nothing at all (the banner was conditional on nothing being active),
  and a failed connection check showed the shell's raw `engine call
  returned -1`. The tap now always gets a sentence of ours: the refusal's
  (`refusedToShow` — the tap wins over an older refusal still in the
  diagnostics) or, for a failed check, the Connection page's sentence by
  the same category rule (`connectFailedKey`; "Could not connect. Try
  again, or try another route." when nothing more is known) — en+fa,
  `lib/routeCheck.test.ts`. **Not verified:** in a window or on a phone
  (runbook P3, P4, P6).
- [x] **Old routes say why they will not connect.** A route imported
  before the signed-endpoint change is refused at connect; the reason is
  now in the diagnostics blob as a closed code (`connect_refused:
  "needs_new_file"`, also `cooldown`, `revoked`, `expired`, `other`) —
  on Android the returned error reaches nobody — and both pages say "This
  file was made by an older version of Daal. Ask the person who gave it
  to you for a new one." (en+fa).
- [x] **The reason survives the Android service's own teardown** (review
  finding, high; REV-1). The two items above were not true on a phone: the VPN
  service calls `engine_clear_route` right after a start that did not
  come up, and again from `onDestroy`, and that call reset `route_check`,
  `connect_refused` and the posture before the page's first poll — every
  failed or refused connect ended on "Press to connect." with no reason.
  `engine_clear_route` now erases only what it stops: with nothing
  running and no check in flight it leaves the last connect's verdict in
  place (`core/abi` `TestClearRoute_KeepsTheVerdictOfAConnectThatAlreadyFailed`,
  `…KeepsARefusalWhenNothingWasRunning`, `…StillClearsWhatItStops`;
  `specs/engine-abi-v1.md`). Not yet seen on a phone.
- [x] **`engine_set_route` is off the main thread** (review finding,
  high). The Android VPN service made every engine call from
  `onStartCommand` — the main thread — so the connection check froze the
  app for its whole length and raised an ANR on a dead route. All engine
  lifecycle calls now run on one control thread; a stop cancels a check
  in flight from a thread of its own and queues the teardown
  (`DaalVpnService.kt`, "THREADING"). The desktop `connect` command is
  async on the blocking pool. Spec: `android-client-v1.md` "Threading".
  **Compiled** (`npm run android:build`); **not run on a phone** — TW-4 a
  is still the acceptance, and now includes: tap Cancel during "Checking
  the connection…", and Disconnect during "Connection lost".
- [x] **TW-8. naive carries app UDP** (FAM-6; decided: do it). The minted
  naive outbound asks for `udp_over_tcp` v2; the released sing-box's naive
  inbound accepts it unconfigured (source read), the signed-endpoint check
  and the freshness merge keep it, `families/naive.json` is `udp: pass`
  and naive's UDP is asserted under every censor scenario. Needs a re-mint
  of existing packs. **Left:** a phone (datagrams over one TCP stream
  through Cronet — throughput, battery; fold into TW-4), and the rig no
  longer exercises the DNS hijack on any family (it ran on naive only;
  tor/http/ssh keep it, unit-tested).
- [ ] **TW-9. Plain (non-RelayPack) bundles still carry unsigned profiles**
  (F-004/F-006 residual). They can no longer replace a committed route, but
  routes under new ids are unauthenticated. Needs a signed per-route digest
  in the base manifest and its cross-language fixtures. Size: `2-3d`.
- [x] **TW-10. Slow is not silent** (CEN-O5). When every ordinary attempt
  times out on a path the engine saw moving (bytes back; a relay that
  took ≥ 1 s to answer a connection; a SYN answered that late) the proof
  makes one 20 s attempt (`slow_budget_ms`): the route connects as
  `path_too_slow`, or fails as `path_too_slow` with no cooldown, no
  failure row and no signal. A silent route still fails in 8 s. Rig:
  `deep-queue` (2.4 s per round trip; all seven families connect, slow,
  first try — connects of 7–15 s) and `WB_NO_QUIET=1 throttle-56k` (every
  first phone connects). **Still open:** a QUIC route whose handshake
  needs more than one attempt shows no progress and is `udp_no_reply`
  with a cooldown (not reached at 2.4 s; needs datagram counting, CM-1);
  a path fast enough for the proof and too slow for a page is still not
  seen. Also here: **a mid-session block is classified like a failed
  connect** — the liveness check asks once more on a fresh outbound
  instead of trusting a stream from a session opened minutes ago (was
  `unknown` on the families that hold one). *Review repair 2026-11-19
  (REV-8):* the bare TCP connect that settles "is the address alive" ran
  on EVERY timed-out attempt, so a failed route made one payload-less
  connect-and-close to the relay's port per recheck (every 30 s) — a
  pattern of its own on the wire. It now starts only when the timeout
  hides its phase (`timeoutPhaseIsUnknown`); a carry-phase timeout on a
  family that dials eagerly starts none
  (`TestProveSubject_CarryTimeoutMakesNoBareConnectToTheRelay`, measured
  at a counting hop in front of an in-process relay, not on a network).
- [x] **TW-11. The certificate follows the cover host** (LC-3 leftover;
  released with TW-1, relay-v1.5.1). `rotate-tls` re-issues the box certificate on the SAME key
  (no pin, no signed endpoint moves): new cover host first, old names
  kept, the addresses the certificate ALREADY named and no others, 90
  days (review repair 2026-11-19, REV-3: it used to add every address
  the box held, so anyone who could reach the old address read a later
  one — a floating IP bound after first boot — out of the certificate
  with no credentials;
  `TestRotateTLS_ReissuedCertificateDoesNotNameALaterBoundAddress` reads
  it the way a prober does). A file minted after an L2 presents
  the current cover host after a later L3; files from before both keep
  connecting. Rig: world `clean.rotation` now runs l2 THEN l3
  (`box.certificate_follows_cover_host`,
  `after-l2.new-file.presents_current_cover_host`,
  `no-new-file.after-l2.address-blocked.*`). **Left (TW-11b):** a phone
  handed nothing keeps presenting the OLD name after L2 → L3 (its name is
  derived from the certificate it holds). Moving it needs the name in the
  signed endpoint — `Endpoint.server_name` for naive, minter and merge
  following it, `/identity` stating the certificate's first name. A pack
  format change across `bundle`, `relaypack`, identity: `1-2d`. And a
  relay provisioned before the truth wave still has no stable name at
  all: rebuild it. Not verified on Android's Cronet (that it accepts the
  re-issued certificate under the old one as root; linux Cronet does).
- [x] **TW-12. The request is signed into the mgmt token** (LC-1
  residual; released with TW-1, relay-v1.5.1). Token format v2: the Ed25519 signature covers
  the relay the token is for (its mgmt TLS fingerprint — one publisher
  key can serve several relays, and a token minted for one was honoured
  by all of them until this line was added, 2026-11-19; REV-7,
  `TestTokenIsBoundToTheRelay`, `TestTokenAudienceIsTheServedCertificate`),
  op, method,
  path and SHA-256 of the body; v1 is refused by the daemon
  and cannot be minted by the publisher; one shared fixture pins both
  modules. The path is signed WITHOUT a query string, so a request that
  carries one — even a bare `?` — is refused with 400 before the token
  is looked at (review repair, REV-9: `?name=…` used to ride a token
  minted for the bare path; `TestQueryStringIsRefused`), and the three
  token field checks nothing held (`TestTokenFieldChecksHold`, each
  proven by mutation) now have a test. The in-memory nonce set stays as
  defence in depth. **Left:**
  after a daemon restart inside 300 s a captured token can repeat the
  IDENTICAL request once — harmless for every verb except
  `rotate-credentials` (re-mints the same recipient). Closing it means
  persisting the nonce set; recorded in spec §3, not done.
- [ ] **TW-13. Small, recorded, undecided.** ~~`rotate-tls` tells the
  operator every recipient needs a new file when only vless-reality (and
  now, with freshness, nobody who polls) does (LC-O1)~~ — fixed with
  TW-2: the verb, the wizard summary (`NeedsFile`) and the screen say
  who, if anyone, needs a new file; ~~`/whoami` has no
  caller that can authenticate (LC-O2)~~ — fixed: the op is mintable and
  `mgmt.Client.WhoAmI` exists; no CLI verb or wizard caller yet; the first freshness poll always
  downloads the pack (LC-O3 — harmless now); the Android protect callback
  is never called (O-1); shadowsocks/anytls ports reset opaque bytes in
  < 1 ms (CEN-O1 — **root-caused 2026-11-18**: sing's
  `CloseOnHandshakeFailure` sets linger 0; no sing-box 1.13.12 option
  changes it; needs an upstream `fallback` on the anytls inbound and a
  drain-instead-of-reset close — exact call sites in FINDINGS, the tell
  per family in `docs/transport-family-inventory.md`; file it upstream); naive ends a first request with `EOF` on a lossy path (CEN-O4,
  not root-caused); report the INT-2 race to sing-box upstream.
- [x] **TW-14. The connection proof's public targets, decided.** Six
  hosts, six operators, five rules (what the relay's network already
  carries; reachable from a rented server; TLS only and nothing after;
  neighbours are different companies; nobody's donated infrastructure —
  Wikipedia is out, GitHub is in), each rule a test; the argument for who
  learns what is in `engine-abi-v1.md` "The default targets". A relay
  that answers and reaches none is `relay_no_egress` — "Reached the
  server, but the server itself cannot reach the internet" — never a
  cooldown. **Not verified:** from a relay in every hosting region (the
  six answer TLS from one residential network); `relay_no_egress` on
  shadowsocks and naive (their dial does not include the relay's answer:
  `unknown`), and a relay that CLOSES instead of going silent (no route,
  no resolver) is still `unknown`. TW-4 b stands.
- [ ] **TW-16. Left open by the release-ready wave (2026-11-19).** None
  blocks the release; each is recorded where it belongs and gathered
  here so the next pass starts from one list.
  (a) Nothing of this wave has run on a device or in a desktop window:
  the Kotlin threading, the surviving reason, every new sentence
  (runbook Part 5). (b) `relay-v1.5.1` is uploaded (2026-11-19), but no
  relay on a real provider has downloaded it yet — the rig serves the
  same bytes from a lab mirror under the pinned addresses. (c) TW-15
  (a)–(d): Hetzner's unchecked SSH host key for the record fallback and
  the rebuild password; no rig world with an attacker between publisher
  and relay; `E_RELAY_KEYS_CHANGED` in plain words on one screen of
  four. (d) TW-12: the nonce set is in memory — one identical replay
  inside 300 s after a daemon restart. (e) TW-11b: a phone handed
  nothing presents the old cover name after L2 → L3. (f) The Network
  and Connection pages are tested through their pure helpers
  (`lib/routeCheck.ts`); no test renders either page. (g) No recipe is
  known that makes a correctly released relay mint a file with a
  left-out route, so TW-4 (e) / runbook P17 may only ever show the
  "older than this phone has" line — or a refusal. (h) The APK still
  packages an `x86` slice with no engine in it (C1; the gate warns).
  (i) ~~The pre-push hook and CI are red on this tree until the pin
  bump~~ — the pin moved 2026-11-19 (TW-1); the wave and the pin bump
  must still be pushed together.

## 14. First phone pass on relay-v1.5.1 (2026-11-19) — what a real relay showed

Samsung S25, APK from `edd3a5e`, one Hetzner relay provisioned from the
phone by the owner. What passed is in `docs/release-runbook.md` Part 5;
this section is what did not.

- [x] **PH-1. The cloud firewall lost a race with the new server.**
  Hetzner refused the attach 280 ms after create ("no public network
  interfaces found … private_net_only_server"); provisioning went on
  without it and the mgmt self-heal attached one later with the
  fleet-baseline ports, which would leave an opt-in family's port shut.
  Fixed: the attach is retried (8 × 3 s) where the family set is known
  (`ensureFirewallAfterCreate`; `TestProvision_FirewallAttachOutlastsTheNewServerRace`,
  `TestProvision_FirewallAttachGivesUpAndSaysSo`). Not yet seen passing
  on a real account.
- [x] **PH-2. The relay page is hard to read (owner, on the phone).** In
  the owner's words: not clean or minimal; not obvious what is for
  everyone and what is for one device; what "Refresh addresses" means;
  how "+ Add" (a recipient) differs from "+ Add address" (a refresh
  address); too much text. Fixed in the tree, not yet seen on a phone:
  the page is now People / One file for everyone / Keep it working /
  Danger zone / Details, one sentence each, explanations behind a tap,
  buttons that name their noun ("Add a person", "Add a refresh
  address"); the raw signed file and "Compare the list with the relay"
  live under Details. Pinned by `publisher/relayPage.test.tsx` (section
  order, one sentence per section, EN/FA key parity, static render in
  both languages). Layout was checked by static render only, never by
  eye; the Farsi was written by the wave and wants a native read.
- [x] **PH-3. Save gives no sign that it worked.** Saving the `.sbpx`
  did save, and said nothing; the owner tapped four times. Fixed in the
  tree, not yet seen on a phone: every publisher action goes through
  one controller (`publisher/useAction.tsx`) that locks while it runs
  and ends in a banner — what happened, or what did not and why in
  plain words, the raw error behind Details. Pinned by
  `publisher/useAction.test.tsx` ("a double tap fires the action once",
  "success ends with a visible result", "failure ends with what did not
  happen…") and `publisher/failureText.test.ts`. Swept: save / send /
  copy / make / replace / add / remove / rename / compare / recovery
  key / refresh-address actions.

### The fix wave (2026-11-19, branch `phone-pass-fixes`)

What the pass showed beyond PH-1..3: one tap on another route's Connect
while connected left the tunnel up and the app blind ("No route
selected", a red "unknown", "Loading…" for ever, nothing in logcat).
Every item is **fixed in the tree, not yet seen on a phone**; the cause
is read from the code and reproduced in the rig, not proven on the
device. (Numbered after the repair pass below, which was written
first.)

- [x] **PH-11. The TUN fd had two owners.** The host copy was closed
  while the old sing-box instance still held the same number, then
  closed again with the instance; whatever opened in between lost its
  file (rig finding SW-0). Now one owner per copy: the engine owns the
  host's copy (`AdoptTunFD` / `ReleaseTunFD`), each instance gets its
  own duplicate. Pinned by `TestTunSwitchDoesNotCloseAnUnrelatedFD`,
  `TestTunDisconnectClosesEachCopyOnce`,
  `TestOpenInterfaceClosesItsDuplicateOnFailure`,
  `TestSetTunFdOwnershipSemantics`, and in the rig by `*.fds_intact`
  on every switch and disconnect (red against the old two files). The
  rig proves the double close; it never made the route store the
  victim, so "the store died of it" is still an inference.
- [x] **PH-12. The route store failed under its own readers, and a
  damaged one would have crashed every launch.** One connection with a
  busy timeout instead of an unbounded pool
  (`TestConcurrentReadersAndOneWriterNeverError` — 4951 failed calls
  before — and `TestStoreUsesOneConnectionWithItsPragmas`); the
  diagnostics record is written only when it changes
  (`TestDiagnosticsExplain_WritesOnlyWhenTheRecordChanges`); a damaged
  file is set aside beside itself, never deleted, an empty store opens,
  and diagnostics say `store_recovered` so the app can tell the person
  to import again (`routestore/recover_test.go`,
  `TestInit_DamagedStoreIsSetAsideAndReported`,
  `TestInit_DamagedStoreIsReportedEvenWhenTheMarkerCannotBeWritten`,
  `TestInit_OrdinaryStoreErrorStillFails`; UI `lib/storeNotice.test.ts`).
  The shell no longer `expect`s on engine or operator-DB start and no
  call reaches an engine that did not start (`failed_init_leaves_a_usable_process`,
  `every_core_call_is_gated`); the page that says so is PH-10.
- [x] **PH-13. The pages learned the active route only through the
  store.** `ExportDiagnostics` now carries `active_route` /
  `active_route_family` from engine memory and the pages read that
  first; a route whose row cannot be read shows as "Current connection
  · name not available", never "No route selected" while connected.
  Pinned by `TestActiveRoute_ServedFromMemoryWhenTheStoreFails`,
  `TestActiveRoute_FollowsTheEngine`, `backends/tauri.test.ts`,
  `lib/activeRoute.test.ts`; in the rig by `*.active_route`.
- [x] **PH-14. Errors were masked in three layers and logged in none.**
  Every export wrapper notes its failure (`recent_errors` in
  diagnostics, scrubbed; `TestEveryExportWrapperReportsItsFailure`,
  `TestRecentErrors_RecordedLoggedAndScrubbed`,
  `TestRecentErrors_SetRouteKeepsOnlyCodes`); the shell attaches the
  engine's words to "engine call returned -1" and logs every failed
  command (`every_result_command_is_logged`,
  `addresses_never_reach_the_log`); the engine logs route up / switch /
  refused / down by id and code (`TestRouteLifecycleIsLogged`); the
  service logs each step of a start. The pages show their own sentence
  with Try again and the raw text under Details, and no "Loading…"
  after a failed read (`lib/errorText.test.ts`, `lib/networkRows.test.ts`
  "never says "Loading…" once the read has failed",
  `d2pages/PageNotices.test.tsx`).
- [x] **PH-15. A config-parse failure wrote the whole sing-box config,
  credentials included, to logcat.** Gone; the line is now the error's
  class, category and outbound type
  (`TestStartParseFailureDoesNotLogTheConfig`).
- [x] **PH-16. A refused switch disconnected the working route, and
  wiped the reason.** The service asks first (`engine_route_precheck`)
  and touches nothing when refused; a switch keeps the TUN it has; a
  switch that fails goes back to the last proven route. Pinned by
  `TestRouteConnectPrecheck`,
  `TestRefusedSwitch_LeavesTheRouteAloneAndADisconnectClearsTheReason`,
  `StartSequenceTest` (`refusedSwitchLeavesTheWorkingRouteUntouched`,
  `switchReusesTheTunAndNeverBuildsOne`,
  `switchToARouteThatCarriesNothingGoesBackToTheOldOne`), and in the
  rig by `check-rotate.refused.*`. `DaalVpnService` itself (threads,
  the real `establish()`) is tested by nothing but a compile. What is
  left of this is PH-8.
- [x] **PH-17. On Android a newer start waited behind a check in
  flight.** It now cancels it
  (`SwitchPolicyTest.newerStartCancelsACheckInFlightInsteadOfWaitingBehindIt`).
  Residual: a cancel landing between "marked checking" and the engine
  entering the check drops the connected route for a moment; the next
  start restores it
  (`theStartAfterACancelledSwitchRestoresTheLastWorkingRouteIfRefused`).
- [x] **PH-18. The Connections page could not cancel a check it
  started, and marked the tapped row connected before the engine said
  so.** A checking row has Cancel; the old row stays marked until the
  engine reports the new one; a refusal for the tapped row is said in
  words (`lib/networkRows.test.ts`; source pin in
  `lib/routeCheck.test.ts`). The limit of that Cancel is PH-7.
- [x] **PH-19. The rig never switched routes.** Ops `switch` (quick)
  and `switch-all` (full, all 42 ordered pairs of the 7 families) run
  the service's call order on a real TUN and assert tunnel, wire,
  store, active route and fd identity after every switch and
  disconnect (`driver/ops_switch_test.go`; `FINDINGS.md` SW-0, SW-1,
  SW-2).
- [x] **PH-20. A green "LIVE" above "not a live health check".** The
  recorded state reads "Set up" in gold; green "Live" is reserved for a
  check that just succeeded, and no such check exists yet
  (`publisher/relayStatus.test.ts` "a recorded state is never green and
  never says live").
- [x] **PH-21. A disguise change could say "Nobody needs a new file"
  when re-signing had failed.** It now says what happened and what to
  do (`publisher/rotateTlsVerdict.test.ts`). The "what to do" sentence
  is read from `relay_identity::heal_after_reply`, not exercised.
- [ ] **PH-22. A person's file cannot be shown as a QR or copied as
  text.** `wizard_qr_render` and `wizard_copy_pasteable` take only
  `shared | raw`; both need a per-person file, plus the variant in
  `wizardCommands.ts`.
- [ ] **PH-23. When the engine cannot start, the shell cannot say
  why.** `engine_init` returns -1 and there is no Core to ask;
  `engine_status` reports the path only. Needs an init-error accessor
  in the ABI. Related: an invalid `secrets.key` still fails start (on
  purpose — it is not damage) and has no recovery path.
- [ ] **PH-24. Small leftovers of the wave.** The store-reset notice
  shows once per app run, so again on each launch until a file is
  imported; the two extra summary fields live in
  `ConnectionSummaryPlus` instead of the contract type; the wave's
  ten recipient strings are in the legacy `i18n/{en,fa}.json`, not
  `d2-extra`; retired `pub.*` keys are still in the catalogs; a TUN
  the system killed without telling the service would be reused;
  `src-tauri/src/lib.rs` command bodies are wrapped but not
  re-indented; `go build -tags gomobile ./abi` was already broken
  (`share_gomobile.go`) and still is.
- [ ] Routes still read "not measured yet" — telemetry, a later stage.

### Repair pass after the fix wave (2026-11-19, branch `phone-pass-fixes`)

Review of the fix wave found the items below. Closed ones name their
test; **none of this has been seen on a phone.**

- [x] **PH-4. A route switch on a kept TUN lost about half of all
  packets (rig finding SW-2).** sing-tun 0.8.9 never stopped the packet
  reader of a closed instance; the service's new "keep the TUN across a
  switch" order made that reader compete with the new instance. Fixed
  in the engine: `third_party/sing-tun` (0.8.9 + one line) through a
  `replace` in `core`, `cmd/daal-core`, `cmd/daal-soak-engine` and the
  rig's `labclient` (`third_party/DAAL-PATCH.md`). Pinned by
  `TestSingTunDetachReachesTheEndpoint` (`-tags singbox,with_gvisor`,
  run by `./daal test`) and by the rig's `keep.*.tunnel` /
  `*.session.old_tuns_released`, which are ordinary green checks now
  (SW-2 is gone from `known-findings.json`). Follow-up: drop the copy
  when a sing-tun release that sing-box 1.13.x accepts carries the fix
  (0.8.10–0.8.15 exist and were not evaluated). First thing to try on
  the next phone pass: after one switch, do pages load?
- [x] **PH-5. A switch that failed and was undone left the tapped row
  on "Checking the connection…" for 90 s, then silence.** The page now
  reads the VPN service's `vpn_status.last_switch` and says "That route
  could not be used. You are still connected through the other one."
  (`lib/networkRows.ts`, `backends/tauri.test.ts`); a wait that runs
  out says so too; the service forgets an older note when a new start
  begins (`StartSequenceTest`).
- [x] **PH-6. Tests nothing ran.** `./daal test` now runs the Android
  service's JVM tests (`tools/test-android-jvm.sh`, 31 tests, real
  JUnit, no Android SDK), `cargo test -p daal-desktop-core` against an
  engine built from the tree (a missing engine is a failure there, not
  a skip), and the sing-tun pin. The four source-pin tests in
  `client-ui/src/lib/connectThreading.test.ts` are re-pinned to
  `StartSequence.kt` / `SwitchPolicy.kt`.
- [ ] **PH-7. "Cancel" on a pending switch cannot give the old route
  back.** While route A is still carrying and B has just been tapped,
  B's button now reads "Disconnect" (it stops everything, and says so)
  instead of "Cancel". A real cancel — abandon B, stay on A — needs the
  service to treat a cancel during a switch as "go back to the last
  proven route" (a new plugin command; `StartSequence` already knows
  how to restore). Once the engine has stopped A to try B (SW-1) there
  is nothing to stay on, so this is tied to PH-8.
- [ ] **PH-8. A switch to a route that carries nothing drops the
  connection for the length of the check (rig finding SW-1, open).**
  The service goes back to A afterwards; closing the gap means the
  engine proving B beside A and swapping only then.
- [ ] **PH-9. The Gradle task for the plugin's unit tests has never
  run.** `:tauri-plugin-daal-platform:testDebugUnitTest` configures and
  compiles offline but `junit:junit:4.13.2` is not in the Gradle cache
  of the build machine. `tools/test-android-jvm.sh` covers the same
  tests without Gradle; run the Gradle task once online so the IDE path
  works too. Also unverified: that the CI runner has `kotlinc` and a
  Gradle distribution for that script (with `CI` set a skip is a
  failure, by design).
- [x] **PH-10. When Daal could not start, the pages said nothing.**
  The Connection and Connections pages now say "Daal could not start on
  this device" with the reason under Details (`lib/engineStart.ts`,
  asked of `engine_status`), a tap on the main button no longer starts
  a connect that can only fail, and the Publisher tab no longer prints
  the framework's error as its sentence. The Daal mark is not drawn as
  disabled while the notice is up; it simply does nothing.
