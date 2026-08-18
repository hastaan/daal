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

---

- [ ] **W5-1. The box binds two listeners for families the relay does not serve.**
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
  - `libcronet.so` is present **only** under `arm64-v8a`. The naive tier is
    therefore arm64-only on Android. `build-engine-android.sh:91` already
    documents this condition per ABI; it should be stated in the release
    notes rather than discovered.
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
