# Daal — capability matrix

**What this answers:** "is all the point in their place in terms of backend
and UI?" For every user-facing capability, this traces the whole chain —

```
Go //export  →  core/abi  →  daal-desktop-core / daal-wizard (Rust)
             →  #[tauri::command]  →  TS wrapper  →  a component that CALLS it
             →  a screen a user can navigate to
```

— and records where it stops. Derived 2026-08-18 against
`solidify-before-selection`, and **reconciled against
`docs/platform-reality.md`, `docs/telemetry-audit.md` and
`docs/backlog-post-45.md` at the end of the same wave.**

**Which document wins.** Four owners wrote into one worktree, so the four
documents are deliberately non-overlapping and each is authoritative for one
thing: this file for *"can a user reach it"*; `docs/platform-reality.md` for
*"what can this OS actually do"*; `docs/telemetry-audit.md` for *"is this
number measured"*; `docs/backlog-post-45.md` for *"what is still owed and what
it costs"*. Where any of them disagrees with the tree, **the tree is right** —
that is the failure mode this whole wave exists to catch.

**Headline: 55 SHIPPED · 17 UNREACHABLE or CLI-ONLY · 7 PARTIAL · 3 INERT (plus CM-8, inert copy) ·
2 NOT MEASURED.**

The first draft of this table said "nothing is *missing a backend*" and
sorted every gap into "no screen" or "no number". **That was wrong, and it
was wrong in the dangerous direction** — it over-reported reachability, which
is the one error this document exists to prevent. A third failure shape
exists and now has its own status: the whole chain is present *down* to
storage, the user reaches a real control, the value is validated and
persisted — and **nothing ever reads it back**. The setting is accepted and
inert. Three capabilities were sitting in SHIPPED in that state (§4b), and
`docs/telemetry-audit.md` had already said so for two of them, so the two
documents were not in fact reconciled on the point they both claimed. They
are now, and §4b is the reconciliation.

The **2 NOT MEASURED** are both the byte counter, seen from two surfaces —
the Connection page's `↑/↓ B/s` readout and `stats_redacted.bytes_in/out` in
the exportable diagnostics blob. One root cause, one backlog item (**CM-1**).
Both now report `null` ("nobody counted") instead of `0` ("counted, nothing
moved"); the counter itself still does not exist. `NetworkSignals` was a third
entry when this table was first written and is **no longer** — the telemetry
lane gave 5 of its 9 values a real producer in this same wave; it now sits in
§3 as PARTIAL.

**Method.** Names and comments were not trusted. Every row was produced by
walking the real inventories (`tools/check-plumbing.mjs --json`, the
`#[tauri::command]` list, the `invoke()` targets, the Go `//export` list) and
then, for each TS wrapper, grepping for a caller **that is not its own
declaration and not a test** — the way `qrRender` hid in Wave 4 — and for each
component, confirming an import that renders it from a mounted shell — the way
`AddEntryModal` hid.

**Why the existing gate cannot see the bottom of this table.**
`tools/check-plumbing.mjs` has four rules and they are all satisfied the moment
an `invoke()` wrapper exists *somewhere in `client-ui/`*. All of
`wizardCommands.ts`, `tauri.ts` and `bridge.ts` are in `client-ui/`. So a
capability can be green in the gate, complete in Go, complete in Rust,
registered, typed, wrapped — and have no screen.

That is **20 wrappers**, presented below as 13 of §1's 17 rows (several rows
bundle siblings: sub-key is 3 wrappers, CDN fronting is 4, cell labels are 2).
Counted mechanically: 14 `Wizard.*` wrappers that appear **exactly once** in
all of `client-ui/src` — in their own declaration in `wizardCommands.ts` —
plus 6 `D2Contract` methods with **zero** `.tsx` callers. The remaining 4 rows
are a different class: the rotation rungs (a live call site passing one
literal), and LAN share / mDNS browse / the TUN-fd pair, which the gate *does*
report, in its allowlist, with reasons. Backlog **CM-4** carries this count.

| status | meaning |
|---|---|
| **SHIPPED** | a user can reach it from a screen, and the backend behind it is real |
| **PARTIAL** | reachable, but a documented part of the capability is missing or platform-limited |
| **CLI-ONLY** | fully implemented; the only driver is a terminal binary, not the app |
| **UNREACHABLE** | every layer exists except a caller; no user can trigger it by any means |
| **INERT** | a user reaches a real screen, the value is validated and persisted — and no production code ever reads it back, so the setting cannot change anything |
| **NOT MEASURED** | the screen renders it, but no code produces the number |

Platform note: there is **one** UI (`client-ui`, a Tauri webview) on both
Android and desktop. The platform column is therefore about the data plane and
the device, not about a second codebase. **The desktop links
`engine.NewStub()`** (D1) — `core/abi/dataplane.go` makes `SetRoute` fail
closed there, so the desktop is honest, but it cannot carry traffic. The full
per-OS account is `docs/platform-reality.md`, written in the same wave; this
table does not repeat it.

---

## 1. UNREACHABLE — nothing can trigger these

Sorted so they are impossible to miss. Every one of these has a working
backend and a typed TS wrapper.

| Capability | Chain | Stops at | Platform | Smallest change that finishes it |
|---|---|---|---|---|
| **Delete a single route** | `engine_route_delete` → `abi.RouteDelete` → `route_delete` → `bridge.routeDelete` → `D2Contract.routeDelete` | no `.tsx` calls `routeDelete` | both | A row action on `NetworkPage`'s route list, beside the publisher-delete it already has. `½d` incl. en+fa confirm copy. Asymmetric today: you can delete a whole publisher but not one of its routes. |
| **Refresh every revocation list now** | `engine_revocation_refresh_all` → `abi` → `revocation_refresh_all` → `tauri.revocationRefreshAll` | no `.tsx` caller | both | One button on `StatusPage` beside the bootstrap-refresh it already has. `½d`. |
| **Re-order rendezvous priority** | `engine_set_rendezvous_priority` → `abi` → `set_rendezvous_priority` → `tauri.setRendezvousPriority` | no `.tsx` caller | both | `SettingsPage` already hosts the other four rendezvous switches; this one needs an ordered list control, not a toggle. `1d` — it is a design decision (what order means to a user). |
| **Redistribute a route to a recipient** | `engine_redistribute_route` → `abi` → `redistribute_route` → `tauri.redistributeRoute` | no `.tsx` caller | both | Recipient-side re-share has no surface at all. `wave` — it needs to answer "who am I sharing with" first. |
| **Read/write a cell label** | `D2Contract.cellLabelGet/Set` | no caller **and no engine** — `backends/tauri.ts` implements them as a `Map` that dies with the process | both | Backlog **T1**. `core/trust/labels.go` has the real store; nothing binds it. `1d`. |
| **Rotation: ask what to rotate** | `wizard_rotate_recommend` → `Wizard.rotateRecommend` | no `.tsx` caller | both | Backlog **W3-5** smallest slice, and the prerequisite for **W3-11**. The wrapper already accepts `network_signals` and `explanation_json` — it is the one publisher-side consumer of selection output. `½d`. |
| **Rotation: revert / history** | `wizard_rotate_revert`, `wizard_rotate_history` | no `.tsx` caller | both | Backlog **W3-5**. History is the worse one: `pub.danger.address.field.reason` tells the user their reason is "kept in this relay's history" and no screen can read it back. |
| **Sub-key rotate / active / history** | `wizard_subkey_*` → `daal-publish subkey rotate` | no `.tsx` caller | both | Backlog **W3-5**. CLI escape hatch exists (`bundle/go/cmd/daal-publish`), so a Helper is not blocked. |
| **CDN fronting (token, provision, list, verify posture)** | `wizard_store_cloudflare_token`, `wizard_provision_cdn_front`, `wizard_list_cdn_fronts`, `wizard_verify_cdn_posture` | no `.tsx` caller | both | Backlog **W3-5**. `daal-deploy cdn-provision` / `cdn-rotate-*` cover provision+rotate from a terminal; `list` and `verify-posture` have no CLI verb either, so those two are unreachable by **any** means. |
| **Server pricing lookup** | `wizard_pricing_lookup` | no `.tsx` caller | both | Backlog **W3-5**. `daal-deploy pricing` exists. The wizard picks a server type without ever showing a price. `½d`. |
| **Import an existing publisher key** | `wizard_publisher_keyimport` | no `.tsx` caller | both | Backlog **W3-5**. Blocks migrating an existing publisher identity onto a new device through the GUI. |
| **Finalize a pre-provision** | `wizard_finalize_pre_provision` | no `.tsx` caller | both | Backlog **W3-5**. |
| **Get an operator's .sbp path** | `wizard_get_sbp_path` | no `.tsx` caller | both | Backlog **W3-5**; largely superseded by `saveSharedSbpToDownloads` / `saveSbpxToDownloads`, which *are* wired. Candidate for deletion rather than a surface. |
| **Rotation rungs L1, L2, L4–L9** | `wizard_rotate_execute` implements nine rungs | `AddressSwap.tsx:157` is the only `rotateExecute` call site and passes the literal `'L3'` at `:159` | both | Backlog **W3-4**. `wave` — each rung needs its own consequence copy. |
| **LAN share (send/receive over Wi-Fi)** | `engine_share_begin/end/pull/pull_url`, `engine_fountain_next_frame` → typed Rust wrappers | **no `#[tauri::command]` at all** | both | Deliberate: Wave 4 wired QR + base64 and stopped there. Allowlisted in `check-plumbing.mjs` rule 4 with the reason. **CLI-ONLY** via `daal-core share-serve` / `share-pull`. |
| **Browse for nearby senders (mDNS)** | `engine_share_browse` | `core/abi/share.go::ShareBrowse` is a hardcoded `{"services":[]}` | both | Not dlsym'd on purpose — offering a "find nearby senders" button guaranteed to find nothing is worse than not offering it. Needs a real Go browser first. |
| **Deliver / clear a TUN fd from the GUI** | `deliver_tun_fd`, `clear_tun_fd` in `commands.rs` | no `#[tauri::command]` | desktop | On Android the fd goes plugin → JNI → `engine_set_tun_fd`, bypassing these. On desktop **nothing delivers an fd at all** (see §3, Connect). |

**Also unreachable, and that is fine:** `D2Contract.availableRoutes`,
`routeSummary` and `skippedFamilies` have no `.tsx` caller, but the underlying
engine calls are reached — `backends/tauri.ts` uses `rawAvailableRoutes` /
`rawRouteSummary` internally to build `whyThisRoute` and `routeHealth`, and
skipped families render through `WhyThisRoute`. These three are contract
surface for a second platform implementer, not dead capability.
`bridge.startSidecar` / `stopSidecar` likewise have no UI caller because
`src-tauri/src/lib.rs:2670` starts the sidecar at app launch; the TS wrappers
are vestigial. Removing them would turn `check-plumbing` rule 3 red, so they
stay until the sidecar topology itself is retired.

---

## 2. NOT MEASURED — a screen renders it, no code produces it

| Capability | What the user saw | Truth | Status |
|---|---|---|---|
| **Throughput (↑/↓ B/s)** | `ConnectionPage` printed `↑ 0 B/s ↓ 0 B/s` for the whole life of every connected session, and `StatusPage` drew a flat sparkline through it | `abi.ThroughputSnapshot` divided `throughputCounters.upBytes/downBytes` by the window. **Nothing in the repository ever incremented either field.** Structurally zero on every build, every platform, forever. | **fixed this pass** — now reports `null` = unmeasured; see §5 |
| **`stats_redacted.bytes_in/out`** | `0`, in the diagnostics blob the user exports and hands to a helper — where a zero reads as the *diagnosis* "the tunnel carried nothing" | `singBox.Stats()` reads `platformInterface.bytesIn/bytesOut`, declared `// reserved for the stats follow-up phase` and never written. `Stub.Stats()` returns `(0,0,nil)` by contract. This is the same absent counter as the row above, one surface over: the first fix reached `ThroughputSnapshot` and stopped there. | **NOT MEASURED** — the *number* is still backlog `CM-1`; the *zero* was **fixed at reconciliation** (§5), and `TestByteCountersReportNullWhenUnmeasured` now guards both surfaces |
| **Probes (UDP / DNS / TCP:443)** | an "unavailable" tile | `probeStub` returns `ProbeUnimplemented = -1000` and the UI maps it to unavailable rather than a fake pass. Already honest. | PARTIAL, honest |
| **"Why this route" skipped list** | "not evaluated" | `refresh.go` hands `selection.Decide` a **one-element** route slice, so `failures` is always empty; `tauri.ts:337` detects the too-short shortlist and renders `null`, not `[]`. Already honest. | PARTIAL, honest |

---

## 3. PARTIAL — reachable, with a named limit

One row below is an exception to that heading and is flagged in place:
`network_signals` is **not** reachable — it is measured and emitted by the
engine and read by no UI code. It is kept here rather than moved to §1
because §1 is about wrappers with no caller, and this is a different shape
(a field dropped by an adapter's type). The headline counts it under PARTIAL;
if you are counting user-reachable capabilities, subtract it.

| Capability | Screen | Platform | Limit |
|---|---|---|---|
| **Connect / disconnect** | `ConnectionPage`, `NetworkPage` | **Android: SHIPPED. Desktop: cannot carry traffic, and now says so on both surfaces.** | Desktop links the Stub (**D1**). `SetRoute` fails closed with `ErrNoDataPlane` (`core/abi/dataplane.go`), which is the load-bearing guarantee — the Stub can never publish "Connected". On top of that, both connect surfaces now read `conn.dataPlane === 'none'`, render the `conn.no_data_plane.*` alert (en+fa) and short-circuit the press *before* calling the engine: `ConnectionPage.tsx:183/213` and — added at reconciliation — `NetworkPage.tsx`, which is where the FIRST connect on a fresh install actually happens (ConnectionPage's Connect only fires once an active route exists). Until that fix, a Farsi desktop user pressing Connect from the Routes list got the raw English Go error, `-tags singbox` build hint included. Note the button is not `disabled`; the press is intercepted and answered. Desktop additionally has no TUN fd: `deliver_tun_fd` has no caller anywhere in the tree. |
| **Add a route by animated QR** | `ScanSheet` → `RecipientImport` | Android; desktop only with a webcam | `RecipientImport.tsx:468` checks `navigator.mediaDevices?.getUserMedia` and degrades honestly. |
| **Save a pack to the device** | `PublisherRecipientsPage` | Android (Downloads) | `save_shared_sbp_to_downloads` / `save_sbpx_to_downloads` are Android-shaped. |
| **Windows TUN helper** | — | Windows | `tun_helper.rs:232` `win::ping` returns "not implemented in 1.5B scaffold" (**D2**). |
| **Scheduler cadence** | `StatusPage` | both | Not **B3** — that item is **closed**. `scheduler:last-bootstrap-refresh` *is* persisted (`abi/scheduler.go` `storeSource.LastBootstrapRefresh` reads it, `refreshExecutor.RefreshBootstrap` writes it success-gated) and `scheduler.Plan` reads it, so the cadence is exact; the item existed only because the read carried a stale comment. The **real** limit is who turns the crank: `scheduler_tick` is driven from `src-tauri/src/lib.rs` (60 s thread) and Android's `DaalVpnService.startSchedulerPump`, never from the UI, so nothing advances while the app is closed and the tunnel is down. That is the blackout case, and it is **W3-3**. |
| **Two connect surfaces** | `ConnectionPage` + `NetworkPage` | both | **A6** — they agree on state now, but have not been collapsed to one model. |
| **`network_signals`** (diagnostics explanation) | **no screen — engine payload only** | both | **Measured, carried, and consumed by nothing in the UI.** The first draft of this row said it was visible on `StatusPage` → "why this route"; it is not, and the correction matters because that is the Wave-2 cover-SNI shape (a value crosses three layers, a struct in the middle drops it) with an audit line asserting it arrived. What is true: `selection.SignalForCategory` / `SignalsFromCategories` turn the durable `routes.last_failure_category` into 5 of the 9 signals and `abi.activeNetworkSignals` feeds them to the one production `Decide` call, so `engine_diagnostics_explain` really does emit `"network_signals": [...]`. What is false: no TS or TSX code reads the field. `grep -rn 'network_signals' client-ui/src` returns two *type declarations* and no reader; `WhyThisRouteSummary` (`contract/D2Contract.ts`) has no signals field, so `backends/tauri.ts`'s `parseExplanation` drops it; and the fallback surface does not carry it either — `abi.ExportDiagnostics` emits no such key, and `StatusPage` truncates the raw blob to 600 chars. Other limits, unchanged and real: the other 4 signals are cross-network probe aggregations with no prober and are deliberately not synthesised (**B2-c**), and the set is per-device rather than per-network because the network ID is a constant (**B2-a**). New item **CM-5** carries the UI surface. Full account: `docs/telemetry-audit.md` §3. |

---

## 4. SHIPPED — reachable, real backend, both platforms

Grouped; each was confirmed to have a component caller AND a mounted screen.
Every one of these is reachable from `MobileShell` / `TabletShell` /
`DesktopShell` via `ShellRouter`.

**Boot & identity** — vault unlock (PIN) · first-run onboarding · engine/GUI
version probe · heartbeat · lifecycle events (sleep/wake/memory) · network-change
notification · locale switch en↔fa · panic wipe.

**Connection** — mode switch (normal/lifeline/…) · "why this route" ·
route health · pointer-rotation banner · recovery sheet · connection duration ·
diagnostics export to clipboard.

**Routes & trust** — add by file (`.sbp` / `.sbpx`) · add by pasted base64 ·
add by `daal://` URI · add by animated QR · trust-prompt resolution ·
apply cooldown · burn-pressure verdict · publisher delete · subscription
list / add / remove / refresh.
*(per-route budget tag moved to §4b — the cap is stored and never enforced.)*

**Recipient identity** — "my Daal address" · device custody level, lock,
rotate, history, event log.

**Settings** — allow-bulk-capable · push rendezvous · auto-promotion ·
loaded WASM modules · WASM kill-switch pubkey · bootstrap install-seeds /
refresh / status.
*(MASQUE sub-mode override and experimental families moved to §4b — both
are stored and never read.)*

**Publisher (opt-in tab, both platforms)** — operator + relay list · custody
gate · 3-screen provisioning wizard · relay teardown with rollback · recipients
page · sign relaypack · distribute shared `.sbp` · per-recipient `.sbpx` ·
save to Downloads · animated-QR send (`QrSendSheet` → `Wizard.qrRender`) ·
L3 address swap · freshness panel · rotate credentials · rotate TLS.

---

## 4b. INERT — a real screen, a real store, and no reader

These were in §4 SHIPPED in the first draft of this table. Each has a
control a user can find, a Tauri command, a Go setter that **validates**
its input and **persists** it. And each ends at storage: the value has no
production reader, so setting it changes nothing at all. That is worse
than an unreachable capability, because an unreachable capability makes no
promise — this one takes an instruction from the user and drops it while
the UI reports success.

Verified by grepping for a caller that is neither the declaration nor a
test, the same method §1 uses.

| Capability | Screen | The chain, as far as it goes | The dead link | Cost to the user |
|---|---|---|---|---|
| **MASQUE sub-mode override** (see the Wave-5 note under this table before "fixing" it) | `SettingsPage.tsx:564-572` (auto / h3 / h2 / h1 dropdown) | `set_masque_submode_override` → `abi.SetMasqueSubmodeOverride` (`core/abi/masque.go:42`) validates the sub-mode and persists it into `secrets_kv` | **`abi.MasqueSubmodeOverride()` (`masque.go:62`) has zero production callers.** The only other mention in the tree is a doc comment on `masque.WithOverrideFn` (`core/transports/masque/masque.go:192`) describing a closure nobody writes — and `masque.NewHandler` (`:211`) itself has zero production callers. | A user pins `h2` to get out from under a QUIC block. The dropdown holds the value across restarts. The engine never asks. New item **CM-6**. |
| **Experimental families** | `SettingsPage` toggle | `engine_set_experimental_families_enabled` → `abi` → persisted | **`pathmanager.RankWithExperimentalGate` (`family_filter.go:80`) has no production caller** — only tests. `core/abi/abi.go:96` and `core/routestore/family.go:117` both already say so *in code*, which is how this one hid: the truth was written down next to the gap and not carried into the table. | The toggle cannot widen or narrow the family set. New item **CM-7**. |
| **Per-route data cap** | `RouteBudgetModal` — `routes.budget.title` = "Data cap" / "سقف داده" | `abi.SetRouteBudget` (`core/abi/budget.go:83`) returns `{"applied":true,"hourly_cap_bytes":<n>}` and the cap is stored; `budgetEngineIfPresent()` really is consulted on several paths | **`budget.Engine.Add` — the only thing that accrues bytes against a cap — has exactly one caller, `proxy.Pipe`, and `proxy.Pipe` has no production caller either** (`grep -rn 'Pipe(' core/` outside `core/proxy/` returns only `os.Pipe` in tests). So usage never accumulates and the cap can never trip. | A user on metered cellular sets 50 MB, is told **"applied"**, and is not capped. Same root cause as **CM-1** (nothing counts bytes anywhere) and the same fix unblocks both; tracked as **B4**, cross-referenced here. |

**CM-8 — the Tor bridge-import copy, written and unreachable.** The
Wave-5 tor lane wrote eight user-visible strings for a bridge-import
screen (`import.tor_bridge.title`, `.body`, `.placeholder`,
`.added_one`, `.added_other`, `.skipped_one`, `.skipped_other`,
`.none`) in en and fa. **No screen renders any of them**: a grep for
`import.tor_bridge` across `.ts`, `.tsx` and `.rs` returns nothing but
the JSON files themselves. Two display labels are in the same state —
`network.family.anytls` and `network.family.tor_bridge` — because
`FamilyChipView` prints the raw family string and reaches only the
dynamic `network.family.<f>.help` key.

This is inert COPY rather than an inert control, so it takes nothing
from the user today; it is recorded here because the alternative is a
translated string sitting in the repo for a year while everyone assumes
it is on a screen. Delete it or wire it; do not leave it undeclared.

The ninth string of that set, `network.family.tor_bridge.unpackaged`
("this build does not include the Tor software"), was the one that
mattered — it was the only place the packaging gap was disclosed, and
it had no reader either, which is why the premature `experimental`
label on `tor-bridge` was silent as well as wrong. The repair pass
**deleted the key and folded its sentence into
`network.family.tor_bridge.help`**, which the chip really does read.

**Wave 5 note on CM-6.** The MASQUE sub-mode override is inert, and the
obvious fix — wire a reader — is the wrong one. `masque` is now labelled
`unsupported`: sing-box 1.13.12 registers no masque outbound, and a
self-hosted MASQUE proxy would have none of the provider-anonymity-set
value that motivates RFC 9298, so the family cannot be dialled and could
not be served either. Giving the setting a reader would connect a user
preference to a family that cannot carry a byte. **CM-6 stays open and
stays unfixed while `masque` is unsupported**; what changed instead is
the help text, which now says in en and fa that nothing reads the
setting. See `docs/transport-family-inventory.md`.

`docs/telemetry-audit.md` §1.5 and §1.8 already carried the budget and
experimental-family findings when this table was written. The failure was
not discovery, it was reconciliation — two documents in one worktree
disagreeing while both claimed to agree. Treat that as the lesson, not the
three rows.

---

## 5. What this pass changed

**Fixed — throughput now says "not measured" instead of "0 B/s".**
`client-shared/contract/d2-contract.ts` states the rule this violated:
*"a non-optional number is a promise that some Go code writes it; do not add
one without a writer."* `upBytesPerSec` was a non-optional `number` with no
writer.

- `core/engine`: added `HasByteAccounting`, the twin of `HasRealDataPlane`.
  `false` in both build variants today — including `singbox`, deliberately,
  because that build *can* carry traffic and still cannot count it.
- `core/abi/d2_summaries.go`: deleted the counters nothing incremented.
  `ThroughputSnapshot` now emits `up_bps`/`down_bps` as **`null`** when there
  is no accounting, and otherwise derives a rate from the delta of
  `driver.Stats()` over the real gap between calls. First sample after connect,
  and any backwards counter, report `null` rather than dividing a cumulative
  total by an invented window.
- `D2Contract.ThroughputSnapshot`: `number | null`, matching the
  measured/unmeasured rule `health_pct` and `in_cooldown` already follow.
- `ConnectionPage` and `StatusPage` render the existing `network.unmeasured`
  string ("not measured yet" / "هنوز اندازه‌گیری نشده") — **no new i18n keys**.
  `StatusPage` drops null samples instead of drawing a flat line through them.
- The day `platformInterface.bytesIn/bytesOut` get written, flipping
  `HasByteAccounting` to `true` starts rendering real numbers with no further
  edits.

**Fixed — three dead duplicate UI files deleted.** Each was a second, older
copy of a surface that already ships, left mountable on disk:
`components/AddEntryModal.tsx` (`ScanSheet.tsx`'s own header already said "the
fix is NOT to mount AddEntryModal — it is a second, older, half-finished copy"
and then left it there), `shell/D2Shell.tsx` and its only consumer
`shell/Topbar.tsx` (superseded by `DesktopShell`). Stale references in five
comments corrected; `tools/check-hardcoded-strings.sh` scan path updated.

**Fixed — a comment that was never true.** `lib/bridge.ts` claimed the desktop
connect path works "because the daal-tun-helper has already delivered the fd at
GUI startup". `deliver_tun_fd` has no caller anywhere in the tree, which
`check-plumbing.mjs` has been recording in its allowlist the whole time.

**Fixed at reconciliation — the diagnostics blob still said `0` bytes.**
The throughput fix above reached `ThroughputSnapshot` and stopped one function
short. `abi.StatsRedacted` (`engine_stats_redacted`) was still marshalling
`driver.Stats()` straight out as `bytes_in`/`bytes_out`, so the blob a user
exports and hands to a helper carried a flat `0` — and it is worse there than
on the Connection page, because a helper reads a zero as a *finding* ("the
tunnel carried nothing") rather than as a missing measurement. It is the same
`engine.HasByteAccounting` gate and now emits `null`. This surface is
Android-reachable in a way the Connection page's is not: on desktop
`driver.Stats()` errors out because the fail-closed guard means nothing is
ever connected, but on Android the tunnel *is* up and the counters are still
the reserved-and-never-written `platformInterface.bytesIn/bytesOut`.

**Fixed at reconciliation — the fix had no test, and one wrapper still
promised a `number`.** `TestByteCountersReportNullWhenUnmeasured`
(`core/abi/byte_accounting_test.go`) now guards both surfaces, asserting
against `engine.HasByteAccounting` rather than a hardcoded expectation so it
follows the constant instead of going red the day the real counter lands. It
was verified to fail on the pre-fix code and pass after. `lib/bridge.ts`'s
`throughputSnapshot()` still declared `up_bps: number` — a non-nullable type
over a value Go now sends as `null`, which is the same class of promise the
contract forbids — and its doc still claimed "Reading resets counters" about
counters that no longer exist. Both corrected; the wrapper has no caller
(`backends/tauri.ts` invokes the command directly), which is noted in place.

**Left, with backlog entries:** everything in §1, §2 and §4b — entries `CM-1`
(real byte accounting), `CM-3` (six unreachable recipient-side contract
methods), `CM-4` (teach `check-plumbing.mjs` the second hop, with the
measured count of what it hides: **20** wrappers across 13 rows), and, added
at repair, `CM-5` (`network_signals` reaches no UI), `CM-6` (MASQUE override
never read) and `CM-7` (experimental-families gate never called). Nothing in
this pass touched `core/internal/selection/` or the desktop driver selection.

### 5b. What the repair pass changed in this document, and why

An independent review was run against this branch and its findings verified
against the tree rather than accepted. Three of them landed here, and all
three were errors **in the reachability-overstating direction** — which is
the only direction that matters for a document whose job is to stop the next
wave planning against a lie.

1. **§4 SHIPPED contained three inert capabilities.** MASQUE sub-mode
   override, experimental families and the per-route data cap each have a
   screen, a command and a validated, persisted value — and no production
   reader. They are now §4b, under a new `INERT` status, and the headline no
   longer claims "nothing is missing a backend". Two of the three were
   already documented in `docs/telemetry-audit.md` §1.5/§1.8 while this file
   called them SHIPPED, so the "reconciled against the other three
   documents" claim in the header was, on this point, not true. It is now.
2. **§3 claimed `network_signals` was visible on `StatusPage`.** No UI code
   reads the field. Corrected in place, with the drop point named
   (`WhyThisRouteSummary` has no signals field), and filed as `CM-5`.
3. **§3's Connect row claimed a pre-press refusal on both surfaces.** Only
   `ConnectionPage` had one; `NetworkPage` — where the first connect on a
   fresh install actually happens — passed the press through and rendered
   the raw English Go error to a Farsi user. **Fixed in code** rather than
   only in the table: `NetworkPage.tsx` now reads `dataPlane`, renders the
   `conn.no_data_plane.*` alert and short-circuits the press. The row also
   said "disables"; the button is not `disabled`, the press is intercepted,
   and the row now says that.

Two further review findings were checked and **did not survive** — recorded
in `docs/backlog-post-45.md` §12 so they are not re-filed.

**Concurrency note.** This audit ran in a worktree two other owners were
writing to. A fourth finding — `data_plane` emitted by Go and read by nothing
above it — was drafted here and deleted before it was filed, because the
platform owner landed the fix mid-audit. Where this document and the tree
disagree, the tree is right.

---

## 6. What the selection wave will consume, and what exists today

| Signal `selection.Decide` accepts | Produced by | State |
|---|---|---|
| route rows, trust class, family, maturity | `routestore` | real |
| cooldown, budget exhaustion | `core/budget`, `pathmanager` | real, nullable-honest |
| health % | `pathmanager.RouteHealth()` | real, nullable-honest |
| `network_signals` (5 error-derived) | `abi.activeNetworkSignals` ← durable `routes.last_failure_category` | **real, new this wave.** Two properties the selector must be built around, both stated in `refresh.go`: a failure is suppressed once the route's most recent recorded outcome is a **success** (`consecutive_failures == 0`) — fixed at repair, before which a route that failed at 14:05 and connected at 14:30 kept asserting `udp_collapsed` for two hours — and the set is **not network-scoped**, so freshness bounds *when*, never *where* (B2-a is a precondition for these names meaning what they say). Not read by any UI (**CM-5**). |
| `network_signals` (4 probe-derived) | nothing — no prober exists | **absent (B2-c); do not synthesise** |
| per-network identity behind all of the above | `App.tsx:147` passes the constant `('unknown','','')`; Android never calls it | **absent (B2-a)** — `netmem.HashID` is hashing constant input |
| `NetMem` snapshot / `RouteFamilyStats` | `selection.Apply` — **zero production callers** | **absent (B2-b)**, must land inside B1 |
| observed throughput per route | nothing — no byte accounting | **absent (CM-1)** |
| last-refresh timestamps | `secrets_kv["scheduler:last-bootstrap-refresh"]` et al, all persisted | **real** (B3 closed) |

The publisher side already has a consumer waiting for selection output:
`Wizard.rotateRecommend` takes `explanation_json` and `network_signals`
directly. It is unreachable (§1), which is why **W3-11** — the L3 button being
enabled on relays that cannot do L3 — cannot be fixed without it.
