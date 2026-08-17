# Daal — post-Phase-45 backlog

Living menu of outstanding work, compiled 2026-08-15. Line refs point at the
tree state when written; re-grep before trusting them. Impact ordering: top =
most user-visible.

## Status / what's already green
- **All 4 transport tiers work on-device** (vless-reality, websocket-tls,
  naive/Cronet, hysteria2) — validated 2026-08-15 on a real Samsung against a
  live relay, through the proper publisher pipeline. Branch
  `fix/android-dataplane-exclude-self`.
- Naive was the last holdout; root cause was **data-plane cert validity**
  (Cronet installs the leaf as a trusted root → CABF max-validity check →
  `ERR_CERT_VALIDITY_TOO_LONG`). Fixed by capping the cloud-init cert at 90
  days (commit `d9b92d2`). See `publisher/deploy/cloudinit/v2.yaml.tmpl`.
- Relay now serves all 4 families (relayports map + hy2/naive/ws inbounds +
  data-plane cert) — several "box serves only vless-reality" notes from older
  surveys are **stale** on this branch.

---

## Workstream E — sharing model & publisher (user-reported 2026-08-15)  ← ACTIVE
Four problems the user hit on-device:

- [x] **E1. Plain `.sbp` didn't connect.** *(Closed 2026-08-17: the REMAINING
  item below — wiring it into the phone publisher wizard — landed in `d06be4c`
  (wizard's final step distributes the CONNECTABLE shared pack) and was
  superseded by `d80c638`.)* Root cause: `.sbp` shipped metadata-only
  profiles; connectable outbounds were injected only in the per-recipient
  `.sbpx` path. FIXED at the pipeline (commit eb42f28, `users-pack-sbp`): a
  plain `.sbp` is now rewritten with ONE shared box user's creds (`r0`) so ANY
  phone imports + connects it, no PIN. **Validated on-device: all 4 tiers egress
  the relay from a shared `.sbp`.** REMAINING: wire it into the phone publisher
  wizard so provisioning auto-produces the shared `.sbp` (needs Rust +
  libdaal_deploy.so rebuild).
- [x] **E2. Publisher simplification.** *(Closed 2026-08-17 in `d80c638`: all
  three REMAINING sub-items are done — the PIN systems were not "unified" but
  ELIMINATED (Device Custody v1; `pin_lockout.rs` deleted), helper_ip is
  auto-detected by the new `client-ui/src/publisher/helperIp.ts` (221 lines),
  and the roster UI is de-duplicated into `RelayListPage.tsx`.)*
  DONE (core, commit 0c1b437): a "Share
  your relay" card produces one shared `.sbp` (mints `r0`, rewrites profiles)
  and opens the share sheet — the common case no longer needs per-recipient
  provisioning. Also fixed `tls_cert_pem` being dropped on deserialize (naive
  couldn't assemble from the wizard). REMAINING (follow-ups, not blocking):
  unify the two PIN systems (custody-unlock vs per-call keystore PIN);
  auto-detect helper_ip instead of a free-text field; surface the silent
  fail-closed; de-duplicate the roster UI.
- [x] **E3. App icon was the stock two-circle placeholder.** FIXED (commit
  5a8b063): real daal eagle on dark teal + adaptive icon; `make-android-icon-
  source.py` + `patch-android-icons.sh` for reproducibility. Ships next build.
- [x] **E4. Delete imported routes/publishers.** DONE (commit 05d0e30):
  *(Related, and now also done: real teardown — "delete the server too" — plus
  provision rollback landed in `58f3fb8`.)*
  routestore DeleteRoute/DeletePublisher (+tests) → engine_route_delete /
  engine_publisher_delete ABI → desktop-core FFI + Tauri commands → a
  "Remove this connection" action on the publisher card (confirm + disconnect
  first). Route summary now carries publisher_id so the UI targets the real
  fingerprint.

## Workstream A — UI honesty & connect UX  (A1-A4 done; see commits)
The app currently shows fabricated/meaningless data and has a confusing
connect model. Goal: never show a number we didn't measure; make connect /
disconnect obvious.

- [x] **A1/A2. Route-health honesty.** DONE (commit 98edc81). Engine exposes a
  `proven` flag (route has ever succeeded); UI drops the 30/90 fabrication and
  renders "not tested yet" on route rows, family chips, and RouteHealthBars
  when unproven. Family-chip health averages only proven routes.
- [x] **A3. Status-page probes.** DONE (commit 45b54b2). `probeStub` returns a
  `ProbeUnimplemented` (-1000) sentinel; tiles render "unavailable" (neutral)
  instead of fake success. Replace with real probes (engine/probe.go) later.
- [x] **A4. Export diagnostics + swallowed errors.** DONE (commit b4eb23f).
  Dropped the fake Save dialog (fs plugin unwired), copy to clipboard with a
  visible "copied"/"failed" notice; surface mode-change failures too.
- [x] **A5. Per-route connected state + one-tap Disconnect.** DONE in `3fae4e5`:
  `NetworkPage.tsx:67 activeRouteId` (fed by the 2 s connectionSummary poll),
  `:114 onDisconnect`, rendered at `:240-241` and `:325`.
- [~] **A6. Unify the two connect surfaces.** PARTIAL. The active route now
  reflects across both — `NetworkPage.tsx:67` shares the same connectionSummary
  poll, so the two surfaces no longer disagree about what is connected. The
  second half is still open: two connect surfaces still exist and have not been
  collapsed to one model.
- [x] **A7. Cosmetic.** DONE — zero `Coming soon` and zero `fountain` hits
  remain anywhere in `client-ui/src/publisher/*.tsx` (verified 2026-08-17).

## Workstream W3 — Wave 3 carried-forward (compiled 2026-08-17 by the Wave 3c owner sweep)
Every item below was **re-verified against the tree at `6a7903c`** during the
sweep, not copied forward from a report. Where an earlier note had already been
fixed it is marked so and struck, because a backlog that lists solved problems
trains people to skim it.

Ordering: recovery-path correctness first, then reachability, then hygiene.

- [ ] **W3-1. The bootstrap pointer hosts are placeholders, so the layer
  BENEATH freshness is inert in production.** `core/abi/refresh_freshness.go`'s
  `recoverViaBootstrapPointers` is what runs when every freshness mirror in a
  pack is blocked — the last channel a censored device has. It walks the
  embedded pointer list, and that list ships pointing at
  `bootstrap-primary.daal.example` / `bootstrap-fallback.daal.example`
  (`core/bootstrap/embedded/fixtures/pointers-{primary,fallback}.json`, embedded
  via `embedded.go:22`). Those are genfixtures placeholders, not hosts. Needs,
  per pointer: a project-controlled domain on infrastructure whose blocking is
  expensive for the censor, serving a directory `.sbp` signed by a Tier-1
  publisher, with the pointer set re-signed by the project root before
  `valid_until` lapses. **Do not substitute plausible-looking hostnames** — a
  placeholder fails visibly, a wrong hostname fails like censorship.
- [ ] **W3-2. `FetchRaw` reads the response body unbounded.**
  `core/bootstrap/fetcher.go:120` is `io.ReadAll(tlsConn)` with a deadline as
  the only limit. Wave 3b widened exactly this path: it is now polled on a
  schedule against N publisher-supplied mirror URLs, over the plain network,
  from the user's real address (refresh fails closed while a tunnel is up). A
  hostile or seized mirror can stream until the timeout and OOM-kill the app on
  a phone — at the moment the recovery channel is being used. Left unfixed
  deliberately: the cap is a design decision, not a one-liner. It must clear the
  V3 bundle ceiling (`core/wasm`: ≤4 MiB/module, ≤16 MiB/bundle) or large but
  legitimate packs start failing in a way indistinguishable from blocking.
- [ ] **W3-3. Recipients have no manual "check for a new pack now".**
  `core/refresh.RelayPackRefresher.RefreshUser` exists, is tested, and has
  **zero callers** — there is no `engine_relaypack_refresh` export to reach it
  (compare `SubscriptionRefresh`, `core/abi/refresh.go:126`, which is the same
  shape and is wired end to end). So the only thing that ever drives a freshness
  poll is the 60 s scheduler tick, which runs while the desktop app is open or,
  on Android, while the app is open or the tunnel is up. Under blackout — tunnel
  down, user staring at a dead relay — the one action a user would reach for
  does not exist. Costs an ABI export + cshared/gomobile symbol + JNI + Tauri
  command + button + 2 languages, which is why it was not done in the sweep.
- [ ] **W3-4. Eight of the nine rotation rungs have no button.**
  `rotate_execute` (`daal-wizard/src/commands.rs:2334`) implements L1, L2,
  L4, L5, L6, L7_CDN_PATH, L8_CDN_HOSTNAME and L9_CDN_ORIGIN. The **only**
  `Wizard.rotateExecute` call site in the entire UI is `AddressSwap.tsx:134`,
  and it passes the literal `'L3'`. (Step 7's `rotate_credentials` /
  `rotate_tls` are separate box endpoints and *are* wired.) Each missing rung
  needs its own confirm sheet, consequence copy in en+fa, and inputs for
  region / provider / profile — a design job, not plumbing.
- [ ] **W3-5. The L3 sheet promises a history the operator cannot read.**
  `pub.danger.address.field.reason` is labelled "Why (kept in this relay's
  history)" and the reason really is persisted — but `Wizard.rotateHistory`,
  `Wizard.rotateRevert` and `Wizard.rotateRecommend` have **no caller anywhere
  in `client-ui/src`**. This class is invisible to `tools/check-plumbing.mjs`
  by construction: the gate is satisfied by the `invoke()` wrapper existing in
  `wizardCommands.ts`, and never asks whether a component calls the wrapper.
  Same pattern, pre-Wave-3 and also unreachable: `finalizePreProvision`,
  `getSbpPath`, `listCdnFronts`, `pricingLookup`, `provisionCdnFront`,
  `publisherKeyimport`, `qrRender`, `storeCloudflareToken`, `subkeyActive`,
  `subkeyHistory`, `subkeyRotate`, `verifyCdnPosture`. Worth teaching
  check-plumbing the second hop.
- [ ] **W3-6. L3 still does not work on real hardware; the fix needs a human
  release step.** `6a7903c` made L3 fail *closed* (`health.AddressServes`
  probes the new address before the swap commits) after a live Hetzner run
  showed the box never answering on a correctly-attached floating IP — a
  Hetzner floating IP is routed at the provider's network layer, but the guest
  OS does not reply until the address is on its interface. The guest-OS half
  (box `/bind-address`) is Wave 3c's subject. Whatever lands there reaches **no
  live relay** until a human rebuilds, re-signs, re-uploads and bumps the pin in
  `publisher/deploy/cloudinit/artifacts.go`, **and rebuilds `libdaal_deploy.so`**.
  Wave 3c adds a second half to that step: the relay must also be
  **reprovisioned**, because `daal-relay-mgmt.service` now needs
  `AmbientCapabilities=CAP_NET_ADMIN` (v2 cloud-init) before it will advertise
  the capability at all. An existing relay given only the new binary reports
  `bind-address` **unavailable** and refuses L3 cleanly — which is correct: the
  boot-unit delegation can add an address and can never remove one.
- [ ] **W3-10. The L3 15-second budget was never measured, and the window it
  bounds grew in Wave 3c.** `L3_FAST_PATH_BUDGET`
  (`daal-wizard/src/commands.rs`), `rotation.L3FastPathBudget` and the soak
  rig's `v1-5-l3-fast-path` scenario all pin 15 s, and all three assert it
  against an *injected* `Duration`. The subprocess it bounds used to be
  reserve → attach → readback → TCP probe; it is now capability probe (a full
  ephemeral-firewall window: provider read-modify-write of the rules, TLS
  handshake, `GET /health`, blocking removal in a defer) → reserve → attach →
  readback → **bind** (a second full window, plus its own capability re-check
  and a `POST /bind-address` that configures the address and writes its
  persistence) → reachability probe → re-sign. The number was **not** moved for
  it — it is a product promise pinned in four places and in the supplement, and
  a "fast path" that quietly becomes 30 s is an outage nobody was warned about.
  What changed instead is the overrun message, which now names the prior
  floating IP left attached and billing. **Measure the real elapsed time on the
  first live L3** (W3-6's run gives it for free) and then decide, once, whether
  the budget or the step count moves. Note the two firewall windows are the
  obvious saving: the capability probe cannot join the bind's window (it must
  refuse *before* anything is reserved), but the bind re-probes capabilities
  inside its own window with the answer already in hand.
- [ ] **W3-11. The L3 button is enabled on relays that cannot do L3.**
  `AddressSwap.tsx`'s `available` gate consults `canReserve` and
  `currentFloatingIpId` only — never whether the relay's mgmt binary can bind
  an address, which since Wave 3c is the deciding fact and is false on every
  relay in the field until W3-6's release step. `rotation.ActionForProvider`
  already computes exactly this refusal (`AvailabilityUnsupported`), and it is
  unreachable for the reason recorded in W3-5: `Wizard.rotateRecommend` has no
  caller. The press is now *safe* — `daal-deploy assign-fip` probes the box
  before anything is reserved and the sheet renders `pub.rotate.too_old` in the
  operator's language — but a rung that can only fail should be disabled with
  the reason showing, not offered.
- [ ] **W3-7. Still mocked, still not proven against a real endpoint.** R2
  SigV4 (`publisher/deploy/freshness/backends/r2`) and the GH Pages contents
  API (`.../backends/ghpages`) are fully implemented but every upload assertion
  in the tree is mocked; the L3 60-second wall-clock budget is injected, never
  measured. Partially retired: Hetzner floating-IP create/assign **was**
  exercised against the real API at `6a7903c` (it succeeded at the API layer —
  that run is what produced W3-6); release is still unproven live.
- [ ] **W3-8. The shared WS path is not per-recipient and no rotation exists
  for it.** `specs/per-recipient-credentials-v1.md` §2.1: a single leaked pack
  discloses the WS path *every* recipient on that relay uses, revoking a
  recipient does not rotate it, and "rotating the shared path for everyone at
  once is the mitigation, and it is not implemented". Re-checked this sweep:
  still true. Note this interacts with W3-4 — L2 is the rung that would move
  `ws_path`, and L2 has no button.
- [ ] **W3-9. The self-healing loop still has a manual upload in the middle.**
  Daal signs and publishes the freshness *document* to the mirrors
  (`freshness::publish` → `PublishAll`, which writes one body), but it never
  uploads the re-signed `.sbp` to the download address that document points at.
  `pack_url` is a field the operator types ("where the rebuilt file **will** be
  downloadable"). The recipient fetches `doc.current_signed_url`
  (`relaypack_refresh.go:619`), so if the operator has not put the pack there,
  every device gets a 404 or a digest mismatch and stays on the burned relay.
  The UI copy was fixed in this sweep to name the step in both languages; the
  *capability* — publish the pack to the same mirror credentials that already
  work, and verify the digest at `pack_url` before reporting success — is not
  built. This is the last courier step in the "no courier" path.
- [x] ~~Freshness `next_due` is projected without the persisted escalation or
  jitter.~~ **FIXED in this sweep.** `core/abi`'s `storeSource.RelayPacks()`
  was the only production path from the persisted per-pack record to
  `scheduler.Plan` / `AllNextDues`, and it dropped `ConsecutiveFailures` and
  `JitterOffset` — so the planner evaluated the trigger policy on zeros while
  `core/refresh` evaluated it on the real values, which is the exact
  disagreement `selection.FreshnessState`'s doc comment forbids. Pinned by
  `TestRelayPacksCarriesTheEscalationAndTheJitter`.

## Workstream B — Smart routing (root cause behind fake health)
- [ ] **B1.** The FRP-3 selection engine (`core/internal/selection/*`: `Decide`
  pipeline.go:69, `PlanRace` race.go:37, `Shortlist` shortlist.go:28) is fully
  built + tested but its **only production caller is diagnostics**
  (`core/abi/refresh.go:231`). Wire it into the connect / SetRoute path.
- [ ] **B2.** No live NetworkSignals feed; `netmem.Sweep` unscheduled. Feed real
  signals so route health/scores become real (fixes A1/A2 at the source).
- [ ] **B3.** `core/abi/scheduler.go:167` — persist a real "last bootstrap
  refresh" timestamp (cadence is approximate).

## Workstream C — Ship polish & CI
- [ ] **C1. APK size.** Installed APK is ~92 MB (universal, 4 ABIs ×
  libdaalcore 39MB + libcronet 24MB + libdaal_deploy 13MB + tauri 12MB).
  Per-ABI split / drop unused ABIs; confirm no stale `libsing_box.so` staged
  (`unzip -l`). Phase-45 doc:309.
- [ ] **C2. Android build scripts not in CI.** `tools/build-deploy-android.sh`
  and `tools/patch-android-mainactivity.sh` aren't in any committed workflow;
  a clean `tauri android init` drops the Kotlin layer + deploy `.so`
  (handover:83,134). Wire them beside `build-engine-android.sh`.
- [ ] **C3.** Rebuild + ship `libdaal_deploy.so` from current Tier-2 code in the
  release APK (handover:237). (Done ad-hoc on-device 2026-08-15; not in build.)
- [~] **C4.** Branch `fix/android-dataplane-exclude-self` is pushed and **fully
  merged into `main`** on both sides — that half is done and the branch is safe
  to delete. The tag bump to v0.2.0-dev is **still outstanding**: no tag is
  reachable from HEAD at all (`git describe --tags --always` returns a bare
  SHA), and the local `v0.1.0` tag has diverged from origin's.

## Workstream D — Desktop data plane
- [ ] **D1.** Desktop still links `engine.NewStub()` (`core/abi/abi.go:223`,
  `newEngineDriver()`; no
  `singbox` tag) — no real data plane. Flip desktop to the in-process sing-box
  driver; retire `daal-desktop-core/src/singbox.rs` sidecar + Clash REST path
  (handover:38).
- [ ] **D2.** Windows TUN-fd handoff is a stub (`daal-desktop-core/src/tun_helper.rs:232`);
  needs the named-pipe `windows-sys` impl.
- [ ] Naive/Cronet on desktop needs the same sidecar `libcronet.{so,dylib,dll}`
  per OS (cross-platform reminder).

## Rust shell / recipient plumbing
- [ ] `daal-wizard/src/recipient_book.rs:150,167,202` — pre-Tier-2 box packs
  ship empty `reality_public_key`; fails closed. (Resolved for freshly-
  provisioned boxes; verify the guard messaging.)
- [ ] `src-tauri/src/lib.rs:1704`, `publisher/wizardCommands.ts:160` — iOS share
  of `.sbpx` is a placeholder (Android/desktop only).
- [~] ~~`daal-wizard/src/commands.rs:1876` — live subscription hosting (R2 /
  GH-Pages Put) stubbed to filesystem; no real origin publish path.~~ **Line
  ref was stale and the claim is half-retired** (re-checked 2026-08-17; that
  line is now `qr_fountain`, and `commands.rs` contains no "subscription" at
  all). Wave 3b shipped real origin backends —
  `publisher/deploy/freshness/backends/r2` (AWS SigV4) and `.../ghpages`
  (contents API) — and they are on the live publish path. What is still true
  is narrower and now tracked as **W3-7** (never exercised against a real
  endpoint; every upload assertion is mocked) and **W3-9** (the `.sbp` itself
  is still never uploaded by Daal).
- [ ] `daal-desktop-core/src/commands.rs:54` — recovery-phrase preview uses
  placeholder wordlists.
- [x] Operator resume UX (handover:136) — **moot.** There is no PIN anywhere in
  the wizard flow any more (Device Custody v1, `d80c638`), so "no inline
  PIN-unlock on resume" and the stale "invalid PIN" error state cannot occur.

## Trust / labels (FRP-11) — stubbed
- [ ] `contract/D2Contract.ts:356` `cellLabelGet/Set` in-memory stubs (engine
  LabelStore not wired). `:353` `burnpressureVerdict` deterministic stub.

## Known-red (tracked, low priority)
- [ ] `bundle/go TestSubkeySignedSampleArtefact` red since 2026-08-01 (90-day
  cert window); regen needs a gitignored key only on the FRP-7.5 machine
  (handover:266).

## Phase-45 exit-gate housekeeping (docs/handovers/frp-45-handover.md)
- [ ] VPN consent dialog + foreground notification on first Connect — re-verify.
- [ ] Clean disconnect tears down VPN network + notification — re-verify.
- [ ] Drop `libsing_box.so` / APK shrink (see C1); tag bump (see C4).
