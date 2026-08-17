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

- [~] **E1. Plain `.sbp` didn't connect.** Root cause: `.sbp` shipped metadata-only
  profiles; connectable outbounds were injected only in the per-recipient
  `.sbpx` path. FIXED at the pipeline (commit eb42f28, `users-pack-sbp`): a
  plain `.sbp` is now rewritten with ONE shared box user's creds (`r0`) so ANY
  phone imports + connects it, no PIN. **Validated on-device: all 4 tiers egress
  the relay from a shared `.sbp`.** REMAINING: wire it into the phone publisher
  wizard so provisioning auto-produces the shared `.sbp` (needs Rust +
  libdaal_deploy.so rebuild).
- [~] **E2. Publisher simplification.** DONE (core, commit 0c1b437): a "Share
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
- [ ] **A5. Per-route connected state + one-tap Disconnect.** Network tab shows
  "Connect" on every route even when one is active; no disconnect there.
  Add an active/connected indicator per route and an inline Disconnect.
- [ ] **A6. Unify the two connect surfaces.** Connection tab ("Press to connect /
  No route selected") vs Network tab per-route Connect are disjoint; the
  Connection-tab "dropdown" chevron just navigates to Network. Make the active
  route reflect across both, or collapse to one model.
- [ ] **A7. Cosmetic.** Hardcoded non-i18n "Coming soon" (`publisher/PublisherWizard.tsx:1015,959`);
  disabled QR-fountain placeholder (`:1710`).

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
- [ ] **C4.** Push branch `fix/android-dataplane-exclude-self`; tag bump to
  v0.2.0-dev once the device exit gate is fully green (doc:310).

## Workstream D — Desktop data plane
- [ ] **D1.** Desktop still links `engine.NewStub()` (`core/abi/abi.go:213`, no
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
- [ ] `daal-wizard/src/commands.rs:1876` — live subscription hosting (R2 /
  GH-Pages Put) stubbed to filesystem; no real origin publish path.
- [ ] `daal-desktop-core/src/commands.rs:54` — recovery-phrase preview uses
  placeholder wordlists.
- [ ] Operator resume UX (handover:136) — no inline PIN-unlock on resume; wizard
  `error` state persists across step changes (stale "invalid PIN").

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
