# V1.6 Closure (v1)

> **Status: HOLD — FRP-9 alpha pilot pending.**
>
> This spec is the formal closure record for the V1.6 milestone of
> the Daal anti-censorship project. The engineering surface is
> SHIPPED at FRP-8 (commits 7b75468 .. d46e09f + the post-FRP-8
> hardening commit c846ab5) **AND at FRP-9** (the engineering
> series that ships the CDN rotate surface, V1.6 soak scenarios,
> `v1-6-superset` selector, V1.6 alpha-pilot evidence template,
> and `internal/v16verifier`).
>
> **Engineering-shipped ≠ closure-shipped.** The closure record is
> gated on a real two-FRP × 14-day alpha-pilot run per the
> supplement §22.2 success metric — engineering completion of
> FRP-9 is the precondition for opening the live alpha pilot, not
> the closure event itself. The project lead flips this status to
> SHIPPED by appending a `## Closure run YYYY-MM-DD` section once
> the FRP-9 alpha-pilot evidence template aggregate roll-up
> returns 2/2 (or per the rules below) on every success-metric
> row. Until then this spec describes the gate.

V1.6 is the **CDN milestone** line: extend the FRP wizard to
produce RelayPacks mixing `direct_vps` and `cdn_fronted`
candidates per supplement §11.7 + §14.4 + §19.2.6 + §22.2.
A diaspora operator with a Cloudflare account + a BYO domain
can now stand up a CDN-fronted RelayPack, hand it to family in
Iran, and absorb a public-path or hostname rotation through the
freshness-endpoint atomic-swap path without ever scanning a
fresh QR code.

## Closure criteria

V1.6 closes when **all** of the following hold on a single
real alpha-pilot run with two FRPs over a 14-day window:

1. **Primary metric (V1.6-P1) green.**
   For 2 of 2 alpha-pilot FRPs at least one designated recipient
   reaches `engine_diagnostics_explain.posture == "connected"`
   via the `cdn_fronted` candidate within 60 seconds of QR
   scan, on first attempt. See
   `daal-roadmap-v3-supplement-diaspora-helper.md` §22.2.

2. **Primary metric (V1.6-P2) green.**
   For 2 of 2 alpha-pilot FRPs at least one
   `cdn_hostname_blocked` or `path_pattern_blocked` selector
   classification was observed during the 14-day window AND
   the freshness-endpoint atomic-swap recovered the recipient
   to `posture == "connected"` within 5 minutes AND no re-TOFU
   prompt was shown.

3. **Stay-online + cooldown metric (V1.6-S1) green.**
   For 2 of 2 alpha-pilot FRPs the family-side anonymized
   session uptime is ≥ 99 % over the 14-day window, **AND**
   at least one §13.4 mode-aware cdn_*-class cooldown
   propagation was observed (e.g. `cdn:cloudflare` cooled →
   selector switched to `direct_vps` siblings) **AND** at
   least one **public-surface rotation** (hostname or
   public-path change) completed in < 30 s via Cloudflare
   API alone with **no box redeploy**, the updated RelayPack
   was delivered through the freshness endpoint to recipients,
   no QR re-scan was required, and **no re-TOFU prompt was
   shown** **AND** at least one **origin-only rotation**
   (origin IP swap, cert refresh, DC move with hostname
   unchanged) completed with **zero family-visible event** and
   **zero RelayPack republish**. Public-surface ≠ origin-only;
   both must be observed independently.

4. **§11.7 hardening + leak metric (V1.6-S2) green.**
   For 2 of 2 alpha-pilot FRPs the wizard's "Verify CDN
   posture" button returned green on the first day of the
   window AND on the last day of the window. No origin-IP leak
   was reported by the §19.2.6 leak-vector lab probe rig
   against either FRP's `cdn_fronted` hostname during the
   window. The §11.7 attestation (`_cdn_attestation`) is
   structurally conformant on every signed `.sbp` produced
   during the window (RP022 / RP023 never fire on
   re-validation).

5. **Schema-correctness + RelayPack conformance metric
   (V1.6-S3) green.**
   The validator phase-lift from V1.5 to V1.6 was exercised
   end-to-end through validator → importer → store → selector
   → UI in the synthetic soak rig (`--scenarios v1-6-superset`
   returns 7/7 PASS — see V1.6-G1 below). **AND** no
   real-pilot RelayPack drifted from the V1.6 phase contract
   during the live window: every `cdn_fronted` candidate
   carries a passing `_cdn_attestation` blob; `freshness_url`
   is non-empty and FRP-controlled; `.sbp` `spec_version` is
   unchanged from the FRP-7.5 value (3 root-signed / 4
   sub-key-signed). Synthetic + real conformance both required.

6. **Engine version unchanged at closure.**
   `daal-core 0.9.0+v3-share` (unchanged through 3F, 3-Soak,
   FRP-0..FRP-7, FRP-7.5, FRP-8 — V1.6 is a packaging-tag
   milestone, not a `Version` constant change).

7. **ABI release surface unchanged at closure.**
   `nm libdaalcore.so | grep ' T engine_' | wc -l` = **48**,
   unchanged from 3F.

8. **`spec_version` unchanged at closure.**
   `freshness_url` is additive within the FRP-1 v3 bump;
   `_cdn_attestation` is additive within the FRP-1 `_relaypack`
   opaque container; sub-key-signed bundles still emit
   `spec_version=4` per FRP-7.5. Any drift is a regression and
   blocks closure.

9. **All 3F + 3-Soak + V1.5 regression matrix green.**
   The full v3-superset 31-scenario matrix + the V1.5 superset
   6-scenario matrix returns the same byte-for-byte verdict
   they returned at their respective ship marks.

10. **Synthetic V1.6 soak rig green (V1.6-G1).**
    `--scenarios v1-6-superset` (**7 V1.6 CDN-fronted
    scenarios** shipped at FRP-9) returns PASS on every
    scenario. The seven scenarios are
    `v1-6-cdn-dominant-route`,
    `v1-6-dns-only-a-leak-detected`,
    `v1-6-origin-ip-scan-rejected`,
    `v1-6-cf-hostname-blocked-fallback`,
    `v1-6-public-surface-rotation`,
    `v1-6-origin-only-rotation`,
    `v1-6-freshness-atomic-swap`. The
    `v1-6-superset` selector is locked at size **7**;
    v1-5-superset (6), v2-superset (26), v3-superset (31)
    counts are unchanged. The synthetic rig is the gate the
    engineering side controls; the live alpha pilot is the
    gate operations controls. **Both are required.**

11. **Pilot consent collected.**
    Both alpha-pilot FRPs signed
    `docs/pilot/consent-template.md` (current git SHA at
    signing). Aggregate consent counts may be cited here; no
    individual consent records are committed to this repo.

## Position B preserved

V1.6 closure is consistent with the project's position-B
telemetry stance:

* No phone-home from the running engine (unchanged through V1.6).
* No telemetry pipeline added by the V1.6 surface.
* The freshness endpoint is **FRP-controlled**, NOT a
  Daal-project hostname. Recipients fetch freshness through
  the same tunneled-fetch path they use for any other URL;
  the project never sees the freshness-fetch event.
* The Cloudflare API token never leaves the Helper machine.
  Edge-range refresh runs on Helper (verified by
  `publisher/deploy/cloudflare/opsec_test.go` — no Cloudflare
  API call originating from the origin box).
* The pilot evidence template captures only operational
  measurements; no real names, IPs, ASNs, or device identifiers
  ever land in the repo.
* Filled evidence forms and signed consent records live
  out-of-tree per `.gitignore`.

## V1.6 → V2 gate

V2 is the **multi-provider** line: extend the FRP wizard to
produce RelayPacks spanning two cloud providers (Hetzner +
Vultr or Hetzner + Stark), with public-surface diversity
enforced by the validator. V1.6 closure is the precondition
for opening V2:

* V2 spec at `phases of development/40-phase-frp-10-v2-multi-provider.md`
  (filed but NOT shipping at V1.6).
* V2 engine target is `daal-core 0.9.0+v3-share` UNCHANGED.
* The V2 phase MUST NOT begin until V1.6 closure is recorded
  here. Engineering may begin spec work on V2 in parallel,
  but no multi-provider RelayPack ships in production until
  V1.6 is closed.

## Closure record contents

Once the live alpha pilot completes the project lead appends:

1. The aggregate roll-up table from the FRP-9 alpha-pilot
   evidence template (no per-FRP rows; only the metric rows).
2. Pilot consent count (e.g. `2 of 2 signed`).
3. The synthetic-soak verdict on `v1-6-superset`.
4. The 3F + 3-Soak + V1.5 regression-matrix re-verification log.
5. The handover documents at
   `docs/handovers/frp-8-handover.md` and
   `docs/handovers/frp-9-handover.md`.
6. A one-line attestation by the project lead.

This spec is appended-to (not edited) when V1.6 actually closes:
when the live alpha pilot delivers the green aggregate the
operator appends a `## Closure run YYYY-MM-DD` section recording
the run ID, the aggregate roll-up, and the attestation. Until
then the above sections describe the gate.

## Pilot results

(Empty until live alpha pilot completes. The aggregate roll-up
table from the FRP-9 alpha-pilot evidence template is
transcribed here. No per-FRP rows. No identifying information.)

| Metric | FRPs PASSING | FRPs FAILING | Median observed |
|---|---|---|---|
| V1.6-P1: family online via cdn_fronted ≤ 60 s | /2 | /2 | |
| V1.6-P2: cdn_hostname/path block → freshness atomic swap recovery ≤ 5 min, no re-TOFU | /2 | /2 | |
| V1.6-S1: 14-day uptime ≥ 99 %, ≥1 §13.4 cdn cooldown propagation, ≥1 public-surface rotation < 30 s with no QR re-scan, ≥1 origin-only rotation with zero family-visible event | /2 | /2 | |
| V1.6-S2: §11.7 posture verified day 1 + day 14, no §19.2.6 leak, RP022/RP023 never fire on signed `.sbp` re-validation | /2 | /2 | |
| V1.6-S3: synthetic v1-6-superset 7/7 PASS AND no real-pilot RelayPack drift from V1.6 phase contract | /2 | /2 | n/a |
| V1.6-G1: synthetic `--scenarios v1-6-superset` returns 7/7 PASS | n/a | n/a | (engineering gate, not pilot row) |

## Carry-overs to V2

(Empty until live alpha pilot completes.)

## FRP-9 engineering deliverables (informational, locked at SHIPPED)

These are the deliverables that cleared engineering at FRP-9.
The closure gate is the live alpha pilot; this list is recorded
here for operator continuity. Commit-by-commit handover at
`docs/handovers/frp-9-handover.md`.

* `publisher/deploy/cloudflare/cf_client.go` +
  `cf_client_live.go` + `cf_client_mock.go` —
  `RotatePublicPath` / `RotateHostname` / `RotateOrigin`
  added to `CFClient`. Live impl re-uploads worker +
  delete-and-rebinds the route (path), re-resolves apex
  zone + ensures proxied DNS + rebinds worker on the new
  zone (hostname), or re-points A/AAAA only (origin).
* `publisher/deploy/cloudflare/provider.go` —
  Provider-level `RotatePublicPath`, `RotateHostname`,
  `RotateOrigin` that own the §14.4 invariants and mutate
  the `FrontRecord` in place. Origin-only path mutates NO
  public-surface field.
* `publisher/deploy/cloudflare/rotate_test.go` — 6 new
  tests locking each invariant byte-for-byte.
* `publisher/deploy/cli/cli.go` — `cdn-rotate-path`,
  `cdn-rotate-hostname`, `cdn-rotate-origin`, and
  `publish-freshness` subcommands. Usage text spells out
  the L7/L8 vs L9 contract; cf-token via mode-0600
  tempfile; subprocess zeroizes on exit.
* `publisher/deploy/cli/cli_frp9_test.go` — 4 new tests
  guarding the wizard ↔ CLI flag contract.
* `client-desktop/daal-wizard/src/cli_bridge.rs` —
  `CdnRotate{Path,Hostname,Origin}Args` +
  `CdnRotateResult` + `PublishFreshnessArgs` +
  `PublishFreshnessResult` + four new `CliRunner`
  methods + `SubprocessRunner` impls + `MockRunner`
  per-method call tracking.
* `client-desktop/daal-wizard/src/operator_db.rs` +
  `migrations/V006__signed_sbps_rotation_kind.sql` — V006
  schema migration (`signed_sbps.rotation_kind` TEXT NOT
  NULL DEFAULT '' + idx); `derive_rotation_kind` helper;
  `get_cdn_front` + `update_cdn_front_rotation` +
  `record_origin_only_rotation` accessors.
* `client-desktop/daal-wizard/src/commands.rs` —
  `rotate_cdn_path` / `rotate_cdn_hostname` /
  `rotate_cdn_origin` Tauri commands;
  `publish_freshness_after_rotate` helper hooked into
  `rotate_execute` for L7/L8 only; `RotateExecuteInput`
  extended with six `cdn_*` fields + `freshness_signed_sbp_url`.
* `client-desktop/tauri/src/wizard/i18n/wizard.{en,fa}.json`
  — 27 new `wizard.rotate.cdn.*` keys × 2 locales (54
  strings). Mode-aware copy: L7/L8 say "your family will
  see a new fingerprint"; L9 says "your family sees no
  change, do not send anyone a new QR".
* `daal-roadmap-v3-supplement-diaspora-helper.md` — new
  §14.6 documenting L7/L8/L9 + five locked invariants;
  supplement bumps to v2.3.8.

**FRP-9 test counts at engineering ship:**

* `publisher/deploy/cloudflare`: FRP-8 baseline + 6 new tests.
* `publisher/deploy/cli`: FRP-8 baseline + 4 new tests.
* `client-desktop/daal-wizard` lib suite: 72 → **82** (+10).
* `soak-driver/cmd/soak-driver`: V1.6 selector count + exact-ID
  + additive-regression tests.
* `soak-driver/internal/soak`: V1.6 action dispatch test.
* `soak-driver/internal/v16verifier`: V1.6 aggregate PASS / FAIL
  / partial-gate tests.

**FRP-9 synthetic soak-rig deliverables (now shipped):**

* `test-rigs/distribution-failure/scenarios/v1-6-*.json` —
  the seven V1.6 scenarios listed under V1.6-G1.
* `test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go`
  — `v1-6-superset` selector wiring; count-locked test.
* `test-rigs/distribution-failure/soak-driver/internal/soak/soak.go`
  — V1.6 rig-local `engine_action` dispatchers. These are
  synthetic outcomes for closure evidence; they add no engine ABI
  symbols and no recipient telemetry.
* `test-rigs/distribution-failure/soak-driver/internal/v16verifier/`
  — V1.6 §22.2 metric verifier (mirrors `v3verifier`
  shape).
* `specs/blackout-soak-rig-v1.md` — new "Phase FRP-9
  additions (V1.6 CDN alpha soak)" section.
* `docs/pilot/frp-9-pilot-template.md` — V1.6 alpha-pilot
  evidence template (2 FRPs × 14 days; mirrors
  `frp-7-pilot-template.md` shape).
* `docs/pilot/consent-template.md` — V1.6 supplement (CDN
  front consent, freshness URL FRP-controlled).

**Remaining carry-overs to closure:**

* Live two-FRP × 14-day alpha pilot.
* Native FA review of the V1.6 CDN copy and consent supplement.
* Live R2 / GH Pages backend SDK wiring for
  `publish-freshness`; current path emits the signed JSON
  to `<staging>/freshness.<id>.json` and the operator
  uploads manually until SDK wiring lands.

## FRP-8 engineering deliverables (informational, locked at SHIPPED)

These are the deliverables that cleared engineering at FRP-8.
The closure gate is the live alpha pilot, not the engineering
ship; this list is recorded here for operator continuity.

* `publisher/deploy/cloudflare/` — provider package (provider,
  origin_ca, aop, worker, dns, edge_ranges).
* `publisher/deploy/freshness/` — freshness builder + R2 +
  GitHub Pages backends; IPFS reserved.
* `publisher/deploy/relaypack/binder.go` — emits cdn_fronted
  candidates with `_cdn_attestation`; threads
  `BindOpts.FreshnessURL` into `Manifest.RelayPack.FreshnessURL`.
* `publisher/deploy/cloudinit/template.yaml.tmpl` — installs
  Origin CA cert + AOP client cert under `/etc/daal/cdn/`.
* `publisher/deploy/cli/cli.go` — `--freshness-url` flag on
  `bind-and-sign`.
* `bundle/go/relaypackvalidate/` — RP022 / RP023 errors,
  RP024 warning, RP004 lift at `Phase: V16`.
* `core/internal/selection/freshness.go` — pure-policy
  `ShouldAttemptRefresh` (no sockets).
* `core/refresh/relaypack.go` — `FetchAndVerifyFreshness` +
  `ApplyRefresh` + sub-key-aware verify chain.
* `bundle/go/importer/refresh_apply.go` — `ApplyVerifiedRefresh`
  (only consumes verified bytes; no fetch).
* `client-desktop/daal-wizard/migrations/V005__cdn_fronts.sql`
  + Tauri command surface + EN/FA i18n (CDN backend path +
  mode-aware rotate copy).
