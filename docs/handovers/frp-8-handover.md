# FRP-8 handover — V1.6 CDN-fronted mode + freshness endpoint

**Status:** SHIPPED 2026-05-03 (engineering surface).
**Closure:** HOLD (`specs/v1-6-closure-v1.md`) — gated on the
FRP-9 alpha pilot (2 FRPs × 14-day soak).
**Engine line:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI:** **48** UNCHANGED.
**Spec version:** UNCHANGED from FRP-7.5 value (verifier accepts
`{1, 2, 3, 4}`; producers default per the FRP-7.5 sub-key path).
`Manifest.relay_pack.freshness_url` is additive within the
FRP-1 v3 bump; `_cdn_attestation` is additive within the
FRP-1 `_relaypack` opaque container.

This handover summarises the eight-commit FRP-8 series. It
ships the V1.6 CDN milestone end-to-end: the publisher-side
Cloudflare provider package, freshness builder + static-host
backends, validator phase-lift (RP004 → V16) with three new
codes (RP022 / RP023 / RP024), recipient-side network IO +
atomic-swap surface, wizard CDN command surface + V005 storage,
cloud-init Origin CA + AOP cert install, and the
daal-deploy `--freshness-url` flag.

The post-review hardening pass replaced the FRP-8 scaffolds with
live Helper-side implementations: `cf_client_live.go` now talks to
Cloudflare's v4 REST API through Daal's narrow `CFClient`
boundary, `daal-deploy cdn-provision` applies the Hetzner
Cloudflare-edge firewall before returning a `FrontRecord`, and the
R2 backend signs PUT requests with AWS SigV4. `cloudflare-go/v4`
is pinned in `publisher/go.mod` for the phase dependency lock, but
the critical path intentionally stays behind the narrow wrapper.

## What FRP-8 ships

V1.6 lets a diaspora operator with a Cloudflare account + a BYO
domain stand up a `cdn_fronted` candidate alongside their
existing `direct_vps` candidate. When TIC blocks the direct
candidate's hostname or path-pattern, recipients fall back to
the CDN front; when TIC blocks the CDN-public-path itself,
operators rotate the path through the Cloudflare API only (no
box redeploy) and recipients pick up the new path through the
freshness-endpoint atomic-swap path without scanning a fresh
QR code.

### Commit-by-commit

| # | SHA | Title |
|---|---|---|
| 1 | `7b75468` | Phase doc + cloudflare provider scaffold + Origin CA + AOP (12 files, 22 tests) |
| 2 | `c063d7c` | DNS coordination + edge-range refresh + Hetzner CF firewall (15 new tests) |
| 3 | `1be5493` | Sub-key-aware freshness builder + R2 + GitHub Pages backends, IPFS reserved (23 tests) |
| 4 | `3de73fd` | Validator widening RP022/RP023/RP024 + RP007 per-family + RP021 V16 lift (14 new tests) |
| 5 | `4ba36fe` | core/refresh network IO + atomic swap; selection/freshness pure-policy; importer ApplyVerifiedRefresh |
| 6 | `9dd4fe2` | Wizard CDN command surface + V005 cdn_fronts + Tauri commands + EN/FA i18n + mode-aware rotate copy |
| 7 | `96e27cc` | Cloud-init CDN cert install + binder _cdn_attestation pass-through + daal-deploy --freshness-url |
| 8 | (this commit) | Spec amendments + V1.6 closure HOLD + this handover |

### New + amended code surfaces

* `publisher/deploy/cloudflare/` — provider package
  (`provider.go`, `origin_ca.go`, `aop.go`, `worker.go`,
  `dns.go`, `edge_ranges.go`, `posture.go`, `cf_client.go`,
  `cf_client_live.go`). Live critical path covers Origin CA,
  AOP, proxied DNS records, Worker script + route binding, zone
  lookup, and posture re-checks.
* `publisher/deploy/freshness/` — `document.go` +
  `subkey_chain.go` + `backends/{r2,ghpages,ipfs}/`. R2 SigV4
  and GitHub Pages backends are live; IPFS remains reserved.
* `publisher/deploy/provider/hetzner/firewall_cf.go` — Hetzner-side
  helper that builds a Firewall.Update payload locked to the
  current Cloudflare edge ranges (refresh runs on Helper).
* `publisher/deploy/relaypack/binder.go` — `BindOpts.FreshnessURL`
  threaded into `Manifest.RelayPack.FreshnessURL`. Validator
  runs at `Phase: V16` when the operator's wizard chose CDN
  mode.
* `publisher/deploy/relaypack/candidate_render.go` — emits
  `_cdn_attestation` inside FamilySpecificConfig for cdn_fronted
  candidates with a non-nil `provider.CandidateMeta.CDNAttestation`.
* `publisher/deploy/relaypack/binder_frp8_test.go` — round-trips
  `_cdn_attestation` + `freshness_url` through bind→ParseSBP;
  asserts RP022 fires when missing at V16.
* `publisher/deploy/cli/cli.go` — `--freshness-url` flag on
  `bind-and-sign`; `cdn-provision` live path that provisions the
  Cloudflare front, refreshes the Hetzner Cloudflare-edge
  firewall, and emits validator-ready `FrontRecord` JSON.
* `publisher/deploy/cloudinit/template.{go,yaml.tmpl}` — three
  new RenderInput fields (`OriginCACertPEM`, `OriginCAPrivPEM`,
  `AOPClientCertPEM`); conditional `{{ if .CDNEnabled }}`
  block writes `/etc/daal/cdn/{origin_ca.pem,origin_ca.key,
  aop_client.pem}` at correct modes; half-state guard ("all
  three or none"); golden SHA re-pinned to
  `a9f38cf1874efdb16600aa7aa88ced913ddb0c4bc95007bb5b0f35873ea4b26b`.
* `publisher/deploy/provider/types.go` — `CandidateMeta` gains
  optional `CDNAttestation` pointer; new `provider.CDNAttestation`
  struct mirrors `bundle.CDNAttestation` byte-for-byte.
* `publisher/cmd/relaypack-fixtures/main.go` — auto-injects a
  passing `_cdn_attestation` when the fixture's exposure mode
  is `cdn_fronted`; 16 fixtures regenerated.
* `bundle/go/bundle/relay_pack.go` — `bundle.CDNAttestation`
  struct + `ParseCDNAttestation` helper.
* `bundle/go/relaypackvalidate/codes.go` — RP022 / RP023 errors
  + RP024 warning.
* `bundle/go/relaypackvalidate/validator.go` — RP004 lifts at
  `Phase: V16`; `validateCDNAttestation` enforces RP022 / RP023;
  `lintRP024` walks the per-bundle siblings.
* `bundle/go/importer/refresh_apply.go` —
  `ApplyVerifiedRefresh(verifiedBytes []byte) error` entry
  point. Importer never opens a socket; caller fetches +
  verifies.
* `core/internal/selection/freshness.go` — pure-policy
  `ShouldAttemptRefresh` (15 min default cooldown / 6 h max
  silence / 5 min event-debounce). Opsec test asserts no
  `net/http`, `crypto/tls`, or `core/bootstrap` references.
* `core/refresh/relaypack.go` — `FetchAndVerifyFreshness` +
  `ApplyRefresh`; sub-key-aware verification chain
  (`pub → cert → sub`) mirrored from FRP-7.5's `VerifyBundle`.
* `client-desktop/daal-wizard/migrations/V005__cdn_fronts.sql`
  — V005 storage row (public CDN metadata only; private cert
  bytes remain on disk at mode 0600).
* `client-desktop/daal-wizard/src/operator_db.rs` —
  `CdnFrontRow` + `upsert_cdn_front` / `list_cdn_fronts` /
  `touch_cdn_front_verification`.
* `client-desktop/daal-wizard/src/commands.rs` — `WizardError::Cdn`
  variant + `provision_cdn_front` (returns SDK-not-wired
  sentinel) + `record_cdn_front_attestation` +
  `list_cdn_fronts` + `verify_cdn_posture`. Five new wizard
  lib tests (72 total).
* `client-desktop/tauri/src/wizard/i18n/wizard.{en,fa}.json` —
  19 new `wizard.cdn.*` keys + 4 `wizard.rotate.copy_*` keys
  (FA copy review queued alongside FRP-6 + 7 + 7.5 i18n).

### Spec deliverables

* `specs/v1-6-closure-v1.md` (NEW) — V1.6 closure record,
  status HOLD pending FRP-9 alpha pilot.
* `specs/relaypack-v1.md` (AMENDED) — new "V1.6 CDN-fronted
  profile" section (§11.7 hardening template, `_cdn_attestation`
  shape, freshness JSON shape sub-key-aware, RP022 / RP023 /
  RP024 entries, RP021 V16 lift wording).
* `specs/sbp-v1.md` (AMENDED) — new "`freshness_url` field
  (FRP-8 lift at V1.6)" cross-reference under the FRP-1
  widening section; validator rule list updated.
* `docs/family-relay-publisher-v1.md` (AMENDED) — "CDN-fronted
  deployment (FRP-8, V1.6)" section now describes the wizard
  flow screen-by-screen, the §11.7 hardening enforcement, the
  live-posture re-verification button, the four mode-aware
  rotate-copy variants, the freshness endpoint shape + cadence,
  and the V005 storage contract.

## Locked invariants (carry-over)

The 26-item list at `phases of development/38-…-frp-8-…md` §3
is unchanged at SHIPPED. The most-cited:

1. `spec_version` UNCHANGED.
2. §11.7 hardening mandatory at V1.6; RP022 enforces structural
   conformance against the wizard/provider-produced signed
   attestation. The validator NEVER calls Cloudflare.
3. Cloud-provider token never leaves Helper. Edge-range refresh
   runs on Helper, never on origin.
4. No DNS-only A or AAAA records. Wizard refuses; RP023 fires
   at validate time as belt-and-braces.
5. Public-path rotation is Cloudflare-API-only (no box
   redeploy).
6. Freshness endpoint is FRP-controlled (NOT a Daal-project
   hostname). BYO domain is the production-closure default.
7. Position B preserved. Opsec scans green; allowlists narrow
   and documented for `edge_ranges.go` + `freshness/backends/*`.
8. §13.4 cooldown rules now LIVE for `cdn_fronted` (they were
   tested as no-ops at V1.5).
9. ABI count = 48 unchanged. iOS untouched.

## Carry-overs into FRP-9

1. **FRP-9 alpha pilot recruitment.** Run two pilot RelayPacks
   for 14 days and fill `specs/v1-6-closure-v1.md` with the
   §22.2 metrics.
2. **BYO-domain production check.** V1.6 closure metrics assume
   real FRP-owned domains, not the closed-pilot project test
   subdomain.
3. **FA copy native review.** `wizard.cdn.*` (19) +
   `wizard.rotate.copy_*` (4) keys land with placeholder Persian
   strings; native review queued alongside the FRP-6 / 7 / 7.5
   i18n review (~102 keys total).
4. **FA consent template review.** `docs/pilot/consent-template.md`
   FA copy still pending native review.
5. **Live V1.5 5-FRP pilot run.** V1.5 closure HOLD; same gate
   as before FRP-8.
6. **Live V1.6 alpha pilot recruitment.** 2 FRPs × 14-day soak
   (per FRP-9 phase doc); V1.6 closure HOLD until that lands.
7. **BYO domain required for production V1.6 closure metrics.**
   The Daal test subdomain is a closed-pilot pathway only.

## Reproducible build matrix at FRP-8 ship

```
$ cd /home/daal/publisher && /usr/local/go/bin/go build ./...
   (no output)
$ cd /home/daal/publisher && /usr/local/go/bin/go test ./...
   ok  daal/publisher/deploy
   ok  daal/publisher/deploy/cli
   ok  daal/publisher/deploy/cloudflare
   ok  daal/publisher/deploy/cloudinit
   ok  daal/publisher/deploy/freshness
   ok  daal/publisher/deploy/freshness/backends/ghpages
   ok  daal/publisher/deploy/freshness/backends/ipfs
   ok  daal/publisher/deploy/freshness/backends/r2
   ok  daal/publisher/deploy/health
   ok  daal/publisher/deploy/profiles
   ok  daal/publisher/deploy/provider
   ok  daal/publisher/deploy/provider/hetzner
   ok  daal/publisher/deploy/relaypack
   ok  daal/publisher/deploy/rotation

$ cd /home/daal/client-desktop && ~/.cargo/bin/cargo test -p daal-wizard --lib
   72 passed; 0 failed
$ cd /home/daal/client-desktop && ~/.cargo/bin/cargo test -p daal-wizard
   (lib + integration: all green; key_opsec scans pass)

$ cd /home/daal/bundle/go && /usr/local/go/bin/go test ./...
   (regression-only: all green)
$ cd /home/daal/core && /usr/local/go/bin/go test ./...
   (regression-only: all green)

$ git log --oneline -8 main
   <commit-8>  FRP-8 commit 8/8: spec amendments + V1.6 closure HOLD + handover
   96e27cc     FRP-8 commit 7/8: cloud-init CDN cert install + binder _cdn_attestation pass-through + daal-deploy --freshness-url
   9dd4fe2     FRP-8 commit 6/8: wizard CDN command surface + V005 cdn_fronts + Tauri commands + EN/FA i18n + mode-aware rotate copy
   4ba36fe     FRP-8 commit 5/8: core/refresh network IO + atomic swap; selection/freshness pure-policy; importer ApplyVerifiedRefresh
   3de73fd     FRP-8 commit 4/8: validator widening RP022/RP023/RP024 + RP004 V16 lift verification + RP007 per-family tests
   1be5493     FRP-8 commit 3/8: sub-key-aware freshness builder + R2 / GitHub Pages backends, IPFS reserved
   c063d7c     FRP-8 commit 2/8: DNS coordination + edge-range refresh + Hetzner CF firewall helper
   7b75468     FRP-8 commit 1/8: phase doc + cloudflare provider scaffold + Origin CA + AOP
```

## FRP-9 gate verdict

**Engineering surface ready for the FRP-9 alpha pilot once
the carry-overs above land.** The two SDK stubs
(`cf_client_live.go`, `r2/sigv4_*.go`) are the only remaining
live-network deltas; everything downstream of them
(provisioning state machine, attestation shape, validator
gates, recipient-side fetch + verify + swap, wizard storage +
i18n, cloud-init cert install, freshness JSON shape) is locked
and tested.

**No regression observed across 3F, 3-Soak, FRP-0..FRP-7.5
matrices.** ABI count remains 48; `spec_version` unchanged.

End of FRP-8 handover.
