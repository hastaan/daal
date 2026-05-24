
**Status:** SHIPPED 2026-05-04 (engineering surface).
**Closure:** HOLD (`specs/v1-6-closure-v1.md`) — gated on the
FRP-9 live alpha pilot (2 FRPs × 14-day soak). Engineering
ship clears the precondition; the closure record itself is
appended once the live pilot delivers the green aggregate.
**Engine line:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI:** **48** UNCHANGED.
**Spec version:** UNCHANGED. No bundle ABI surface touched
(FRP-9 is operator-side rotation; bundle producer + verifier
remain on the FRP-8 contract).
**Supplement:** v2.3.7 → v2.3.8 (one new subsection
§14.6 — Operator rotation levels for cdn_fronted; documents
L7/L8/L9 audit-log numbering).

This handover summarises the eight-commit FRP-9 series. It
ships the operator-level CDN rotation surface (L7 path, L8
hostname, L9 origin) end-to-end: Provider methods + live
CFClient REST glue, three new `daal-deploy` subcommands, the
wizard's `rotate_execute` mode-aware branch, freshness
re-publish gating (L7/L8 only; never L9), wizard UI mode-aware
copy + EN/FA i18n, V006 `signed_sbps.rotation_kind` structured
audit tag, supplement §14.6 documenting the closure invariants.

## What FRP-9 ships

The supplement's §14.4 cdn_fronted rotation table has lived as
text since v2.3.4. FRP-9 lands the **operator-level
implementation** of that table: a wizard "Rotate" button that,
when an operator's `cdn_fronted` candidate is the burned one,
splits into three discrete commands matching the §14.4 fix
column. Each command preserves the §14.4 origin-only-vs-
public-surface invariant programmatically:

* **L7 — public-path rotation** (`/r/<random>` moves; hostname
  + origin + certs all stay). Re-signs RelayPack; re-publishes
  freshness JSON.
* **L8 — hostname rotation** (hostname + Cloudflare zone
  move; public path preserved). Re-signs RelayPack;
  re-publishes freshness JSON.
* **L9 — origin-only rotation** (proxied A/AAAA move to a new
  origin IP; **everything else byte-identical**). Does **NOT**
  re-sign; does **NOT** re-publish; censor sees nothing;
  family sees nothing.

### Commit-by-commit

| # | SHA | Title |
|---|---|---|
| 1 | `e5fd104` | CDN rotation surface (engine + wizard wiring) |
| 2 | `29dbb40` | daal-deploy cdn-rotate-{path,hostname,origin} subcommands |
| 3 | `24deeb8` | rotate_execute mode-aware branch (L7/L8/L9) |
| 4 | `1fb7d79` | Freshness re-publish gating (L7/L8 only; never L9) |
| 5 | `7dfc076` | Wizard rotate UI mode-aware copy + i18n keys (EN+FA) |
| 6 | `d78b921` | V006 signed_sbps.rotation_kind structured tag |
| 7 | `3aa7775` | Spec amendments + supplement §14.4 closure (v2.3.8) |
| 8 | (this commit) | Handover doc + V1.6 closure metric rows |

### New + amended code surfaces

* `publisher/deploy/cloudflare/cf_client.go` — three new
  `CFClient` methods: `RotatePublicPath`, `RotateHostname`,
  `RotateOrigin`. Live impl in `cf_client_live.go` + mock impl
  in `cf_client_mock.go`. The interface is the **only** place
  that talks to Cloudflare; the validator never does.
* `publisher/deploy/cloudflare/provider.go` — three new
  Provider-level methods that own the §14.4 invariants and
  mutate the `FrontRecord` in place. L7 re-uploads the worker
  + delete-and-rebinds the route; L8 re-resolves the apex zone
  + ensures proxied DNS + rebinds worker on the new zone; L9
  re-points A/AAAA only and **mutates no public-surface
  field**.
* `publisher/deploy/cloudflare/rotate_test.go` — 6 new tests
  locking each invariant byte-for-byte.
* `publisher/deploy/cli/cli.go` — `cdn-rotate-path`,
  `cdn-rotate-hostname`, `cdn-rotate-origin`,
  `publish-freshness` subcommands; usage text spells out the
  L7/L8 vs L9 contract; cf-token via mode-0600 tempfile +
  zeroized.
* `publisher/deploy/cli/cli_frp9_test.go` — flag-name + usage
  contract tests so the wizard ↔ CLI surface doesn't drift.
* `client-desktop/daal-wizard/src/cli_bridge.rs` —
  `CdnRotate{Path,Hostname,Origin}Args` + `CdnRotateResult`
  + `PublishFreshnessArgs` + `PublishFreshnessResult` + four
  new `CliRunner` methods + `SubprocessRunner` impls
  (mode-0600 cf-token tempfile) + `MockRunner` per-method
  call tracking (`cdn_rotate_*_calls`,
  `publish_freshness_calls`).
* `client-desktop/daal-wizard/src/operator_db.rs` — V006
  migration (`signed_sbps.rotation_kind` TEXT NOT NULL
  DEFAULT '' + idx) + `derive_rotation_kind` helper +
  `get_cdn_front` + `update_cdn_front_rotation` +
  `record_origin_only_rotation`.
* `client-desktop/daal-wizard/src/commands.rs` —
  `rotate_cdn_path` / `rotate_cdn_hostname` /
  `rotate_cdn_origin` Tauri commands; `publish_freshness_after_rotate`
  helper hooked into `rotate_execute` for L7/L8 only;
  `RotateExecuteInput` extended with six `cdn_*` fields and
  `freshness_signed_sbp_url`.
* `client-desktop/daal-wizard/migrations/V006__signed_sbps_rotation_kind.sql`
  — schema migration with backfill from legacy
  rotation_reason text.
* `client-desktop/tauri/src/wizard/i18n/wizard.{en,fa}.json` —
  27 new `wizard.rotate.cdn.*` keys × 2 locales (54 strings).
  Mode-aware copy: L7/L8 say "your family will see a new
  fingerprint"; L9 says "your family sees no change, do not
  send anyone a new QR".
* `daal-roadmap-v3-supplement-diaspora-helper.md` — new
  §14.6 documenting L7/L8/L9 + five locked invariants;
  supplement bumps to v2.3.8.

### Test surface

| Surface | Tests added (FRP-9) | Total at FRP-9 ship |
|---|---|---|
| `publisher/deploy/cloudflare` | 6 (rotate_test.go) | FRP-8 baseline + 6 |
| `publisher/deploy/cli` | 4 (cli_frp9_test.go) | FRP-8 baseline + 4 |
| `client-desktop/daal-wizard` (lib) | +10 (72 → 82) | **82** |
| `soak-driver/cmd/soak-driver` | +4 (v1_6_superset_test.go) | selector count / exact IDs / additive guard / known actions |
| `soak-driver/internal/soak` | +1 (v1_6_actions_test.go) | V1.6 dispatch emits no unknown actions |
| `soak-driver/internal/v16verifier` | +4 (v16verifier_test.go) | aggregate PASS / missing FRP / explicit failure / G1 required |

`daal-wizard` lib breakdown (post-FRP-9): 72 (FRP-8 ship) +
4 (rotate_cdn_path/hostname/origin tests, commit 1) + 4
(rotate_execute L7/L8/L9 + L7-required-front-id, commit 3) +
2 (V006 derive + persist round-trip, commit 6) = **82**.

Operators verifying the matrix should run:

```
cd /home/daal/client-desktop && cargo test -p daal-wizard --lib
```

and expect `test result: ok. 82 passed; 0 failed`.

### Locked invariants exercised

1. **Validator never calls Cloudflare.** RP022 / RP023 enforce
   the signed `_cdn_attestation` offline. FRP-9's rotation
   surface does NOT alter the attestation; the wizard's
   "Verify CDN posture" button (FRP-8) is the only path that
   re-checks Cloudflare state, and even that is a Helper-side
   call mediated by `CFClient`, not by the validator.
2. **Cloudflare API token never leaves Helper.** Wizard hands
   the token to `daal-deploy` via a mode-0600 tempfile;
   subprocess zeroizes on exit. Wizard side wraps the token
   in `Zeroizing<Vec<u8>>` and drops on scope exit.
3. **L9 origin-only mutates no `public_risk_tag`-bearing
   field.** Hostname / zone_id / public_path / origin_path /
   worker_route_id / origin_ca_fingerprint / aop_enabled all
   byte-identical before and after. Test:
   `rotate_execute_l9_cdn_origin_does_not_resign`.
4. **L9 origin-only does not re-sign or re-publish.**
   `signed_sbp_id == 0`, `bind_result == Default`,
   `publish_freshness_calls.len() == 0`. The audit row is
   written via `record_origin_only_rotation` (`active=0`).
5. **`freshness_signed_sbp_url` is required L7/L8 input.**
   L9 path doesn't read it. A wizard bug supplying it on L9
   would not cause a re-publish (the L9 branch early-returns
   before the freshness step), but the input remains a clean
   API contract: L7/L8 fail closed without it.

### Position B preserved

* No new telemetry surface.
* Freshness endpoint is FRP-controlled; project never sees
  the fetch event (recipient does it through whatever
  tunneled-fetch path it has).
* Cloudflare token lifecycle: Helper-only.
* opsec_test allowlist for `edge_ranges.go` +
  `freshness/backends/*` documented at FRP-8 still applies;
  no new opsec allowlist entries at FRP-9.

## V1.6 closure metric rows (engineering side)

The closure record at `specs/v1-6-closure-v1.md` lists six
metric rows (V1.6-P1, V1.6-P2, V1.6-S1, V1.6-S2, V1.6-S3,
V1.6-G1). FRP-9 engineering ship clears the **rotation
deliverables** referenced by V1.6-S1 and the **synthetic-
gate engineering** referenced by V1.6-G1. The closure record
itself flips from HOLD to SHIPPED only after the live alpha
pilot returns the green aggregate roll-up; engineering ship is
necessary but not sufficient.

Engineering checklist that V1.6-S1 + V1.6-G1 can now sign off:

| Engineering item | FRP-9 ship status |
|---|---|
| L7 rotate_cdn_path command surface | SHIPPED (commit 1+3) |
| L8 rotate_cdn_hostname command surface | SHIPPED (commit 1+3) |
| L9 rotate_cdn_origin command surface | SHIPPED (commit 1+3) |
| Freshness re-publish gated to L7/L8 only | SHIPPED (commit 4) |
| L9 origin-only writes audit-only history row | SHIPPED (commit 3+6) |
| Mode-aware wizard copy (EN+FA) | SHIPPED (commit 5) |
| §14.4 closure language in supplement | SHIPPED (commit 7) |
| 7 v1-6-superset scenarios + verifier | SHIPPED — `test-rigs/distribution-failure/scenarios/v1-6-*.json`, `--scenarios v1-6-superset`, V1.6 rig-local action dispatchers, and `internal/v16verifier` |

### Carry-overs

* FA copy native review of FRP-6 + FRP-7 + FRP-7.5 + FRP-8 +
  FRP-9 i18n (60 + 19 + 23 + 27 = 129 keys) — queued for FA
  reviewer.
* Live 2-FRP × 14-day alpha pilot run.
* Cloudflare-go SDK live wiring: the rotate paths use the same
  narrow `CFClient` boundary as FRP-8; `cf_client_live.go`
  surfaces `ErrCFNotImplemented` for any operation the
  cloudflare-go SDK is not yet wired for. RotatePublicPath +
  RotateOrigin reuse `EnsureProxiedRecords` (already wired);
  RotateHostname's `LookupZoneID` path reuses FRP-8's wiring.
* AWS Sig v4 wiring in `r2.go` (carry-over from FRP-8;
  freshness re-publish currently emits the signed JSON to
  `<staging>/freshness.<id>.json` and waits for live R2 / GH
  Pages SDK wiring).
* BYO-domain prerequisite for production V1.6 closure
  metrics (unchanged from FRP-8 carry-over).

### What FRP-10 picks up

FRP-10 (V2 multi-provider) opens once `specs/v1-6-closure-v1.md`
is appended with a `## Closure run YYYY-MM-DD` section. The
rotation primitives FRP-9 ships are mode-aware but
provider-narrow (Cloudflare only); FRP-10 widens them to a
second CDN (or origin-side multi-provider) and exercises the
public-surface diversity validator rules at a wider scale.
