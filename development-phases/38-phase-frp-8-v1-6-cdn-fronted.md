# Phase 38 (FRP-8) — V1.6 CDN-Fronted Mode + Freshness Endpoint

**Status:** SHIPPED 2026-05-03 (engineering surface). Closure HOLD per `specs/v1-6-closure-v1.md` pending FRP-9 alpha pilot. Eight-commit series 7b75468..(commit 8) on `main`. Handover at `docs/handovers/frp-8-handover.md`.
**Roadmap line:** *"V1.6 — CDN milestone. `cdn_fronted` candidates ship, with the §11.7 hardening template enforced. Cloudflare wizard path. Origin CA + Authenticated Origin Pulls + provider-firewall-locked-to-CF-edge-ranges + public-path-rewrite indirection. Mode-aware rotation UI (§14.4)."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.2
**Supplement target:** v2.3.7.
**Engine `Version` target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — supplement holds engine `Version` constant; V1.6 is a packaging-tag milestone, not a `Version` constant change. Any future `Version` bump would require an explicit supplement amendment outside this phase doc's scope).**
**ABI release surface target:** **48** **(UNCHANGED).**
**Maturity:** code phase. Largest CDN-side work in the FRP track. Lifts FRP-1 RP004 (`cdn_fronted` validator-reject at V1.5).
**Predecessor:** Phase 37 (FRP-7.5) — sub-key cert chain stable; long-running FRPs can rotate without root touch.
**Successor:** Phase 39 (FRP-9) — V1.6 CDN soak; produces `specs/v1-6-closure-v1.md`.

## 1. Strategic frame (verbatim from the supplement)

> **§11.7 Required deployment posture for every `cdn_fronted` candidate in V1.6.** Cloudflare Origin CA cert; Full Strict TLS verification; Authenticated Origin Pulls; provider-level firewall locked to Cloudflare edge ranges (refresh on Helper, not origin); no DNS-only A record; no SMTP/MX/SSH on origin IP; public random path → Worker/Page Rule rewrite → stable origin path indirection. HTTP/HTTPS only; UDP families never `cdn_fronted`.
>
> **§14.4 V1.6 freshness model.** Per-publisher freshness URL on Manifest. Recipient polls opportunistically. Atomic RelayPack swap on same-publisher hit; no re-TOFU. Boundary: works only when at least one route is reachable; fully-burned cases still require out-of-band QR.
>
> **§19.2.6 Origin-IP leak attack against `cdn_fronted` candidates.** CT scanning, DNS history, SMTP/MX leak, SSH banner. Mitigation = §11.7 template strictly enforced.

FRP-8's job: ship `publisher/deploy/cloudflare/` (Cloudflare provisioning + freshness endpoint upload), lift FRP-1's RP004 to allow `cdn_fronted` candidates at `Phase: V16`, populate the `Manifest.relay_pack.freshness_url` slot, wire the recipient-side freshness polling, and amend FRP-5's wizard with the V1.6 CDN command surface.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Cloudflare API client | `cloudflare-go/v4` pinned in `publisher/go.mod`; FRP-8 critical path uses Daal's narrow `CFClient` REST wrapper so only the required API surface is live. |
| Package layout | `publisher/deploy/cloudflare/`: `provider.go`, `origin_ca.go`, `aop.go` (Authenticated Origin Pulls), `worker.go` (Worker/Page Rule), `dns.go`, `edge_ranges.go`, `freshness.go`. |
| Origin CA cert provisioning | Via Cloudflare Origin CA API. Cert valid 15 years (Cloudflare default); pinned in OperatorRecord; refreshed on rotation. |
| AOP enable | Enable via `Zone.Settings.AuthenticatedOriginPulls = true`. Client cert deployed to origin via cloud-init (FRP-4a's template extended). |
| Worker / Page Rule | Worker preferred (free tier, more flexible). Public random path → stable origin path rewrite. Worker code is a 20-line template. |
| DNS records | Proxied A + AAAA only. NEVER DNS-only. Wizard refuses if DNS-only A exists for the chosen subdomain. |
| Edge-range refresh | Runs on Helper (NEVER on origin). Triggers: every deploy, every rotate, explicit "Verify CDN posture" check, optional OS scheduled task. Worst-case stale ranges → `origin_unhealthy` → §13.4 origin-repair path, not censorship event. |
| Freshness endpoint | Per-publisher signed JSON document at FRP-controlled static URL (NOT a Daal endpoint). Hosted on the FRP's choice of: GitHub Pages, Cloudflare R2, IPFS gateway. Wizard offers all three. |
| Freshness JSON shape | `{relay_pack_id, current_bundle_sha256, current_signed_url, last_modified}` signed by FRP's publisher key. Locked in §6 below. |
| Recipient polling cadence | Opportunistic per supplement §14.4: on every successful tunnel-establishment event (cheap; runs through whichever route is currently working) + on selector-classified `cdn_hostname_blocked` / `path_pattern_blocked` events. NO scheduled poll. NO fixed cadence. |
| Atomic swap | Recipient downloads new bundle, verifies signature against same publisher key (already trusted; no re-TOFU), replaces RelayPack atomically. |
| BYO-domain default | Yes per supplement §20.4.1. Project test-zone (`daal-relay-test.org`) only behind closed-pilot warning + `domain_suffix:daal-relay-test.org` shared-risk tag. |
| Wizard surface for V1.6 | V005 storage + Tauri commands + i18n for a CDN-front step; direct GUI placement is pilot-polish, while the backend and CLI path are live for FRP-9. Skippable for direct-only RelayPacks. |
| Validator phase lift | All FRP-N call sites that pass `Phase: V15` now pass `Phase: V16` after FRP-8 ships. RP004 lifts (`cdn_fronted` accepted). RP013 (modifiers) still rejects. |
| Telemetry | None. Verified by `publisher/deploy/cloudflare/opsec_test.go`. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **`spec_version` does NOT bump at FRP-8.** `freshness_url` is additive in the same `relay_pack` slot bumped at FRP-1.
18. **§11.7 hardening is mandatory for every `cdn_fronted` candidate.** Validator rule **RP022** (new; RP021 is the existing V1.5 freshness_url-empty gate from FRP-1) enforces structural conformance against the **wizard/provider-produced signed attestation**: every `cdn_fronted` candidate's `_cdn_attestation` blob must carry Origin CA fingerprint + AOP enable flag + Cloudflare-edge firewall ID + `dns_only_present:false`. **The validator does NOT call Cloudflare** — live-posture re-verification is the wizard's "Verify CDN posture" button + `publisher/deploy/cloudflare`'s job.
19. **Cloud-provider token never leaves Helper.** Edge-range refresh runs on Helper; verified by no Cloudflare API call originating from the origin box.
20. **No DNS-only A records.** Wizard refuses; verified by a wizard test.
21. **Public-path rotation is Cloudflare-API-only.** No box redeploy; verified by a rotation test.
22. **Freshness endpoint is FRP-controlled.** No Daal-project hostname involved. Verified by wizard prompts; documented in `specs/relaypack-v1.md`.
23. **Position B preserved.** Recipient never reports successful freshness fetches to anyone; the freshness URL is FRP's, not project's.
24. **§13.4 cooldown rules now LIVE for `cdn_fronted`.** They were tested as no-ops at V1.5 (FRP-3 invariant 19). At FRP-8 they activate because real `cdn_fronted` candidates exist. Selector code unchanged from FRP-3; only validator phase lifts.
25. **No engine release symbols added.** ABI count stays 48.
26. **iOS untouched.** Per supplement §21.5, post-V3.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-8 stub with this locked spec at `phases of development/38-phase-frp-8-v1-6-cdn-fronted.md`. |
| 1  | Read inputs end-to-end: supplement §11.7, §14.4, §14.5, §19.2.6, §20.4.1, §21.2, §22.2; FRP-1 (validator schema for `cdn_fronted`); FRP-3 (`cdn_*` cooldown rules already wired); FRP-4a (Hetzner Provider; cloud-init template); FRP-5 (wizard staging path). |
| 2  | Author `publisher/deploy/cloudflare/provider.go` implementing a CDN-side helper interface: `ProvisionFront(ctx, opts) (*FrontRecord, error)`, `RotateHostname`, `RotatePath`, `Decommission`. |
| 3  | Author `publisher/deploy/cloudflare/origin_ca.go`: provision Origin CA cert via Cloudflare's Origin CA API. Persist cert + key in OperatorRecord (Helper-side, encrypted with publisher's keystore). |
| 4  | Author `publisher/deploy/cloudflare/aop.go`: enable Authenticated Origin Pulls on the zone; download client cert; deploy to origin via cloud-init `write_files` extension. |
| 5  | Author `publisher/deploy/cloudflare/worker.go`: 20-line Worker template that rewrites `/<random-public-path>` to `/<stable-origin-path>`. Deployed via `Workers.UploadScript` + route binding. |
| 6  | Author `publisher/deploy/cloudflare/dns.go`: create proxied A + AAAA records (NEVER DNS-only). Reject existing DNS-only records on the chosen subdomain. |
| 7  | Author `publisher/deploy/cloudflare/edge_ranges.go`: HTTPS GET `cloudflare.com/ips-v4` + `ips-v6` from Helper; apply via cloud-provider firewall API (`hcloud-go.Firewall.Update`). Trigger moments per §2 above. Optional `cron`/`launchd`/`Task Scheduler` integration via Tauri commands. |
| 8  | Author `publisher/deploy/cloudflare/freshness.go`: build signed freshness JSON document (§6 below); upload to chosen static-host (GitHub Pages / R2 / IPFS — provider chosen via wizard). |
| 9  | Extend FRP-4a's cloud-init template (`publisher/deploy/cloudinit/template.yaml.tmpl`) to include AOP client cert deployment when CDN-mode is selected. |
| 10 | Wire wizard CDN command surface: V005 `cdn_fronts` storage, Tauri commands, Cloudflare token in OS keystore, BYO-domain (or project test-zone) inputs, and V1.6 signing path. Full visual placement is pilot-polish; backend and CLI are live for FRP-9. |
| 11 | Extend FRP-1 validator: lift RP004 at `Phase: V16`. Add new rule RP022: `cdn_fronted` candidate requires Origin CA fingerprint + AOP enable flag + Cloudflare-edge firewall ID in its `_relaypack._cdn_attestation` sub-object (new optional field — additive within the already-bumped slot). |
| 12 | Wire recipient-side freshness polling at `internal/selection/freshness.go` (FRP-3 reserved this file). Triggers per §2 above. Verifies signature against pinned publisher pubkey; atomic swap. |
| 13 | Wire wizard rotation copy per §14.5: 4 mode-aware copy variants. EN + FA. |
| 14 | Author tests: ≥30 across `publisher/deploy/cloudflare/` and `internal/selection/freshness/`. Specifically: AOP-enabled positive case; AOP-missing rejected; DNS-only-A rejected; edge-range refresh from Helper succeeds; edge-range refresh attempted from origin (negative test) rejects; freshness JSON round-trip; atomic-swap test; same-publisher-key swap; wrong-publisher-key swap rejected. |
| 15 | Final regression sweep: `cd publisher && go build ./... && go test ./deploy/cloudflare/...`; `cd core && go build ./... && go test ./internal/selection/freshness/...`; `cd bundle/go && go build ./... && go test ./bundle/...` (regression-only); `cd cmd/daal-deploy && go build ./...`; `nm` returns 48; `cdn_fronted` end-to-end (wizard → cloudflare → bundle sign → recipient pickup) succeeds in test environment; FRP-9 gate verdict; handover. |

## 5. Architectural detail — provisioning flow

```mermaid
sequenceDiagram
    participant Wizard
    participant CFP as cloudflare provider
    participant CF as Cloudflare API
    participant CIP as cloud-init provider (Hetzner)
    participant Origin

    Wizard->>CFP: ProvisionFront(domain, token)
    CFP->>CF: OriginCA.IssueCert(domain)
    CF-->>CFP: cert + privkey
    CFP->>CF: Zone.Settings.AOP=true
    CFP->>CF: Workers.Upload(rewriteScript)
    CFP->>CF: Zone.Routes.Bind(public_path → worker)
    CFP->>CF: DNS.Create(proxied A + AAAA)
    CFP->>CFP: edge_ranges = HTTPS GET cloudflare.com/ips-v4
    Wizard->>CIP: ProvisionOpts.CloudInit += AOP cert; firewall = edge_ranges
    CIP->>Origin: cloud-init runs; AOP cert deployed; firewall locked
    Wizard->>Wizard: BindAndSign(rec) — cdn_fronted candidate signed
    Wizard->>CFP: UploadFreshnessDoc(doc, host)
    CFP->>CFP: write to GitHub Pages / R2 / IPFS
```

## 6. Freshness JSON shape (locked) — sub-key-aware

The freshness document follows the FRP-7.5 sub-key chain semantics: a freshness doc is **either** root-signed (no active sub-key on the publisher) **or** sub-key-signed with the cert embedded inline (active sub-key exists). The recipient walks the same `pub → cert → sub` chain it already walks for `.sbp` bundles, so no second trust path is introduced.

```jsonc
{
  "kind":                  "daal/freshness-v1",
  "relay_pack_id":         "<deterministic from BindAndSign>",
  "current_bundle_sha256": "<hex>",
  "current_signed_url":    "https://<frp-static-host>/<bundle-name>.sbp",
  "last_modified":         "2026-05-14T12:34:56Z",
  "publisher_pub_hex":     "<root publisher pub, hex>",
  "subkey_cert":           {/* SubkeyCert JSON, omitted iff root-signed */},
  "signature_hex":         "<Ed25519 over canonical JSON above with signature_hex stripped>"
}
```

Signing rules:

* If the wizard has **no active sub-key** for this operator: omit `subkey_cert`; sign with the root publisher key.
* If the wizard has an **active sub-key**: embed the canonical `SubkeyCert` JSON in `subkey_cert`; sign with the sub-key.

Recipient verification (mirrors `bundle.VerifyBundle`'s walk; lives in `core/refresh/verify.go`, NOT in `core/internal/selection/`):

1. Recipient already has the publisher root pubkey pinned (TOFU at FRP-6).
2. Fetch the freshness URL via `core/bootstrap.FetchRaw` (the existing HTTPS-only fetcher; `core/internal/selection/` is pure-policy and never fetches).
3. If `subkey_cert` absent → verify `signature_hex` against `publisher_pub_hex`. Reject if `publisher_pub_hex ≠ pinned root`.
4. If `subkey_cert` present → walk: `publisher_pub_hex == pinned root` AND `cert.root_pub == pinned root` AND `cert.signature` valid AND now ∈ `[cert.not_before, cert.not_after]` AND `signature_hex` valid against `cert.sub_pub`.
5. If `current_bundle_sha256` ≠ recipient's current bundle SHA-256, fetch `current_signed_url` (also via `core/bootstrap.FetchRaw`), then `bundle.VerifyBundle` the bytes (existing FRP-7.5 chain). The bundle's own `subkey_cert` (separate from the freshness doc's) is whatever the wizard's signing path emitted.
6. Atomic swap (in `core/refresh/swap.go`): replace local RelayPack, preserve trust state, do NOT re-prompt TOFU. Importer (`bundle/go/importer/`) only consumes verified bytes — it never opens a socket.

## 7. CDN-mode validator rules added (locked)

Builds on FRP-1's RP001-RP021 (RP021 is the existing V1.5 `freshness_url`-empty gate). New at FRP-8:

| Rule ID | Severity | Description |
|---|---|---|
| `RP022` | error | At `Phase: V16`, every `cdn_fronted` candidate's `_relaypack._cdn_attestation` (new optional sub-field, additive inside the FRP-1 `_relaypack` opaque blob — no `spec_version` bump) must carry: `origin_ca_fingerprint`, `aop_enabled: true`, `firewall_id`, `dns_only_present: false`. The validator parses the wizard/provider-produced attestation; **it does NOT call Cloudflare**. |
| `RP023` | error | The `_cdn_attestation.dns_only_present` field is `true` (the wizard's deploy-time check found a DNS-only A/AAAA record on the chosen subdomain). Distinguishes "attestation missing" (RP022) from "attestation present but reports posture failure" (RP023). |
| `RP024` | warn | A `cdn_fronted` candidate without a `direct_vps` sibling in the same RelayPack — surfaces "consider adding a direct route as fallback" nudge. |

UDP family + `cdn_fronted` is **already covered by RP007** (the §11.1.1 family-matrix gate). FRP-8 adds explicit per-family unit tests (Hysteria2, TUIC, WireGuard, AmneziaWG) under the existing RP007 case to make the matrix coverage observable in the test ledger.

RP004 is **lifted** at `Phase: V16`. RP013 (modifiers) and RP016 (cell transitive) remain.

**Live-posture re-verification** is the wizard's "Settings → Routes → Verify CDN posture" button (per §11.7). It calls `publisher/deploy/cloudflare/posture.go::Verify` which re-fetches Origin CA fingerprint, AOP flag, firewall rule, and the proxied-DNS state from Cloudflare and surfaces drift. The validator's job is structural-attestation conformance; the wizard's job is live-posture re-confirmation.

## 8. Build matrix at FRP-8 exit

```
$ cd publisher && gofmt -l ./deploy/cloudflare/                 # no output
$ cd publisher && go build ./deploy/cloudflare/...               # green (under daal/publisher module)
$ cd publisher && go test ./deploy/cloudflare/...                # ≥20 tests
$ cd core && go test ./internal/selection/freshness/...          # ≥10 tests
$ /tmp/daal-deploy provision --dry-run --provider hetzner --cdn cloudflare --domain test.example.com --cf-token-fd /tmp/token --pubkey /tmp/test.pub
   # emits OperatorRecord with cdn_fronted candidate; no API call (dry-run)
$ /tmp/daal-publish verify /tmp/test-cdn.sbp                    # green; cdn_fronted accepted at V16
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l           # 48 (UNCHANGED)
$ git grep -n 'spec_version' bundle/go/bundle/types.go          # UNCHANGED from FRP-7.5 value (freshness_url is additive)
$ # OPSEC: no Cloudflare API call from origin
$ rg -n 'cloudflare-go' core/ | wc -l                           # 0
```

## 9. Spec deliverables

**1 NEW:**
- `specs/v1-6-closure-v1.md` — V1.6 closure record, status HOLD pending FRP-9 alpha pilot. Mirrors `specs/v1-5-closure-v1.md` shape.

**3 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"V1.6 CDN-fronted profile" section with the §11.7 hardening template, the freshness JSON shape (sub-key-aware), and the new validator rules (RP022-RP024).
- `specs/sbp-v1.md` — gains a §"`freshness_url` Manifest field" cross-reference.
- `docs/family-relay-publisher-v1.md` — gains the V1.6 CDN wizard flow.

## 10. Out of scope (deferred)

- Vultr / Stark CDN paths — V2 (FRP-10).
- Cell-aware freshness (cross-publisher updates) — **FRP-11.**
- Per-CDN comparison (Fastly, Akamai) — V4.
- Cloudflare Spectrum (paid TCP/UDP) — explicitly out of scope per §11.7.
- Modifier opt-in inside CDN-fronted — **FRP-12.**

## 11. Handover requirements

The FRP-8 handover must contain:

1. Status: SHIPPED. Date.
2. New file paths under `publisher/deploy/cloudflare/`.
3. Cloud-init template diff (AOP cert deploy added).
4. Validator rule additions (RP022-RP024) test pass; explicit RP007 per-family tests for Hysteria2/TUIC/WireGuard/AmneziaWG.
5. Wizard CDN command-surface evidence and pilot UI notes.
6. End-to-end CDN deploy + sign + recipient pickup result.
7. Freshness atomic-swap test result (≥3 swap cycles).
8. `nm` count = 48 unchanged.
9. `spec_version` unchanged from FRP-7.5 value.
10. FRP-9 gate verdict.

## 12. Track ordering rationale

FRP-8 between FRP-7.5 and FRP-9 because: (a) sub-key chain (FRP-7.5) must work before V1.6 expands the deploy surface — long-running CDN deployments accumulate operational scar without sub-key rotation; (b) the V1.6 closure is the next gate (FRP-9), and FRP-8's deliverables are what FRP-9 soaks against; (c) the "freshness endpoint is FRP-controlled, NOT a Daal-project endpoint" property comes from how FRP-8 is implemented (publisher-side static-host upload), and committing to that shape early prevents architecture drift toward a project-side service.

## 13. Layer split + production-gate clarifications (locked at execution review)

Six locked clarifications applied during execution review of the spec, all consistent with already-shipped invariants:

1. **`core/internal/selection/` stays pure-policy.** `selection/freshness.go` (NEW) only answers *"should we poll now?"* given recent signals + last-poll timestamp. It MUST NOT open sockets or import `core/bootstrap`. The opsec test at `core/internal/selection/opsec_test.go` is extended with an assertion that `selection/freshness.go` does not reference `net/http`, `crypto/tls`, or `core/bootstrap` symbols.
2. **`core/refresh/` (NEW package) owns network IO + atomic swap.** `core/refresh/poller.go` consults `selection.ShouldPollFreshness`; `core/refresh/fetch.go` calls `core/bootstrap.FetchRaw` for both the freshness JSON and (on sha-mismatch) the new `.sbp`; `core/refresh/verify.go` walks the sub-key-aware verification chain (§6); `core/refresh/swap.go` performs the atomic file replace.
3. **`bundle/go/importer/` only consumes verified bytes.** No URL fetch, no socket. The importer gains an `ApplyVerifiedRefresh(verifiedBytes []byte) error` entry point that walks `bundle.VerifyBundle` and updates the route store; the caller (`core/refresh/swap.go`) is responsible for fetching + first-pass verification before handing bytes in.
4. **Freshness signing is sub-key-aware** per §6 above: root-signed if no active sub-key; sub-key-signed with embedded `subkey_cert` if an active sub-key exists. The wizard's `freshness build` path consults the V004 `subkeys` table (FRP-7.5) the same way `sign_relaypack` already does.
5. **OperatorRecord stores public CDN metadata only.** `OperatorRecord.CDNFront` carries: hostname, zone_id, worker route, firewall_id, origin_ca_fingerprint (PUBLIC fingerprint, hex), aop_enabled flag, freshness_url. The Cloudflare API token lives in the OS keystore (sealed under PIN, alias `daal.cloudflare.{operator_id}.token`); the Origin CA private key + AOP client cert private bytes live in the wizard staging dir under `cdn/{operator_id}/` at mode 0600 and are referenced by path only in the V005 SQLite row, never in the operator JSON blob.
6. **BYO domain is the production-closure default.** Invariant 22 ("freshness endpoint is FRP-controlled") is read as **production-specific**: BYO domain is required for V1.6 closure-metric eligibility per §22.2; the Daal test subdomain is a closed-pilot pathway only, surfaced behind a warning checkbox, and tagged with `project_subdomain_pool:daal` + `domain_suffix:daal-relay-test.org` shared-risk tags so the §13.4 propagation rules can demote the entire pool if it starts failing.

End — locked at FRP-track planning + execution review. Next: FRP-9 (V1.6 CDN soak).
