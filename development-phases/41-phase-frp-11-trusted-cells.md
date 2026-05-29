# Phase 41 (FRP-11) — Trusted Cells

**Status:** SHIPPED — engineering complete at FRP-11; cell-closure-v1.md HOLD pending V2 cell alpha pilot.
**Roadmap line:** *"V2 — Trusted cells. Cells reuse 3F's wire shape and cap mechanics, but require new specs (`specs/cell-v1.md`), new import-side cell-signature verification, and new cell-management UI. The engine release ABI stays unchanged (count = 48); the work is at the bundle-format / importer / UI layer."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §16.2 + §16.3
**Supplement target:** v2.3.10.
**Engine `Version` target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — supplement holds engine `Version` constant; cells are bundle/importer/UI work, ABI=48).**
**ABI release surface target:** **48** **(UNCHANGED).**
**Maturity:** code phase + closure phase. Ships `specs/cell-v1.md` AND `specs/cell-closure-v1.md`. Gates FRP-13 (public directory).
**Predecessor:** Phase 40 (FRP-10) — multi-provider live.
**Successor:** Phase 42 (FRP-12) — modifier framework; not blocked on cells, but ordered after for review-load reasons.

## 1. Strategic frame (verbatim from the supplement)

> **§16.1 What a cell is.** A bounded group of FRPs (family + close friends + a diaspora student org + a local mosque circle) that mutually share spare RelayPack capacity using the existing 3F `delegated_n` redistribution policy.
>
> **§16.2 Cell components.** Cell admin scheme (M-of-N independent Ed25519 signatures over the membership document — NOT a threshold cryptosystem; see §2 Locked Answers); cell-membership document carrying `(cell_id, members[], rule_set, valid_until)` plus the admin-pubkey array + quorum and signed independently by each admin; admin-quorum-signed delegation document grants bundle-signer authority to a per-cell signing key; aggregated RelayPack signed by that bundle-signer key carrying inner per-FRP signed candidates; import-side cell verification chain (admin-quorum → membership → delegation → bundle-signer → inner-publisher); cell-management UI.
>
> **§22.3 V2 trusted-cell success metric.** Across 100 FRPs across ≥3 providers and ≥2 EU regions, organised into ≥5 cells of 5–25 members each, a TIC-driven burn cycle blocking one entire provider's Frankfurt range is recovered from in <15 minutes wall-clock, with no more than 10% of family connections experiencing a lost-traffic event >30 seconds.

FRP-11 is the largest single bundle-format / spec phase on the FRP track. It defines `specs/cell-v1.md`, ships the M-of-N independent Ed25519 admin-quorum scheme + delegation chain, the aggregated-RelayPack inner-provenance, the import-side cell-signature verification, and the cell-management UI; runs the V2 trusted-cell soak; produces `specs/cell-closure-v1.md` (the gate FRP-13 requires).

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Cell key admin scheme | **M-of-N independent Ed25519 signatures** over the cell-membership document. NOT a threshold cryptosystem (no key aggregation, no MPC, no BLS). Each cell admin holds their own independent Ed25519 keypair; the membership doc carries an array of N admin pubkeys plus a quorum requirement M; verification accepts the doc if at least M of the N admin pubkeys have produced a valid signature over the canonical doc bytes. This is auditable, simple, uses primitives Daal already depends on, and avoids inventing a custom threshold scheme. Default M = ⌈(N+1)/2⌉ (simple majority); cell admins MAY choose stricter quora at cell-creation time. |
| Cell-membership doc shape | JSON: `{cell_id, admin_pubkeys[], quorum_m, members[], rule_set, admin_signatures[]}`. Per-member entry: `{publisher_fp_hex, subkey_fp_hex, joined_at_unix}`. Per-signature entry: `{admin_pubkey_idx, signature_b64}` where `signature_b64` is an Ed25519 signature over the canonical bytes of the doc minus `admin_signatures[]`. Verifier counts unique valid signatures from `admin_pubkeys[]`; accepts iff ≥ `quorum_m`. |
| Aggregated RelayPack shape | A profile of `.sbp` with all member-FRPs' candidates merged into the manifest, each candidate carrying `_relaypack._inner_provenance` metadata that names the contributing membership entry (`publisher_fp_hex`, `subkey_fp_hex`). The outer bundle is signed by **a single delegated cell-signer key**, whose authority is granted by an admin-quorum-signed delegation embedded in the bundle's `trust/cell-delegation.json`. (One delegated signer per emission; the delegation itself bears the M-of-N admin signatures over the canonical delegation bytes.) |
| Import-side verification | Recipient verifies: (a) admin-quorum signatures on `trust/cell-membership.json`; (b) cell-membership validity (`valid_until`); (c) admin-quorum signatures on `trust/cell-delegation.json` granting authority to the bundle's `publisher.pub`; (d) delegation valid_from..valid_until; (e) bundle signature against the delegated `publisher.pub`; (f) every route's `_relaypack._inner_provenance` names a member in the signed membership doc. |
| Trust ladder placement | Cells are Tier-0 + Tier-1 trust per supplement §15.3. Recipient TOFU's the cell-membership doc's admin set on first import (one-tap; surfaces the N admin pubkeys + M quorum to the user; same UX shape as FRP-6 publisher TOFU). |
| 3F reuse | `redistribution_policy` wire shape from 3F is reused for share-class / cap mechanics. Engine code untouched. |
| Cell-management UI | New screens at `client-desktop/tauri/src/cell/` (frontend) + `client-desktop/tauri/src-tauri/src/cell/` (Tauri commands): create cell (admin); join cell (member); list members; rotate admin set (re-issue membership doc with new admin pubkeys + signatures); revoke member. EN + FA. |
| Cell soak target | 100-FRP synthetic + 25-FRP closed pilot. Synthetic models the 100-FRP scale per supplement §22.3; pilot demonstrates 5 cells × 5 members. |
| Cell closure record | `specs/cell-closure-v1.md` (mirror of `specs/v1-6-closure-v1.md`). Status: SHIPPED on PASS, HOLD on any FAIL. **Required by FRP-13** (public directory gate). |
| Engine `Version` constant | UNCHANGED. Stays `daal-core 0.9.0+v3-share`. Cells are bundle / importer / UI work; ABI=48. |
| Telemetry | None. Cells are recipient-pulled; no project-side aggregation. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **Engine release ABI stays 48.** All cell work is at bundle / importer / UI layers.
18. **Cell admin uses M-of-N independent Ed25519 signatures only.** No threshold cryptosystem, no key aggregation, no BLS. Each admin signs the doc independently with their own key; verifier counts ≥M valid sigs from the listed admin set.
19. **Per-candidate inner-publisher provenance preserved.** A cell-aggregated RelayPack carries each contributing FRP's publisher/sub-key fingerprint inside signed `_relaypack._inner_provenance`; recipient import rejects routes whose provenance does not name a member in the signed membership doc.
20. **Cell admin-set TOFU is one-tap.** Surfaces the N admin pubkeys + M quorum on first import; pinned thereafter. Adding/removing admins requires re-issuing the membership doc with a new admin set, which on import surfaces a "cell membership changed" prompt to the user.
21. **Cell-membership doc is signed and time-bounded.** `valid_until` enforced at recipient; expired doc → reject. Soft window 30 days; admin can extend.
22. **Cells operate over both `direct_vps` and `cdn_fronted` candidates.** No mode discrimination at the cell layer.
23. **`specs/cell-closure-v1.md` is mandatory.** FRP-13 (public directory) is gated on cell closure record SHIPPED; without it, FRP-13 stays in pre-spec.
24. **Position B preserved.** Cells are recipient-pulled; no project-aggregator service.
25. **Cell membership is small.** Recommended cap: 25 members per cell. Larger cells fragment trust; the cell-management UI surfaces a warning above 25.
26. **`daal/bundle-go` module independence preserved.** `bundle/go/go.mod` is its own Go module; `core/go.mod` imports `daal/bundle-go`, never the reverse. FRP-11 cell verification respects this: `bundle/go/bundle/sbp.go` + `bundle/go/bundle/cellcanon.go` carry only bundle-local logic (parse, canonicalise, verify the bundle-signer signature on the aggregate, expose accessors); the recipient-side chain walk lives at `core/trust/cell_verify.go` and calls into `bundle.VerifyBundle`, NOT the other way around. Verified by an existing-pattern parallel: `bundle/go/bundle/sbp.go:251` already mirrors a `core/rendezvous` table locally because the bundle module deliberately cannot import the engine. CI-equivalent guards (each module built from its own root, since the repo has no root `go.mod` or `go.work`): `cd bundle/go && go build ./...` succeeds; `! rg -n 'daal/core' bundle/go/bundle/` returns non-zero (no engine imports inside the bundle module).

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-11 stub with this locked spec at `phases of development/41-phase-frp-11-trusted-cells.md`. |
| 1  | Read inputs end-to-end: supplement §16.1–§16.3, §17.1, §22.3; 3F handover (`redistribution_policy` wire shape); FRP-1 (`relay_pack` slot); FRP-3 (cooldown rules; cell-aware extension hooks); FRP-7.5 (sub-key cert chain pattern reused for cell-key chain). |
| 2  | Author `specs/cell-v1.md` — defines: M-of-N independent Ed25519 admin signature scheme; cell-membership doc shape; cell-delegation doc shape; aggregated-RelayPack profile; import-side verification rules; admin-set rotation; cell admin operations. |
| 3  | Author `publisher/cell/` (per supplement §21.3 explicit path) — **publisher-side primitives**: `admin_set.go` (M-of-N independent signature build/verify); `membership_doc.go` (parse/sign/verify); `delegation.go` (admin-quorum-signed delegation to bundle signer); `aggregator.go` (merge candidates into one bundle). |
| 4a | Extend `bundle/go/bundle/sbp.go` ONLY with **bundle-local** cell-aggregate work: parse + canonicalise the new cell docs; expose accessors so a caller can read the membership doc, delegation doc, and `_relaypack._inner_provenance` metadata. **`VerifyBundle` MUST NOT call into `core/trust/`** — that would invert the module boundary (`bundle/go/go.mod` is independent; `core/go.mod` imports `daal/bundle-go`, never the reverse; see `bundle/go/bundle/sbp.go:251` comment about the existing rendezvous-channel mirror pattern). The shared canonicalisation primitives (admin-set canon, membership-doc canon, delegation-doc canon) live at `bundle/go/bundle/cellcanon.go` so both `publisher/cell/aggregator.go` (via the bundle module) and `core/trust/cell_verify.go` (via the same import) get the same bytes. |
| 4b | Author `core/trust/cell_verify.go` — **recipient-side verification chain** (per supplement §16.2 explicit path): owns the full chain walk admin-quorum-over-membership → membership validity → delegation-grant → bundle-signer-on-aggregate → per-route provenance membership. **Calls into `bundle.VerifyBundle` and reads bundle accessors; NOT the other way around** — preserving the existing `core → bundle` dependency direction. Cached membership + delegation docs keyed by `cell_id`. |
| 5  | Author wizard cell-management screens at `client-desktop/tauri/src/cell/` (frontend) + `client-desktop/tauri/src-tauri/src/cell/` (Tauri commands): create-cell, join-cell, list-members, rotate-admin-set, revoke-member. EN + FA. |
| 6  | Wire FRP-3's selector hooks for cell-aware fallback: when an FRP's own RelayPack is fully cooled, selector falls back to cell-peers' candidates per supplement §16.4. |
| 7  | Author `test-rigs/distribution-failure/scenarios/v2-cell-*.json` (≥10 scenarios): cell join, cell rotation, peer fallback, cell-key compromise + recovery, member revocation, expired membership doc, share-class quota enforcement, multi-provider cell, multi-region cell, TIC-driven burn cycle. |
| 8  | Wire `--scenarios v2-cell-superset` selector. Target ≥10 scenarios; this is additive to v2-superset (cell-only paths). |
| 9  | Run synthetic 100-FRP soak: `soak-driver run --scenarios v2-cell-superset --providers hetzner,vultr,stark --regions fsn1,nbg1,ams1 --duration 14d --seed 42`. Validate §22.3 success criterion. |
| 10 | Recruit 25-FRP × 5-cell closed pilot from V1.6 graduates. |
| 11 | Run live closed pilot. Capture cell-formation timeline, peer-fallback events, cell-key rotation events, anonymized family-side timestamps. |
| 12 | If PASS: write `specs/cell-closure-v1.md` SHIPPED; FRP-13 gate = PASS (subject to §17.2 conditions in addition). **DO NOT modify `core/abi/abi.go`'s `Version` constant.** If HOLD: closure HOLD; FRP-13 gate = BLOCKED. Final regression sweep; FRP-12 gate verdict; handover. |

## 5. Cell-aggregated RelayPack shape (locked)

```
.sbp
├── manifest.json (signed by the cell-delegated bundle signer)
│   └── relay_pack:
│       ├── version: "1"
│       └── shared_risk_graph[]             # merged across all member FRPs
│   └── routes[]:
│       ├── candidate-A (from FRP-1)
│       │   └── family_specific_config._relaypack._inner_provenance:
│       │       {publisher_fp_hex, subkey_fp_hex, proof_b64?}
│       ├── candidate-B (from FRP-2)
│       │   └── family_specific_config._relaypack._inner_provenance:
│       │       {publisher_fp_hex, subkey_fp_hex, proof_b64?}
│       └── ...
├── publisher.pub (the cell-delegated bundle signer's pubkey)
├── trust/cell-membership.json   # admin set + members + quorum_m + signatures[] (M valid sigs from N admins)
├── trust/cell-delegation.json   # admin-quorum-signed delegation: "admin set authorizes <publisher.pub> to sign cell bundles until <not_after>"
├── manifest.sig                 # delegated bundle signer over manifest.json
└── profiles/...                 # route profile files
```

Recipient verification:
1. Parse `trust/cell-membership.json`; check ≥`quorum_m` valid Ed25519 sigs from listed `admins[]` over canonical doc bytes; check `valid_until`. (TOFU the admin set on first import; pin thereafter.)
2. Parse `trust/cell-delegation.json`; check ≥`quorum_m` valid Ed25519 sigs from listed `admins[]` over canonical delegation bytes; check `not_after`; check that delegation's `delegated_pub` matches archive's `publisher.pub`.
3. Verify outer manifest signature against `publisher.pub` (the delegated signer).
4. For each candidate, require `_relaypack._inner_provenance.publisher_fp_hex` + `subkey_fp_hex` to match one signed membership entry.
5. On any failure: reject. On success: install RelayPack atomically.

## 6. V2 trusted-cell success metric — operational form

Per supplement §22.3:

1. **Scale**: 100 FRPs simulated across ≥3 providers, ≥2 EU regions.
2. **Cell organization**: ≥5 cells of 5–25 members each.
3. **Burn recovery time**: TIC-driven burn cycle blocking one provider's Frankfurt range recovered in <15 minutes wall-clock.
4. **Connection continuity**: ≤10% of family connections experience a lost-traffic event >30 seconds.

PASS = all four PASS in synthetic. Pilot validates the same operationally (with N=25 instead of 100).

## 7. Build matrix at FRP-11 exit

```
$ cd publisher && go build ./cell/... && go test ./cell/...      # ≥25 publisher-side tests (under daal/publisher module)
$ cd bundle/go && go build ./bundle/... && go test ./bundle/... -run 'CellAggregate'  # ≥10 bundle-local cell-aggregate tests
$ cd core && go build ./trust/... && go test ./trust/... -run 'CellVerify'  # ≥15 recipient-side chain-walk tests
$ ls core/trust/cell_verify.go publisher/cell/ bundle/go/bundle/cellcanon.go  # all present
$ # Module-boundary guard: no core/ import inside bundle/go/bundle/
$ ! rg -n 'daal/core' bundle/go/bundle/                         # MUST exit non-zero (no match)
$ # Asymmetric publisher dependency: no publisher import inside bundle/ or core/
$ ! rg -n 'daal/publisher' bundle/go/                           # MUST exit non-zero
$ ! rg -n 'daal/publisher' core/                                # MUST exit non-zero
$ # Reverse direction is allowed:
$ rg -n 'daal/bundle-go' core/                                  # at least one hit (cell_verify.go imports the bundle module)
$ cd client-desktop/tauri/src-tauri && cargo test
$ cd client-desktop/tauri && pnpm test
$ soak-driver run --scenarios v2-cell-superset --duration 14d   # ≥10 PASS
$ soak-driver run --scenarios v1-5-superset                      # 6 PASS
$ soak-driver run --scenarios v1-6-superset                      # 7 PASS
$ soak-driver run --scenarios v2-superset                        # 26 PASS
$ soak-driver run --scenarios v3-superset                        # 31 PASS
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l           # 48 (UNCHANGED)
$ grep -E '^const Version' core/abi/abi.go                       # daal-core 0.9.0+v3-share (UNCHANGED)
$ ls specs/cell-v1.md specs/cell-closure-v1.md                  # both exist
```

## 8. Spec deliverables

**3 NEW:**
- `specs/cell-v1.md` — M-of-N independent Ed25519 admin-quorum scheme over the membership doc, admin-quorum-signed delegation grant of bundle-signer authority, aggregated-RelayPack profile, full verification chain (admin-quorum → membership → delegation → bundle-signer → inner-publisher).
- `specs/cell-closure-v1.md` — cell soak closure record (mirror of `specs/v1-6-closure-v1.md`). **Required by FRP-13.**
- `specs/federation-primitives-v1.md` — names the cross-cell primitives the cell substrate exposes (cell-doc fetch shape, membership-doc canonicalisation, delegation-doc canonicalisation, abuse-hook surfaces, freshness/revocation hooks for cell scope). Per supplement §17.1 / §21.4 V2 deliverable list.

**1 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"Cell-aggregated profile" section.

**0 ENGINE CHANGES:**
- `core/abi/abi.go` — UNCHANGED; engine `Version` constant stays `daal-core 0.9.0+v3-share` (per FRP-track invariant).

## 9. Out of scope (deferred)

- Public directory aggregating cells — **FRP-13** (and gated by `specs/cell-closure-v1.md` SHIPPED).
- Cross-cell delegation (cells sharing capacity with other cells) — V3 candidate; explicitly not in V2.
- Cell-aware modifier opt-in — **FRP-12.**
- Mobile cell-management UI — sibling V2 deliverable, not a phase here.

## 10. Handover requirements

Status, new file paths under `publisher/cell/` (publisher-side primitives) AND `core/trust/cell_verify.go` (recipient-side verification chain) AND any extracted shared canonicalisation at `bundle/go/bundle/cellcanon.go`, M-of-N independent-Ed25519 admin signature test result (including: under-quorum reject; expired doc reject; admin-not-in-set reject), full chain-walk test result on the recipient side (admin-quorum → membership validity → delegation → bundle-signer → per-route provenance membership), aggregated-RelayPack round-trip test result, delegation-doc verification result, synthetic 100-FRP soak ledger, 25-FRP pilot summary, V2 success metric four-line PASS/FAIL table, `nm`=48, engine `Version` constant value (must read `daal-core 0.9.0+v3-share` — UNCHANGED), `specs/cell-closure-v1.md` attached, FRP-12 gate verdict, FRP-13 unblock confirmation (subject to §17.2).

## 11. Track ordering rationale

FRP-11 is the gate phase for FRP-13 (public directory). Putting cells before modifiers (FRP-12) means the cell-closure record can ship without modifier-related complications, and FRP-13 has its sole prerequisite (`cell-closure-v1.md` SHIPPED) settled at the natural breakpoint.

End — locked. Next: FRP-12 (modifier framework).
