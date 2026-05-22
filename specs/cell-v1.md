# Cell v1 (FRP-11)

**Status**: locked at FRP-11. Append-only thereafter.
**Engine version**: `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI release surface**: 48 UNCHANGED.
**Spec version**: 4 UNCHANGED (cell aggregation reuses the FRP-7.5 manifest contract; new files only — `trust/cell-membership.json` and `trust/cell-delegation.json`; per-route provenance is embedded inside the signed `_relaypack` object).

## 1 Goals

A trusted cell is a bounded group of FRPs (3–25 helpers) who mutually share spare RelayPack capacity. Cells let small groups of helpers operate as one logical FRP without a public directory and without a project-operated root, while preserving the V1.5/V1.6 trust ladder.

The cell-v1 contract:

1. Defines the M-of-N independent-Ed25519 admin scheme.
2. Defines the membership document, the delegation grant, and the cell-aggregated `.sbp` shape.
3. Defines the recipient-side chain walk.
4. Locks the abuse-ticket and cell-internal revocation primitives.

## 2 Locked invariants

| # | Invariant |
|---|---|
| 31 | Cell admin scheme is M-of-N independent Ed25519. NO threshold cryptosystem. N ∈ [1, 25]; M ≤ N. Default M = ⌈(N+1)/2⌉. |
| 32 | `spec_version` UNCHANGED at 4. Cell aggregation reuses the FRP-7.5 manifest contract via two new bundle files. |
| 33 | `bundle/go/bundle/` MUST NOT import `daal/core`. Recipient-side chain walk lives at `core/trust/cell_verify.go`. |
| 34 | No public directory. Per-cell directories only; FRP-13 gate. |
| 35 | No new `engine_*` C-shared symbols. ABI count stays 48. |
| 36 | Android cell-admin signing absent. Source-grep guard at `client-android/app/src/test/java/.../publisher/CellGuardTest.kt`. |

## 3 Wire format

### 3.1 `trust/cell-membership.json`

```jsonc
{
  "cell_id": "moms-extended-family-may-2026",
  "admin_pubkeys": ["<base64-rawstd-32B>", ...],
  "quorum_m": 2,
  "members": [
    {"publisher_fp_hex": "9f3a", "subkey_fp_hex": "1c2b", "joined_at_unix": 1735689600}
  ],
  "rule_set": {
    "cell_max_depth": 1,
    "abuse_route": "cell-internal",
    "valid_until_unix": 1767225600
  },
  "admin_signatures": [
    {"admin_pubkey_idx": 0, "signature_b64": "<base64>"},
    {"admin_pubkey_idx": 2, "signature_b64": "<base64>"}
  ]
}
```

The admin-quorum signature covers `canonical({"cell_id","admin_pubkeys","quorum_m","members","rule_set"})` — the document with the `admin_signatures` field stripped (a signature cannot cover itself).

### 3.2 `trust/cell-delegation.json`

```jsonc
{
  "cell_id": "moms-extended-family-may-2026",
  "bundle_signer_pubkey": "<base64-rawstd-32B>",
  "valid_from_unix": 1735689600,
  "valid_until_unix": 1767225600,
  "admin_signatures": [...]
}
```

The admin-quorum signature covers `canonical({"cell_id","bundle_signer_pubkey","valid_from_unix","valid_until_unix"})`.

### 3.3 Cell-aggregated `.sbp` archive layout

```
.sbp/
├── manifest.json                     # SpecVersion=4 unchanged; Publisher.KeyFingerprintHex = bundle-signer fp
├── manifest.sig                      # Ed25519 over canonical(manifest) by bundle-signer key
├── publisher.pub                     # bundle-signer pubkey
├── trust/cell-membership.json
├── trust/cell-delegation.json
└── profiles/...                      # profile files for cell-aggregated routes
```

`bundle.VerifyBundle` is UNCHANGED. The bundle-signer signature is what core/import keys off; the cell trust chain walks AFTER VerifyBundle returns nil.

Every cell-aggregated route MUST carry `_relaypack._inner_provenance` inside its signed `family_specific_config`:

```jsonc
{
  "_relaypack": {
    "exposure_mode": "direct_vps",
    "family_class": "vps-native",
    "probing_risk_class": "low",
    "public_risk_tags": ["public_ip:5.75.x.x"],
    "origin_risk_tags": [],
    "_inner_provenance": {
      "publisher_fp_hex": "9f3a",
      "subkey_fp_hex": "1c2b",
      "proof_b64": ""
    }
  }
}
```

`publisher_fp_hex` + `subkey_fp_hex` MUST exactly match one `members[]` entry in `trust/cell-membership.json`. `proof_b64` is reserved opaque metadata at FRP-11; the enforced contract is membership linkage plus the outer delegated bundle signature.

### 3.4 Cell-internal revocation document

```jsonc
{
  "cell_id": "...",
  "revoked_publisher_fp_hex": "...",
  "reason": "...",
  "issued_at_unix": 1735690000,
  "admin_signatures": [...]
}
```

The admin-quorum signature covers `canonical({"cell_id","revoked_publisher_fp_hex","reason","issued_at_unix"})`. M-of-N independent Ed25519 signatures from the same admin pubkey set as the parent membership doc.

### 3.5 Abuse ticket

```jsonc
{
  "cell_id": "...",
  "reporter_publisher_fp_hex": "...",
  "revoked_publisher_fp_hex": "...",
  "reason": "...",
  "observed_at_unix": 1735690000,
  "reporter_signature_b64": "<base64>"
}
```

Signed by the REPORTER's publisher key (NOT a cell admin key). Cell admins decide whether to escalate the ticket into a cell-internal revocation.

### 3.6 `.cell-join` envelope

```jsonc
{
  "cell_id": "...",
  "membership_doc": { /* trust/cell-membership.json shape */ },
  "current_directory_url": "https://r2.example.com/cell/<id>/directory.json",
  "trust_label_hint": "family"
}
```

## 4 Recipient-side chain walk

`core/trust/cell_verify.go::VerifyCellChain(b, now)` walks:

```
admin-quorum (M-of-N) ──signs──▶ membership doc
       │
       ▼
admin-quorum (M-of-N) ──signs──▶ delegation grant
       │
       ▼
delegation.bundle_signer_pubkey ──must equal──▶ archive publisher.pub bytes
       │
       ▼
manifest.sig (already verified by bundle.VerifyBundle)
       │
       ▼
per-route _relaypack._inner_provenance names a membership member
```

A non-cell bundle returns `ErrCellChainNotPresent`; the caller falls through to the standard publisher TOFU prompt.

## 5 Trust label store

`core/trust/labels.go::MemoryLabelStore`. Engine-side, encrypted at rest with AES-GCM (32-byte key, AEAD AD = `cellIDFPHex`). Never serialised into bundles, diagnostics, or cell-side directory documents.

## 6 Operational shape

The desktop wizard at FRP-11 commit 8 ships:

* V008 SQL migration (`cells` / `operator_cell_membership` / `cell_revocations`).
* `OperatorDb::insert_cell` / `lookup_cell` / `list_cells` /
  `link_operator_to_cell` / `record_cell_revocation`.
* ~50 EN + ~50 FA i18n strings under `wizard.cells.*`.

The Android publisher at FRP-11 commit 9 ships **cell-join only** per locked answer #2 + invariant 36. Forbidden tokens (`SignMembership`, `SignDelegation`, `SignRevocation`, `SignAbuseTicket`, `MintAdminToken`, `core/trust/cell_admin`, `publisher/cell/admin`) are pinned absent by `CellGuardTest`.

## 7 Closed errors (locked at FRP-11)

Bundle-side, in `bundle/go/bundle/errors.go`:

```
ErrCellMembershipMalformed
ErrCellDelegationMalformed
ErrCellAdminPubkeyMalformed
ErrCellQuorumOutOfRange
ErrCellAdminSignatureMalformed
ErrCellAdminQuorumNotMet
ErrCellAdminQuorumDuplicateIdx
ErrCellDelegationCellIDMismatch
ErrCellDelegationOutOfWindow
```

Recipient-side, in `core/trust/cell_verify.go` + `core/trust/cell_revocation.go`:

```
ErrCellChainNotPresent
ErrCellChainBundleSignerMismatch
ErrCellChainDelegationOutOfWindow
ErrCellChainMembershipExpired
ErrCellChainInnerProvenanceMissing
ErrCellChainInnerPublisherNotMember
ErrCellRevocationDocMalformed
ErrCellRevocationCellIDMismatch
ErrCellRevocationQuorumNotMet
```

Publisher-side, in `publisher/cell/cell.go` + `publisher/cell/abuse.go`:

```
ErrAdminCountOutOfRange
ErrQuorumOutOfRange
ErrAdminKeyMismatch
ErrInsufficientQuorum
ErrAdminKeyAlreadyPresent
ErrAggregateNoMembers
ErrAggregateCellIDMismatch
ErrAggregateMissingProfile
ErrAggregateMissingRelayPack
ErrAggregateInnerPublisherNotMember
ErrAggregateMembershipExpired
ErrAggregateBundleSignerExpired
ErrAbuseTicketUnsigned
ErrAbuseTicketEmpty
ErrRevocationDocUnsigned
ErrRevocationDocEmpty
```

End — locked at FRP-11.
