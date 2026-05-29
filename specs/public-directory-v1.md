# Public Directory v1 — protocol contract

**Status:** GATED.
**Implementation:** HOLD pending the §17.2 six conditions PASS *and* `specs/cell-closure-v1.md` SHIPPED. Both required.
**Engine `Version`:** `daal-core 0.9.0+v3-share` UNCHANGED at FRP-13. A future V3 ship is recorded in `specs/public-directory-closure-v1.md` and a packaging tag, NOT in the engine constant.
**Predecessor:** FRP-12 modifier framework (SHIPPED).
**Successor:** none on the FRP track. Post-track implementation if gate flips.

> This document is a **contract** — the canonical reference the post-track implementation phase must satisfy. It does NOT describe code that ships at FRP-13. FRP-13 ships only the gate-evaluation framework (`specs/public-directory-gate-v1.md` + `cmd/daal-gate-eval`). The Go package `publisher/directory/`, the wizard "opt-in to public directory" screen, and the recipient-side fallback wiring in `core/` are all post-track.

---

## 1. Scope

The public directory aggregates **opted-in trusted cells** (FRP-11) into a single signed registry that Iran-side recipients can query when:

- Tier-1 (family-only) RelayPacks are all in cooldown, AND
- Tier-2 (cell-aggregated) RelayPacks from cells the recipient already trusts are all in cooldown.

Per supplement §21.4: *"Iran-side fallback: when no Tier-1/Tier-2/cell routes are reachable, query the public directory."*

The directory is **recipient-pulled**. There is no project-side aggregation of recipient queries (locked invariant 50; Position B preserved at the directory layer).

## 2. Out of scope (permanent)

- Per-recipient identifiers in directory queries.
- Project-side query logging or aggregation.
- Publisher-driven push (cells push their own opt-in updates; the directory pulls; recipients pull from the directory).
- Cross-directory federation. There is exactly one project-controlled directory; cells choose to opt in or not.
- Project-operated relay infrastructure of any kind (carryover from §10 Position B).

## 3. Architectural shape

```
┌────────────┐   opt-in (signed by cell admin quorum)
│  Cell A    ├─────────────────────────────────┐
└────────────┘                                  ▼
┌────────────┐                          ┌──────────────┐
│  Cell B    ├─────────────────────────►│   Public     │
└────────────┘                          │  Directory   │
┌────────────┐                          │ (signed by   │
│  Cell C    ├─────────────────────────►│ project key) │
└────────────┘                          └──────┬───────┘
                                                │
                                                │ pull (recipient)
                                                ▼
                                        ┌──────────────┐
                                        │  Recipient   │
                                        │  (fallback)  │
                                        └──────────────┘
```

The directory is a single signed JSON document hosted on a project-controlled domain. Cells opt in by submitting a signed inclusion request; the project signs the inclusion. Recipients fetch the directory document, verify both signatures, then TOFU each new cell key (locked invariant 53).

## 4. Directory document shape

```jsonc
{
  "spec_version":         1,
  "directory_id":         "daal-public-directory",
  "issued_at":            "2026-MM-DDTHH:MM:SSZ",
  "valid_until":          "2026-MM-DDTHH:MM:SSZ",
  "transparency_log_url": "https://example/transparency-log/<entry-id>",
  "directory_pub":        "<base64 ed25519 pubkey>",
  "entries": [
    {
      "cell_id":            "moms-extended-family-may-2026",
      "cell_key_fp":        "9f3a...",
      "contact":            "<contact handle / opaque>",
      "abuse_handling_url": "https://...",
      "capacity_class":     "small | medium | large",
      "opt_in_signature":   "<base64 ed25519 signature by cell admin quorum>",
      "inclusion_signature":"<base64 ed25519 signature by directory key>",
      "added_at":           "2026-MM-DDTHH:MM:SSZ",
      "status":             "active | quarantined | removed"
    }
  ],
  "signatures": [
    { "kid": "directory-key-2026", "sig": "<base64 ed25519 over canonical doc bytes>" }
  ]
}
```

Canonicalisation rules MUST mirror the FRP-7.5 manifest contract (key ordering, no trailing whitespace, integer-only timestamps optional but recommended).

## 5. Trust chain (recipient-side)

Per locked invariant 53 — recipient TOFUs each new cell key.

```
1. Recipient fetches directory.json from <project-domain>/directory.json.
2. Recipient verifies directory.signatures against directory_pub.
3. Recipient verifies directory_pub against the project's public
   transparency log entry (locked invariant 51).
4. For each entry:
   a. Recipient verifies opt_in_signature against the entry's
      cell_key_fp (look up cell membership; admin quorum signs).
   b. Recipient verifies inclusion_signature against directory_pub.
5. Recipient TOFUs each cell key on first use (one-tap; surfaces the
   admin set + quorum to the user; mirrors FRP-6 publisher TOFU).
6. Recipient queries the cell directly (out-of-band of the public
   directory) to fetch the cell-aggregated RelayPack.
```

**Quarantine + removal.** An entry whose `status` is `quarantined` MUST NOT be used by recipients for new RelayPack discovery; existing TOFU-trusted relationships continue. An entry whose `status` is `removed` MUST be removed from the recipient's local cache within 24 hours of next directory fetch.

## 6. Directory key custody

Per locked invariant 51:

- Long-lived project-held Ed25519 key.
- Custody plan is part of the post-track implementation (NOT FRP-13).
- All signing operations MUST be recorded in a public transparency log (URL in the directory document's `transparency_log_url` field).
- The transparency-log URL is one of the gate-eval CLI's PASS checks (per `specs/public-directory-gate-v1.md`).

## 7. Recipient-side fallback (post-track wiring)

Per supplement §21.4. Pseudocode (architectural-only at FRP-13):

```
when selector exhausts Tier-1 + Tier-2 cell candidates:
  if directory.cached_recently_enough():
    pick a random `active` entry within the recipient's preferred
    capacity_class
    pull the cell's aggregated RelayPack via the cell directory URL
    on inclusion: TOFU the new cell key (one-tap)
  else:
    refetch directory; verify; cache; retry
```

**No automatic cell-key trust transfer** (locked invariant 53). Each new cell is a one-tap TOFU.

## 8. Opt-in flow (post-track wiring)

Cell admins, via a future wizard "Add my cell to public directory" screen at `client-desktop/tauri/src/cell/opt-in-public/`:

1. Construct an `opt_in_signature` over the canonical bytes of the entry minus `inclusion_signature` and `signatures`.
2. POST the signed entry to a project-controlled submission endpoint (rate-limited; over HTTPS only; opaque submission tokens).
3. Project reviews (manual at first; automated checks possible later).
4. Project signs the `inclusion_signature` and merges into the directory document.
5. Directory document is republished to the project-controlled domain; transparency-log entry recorded.
6. Cells can opt out at any time; the directory honours opt-out within 24 hours by setting `status: removed`.

## 9. Abuse handling

Per locked invariant 22 (FRP-13 carryover from phase-doc §3):

- Abuse complaints flagged in the directory itself.
- Cells with unhandled complaints are quarantined within 7 days.
- Complete removal within 30 days unless the cell resolves the complaint.
- Per-cell abuse-handling URL (`abuse_handling_url`) MUST be present.

## 10. Validator behaviour at recipient

The future `core/import/directory.go` (post-track) MUST:

- Reject directory documents whose `valid_until` is in the past.
- Reject directory documents whose `transparency_log_url` is empty.
- Reject directory entries whose `opt_in_signature` does not verify against the cell's published admin-quorum membership.
- Reject directory entries whose `inclusion_signature` does not verify against `directory_pub`.
- Surface quarantined entries to the recipient as an opt-out signal (do not auto-discover from a quarantined cell).

These checks are out of scope at FRP-13; documented here as the contract.

## 11. Locked invariants (mirror onto the global list)

The eight FRP-13 phase-specific invariants (48–55) are documented in:

- `phases of development/43-phase-frp-13-public-directory.md` §3.
- Supplement §17.6 (added at v2.3.12).
- This spec normatively binds the implementation phase to invariants 48, 50, 51, 52, 53.

## 12. Test vectors (forward-looking)

The post-track implementation phase must ship test vectors mirroring `specs/test-vectors/cell/`:

- One `directory.json` with one active entry.
- One with one quarantined entry.
- One with one removed entry.
- One with stale `valid_until` (must be rejected).
- One with bad `inclusion_signature` (must be rejected).
- One with empty `transparency_log_url` (must be rejected).

Five negative + one positive minimum.

## 13. Cross-references

- Supplement §17.1 / §17.2 / §17.3 / §17.6 — sequencing + gate.
- Supplement §21.4 — V3 phase placement.
- Supplement §22.4 — V3 success metric.
- `specs/cell-v1.md` — cell admin-quorum + membership doc shape (the `opt_in_signature` is constructed by the same admin set).
- `specs/cell-closure-v1.md` — separate prerequisite (HOLD; V2 cell alpha pilot).
- `specs/public-directory-gate-v1.md` — machine-readable §17.2 + §22.4 gate spec.
- `specs/public-directory-closure-v1.md` — V3 closure record (HOLD).
- `phases of development/43-phase-frp-13-public-directory.md` — the phase doc.

End — Status: GATED. Implementation: HOLD.
