# FRP-14 handover — Pack-to-Person (per-recipient credentials + `.sbpx`)

**Status:** SHIPPED (code in the v0.1.0 line; this handover written retroactively on 2026-08-14 during the Phase 45 session — FRP-14 ended without one, and `development-phases/44-phase-frp-14-pack-to-person.md` §exit-checklist still shows it owed).
**Position:** outside the FRP-track terminator (the track formally ends at FRP-13); FRP-14 ran as a post-track follow-on, then fed directly into Phase 45.
**Predecessor:** FRP-13 (gate framework, HOLD). **Successor:** Phase 45 — data plane (`45-gap-dataplane-and-delivery.md`).

Everything below is verified against the tree at commit `54abbf4`; deviations from the phase doc are called out rather than papered over.

## 1. What landed (verified on disk)

**Specs (all five NEW, locked):** `specs/recipient-address-v1.md`, `specs/sbpx-envelope-v1.md`, `specs/per-recipient-credentials-v1.md`, `specs/recipient-identity-v1.md`, `specs/sbpx-import-v1.md`. Updated: `specs/daal-relay-mgmt-v1.md` (3→6 routes, `TestExactlyNRoutes` n=6 pinned at line 47), `specs/relaypack-v1.md` (`bundle.recipient_fp_hex`, RP024 `ErrRecipientMismatch`).

**Code:**

- `core/recipient/address/` — bech32m `daal1…` codec + tests (green).
- `client-shell/tauri/daal-recipient-addr/` — Rust mirror (tests inline in `src/lib.rs`).
- `bundle/go/envelope/` — age v1 wrapper; magic `DSBP\x00\x01` pinned; sniffer rejects `\x00\x02`. Cross-binding covered by `bundle/go/bundle/frp14_recipient_test.go`.
- `cmd/daal-relay-mgmt/` — the three `/users/*` routes (main.go:197-199), surgical users-rewriter (`singbox_users.go`), SIGUSR2 kick wrapper (main.go:159-177), `TestExactlyNRoutes` n=6. Suite green.
- `publisher/deploy/mgmt/users.go` — `ProvisionUser` / `RevokeUser` / `ListUsers` + tests.
- `publisher/deploy/cloudinit/v2.yaml.tmpl` — empty `users:` at boot (line 27), kick-wrapper drop-in (line 58).
- Wizard: `daal-wizard/src/{recipient_book,recipient_identity,recipient_sbpx}.rs` (`is_sbpx`, `sniff_file`, `import_sbpx`, `sweep_stale`).
- UI: Step-7 roster load (`client-ui/src/publisher/PublisherWizard.tsx:368`), standalone `PublisherRecipientsPage.tsx` (provision/revoke/resend), `.sbpx` import branch (`client-ui/src/components/AddEntryModal.tsx:38-62` magic sniff → PIN → age-open), `client-ui/src/recipient/RecipientImport.tsx` + first-launch identity flow.

## 2. Deviations from the phase doc

1. **Migration numbering.** Plan said `V015__recipient_book.sql`; reality is `daal-wizard/migrations/V009__recipient_book.sql` + `V010__recipient_identity.sql` + `V011__recipient_identity_history.sql` (V011 is the head; V015 exists nowhere). The plan's number assumed migrations that never happened.
2. **Command names.** Shipped Tauri commands are `wizard_recipient_provision` / `wizard_recipient_revoke` / `wizard_recipient_list` / `wizard_recipient_list_remote` (see `client-ui/src/publisher/wizardCommands.ts:367-395`), not the planned `recipient_add`/`recipient_revoke`/`recipient_resend`/`recipient_list`. There is **no** `address_book_list`; resend is `Wizard.shareInviteSbpx` (wizardCommands.ts:169).
3. **No `mission/` CI rigs.** None of `mission/frp-14-{address-cross-impl,revoke-soak,e2e-android,e2e-linux}.sh` exist. The E2E claims rest on the manual device session recorded in Phase 45's preamble (Samsung One UI 16, webview flow checks), not on repeatable scripts. This is the biggest gap between plan and tree.
4. **`specs/v2-closure-v1.md` was never updated** — the V2-blocker vs V2.1-deferral decision (phase doc exit item) is unrecorded.
5. **RP024 was double-assigned** in `specs/relaypack-v1.md`: recipient mismatch and the FRP-8 CDN-front warning (which owns the number in `relaypackvalidate/codes.go`) shared the code. Resolved 2026-08-14: recipient mismatch renumbered to RP025, reserved in the codebook.
6. **Farsi i18n incomplete.** `client-ui/src/i18n/en.json` and `client-shared/i18n/d2-extra.{en,fa}.json` carry the recipient strings, but `desktop.*`/`mobile.*` have none and `onboarding.fa.json` recipient values are empty — consistent with the D-2 "FA is DRAFT / release veto" caveat.

## 3. Known-red at handover time

- `go test ./...` in `bundle/go` fails on `TestDeterministicBuildIsByteIdentical` + `TestSubkeySignedSampleArtefact` ("verify: bundle expired") — expired sample fixtures, same failure class as the trust rotation fixtures that broke 2026-06-05 (fixed in `core` by anchoring to fixture time, commit `52afc55`). The bundle-go twins still need the same treatment or regenerated samples.
- Phase 45's preamble credits FRP-14 with "gap 5 — posture FSM tightening"; posture logic lives in `core/pathmanager/posture.go`, but no artifact in the tree distinguishes the claimed tightening from FRP-3-era code. Treat that claim as unverified.

## 4. What FRP-14 unblocks

- Phase 45 (data plane) — consumed the per-recipient `.sbpx` flow as its import path; ACTIVE.
- FRP-11 cell aggregation — the `.sbpx` envelope wire format is forward-compatible with one-envelope-N-recipients (`specs/cell-v1.md`).
- Recipient-address rotation UX — deferred post-V2 (carry-over §98-103 of the phase doc still accurate).

## 5. Follow-ups, in priority order

1. Regenerate or time-anchor the expired `bundle/go` sample fixtures (red suite).
2. Record the FRP-14 decision in `specs/v2-closure-v1.md` (V2 blocker vs V2.1 deferral).
3. ~~Renumber the duplicated RP024~~ — done 2026-08-14 (RP025).
4. Script the E2E flows the plan promised (`mission/frp-14-*.sh`) or explicitly waive them in the phase doc.
5. Complete the FA recipient strings before any release that unveils the recipient UI (D-2 release veto applies).
