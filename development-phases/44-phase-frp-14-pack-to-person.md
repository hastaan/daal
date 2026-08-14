# Phase FRP-14 — Pack-to-Person: per-recipient credentials + encrypted relay packs

**Status:** SHIPPED (code in the v0.1.0 line; retroactive handover `docs/handovers/frp-14-handover.md`, written 2026-08-14, records the deviations from this plan). Slots after FRP-10 (`40-phase-frp-10-v2-multi-provider.md`) and before FRP-11 (`41-phase-frp-11-trusted-cells.md`). **Branch:** `frp-14-pack-to-person`. **Codename:** `pack-to-person`.

## Premise

Pre-FRP-14, a Daal relay shipped a single set of sing-box credentials baked into the box. Every recipient who held the `.sbp` used the same UUID/short_id/password. This had two consequences:

1. **No per-recipient revocation.** Removing one person from the relay required rotating credentials for everyone (FRP-10 L1).
2. **No envelope confidentiality.** A `.sbp` leaking in transit leaked the server's IP, the SNI, and the credentials, with no recovery short of rotating everything plus a new IP.

FRP-14 splits the recipient table from the data-plane config, exposes a small CRUD over the FRP-10 mgmt-plane, and adds an age-based encryption envelope (`.sbpx`) bound to each recipient's X25519 identity. The wizard's Step 7 is reshaped from a one-shot "share" into a persistent recipient-management screen.

## Invariants (locked at the end of FRP-14)

1. `daal-relay-mgmt` exposes **exactly six routes** — the original three (`/rotate-credentials`, `/rotate-tls`, `/health`) plus three per-recipient routes (`/users/provision`, `/users/revoke`, `/users/list`). Pinned by `TestExactlyNRoutes` with `n=6`.
2. **Per-recipient credentials are independent.** Adding or revoking recipient X never modifies the on-box credentials of recipient Y. Pinned by `TestUsersProvisionIsolated` + `TestUsersRevokeIsolated`.
3. **Recipient name is stable.** `r<recipient_id>` is generated once from the wizard DB's autoincrement PK and never re-used. Pinned by the DB schema (`recipients.id` is `AUTOINCREMENT`, not `INTEGER PRIMARY KEY` alone, so SQLite never recycles).
4. **Hard revoke is effective within ≤ 10 s.** Per-user revoke kicks live sing-box sessions via the SIGUSR2 + reload wrapper. Pinned by the FRP-14 integration soak (`mission/frp-14-revoke-soak.sh`).
5. **Empty user table at first boot.** The V2 cloud-init template emits sing-box with zero users; the server is dormant until the first `users/provision` call. Pinned by `TestRenderV2_EmptyUsers`.
6. **Per-recipient credentials never appear in clear in the inner `.sbp` manifest.** They live only in the per-recipient `profiles/*.json` sing-box configs and in the encrypted `.sbpx` envelope. Pinned by `TestManifestNoCreds`.
7. **Per-server WS-inbound count cap.** Hard cap 128 per server (sing-box config size + reload time). Warning at 32. Pinned by `TestUsersProvisionCapEnforced`.
8. **`.sbpx` magic prefix is `DSBP\x00\x01`.** Pinned by `TestSniffMagic` in `bundle/go/envelope`.
9. **Recipient identity X25519 keypair is generated at first launch of the recipient app and sealed under PIN.** Pinned by `TestRecipientFirstLaunchIdentity`.
10. **`bundle.recipient_fp_hex` cross-binds each `.sbpx` to a single recipient.** Mismatch returns `ErrRecipientMismatch` (RP024). Pinned by recipient-app import test.
11. **The branded address format `daal1...` is bech32m with HRP=`daal`, 62 chars.** Pinned by the cross-impl golden vectors.
12. **V1.6 publisher app produces only `.sbpx`.** No code path emits a bare `.sbp`. Pinned by a grep-style test (`TestNoSbpEmissionInPublisherCode`).

## Deliverables

### Spec docs

- NEW `specs/recipient-address-v1.md` (locked)
- NEW `specs/sbpx-envelope-v1.md` (locked)
- NEW `specs/per-recipient-credentials-v1.md` (locked)
- NEW `specs/recipient-identity-v1.md` (locked — Layer 3c)
- NEW `specs/sbpx-import-v1.md` (locked — Layer 3d)
- UPDATE `specs/daal-relay-mgmt-v1.md` (3→6 routes; new ops in token-binding)
- UPDATE `specs/relaypack-v1.md` (`bundle.recipient_fp_hex`; RP024)
- UPDATE `specs/v2-closure-v1.md` (note FRP-14 as V2 dependency or V2.1 deferral)

### Code packages

- NEW Go package `core/recipient/address/` — bech32m daal1... codec.
- NEW Rust crate `client-shell/tauri/daal-recipient-addr/` — mirror.
- NEW Go package `bundle/go/envelope/` — age v1 wrapper + magic prefix.
- UPDATE Go package `bundle/go/bundle/` — add `Manifest.Bundle.RecipientFPHex`; extend `VerifyBundle`.
- UPDATE `cmd/daal-relay-mgmt/` — three new routes; surgical users-rewriter; SIGUSR2 kick wrapper; exactly-six-route invariant test.
- UPDATE `publisher/deploy/mgmt/` — three new client methods.
- UPDATE `publisher/deploy/cloudinit/v2.yaml.tmpl` — sing-box ≥ v1.10; kick wrapper drop-in; empty users[] at boot.
- NEW wizard migration `V015__recipient_book.sql`.
- NEW Rust commands in `client-shell/tauri/daal-wizard/src/commands.rs`: `recipient_add`, `recipient_revoke`, `recipient_resend`, `recipient_list`, `address_book_list`.
- NEW recipient-app first-launch identity flow + "My Daal address" screen.
- UPDATE recipient-app import path: detect `.sbpx` magic, decrypt, then existing parser.
- REBUILD publisher UI Step 7: RecipMgmt screen + Add/Revoke/Resend sheets.
- UPDATE i18n keys (en + fa).

### CI gates

- `mission/frp-14-address-cross-impl.sh` — Go encode → Rust decode and back; 1024 keys.
- `mission/frp-14-revoke-soak.sh` — provision two users; open long download; revoke A; assert socket close ≤ 10 s; assert B unaffected.
- `mission/frp-14-e2e-android.sh` — full Android flow: provision → add Mom → Mom imports `.sbpx` → connects → add Cousin → revoke Cousin → assert Mom still connected.
- `mission/frp-14-e2e-linux.sh` — same flow on Linux desktop.

## Implementation order

The implementation lands in three layers; each layer compiles + tests cleanly on its own before the next begins.

### Layer 1 — Foundation libraries (no on-box changes, no UI changes)

1. `core/recipient/address/` (Go) + golden vectors + tests.
2. `client-shell/tauri/daal-recipient-addr/` (Rust) + tests (loads same golden vectors).
3. `bundle/go/envelope/` (Go) + tests.
4. `bundle/go/bundle/`: add `Manifest.Bundle.RecipientFPHex`; extend `VerifyBundle`; tests.

Exit criteria: `go test ./...` and `cargo test -p daal-recipient-addr` both green. The publisher app and on-box service are unchanged at this point.

### Layer 2 — On-box service + Helper client

5. `cmd/daal-relay-mgmt/`: routes, kick wrapper, users-rewriter, golden config diffs, exactly-6-route test.
6. `publisher/deploy/mgmt/`: three new client methods + tests.
7. `publisher/deploy/cloudinit/v2.yaml.tmpl` + tests.

Exit criteria: `cmd/daal-relay-mgmt` test surface green; cloud-init render tests green; mgmt-plane integration test green against a mock provider.

### Layer 3 — Wizard + UI

8. Wizard migration V015 + `recipient_db.rs` + tests.
9. Rust wizard commands + tests.
10. Recipient app first-launch identity + "My Daal address" screen.
11. Recipient app `.sbpx` import branch + tests.
12. Publisher UI Step 7 rebuild + Add/Revoke/Resend sheets.
13. i18n keys (en + fa).
14. End-to-end mission runs on Android + Linux.

Exit criteria: all `mission/frp-14-*.sh` scripts pass on real hardware; one full Android + Linux dual-platform soak completes cleanly.

## Carry-overs

- **sing-box v1.10 verification.** Confirm SIGUSR2 graceful-drop behavior on the pinned sing-box version. Fallback: `systemctl restart sing-box` (1–2 s downtime for all users).
- **Address rotation UX.** A recipient who moves to a new device today cannot migrate their identity — they must re-add the new address with every publisher. Rotation UX is deferred to a post-V2 spec.
- **V1.5 → V1.6 migration banner.** Pre-FRP-14 operators in an existing wizard DB show a one-time banner explaining the new per-recipient model; the legacy single-tenant credentials remain on-box until the operator chooses to migrate. After 60 days the wizard nags.
- **Cell aggregation.** Sending one `.sbpx` decryptable by N recipients lives in FRP-11 (`specs/cell-v1.md`); the envelope wire format is forward-compatible.

## Phase exit checklist

- [ ] All spec docs landed and locked.
- [ ] All test files in the per-layer "exit criteria" pass.
- [ ] One Android E2E run shows: provision → add 2 recipients → both connect → revoke 1 → revoked disconnects in ≤ 10 s → other unaffected.
- [ ] One Linux E2E run with the same script.
- [ ] `specs/v2-closure-v1.md` updated (V2-blocker or V2.1 deferral decision recorded).
- [x] Handover doc written: `docs/handovers/frp-14-handover.md` (post-FRP-3 handovers live in `docs/handovers/`, not as `.handover.md` siblings; written retroactively 2026-08-14 — unticked items above are inventoried there as deviations/follow-ups).
