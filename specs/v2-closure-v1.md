
> **Status: HOLD — FRP-10 alpha pilot pending.**
>
> This spec is the formal closure record for the **V2** milestone
> of the Daal anti-censorship project. The engineering surface
> is SHIPPED at FRP-10 (the engineering series that lands the
> cloud-provider firewall mgmt API across Hetzner + Vultr +
> Stark, the in-box `daal-relay-mgmt` service, the V2 cloud-init
> template, the Helper-side TLS-pinned mgmt client, the V007
> desktop wizard schema migration, and an Android publisher
> wizard at FRP-5 parity).
>
> **Engineering-shipped ≠ closure-shipped.** The closure record
> is gated on a real V2 alpha-pilot run per the supplement
> §9.5.5 + §21.3 success metrics — engineering completion of
> FRP-10 is the precondition for opening the live V2 alpha
> pilot, not the closure event itself. The project lead flips
> this status to SHIPPED by appending a `## Closure run
> YYYY-MM-DD` section once the V2 alpha-pilot evidence template
> aggregate roll-up returns 2/2 (or per the rules below) on
> every success-metric row. Until then this spec describes the
> gate.

V2 is the **multi-provider + cloud-firewall mgmt-plane**
milestone. A diaspora operator can now provision an FRP relay at
Hetzner, Vultr, or Stark; rotate L1 (credentials) in ~5 s and L2
(TLS) in ~20 s without rebuilding the box; trust the in-box mgmt
service via a fingerprint pinned at provision time; and drive
provisioning from a phone (Android publisher wizard) when a
desktop is unavailable, while keeping rotations on a desktop
where the long-lived mgmt-token-signing key lives.

## Closure criteria

V2 closes when **all** of the following hold on a single real
alpha-pilot run with two FRPs across at least two of the three
providers over a 14-day window:

1. **Primary metric (V2-P1) green — multi-provider provision.**
   For 2 of 2 alpha-pilot FRPs at least one fully-functional
   `cdn_fronted` or `direct_vps` RelayPack is provisioned at a
   non-Hetzner provider (Vultr or Stark), reaches
   `engine_diagnostics_explain.posture == "connected"` from a
   designated Iranian recipient within 60 s of QR scan, on first
   attempt. The `OperatorRecord.Provider` field for the
   originating box is `vultr` or `stark`.

2. **Primary metric (V2-P2) green — V2 fast-path rotation.**
   At least 1 of the 2 FRPs successfully drives an L1
   credential rotation through the V2 mgmt-plane (not redeploy)
   with end-to-end wall-clock ≤ 20 s, including ephemeral-
   firewall-rule open + TLS-pinned call + sing-box reload + new
   credentials confirmed live by the recipient. Evidence:
   `OperatorRecord.MgmtPort != 0`, post-rotation
   `signed_sbps.rotation_kind = direct_l1`, recipient log shows
   the new VLESS UUID applied within the L1 wall-clock budget.

3. **Primary metric (V2-P3) green — Android provision.**
   At least 1 of the 2 FRPs successfully provisions a relay
   from the Android publisher wizard (no desktop touched
   between phone-side `runProvision` and the family scanning
   the QR), with the resulting RelayPack reaching `connected`
   on a designated recipient. The Android-no-rotate boundary
   (FRP-10 invariant 30) is observed: any post-provision
   rotations on the same operator record are driven from a
   desktop wizard.

4. **Secondary metric (V2-S1) green — fingerprint pin holds.**
   Across the 14-day window every L1/L2 mgmt-plane call
   succeeds against the per-deploy fingerprint pinned at
   provision time. Zero `ErrFingerprintMismatch` instances
   logged. (A single legitimate L2 cert-rotation re-pin after
   the operator explicitly rotated TLS does not count.)

5. **Secondary metric (V2-S2) green — cloud-firewall hygiene.**
   Across the 14-day window every L1/L2 call follows the
   `Provider.SetEphemeralFirewallRule` →
   `RemoveEphemeralFirewallRule` sequence, with no rule
   surviving > 600 s after its corresponding mgmt call (cloud-
   provider auto-expiry plus Helper-side `defer` cleanup both
   active).

6. **Locked invariants 26–30 unchanged.** No supplement
   amendment between FRP-10 ship and the closure run inverts
   any of the five FRP-10 invariants (mgmt TLS pinned per
   deploy; mgmt port random per deploy; ephemeral FW
   `(port, IP)` tuple full key; mgmt API exactly three routes;
   Android wizard no rotation surface). Verified by re-running
   the FRP-10 invariant-pin tests at closure.

7. **No post-FRP-10 hardening regression.** The FRP-10 test
   surface — `cmd/daal-relay-mgmt` (11), `publisher/deploy/mgmt`
   (12), `publisher/deploy/cloudinit` V2 template (+6),
   `publisher/deploy/provider` (+6), `providers/hetzner` (+4),
   `providers/vultr` (13), `providers/stark` (12),
   `client-desktop/daal-wizard` (89 = 82 V1.6 baseline + 7
   V007), `client-android/app` `:testDebugUnitTest` (34) — runs
   green at the closure-run head commit.

## Pilot evidence template

A V2 alpha-pilot evidence template (`docs/pilot/v2-pilot-template.md`)
is added at FRP-10 commit 10 alongside the existing
`docs/pilot/frp-9-pilot-template.md`. The template captures, per
FRP, per provider:

* OperatorRecord JSON (sanitized — public_ip and provider only)
* MgmtPort + MgmtTLSFingerprint at provision time
* Wall-clock measurement of every L1 / L2 / L3 / L4–L6 rotation
  attempted during the window
* Recipient-side `engine_diagnostics_explain` JSON dumps at
  pre-rotation, immediately-post-rotation, and 24 hours
  post-rotation
* Cloud-firewall audit log dump (provider-native) covering the
  window — used to verify rule-lifecycle hygiene per V2-S2

The template is filled by the FRP and reviewed by the project
lead; the aggregate roll-up determines closure pass/fail.

## Carry-overs

The following gate the V2 alpha pilot but are not blockers for
the engineering ship:

* **Live govultr/v3 SDK wiring.** FRP-10 ships the Vultr
  adapter against an injected client interface so unit tests
  run without an account; the live wiring lands at the start of
  the alpha pilot.
* **Live Stark API testing.** Same shape as Vultr — the FRP-10
  adapter compiles + tests against a mock REST client; live
  testing requires a Stark account.
* **AndroidKeystorePublisherKey + Deploy.aar.** Production
  Android wiring requires the gomobile cross-compile toolchain
  to land. The FRP-10 stub (`InMemoryPublisherKey` +
  `DeployBridgeStub`) carries the Kotlin contract; the AAR ship
  is part of the alpha-pilot prep.
* **FA copy native review.** ~36 new desktop V2 i18n strings
  + ~100 Android wizard strings (when the Android UI ships its
  i18n) need a native FA-speaker review pass before the V2
  alpha pilot is offered to FRPs whose families are FA-first.

## Engine line check at closure

* **Version constant:** `daal-core 0.9.0+v3-share` — UNCHANGED.
* **ABI count:** 48 — UNCHANGED. (V2 adds no engine-side ABI
  surface; the mgmt-plane is a Helper ↔ box wire protocol that
  never reaches the engine.)
* **`spec_version`:** UNCHANGED beyond V1.5's. (No new RelayPack
  schema fields, no new SBP shape; V007 is wizard-database-only.)
