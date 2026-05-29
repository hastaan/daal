# Phase 40 (FRP-10) — V2 Multi-Provider + Mgmt-Plane API

**Status:** SHIPPED 2026-05-04 (engineering surface; closure record HOLD per `specs/v2-closure-v1.md` pending live alpha pilot).
**Handover:** `docs/handovers/frp-10-handover.md` summarises the ten-commit series and the carry-overs.
**Roadmap line:** *"V2 — Trusted cells + federation primitives + multi-provider + mobile. Add Vultr and Stark Industries providers. V2 unlocks faster L1/L2 rotation by adding a persistent in-box management service guarded by the cloud-provider firewall."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.3 + §9.5.2
**Supplement landed:** v2.3.9 (one new subsection — §9.5.5 FRP-10 implementation lock for the V2 mgmt-plane).
**Engine `Version` target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — engine `Version` constant is not changed in this phase. The supplement holds it stable through this work; any future bump would require an explicit supplement amendment).**
**ABI release surface target:** **48** **(UNCHANGED — provider expansion is at publisher-side; engine ABI untouched).**
**Maturity:** code phase. Adds Vultr + Stark provider adapters and the V2 mgmt-plane API.
**Predecessor:** Phase 39 (FRP-9) — V1.6 closed.
**Successor:** Phase 41 (FRP-11) — Trusted cells; uses multi-provider as cell-diversity substrate.

## 1. Strategic frame (verbatim from the supplement)

> **§21.3 V2 scope.** Add Vultr and Stark Industries providers. Mobile (Android Compose) wizard. Trusted cells (§16). Federation primitives (§17.1). Default: cells only; no public directory. Cells operate over both `direct_vps` and `cdn_fronted` candidates from V1.6.
>
> **§9.5.2 V2 management plane.** `Provider.SetEphemeralFirewallRule(ctx, serverID, callerIP, port, durationSec)` is added to the `Provider` interface. Implementations exist for Hetzner (Cloud Firewalls API), Vultr (Firewall API), Stark (REST). The Helper calls this to allowlist its own outbound IP and the record's random management port for a 5-minute window before each L1/L2 operation. The provider auto-removes the rule at expiry; the Helper also explicitly removes it on completion.
>
> **§14.1 Direct-mode rotation ladder, V2 column.** L1 ~5 s, L2 ~20 s via in-box mgmt service. (Down from ~90 s redeploy at V1.5.)

FRP-10's job: add Vultr (`govultr/v3`) + Stark (REST) provider adapters; ship `daal-relay-mgmt` in-box management service; extend `Provider` with `SetEphemeralFirewallRule`; restore L1 5 s / L2 20 s wall-clock targets; **and ship the V2 mobile (Android Compose) FRP wizard at FRP-5 parity**. The Android wizard is owned by FRP-10 because it depends on the same `Provider` interface + multi-provider adapters FRP-10 ships; its production keystore/gomobile deploy binding remains an alpha-pilot carry-over, and Android explicitly does not ship rotation in this phase.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Vultr SDK | `govultr/v3` (per supplement §21.2 / §11.5). Pin discipline: latest stable v3.x in go.mod. |
| Stark SDK | None exists; wrap their REST API in ~150 lines at `publisher/deploy/providers/stark/`. |
| Provider package layout | `publisher/deploy/providers/{hetzner,vultr,stark}/` (per supplement §21.3 explicit plural-`providers` path). FRP-4a's existing `publisher/deploy/provider/hetzner/` is moved to `publisher/deploy/providers/hetzner/` at FRP-10 (path-only refactor: singular `provider/` → plural `providers/`). The `Provider` interface symbol stays at `publisher/deploy/provider/provider.go` (singular interface package; plural adapter package — distinct on purpose). |
| Mobile wizard | Android Compose at FRP-5 parity (provision + bind + QR; no rotate surface). Lives at `client-android/app/src/main/java/.../publisher/wizard/`. The live production `gomobile` deploy binding and AndroidKeystore publisher key are tracked as V2 alpha-pilot carry-overs. |
| Provider interface extension | `Provider.SetEphemeralFirewallRule(ctx, serverID, callerIP, port, durationSec) (*EphemeralFirewallRule, error)` (per supplement §9.5.2 + §9.5.5). All three adapters (Hetzner, Vultr, Stark) implement it. Cleanup: `RemoveEphemeralFirewallRule(ctx, rule)`. |
| Mgmt-plane service | New binary `daal-relay-mgmt` running on the origin box. Listens on the random per-deploy port stamped into `/etc/daal/mgmt/port`, constrained to `[10000, 65000]`; the cloud-provider firewall is the public gate. Surface: minimal — `POST /rotate-credentials` (L1), `POST /rotate-tls` (L2 data-plane TLS/SNI profile), `GET /health`. Authenticated by a per-deploy Ed25519 token issued by the wizard. |
| Bootstrap path | Helper requests `Provider.SetEphemeralFirewallRule` to open a 5-minute window from Helper's outbound IP; Helper hits the mgmt port; Helper closes the window. Box-side `ufw` is closed; cloud-provider firewall is the gate. |
| Why ABI=48 unchanged | All work is publisher-side; engine release surface unchanged. |
| Engine `Version` constant | UNCHANGED. Supplement holds it at `daal-core 0.9.0+v3-share`. V2 multi-provider is a packaging-tag milestone, not a `Version` constant change. |
| Backward compat | V1.6 boxes (no `daal-relay-mgmt`) keep working at L1/L2 redeploy timings. New deploys get the V2 timing boost; existing deploys get it only after L4 redeploy or explicit migration. |
| Telemetry | None. `daal-relay-mgmt` ships an `OPSecTest` similar to FRP-4a's. |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **No engine release symbols added.** ABI count stays 48.
18. **Cloud-provider firewall is the gate, not box-side `ufw`.** Box-side `ufw` is closed. Verified by an OPSEC test that a deployed mgmt port is unreachable without the cloud-provider firewall rule present.
19. **Per-deploy mgmt-plane Ed25519 token.** Token is generated at deploy time; signed by publisher key; embedded in OperatorRecord; transferred to box via cloud-init. Lost token = redeploy from scratch.
20. **`SetEphemeralFirewallRule` auto-expires.** Provider removes rule at `durationSec`; Helper still attempts explicit removal on completion as defensive cleanup.
21. **L1 and L2 wall-clock targets restored.** L1 ≤5 s, L2 ≤20 s when V2 mgmt-plane is reachable. Verified by a soak scenario.
22. **Mgmt-plane is narrow.** Only L1 and L2 operations supported. L3 (floating IP) goes through cloud-provider API directly per V1.5. L4/L5/L6 are still redeploy. No general-purpose RPC.
23. **Position B preserved.** Mgmt-plane never reports usage; just executes the operation and returns.
24. **Android publisher wizard ships as part of FRP-10.** Per supplement §21.3, the V2 mobile wizard ships at FRP-5 parity (provision + bind + QR only). Owned by FRP-10 (not split into a sibling sub-phase) because it depends on the same `Provider` interface + multi-provider adapters FRP-10 ships.
25. **Provider package layout: `publisher/deploy/providers/{hetzner,vultr,stark}/`** per supplement §21.3 explicit path; FRP-4a's existing `publisher/deploy/hetzner/` is moved (path-only refactor).

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-10 stub with this locked spec at `phases of development/40-phase-frp-10-v2-multi-provider.md`. |
| 1  | Read inputs end-to-end: supplement §9.5.2, §11.5 (Vultr), §11.6 (Stark), §14.1, §21.3; FRP-4a `Provider` interface; FRP-7 rotation executor. |
| 2  | Extend `Provider` interface in `publisher/deploy/provider/provider.go`: add `SetEphemeralFirewallRule` + `RemoveEphemeralFirewallRule`. |
| 3  | Move FRP-4a's Hetzner adapter from `publisher/deploy/provider/hetzner/` to `publisher/deploy/providers/hetzner/` (path-only refactor: singular → plural directory; symbol contract unchanged). Update all imports. |
| 4  | Author `publisher/deploy/providers/vultr/`: `provider.go`, `pricing.go`, `regions.go`. Implement the full `Provider` interface using `govultr/v3`. |
| 5  | Author `publisher/deploy/providers/stark/`: `provider.go`, `pricing.go`, `regions.go`, `client.go` (~150 line REST wrapper). Implement the full `Provider` interface. |
| 5b | Implement `SetEphemeralFirewallRule` on Hetzner adapter: use `hcloud-go.Firewall.SetRules` with a time-tagged rule. |
| 6  | Implement `SetEphemeralFirewallRule` on Vultr: use `govultr/v3.FirewallGroup` resource. |
| 7  | Implement `SetEphemeralFirewallRule` on Stark: use Stark REST `/firewall/rules` endpoints. |
| 8  | Author `cmd/daal-relay-mgmt/main.go` — the new in-box mgmt-plane service. Listens with a per-deploy self-signed leaf whose SHA-256 fingerprint is pinned into `OperatorRecord.MgmtTLSFingerprint`. |
| 9  | Author `publisher/deploy/cloudinit/v2.yaml.tmpl` — extends V1.5 template to install + start `daal-relay-mgmt` and configure cloud-provider firewall. Old template stays usable for V1.5 graphs. |
| 10 | Wire desktop wizard to surface provider choice (Hetzner default, Vultr / Stark advanced) at screen 1; surface "Enable V2 mgmt-plane" toggle on by default for new deploys. |
| 10b | **Author Android publisher wizard** at `client-android/app/src/main/java/.../publisher/wizard/`. Mirrors the FRP-5 desktop wizard flow at provision + bind + QR parity (Compose UI; same OperatorRecord JSON shape). AndroidKeystore publisher key and gomobile-bound live deploy are V2 alpha-pilot carry-overs. EN + FA. Per supplement §21.3 deliverable. |
| 11 | Author tests: ≥40 across `providers/{vultr,stark,hetzner}/`, `daal-relay-mgmt`, ephemeral firewall, L1 5s + L2 20s timing, Android wizard. Include OPSEC tests. |
| 12 | Final regression sweep: `cd publisher && go build ./... && go test ./deploy/providers/...`; `cd cmd/daal-relay-mgmt && go build ./... && go test ./...`; `cd cmd/daal-deploy && go build ./...`; `cd core && go build ./... && go test ./...`; `cd bundle/go && go build ./... && go test ./bundle/...` (regression-only); `cd client-android && ./gradlew test`; `nm` returns 48; v1-5-superset, v1-6-superset, v2-superset, v3-superset all PASS; FRP-11 gate verdict; handover. |

## 5. `Provider` interface extension (locked)

```go
package provider

type EphemeralFirewallRule struct {
    ID           string
    ServerID     string
    CallerIP     string
    Port         int
    ExpiresAt    time.Time
}

type Provider interface {
    // existing methods (FRP-4a) ...

    SetEphemeralFirewallRule(ctx context.Context, serverID, callerIP string, port int, durationSec int) (*EphemeralFirewallRule, error)
    RemoveEphemeralFirewallRule(ctx context.Context, rule *EphemeralFirewallRule) error
}
```

Hetzner / Vultr / Stark implement these atop their respective firewall APIs.

## 6. Mgmt-plane API (locked)

```
POST /rotate-credentials       — L1 (~5 s); regenerates VLESS UUID + REALITY private key; restarts sing-box; returns new credentials JSON.
POST /rotate-tls               — L2 (~20 s); rotates SNI / dest set; updates TLS config; restarts sing-box; returns new TLS profile.
GET  /health                   — liveness probe.
```

All state-changing endpoints require Ed25519 signature in `Authorization: Daal-Mgmt-Token <signed-blob>` header, verified against the per-deploy publisher public key written to `/etc/daal/mgmt/pubkey` by cloud-init. `GET /health` is unauthenticated but still reachable only while the cloud-provider firewall rule is open.

## 7. Build matrix at FRP-10 exit

```
$ cd publisher && go build ./deploy/providers/{hetzner,vultr,stark}/...   # green (under daal/publisher module)
$ cd publisher && go test  ./deploy/providers/{hetzner,vultr,stark}/...
$ cd cmd/daal-relay-mgmt && go build ./...                                # green (its own module)
$ cd cmd/daal-relay-mgmt && go test  ./...
$ cd client-android && ./gradlew test                              # Android publisher wizard tests
$ # Soak: L1 + L2 timing
$ soak-driver run --scenarios v2-l1-l2-fast-path                  # PASS (L1 ≤5s, L2 ≤20s)
$ soak-driver run --scenarios v2-superset                          # 26 PASS (existing)
$ soak-driver run --scenarios v1-5-superset                        # 6 PASS
$ soak-driver run --scenarios v1-6-superset                        # 7 PASS
$ soak-driver run --scenarios v3-superset                          # 31 PASS
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l             # 48 (UNCHANGED)
$ grep -E '^const Version' core/abi/abi.go                         # daal-core 0.9.0+v3-share (UNCHANGED)
```

## 8. Spec deliverables

**1 NEW:** `specs/daal-relay-mgmt-v1.md` — narrow API surface, auth, and operations.
**1 AMENDED:**
- `specs/relaypack-v1.md` — gains a §"V2 multi-provider" cross-reference.
- `core/abi/abi.go` — UNCHANGED; engine `Version` constant stays `daal-core 0.9.0+v3-share`.

## 9. Out of scope (deferred)

- Cell-aware mgmt-plane (peer FRP can rotate via cell key) — **FRP-11.**
- Linode adapter — V3 demand-driven.
- iOS publisher wizard — post-V3 per supplement §21.5.

## 10. Handover requirements

Status, new file paths under `publisher/deploy/providers/{hetzner,vultr,stark}/`, Provider interface diff, mgmt-plane API doc, ephemeral firewall test results, L1/L2 timing soak result, Android publisher wizard screenshots + EN/FA copy review, `nm`=48 unchanged, engine `Version` constant value (must read `daal-core 0.9.0+v3-share` — UNCHANGED), FRP-11 gate verdict.

## 11. Track ordering rationale

FRP-10 before FRP-11 because trusted cells (FRP-11) need multi-provider diversity to actually be diverse; running 5 family Hetzner boxes in one cell is not diversity. Adding Vultr + Stark first means cells can be heterogeneous from day one.

End — locked. Next: FRP-11 (trusted cells).
