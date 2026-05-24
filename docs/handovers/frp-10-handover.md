**Status:** SHIPPED 2026-05-04 (engineering surface).
**Closure:** HOLD (`specs/v2-closure-v1.md`) — gated on the
FRP-10 live alpha pilot (2 FRPs × 14-day soak across at least
two of the three providers). Engineering ship clears the
precondition; the closure record itself is appended once the
live pilot delivers the green aggregate.
**Engine line:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI:** **48** UNCHANGED.
**Spec version:** UNCHANGED. No bundle ABI surface touched
(FRP-10 is multi-provider + V2 mgmt-plane; bundle producer +
verifier remain on the FRP-8 / FRP-9 contract).
**Supplement:** v2.3.8 → v2.3.9 (one new subsection
§9.5.5 — FRP-10 implementation lock for the V2 mgmt-plane;
documents the five concrete locks on TLS posture, port
discipline, three-route API, Ed25519 token shape, cloud-
firewall-as-gate, plus the Android-no-rotate boundary).

This handover summarises the ten-commit FRP-10 series plus the
post-review hardening pass that made the shipped code match the
v2.3.9 implementation lock. It ships the V2
cloud-provider-firewall mgmt-plane architecture the supplement
has carried as §9.5.2 text since v2.3, plus the multi-provider
and Android-publisher work blocked behind that architecture.

## What FRP-10 ships

The supplement's §9.5.2 V2 mgmt-plane has lived as a text
sketch since v2.3 ("persistent in-box service guarded by the
cloud-provider firewall"). FRP-10 lands the **wire-level
implementation** of that sketch end-to-end:

* **Three provider adapters.** Hetzner extension +
  brand-new Vultr (`govultr/v3`) + brand-new Stark (REST
  bearer). All three implement the FRP-10-extended `Provider`
  interface (the new `SetEphemeralFirewallRule` /
  `RemoveEphemeralFirewallRule` pair).
* **In-box `daal-relay-mgmt` service.** New module at
  `cmd/daal-relay-mgmt/`. P-256 self-signed leaf cert
  generated at first boot; SHA-256 fingerprint published to
  the bootstrap-window relay. Three routes exactly:
  `POST /rotate-credentials` (L1, ~5 s),
  `POST /rotate-tls` (L2, ~20 s), `GET /health`.
* **V2 cloud-init template.** New `v2.yaml.tmpl` adds the
  daal-relay-mgmt unit, the per-deploy publisher pubkey,
  and the random mgmt port — without opening box-side `ufw`
  for that port (cloud-provider firewall is the gate).
* **Helper-side TLS-pinned mgmt client.**
  `publisher/deploy/mgmt/` mints Ed25519 op-bound tokens,
  pins the box's TLS leaf against
  `OperatorRecord.MgmtTLSFingerprint`, and orchestrates the
  ephemeral-firewall-rule open / call / close dance for L1/L2.
* **V007 desktop schema.** Adds `mgmt_port` +
  `mgmt_tls_fingerprint` columns to the operators table; the
  wizard persists them post-bootstrap-handshake.
* **36 new EN+FA i18n strings** for the desktop V2 toggle,
  fingerprint display, port explanation, and fast-path
  rotation copy.
* **Android publisher wizard.** FRP-5 parity (provision +
  bind + QR only — no rotation surface). Reflection +
  source-grep tests pin invariant 30 at the file level.

## Locked answers from the spec session

Four design decisions that the spec session locked:

1. **Stark auth: bearer token only.** No HMAC, no signed
   request bodies — just `Authorization: Bearer <token>`.
   (HMAC remains an internal seam in case Stark adds it
   later, but is not exposed.)
2. **Android wizard: FRP-5 parity only.** Provision + bind +
   QR. No rotate, no V2 mgmt-plane signing key on the phone.
3. **Mgmt-plane TLS: self-signed + per-deploy fingerprint
   pin.** Persisted in `OperatorRecord.MgmtTLSFingerprint`.
4. **Mgmt-plane port: random per-deploy in `[10000, 65000]`.**
   Stamped in `OperatorRecord.MgmtPort`.

## Five new locked invariants (26–30)

26. Mgmt-plane TLS pinned per deploy.
27. Mgmt port random + persisted; no fixed constant in any
    call site.
28. `SetEphemeralFirewallRule(port, IP)` tuple is the full
    key; refuses `port == 0` or `dur ≤ 0`.
29. Mgmt API exactly 3 routes (`/health`,
    `/rotate-credentials`, `/rotate-tls`).
30. Android wizard: no `rotate_execute` /
    `cdn_rotate_*` / `recommend_l[1-9]` call sites, no desktop
    mgmt-plane client import.

## Commit-by-commit

| # | SHA | Title |
|---|---|---|
| 1 | `9da5e22` | path-only refactor `provider/hetzner` → `providers/hetzner` |
| 2 | `228bf15` | Provider interface extension + ephemeral FW + mgmt fields |
| 3 | `875b914` | Vultr adapter (`govultr/v3`) at `providers/vultr/` |
| 4 | `a07b4fa` | Stark adapter (REST bearer) at `providers/stark/` |
| 5 | `bb10c39` | `cmd/daal-relay-mgmt` service (11 unit tests) |
| 6 | `cee498b` | V2 cloud-init template + bootstrap fingerprint relay (+6 tests) |
| 7 | `464a6ca` | Helper-side mgmt-plane client + token signing (+12 tests) |
| 8 | `4c2bff1` | desktop wizard V007 migration + V2 i18n + mgmt-plane row API (+7 wizard tests) |
| 9 | `992148c` | Android publisher wizard FRP-5 parity (16 unit tests) |
| 10 | _this commit_ | specs + supplement v2.3.8→v2.3.9 + handover |

## Post-review hardening

The readiness review found three mismatches and this handover now
records their closure:

* Provider `Provision` paths render the V2 cloud-init template,
  stamp a random `[10000, 65000]` management port, and, on live
  provision, wait for the bootstrap health endpoint to publish a
  valid 32-byte management TLS fingerprint before returning the
  `OperatorRecord`.
* The Helper-side client, daemon port reader, provider firewall
  methods, and desktop SQLite row API all reject `8443`, zero, and
  out-of-range ports; the fixed-port wording in the phase/spec docs
  has been removed.
* `/rotate-tls` is documented and implemented as data-plane TLS/SNI
  rotation only. The management-plane self-signed certificate remains
  fingerprint-pinned per deploy; replacing it is a redeploy/future
  explicit management-cert-rotation task.
* Idempotent live-provider retries now require the persisted
  `MgmtPort` when a same-name server already exists. Providers no
  longer fabricate a fresh random port for an already-stamped box.
  The Stark REST wrapper also preserves query strings in lookup paths
  so same-hostname VPS detection is exercised by tests.

## Test surface deltas at FRP-10

| Surface | Δ | Total at FRP-10 |
|---|---|---|
| `publisher/deploy/provider` | +6 | baseline+6 |
| `publisher/deploy/providers/hetzner` | +5 | baseline+5 |
| `publisher/deploy/providers/vultr` | +14 (new package) | 14 |
| `publisher/deploy/providers/stark` | +13 (new package) | 13 |
| `publisher/deploy/cloudinit` (V2 template) | +6 | baseline+6 |
| `publisher/deploy/mgmt` | +15 (new package + port/fingerprint hardening) | 15 |
| `cmd/daal-relay-mgmt` | +11 (new package) | 11 |
| `cmd/daal-relay-health` | +1 mgmt-fingerprint publication test | baseline+1 |
| `client-desktop/daal-wizard` lib | +7 | **89** (was 82 at FRP-9 baseline) |
| `client-android/app` `:testDebugUnitTest` | +16 | **34** (was 18 baseline) |

All surfaces green at the FRP-10 head commit.

## Verification one-liners

```
# Helper / box engineering surfaces
cd publisher && go test ./...
cd cmd/daal-relay-mgmt && go test ./...
cd cmd/daal-relay-health && go test ./...
cd cmd/daal-deploy && go test ./...

# Desktop wizard
cd client-desktop && cargo test -p daal-wizard
cd client-desktop/tauri && npx tsc --noEmit && npm run build

# Android publisher wizard (Android SDK at /opt/android-sdk)
cd client-android && ANDROID_HOME=/opt/android-sdk \
    ./gradlew :app:testDebugUnitTest

# Engine regression / ABI
cd core && go test ./...
cd core && go build -buildmode=c-shared -tags cshared \
    -o /tmp/libdaalcore.so ./cmd/libdaalcore
nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l  # 48
cd bundle/go && go test ./...
```

All commands return green at the post-review hardening head.

## Carry-overs

These are explicit non-blockers for the engineering ship; the
V2 alpha pilot (per `specs/v2-closure-v1.md`) gates each:

* **Live `govultr/v3` SDK wiring.** Today the Vultr adapter
  ships against an injected `vultrClient` interface;
  `live_client.go` returns `ErrLiveNotImplemented`.
* **Live Stark API testing.** Same shape — the FRP-10 adapter
  compiles + tests against a mock REST client; live testing
  needs a Stark account with credentials.
* **AndroidKeystorePublisherKey + gomobile-bound
  `Deploy.aar`.** Today the Android wizard runs against
  `InMemoryPublisherKey` + `DeployBridgeStub`; the production
  wiring lands when the gomobile cross-compile toolchain is
  in CI.
* **FA copy native review.** ~36 new desktop V2 strings
  + ~100 Android wizard strings (when Android i18n ships)
  need a native-FA review pass before the V2 alpha is offered
  to FA-first FRP families.
* **BYO domain prereq for V1.6 production** — carried over
  from FRP-9.
* **Live V1.6 alpha pilot** — gates `specs/v1-6-closure-v1.md`
  flip; carried over from FRP-9.
* **Live R2 / GH Pages SDK wiring for publish-freshness** —
  carried over from FRP-9.

## What FRP-11 picks up

FRP-11 is the trusted-cells milestone (supplement §16). It is
unblocked by FRP-10 because:

* The provider-adapter trio (Hetzner / Vultr / Stark) is the
  base layer cells will run their own boxes on.
* The V2 mgmt-plane gives cells the rotation primitive they
  need for cell-coordinated credential refresh.
* The Android publisher wizard's FRP-5 parity establishes the
  pattern for cell-member onboarding (provision-only on
  phone; cell-admin operations on desktop).

The FRP-track v3 doc + the supplement §16 prose are the
authoritative entry points; this handover does not preempt
either.

---

## Engine line check

* **Version constant:** `daal-core 0.9.0+v3-share` — UNCHANGED.
* **ABI count:** 48 — UNCHANGED.
* **`spec_version`:** UNCHANGED. (V007 is a wizard-database-only
  schema; the on-the-wire `.sbp` and on-disk `relay_pack_id`
  contracts are byte-identical to FRP-9.)
* **Locked invariants:** 30 (was 25 at FRP-9; FRP-10 adds 26–30).
