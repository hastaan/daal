# Phase 1.5A — Reliability Hardening — Handover

## What landed

### Bundle (`bundle/go/`)

- `bundle/go/bundle/types.go` — added v2 fields to `PublisherInfo`
  (`RevocationURL`, `RevocationFingerprintHex`) and to `BundleInfo`
  (`PointerRotation` of type `PointerRotationRef{Path}`).
- `bundle/go/bundle/sbp.go` — `VerifyBundle` now accepts
  `spec_version` 1 OR 2.
- `bundle/go/cmd/daal-publish/main.go` — added `--legacy-v1` flag.
- `bundle/go/publisher/bundle_cmd.go` —
  `BundleOptions.LegacyV1`; manifests with `spec_version=0` default to
  2 (or 1 if `--legacy-v1` is set); `spec_version=1` is silently
  promoted to 2 unless `--legacy-v1` is set; `enforceManifestPolicy`
  accepts 1 or 2.
- `bundle/go/publisher/revocation.go` —
  `BuildSignedRevocationList`, `VerifySignedRevocationBytes`.
- `bundle/go/bundle/v2_test.go` — round-trip of v2 fields, v1+v2
  acceptance, v3 rejection, pointer_rotation_ref preserved.

### Routestore (`core/routestore/`)

- `core/routestore/schema.go` — three columns added to `publishers`
  (`revocation_url`, `revocation_fp_hex`, `last_revocation_check`)
  via the embedded `migrations` slice (forward-only, additive).
  Three new tables: `subscriptions`, `refresh_audit`,
  `diagnostics_explain`.
- `core/routestore/store.go` — `PublisherRow` extended with
  `RevocationURL`, `RevocationFingerprintHex`, `LastRevocationCheck`.
- `core/routestore/subscriptions.go` —
  `SubscriptionRow`, `UpsertSubscription`, `GetSubscription`,
  `ListSubscriptions`, `DeleteSubscription`, `SetPublisherRevocation`,
  `MarkPublisherRevocationChecked`, `ListPublishersWithRevocationURL`,
  `AppendRefreshAudit`, `PutDiagnosticsExplain`,
  `LatestDiagnosticsExplain`.
- The subscription FK is intentionally soft (no SQL `REFERENCES`)
  because a user can add a subscription before the first .sbp from
  that publisher arrives.

### Bootstrap (`core/bootstrap/`)

- `core/bootstrap/fetcher.go` — extracted `FetchRaw(ctx, url, dialer,
  timeout) ([]byte, error)`; the existing `Fetch` (which parses .sbp)
  now delegates to `FetchRaw`. Subscription and revocation refreshers
  reuse `FetchRaw` directly.
- `core/bootstrap/pointer_rotation.go` —
  `PointerRotation` envelope, `PersistedPointers`, `PersistKey =
  "bootstrap-pointers:v1"`, `VerifyPointerRotation`,
  `LoadPersistedPointers`, `PersistPointerRotation`,
  `OverlayPersistedOntoManifest`, `Manifest.StatusFromStore`.
- A persisted rotation only writes when at least one inner set
  strictly beats the higher of (persisted, embedded). Tampered
  envelopes silent-drop.

### Refresh (`core/refresh/` — NEW)

- `doc.go` — package contract (no net/http; no URL logs).
- `parse.go` —
  `ParseSubscriptionBody(body, hint)` returns
  `ParsedSubscription{Format, ProfileTitle, SupportURL, Routes}`.
  Recognized formats: base64 / URI list, SIP008 JSON, Clash YAML
  (hand-rolled — no YAML dependency).
- `synthetic.go` —
  `BuildSyntheticSubscriptionBundle(...)` produces a transient
  `spec_version=2` .sbp signed by the device delegate identity
  (`bundleshare.PublisherIdentity` from
  `secrets_kv:share/identity:v1`).
- `subscription.go` —
  `Refresher{Store, Identity, Adapter, Dialer, Fetch, Now}`,
  `Add(AddInput)`, `Refresh(ctx, id, timeout)`, `Remove`,
  `RefreshAll`. The `Fetch` field defaults to `bootstrap.FetchRaw`;
  tests inject a stub.
- `revocation.go` —
  `RevocationRefresher{Store, Dialer, Fetch, Now}`,
  `RefreshAll(ctx, timeout)`. Per-publisher, verifies under
  `revocation_fp_hex`. Tampered → silent drop.
- `audit.go` —
  `AuditWriter` interface (satisfied by `routestore.Store`),
  `recordAudit(...)` — best-effort.
- Tests — happy path (URI list), failure-keeps-cache, malformed body,
  add/list/remove round-trip, revocation apply, tampered signature.

### Pathmanager (`core/pathmanager/`)

- `explain.go` —
  `WhyExplain{Bucket, State, ActiveRoute, WhyChoseRoute,
  SkippedFamilies, LastFailure}`,
  `Manager.Explain()` returns a deterministic projection.
- Tests for happy path, cooldown, family-cooldown.

### ABI (`core/abi/`)

- `Version` bumped to `daal-core 0.4.0+reliability`.
- `refresh.go` — 6 new functions:
  `SubscriptionAdd`, `SubscriptionRefresh`, `SubscriptionRemove`,
  `SubscriptionList` (gomobile-only; not in C ABI),
  `RevocationRefreshAll`, `PointerRotationStatus`,
  `DiagnosticsExplain`.
- `refresh_export.go` (cshared) — same 6 wrapped for `//export`.
- `refresh_gomobile.go` — same 6 + `SubscriptionList`.
- Lazy state under `globalRefresh`; `resetRefreshForShutdown` clears it
  on `Shutdown` so test re-Init picks up a fresh store. Equivalent
  resets added for `globalBootstrap` and `globalShare`.
- `refresh_test.go` — round-trip add/list/remove (URL not in list
  output), revocation refresh-all with no targets, pointer rotation
  status (embedded only), diagnostics explain (NoRoute), engine
  version literal check.

### CLI (`cmd/daal-core/`)

- 6 new subcommands (`subscription-add/refresh/list/remove`,
  `revocation-refresh-all`, `pointer-rotation-status`,
  `diag-explain`).

### Android (`client-android/`)

- `data/DaalCoreBridge.kt` — 7 new delegating methods for the Phase
  1.5A surface (subscription_*, revocation_refresh_all,
  pointer_rotation_status, diagnostics_explain).
- `vm/DaalViewModel.kt` — added `SubscriptionUi`, `KeyRotationEvent`,
  `WhyExplainUi`; load/refresh/remove/add coroutines;
  `loadWhyThisRoute`.
- `ui/SubscriptionsScreen.kt`, `ui/KeyRotationCard.kt`,
  `ui/WhyThisRouteScreen.kt` — three new screens.
- `res/values/strings.xml` + `res/values-fa/strings.xml` — EN + FA
  copy for all new screens.

### Specs

New: `subscription-v1.md`, `revocation-v1.md`,
`key-rotation-ux-v1.md`, `pointer-rotation-v1.md`,
`diagnostics-explain-v1.md`.

Amended: `sbp-v1.md` (spec_version 2 + new fields),
`engine-abi-v1.md` (six functions; surface 32; engine version
0.4.0+reliability), `routestore-v1.md` (subscriptions, refresh_audit,
diagnostics_explain tables; publishers columns), `publisher-keys-v1.md`
(per-publisher revocation_url).

### OPSEC (`core/opsec_test.go`)

`TestNoNetHTTPInRefresh` checks that `core/refresh/*.go` (excluding
tests) contains no `"net/http"`, no `http.*` calls, no `log.Printf`,
no `fmt.Println`, and no obvious URL log patterns.

## How to verify

```bash
cd /home/daal/bundle/go && go test ./...
cd /home/daal/core      && go test ./...
cd /home/daal/cmd/daal-core && go build -o daal-core ./...

# CLI smoke (state dir is fresh)
rm -rf /tmp/hytest && mkdir /tmp/hytest
./daal-core --state-dir /tmp/hytest version             # 0.4.0+reliability
./daal-core --state-dir /tmp/hytest subscription-add fp1 https://example.invalid/sub TestSub
./daal-core --state-dir /tmp/hytest subscription-list   # URL absent
./daal-core --state-dir /tmp/hytest pointer-rotation-status
./daal-core --state-dir /tmp/hytest diag-explain
```

## Known edge cases / TODOs not landed

- The TunnelDialer is unwired (Phase 1.5A's Refresher gets a
  `NewDirectDialer`). Phase 1.5B will:
  1. Expose a SOCKS5 inlet on the active sing-box outbound.
  2. Provide a `TunnelDialer` to `core/refresh` so `viaTunnel=true`
     becomes the steady-state.
- Subscription auto-refresh scheduler is a future-V2 affordance; the
  `profile_update_min` column is recorded but not consulted.
- The KeyRotationCard is wired to a `lastKeyRotation` UiState field;
  the path that sets that field on a successful
  `VerdictRotationAccepted` is not yet plumbed (the importer would
  need a thin shim to surface a rotation event to the ABI). Tracked
  for 1.5A-Polish; the UI piece is ready to consume the event.
- The `pointer_rotation_ref.path` lookup inside `applyDirectory` (i.e.
  reading `trust/pointer-rotation.json` out of the directory's .sbp
  archive bytes and calling `PersistPointerRotation` after a
  successful `BootstrapRefresh`) is implemented as the standalone
  `PersistPointerRotation` API but the orchestrator wiring to call it
  during `Provider.Refresh` is deferred to 1.5A-Polish — the test rig
  exercises the persistence path directly. Adding the integration is
  ~10 lines once a sample directory bundle with a rotation envelope
  is available.
- `LastFailure` field on `WhyExplain` is reserved for V2; the FSM
  currently only carries a string `lastReason`, so the structured
  classification is not populated.

## Pointer for next phase

`09-phase-1-5b-desktop-port.md` — Tauri 2 + Rust + bundle-rs.
`10-phase-1-5c-blackout-soak.md` — rig, 7-day soak, 30-day soak.
