# Phase 1.5C — Blackout Rig + 7-day + 30-day Soak

## Status

**In progress / nearing exit.** Measurement-only phase. Engine version
unchanged: `daal-core 0.4.1+desktop`. Release ABI surface unchanged at
**33** functions; soak-tagged builds add a 34th
(`engine_set_now_unix`).

## Goal

Demonstrate that the Phase 1.5B engine survives a sustained denial of
its primary distribution paths for **30 simulated days** under five
blackout scenarios, on real engine instances driven by the rig. The
7-day simulated soak gates the 30-day soak. The 30-day green run is
the V1.5 success metric in lab form.

## Anchor decisions (locked at planning)

| Decision | Choice |
|---|---|
| Soak surface | Linux desktop client(s) running the real engine binary; Android emulator best-effort (skipped if no AVD on PATH). |
| Time model | Accelerated clock only (set-now-unix injection). Wall-clock 7-day smoke is a 1.5C-Polish manual one-shot. |
| Driver language | Pure Go, stdlib-only, matching `test-rigs/censor-lab/lab-driver`. |
| Run location | Local-only (developer laptop). CI keeps running unit tests; the soak is developer-invoked. |
| Scheduler | Rig-side scheduler in 1.5C (driver loops over the existing engine commands). Production in-engine scheduler is V2. |
| Artifacts | JSONL per simulated day (public-redactable) + sqlite snapshot per day (internal). |

## Out of scope

- New engineering features. 1.5C is measurement-only.
- Real users / real networks. Synthetic origins on loopback only.
- Production auto-refresh scheduler (V2).
- macOS soak (CI-matrix only on desktop builds; soak is Linux-first).
- Wall-clock 30-day proof of long-term fd/handle leaks.

## Deliverables landed in this phase

### Code

- `core/abi/clock.go` + `clock_soak.go` + `clock_soak_export.go` +
  `clock_soak_gomobile.go` — process-wide atomic clock override gated
  by `-tags soak`. Integrated into `Init` (`pm.SetNow(nowUTC)`),
  `ImportSBP`, `ResolveTrustPrompt`, refresh / bootstrap orchestration,
  diagnostics export, and `Shutdown` reset.
- `cmd/daal-soak-engine/` — long-lived child process speaking
  line-delimited JSON on stdio. Build flavors: release (rejects
  `set-now`) and `-tags soak` (full).
- `test-rigs/distribution-failure/soak-driver/` — pure-Go module
  containing:
  - `internal/clock/` accelerated clock primitive
  - `internal/origin/` six fake HTTP origins on loopback (subscription,
    revocation, directory, ipfs, telegram, github)
  - `internal/censor/` scenario loader + channel→origin mapping
  - `internal/client/` rig-side wrapper around the soak-engine binary
  - `internal/artifacts/` per-day JSONL/JSON writers + redact + verify
  - `internal/invariants/` 6-rule per-day invariant assessor
  - `internal/soak/` per-scenario day loop
  - `cmd/soak-driver/` CLI surface (run / run-7d / run-30d / verify / redact)
  - `testdata/canned-7d/` checked-in 1-scenario × 7-day snapshot for
    the offline `verify` regression net.
- `test-rigs/distribution-failure/scenarios/publisher-revocation-url-unreachable.json`
  + paired fixture file.

### Specs

- New: `blackout-soak-rig-v1.md`, `failure-channels-v1.md`.
- Amended: `engine-abi-v1.md` (soak-only `engine_set_now_unix`
  documented; release count remains 33), `failure-taxonomy-v1.md`
  (cross-ref to channels), `routestore-v1.md` (snapshot copy is
  developer-side only, never in the public bundle).

### OPSEC

- New `TestSoakDriverNetworkSurfaceContained` — asserts that no Go
  file under `test-rigs/distribution-failure/soak-driver/` outside
  `internal/origin/` imports `net/http`.
- All existing OPSEC tests still green
  (`TestNoNetHTTPInRefresh`, `TestNoTelemetryInDesktop`,
  `TestShareBindsOnlyPrivate`, `TestNoGroupBasedLabels`).

## Local exit-criteria evidence

```
$ cd /home/daal/core && go test ./...
all 11 packages OK

$ go build -tags soak -o /tmp/daal-soak-engine-soak ./cmd/daal-soak-engine

$ cd /home/daal/test-rigs/distribution-failure/soak-driver && go test ./...
ok  daal/soak-driver/internal/artifacts
ok  daal/soak-driver/internal/censor
ok  daal/soak-driver/internal/clock
ok  daal/soak-driver/internal/origin

$ go run ./cmd/soak-driver run-7d  --engine /tmp/daal-soak-engine-soak --out /tmp/soak-7d
scenario: bootstrap-directory-mirror-unreachable   PASS
scenario: github-unreachable                       PASS
scenario: publisher-revocation-url-unreachable     PASS
scenario: subscription-url-unreachable             PASS
scenario: telegram-unreachable                     PASS
ALL SCENARIOS PASSED

$ go run ./cmd/soak-driver run-30d --engine /tmp/daal-soak-engine-soak --out /tmp/soak-30d
scenario: bootstrap-directory-mirror-unreachable   PASS
scenario: github-unreachable                       PASS
scenario: publisher-revocation-url-unreachable     PASS
scenario: subscription-url-unreachable             PASS
scenario: telegram-unreachable                     PASS
ALL SCENARIOS PASSED

$ go run ./cmd/soak-driver verify --in /tmp/soak-30d
verify: ok

$ go run ./cmd/soak-driver redact --in /tmp/soak-30d
wrote /tmp/soak-30d/public-bundle.zip   (no daal.db.snapshot inside)
```

## Exit criteria

1. ✅ `soak-driver` and `daal-soak-engine` build with stdlib only.
2. ✅ `soak-driver verify` is green against the checked-in canned 7d snapshot.
3. ✅ All five scenarios live under `scenarios/` with paired fixtures.
4. ✅ `engine_set_now_unix` exists ONLY under `-tags soak`. Release
   build still exposes 33 ABI symbols. Verified locally; CI symbol-count
   step in `desktop.yml` already enforces it.
5. ✅ `run-7d` against all five scenarios completes without any red invariant.
6. ✅ `run-30d` (gated by green 7d) completes without any red invariant.
7. ✅ `redact` produces `public-bundle.zip` containing only allow-listed
   files; `daal.db.snapshot` is never included.
8. ✅ New specs landed; amended specs landed.
9. ✅ `core/opsec_test.go` still green; new `TestSoakDriverNetworkSurfaceContained` green.
10. ✅ Phase doc + handover landed.

## Risks & known follow-ups (1.5C-Polish / V2)

- Accelerated clock cannot prove fd/handle leaks. Wall-clock 7-day
  smoke is documented as a manual one-shot.
- Android emulator client (`internal/client/android_emulator.go`) is
  scaffolded but no-op'd; will activate when an AVD is on PATH in V2.
- The fake-origin bodies are minimal stubs; the directory and IPFS
  channels do not yet serve real `.sbp` archives. The current rig
  exercises the failure-mode plumbing (StateDrop) end-to-end; happy-
  path bundle import through these channels is exercised by the
  censor-lab rig and bundle-go tests, not the soak.
- V2's in-engine scheduler must replay the rig's 30-day artifact and
  produce the same invariant ledger; this is a "scheduler parity"
  test in V2's entry criteria.

## Pointer for next phase

`11-phase-2-survivability.md` (V2 — route budget engine, mode budgets,
cooldown FSM expansion, per-network memory, iOS bring-up,
in-engine auto-refresh scheduler).
