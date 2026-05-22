# Phase 1.5C Handover

## What landed

`daal-core 0.4.1+desktop` (release version unchanged). Soak-only build
adds `engine_set_now_unix`; release ABI surface still 33. New crates /
binaries:

- `cmd/daal-soak-engine/` — long-lived JSON-on-stdio child process the
  soak driver spawns. Two flavors: release (rejects `set-now`) and
  `-tags soak` (full).
- `test-rigs/distribution-failure/soak-driver/` — pure-Go module
  containing the rig, scenario loader, fake-origin servers, accelerated
  clock, per-day invariant assessor, redact + verify subcommands, and
  the checked-in canned-7d snapshot.

## Test results (last local run)

```
$ cd /home/daal/core && go test ./...
ok  daal/core
ok  daal/core/abi
ok  daal/core/bootstrap
ok  daal/core/bootstrap/embedded
ok  daal/core/diagnostics
ok  daal/core/engine
ok  daal/core/pathmanager
ok  daal/core/refresh
ok  daal/core/routestore
ok  daal/core/share
ok  daal/core/trust

$ cd /home/daal/test-rigs/distribution-failure/soak-driver && go test ./...
ok  daal/soak-driver/internal/artifacts
ok  daal/soak-driver/internal/censor
ok  daal/soak-driver/internal/clock
ok  daal/soak-driver/internal/origin

$ go run ./cmd/soak-driver run-30d ...
ALL SCENARIOS PASSED

$ go run ./cmd/soak-driver verify --in /tmp/soak-30d
verify: ok
```

## Architectural decisions captured

See `specs/blackout-soak-rig-v1.md` and `specs/failure-channels-v1.md`.
Six locked anchors:

1. Linux-first; Android emulator best-effort (skipped if no AVD).
2. Accelerated clock only; wall-clock smoke deferred to 1.5C-Polish.
3. Pure-Go, stdlib-only soak driver.
4. Local-only execution; CI keeps unit tests, no soak job.
5. Rig-side scheduler in 1.5C; production scheduler is a V2 entry-criterion.
6. JSONL + sqlite per-day artifacts; redact strips IPs/URLs and excludes
   the sqlite snapshot from public bundles.

## Carry-overs into 1.5C-Polish

- Wall-clock 7-day smoke for fd/handle leak detection.
- Android emulator client implementation (currently a stub; needs `adb`
  + AVD wiring).
- Real-bundle directory / IPFS happy-path responses (currently the
  soak only exercises StateDrop on these channels).
- Pointer-rotation envelope happy-path test through the directory
  channel.

## Carry-overs into V2

- In-engine auto-refresh scheduler. The V2 entry criterion: "the V2
  scheduler must replay the 1.5C rig's 30-day artifact and produce
  the same invariant ledger." Recorded under
  "scheduler parity test" in the V2 phase doc.
- Route-budget engine + mode-budget UI + cooldown FSM expansion +
  per-network memory + iOS bring-up.
- ABI version bump to `daal-core 0.5.0+survivability` when the
  V2 scheduler lands; prefix in `client-desktop/daal-desktop-core/src/engine.rs`
  follows.

## Known limitations & non-issues

- The soak's "30 days" is simulated wall-clock; an engine that leaked
  one fd per real second would not be detected. We document this and
  leave the wall-clock smoke as a manual one-shot.
- The soak runs five scenarios sequentially; each scenario uses its
  own subdirectory under `<runDir>` so a partial failure on one
  scenario still leaves usable artifacts for the others.
- The soak driver and the soak-engine binary do not share any in-process
  state; the binary is a child process. If the rig crashes, the engine
  child exits cleanly on stdin EOF.

## How to run locally

```sh
# 1. Build the soak engine binary:
cd /home/daal/cmd/daal-soak-engine
go build -tags soak -o /tmp/daal-soak-engine-soak .

# 2. Run the 7-day soak (gate):
cd /home/daal/test-rigs/distribution-failure/soak-driver
go run ./cmd/soak-driver run-7d \
    --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d

# 3. Run the 30-day soak:
go run ./cmd/soak-driver run-30d \
    --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-30d

# 4. Produce a redacted public bundle:
go run ./cmd/soak-driver redact --in /tmp/soak-30d
```

The whole pipeline takes minutes locally — accelerated clock.

## Engine ABI version policy reminder

`daal-core 0.4.1+desktop` (unchanged). Soak builds add
`engine_set_now_unix` ONLY under `-tags soak`. CI's symbol-count step
in `.github/workflows/desktop.yml` enforces the release surface stays
at 33.

V2 will bump to `0.5.0+survivability` when the in-engine auto-refresh
scheduler lands.
