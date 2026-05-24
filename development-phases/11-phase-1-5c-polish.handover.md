# Phase 1.5C-Polish Handover

## What landed

Engine version unchanged (`daal-core 0.4.1+desktop` for the duration
of this phase; bumped to `0.5.0+survivability` in 2F). Release ABI
surface 33 → 34 with one new append-only function:
`engine_subscription_list`.

Four items, each green:

1. `client-desktop/tun-helper/src/main.rs` — real TUNSETIFF
   `open_tun` with strict ifname validation (no NULs, no slashes, no
   spaces, ≤15 bytes). Bind/connect now use
   `std::os::linux::net::SocketAddrExt::from_abstract_name` because
   the path-based API rejects interior NULs (the 1.5B scaffold had
   this bug latent).
2. `core/abi/refresh_export.go` — `engine_subscription_list` C
   export. Backed by the existing `SubscriptionList()` Go helper.
3. `client-desktop/daal-desktop-core/src/engine.rs`,
   `commands.rs`, `tauri/src-tauri/src/lib.rs`,
   `tauri/src/lib/bridge.ts` — wire through; React Subscriptions
   screen now daaltes on mount.
4. `client-desktop/tauri/src/pages/Home.tsx` — pure `classify()`
   function bucketizes pointer-rotation status into
   `ok | rotated | expiring | expired | unknown`; banner renders
   with category-appropriate CSS classes and `data-banner-kind`
   attribute.
5. `test-rigs/distribution-failure/soak-driver/internal/wallclock/`
   — new package with `Run(Config)` driving any spawned client for
   `Duration` at `TickEvery` cadence, sampling `/proc/<pid>/fd`,
   asserting `max(fd) - min(fd) <= MaxFDGrowth`. Unit test runs a
   2-second loop and asserts ≥5 ticks plus a non-empty JSONL
   artifact.
6. `cmd/soak-driver run-wallclock` subcommand exposing the loop with
   `--duration 7d --tick 1m --max-fd-growth 50` defaults.

## Test results (last local run)

```
$ cd /home/daal/core && go test ./...
ok all 12 packages

$ cd /home/daal/test-rigs/distribution-failure/soak-driver && \
  DAAL_REPO=/home/daal go test ./...
ok daal/soak-driver/internal/{artifacts,censor,clock,origin,wallclock}

$ cd /home/daal/client-desktop && \
  DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test --workspace
ok daal-tun-helper (3 unit + 1 e2e)
ok daal-desktop-core (engine_load + parity_with_go)
ok bundle-rs

$ nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'
34
```

## Carry-overs into V2

- `tun-helper` AppImage path requires `pkexec` invocation; documented
  in 2E once the Apple/Windows polish ships.
- The wall-clock 7-day procedure is documented but not automated;
  it remains a manual one-shot run on a developer machine.

## How to repeat 1.5C-Polish locally

```sh
# 1. Rebuild the cshared engine (now 34 release symbols):
cd /home/daal/core
go build -tags cshared -buildmode=c-shared \
    -o /tmp/libdaalcore.so ./cmd/libdaalcore

# 2. Verify symbol count:
nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'   # → 34

# 3. Cargo workspace:
cd /home/daal/client-desktop
DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test --workspace

# 4. Wall-clock smoke (short):
cd /home/daal/cmd/daal-soak-engine
go build -tags soak -o /tmp/daal-soak-engine-soak .
cd /home/daal/test-rigs/distribution-failure/soak-driver
go run ./cmd/soak-driver run-wallclock \
    --engine /tmp/daal-soak-engine-soak \
    --out /tmp/wallclock-5s \
    --duration 5s --tick 200ms

# 5. Wall-clock smoke (the documented 7-day procedure):
go run ./cmd/soak-driver run-wallclock \
    --engine /tmp/daal-soak-engine-soak \
    --out /tmp/wallclock-7d \
    --duration 7d --tick 1m
```

## Engine ABI version policy reminder

`daal-core 0.4.1+desktop` (for this phase only). Release surface 34.
Phase 2F bumps to `0.5.0+survivability` and surface 35.

## Known issues

- Desktop NPM/Vite build path is not exercised by in-tree tests; the
  TS edits are syntactically sound but rely on CI to typecheck. The
  packaging pipeline runs `tsc --noEmit && vite build`, which will
  catch any drift.
