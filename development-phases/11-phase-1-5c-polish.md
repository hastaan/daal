# Phase 1.5C-Polish — Closeout

## Roadmap Coverage

Closes the four items the 1.5B and 1.5C handovers explicitly carried
forward, before V2 begins.

## Goal

Land the smallest set of items that 1.5B / 1.5C deferred. Engine
version stays at `daal-core 0.4.1+desktop`. ABI surface goes 33 → 34
(one append-only addition: `engine_subscription_list`, used by the
desktop Subscriptions screen on mount).

## Scope

Four items, each landed with a unit or integration test:

1. **`tun-helper::open_tun`** — TUNSETIFF + interface configuration on
   Linux desktops. Replaces the 1.5B scaffold's stub. End-to-end
   integration test that spawns the helper, connects to the abstract
   socket, sends `Open`, receives the fd via SCM_RIGHTS, and
   TUNGETIFF-verifies the iface name.
2. **`engine_subscription_list`** — the desktop Subscriptions screen
   only renders rows added in the current session. Add the C ABI
   function (release surface 33 → 34), wire through the Tauri command
   layer, daalte the React screen on mount.
3. **Pointer-rotation banner** — the desktop Home screen renders
   `engine_pointer_rotation_status` in a small footer. Replace it with
   a categorised banner (ok / rotated / expiring / expired / unknown)
   that classifies the engine response and renders the right CSS class.
4. **`soak-driver run-wallclock`** — a single-client, real-clock
   subcommand that drives the same engine commands the per-day soak
   drives, samples `/proc/<pid>/fd` per tick, and fails the run if
   `max(fd) - min(fd)` exceeds a configurable ceiling. Default
   `--duration 7d --tick 1m --max-fd-growth 50`.

## Out of scope

- `win-service` crate (folds into 2E's broader Apple/Windows polish).
- Persian wordlist commissioning (CC operational item).
- Real-bundle directory / IPFS happy-path responses for the soak rig
  (1.5C carry-over; not blocking V2).
- Pointer-rotation envelope happy-path test through the directory
  channel (1.5C carry-over).

## Exit criteria

1. `cargo test --workspace` (in `client-desktop/`) green; tun-helper
   integration test passes when run as root with `/dev/net/tun`
   accessible.
2. `engine_load.rs` confirms `subscription_list` returns
   `{"subscriptions":...}` against a freshly built libdaalcore.
3. Desktop Home banner renders without a separate `loading` state for
   the rotation status; classify() is exercised by render-on-mount.
4. `soak-driver run-wallclock --duration 5s --tick 200ms` returns 0
   exit and writes `wallclock_result.json` with `Failed: false`.
5. `cd core && go test ./... && cd test-rigs/.../soak-driver && go test ./...`
   all green.
6. Engine version unchanged; release ABI surface = 34; soak ABI surface
   = 35.

## Handover to Phase 2F

Phase 2F receives:
- A 34-function release ABI ready to grow to 35 with the scheduler.
- A real `tun_helper::open_tun` so the desktop NSIS / .deb / AppImage
  paths are no longer blocked on the helper stub.
- A wall-clock smoke loop the long-running 7-day procedure can re-use.
- A desktop Subscriptions screen and Home banner that both round-trip
  through the engine, so the V2 budget banner can land on the same
  pattern.
