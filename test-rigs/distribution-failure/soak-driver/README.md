# Soak Driver

Linux-first, stdlib-only Go driver for the Phase 1.5C blackout +
accelerated 30-day soak.

## What it does

Runs the Phase 1.5B engine (libdaalcore.so via the `daal-core` CLI
or the Tauri-shell-equivalent in-process loader, plus the Phase 1B
Android APK on an emulator when one is available) under each of five
distribution-failure scenarios for 7 simulated days, then 30 simulated
days, and asserts a fixed list of invariants per simulated day per
client.

Time is **accelerated**: simulated days advance via the build-tag-gated
`engine_set_now_unix` symbol that ships only in `-tags soak` builds of
`libdaalcore.so`. Release builds still expose 33 ABI symbols.

The driver is purely measurement: it adds no production code paths.

## Usage

```sh
# Build a soak engine library (NOT a release library).
cd /home/daal/core
CGO_ENABLED=1 go build -tags "cshared soak" -buildmode=c-shared \
  -o /tmp/libdaalcore-soak.so ./cmd/libdaalcore

# Run a 7-day soak across all five scenarios:
cd /home/daal/test-rigs/distribution-failure/soak-driver
go run ./cmd/soak-driver run-7d \
  --engine-lib /tmp/libdaalcore-soak.so \
  --out runs/$(date +%Y%m%d-%H%M)

# After it's green, run the 30-day soak (gated by 7-day green):
go run ./cmd/soak-driver run-30d \
  --engine-lib /tmp/libdaalcore-soak.so \
  --out runs/$(date +%Y%m%d-%H%M)

# Re-run invariants offline against an existing run:
go run ./cmd/soak-driver verify --in runs/<run_id>

# Produce a redacted public artifact bundle:
go run ./cmd/soak-driver redact --in runs/<run_id>
```

## Why a sibling Go module

Self-contained, stdlib-only. The driver pulls in fixture-forging, fake
HTTP servers, and shell-out helpers that have no business in production
code. This mirrors the existing `test-rigs/censor-lab/lab-driver`
pattern.

## Privacy

The rig generates synthetic origins on loopback, never touches real
networks, and does not collect anything from anyone. Public artifact
bundles are produced through `redact` which strips IP literals, exact
timestamps, AVD device IDs, and any `secrets_kv` content.
