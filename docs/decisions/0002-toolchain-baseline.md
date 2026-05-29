# Decision 0002 — Toolchain Baseline

## Status

Accepted as initial baseline.

## Decision

Use the following toolchain direction:

- **Go** for the core engine wrapper, reference bundle library, and publisher CLI.
- **Kotlin + Jetpack Compose** for Android.
- **Swift/SwiftUI + Network Extension** for iOS and macOS tunnel integration.
- **Rust + Tauri + React/TypeScript** for desktop.
- **Ed25519** as the first signing primitive for publishers and bundles.

## Platform Strategy

- Linux is the primary development base for core libraries, publisher tooling, test rigs, and CI bootstrap.
- Android is the first full user client.
- Windows is a desktop/tooling validation target and later user client.
- macOS and iOS remain required targets even without local Apple hardware; use macOS CI, external Apple hardware, TestFlight partners, or a trusted maintainer.

## Reproducible Build Direction

The roadmap requires hermetic, reproducible builds. Phase 0A does not lock Bazel vs Nix yet; that decision should be made after the first concrete build graph is clearer.

Until then:

- pin toolchain versions when introduced,
- avoid implicit system dependencies,
- prefer deterministic generated artifacts,
- and document every build requirement.

## Rationale

The circumvention ecosystem is Go-heavy. sing-box and adjacent transports are load-bearing dependencies, so Go is the practical core language. Native mobile and Tauri desktop preserve bundle size and platform behavior.
