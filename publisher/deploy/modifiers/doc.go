// Package modifiers is the FRP-12 modifier-framework publisher-side
// catalogue and adapter. It owns:
//
//  1. The build-time registry — frontmatter.go parses each
//     specs/modifiers/<kind>.md file into a Meta record, and the
//     genregistry binary at cmd/genregistry emits registry_gen.go.
//
//  2. The runtime API — registry.go exposes Lookup(kind) Meta and
//     AllowedKindsAt(phase) map[string]bool for callers that need to
//     populate relaypackvalidate.ValidateOpts.AllowedModifierKinds.
//
//  3. The platform helper — platforms.go translates a runtime GOOS
//     value into the list of allowed modifier kinds.
//
// The validator (bundle/go/relaypackvalidate) is NOT modified at
// FRP-12. Its existing RP013 rule (and the AllowedModifierKinds
// option) was already plumbed at FRP-1; this package supplies the
// allow-list contents at deploy time, so RP013 lifts conditionally
// only for kinds whose specs/modifiers/<kind>.md carries
// pass_record.status=PASS at and above min_phase.
//
// Locked invariants (FRP-12):
//
//  37. Zero PASS records ship at FRP-12.
//  38. Unknown / PENDING kinds stay hard-rejected.
//  39. min_phase enforced (caller-side via AllowedKindsAt).
//  40. platforms[] enforced at the engine importer
//     (core/internal/selection/candidate_platform.go).
//  41. Per-candidate scoping (RP013 fires per-route).
//  42. Recipient UI default OFF.
//  43. Pass record reviewable; codegen rejects malformed
//     front-matter.
//  44. No engine release symbols added; ABI=48.
//  45. Position B preserved (no telemetry).
//  46. exposure_mode: serverless_external NOT in scope.
//  47. Android source-grep guard (no modifier admin paths).
//
// Engine line UNCHANGED throughout FRP-12: daal-core 0.9.0+v3-share,
// ABI=48, spec_version=4.
package modifiers
