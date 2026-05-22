// Package rotation is the FRP-7 direct-VPS rotation surface.
//
// This package owns two pure-function entry points:
//
//   - FromExplanation: takes the recipient family's FRP-3
//     selection.Explanation (parsed from the local mirror type
//     [Explanation], because publisher/ cannot import
//     core/internal/selection) plus the operator's record, and
//     returns a [RotationRecommendation].
//
//   - FromContext: takes a [RotationContext] (failure
//     classifications, network signals, exposure mode, operator
//     record) and returns a [RotationRecommendation]. Used when
//     the FRP cannot exfiltrate the recipient's diagnostics blob
//     (the realistic outage case).
//
// Both functions normalise to the same private signal model and
// run the same ladder mapping. The difference is confidence:
// FromExplanation can return [ConfidenceHigh]; FromContext is
// capped at [ConfidenceMedium].
//
// The package also exposes [Executor], the rotation execution
// surface, which wraps a [provider.Provider], the FRP-4b binder,
// and an [OperatorDb] handle into one transactional rotate-step
// (FRP-7 invariant 24, "rotation is reversible"; see
// specs/v1-5-closure-v1.md).
//
// Position B: this package opens NO sockets. All network I/O is
// delegated to the [provider.Provider] (which is the documented
// network actor — Hetzner API at V1.5). The rotation/opsec_test.go
// in-package guard backstops the package-level
// publisher/deploy/opsec_test.go check.
//
// V1.5 ship surface: this package is direct-VPS only. cdn_fronted
// rotation rules (supplement §14.4) land at FRP-8 and are tested
// here as inert no-ops.
package rotation
