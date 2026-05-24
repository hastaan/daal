// Package proxy is the byte-counter spine that sits between the
// engine's outbound (sing-box dialer or any future replacement) and
// the per-route budget engine. It does NOT terminate TLS, do not own
// any user-visible config, and does not negotiate any protocol — it
// is a thin io.Copy with a counter callback and an upstream-error
// classifier.
//
// Phase 2A introduces this package. Until 2E (iOS bring-up) wires the
// real outbound, Pipe is consumed only by core/budget tests and the
// soak rig. This is deliberate: the seam ships before the cap-flow it
// guards so 2B (mode multipliers), 2C (per-network bucketing), and 2D
// (lifeline-only filter) all land on a tested abstraction.
//
// Privacy invariant: Pipe NEVER inspects payload contents. The
// classifier in classes.go sees only error chains from the upstream
// dialer.
package proxy
