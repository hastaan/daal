// Package netns is a stub for the live-run namespace orchestrator.
// In Phase 0C the live runner is intentionally narrow: it refuses to run
// without CAP_NET_ADMIN and prints a clear remediation message. The full
// implementation lands incrementally as scenarios are exercised against
// real netns on Linux hosts. The replay path does not depend on this.
package netns

import (
	"errors"
	"runtime"
)

var ErrNeedsNetAdmin = errors.New("live run requires Linux + CAP_NET_ADMIN; use the 'replay' subcommand for offline fixture generation")

// Available reports whether the host is plausibly capable of running the
// live netns rig. It does not actually probe capabilities; it is a guard for
// the CLI to print an actionable error.
func Available() bool {
	return runtime.GOOS == "linux"
}
