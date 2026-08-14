//go:build singbox

package abi

import "daal/core/engine"

// Under the singbox tag NewDefaultDriver returns the real in-process
// sing-box driver, whose Start correctly refuses to run without a TUN
// fd — impossible to satisfy in unit tests. Per Phase 45 Part 1 the
// unit-test target is always the stub; this init pins it back in for
// singbox-tagged test runs so `go test -tags singbox ./core/...` tests
// the ABI logic, while driver *selection* stays covered by the
// TestDriverSelectionByBuildTag twins in core/engine.
func init() {
	newEngineDriver = func() engine.Driver { return engine.NewStub() }
}
