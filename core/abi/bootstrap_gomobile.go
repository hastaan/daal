//go:build gomobile

package abi

// Phase 1D extensions to the DaalCore gomobile facade. All return JSON.

func (h *DaalCore) BootstrapInstallSeeds() (string, error) { return BootstrapInstallSeeds() }

func (h *DaalCore) BootstrapRefresh(timeoutMs int) (string, error) {
	return BootstrapRefresh(timeoutMs)
}

func (h *DaalCore) BootstrapStatus() (string, error) { return BootstrapStatus() }
