//go:build gomobile

package abi

// D-2.1 gomobile exports for the display-summary surface.

func (h *DaalCore) RouteSummary(routeID string) (string, error) {
	return RouteSummary(routeID)
}

func (h *DaalCore) AvailableRoutes() (string, error) {
	return AvailableRoutes()
}

func (h *DaalCore) ThroughputSnapshot() (string, error) {
	return ThroughputSnapshot()
}

func (h *DaalCore) PanicWipe() error {
	return PanicWipe()
}
