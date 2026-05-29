package freshness

import (
	deployFresh "daal/publisher/deploy/freshness"
)

// NewR2Adapter constructs a per-cell publisher over an FRP-9 R2
// backend. The R2 backend's live SDK wiring is a V2 alpha pilot
// carry-over (publisher/deploy/freshness/backends/r2/live_*.go
// returns ErrBackendNotImplemented at FRP-11); the adapter shape
// is locked here so the alpha-pilot live wiring lands as a
// drop-in.
func NewR2Adapter(backend deployFresh.Backend, cellID string) (CellPublisher, error) {
	return New(backend, cellID)
}
