package freshness

import (
	deployFresh "daal/publisher/deploy/freshness"
)

// NewGHPagesAdapter constructs a per-cell publisher over an FRP-9
// GH-Pages backend. Same carry-over rationale as NewR2Adapter:
// live wiring (git push to gh-pages branch) lands at the V2 alpha
// pilot.
func NewGHPagesAdapter(backend deployFresh.Backend, cellID string) (CellPublisher, error) {
	return New(backend, cellID)
}
