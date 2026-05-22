package pathmanager

// NetworkView is the per-network read-only projection that Rank uses
// in `lifeline-strict` mode (Phase 2D). It is satisfied by a thin
// adapter over the netmem snapshot + the budget engine's
// per-session bulk-capable opt-in flag.
//
// Pre-2D callers that don't have a view should pass a zeroNetworkView
// (or nil; Rank treats nil as zero). 2B's lifeline / normal / bulk
// paths do not consult the view at all, so legacy ranking is
// byte-stable.
type NetworkView interface {
	// FailureRate returns a normalized failure rate in [0,1] for
	// the given route on the active network. 0 if unknown. Used by
	// the lifeline-strict stability-biased sort.
	FailureRate(routeID string) float64
	// AllowsBulkCapableThisSession reports the engine session's
	// per-session opt-in flag. In lifeline-strict, bulk-capable
	// routes are filtered out unless this returns true.
	AllowsBulkCapableThisSession() bool
}

// zeroNetworkView is the no-op view used when the caller hasn't
// wired one up. Failure rates are 0 (no information); the bulk
// opt-in is false (default-deny in lifeline-strict).
type zeroNetworkView struct{}

func (zeroNetworkView) FailureRate(string) float64         { return 0 }
func (zeroNetworkView) AllowsBulkCapableThisSession() bool { return false }
