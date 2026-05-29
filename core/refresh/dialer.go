package refresh

import (
	"sync"
	"time"

	"daal/core/bootstrap"
)

// globalDialerSlot is the process-wide override that takes precedence
// over a Refresher's per-instance Dialer field when set. It is the
// hook the Phase 1.5B desktop port uses to point subscription /
// revocation refreshes at the local sing-box SOCKS5 inlet without
// reaching into every Refresher's struct.
//
// The function returns:
//   - the dialer to use for the next fetch,
//   - whether the fetch is going through a tunnel (audit purposes),
//   - an error if the tunnel was expected but is unhealthy. A nil
//     dialer with no error means "fall back to direct".
type globalDialerFn func() (bootstrap.Dialer, bool, error)

var (
	globalDialerMu sync.RWMutex
	globalDialer   globalDialerFn
)

// SetGlobalDialer installs a process-wide tunnel-aware Dialer factory.
// Pass nil to clear it (revert to per-Refresher / direct-dial).
//
// Implementation note: callers are expected to install a TunnelDialer
// (see core/bootstrap/fetcher_dialer.go) wired to a SOCKS5 inlet on a
// loopback address. We deliberately do not store the SOCKS endpoint
// here — that lives in the host (Tauri Rust) and is invisible to Go
// past the construction of the Dialer.
func SetGlobalDialer(d globalDialerFn) {
	globalDialerMu.Lock()
	globalDialer = d
	globalDialerMu.Unlock()
}

// CurrentGlobalDialer returns the installed dialer factory or nil.
// Used by the Refresher to honor the override before falling back to
// its own Dialer field.
func CurrentGlobalDialer() globalDialerFn {
	globalDialerMu.RLock()
	defer globalDialerMu.RUnlock()
	return globalDialer
}

// directFallback is the same defaulting logic the Refresher used in
// Phase 1.5A, kept here so the dial() helper has one source of truth.
func directFallback() (bootstrap.Dialer, bool, error) {
	return bootstrap.NewDirectDialer(15 * time.Second), false, nil
}
