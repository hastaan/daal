package refresh

import (
	"errors"
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

// ErrTunnelRequired is returned instead of a direct dialer when a tunnel
// is up but no tunnel-aware dialer is installed. Callers must treat it as
// "this fetch did not happen", never as "fetch failed, try direct".
var ErrTunnelRequired = errors.New(
	"refresh: a tunnel is active but no tunnel dialer is installed; " +
		"refusing to fetch from the device's real address")

// tunnelRequired is set while the engine holds an active route.
//
// WHY THIS EXISTS — a real leak, found 2026-08-17.
//
// On Android the engine's own sockets are deliberately excluded from the
// TUN (DaalVpnService calls addDisallowedApplication(self), without which
// every outbound dial fails with "no available network interface"). The
// refresher only rides the tunnel when SetGlobalDialer has been installed,
// and the sole installer — abi.SetTunnelSocks — is reached on desktop from
// start_sidecar, which cannot resolve a sing-box binary on Android. So the
// scheduled subscription / revocation / bootstrap fetches fell through to
// directFallback: plain TCP, from the excluded UID, on a fixed cadence,
// while the UI said "connected".
//
// For a censorship-circumvention tool that is close to the worst signal we
// can emit: it ties a residential address to a known distribution endpoint,
// repeatedly, and it is exactly the pattern that identifies a user of this
// class of tool. It is strictly worse than the feature being unavailable.
//
// So: fail CLOSED. While a route is active, a fetch that cannot go through
// the tunnel does not happen at all. Refreshing resumes when a tunnel-aware
// dialer exists on this platform (an in-process loopback SOCKS inlet plus
// engine_set_tunnel_socks from the JNI bridge — Wave 2 transport work).
//
// This guard is stated in terms of ROUTE STATE, not of refresh kind, and
// that distinction was got wrong once already. Wave 1 exempted bootstrap
// wholesale on the reasoning "with no route active there is no tunnel to
// betray, and a first fetch has to start somewhere" — true of the cold
// fetch, false of the scheduled one, which core/scheduler fires on a 24 h
// cadence from a pump that only runs WHILE the tunnel is up. The exemption
// therefore kept the leak open on a third kind for a whole wave. Every
// dialer selection now asks the same question this variable answers, and
// only that question: see abi.bootstrapDialer and abi.ensureRefresh.
//
// A cold fetch with no route active is still direct — there is genuinely
// no tunnel to betray, and a device with no routes has to start somewhere.
// The dangerous case is precisely "tunnel up + background timer + direct
// egress", and it is the one this refuses.
var (
	tunnelRequiredMu sync.RWMutex
	tunnelRequired   bool
)

// SetTunnelRequired records whether the engine currently holds an active
// route. Driven by the ABI's route lifecycle, not by the host.
func SetTunnelRequired(b bool) {
	tunnelRequiredMu.Lock()
	tunnelRequired = b
	tunnelRequiredMu.Unlock()
}

// TunnelRequired reports whether egress outside the tunnel is currently
// forbidden.
func TunnelRequired() bool {
	tunnelRequiredMu.RLock()
	defer tunnelRequiredMu.RUnlock()
	return tunnelRequired
}

// directFallback is the same defaulting logic the Refresher used in
// Phase 1.5A — now refusing rather than leaking when a tunnel is up.
func directFallback() (bootstrap.Dialer, bool, error) {
	if TunnelRequired() {
		return nil, false, ErrTunnelRequired
	}
	return bootstrap.NewDirectDialer(15 * time.Second), false, nil
}
