package abi

import (
	"encoding/json"
	"errors"
	"sync/atomic"

	"daal/core/engine"
	"daal/core/refresh"
)

// SetTunnelRefresh is the Go-side implementation of
// engine_set_tunnel_refresh — the call that restores scheduled refresh
// on platforms where the engine runs sing-box IN-PROCESS (Android).
//
// WHY IT EXISTS RATHER THAN THE HOST CALLING SetTunnelSocks DIRECTLY.
//
// On desktop the SOCKS inlet belongs to a sidecar process the host
// spawned, so the host is the only party that knows the endpoint and
// engine_set_tunnel_socks(host, port, …) is the right shape. On Android
// there is no sidecar: the inlet is an inbound in the engine's own
// generated config, so the ENGINE is the only party that knows the
// endpoint — and, since that inlet is authenticated (see
// core/engine/inlet.go), it is also the only party that holds the
// credential.
//
// Handing that credential out over JNI so Kotlin could hand it back is
// pure exposure with no benefit: it would put a live proxy password
// into the JVM heap, into any crash dump, and one careless Log.d from a
// diagnostic build. So the host asks a question it can answer —
// "is the tunnel up? then turn refresh on" — and this function does the
// rest, calling SetTunnelSocks with values that never leave the process.
//
// ORDERING CONTRACT. enabled=true fails unless a driver has already
// published a live inlet, which engine/inlet.go only does once the
// sing-box instance has started and therefore bound its inbounds. The
// host cannot get this wrong by calling too early: it gets an error and
// refresh stays fail-closed (refresh.ErrTunnelRequired), which is the
// safe direction. Calling too LATE only costs one scheduler cadence.
//
// enabled=false clears the process-wide dialer slot outright, which is
// the same slot the desktop sidecar path uses. That is fine because the
// two hosts are mutually exclusive — a build either runs sing-box
// in-process or shells out to a sidecar — but a host that somehow did
// both must not interleave these calls.
func SetTunnelRefresh(enabled bool) (string, error) {
	if !enabled {
		tunnelRefreshWanted.Store(false)
		clearTunnel()
		body, _ := json.Marshal(map[string]any{
			"applied":   true,
			"tunnelled": false,
		})
		return string(body), nil
	}
	inlet := engine.CurrentRefreshInlet()
	if inlet == nil {
		return "", errors.New(
			"abi: no live refresh inlet; the engine driver is not running " +
				"one (call after engine_set_route succeeds, and only on a " +
				"build whose driver hosts sing-box in-process)")
	}
	if _, err := SetTunnelSocks(inlet.Host, inlet.Port, inlet.Username, inlet.Password); err != nil {
		return "", err
	}
	tunnelRefreshWanted.Store(true)
	// Deliberately no endpoint and no credential in the envelope: the
	// host does not need either, and this string is the kind of thing
	// that ends up in a log.
	body, _ := json.Marshal(map[string]any{
		"applied":       true,
		"tunnelled":     true,
		"authenticated": inlet.Username != "" || inlet.Password != "",
	})
	return string(body), nil
}

// TunnelRefreshActive reports whether a tunnel-aware dialer is installed
// right now. Exposed for the host's own diagnostics and for tests; it
// says nothing about whether a fetch is in flight.
func TunnelRefreshActive() bool {
	return refresh.CurrentGlobalDialer() != nil && currentTunnel() != nil
}

// tunnelRefreshWanted: the host's last word through SetTunnelRefresh was
// "on". Every engine instance has an inlet of its own (a new port, a new
// credential — core/engine/inlet.go), so the dialer SetTunnelRefresh
// installed points at the instance that was running THEN.
var tunnelRefreshWanted atomic.Bool

// rearmTunnelRefresh points scheduled refresh at the inlet of the
// instance that is running now, when the host had turned tunnelled
// refresh on. The engine calls it after every instance it starts — the
// host cannot know about the ones the engine starts by itself (the
// automatic connect moving to another route, the instance of a route
// being put back, the way back from a switch that failed), and a dialer
// left on a dead inlet fails closed: no subscription, no revocation
// list, for as long as the person stays connected.
//
// Reports whether a dialer was installed. Nothing leaves the process and
// nothing about the inlet is logged.
func rearmTunnelRefresh() bool {
	if !tunnelRefreshWanted.Load() {
		return false
	}
	inlet := engine.CurrentRefreshInlet()
	if inlet == nil {
		return false
	}
	if _, err := SetTunnelSocks(inlet.Host, inlet.Port, inlet.Username, inlet.Password); err != nil {
		return false
	}
	return true
}
