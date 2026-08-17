package abi

import (
	"encoding/json"
	"errors"

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
