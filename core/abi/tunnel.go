package abi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"daal/core/bootstrap"
	"daal/core/refresh"
)

// Phase 1.5B — TunnelDialer wiring.
//
// SetTunnelSocks (engine_set_tunnel_socks) lets the host process tell
// the engine "here is a SOCKS5 endpoint on loopback that fronts the
// active sing-box outbound." When set, all subsequent
// core/refresh fetches (subscription + revocation) go through it. When
// the host clears it (host empty), refreshes revert to direct dial.
//
// Privacy invariants (CC.6 + ABI privacy contract):
//   - The function takes only host/port + optional username/password.
//   - It never accepts or returns a destination URL.
//   - It is idempotent and stateless other than the in-process dialer slot.
//   - The function is callable while a refresh is in-flight; the next
//     fetch picks up the new endpoint.

// tunnelEndpoint is the in-process record of the host-supplied SOCKS5.
type tunnelEndpoint struct {
	host     string
	port     int
	username string
	password string
}

var (
	tunnelMu      sync.RWMutex
	tunnelCurrent *tunnelEndpoint
)

// SetTunnelSocks is the Go-side implementation of engine_set_tunnel_socks.
//
// host==""  → clear the override; refreshes revert to direct dial.
// host!="" → install a TunnelDialer; refreshes flow through it.
//
// Returns a small JSON envelope describing the applied state.
func SetTunnelSocks(host string, port int, username, password string) (string, error) {
	if host == "" {
		clearTunnel()
		body, _ := json.Marshal(map[string]any{
			"applied":  true,
			"endpoint": "",
		})
		return string(body), nil
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("abi: invalid socks port %d", port)
	}
	// We do not resolve the hostname; loopback IP is the supported
	// case, but accepting a literal hostname is fine.
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	tunnelMu.Lock()
	tunnelCurrent = &tunnelEndpoint{
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
	tunnelMu.Unlock()

	// Install the global dialer factory. We deliberately re-construct
	// the TunnelDialer per fetch so the stored endpoint is the only
	// state; nothing about the connection is cached.
	refresh.SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		ep := currentTunnel()
		if ep == nil {
			// The endpoint was cleared underneath us. If a route is
			// still active this must NOT become a direct dial — see
			// refresh.ErrTunnelRequired.
			if refresh.TunnelRequired() {
				return nil, false, refresh.ErrTunnelRequired
			}
			return bootstrap.NewDirectDialer(15 * time.Second), false, nil
		}
		// DirectFallback is deliberately nil while a route is active:
		// TunnelDialer falls back to it whenever SocksAddress is empty,
		// which would reintroduce the very leak this guard closes if the
		// inlet ever went away mid-session. TunnelDialer already returns
		// a clean error for a nil fallback.
		var escape bootstrap.Dialer
		if !refresh.TunnelRequired() {
			escape = bootstrap.NewDirectDialer(15 * time.Second)
		}
		// Credentials are honoured (RFC 1929). Empty means "offer no
		// auth", which is the desktop sidecar's unauthenticated
		// loopback inlet; the in-process Android inlet always supplies
		// a per-activation pair — see core/engine/inlet.go for why an
		// unauthenticated loopback SOCKS on Android is an open proxy
		// for every other app on the device.
		return &bootstrap.TunnelDialer{
			SocksAddress:   net.JoinHostPort(ep.host, strconv.Itoa(ep.port)),
			Username:       ep.username,
			Password:       ep.password,
			DirectFallback: escape,
			Timeout:        15 * time.Second,
		}, true, nil
	})

	body, _ := json.Marshal(map[string]any{
		"applied":  true,
		"endpoint": addr,
	})
	return string(body), nil
}

func clearTunnel() {
	tunnelMu.Lock()
	tunnelCurrent = nil
	tunnelMu.Unlock()
	refresh.SetGlobalDialer(nil)
}

func currentTunnel() *tunnelEndpoint {
	tunnelMu.RLock()
	defer tunnelMu.RUnlock()
	if tunnelCurrent == nil {
		return nil
	}
	cp := *tunnelCurrent
	return &cp
}

// resetTunnelForShutdown clears the override on Shutdown so a
// subsequent Init() in the same process starts fresh.
func resetTunnelForShutdown() {
	clearTunnel()
}

var _ = errors.New
