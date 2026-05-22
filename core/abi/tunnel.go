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
			return bootstrap.NewDirectDialer(15 * time.Second), false, nil
		}
		// Ignore username/password for now: Phase 1.5B's sing-box
		// SOCKS5 inlet is unauthenticated on loopback. We carry the
		// fields in the ABI for forward compatibility (V2 may add
		// per-process auth tokens).
		_ = ep.username
		_ = ep.password
		return &bootstrap.TunnelDialer{
			SocksAddress:   net.JoinHostPort(ep.host, strconv.Itoa(ep.port)),
			DirectFallback: bootstrap.NewDirectDialer(15 * time.Second),
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
