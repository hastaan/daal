package engine

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"sync"
)

// The refresh inlet — the loopback SOCKS5 listener the engine's own
// sing-box instance exposes so that in-process fetches (subscription
// refresh, revocation refresh, bootstrap refresh) can ride the active
// route instead of egressing from the device's real address.
//
// WHY THIS EXISTS
//
// On Android the VpnService excludes our own package from the TUN
// (addDisallowedApplication(self)); without that exclusion the engine's
// dial to the relay loops back into its own tunnel. The exclusion is
// load-bearing and cannot be removed — but it also means a plain
// net.Dial from inside this process bypasses the tunnel entirely. Wave 1
// closed that leak by refusing to fetch at all while a route is active
// (refresh.ErrTunnelRequired), which was correct and left scheduled
// refresh — including *revocation* refresh — dead on the one platform
// where all four transports are field-proven.
//
// The way back is not to weaken the guard. It is to give the process a
// path that genuinely goes through the tunnel: a SOCKS5 inbound inside
// the same sing-box instance, whose traffic route.final sends to the
// "active" outbound. A fetch dialled at that inlet leaves the device
// over the relay, exactly like app traffic that entered via the TUN.
//
// LOOPBACK EXPOSURE — stated honestly.
//
// Android has no per-UID isolation on 127.0.0.1. Any app on the phone
// holding INTERNET can connect to another app's loopback listener, and
// localhost port-scanning is a technique that has been used in the wild
// to fingerprint and to abuse co-resident apps. An unauthenticated SOCKS
// inlet would therefore be (a) an open proxy any app could push traffic
// through — spending the user's relay and attributing a stranger's
// traffic to their pack — and (b) a reliable "this device is running a
// circumvention tool, and it is connected right now" beacon.
//
// Three mitigations, in decreasing order of how much they actually buy:
//
//  1. SOCKS5 username/password authentication (RFC 1929) with a 128-bit
//     credential generated per route activation. This is the real
//     control: an unauthenticated prober is answered METHOD=0xFF and
//     cannot use the proxy. The credential is created here, travels only
//     inside this process (engine → abi → bootstrap.TunnelDialer), and
//     is never written to a config file on disk, never logged, and never
//     crosses the JNI boundary — the host asks for "tunnel refresh on",
//     not for the secret (see abi.SetTunnelRefresh).
//  2. A kernel-assigned ephemeral port, re-drawn on every activation, so
//     there is no fixed port to look for. On its own this is weak — the
//     ephemeral range is small enough to sweep in seconds — which is why
//     it is second, not first.
//  3. Binding 127.0.0.1 explicitly (never 0.0.0.0), so nothing off the
//     device can reach the inlet even on a hostile LAN.
//
// RESIDUAL, not fixed: a co-resident app that finds the port still
// learns that *something* on this device is speaking SOCKS5 and
// demanding auth. That is a weak signal (many apps run local proxies)
// but it is not zero, and it cannot be removed while the mechanism is a
// TCP listener. The clean fix is a unix-domain socket in the app's
// private directory, which IS UID-isolated — sing-box 1.13's
// ListenOptions.Listen is a netip.Addr, so its socks inbound cannot bind
// one. If that changes upstream, take it.

// refreshInletTag is the inbound tag. Kept distinct from "tun-in" so the
// driver's config-rewrite step and any future routing rule can name it.
const refreshInletTag = "daal-refresh-in"

// RefreshInlet describes one activation's loopback SOCKS5 inlet.
type RefreshInlet struct {
	Host     string
	Port     int
	Username string
	Password string
}

var (
	inletMu      sync.Mutex
	inletPending *RefreshInlet
	inletLive    *RefreshInlet
)

// planRefreshInlet reserves an ephemeral loopback port and mints a fresh
// credential pair. Returns nil if either step fails — a device that will
// not lend us a loopback port still gets a working tunnel, it just does
// not get scheduled refresh (which then stays fail-closed rather than
// falling back to a direct fetch). Degrading the *refresh* capability is
// acceptable; degrading the *connection* is not.
//
// The reserve-then-close is a TOCTOU window: another process could take
// the port between Close and sing-box's bind. It is microseconds wide
// (BuildSingBoxConfig is called immediately before driver.Start) against
// ~28k ports, and the failure mode if it is lost is a failed connect the
// user retries. The alternative — a fixed port — trades a rare race for
// a permanent, scannable, well-known address, which is the worse deal.
func planRefreshInlet() *RefreshInlet {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	if !ok || addr.Port <= 0 {
		return nil
	}
	user, err := randomToken(9)
	if err != nil {
		return nil
	}
	pass, err := randomToken(16)
	if err != nil {
		return nil
	}
	return &RefreshInlet{
		Host:     "127.0.0.1",
		Port:     addr.Port,
		Username: user,
		Password: pass,
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// inboundJSON renders the sing-box inbound. Deliberately minimal: tag,
// type, listen, listen_port, users. sing-box 1.13 REMOVED the legacy
// inbound fields (sniff, domain_strategy, …) and box.New rejects a
// config that still carries them, so anything beyond this set is a
// liability, not a feature.
func (in *RefreshInlet) inboundJSON() map[string]any {
	return map[string]any{
		"tag":         refreshInletTag,
		"type":        "socks",
		"listen":      in.Host,
		"listen_port": in.Port,
		"users": []any{
			map[string]any{"username": in.Username, "password": in.Password},
		},
	}
}

// stageRefreshInlet records the inlet that the config just built asks
// for. It is NOT yet reachable: nothing is listening until the driver
// starts. Pass nil to record "this activation has no inlet".
func stageRefreshInlet(in *RefreshInlet) {
	inletMu.Lock()
	inletPending = in
	inletMu.Unlock()
}

// promoteRefreshInlet publishes the staged inlet as live. The ordering
// contract is the whole point of the two-stage design: a driver calls
// this only after its instance has started, i.e. after sing-box has
// bound every inbound. Until then CurrentRefreshInlet returns nil and
// the host cannot advertise a tunnel dialer that would dial a port
// nobody is listening on.
func promoteRefreshInlet() {
	inletMu.Lock()
	inletLive = inletPending
	inletMu.Unlock()
}

// unpublishRefreshInlet retracts the live inlet but keeps whatever the
// next activation has already staged. Used at the top of a route switch,
// where the outgoing instance is closed before the incoming one binds:
// for that window there is no listener, and the host must not be told
// otherwise.
func unpublishRefreshInlet() {
	inletMu.Lock()
	inletLive = nil
	inletMu.Unlock()
}

// retireRefreshInlet clears both slots. Called when the driver stops, so
// the host can never point a dialer at a dead listener — and so a
// re-activation is forced to draw a fresh port and credential rather
// than reusing the previous session's.
func retireRefreshInlet() {
	inletMu.Lock()
	inletPending = nil
	inletLive = nil
	inletMu.Unlock()
}

// CurrentRefreshInlet returns a copy of the live inlet, or nil when no
// driver is currently listening on one.
func CurrentRefreshInlet() *RefreshInlet {
	inletMu.Lock()
	defer inletMu.Unlock()
	if inletLive == nil {
		return nil
	}
	cp := *inletLive
	return &cp
}
