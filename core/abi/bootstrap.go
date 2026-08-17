package abi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"daal/core/bootstrap"
	"daal/core/bootstrap/embedded"
	"daal/core/pathmanager"
	"daal/core/refresh"
)

// bootstrapState holds the initialised provider. The manifest is loaded
// lazily from the embedded sub-package on first use; tests can swap the
// manifest via SetBootstrapManifestForTest.
type bootstrapState struct {
	mu       sync.Mutex
	manifest *bootstrap.Manifest
	provider *bootstrap.Provider
}

var globalBootstrap = &bootstrapState{}

// resetBootstrapForShutdown clears the cached Provider so a subsequent
// Init() picks up the new store.
func resetBootstrapForShutdown() {
	globalBootstrap.mu.Lock()
	globalBootstrap.provider = nil
	globalBootstrap.mu.Unlock()
}

// SetBootstrapManifestForTest replaces the embedded manifest. Tests only.
func SetBootstrapManifestForTest(m *bootstrap.Manifest) {
	globalBootstrap.mu.Lock()
	globalBootstrap.manifest = m
	globalBootstrap.provider = nil
	globalBootstrap.mu.Unlock()
}

func ensureBootstrap() (*bootstrap.Provider, error) {
	// Snapshot loadedCore() once so a concurrent Shutdown can't null it
	// out between the check and the use. ensureBootstrap is reachable
	// from gomobile-bound entry points the Android UI polls during
	// the Init/Shutdown window.
	c := loadedCore()
	if c == nil {
		return nil, errors.New("abi: not initialized")
	}
	globalBootstrap.mu.Lock()
	defer globalBootstrap.mu.Unlock()
	if globalBootstrap.provider != nil {
		return globalBootstrap.provider, nil
	}
	if globalBootstrap.manifest == nil {
		m, err := embedded.LoadManifest()
		if err != nil {
			return nil, err
		}
		globalBootstrap.manifest = m
	}
	globalBootstrap.provider = bootstrap.NewProvider(c.store, c.adapter,
		globalBootstrap.manifest, bootstrapDialer, nowUTC)
	return globalBootstrap.provider, nil
}

// bootstrapDialer picks the dialer for one directory fetch.
//
// WHY THIS IS NOT `NewDirectDialer` ANY MORE — a leak that survived
// Wave 1, found 2026-08-17 during the Wave 2 repair pass.
//
// Wave 1 made SUBSCRIPTION and REVOCATION refresh fail closed while a
// route is active (refresh.ErrTunnelRequired), because on Android the
// engine's own UID is excluded from the TUN and a plain net.Dial from
// this process therefore leaves over the censored network from the
// user's real address. Bootstrap was deliberately exempted, on the
// stated rationale that "with no route active there is no tunnel to
// betray, and a first fetch has to start somewhere."
//
// That rationale is true of the COLD fetch and false of the scheduled
// one. core/scheduler emits KindBootstrap on a 24 h cadence regardless
// of connection state (core/scheduler/plan.go:138,206), the tick pump
// runs precisely while the tunnel is up (DaalVpnService.startSchedulerPump),
// and abi/scheduler.go's refreshExecutor.RefreshBootstrap lands right
// here. So the exemption was not "the first fetch is allowed to be
// direct" — it was "a fixed-cadence TLS fetch to a known bootstrap
// directory host egresses in the clear, from a residential address,
// while the UI says connected." Same signal Wave 1 called close to the
// worst thing this tool can emit; it just arrived on a different kind.
//
// The rule is now uniform across all three refresh kinds:
//
//	tunnel dialer installed → use it;
//	no dialer but a route is active → refuse (fail closed);
//	no route active → direct, because a cold start has to begin
//	somewhere and there is no tunnel to betray.
func bootstrapDialer() bootstrap.Dialer {
	// The process-wide override wins, exactly as it does in
	// refresh.Refresher.dial(): it is what SetTunnelSocks (desktop
	// sidecar) and SetTunnelRefresh (in-process inlet) install.
	if fn := refresh.CurrentGlobalDialer(); fn != nil {
		d, _, err := fn()
		if err == nil && d != nil {
			return d
		}
		// The installed factory refused (endpoint cleared mid-session
		// while a route is up). Do NOT silently fall through to direct.
		return refusingDialer{err: errOrTunnelRequired(err)}
	}
	if refresh.TunnelRequired() {
		return refusingDialer{err: refresh.ErrTunnelRequired}
	}
	return bootstrap.NewDirectDialer(15 * time.Second)
}

func errOrTunnelRequired(err error) error {
	if err != nil {
		return err
	}
	return refresh.ErrTunnelRequired
}

// refusingDialer is how "this fetch does not happen" is expressed to
// bootstrap.Provider, whose dialerFn signature has no error channel.
// Provider.Refresh walks every pointer, gets this from each, and
// returns the error as its own — so the caller sees a failed refresh
// with ErrTunnelRequired in the reason string, never a direct fetch.
type refusingDialer struct{ err error }

func (d refusingDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, d.err
}

// BootstrapInstallSeeds is engine_bootstrap_install_seeds.
//
// Gap 5: announce bootstrap discovery onto the posture axis so the
// GUI can render the discovery affordance. The transition is legal
// only from PostureNoRoute; if the device already has an active
// posture (re-running InstallSeeds after a connection), the
// illegal-but-harmless transition is ignored.
func BootstrapInstallSeeds() (string, error) {
	p, err := ensureBootstrap()
	if err != nil {
		return "", err
	}
	res, err := p.InstallSeeds()
	if err != nil {
		return "", err
	}
	if c := loadedCore(); c != nil && c.pm != nil {
		_ = c.pm.SetPosture(pathmanager.EventBootstrapStart, pathmanager.PostureBootstrapDiscovery)
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// BootstrapRefresh is engine_bootstrap_refresh.
func BootstrapRefresh(timeoutMs int) (string, error) {
	if timeoutMs <= 0 {
		timeoutMs = 15000
	}
	p, err := ensureBootstrap()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	res, err := p.Refresh(ctx, time.Duration(timeoutMs)*time.Millisecond)
	// Gap 5: when a real directory came back, advance the posture
	// to ImportedActive. The transition is legal from
	// BootstrapDiscovery (the canonical path) and from NoRoute (cold
	// refresh without an InstallSeeds first). From any other active
	// posture the transition is illegal and silently ignored — we
	// don't want to clobber e.g. ExperimentalActive or Lifeline just
	// because a background refresh succeeded.
	if err == nil && res.DirectoryFetched {
		if c := loadedCore(); c != nil && c.pm != nil {
			_ = c.pm.SetPosture(pathmanager.EventDirectoryFetched, pathmanager.PostureImportedActive)
		}
	}
	body, _ := json.Marshal(res)
	if err != nil {
		// Still return JSON so callers can inspect res.Reason; surface err
		// only when we have nothing useful to report.
		if res.Reason == "" {
			return "", err
		}
	}
	return string(body), nil
}

// BootstrapStatus is engine_bootstrap_status.
func BootstrapStatus() (string, error) {
	if loadedCore() == nil {
		return "", errors.New("abi: not initialized")
	}
	p, err := ensureBootstrap()
	if err != nil {
		return "", err
	}
	st, err := p.Status()
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(st)
	return string(out), nil
}

var _ = errors.New
