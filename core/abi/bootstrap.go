package abi

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"daal/core/bootstrap"
	"daal/core/bootstrap/embedded"
	"daal/core/pathmanager"
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
	dialerFn := func() bootstrap.Dialer {
		// Phase 1D: only direct dialer is wired. The TunnelDialer hook
		// lands when the engine exposes a SOCKS5 inlet (V1.5.5).
		return bootstrap.NewDirectDialer(15 * time.Second)
	}
	globalBootstrap.provider = bootstrap.NewProvider(c.store, c.adapter,
		globalBootstrap.manifest, dialerFn, nowUTC)
	return globalBootstrap.provider, nil
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
