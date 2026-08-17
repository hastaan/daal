package refresh

import (
	"errors"
	"testing"
)

// The leak this guards against, found 2026-08-17: on Android the engine's
// sockets are excluded from the TUN by design, no tunnel-aware dialer is
// installed on that platform, and the scheduled refreshes therefore dialled
// out in the clear — from the user's real address, on a fixed cadence, while
// the UI read "connected". For a censorship-circumvention tool that beacon is
// worse than the feature being unavailable, so the dialer fails closed.
//
// These tests pin the behaviour rather than the implementation: the property
// is "while a route is active, no code path hands out a direct dialer".

func TestDirectFallback_RefusesWhileTunnelRequired(t *testing.T) {
	t.Cleanup(func() { SetTunnelRequired(false) })

	SetTunnelRequired(true)
	d, viaTunnel, err := directFallback()
	if !errors.Is(err, ErrTunnelRequired) {
		t.Fatalf("want ErrTunnelRequired, got err=%v", err)
	}
	if d != nil {
		t.Fatal("a dialer was returned while a tunnel was required — that is the leak")
	}
	if viaTunnel {
		t.Fatal("viaTunnel must be false when the fetch was refused")
	}
}

func TestDirectFallback_AllowedWhenNoRouteIsActive(t *testing.T) {
	t.Cleanup(func() { SetTunnelRequired(false) })

	// Bootstrap must still work: with no route there is no tunnel to
	// betray, and a first fetch has to start somewhere.
	SetTunnelRequired(false)
	d, viaTunnel, err := directFallback()
	if err != nil {
		t.Fatalf("bootstrap direct dial must be permitted, got %v", err)
	}
	if d == nil {
		t.Fatal("expected a direct dialer when no route is active")
	}
	if viaTunnel {
		t.Fatal("a direct dial must not claim to be tunnelled")
	}
}

// The Refresher's own Dialer field must not become a way around the guard:
// dial() consults the global override, then r.Dialer, then directFallback.
// A per-instance dialer is legitimate (tests, desktop), so it is allowed —
// but the DEFAULT path, which is what the scheduler uses in production, must
// refuse.
func TestRefresherDial_DefaultPathRefusesWhileTunnelRequired(t *testing.T) {
	t.Cleanup(func() {
		SetTunnelRequired(false)
		SetGlobalDialer(nil)
	})

	SetGlobalDialer(nil)
	SetTunnelRequired(true)

	r := &Refresher{} // no override, no per-instance dialer: the scheduler's shape
	if _, _, err := r.dial(); !errors.Is(err, ErrTunnelRequired) {
		t.Fatalf("Refresher.dial must fail closed, got %v", err)
	}

	rr := &RevocationRefresher{}
	if _, _, err := rr.dial(); !errors.Is(err, ErrTunnelRequired) {
		t.Fatalf("RevocationRefresher.dial must fail closed, got %v", err)
	}
}

func TestTunnelRequired_RoundTrips(t *testing.T) {
	t.Cleanup(func() { SetTunnelRequired(false) })
	if TunnelRequired() {
		t.Fatal("default must be permissive — bootstrap needs a first fetch")
	}
	SetTunnelRequired(true)
	if !TunnelRequired() {
		t.Fatal("SetTunnelRequired(true) did not take")
	}
	SetTunnelRequired(false)
	if TunnelRequired() {
		t.Fatal("SetTunnelRequired(false) did not take")
	}
}
