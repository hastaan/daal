package abi

import (
	"context"
	"errors"
	"testing"
	"time"

	"daal/core/bootstrap"
	"daal/core/refresh"
)

// The scheduled bootstrap refresh is the third of the three kinds
// core/scheduler fires while the tunnel is up (KindSubscription,
// KindRevocation, KindBootstrap). Wave 1 closed the direct-egress leak
// for the first two and exempted the third; these tests pin that the
// exemption is gone and cannot come back by accident.
//
// The exemption's stated reason — "a first fetch has to start
// somewhere" — is still honoured, but only in the state it is actually
// true of: no route active.

func TestBootstrapDialer_FailsClosedWhileARouteIsActive(t *testing.T) {
	refresh.SetGlobalDialer(nil)
	refresh.SetTunnelRequired(true)
	t.Cleanup(func() {
		refresh.SetTunnelRequired(false)
		refresh.SetGlobalDialer(nil)
	})

	d := bootstrapDialer()
	if d == nil {
		t.Fatal("bootstrapDialer returned nil")
	}
	// The dialer must exist (Provider's signature has no error channel)
	// but must refuse rather than open a socket from the real address.
	conn, err := d.DialContext(context.Background(), "tcp", "example.invalid:443")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("bootstrap dialed a real socket while a route was active")
	}
	if !errors.Is(err, refresh.ErrTunnelRequired) {
		t.Fatalf("err = %v, want refresh.ErrTunnelRequired", err)
	}
	// And it must NOT be a direct dialer wearing a different name.
	if _, ok := d.(refusingDialer); !ok {
		t.Fatalf("bootstrapDialer returned %T, want refusingDialer", d)
	}
}

func TestBootstrapDialer_DirectWhenNoRouteIsActive(t *testing.T) {
	refresh.SetGlobalDialer(nil)
	refresh.SetTunnelRequired(false)

	d := bootstrapDialer()
	if _, ok := d.(refusingDialer); ok {
		t.Fatal("a cold bootstrap with no active route must still be allowed to dial")
	}
}

func TestBootstrapDialer_PrefersTheInstalledTunnelDialer(t *testing.T) {
	want := bootstrap.NewDirectDialer(time.Second) // stand-in identity
	refresh.SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		return want, true, nil
	})
	refresh.SetTunnelRequired(true)
	t.Cleanup(func() {
		refresh.SetTunnelRequired(false)
		refresh.SetGlobalDialer(nil)
	})

	if got := bootstrapDialer(); got != want {
		t.Fatalf("bootstrapDialer = %#v, want the installed tunnel dialer", got)
	}
}

// A factory that refuses mid-session (endpoint cleared while the route
// is still up) must not degrade into a direct dial — that is exactly the
// hole abi.SetTunnelSocks's own nil-endpoint branch guards on the
// subscription path.
func TestBootstrapDialer_HonoursAFactoryThatRefuses(t *testing.T) {
	sentinel := errors.New("inlet went away")
	refresh.SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		return nil, false, sentinel
	})
	refresh.SetTunnelRequired(true)
	t.Cleanup(func() {
		refresh.SetTunnelRequired(false)
		refresh.SetGlobalDialer(nil)
	})

	_, err := bootstrapDialer().DialContext(context.Background(), "tcp", "example.invalid:443")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the factory's own error", err)
	}
}
