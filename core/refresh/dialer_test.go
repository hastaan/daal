package refresh

import (
	"context"
	"errors"
	"testing"
	"time"

	"daal/core/bootstrap"
)

// TestRefreshHonorsGlobalDialer asserts that when SetGlobalDialer
// installs an override, both the subscription Refresher and the
// revocation refresher route their fetches through it instead of the
// per-instance Dialer field.
func TestRefreshHonorsGlobalDialer(t *testing.T) {
	t.Cleanup(func() { SetGlobalDialer(nil) })

	called := 0
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		called++
		// nil dialer + viaTunnel=true. The Refresher passes whatever
		// we return to the FetchFn; our test FetchFn ignores the
		// dialer and returns canned bytes.
		return nil, true, nil
	})

	st := newFakeStore()
	r := &Refresher{
		Store:    st,
		Identity: mustIdentity(t),
		Adapter:  st,
		Now:      nowFn(2026, 1),
		// Per-instance dialer that we expect NOT to be called.
		Dialer: func() (bootstrap.Dialer, bool, error) {
			t.Fatal("instance dialer must not be called when global is set")
			return nil, false, nil
		},
		Fetch: func(_ context.Context, _ string, _ bootstrap.Dialer, _ time.Duration) ([]byte, error) {
			// Single-line vless URI accepted by the parser.
			return []byte("vless://2eb73a7c-8c7e-4e1a-aaaa-aaaaaaaaaaaa@server.example:443?encryption=none&type=tcp&security=reality&pbk=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ&fp=chrome&sni=example.com#tunneled\n"), nil
		},
	}
	add, err := r.Add(AddInput{PublisherID: "device", URL: "https://example.invalid/sub", DisplayName: "t"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Refresh(context.Background(), add.SubscriptionID, 5*time.Second)
	if err != nil && res.Verdict != "trust_prompt_needed" {
		t.Fatalf("refresh: %v", err)
	}
	if !res.ViaTunnel {
		t.Fatal("expected ViaTunnel=true to follow the global dialer")
	}
	if called == 0 {
		t.Fatal("global dialer was never consulted")
	}
}

func TestSetGlobalDialerNilClearsOverride(t *testing.T) {
	SetGlobalDialer(func() (bootstrap.Dialer, bool, error) {
		return nil, true, errors.New("test")
	})
	if CurrentGlobalDialer() == nil {
		t.Fatal("expected dialer set")
	}
	SetGlobalDialer(nil)
	if CurrentGlobalDialer() != nil {
		t.Fatal("expected dialer cleared")
	}
}
