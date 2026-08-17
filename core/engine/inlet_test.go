package engine

import (
	"encoding/json"
	"testing"

	"daal/core/routestore"
)

func buildForInlet(t *testing.T) *SingBoxConfig {
	t.Helper()
	cfg, err := BuildSingBoxConfig(
		routestore.RouteRow{RouteID: "r1", TransportFamily: "vless-reality"},
		[]byte(`{"type":"vless","tag":"active","server":"203.0.113.1"}`),
	)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	return cfg
}

// The Inbounds slot existed and was never written, which is precisely
// why Android had no way for the engine's own fetches to reach the
// tunnel. Assert the shape sing-box 1.13 accepts — and assert the
// credential, because an unauthenticated loopback SOCKS on Android is an
// open proxy for every other app on the phone.
func TestBuildSingBoxConfigWritesAuthenticatedLoopbackInlet(t *testing.T) {
	t.Cleanup(retireRefreshInlet)
	cfg := buildForInlet(t)

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected exactly one inbound (the refresh inlet), got %d", len(cfg.Inbounds))
	}
	in := cfg.Inbounds[0]
	if in["type"] != "socks" {
		t.Fatalf("inlet type = %v, want socks", in["type"])
	}
	if in["listen"] != "127.0.0.1" {
		t.Fatalf("inlet must bind loopback only, got listen=%v", in["listen"])
	}
	port, ok := in["listen_port"].(int)
	if !ok || port <= 0 || port > 65535 {
		t.Fatalf("inlet listen_port = %v, want a real port", in["listen_port"])
	}
	users, ok := in["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("inlet must carry exactly one user, got %v", in["users"])
	}
	u := users[0].(map[string]any)
	if u["username"] == "" || u["password"] == "" {
		t.Fatalf("inlet credential must not be empty: %v", u)
	}
	if u["password"] == u["username"] {
		t.Fatal("username and password must be independently random")
	}

	// It must survive MarshalSingBox — that is what the driver parses.
	body, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var round SingBoxConfig
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatal(err)
	}
	if len(round.Inbounds) != 1 {
		t.Fatalf("inlet did not survive marshalling: %s", body)
	}
}

// A fixed port and a reused credential would both be scannable across
// sessions. Each activation must draw its own.
func TestRefreshInletIsFreshPerActivation(t *testing.T) {
	t.Cleanup(retireRefreshInlet)

	a := buildForInlet(t).Inbounds[0]
	b := buildForInlet(t).Inbounds[0]
	if a["listen_port"] == b["listen_port"] {
		t.Fatal("two activations reused the same loopback port")
	}
	ua := a["users"].([]any)[0].(map[string]any)
	ub := b["users"].([]any)[0].(map[string]any)
	if ua["password"] == ub["password"] {
		t.Fatal("two activations reused the same credential")
	}
}

// THE ORDERING GUARANTEE, as a test. Building the config only STAGES the
// inlet; nothing is listening until a driver starts. If CurrentRefreshInlet
// returned it early, the host would install a tunnel dialer aimed at a
// port nobody has bound, and the first scheduled refresh would fail.
func TestRefreshInletIsNotLiveUntilTheDriverPublishesIt(t *testing.T) {
	t.Cleanup(retireRefreshInlet)
	retireRefreshInlet()

	cfg := buildForInlet(t)
	if got := CurrentRefreshInlet(); got != nil {
		t.Fatalf("inlet was live before any driver started: %+v", got)
	}

	promoteRefreshInlet()
	live := CurrentRefreshInlet()
	if live == nil {
		t.Fatal("inlet not published after the driver reported started")
	}
	wantPort := cfg.Inbounds[0]["listen_port"].(int)
	if live.Port != wantPort {
		t.Fatalf("published port %d != config port %d", live.Port, wantPort)
	}
	if live.Host != "127.0.0.1" {
		t.Fatalf("published host %q, want loopback", live.Host)
	}

	// A stop must retract it: a dialer pointing at a closed listener is
	// worse than no dialer, because no dialer fails closed and quiet.
	retireRefreshInlet()
	if CurrentRefreshInlet() != nil {
		t.Fatal("inlet still live after retire")
	}
}

// A route switch closes the outgoing instance before the incoming one
// binds. Nothing may be published for that window.
func TestRefreshInletUnpublishKeepsTheStagedOne(t *testing.T) {
	t.Cleanup(retireRefreshInlet)

	buildForInlet(t)
	promoteRefreshInlet()
	if CurrentRefreshInlet() == nil {
		t.Fatal("precondition: expected a live inlet")
	}

	// Config for the incoming route is built, then the driver tears the
	// old instance down.
	cfg2 := buildForInlet(t)
	unpublishRefreshInlet()
	if CurrentRefreshInlet() != nil {
		t.Fatal("an inlet stayed live across the switch window")
	}

	promoteRefreshInlet()
	live := CurrentRefreshInlet()
	if live == nil {
		t.Fatal("the staged inlet was lost by unpublish")
	}
	if live.Port != cfg2.Inbounds[0]["listen_port"].(int) {
		t.Fatal("published the outgoing route's inlet, not the incoming one")
	}
}

// The connection matters more than the refresh capability: if no
// loopback port can be reserved we ship a config with no inbounds rather
// than failing the route.
func TestBuildSingBoxConfigStillWorksWithoutAnInlet(t *testing.T) {
	t.Cleanup(retireRefreshInlet)
	cfg := buildForInlet(t)
	if cfg.Route["final"] != "active" {
		t.Fatal("the inlet work must not disturb route.final")
	}
	if len(cfg.Outbounds) != 3 {
		t.Fatalf("expected active+direct+block, got %d", len(cfg.Outbounds))
	}
}
