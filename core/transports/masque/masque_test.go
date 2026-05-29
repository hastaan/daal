package masque

import (
	"context"
	"errors"
	"testing"
	"time"
)

func okDialer(label string) SubmodeDialer {
	return func(ctx context.Context, endpoint string) (*Conn, error) {
		return &Conn{Endpoint: endpoint, Submode: Submode("dialer:" + label)}, nil
	}
}

// TestFamilyIDIsMasque — the 3A taxonomy mandates the family
// ID; this is a constant-string regression.
func TestFamilyIDIsMasque(t *testing.T) {
	if FamilyID != "masque" {
		t.Fatalf("FamilyID drifted: %q", FamilyID)
	}
}

// TestSubmodesClosedAtV1 — the v1 closed list of three
// sub-modes; the constants and the predicate must agree. A
// 4th value is a roadmap-level decision.
func TestSubmodesClosedAtV1(t *testing.T) {
	want := []Submode{SubmodeH3QUIC, SubmodeH2Connect, SubmodeLifeline}
	got := AllSubmodes()
	if len(got) != len(want) {
		t.Fatalf("AllSubmodes len: got %d want %d", len(got), len(want))
	}
	for i, sm := range want {
		if got[i] != sm {
			t.Errorf("AllSubmodes[%d]: got %q want %q", i, got[i], sm)
		}
		if !IsKnownSubmode(string(sm)) {
			t.Errorf("IsKnownSubmode(%q) = false; want true", sm)
		}
	}
	if IsKnownSubmode("masque_h3_tcp") {
		t.Error("IsKnownSubmode accepted a non-v1 value")
	}
	if IsKnownSubmode("") {
		t.Error("IsKnownSubmode accepted empty string")
	}
}

// TestChooseSubmode_OverrideWins — when the engine pins a
// sub-mode via engine_set_masque_submode_override, that value
// is used regardless of UDP probe outcome or netmem hint.
// Exception: lifeline-strict mode clamps the override down to
// the lifeline rung (the strict budget rules win).
func TestChooseSubmode_OverrideWins(t *testing.T) {
	cases := []struct {
		name     string
		route    Route
		override string
		want     Submode
	}{
		{"override h3 with udp broken", Route{UDPProbeOK: false, Mode: "normal"}, string(SubmodeH3QUIC), SubmodeH3QUIC},
		{"override h2 with udp ok", Route{UDPProbeOK: true, Mode: "normal"}, string(SubmodeH2Connect), SubmodeH2Connect},
		{"override h3 against netmem hint", Route{LastUsedSubmode: string(SubmodeLifeline), Mode: "normal"}, string(SubmodeH3QUIC), SubmodeH3QUIC},
		// lifeline-strict clamps even an h3 override to lifeline.
		{"override h3 clamped by strict", Route{UDPProbeOK: true, Mode: "lifeline-strict"}, string(SubmodeH3QUIC), SubmodeLifeline},
		{"override lifeline in strict mode passes through", Route{Mode: "lifeline-strict"}, string(SubmodeLifeline), SubmodeLifeline},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := chooseSubmode(c.route, c.override)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}

	// Unknown override → ErrUnknownSubmode.
	if _, err := chooseSubmode(Route{Mode: "normal"}, "masque_h3_over_avian"); !errors.Is(err, ErrUnknownSubmode) {
		t.Errorf("unknown override: got %v, want ErrUnknownSubmode", err)
	}
}

// TestChooseSubmode_LifelineStrictHintsLifeline — without an
// override, lifeline-strict mode + masque family auto-hints
// the lifeline rung. Per locked decision: the dual-keyed
// answer is "sub-mode flag canonical; lifeline-strict pins
// lifeline rung; override wins."
func TestChooseSubmode_LifelineStrictHintsLifeline(t *testing.T) {
	got, err := chooseSubmode(Route{Mode: "lifeline-strict", UDPProbeOK: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != SubmodeLifeline {
		t.Errorf("strict mode no override: got %q want %q", got, SubmodeLifeline)
	}
	// Without strict mode, UDP-probe-OK should pick H3QUIC.
	got, _ = chooseSubmode(Route{Mode: "normal", UDPProbeOK: true}, "")
	if got != SubmodeH3QUIC {
		t.Errorf("normal mode udp ok: got %q want %q", got, SubmodeH3QUIC)
	}
}

// TestChooseSubmode_NetmemHintBiasesStart — a netmem hint
// from a previous session on this network biases the start
// rung over the UDP-probe outcome (step 3 of the cascade
// runs before step 4/5).
func TestChooseSubmode_NetmemHintBiasesStart(t *testing.T) {
	// UDP probe says OK (would normally pick H3QUIC) but
	// netmem hint says H2 was the last working rung — bias
	// to H2.
	got, _ := chooseSubmode(Route{
		Mode:            "normal",
		UDPProbeOK:      true,
		LastUsedSubmode: string(SubmodeH2Connect),
	}, "")
	if got != SubmodeH2Connect {
		t.Errorf("netmem hint not honoured: got %q want %q", got, SubmodeH2Connect)
	}
	// An out-of-list netmem hint is ignored (defence in depth);
	// the cascade falls through to the UDP-probe step.
	got, _ = chooseSubmode(Route{
		Mode:            "normal",
		UDPProbeOK:      true,
		LastUsedSubmode: "masque_quantum",
	}, "")
	if got != SubmodeH3QUIC {
		t.Errorf("invalid netmem hint should fall through; got %q", got)
	}
}

// TestChooseSubmode_UDPProbeDrivesDefault — without override
// or netmem hint, the 2C UDP probe outcome decides between
// H3QUIC (UDP works) and H2Connect (UDP broken).
func TestChooseSubmode_UDPProbeDrivesDefault(t *testing.T) {
	got, _ := chooseSubmode(Route{Mode: "normal", UDPProbeOK: true}, "")
	if got != SubmodeH3QUIC {
		t.Errorf("udp ok: got %q want H3QUIC", got)
	}
	got, _ = chooseSubmode(Route{Mode: "normal", UDPProbeOK: false}, "")
	if got != SubmodeH2Connect {
		t.Errorf("udp broken: got %q want H2Connect", got)
	}
}

// TestChooseSubmode_H2BurnedDropsToLifelineInLifelineModes —
// step 6 of the cascade. H2Burned + mode in {lifeline,
// lifeline-strict} → drop to lifeline rung.
func TestChooseSubmode_H2BurnedDropsToLifelineInLifelineModes(t *testing.T) {
	// In lifeline mode, UDP broken + H2 burned → drop.
	got, _ := chooseSubmode(Route{Mode: "lifeline", UDPProbeOK: false, H2Burned: true}, "")
	if got != SubmodeLifeline {
		t.Errorf("lifeline + h2 burned: got %q want %q", got, SubmodeLifeline)
	}
	// In normal mode, the burn does NOT drop — the path manager
	// is expected to pick a different route entirely.
	got, _ = chooseSubmode(Route{Mode: "normal", UDPProbeOK: false, H2Burned: true}, "")
	if got != SubmodeH2Connect {
		t.Errorf("normal + h2 burned: got %q want %q", got, SubmodeH2Connect)
	}
}

// TestHandler_UnavailableInBuildWithoutMasque — when all
// three dialer callbacks are nil (modelling -tags no_masque),
// Dial returns ErrFamilyHandlerUnavailable.
func TestHandler_UnavailableInBuildWithoutMasque(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	if h.Available() {
		t.Error("Available() should be false with all dialers nil")
	}
	_, err := h.Dial(context.Background(), Route{
		RouteID: "rA", MasqueEndpoint: "https://x/m",
	})
	if !errors.Is(err, ErrFamilyHandlerUnavailable) {
		t.Errorf("got %v, want ErrFamilyHandlerUnavailable", err)
	}
}

// TestHandler_DialPersistsChosenSubmode — a successful Dial
// fires the recordSubmode callback with (routeID, submode,
// networkID). Verifies the engine layer's persistence hook
// shape.
func TestHandler_DialPersistsChosenSubmode(t *testing.T) {
	var got struct {
		routeID, networkID string
		submode            Submode
	}
	h := NewHandler(
		okDialer("h3"),
		okDialer("h2"),
		okDialer("ll"),
		WithRecordSubmode(func(rid string, sm Submode, nid string) {
			got.routeID, got.submode, got.networkID = rid, sm, nid
		}),
	)
	h.dialDeadline = 200 * time.Millisecond

	conn, err := h.Dial(context.Background(), Route{
		RouteID:        "r-m1",
		NetworkID:      "net-99",
		MasqueEndpoint: "https://example.com/m",
		Mode:           "normal",
		UDPProbeOK:     true, // → H3QUIC
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn.Submode != SubmodeH3QUIC {
		t.Errorf("conn.Submode: got %q want %q", conn.Submode, SubmodeH3QUIC)
	}
	if conn.Endpoint != "https://example.com/m" {
		t.Errorf("conn.Endpoint: got %q", conn.Endpoint)
	}
	if got.routeID != "r-m1" || got.networkID != "net-99" || got.submode != SubmodeH3QUIC {
		t.Errorf("recordSubmode got (%q, %q, %q)", got.routeID, got.networkID, got.submode)
	}
}

// TestHandler_OverrideFnPinsSubmode — engine_set_masque_submode_override
// pins the rung via the override closure.
func TestHandler_OverrideFnPinsSubmode(t *testing.T) {
	pinned := string(SubmodeH2Connect)
	h := NewHandler(
		okDialer("h3"),
		okDialer("h2"),
		okDialer("ll"),
		WithOverrideFn(func() string { return pinned }),
	)
	conn, err := h.Dial(context.Background(), Route{
		RouteID:        "r-pin",
		MasqueEndpoint: "https://x/m",
		Mode:           "normal",
		UDPProbeOK:     true, // would normally pick H3QUIC
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn.Submode != SubmodeH2Connect {
		t.Errorf("override-pinned: got %q want H2Connect", conn.Submode)
	}
}

// TestHandler_NoEndpointRejected — defence in depth. The
// bundle parser rejects masque routes without an endpoint;
// the handler also refuses, so engine-internal call sites
// cannot accidentally surface a route without a target.
func TestHandler_NoEndpointRejected(t *testing.T) {
	h := NewHandler(okDialer("h3"), okDialer("h2"), okDialer("ll"))
	_, err := h.Dial(context.Background(), Route{
		RouteID: "rA",
		Mode:    "normal",
	})
	if !errors.Is(err, ErrNoEndpoint) {
		t.Errorf("got %v, want ErrNoEndpoint", err)
	}
}

// TestHandler_SubmodeUnreachableWhenDialerMissing — chooseSubmode
// picks H3QUIC but the build only supplied H2; Dial returns
// ErrSubmodeUnreachable so the engine layer can downgrade
// rather than skip the route entirely.
func TestHandler_SubmodeUnreachableWhenDialerMissing(t *testing.T) {
	h := NewHandler(nil, okDialer("h2"), okDialer("ll"))
	_, err := h.Dial(context.Background(), Route{
		RouteID:        "rA",
		MasqueEndpoint: "https://x/m",
		Mode:           "normal",
		UDPProbeOK:     true, // → H3QUIC, but h3 dialer is nil
	})
	if !errors.Is(err, ErrSubmodeUnreachable) {
		t.Errorf("got %v, want ErrSubmodeUnreachable", err)
	}
}
