package snowflake

import (
	"context"
	"errors"
	"testing"
	"time"

	"daal/core/rendezvous"
)

func makeChannel(id string, succeed bool) rendezvous.Channel {
	return &stubChannel{id: id, succeed: succeed}
}

type stubChannel struct {
	id      string
	succeed bool
}

func (c *stubChannel) ID() string { return c.id }
func (c *stubChannel) Solicit(ctx context.Context, req rendezvous.Request) (rendezvous.Hint, error) {
	if !c.succeed {
		return rendezvous.Hint{}, errors.New("synthetic")
	}
	return rendezvous.Hint{ChannelID: c.id, BridgeFP: "fp-" + c.id}, nil
}

// TestHandler_UnavailableInBuildWithoutSnowflake — when
// `-tags no_snowflake` is in effect (modelled here by passing
// a nil WebRTCDialer), Dial returns ErrFamilyHandlerUnavailable
// and the upstream code is never invoked.
func TestHandler_UnavailableInBuildWithoutSnowflake(t *testing.T) {
	sel := rendezvous.New([]rendezvous.Channel{makeChannel("domain_fronted_broker", true)}, nil)
	h := NewHandler(sel, nil)
	if h.Available() {
		t.Error("Available() should be false with nil webrtc")
	}
	_, err := h.Dial(context.Background(), Route{RouteID: "rA"})
	if !errors.Is(err, ErrFamilyHandlerUnavailable) {
		t.Errorf("got %v, want ErrFamilyHandlerUnavailable", err)
	}
}

// TestHandler_DialPersistsWinningChannel — a successful Dial
// records the winning channel via the per-route callback.
func TestHandler_DialPersistsWinningChannel(t *testing.T) {
	sel := rendezvous.New([]rendezvous.Channel{
		makeChannel("domain_fronted_broker", false),
		makeChannel("sqs", true),
	}, nil)
	sel.SetHedge(5 * time.Millisecond)

	var got struct {
		routeID, channelID, networkID string
	}
	h := NewHandler(sel, func(ctx context.Context, hint rendezvous.Hint) (*Conn, error) {
		return &Conn{Hint: hint}, nil
	}, WithRecordWinner(func(rid, cid, nid string) {
		got.routeID, got.channelID, got.networkID = rid, cid, nid
	}))
	h.dialDeadline = 200 * time.Millisecond

	conn, err := h.Dial(context.Background(), Route{
		RouteID:            "rA",
		NetworkID:          "net-1",
		RendezvousPriority: []string{"domain_fronted_broker", "sqs"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn.WinningChannel != "sqs" {
		t.Errorf("winning channel: got %q want sqs", conn.WinningChannel)
	}
	if got.routeID != "rA" || got.channelID != "sqs" || got.networkID != "net-1" {
		t.Errorf("recordWinner got (%q,%q,%q)", got.routeID, got.channelID, got.networkID)
	}
}

// TestHandler_AllChannelsFailedMapsToRendezvousErr — when every
// channel returns an error, Dial returns ErrRendezvousFailed
// (the engine maps this to tcp_connect_timeout per the V0
// taxonomy).
func TestHandler_AllChannelsFailedMapsToRendezvousErr(t *testing.T) {
	sel := rendezvous.New([]rendezvous.Channel{
		makeChannel("domain_fronted_broker", false),
		makeChannel("sqs", false),
	}, nil)
	sel.SetHedge(5 * time.Millisecond)
	h := NewHandler(sel, func(ctx context.Context, hint rendezvous.Hint) (*Conn, error) {
		t.Error("webrtc dialer must not run when all channels failed")
		return nil, nil
	})
	_, err := h.Dial(context.Background(), Route{
		RouteID:            "rA",
		RendezvousPriority: []string{"domain_fronted_broker", "sqs"},
	})
	if !errors.Is(err, ErrRendezvousFailed) {
		t.Errorf("got %v, want ErrRendezvousFailed", err)
	}
}

// TestHandler_EmptyPriorityFallsThroughToDefault — a route
// without an explicit RendezvousPriority list uses the
// rendezvous package default order.
func TestHandler_EmptyPriorityFallsThroughToDefault(t *testing.T) {
	sel := rendezvous.New([]rendezvous.Channel{
		makeChannel("domain_fronted_broker", true),
	}, nil)
	h := NewHandler(sel, func(ctx context.Context, hint rendezvous.Hint) (*Conn, error) {
		return &Conn{}, nil
	})
	conn, err := h.Dial(context.Background(), Route{RouteID: "rA"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn.WinningChannel != "domain_fronted_broker" {
		t.Errorf("winner: got %q", conn.WinningChannel)
	}
}

// TestFamilyIDIsSnowflake — the 3A taxonomy mandates the
// family ID; this is a constant-string regression.
func TestFamilyIDIsSnowflake(t *testing.T) {
	if FamilyID != "snowflake" {
		t.Fatalf("FamilyID drifted: %q", FamilyID)
	}
}
