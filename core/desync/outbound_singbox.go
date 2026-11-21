//go:build singbox

package desync

import (
	"context"
	"errors"
	"net"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// OutboundOptions is the `daal-desync` outbound's configuration: an
// ordinary dialer (no detour of its own) and the strategy. sing-box's
// decoder is strict, so a misspelt strategy member fails the config
// parse, like any other outbound option would.
//
//	{"type": "daal-desync", "tag": "daal-desync", "strategy": {"preset": "sni-cut"}}
type OutboundOptions struct {
	option.DialerOptions
	Strategy Strategy `json:"strategy"`
}

// Outbound dials TCP like a direct outbound and wraps each connection in
// a desync Conn; UDP passes through untouched. Another outbound reaches
// it through `detour`: sing-box's dialer.New honours Detour
// (common/dialer/dialer.go), and the TLS layer of that outbound (uTLS,
// REALITY) then runs its handshake over the wrapped conn.
type Outbound struct {
	outbound.Adapter
	dialer   N.Dialer
	strategy Strategy
}

// Register adds the `daal-desync` outbound type to a registry.
func Register(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, newOutbound)
}

// BoxContext is include.Context with the `daal-desync` outbound type
// registered: the engine's two box-building call sites use it instead
// (core/engine engine_singbox.go and side_singbox.go). Every other
// registry is sing-box's own, built exactly as include.Context builds it.
func BoxContext(ctx context.Context) context.Context {
	reg := include.OutboundRegistry()
	Register(reg)
	return box.Context(ctx, include.InboundRegistry(), reg, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
}

func newOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	if options.Detour != "" {
		return nil, errors.New("daal-desync: `detour` is not supported: it dials the relay itself")
	}
	s, err := options.Strategy.Normalized()
	if err != nil {
		return nil, err
	}
	// The same dialer construction as every stock outbound, from the
	// same context: whatever socket control the platform contributes
	// (protect(), interface binding, routing mark) applies here exactly
	// as it would to the outbound that names us as its detour.
	d, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:  outbound.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		dialer:   d,
		strategy: s,
	}, nil
}

// DialContext dials and, for TCP, wraps. Nothing about the destination
// is logged: it is the relay's address.
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	conn, err := h.dialer.DialContext(ctx, network, destination)
	if err != nil || N.NetworkName(network) != N.NetworkTCP {
		return conn, err
	}
	return Wrap(conn, h.strategy), nil
}

// ListenPacket passes UDP through: there is no hello to cut.
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	return h.dialer.ListenPacket(ctx, destination)
}
