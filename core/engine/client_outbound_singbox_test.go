//go:build singbox

package engine

import (
	"context"
	"testing"

	"daal/core/routestore"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func sampleRowForFamily(family string) routestore.RouteRow {
	return routestore.RouteRow{RouteID: "r1", TransportFamily: family}
}

// TestAssembledClientOutboundsParse validates that the client outbounds
// the publisher assembler emits (FRP-14 Tier-2,
// publisher/deploy/relaypack/client_outbound.go) are accepted by
// sing-box's option decoder after BuildSingBoxConfig wraps them — i.e.
// the recipient engine can actually build a route from them. This
// catches field/shape bugs locally, without a device.
//
// The sample profiles below mirror ClientOutboundForFamily's output for
// each family (kept in sync by hand; both are small and stable). The
// decoder is strict — it rejects unknown fields and wrong nesting — which
// is the whole point: this is the same parser the recipient engine runs.
func TestAssembledClientOutboundsParse(t *testing.T) {
	samples := map[string]struct {
		family  string
		profile string
	}{
		// Wave 2: the REALITY cover host is now per-relay
		// (ClientConnParams.CoverSNI), not a fleet-wide constant, and the
		// TCP/TLS families carry `multiplex` — the only documented
		// defence against the Xue et al. nested-TLS classifier.
		"vless-reality": {"vless-reality", `{
			"type":"vless","tag":"active","server":"78.47.152.16","server_port":443,
			"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",
			"multiplex":{"enabled":true,"protocol":"h2mux","padding":true,"max_streams":64},
			"tls":{"enabled":true,"server_name":"cdn.example-host.net",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "reality":{"enabled":true,"public_key":"0vmceLH_-1xDCVW1dKhUKNw0mof6qoIGLOhMyF6eN28","short_id":"deadbeef"}}}`},
		"websocket-tls": {"websocket-tls", `{
			"type":"vless","tag":"active","server":"78.47.152.16","server_port":443,
			"uuid":"11111111-2222-3333-4444-555555555555",
			"multiplex":{"enabled":true,"protocol":"h2mux","padding":true,"max_streams":64},
			"transport":{"type":"ws","path":"/r1/cafebabe"},
			"tls":{"enabled":true,"server_name":"78.47.152.16",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJhc2U2NA=="}}`},
		// hysteria2 must stay mux-free: sing-mux is a stream layer over
		// one TCP-like connection (head-of-line blocking on a QUIC
		// transport), and option/hysteria2.go has no Multiplex field, so
		// emitting one here would not parse at all.
		"hysteria2": {"hysteria2", `{
			"type":"hysteria2","tag":"active","server":"78.47.152.16","server_port":443,
			"password":"hy2secretpassword22ch",
			"tls":{"enabled":true,"server_name":"78.47.152.16",
			  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJhc2U2NA=="}}`},
		// A pack minted BEFORE Wave 2: legacy fleet-wide cover SNI, no
		// multiplex block. Already-distributed packs render exactly this,
		// and the engine must keep building them.
		"vless-reality-pre-wave2": {"vless-reality", `{
			"type":"vless","tag":"active","server":"78.47.152.16","server_port":443,
			"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",
			"tls":{"enabled":true,"server_name":"www.cloudflare.com",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "reality":{"enabled":true,"public_key":"0vmceLH_-1xDCVW1dKhUKNw0mof6qoIGLOhMyF6eN28","short_id":"deadbeef"}}}`},
		"websocket-tls-pre-wave2": {"websocket-tls", `{
			"type":"vless","tag":"active","server":"78.47.152.16","server_port":443,
			"uuid":"11111111-2222-3333-4444-555555555555",
			"transport":{"type":"ws","path":"/r1/cafebabe"},
			"tls":{"enabled":true,"server_name":"78.47.152.16",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJhc2U2NA=="}}`},
	}

	ctx := include.Context(context.Background())
	for name, s := range samples {
		t.Run(name, func(t *testing.T) {
			cfg, err := BuildSingBoxConfig(sampleRowForFamily(s.family), []byte(s.profile))
			if err != nil {
				t.Fatalf("BuildSingBoxConfig: %v", err)
			}
			// Mirror singBox.Start's preprocessing: the daal-internal
			// route.udp_gated marker is stripped before sing-box sees
			// the config (the path manager already enforced the gate).
			delete(cfg.Route, "udp_gated")
			raw, err := MarshalSingBox(cfg)
			if err != nil {
				t.Fatalf("MarshalSingBox: %v", err)
			}
			if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, raw); err != nil {
				t.Fatalf("sing-box rejected assembled %s config: %v", name, err)
			}
		})
	}
}

// TestMultiplexOnQUICFamilyIsRejected is the negative half of the
// multiplex assertion, and the reason familyCarriesMultiplex is a hard
// gate rather than a default: sing-box's hysteria2 options carry no
// Multiplex field, so a profile that talked the renderer into emitting
// one would produce a route the recipient engine cannot build at all —
// a silently dead tier, not a slower one.
func TestMultiplexOnQUICFamilyIsRejected(t *testing.T) {
	profile := `{
		"type":"hysteria2","tag":"active","server":"78.47.152.16","server_port":443,
		"password":"hy2secretpassword22ch",
		"multiplex":{"enabled":true,"protocol":"h2mux","padding":true,"max_streams":64},
		"tls":{"enabled":true,"server_name":"78.47.152.16",
		  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJhc2U2NA=="}}`
	cfg, err := BuildSingBoxConfig(sampleRowForFamily("hysteria2"), []byte(profile))
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	delete(cfg.Route, "udp_gated")
	raw, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatalf("MarshalSingBox: %v", err)
	}
	ctx := include.Context(context.Background())
	if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, raw); err == nil {
		t.Fatal("expected sing-box to reject multiplex on hysteria2; if this " +
			"ever passes, re-check whether the QUIC tier may now carry mux " +
			"(it still should not: head-of-line blocking)")
	}
}
