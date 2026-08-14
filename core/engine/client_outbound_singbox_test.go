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
// each family (kept in sync by hand; both are small and stable).
func TestAssembledClientOutboundsParse(t *testing.T) {
	samples := map[string]string{
		"vless-reality": `{
			"type":"vless","tag":"active","server":"78.47.152.16","server_port":443,
			"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",
			"tls":{"enabled":true,"server_name":"www.cloudflare.com",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "reality":{"enabled":true,"public_key":"cHVia2V5LWJhc2U2NC0zMi1ieXRlcy14eA","short_id":"deadbeef"}}}`,
		"websocket-tls": `{
			"type":"vless","tag":"active","server":"78.47.152.16","server_port":443,
			"uuid":"11111111-2222-3333-4444-555555555555",
			"transport":{"type":"ws","path":"/r1/cafebabe"},
			"tls":{"enabled":true,"server_name":"78.47.152.16",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJhc2U2NA=="}}`,
		"hysteria2": `{
			"type":"hysteria2","tag":"active","server":"78.47.152.16","server_port":443,
			"password":"hy2secretpassword22ch",
			"tls":{"enabled":true,"server_name":"78.47.152.16",
			  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJhc2U2NA=="}}`,
	}

	ctx := include.Context(context.Background())
	for family, profile := range samples {
		t.Run(family, func(t *testing.T) {
			cfg, err := BuildSingBoxConfig(sampleRowForFamily(family), []byte(profile))
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
				t.Fatalf("sing-box rejected assembled %s config: %v", family, err)
			}
		})
	}
}
