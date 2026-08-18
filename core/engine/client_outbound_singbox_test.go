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
// each family, KEPT IN SYNC BY HAND — and that is exactly as unreliable
// as it sounds: the samples had websocket-tls on port 443 for two waves
// after relayports moved it to 8445, and naive, a shipped stable family,
// had no sample at all. Do not add new families here.
//
// TestEveryMintedOutboundParses (client_outbound_matrix_singbox_test.go)
// is the one that follows the renderer: it parses the publisher's real
// generated output for every family. What survives HERE is the set of
// vectors that renderer cannot produce — the pre-Wave-2 shapes that
// already-distributed packs carry and the engine must keep building.
//
// The decoder is strict — it rejects unknown fields and wrong nesting —
// which is the whole point: this is the same parser the recipient engine
// runs.
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
		// WAVE 5 — shadowsocks-2022, the only family here with no `tls`
		// block at all. That absence is the point: every other sample
		// above opens with a TLS handshake, so the Xue et al. nested-TLS
		// classifier threatens them together, and this one is outside it.
		//
		// Three shapes are load-bearing and all three are real
		// option/shadowsocks.go fields (ShadowsocksOutboundOptions):
		//   - `password` is "<box iPSK>:<recipient uPSK>", each half
		//     padded base64-std of 16 bytes. sing-shadowsocks2 splits on
		//     ":" and StdEncoding-decodes each half, then refuses any key
		//     that is not exactly the method's length.
		//   - `udp_over_tcp` is the route's ONLY UDP: the box inbound is
		//     network=tcp on a single opened port.
		//   - NO `multiplex`, because the shadowsocks outbound builds a
		//     UoT client OR a mux client and never both — the loser is
		//     discarded silently, so a mux block here would be a claim
		//     the pack does not deliver.
		"shadowsocks": {"shadowsocks", `{
			"type":"shadowsocks","tag":"active","server":"78.47.152.16","server_port":8446,
			"method":"2022-blake3-aes-128-gcm",
			"password":"bW9jay1ib3gtaXBzay0xNg==:bW9jay11c2VyLXVwc2sxNg==",
			"udp_over_tcp":{"enabled":true,"version":2}}`},
		// Wave 5. tuic mirrors ClientOutboundForFamily's "tuic" case.
		// The `alpn` is not decoration: sing-quic's tuic client and
		// service never set NextProtos (its hysteria2 pair defaults to
		// h3), and quic-go requires an application protocol on both
		// ends, so an alpn-less tuic route fails the QUIC handshake
		// rather than degrading. Note the port: 8443/udp, not 443 —
		// hysteria2 owns 443/udp and two UDP inbounds on one port is a
		// relay that does not boot (BUG-14).
		"tuic": {"tuic", `{
			"type":"tuic","tag":"active","server":"78.47.152.16","server_port":8443,
			"uuid":"11111111-2222-3333-4444-555555555555","password":"tuicsecretpassword22c",
			"congestion_control":"bbr",
			"tls":{"enabled":true,"server_name":"78.47.152.16","alpn":["h3"],
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
		// WAVE 5 — anytls. Byte-for-byte what
		// publisher/deploy/relaypack/client_outbound.go emits for this
		// family; TestAnyTLSOutboundMatchesPinnedShape in the publisher
		// module asserts the renderer still produces exactly this, so
		// the "kept in sync by hand" note above does not apply here.
		//
		// The three idle-session keys are the whole reason the family is
		// worth having, so a strict parse of THEM is the point of this
		// vector: they are option.AnyTLSOutboundOptions' real field
		// names, and badoption.Duration is what makes "30s" decode. No
		// `padding_scheme` — the outbound options have no such field,
		// because the server dictates the scheme in band.
		"anytls": {"anytls", `{
			"type":"anytls","tag":"active","server":"78.47.152.16","server_port":8447,
			"password":"YW55dGxzLXBlci1yZWNpcGllbnQtcGFzc3dvcmQtMzJi",
			"min_idle_session":1,
			"idle_session_check_interval":"30s",
			"idle_session_timeout":"30s",
			"tls":{"enabled":true,"server_name":"78.47.152.16",
			  "utls":{"enabled":true,"fingerprint":"chrome"},
			  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJpbi1iYXNlNjQ="}}`},
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

// TestMultiplexOnAnyTLSIsRejected is the negative half of the anytls
// multiplex decision, and it is the reason familyCarriesMultiplex
// returns false for this family rather than merely defaulting to off.
//
// anytls already multiplexes: streams ride reused sessions, and the
// padding scheme is applied over that layer. Stacking sing-mux on top
// would be two multiplexers deep over one connection — but the config
// never gets that far, because option.AnyTLSOutboundOptions has no
// Multiplex field at all, so a profile that talked the renderer into
// emitting one would produce a route the recipient engine cannot build.
// A silently dead tier, not a slower one.
func TestMultiplexOnAnyTLSIsRejected(t *testing.T) {
	profile := `{
		"type":"anytls","tag":"active","server":"78.47.152.16","server_port":8447,
		"password":"YW55dGxzLXBlci1yZWNpcGllbnQtcGFzc3dvcmQtMzJi",
		"min_idle_session":1,
		"multiplex":{"enabled":true,"protocol":"h2mux","padding":true,"max_streams":64},
		"tls":{"enabled":true,"server_name":"78.47.152.16",
		  "certificate_public_key_sha256":"c3BraS1zaGEyNTYtcGluLWJpbi1iYXNlNjQ="}}`
	cfg, err := BuildSingBoxConfig(sampleRowForFamily("anytls"), []byte(profile))
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
		t.Fatal("expected sing-box to reject multiplex on anytls; if this ever " +
			"passes, re-check whether stacking sing-mux over anytls's own " +
			"session layer is wanted (it still should not be)")
	}
}

// TestMultiplexOnTUICIsRejected is the tuic twin of the hysteria2
// assertion below, and the reason client_outbound.go emits no multiplex
// block for tuic even though the profile schema could carry one:
// option.TUICOutboundOptions has no Multiplex field at all, so a mux
// tuic outbound is not a slower route, it is a route the recipient
// engine cannot build.
func TestMultiplexOnTUICIsRejected(t *testing.T) {
	profile := `{
		"type":"tuic","tag":"active","server":"78.47.152.16","server_port":8443,
		"uuid":"11111111-2222-3333-4444-555555555555","password":"tuicsecretpassword22c",
		"multiplex":{"enabled":true,"protocol":"h2mux","padding":true,"max_streams":64},
		"tls":{"enabled":true,"server_name":"78.47.152.16","alpn":["h3"]}}`
	cfg, err := BuildSingBoxConfig(sampleRowForFamily("tuic"), []byte(profile))
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
		t.Fatal("expected sing-box to reject multiplex on tuic")
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
