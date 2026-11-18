//go:build singbox

package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"daal/bundle-go/bundle"
	"daal/core/routestore"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// parseActive runs a profile through the two steps the engine really
// takes — BuildSingBoxConfig, then the linked sing-box's own option
// decoder — and returns what sing-box understood the active outbound
// to be.
func parseActive(t *testing.T, family, profile string) any {
	t.Helper()
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r1", TransportFamily: family}, []byte(profile))
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	t.Cleanup(retireRefreshInlet)
	delete(cfg.Route, "udp_gated")
	blob, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	options, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, blob)
	if err != nil {
		t.Fatalf("sing-box refused the config (the premise of this test is that it does not): %v", err)
	}
	for _, ob := range options.Outbounds {
		if ob.Tag == "active" {
			return ob.Options
		}
	}
	t.Fatal("no active outbound")
	return nil
}

// WHY bundle.CheckOutbound refuses a member name that is not plain
// lower-case ASCII, shown against the sing-box this engine links.
//
// Each profile below keeps every signed value under its exact name and
// adds the attacker's value under a second spelling. The first half of
// each case pins the premise: sing-box reads the second spelling (if a
// sing-box upgrade ever stops folding names, that half fails and says
// so — the refusal stays correct, it just stops being load-bearing).
// The second half is the property: the endpoint check refuses the
// profile, so it never reaches the engine.
func TestFoldedProfileKeys_SingBoxReadsThem_TheEndpointCheckRefusesThem(t *testing.T) {
	const server = "203.0.113.10"
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	evil := make([]byte, 32)
	evil[0] = 0xEE
	evilPin := base64.StdEncoding.EncodeToString(evil)
	realityKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	evilReality := base64.RawURLEncoding.EncodeToString(evil)

	// "public_Key" with an ASCII K would also be read by sing-box, but
	// it sorts BEFORE "public_key", so after the engine's re-marshal
	// the genuine member comes last and wins. The Kelvin sign sorts
	// after it. Both are refused; only one of them is an attack.
	t.Run("vless-reality: long-s server and Kelvin-sign public_key", func(t *testing.T) {
		ep := &bundle.Endpoint{V: 1, Server: server, Port: 443, ServerName: "cover.example", RealityPublicKey: realityKey}
		genuine := `{"type":"vless","server":"` + server + `","server_port":443,"uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8",` +
			`"tls":{"enabled":true,"server_name":"cover.example","utls":{"enabled":true},` +
			`"reality":{"enabled":true,"public_key":"` + realityKey + `","short_id":"ab"}}}`
		if err := bundle.CheckOutbound("vless-reality", ep, []byte(genuine)); err != nil {
			t.Fatalf("genuine profile refused: %v", err)
		}
		folded := `{"type":"vless","server":"` + server + `","ſerver":"198.51.100.66","server_port":443,"uuid":"6ba7b810-9dad-11d1-80b4-00c04fd430c8",` +
			`"tls":{"enabled":true,"server_name":"cover.example","utls":{"enabled":true},` +
			`"reality":{"enabled":true,"public_key":"` + realityKey + `","public_\u212aey":"` + evilReality + `","short_id":"ab"}}}`
		got, ok := parseActive(t, "vless-reality", folded).(*boxoption.VLESSOutboundOptions)
		if !ok {
			t.Fatal("active outbound is not vless")
		}
		if got.Server != "198.51.100.66" {
			t.Errorf("premise: sing-box no longer reads \"ſerver\" as server (got %q)", got.Server)
		}
		if got.TLS == nil || got.TLS.Reality == nil || got.TLS.Reality.PublicKey != evilReality {
			t.Errorf("premise: sing-box no longer reads \"public_\\u212aey\" (Kelvin sign) as public_key")
		}
		if err := bundle.CheckOutbound("vless-reality", ep, []byte(folded)); !errors.Is(err, bundle.ErrEndpointMismatch) {
			t.Fatalf("the endpoint check accepted a profile sing-box dials elsewhere: err=%v", err)
		}
	})

	t.Run("hysteria2: long-s pin, Insecure, Server_Ports", func(t *testing.T) {
		ep := &bundle.Endpoint{V: 1, Server: server, Port: 443, ServerName: server, TLSSPKISHA256: pin}
		tls := `"enabled":true,"server_name":"` + server + `","certificate_public_key_sha256":"` + pin + `"`
		head := `{"type":"hysteria2","server":"` + server + `","server_port":443,"password":"p-1",`
		if err := bundle.CheckOutbound("hysteria2", ep, []byte(head+`"tls":{`+tls+`}}`)); err != nil {
			t.Fatalf("genuine profile refused: %v", err)
		}
		for name, folded := range map[string]string{
			"pin":          head + `"tls":{` + tls + `,"certificate_public_key_ſha256":["` + evilPin + `"]}}`,
			"Insecure":     head + `"tls":{` + tls + `,"Insecure":true}}`,
			"Server_Ports": head + `"Server_Ports":["1:65535"],"tls":{` + tls + `}}`,
			"Detour":       head + `"Detour":"direct","tls":{` + tls + `}}`,
		} {
			got, ok := parseActive(t, "hysteria2", folded).(*boxoption.Hysteria2OutboundOptions)
			if !ok || got.TLS == nil {
				t.Fatalf("%s: active outbound is not hysteria2 with tls", name)
			}
			var read bool
			switch name {
			case "pin":
				pins := got.TLS.CertificatePublicKeySHA256
				read = len(pins) == 1 && pins[0][0] == 0xEE
			case "Insecure":
				read = got.TLS.Insecure
			case "Server_Ports":
				read = len(got.ServerPorts) == 1
			case "Detour":
				read = got.Detour == "direct"
			}
			if !read {
				t.Errorf("premise: sing-box no longer reads the %s spelling", name)
			}
			if err := bundle.CheckOutbound("hysteria2", ep, []byte(folded)); !errors.Is(err, bundle.ErrEndpointMismatch) {
				t.Errorf("%s: the endpoint check accepted a profile sing-box reads differently: err=%v", name, err)
			}
		}
	})
}
