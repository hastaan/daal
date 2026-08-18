//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"daal/bundle-go/uri"
	"daal/core/routestore"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

const wgConf = `[Interface]
PrivateKey = SLVvRuBMYzKPPFvQfE0nT4jGgpN0GfmwFCU6Rf1jZ2Y=
Address = 10.13.13.2/32, fd00:1::2/128
MTU = 1420
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
Endpoint = 198.51.100.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

// The same conf with AmneziaWG's Iran-flavoured obfuscation knobs. The
// shipped engine has no AmneziaWG support at all, so this must produce
// the SAME wire shape as the plain conf — a WireGuard endpoint — plus a
// downgrade notice, not an "amnezia-wg" outbound sing-box has never
// heard of.
const awgConf = wgConf + `
[Interface]
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 34
H1 = 1234567890
H2 = 1122334455
H3 = 2233445566
H4 = 3344556677
`

// parseOne runs the importer over a wg-quick body and returns the single
// profile plus its provenance.
func parseOne(t *testing.T, body string) (uri.Profile, uri.Provenance) {
	t.Helper()
	profs, prov, err := uri.ParseAny([]byte(body), "wireguard")
	if err != nil {
		t.Fatalf("ParseAny: %v", err)
	}
	if len(profs) != 1 {
		t.Fatalf("got %d profiles, want 1", len(profs))
	}
	return profs[0], prov
}

// TestPastedWireGuardConfigIsAcceptedBySingBox is the end-to-end proof
// for the CLIENT half of the WireGuard family: importer output, wrapped
// by BuildSingBoxConfig, decoded by the same strict option decoder the
// recipient engine runs.
//
// This is the test that could not have passed before Wave 5, twice over:
// the importer emitted the WireGuard OUTBOUND shape sing-box 1.13.0
// removed, and SingBoxConfig had no `endpoints` field to put an endpoint
// in even if it had emitted one.
func TestPastedWireGuardConfigIsAcceptedBySingBox(t *testing.T) {
	for _, tc := range []struct {
		name         string
		conf         string
		wantAmnezia  bool
		wantDropped  int
		wantFamilyIs string
	}{
		{"plain-wireguard", wgConf, false, 0, "wireguard"},
		// An AmneziaWG conf is imported as plain WireGuard: the family
		// names what is on the wire, because the obfuscation cannot be
		// expressed and the badge must not claim it.
		{"amneziawg-degraded", awgConf, true, 9, "wireguard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prof, prov := parseOne(t, tc.conf)
			if prof.TransportFamily != tc.wantFamilyIs {
				t.Fatalf("family = %q, want %q", prof.TransportFamily, tc.wantFamilyIs)
			}
			if prov.HadAmnezia != tc.wantAmnezia {
				t.Errorf("HadAmnezia = %v, want %v", prov.HadAmnezia, tc.wantAmnezia)
			}
			if len(prov.DroppedParams) != tc.wantDropped {
				t.Errorf("DroppedParams = %v, want %d entries", prov.DroppedParams, tc.wantDropped)
			}
			if tc.wantAmnezia && prov.Downgrade == "" {
				t.Error("a degraded AmneziaWG import must carry a Downgrade notice")
			}
			if !tc.wantAmnezia && prov.Downgrade != "" {
				t.Errorf("plain WireGuard must not claim a downgrade: %q", prov.Downgrade)
			}

			raw, err := uri.MarshalOutbound(prof)
			if err != nil {
				t.Fatalf("MarshalOutbound: %v", err)
			}
			cfg, err := BuildSingBoxConfig(
				routestore.RouteRow{RouteID: "r1", TransportFamily: prof.TransportFamily}, raw)
			if err != nil {
				t.Fatalf("BuildSingBoxConfig: %v", err)
			}

			// A WireGuard route lives in endpoints[], never in
			// outbounds[]: sing-box 1.13 answers a `wireguard` OUTBOUND
			// with "deprecated … use WireGuard endpoint instead", and it
			// does so at DIAL time, so a config that puts it in the
			// wrong array still parses and then silently never works.
			if len(cfg.Endpoints) != 1 {
				t.Fatalf("want 1 endpoint, got %d", len(cfg.Endpoints))
			}
			if cfg.Endpoints[0]["tag"] != "active" {
				t.Errorf("endpoint tag = %v, want active (route.final names it)", cfg.Endpoints[0]["tag"])
			}
			for _, ob := range cfg.Outbounds {
				if ob["type"] == "wireguard" {
					t.Fatalf("wireguard must not appear in outbounds[]: %v", ob)
				}
			}

			delete(cfg.Route, "udp_gated")
			body, err := MarshalSingBox(cfg)
			if err != nil {
				t.Fatalf("MarshalSingBox: %v", err)
			}
			ctx := include.Context(context.Background())
			opts, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, body)
			if err != nil {
				t.Fatalf("sing-box rejected the assembled WireGuard config: %v\n%s", err, body)
			}
			if len(opts.Endpoints) != 1 {
				t.Fatalf("decoded %d endpoints, want 1", len(opts.Endpoints))
			}
			// Assert against the REAL option struct, not a lookalike:
			// this is what proves address/peers/allowed_ips are the
			// field names sing-box 1.13.12 actually reads.
			wg, ok := opts.Endpoints[0].Options.(*boxoption.WireGuardEndpointOptions)
			if !ok {
				t.Fatalf("endpoint options are %T, want *option.WireGuardEndpointOptions", opts.Endpoints[0].Options)
			}
			if len(wg.Address) != 2 {
				t.Errorf("Address = %v, want the two local prefixes from the conf", wg.Address)
			}
			if wg.PrivateKey == "" {
				t.Error("PrivateKey did not survive the round trip")
			}
			if wg.MTU != 1420 {
				t.Errorf("MTU = %d, want 1420", wg.MTU)
			}
			if len(wg.Peers) != 1 {
				t.Fatalf("Peers = %v, want 1", wg.Peers)
			}
			p := wg.Peers[0]
			if p.Address != "198.51.100.7" || p.Port != 51820 {
				t.Errorf("peer endpoint = %s:%d, want 198.51.100.7:51820", p.Address, p.Port)
			}
			if p.PublicKey == "" || p.PreSharedKey == "" {
				t.Errorf("peer keys did not survive: %+v", p)
			}
			if len(p.AllowedIPs) != 2 {
				t.Errorf("AllowedIPs = %v, want both default routes", p.AllowedIPs)
			}
			if len(p.Reserved) != 0 {
				t.Errorf("Reserved = %v; allowed-IPs must never be written into the "+
					"three-byte WARP reserved field", p.Reserved)
			}
			if p.PersistentKeepaliveInterval != 25 {
				t.Errorf("PersistentKeepaliveInterval = %d, want 25", p.PersistentKeepaliveInterval)
			}
		})
	}
}

// TestWireGuardOutboundShapeIsStillRejected is the negative half, and it
// pins the reason the importer had to change rather than the symptom.
// sing-box 1.13 keeps the `wireguard` outbound registered as a STUB, so
// the old shape decodes fine and only fails when a route is dialled —
// which is exactly why nothing caught it. The stub's options type is
// option.StubOptions (no fields at all), so the strict decoder refuses
// the 1.x field set, and that refusal is what this asserts.
func TestWireGuardOutboundShapeIsStillRejected(t *testing.T) {
	legacy := `{"type":"wireguard","tag":"active","server":"198.51.100.7","server_port":51820,
	  "private_key":"SLVvRuBMYzKPPFvQfE0nT4jGgpN0GfmwFCU6Rf1jZ2Y=",
	  "peer_public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	  "local_address":["10.13.13.2/32"]}`
	// Bypass BuildSingBoxConfig's endpoint routing so the object really
	// lands in outbounds[], which is what the old importer produced.
	cfg := &SingBoxConfig{
		Outbounds: []map[string]any{
			mustJSONMap(t, legacy),
			{"tag": "direct", "type": "direct"},
		},
		Route: map[string]any{"final": "active"},
	}
	body, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	if _, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, body); err == nil {
		t.Fatal("expected sing-box to reject the pre-1.11 WireGuard outbound shape")
	}
}

// TestAmneziaFieldsAreNeverEmitted guards the specific regression that
// made the family unusable: `"type":"amnezia-wg"` and an `amnezia`
// object. Neither exists anywhere in sing-box 1.13.12, so emitting
// either is an unknown-type or unknown-field refusal at import.
func TestAmneziaFieldsAreNeverEmitted(t *testing.T) {
	prof, _ := parseOne(t, awgConf)
	raw, err := uri.MarshalOutbound(prof)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"amnezia-wg", `"amnezia"`, `"jc"`, `"h1"`} {
		if strings.Contains(text, forbidden) {
			t.Errorf("emitted %s, which sing-box 1.13.12 does not define: %s", forbidden, text)
		}
	}
}

func mustJSONMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad test JSON: %v", err)
	}
	return m
}
