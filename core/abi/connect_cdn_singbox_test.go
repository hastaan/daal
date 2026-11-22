//go:build singbox

package abi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"daal/core/routestore"
)

// Every config the ladder builds for a CDN-fronted route (its own ECH
// hello, the split one, a plain one) and for a standby is one sing-box's
// own option decoder accepts — the fields the ladder sets
// (tls.record_fragment, tls.fragment, tls.ech, server) are real
// sing-box options, not names it would ignore.
func TestCDNAndStandbyVariantsParseAsSingBox(t *testing.T) {
	f := newCDNFixtureOpts(t, cdnTestECH, true)
	row := routestore.RouteRow{RouteID: "c1", TransportFamily: "websocket-tls"}
	lr := ladderRoute{row: row, profile: []byte(f.profile), cdn: f.ep, ech: true}
	sbRow := routestore.RouteRow{RouteID: "r1", TransportFamily: "vless-reality"}
	sbLR := ladderRoute{row: sbRow, profile: []byte(sbPrimaryREALITY), standby: sbAddr}
	ctx := include.Context(context.Background())
	for name, c := range map[string]struct {
		lr ladderRoute
		v  routeVariant
	}{
		"ech":     {lr, routeVariant{}},
		"split":   {lr, routeVariant{hello: helloSplit}},
		"plain":   {lr, routeVariant{hello: helloPlain}},
		"standby": {sbLR, routeVariant{standby: true}},
	} {
		t.Run(name, func(t *testing.T) {
			body, err := buildVariant(c.lr, c.v)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(body, &cfg); err != nil {
				t.Fatal(err)
			}
			if r, ok := cfg["route"].(map[string]any); ok {
				delete(r, "udp_gated")
			}
			raw, _ := json.Marshal(cfg)
			opts, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, raw)
			if err != nil {
				t.Fatalf("sing-box refuses the %s config: %v", name, err)
			}
			for _, ob := range opts.Outbounds {
				if ob.Tag != "active" {
					continue
				}
				v, ok := ob.Options.(*boxoption.VLESSOutboundOptions)
				if !ok {
					t.Fatalf("active outbound is %T", ob.Options)
				}
				tls := v.OutboundTLSOptionsContainer.TLS
				switch name {
				case "split":
					if !tls.Fragment || !tls.RecordFragment || tls.ECH == nil || !tls.ECH.Enabled {
						t.Fatalf("split hello: %+v", tls)
					}
				case "plain":
					if tls.ECH != nil && tls.ECH.Enabled {
						t.Fatal("plain hello kept ECH")
					}
				case "ech":
					if tls.ECH == nil || !tls.ECH.Enabled || len(tls.Certificate) != 1 {
						t.Fatalf("ECH hello: %+v", tls)
					}
				case "standby":
					if v.Server != sbAddr {
						t.Fatalf("standby dials %s", v.Server)
					}
				}
			}
		})
	}
}
