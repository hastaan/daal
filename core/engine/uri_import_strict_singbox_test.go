//go:build singbox

package engine

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"daal/bundle-go/uri"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// importVectorsFile is the importer's shared vector list. It lives with
// the parsers (bundle/go/uri) because that module has no sing-box
// dependency and so cannot run the engine's parse itself; this test is
// the half that can.
const importVectorsFile = "../../bundle/go/uri/testdata/import_vectors.json"

// TestEveryImportedOutboundParses is TestEveryMintedOutboundParses for
// routes that did NOT come from a Daal publisher: every pasted link,
// subscription line, Clash entry and wg-quick conf the importer accepts
// is run through BuildSingBoxConfig and then the strict decoder
// engine_singbox.go Start runs (singjson.UnmarshalExtendedContext with
// DisallowUnknownFields). Before this test the importer wrote REALITY
// spider_x and VLESS encryption, which that decoder rejects, so the most
// shared link format in Iran imported with a stable badge and failed at
// connect on the phone.
//
// It also asserts the importer's own invariants on the parsed options,
// where the decoder is too lenient to catch them: REALITY has uTLS
// (otherwise sing-box's REALITY client refuses to start), ALPN is a
// real list, and hysteria2 server_ports entries are "start:end".
func TestEveryImportedOutboundParses(t *testing.T) {
	raw, err := os.ReadFile(importVectorsFile)
	if err != nil {
		t.Fatalf("read %s: %v", importVectorsFile, err)
	}
	var doc struct {
		Accepted []struct {
			Name   string `json:"name"`
			Input  string `json:"input"`
			Hint   string `json:"hint"`
			Family string `json:"family"`
		} `json:"accepted"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// A silently thin list would make this pass forever.
	seen := map[string]bool{}
	ctx := include.Context(context.Background())
	for _, v := range doc.Accepted {
		t.Run(v.Name, func(t *testing.T) {
			var profs []uri.Profile
			if v.Hint == "" && strings.Contains(v.Input, "://") && !strings.Contains(v.Input, "\n") {
				p, _, err := uri.ParseURI(v.Input)
				if err != nil {
					t.Fatalf("importer refused an accepted vector: %v", err)
				}
				profs = []uri.Profile{p}
			} else {
				ps, _, err := uri.ParseAny([]byte(v.Input), v.Hint)
				if err != nil {
					t.Fatalf("importer refused an accepted vector: %v", err)
				}
				profs = ps
			}
			for _, p := range profs {
				typ, _ := p.Outbound["type"].(string)
				seen[typ] = true
				body, err := uri.MarshalOutbound(p)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := BuildSingBoxConfig(sampleRowForFamily(p.TransportFamily), body)
				if err != nil {
					t.Fatalf("BuildSingBoxConfig: %v", err)
				}
				delete(cfg.Route, "udp_gated")
				merged, err := MarshalSingBox(cfg)
				if err != nil {
					t.Fatal(err)
				}
				opts, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, merged)
				if err != nil {
					t.Fatalf("sing-box 1.13.12 rejected the imported %s outbound: %v\n\noutbound: %s", typ, err, body)
				}
				checkImportedOptions(t, opts)
			}
		})
	}
	for _, must := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "wireguard"} {
		if !seen[must] {
			t.Errorf("no accepted vector produced a %s outbound; %s is stale", must, importVectorsFile)
		}
	}
}

func checkImportedOptions(t *testing.T, opts boxoption.Options) {
	t.Helper()
	for _, ob := range opts.Outbounds {
		if ob.Tag != "active" {
			continue
		}
		var tls *boxoption.OutboundTLSOptions
		switch o := ob.Options.(type) {
		case *boxoption.VLESSOutboundOptions:
			tls = o.TLS
		case *boxoption.TrojanOutboundOptions:
			tls = o.TLS
		case *boxoption.VMessOutboundOptions:
			tls = o.TLS
		case *boxoption.TUICOutboundOptions:
			tls = o.TLS
		case *boxoption.Hysteria2OutboundOptions:
			tls = o.TLS
			for _, r := range o.ServerPorts {
				lo, hi, ok := strings.Cut(r, ":")
				if !ok || lo == "" || hi == "" {
					t.Errorf("server_ports entry %q is not start:end (sing-quic ParsePorts fails at connect)", r)
				}
			}
			if len(o.ServerPorts) > 0 && o.HopInterval <= 0 {
				t.Error("server_ports without hop_interval")
			}
		}
		if tls == nil {
			continue
		}
		if tls.Reality != nil && tls.Reality.Enabled && (tls.UTLS == nil || !tls.UTLS.Enabled) {
			t.Error("REALITY without uTLS: sing-box's REALITY client refuses to start")
		}
		for _, a := range tls.ALPN {
			if strings.Contains(a, ",") {
				t.Errorf("ALPN element %q is a joined list", a)
			}
		}
	}
}
