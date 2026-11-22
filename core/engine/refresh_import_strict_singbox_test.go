//go:build singbox

package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"daal/core/refresh"

	"github.com/sagernet/sing-box/include"
	boxoption "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// TestEverySubscriptionRouteParses is TestEveryImportedOutboundParses
// for the OTHER way a stranger's links reach the engine: a subscription
// URL that core/refresh re-reads in the background. That path has its
// own readers (base64/URI list, Clash, SIP008), and its output never
// passed through the strict-parse test, so a refresh could store routes
// the engine rejects at connect and nothing would fail until a phone.
//
// It builds one base64 subscription out of every single-link vector the
// importer accepts and one out of every link it refuses, runs both plus
// a Clash and a SIP008 body through refresh.ParseSubscriptionBody, and
// hands each stored route to BuildSingBoxConfig and the same
// singjson.UnmarshalExtendedContext[option.Options] decoder
// engine_singbox.go Start uses. It also checks the refused links are
// reported by code (ParsedSubscription.Refusals) instead of vanishing.
func TestEverySubscriptionRouteParses(t *testing.T) {
	raw, err := os.ReadFile(importVectorsFile)
	if err != nil {
		t.Fatalf("read %s: %v", importVectorsFile, err)
	}
	var doc struct {
		Accepted []struct {
			Name  string `json:"name"`
			Input string `json:"input"`
			Hint  string `json:"hint"`
		} `json:"accepted"`
		Refused []struct {
			Name  string `json:"name"`
			Input string `json:"input"`
			Code  string `json:"code"`
		} `json:"refused"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var good, bad []string
	var clash []string
	for _, v := range doc.Accepted {
		switch {
		case v.Hint == "" && strings.Contains(v.Input, "://") && !strings.Contains(v.Input, "\n"):
			good = append(good, v.Input)
		case v.Hint == "clash" || strings.Contains(v.Input, "proxies:"):
			clash = append(clash, v.Input)
		}
	}
	var wantCodes []string
	for _, v := range doc.Refused {
		bad = append(bad, v.Input)
		wantCodes = append(wantCodes, v.Code)
	}
	if len(good) < 10 || len(bad) < 10 || len(clash) == 0 {
		t.Fatalf("vector file too thin: %d accepted links, %d refused, %d clash", len(good), len(bad), len(clash))
	}

	mixed := strings.Join(append(append([]string{}, good...), bad...), "\n")
	bodies := map[string][]byte{
		"base64":   []byte(base64.StdEncoding.EncodeToString([]byte(mixed))),
		"uri-list": []byte(mixed),
		"sip008": []byte(`{"version":1,"servers":[` +
			`{"id":"a","remarks":"a","server":"s.example.com","server_port":8388,"password":"pw","method":"aes-256-gcm"},` +
			`{"id":"b","remarks":"b","server":"s.example.com","server_port":8389,"password":"pw","method":"none"}]}`),
	}
	for i, c := range clash {
		bodies["clash-"+string(rune('a'+i))] = []byte(c)
	}

	ctx := include.Context(context.Background())
	seen := map[string]bool{}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			sub, err := refresh.ParseSubscriptionBody(body, "vectors")
			if err != nil {
				t.Fatalf("ParseSubscriptionBody: %v", err)
			}
			if strings.HasPrefix(name, "base64") || name == "uri-list" {
				if len(sub.Routes) != len(good) {
					t.Errorf("%d routes, want %d (one per accepted link)", len(sub.Routes), len(good))
				}
				got := append([]string{}, sub.Refusals...)
				want := append([]string{}, wantCodes...)
				sort.Strings(got)
				sort.Strings(want)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("refusals = %v\nwant       %v", got, want)
				}
			}
			if name == "sip008" && (len(sub.Routes) != 1 || len(sub.Refusals) != 1 || sub.Refusals[0] != "plaintext_refused") {
				t.Errorf("sip008: %d routes, refusals %v; want 1 route and [plaintext_refused]", len(sub.Routes), sub.Refusals)
			}
			for _, r := range sub.Routes {
				var ob map[string]any
				if err := json.Unmarshal(r.OutboundJSON, &ob); err != nil {
					t.Fatalf("%s: outbound is not JSON: %v", r.RouteID, err)
				}
				typ, _ := ob["type"].(string)
				seen[typ] = true
				cfg, err := BuildSingBoxConfig(sampleRowForFamily(r.TransportFamily), r.OutboundJSON)
				if err != nil {
					t.Fatalf("%s: BuildSingBoxConfig: %v", r.RouteID, err)
				}
				delete(cfg.Route, "udp_gated")
				merged, err := MarshalSingBox(cfg)
				if err != nil {
					t.Fatal(err)
				}
				opts, err := singjson.UnmarshalExtendedContext[boxoption.Options](ctx, merged)
				if err != nil {
					t.Fatalf("sing-box 1.13.12 rejected the refreshed %s route %s (family %s): %v",
						typ, r.RouteID, r.TransportFamily, err)
				}
				checkImportedOptions(t, opts)
				// A stranger's Trojan or VLESS+TLS server never gets the
				// badge of a Daal tier (parse.go once mapped every trojan
				// entry to websocket-tls).
				if (typ == "trojan" || typ == "vmess") && r.TransportFamily != "other" {
					t.Errorf("%s route %s has family %q, want other", typ, r.RouteID, r.TransportFamily)
				}
			}
		})
	}
	for _, must := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"} {
		if !seen[must] {
			t.Errorf("no refreshed route produced a %s outbound", must)
		}
	}
}
