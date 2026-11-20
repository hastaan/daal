package engine

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"daal/core/desync"
	"daal/core/routestore"
)

const desyncRealityProfile = `{"type":"vless","tag":"active","server":"203.0.113.10","server_port":443,
	"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision",
	"tls":{"enabled":true,"server_name":"cdn.example-host.net","utls":{"enabled":true,"fingerprint":"chrome"},
	  "reality":{"enabled":true,"public_key":"0vmceLH_-1xDCVW1dKhUKNw0mof6qoIGLOhMyF6eN28","short_id":"deadbeef"}}}`

func buildForTest(t *testing.T, row routestore.RouteRow, profile string) map[string]any {
	t.Helper()
	cfg, err := BuildSingBoxConfig(row, []byte(profile))
	if err != nil {
		t.Fatalf("BuildSingBoxConfig: %v", err)
	}
	t.Cleanup(retireRefreshInlet)
	blob, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// activeAndDesync returns the active outbound and the daal-desync one
// (nil when absent).
func activeAndDesync(raw map[string]any) (active, ds map[string]any) {
	for _, ob := range objects(raw["outbounds"].([]any)) {
		switch ob["tag"] {
		case "active":
			active = ob
		case desync.Tag:
			ds = ob
		}
	}
	return active, ds
}

func realityRow(fsc string) routestore.RouteRow {
	return routestore.RouteRow{RouteID: "rt-desync", TransportFamily: "vless-reality", FamilySpecificConfigJSON: fsc}
}

// Nothing turned on: the config is what it was before desync existed —
// no detour, no extra outbound, the same outbound list.
func TestDesyncOffByDefault(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	for _, fsc := range []string{"", "{}", `{"_endpoint":{}}`,
		`{"_desync":{"v":1,"strategy":{"preset":"sni-cut"}}}`,                  // an offer is not "on"
		`{"_desync":{"v":9,"apply":"always","strategy":{"preset":"sni-cut"}}}`, // unknown version: OFF
		`{"_desync":{"v":1,"apply":"always","strategy":{"splitat":[1]}}}`,      // invalid: OFF, not a default
		`{"_desync":{"v":1,"apply":"always","strategy":{"preset":"sni-cut"}}}`, // always is held as an offer (packAlwaysAllowed)
	} {
		raw := buildForTest(t, realityRow(fsc), desyncRealityProfile)
		active, ds := activeAndDesync(raw)
		if ds != nil || active["detour"] != nil {
			t.Errorf("fsc %s: desync applied", fsc)
		}
		if n := len(raw["outbounds"].([]any)); n != 3 {
			t.Errorf("fsc %s: %d outbounds, want active+direct+block", fsc, n)
		}
	}
}

// allowPackAlways opens the pack "always" gate for one test.
func allowPackAlways(t *testing.T) {
	t.Helper()
	packAlwaysAllowed = true
	t.Cleanup(func() { packAlwaysAllowed = false })
}

// desyncNetwork sets the current network for one test and puts the
// package's default ("") back after it.
func desyncNetwork(t *testing.T, id string) {
	t.Helper()
	SetDesyncNetwork(id)
	t.Cleanup(func() { SetDesyncNetwork(""); ClearAllRouteDesync() })
}

// Until tls_fragment has a PASS record, a pack's "always" is an offer:
// nothing is applied, and the ladder can still read it.
func TestDesyncPackAlwaysHeldAsOffer(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	row := realityRow(`{"_desync":{"v":1,"apply":"always","strategy":{"preset":"sni-cut"}}}`)
	if active, ds := activeAndDesync(buildForTest(t, row, desyncRealityProfile)); ds != nil || active["detour"] != nil {
		t.Fatal("a pack's always applied while the gate is closed")
	}
	if o, err := PackDesyncOffer(row); err != nil || o.Apply != desync.ApplyAlways || !o.StrategyValue().Enabled() {
		t.Fatalf("the held offer is not readable: %+v %v", o, err)
	}
}

func TestDesyncPackAlwaysAppliesWhenAllowed(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	allowPackAlways(t)
	raw := buildForTest(t, realityRow(`{"_desync":{"v":1,"apply":"always","strategy":{"preset":"sni-cut"}}}`), desyncRealityProfile)
	active, ds := activeAndDesync(raw)
	if active["detour"] != desync.Tag || ds == nil || ds["type"] != desync.Type {
		t.Fatalf("not applied: active=%v desync=%v", active, ds)
	}
	// The preset is rendered as its fields: what sing-box is handed is
	// the strategy itself, not a name a newer engine might read otherwise.
	st, _ := json.Marshal(ds["strategy"])
	got, err := desync.ParseStrategy(st)
	if err != nil || !reflect.DeepEqual(got, desync.Presets["sni-cut"]) {
		t.Fatalf("rendered strategy %s → %+v, %v", st, got, err)
	}
	// Desync changes how the hello leaves, never where it goes.
	if active["server"] != "203.0.113.10" || active["server_port"] != float64(443) {
		t.Fatal("the outbound's endpoint changed")
	}
	if !SideProbeable(mustJSON(t, raw)) {
		t.Fatal("the engine's own desync detour made the route un-side-probeable")
	}
}

func TestDesyncOverridePrecedence(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	allowPackAlways(t)
	always := realityRow(`{"_desync":{"v":1,"apply":"always","strategy":{"preset":"sni-cut"}}}`)
	offer := realityRow(`{"_desync":{"v":1,"strategy":{"preset":"chain"}}}`)
	none := realityRow("")

	// The ladder forces it off where it hurt: beats the pack's "always".
	if err := SetRouteDesync(always.RouteID, desync.Off); err != nil {
		t.Fatal(err)
	}
	if _, ds := activeAndDesync(buildForTest(t, always, desyncRealityProfile)); ds != nil {
		t.Fatal("override Off did not beat apply=always")
	}
	ClearRouteDesync(always.RouteID)
	if _, ds := activeAndDesync(buildForTest(t, always, desyncRealityProfile)); ds == nil {
		t.Fatal("after ClearRouteDesync the pack's always did not apply")
	}

	// The ladder takes the pack's offer for this network.
	o, err := PackDesyncOffer(offer)
	if err != nil || o.Apply != desync.ApplyOffer {
		t.Fatalf("PackDesyncOffer: %+v %v", o, err)
	}
	if err := SetRouteDesync(offer.RouteID, o.StrategyValue()); err != nil {
		t.Fatal(err)
	}
	_, ds := activeAndDesync(buildForTest(t, offer, desyncRealityProfile))
	if ds == nil {
		t.Fatal("override with the pack's offer not applied")
	}
	st, _ := json.Marshal(ds["strategy"])
	if got, _ := desync.ParseStrategy(st); !reflect.DeepEqual(got, desync.Presets["chain"]) {
		t.Fatalf("applied %s, want the chain preset", st)
	}

	// A route whose pack says nothing: the ladder's own preset.
	if _, err := PackDesyncOffer(none); !errors.Is(err, desync.ErrNoOffer) {
		t.Fatalf("no offer: %v", err)
	}
	if err := SetRouteDesync(none.RouteID, desync.Strategy{Preset: "split1"}); err != nil {
		t.Fatal(err)
	}
	if _, ds := activeAndDesync(buildForTest(t, none, desyncRealityProfile)); ds == nil {
		t.Fatal("override on a route with no offer not applied")
	}
	if err := SetRouteDesync(none.RouteID, desync.Strategy{Preset: "nope"}); err == nil {
		t.Fatal("an invalid override was accepted")
	}
}

// A choice remembered on one network does not follow the phone to
// another, and is gone when it comes back.
func TestDesyncChoiceIsPerNetwork(t *testing.T) {
	desyncNetwork(t, "net-a")
	row := realityRow("")
	if err := SetRouteDesync(row.RouteID, desync.Strategy{Preset: "sni-cut"}); err != nil {
		t.Fatal(err)
	}
	if _, ds := activeAndDesync(buildForTest(t, row, desyncRealityProfile)); ds == nil {
		t.Fatal("not applied on the network it was chosen on")
	}
	SetDesyncNetwork("net-b")
	if _, ds := activeAndDesync(buildForTest(t, row, desyncRealityProfile)); ds != nil {
		t.Fatal("a choice made on net-a applied on net-b")
	}
	// A forced Off does not travel either.
	if err := SetRouteDesync(row.RouteID, desync.Off); err != nil {
		t.Fatal(err)
	}
	if _, ok := routeDesyncChoice(row.RouteID); !ok {
		t.Fatal("the Off choice on net-b was not remembered")
	}
	SetDesyncNetwork("net-a")
	if _, ok := routeDesyncChoice(row.RouteID); ok {
		t.Fatal("net-b's choice applies on net-a")
	}
	if _, ds := activeAndDesync(buildForTest(t, row, desyncRealityProfile)); ds != nil {
		t.Fatal("net-a's old choice came back after a round trip")
	}
}

// A strategy handed to one build is used for that build only: the
// remembered choice is neither read nor changed by it.
func TestDesyncExplicitBuildIsIsolated(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	row := realityRow("")
	build := func(s *desync.Strategy) map[string]any {
		t.Helper()
		var cfg *SingBoxConfig
		var err error
		if s == nil {
			cfg, err = BuildSingBoxConfig(row, []byte(desyncRealityProfile))
		} else {
			cfg, err = BuildSingBoxConfigWithDesync(row, []byte(desyncRealityProfile), *s)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(retireRefreshInlet)
		var raw map[string]any
		_ = json.Unmarshal(mustJSON(t, cfg), &raw)
		return raw
	}
	probe := desync.Strategy{Preset: "chain"}
	if _, ds := activeAndDesync(build(&probe)); ds == nil {
		t.Fatal("the explicit strategy was not applied")
	}
	if _, ds := activeAndDesync(build(nil)); ds != nil {
		t.Fatal("a side probe's strategy leaked into the main tunnel's next build")
	}
	if err := SetRouteDesync(row.RouteID, desync.Strategy{Preset: "sni-cut"}); err != nil {
		t.Fatal(err)
	}
	if _, ds := activeAndDesync(build(&desync.Off)); ds != nil {
		t.Fatal("an explicit Off did not beat the remembered choice")
	}
	if _, ds := activeAndDesync(build(nil)); ds == nil {
		t.Fatal("the remembered choice was lost")
	}
	if _, err := BuildSingBoxConfigWithDesync(row, []byte(desyncRealityProfile), desync.Strategy{Preset: "nope"}); err == nil {
		t.Fatal("an invalid explicit strategy was accepted")
	}
}

// The route outbound's dialer options would be ignored behind a detour:
// they move to the desync outbound, which dials. The resolver stays.
func TestDesyncMovesDialerOptions(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	row := realityRow("")
	if err := SetRouteDesync(row.RouteID, desync.Strategy{Preset: "sni-cut"}); err != nil {
		t.Fatal(err)
	}
	var ob map[string]any
	_ = json.Unmarshal([]byte(desyncRealityProfile), &ob)
	ob["bind_interface"] = "wlan0"
	ob["routing_mark"] = float64(7)
	ob["connect_timeout"] = "5s"
	ob["tcp_multi_path"] = true
	ob["tcp_fast_open"] = false
	ob["network_strategy"] = "fallback"
	ob["fallback_delay"] = "300ms"
	ob["domain_resolver"] = "local"
	active, ds := activeAndDesync(buildForTest(t, row, string(mustJSON(t, ob))))
	if ds == nil {
		t.Fatal("not applied")
	}
	for _, k := range []string{"bind_interface", "routing_mark", "connect_timeout", "tcp_multi_path", "network_strategy"} {
		if _, ok := active[k]; ok {
			t.Errorf("%s left on the detoured outbound, where sing-box ignores it", k)
		}
		if !reflect.DeepEqual(ds[k], ob[k]) {
			t.Errorf("%s: desync outbound has %v, want %v", k, ds[k], ob[k])
		}
	}
	if _, ok := active["tcp_fast_open"]; ok {
		t.Error("a false tcp_fast_open left on the detoured outbound")
	}
	if active["domain_resolver"] != "local" || ds["domain_resolver"] != nil {
		t.Errorf("domain_resolver moved: active %v desync %v", active["domain_resolver"], ds["domain_resolver"])
	}
	if active["fallback_delay"] != "300ms" || ds["fallback_delay"] != "300ms" {
		t.Errorf("fallback_delay: active %v desync %v, want both", active["fallback_delay"], ds["fallback_delay"])
	}
}

// What a profile cannot do with the desync outbound's name.
func TestDesyncProfileCannotNameIt(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	row := realityRow("")
	// A dangling detour (desync off): removed, so box.New does not fail
	// on it and nothing is cut.
	var ob map[string]any
	_ = json.Unmarshal([]byte(desyncRealityProfile), &ob)
	ob["detour"] = desync.Tag
	active, ds := activeAndDesync(buildForTest(t, row, string(mustJSON(t, ob))))
	if ds != nil || active["detour"] != nil {
		t.Fatalf("a profile's own daal-desync detour survived: detour=%v desync=%v", active["detour"], ds)
	}
	for _, p := range []string{
		`{"type":"daal-desync","tag":"active","strategy":{"preset":"sni-cut"}}`,
		`{"type":"direct","tag":"daal-desync"}`,
	} {
		if _, err := BuildSingBoxConfig(row, []byte(p)); err == nil {
			t.Errorf("profile %s accepted", p)
		}
	}
}

// Where the detour cannot sit, turning desync on changes nothing.
func TestDesyncNotApplicable(t *testing.T) {
	t.Cleanup(ClearAllRouteDesync)
	cases := []struct {
		name, family, profile, why string
	}{
		{"hysteria2", "hysteria2", `{"type":"hysteria2","tag":"active","server":"203.0.113.10","server_port":443,"password":"x","tls":{"enabled":true,"server_name":"a"}}`, "udp_family"},
		{"naive", "naive", `{"type":"naive","tag":"active","server":"203.0.113.10","server_port":443,"username":"u","password":"p","tls":{"enabled":true,"server_name":"a"}}`, "type_not_supported"},
		{"detoured", "vless-reality", `{"type":"vless","tag":"active","server":"203.0.113.10","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","detour":"direct"}`, "already_detoured"},
		{"tfo", "vless-reality", `{"type":"vless","tag":"active","server":"203.0.113.10","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tcp_fast_open":true,"tls":{"enabled":true,"server_name":"a"}}`, "tcp_fast_open"},
		{"fragment", "vless-reality", `{"type":"vless","tag":"active","server":"203.0.113.10","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"a","fragment":true}}`, "stock_fragment"},
		{"record_fragment", "trojan", `{"type":"trojan","tag":"active","server":"203.0.113.10","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a","record_fragment":true}}`, "stock_fragment"},
	}
	for _, c := range cases {
		row := routestore.RouteRow{RouteID: "na-" + c.name, TransportFamily: c.family}
		if err := SetRouteDesync(row.RouteID, desync.Strategy{Preset: "sni-cut"}); err != nil {
			t.Fatal(err)
		}
		var ob map[string]any
		_ = json.Unmarshal([]byte(c.profile), &ob)
		if got := desyncApplicable(row, ob); got != c.why {
			t.Errorf("%s: desyncApplicable = %q, want %q", c.name, got, c.why)
		}
		if RouteCanDesync(row, []byte(c.profile)) {
			t.Errorf("%s: RouteCanDesync", c.name)
		}
		raw := buildForTest(t, row, c.profile)
		if _, ds := activeAndDesync(raw); ds != nil {
			t.Errorf("%s: desync outbound added", c.name)
		}
	}
	if !RouteCanDesync(realityRow(""), []byte(desyncRealityProfile)) {
		t.Fatal("RouteCanDesync false for vless-reality")
	}
	// Cuttable but with no TLS hello: the ladder's question says no,
	// though an explicit strategy would still be applied.
	ss := routestore.RouteRow{RouteID: "na-ss", TransportFamily: "shadowsocks"}
	ssProfile := `{"type":"shadowsocks","tag":"active","server":"203.0.113.10","server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"x"}`
	if got := RouteDesyncReason(ss, []byte(ssProfile)); got != "no_tls_hello" {
		t.Fatalf("shadowsocks: RouteDesyncReason = %q, want no_tls_hello", got)
	}
	var ob map[string]any
	_ = json.Unmarshal([]byte(ssProfile), &ob)
	if got := desyncApplicable(ss, ob); got != "" {
		t.Fatalf("shadowsocks: desyncApplicable = %q, want applicable", got)
	}
	for _, p := range []string{
		`{"type":"anytls","tag":"active","server":"203.0.113.10","server_port":443,"password":"p"}`,
		`{"type":"vmess","tag":"active","server":"203.0.113.10","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"a"}}`,
	} {
		if got := RouteDesyncReason(routestore.RouteRow{RouteID: "ok", TransportFamily: "vmess"}, []byte(p)); got != "" {
			t.Errorf("%s: RouteDesyncReason = %q", p, got)
		}
	}
}

// A detour to anything but the engine's own desync outbound still keeps
// a route out of side instances and twins.
func TestOwnDesyncDetourOnly(t *testing.T) {
	foreign := `{"outbounds":[{"tag":"active","type":"vless","server":"203.0.113.10","detour":"daal-desync"},{"tag":"daal-desync","type":"socks"}]}`
	if SideProbeable([]byte(foreign)) {
		t.Fatal("a detour to a non-desync outbound tagged daal-desync was taken for the engine's own")
	}
	own := `{"outbounds":[{"tag":"active","type":"vless","server":"203.0.113.10","detour":"daal-desync"},{"tag":"daal-desync","type":"daal-desync"}]}`
	if !SideProbeable([]byte(own)) {
		t.Fatal("own desync detour not side-probeable")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
