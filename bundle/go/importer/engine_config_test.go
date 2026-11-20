package importer_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/bundle-go/importer"
)

// The engine's part of a signed route's family_specific_config — its
// `_desync` offer and its `_cover_names` — reaches the store with the
// route; `_endpoint` (an address and a key) and `_relaypack` never do.
// A route with no signed endpoint gets none of it.
func TestImport_EngineConfigTravelsWithASignedRouteOnly(t *testing.T) {
	cover := json.RawMessage(`{"v":1,"names":[{"id":1,"name":"answered.example","class":"mirror","reality":true}]}`)
	desync := json.RawMessage(`{"v":1,"strategy":{"preset":"chain"}}`)
	body := makeBundle(t, func(m *bundle.Manifest) {
		addRelayPack(t, m)
		for i := range m.Routes {
			var fc map[string]json.RawMessage
			_ = json.Unmarshal(m.Routes[i].FamilySpecificConfig, &fc)
			fc[bundle.CoverNamesKey], fc["_desync"] = cover, desync
			m.Routes[i].FamilySpecificConfig, _ = json.Marshal(fc)
		}
	})
	st := newFakeState()
	now := time.Now().UTC()
	if _, err := importer.ImportBytes(body, st, wordlists(), now); err != nil {
		t.Fatal(err)
	}
	if v, err := importer.AcceptTrustPrompt("trust", body, st, wordlists(), now); err != nil || v.Kind != importer.VerdictImported {
		t.Fatalf("%v %+v", err, v)
	}
	for _, ri := range st.saved[0] {
		if !strings.Contains(ri.EngineConfig, bundle.CoverNamesKey) || !strings.Contains(ri.EngineConfig, "_desync") {
			t.Fatalf("route %s: engine config %q", ri.RouteID, ri.EngineConfig)
		}
		for _, leak := range []string{bundle.EndpointKey, "5.75.0.1", "fixture-reality-public-key", "_relaypack"} {
			if strings.Contains(ri.EngineConfig, leak) {
				t.Fatalf("route %s: engine config holds %q: %s", ri.RouteID, leak, ri.EngineConfig)
			}
		}
	}

	plain := makeBundle(t, func(m *bundle.Manifest) {
		for i := range m.Routes {
			m.Routes[i].FamilySpecificConfig = json.RawMessage(`{"_cover_names":` + string(cover) + `}`)
		}
	})
	st = newFakeState()
	if _, err := importer.ImportBytes(plain, st, wordlists(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := importer.AcceptTrustPrompt("trust", plain, st, wordlists(), now); err != nil {
		t.Fatal(err)
	}
	for _, ri := range st.saved[0] {
		if ri.EngineConfig != "" {
			t.Fatalf("a route with no signed endpoint kept %q", ri.EngineConfig)
		}
	}
}

func TestEngineFamilyConfig_Allowlist(t *testing.T) {
	got := bundle.EngineFamilyConfig(json.RawMessage(`{"_endpoint":{"v":1,"server":"198.51.100.1"},"_desync":{"v":1},"_report_to":"x","other":1}`))
	if got != `{"_desync":{"v":1}}` {
		t.Fatalf("got %s", got)
	}
	for _, in := range []string{"", "  ", "[]", "not json", `{"_endpoint":{}}`} {
		if got := bundle.EngineFamilyConfig(json.RawMessage(in)); got != "" {
			t.Fatalf("%q -> %q", in, got)
		}
	}
}
