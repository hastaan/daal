package abi

import (
	"testing"
	"time"

	"daal/bundle-go/importer"
	"daal/core/netmem"
)

// A new relay saved under the route ids of one it replaces (core/trust
// route_identity.go) starts with no history in the route list: not
// "worked before", no health, nothing remembered on any network. A
// refresh of the SAME relay keeps all of it.
func TestRebound_ANewRelayUnderReusedRouteIDsShowsNoOldHistory(t *testing.T) {
	setClock(t, time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC))
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Shutdown() })
	c := mustCore()
	pub := importer.PublisherInput{Fingerprint: "pub-rebound", DisplayName: "P", TrustLevel: "tofu_friend",
		KeyStatus: "active", FirstSeen: "2026-11-01T00", LastSeenBundle: "2026-11-01T00"}
	route := func(id, server, pack string) importer.RouteInput {
		return importer.RouteInput{
			RouteID: id, TransportFamily: "vless-reality", ScarcityClass: "normal", Engine: "sing-box",
			SourceType: "bundle", ModesAllowed: []string{"normal"}, ExpiresAt: "2027-01-01T00:00:00Z",
			ImportedAt: "2026-11-01T00", TrustState: "tofu",
			Profile:   []byte(`{"type":"vless","server":"` + server + `","server_port":443,"uuid":"u"}`),
			Endpoint:  []byte(`{"v":1,"server":"` + server + `","port":443,"server_name":"cover.example","reality_public_key":"k"}`),
			SignedAt:  "2026-11-01T00:00:00Z",
			RelayPack: &importer.RelayPackMeta{RelayPackID: pack, SharedRiskGraphJSON: "[]"},
		}
	}
	if err := c.adapter.SaveImport(pub, []importer.RouteInput{route("r1", "203.0.113.9", "rp-old"), route("r2", "203.0.113.9", "rp-old")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"r1", "r2"} {
		if err := c.store.RecordSuccess(id, nowUTC()); err != nil {
			t.Fatal(err)
		}
		c.rememberOutcome(id, netmem.RouteOutcome{Carried: true, HasSetup: true, SetupMs: 300})
	}
	for _, id := range []string{"r1", "r2"} {
		if row := routeRow(t, id); row["proven"] != true || row["health_pct"] == nil {
			t.Fatalf("premise: %s %v", id, row)
		}
	}

	lc := captureLog(t)
	// r1: the publisher deleted the old relay and sent a file for a new
	// one, numbered the same. r2: a freshness refresh of the old relay.
	newR1 := route("r1", "198.51.100.7", "rp-new")
	sameR2 := route("r2", "203.0.113.9", "rp-old")
	sameR2.SignedAt = "2026-11-21T00:00:00Z"
	if err := c.adapter.SaveImport(pub, []importer.RouteInput{newR1, sameR2}); err != nil {
		t.Fatal(err)
	}
	r1 := routeRow(t, "r1")
	m1, _ := r1["measured"].(map[string]any)
	if r1["proven"] != false || r1["health_pct"] != nil || m1["grade"] != netmem.GradeUnknown || m1["samples"] != float64(0) {
		t.Fatalf("the new relay shows the old one's history: %v", r1)
	}
	if _, ok := c.routeMemory()["r1"]; ok {
		t.Fatal("this network still remembers r1 from the old relay")
	}
	r2 := routeRow(t, "r2")
	m2, _ := r2["measured"].(map[string]any)
	if r2["proven"] != true || m2["grade"] != netmem.GradeGood {
		t.Fatalf("a refresh of the same relay lost its history: %v", r2)
	}
	if !lc.has("route history reset route=r1 reason=another_server") || lc.has("route history reset route=r2") {
		t.Fatalf("log: %v", lc.all())
	}
}
