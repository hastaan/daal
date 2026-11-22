package trust_test

import (
	"testing"
	"time"

	"daal/bundle-go/importer"
	"daal/core/trust"
)

// A route id is not a server (route_identity.go): a new relay saved
// under a reused id starts with no history; a refresh of the SAME relay
// keeps it.

func historyRoute(server, packID, spki string) importer.RouteInput {
	r := testRouteInputWithModifiers("")
	r.RouteID = "r1"
	r.Endpoint = []byte(`{"v":1,"server":"` + server + `","port":443,"server_name":"cover.example","reality_public_key":"` + spki + `"}`)
	r.SignedAt = "2026-11-20T10:00:00Z"
	r.Profile = []byte(`{"type":"vless","server":"` + server + `","server_port":443,"uuid":"u-1"}`)
	r.RelayPack.RelayPackID = packID
	return r
}

func saveWithHistory(t *testing.T, a *trust.StoreAdapter, r importer.RouteInput) {
	t.Helper()
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	if err := a.S.RecordFailure(r.RouteID, "relay_unreachable", time.Time{}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := a.S.RecordSuccess(r.RouteID, now); err != nil {
		t.Fatal(err)
	}
	if err := a.S.RecordRendezvousWinner(r.RouteID, "dns"); err != nil {
		t.Fatal(err)
	}
}

func historyOf(t *testing.T, a *trust.StoreAdapter, id string) (success, failure, channel string) {
	t.Helper()
	row, err := a.S.GetRoute(id)
	if err != nil {
		t.Fatal(err)
	}
	return row.LastSuccessBucket, row.LastFailureBucket, row.LastWinningRendezvousChannel
}

func TestSaveImport_ANewServerUnderAReusedRouteIDStartsWithNoHistory(t *testing.T) {
	cases := []struct {
		name string
		next importer.RouteInput
	}{
		{"another relay (a new pack id, a new address)", historyRoute("198.51.100.7", "rp-new", "key-b")},
		{"the same pack at a new address", historyRoute("198.51.100.7", "rp-old", "key-a")},
		{"the same address with a new relay key", historyRoute("203.0.113.9", "rp-old", "key-b")},
		{"a new pack id at the same address", historyRoute("203.0.113.9", "rp-new", "key-a")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rebound []string
			a := &trust.StoreAdapter{S: openStore(t), OnRouteRebound: func(id string) { rebound = append(rebound, id) }}
			saveWithHistory(t, a, historyRoute("203.0.113.9", "rp-old", "key-a"))
			if s, _, _ := historyOf(t, a, "r1"); s == "" {
				t.Fatal("premise: no success recorded")
			}
			if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{tc.next}); err != nil {
				t.Fatal(err)
			}
			s, f, ch := historyOf(t, a, "r1")
			if s != "" || f != "" || ch != "" {
				t.Fatalf("the old server's history stayed: success=%q failure=%q channel=%q", s, f, ch)
			}
			row, _ := a.S.GetRoute("r1")
			if row.ConsecutiveFailures != 0 || row.CooldownUntil != "" || row.LastFailureCategory != "" {
				t.Fatalf("the old server's failures stayed: %+v", row)
			}
			if len(rebound) != 1 || rebound[0] != "r1" {
				t.Fatalf("OnRouteRebound got %v, want [r1]", rebound)
			}
		})
	}
}

func TestSaveImport_ARefreshOfTheSameRelayKeepsItsHistory(t *testing.T) {
	var rebound []string
	a := &trust.StoreAdapter{S: openStore(t), OnRouteRebound: func(id string) { rebound = append(rebound, id) }}
	saveWithHistory(t, a, historyRoute("203.0.113.9", "rp-old", "key-a"))
	before, _, _ := historyOf(t, a, "r1")

	// A freshness refresh: signed again later, new credentials in the
	// profile, a new expiry, the same relay.
	r := historyRoute("203.0.113.9", "rp-old", "key-a")
	r.SignedAt = "2026-11-21T10:00:00Z"
	r.ExpiresAt = "2027-01-31T00:00:00Z"
	r.Profile = []byte(`{"type":"vless","server":"203.0.113.9","server_port":443,"uuid":"u-2"}`)
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	// A file with no credentials for the route: the profile held is kept.
	r.Profile = nil
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if s, _, ch := historyOf(t, a, "r1"); s != before || ch != "dns" {
		t.Fatalf("a refresh of the same relay lost its history: success=%q (was %q) channel=%q", s, before, ch)
	}
	if len(rebound) != 0 {
		t.Fatalf("OnRouteRebound called for a refresh of the same relay: %v", rebound)
	}
}

// A CDN-fronted route is the same server while its zone, port and CDN
// are: the zone's ECH config and edge seeds rotate on their own.
func TestSaveImport_ACDNRouteKeepsItsHistoryAcrossAnECHRotation(t *testing.T) {
	var rebound []string
	a := &trust.StoreAdapter{S: openStore(t), OnRouteRebound: func(id string) { rebound = append(rebound, id) }}
	cdn := func(ech, seed, host string) importer.RouteInput {
		r := testRouteInputWithModifiers("")
		r.RouteID, r.TransportFamily = "r5", "vless-ws-cdn"
		r.Endpoint = []byte(`{"v":1,"server":"` + host + `","port":443,"server_name":"` + host + `","cdn":"cloudflare","edge_seeds":["` + seed + `"],"ech_config":"` + ech + `","tls_roots_sha256":["root"]}`)
		r.SignedAt = "2026-11-20T10:00:00Z"
		r.Profile = []byte(`{"type":"vless","server":"104.16.0.1","server_port":443}`)
		return r
	}
	saveWithHistory(t, a, cdn("ech-a", "104.16.0.0/20", "a.zone.example"))
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{cdn("ech-b", "172.64.0.0/20", "a.zone.example")}); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := historyOf(t, a, "r5"); s == "" || len(rebound) != 0 {
		t.Fatalf("an ECH rotation reset the history: success=%q rebound=%v", s, rebound)
	}
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{cdn("ech-b", "172.64.0.0/20", "b.zone.example")}); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := historyOf(t, a, "r5"); s != "" || len(rebound) != 1 {
		t.Fatalf("a new zone kept the history: success=%q rebound=%v", s, rebound)
	}
}

// A route that gains a signed endpoint at the same address is the same
// server; a route with no commitment moved to another address is not.
func TestSaveImport_ARouteWithoutACommitmentIsNamedByItsOutbound(t *testing.T) {
	var rebound []string
	a := &trust.StoreAdapter{S: openStore(t), OnRouteRebound: func(id string) { rebound = append(rebound, id) }}
	link := func(server string) importer.RouteInput {
		r := testRouteInputWithModifiers("")
		r.RouteID, r.RelayPack, r.SourceType = "link-1", nil, "uri"
		r.Profile = []byte(`{"type":"trojan","server":"` + server + `","server_port":443,"password":"p"}`)
		return r
	}
	saveWithHistory(t, a, link("203.0.113.9"))
	r := link("203.0.113.9")
	r.Profile = []byte(`{"type":"trojan","server":"203.0.113.9","server_port":443,"password":"q"}`)
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{r}); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := historyOf(t, a, "link-1"); s == "" || len(rebound) != 0 {
		t.Fatalf("a new password at the same server reset the history: success=%q rebound=%v", s, rebound)
	}
	if err := a.SaveImport(testPublisherInput(), []importer.RouteInput{link("198.51.100.7")}); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := historyOf(t, a, "link-1"); s != "" || len(rebound) != 1 {
		t.Fatalf("another server kept the history: success=%q rebound=%v", s, rebound)
	}
}
