package abi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
	"daal/core/refresh"
)

// The drill through engine_relaypack_refresh's JSON request
// (relaypack_drill.go), the backup_routes field of the route summary,
// and the empty summary of a route the store does not hold.

const (
	drillOwner = "drillowner"
	drillRepo  = "drillrepo"
	drillZone  = "notes.drill.example.org"
)

// seedLadder gives the fixture pack's first route what the ladder needs.
func seedLadder(t *testing.T, r *c0Rig) string {
	t.Helper()
	rows, err := r.c.store.ListRoutes()
	if err != nil || len(rows) == 0 {
		t.Fatal(err)
	}
	id := rows[0].RouteID
	var u bundle.UpdateSecret
	u.Audience = bundle.UpdateAudiencePeople(1)
	_, _ = rand.Read(u.Secret[:])
	us, err := bundle.MarshalUpdateSecret(u)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := bundle.MarshalUpdateCarriers(bundle.UpdateCarriers{
		GitTag: &bundle.GitTagCarrier{Owner: drillOwner, Repo: drillRepo},
		DNS:    &bundle.DNSCarrier{Zone: drillZone},
	})
	if err != nil {
		t.Fatal(err)
	}
	k, _ := bundle.NewStandbyKey("93.184.216.34", rand.Reader)
	sb, _ := json.Marshal(bundle.SealedStandby(k))
	for key, v := range map[string][]byte{
		bundle.UpdateSecretStoreKey(id):   us,
		bundle.UpdateCarriersStoreKey(id): cs,
		bundle.StandbyStoreKey(id):        sb,
	} {
		if err := r.c.store.PutSecret(key, v); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

type drillFakes struct{ all []*refresh.FakeCarrier }

func (f *drillFakes) calls() int {
	n := 0
	for _, c := range f.all {
		n += c.Calls()
	}
	return n
}

func installDrillFakes(t *testing.T, r *c0Rig) *drillFakes {
	t.Helper()
	g := bundle.NoteCarrierGitTag
	mk := func(name, label, class string, rung int, cost refresh.CarrierCost, k refresh.NoteKind) *refresh.FakeCarrier {
		return &refresh.FakeCarrier{InfoV: refresh.CarrierInfo{Name: name, Label: label, Class: class, Rung: rung, Cost: cost, Kinds: k}}
	}
	f := &drillFakes{all: []*refresh.FakeCarrier{
		mk("github", g, refresh.ClassGitHub, refresh.RungGitTag, refresh.CarrierCost{TCP: 2}, refresh.NoteBoth),
		mk("goproxy-front", g, refresh.ClassGoogle, refresh.RungGoogle, refresh.CarrierCost{TCP: 1}, refresh.NoteBoth),
		mk("goproxy-direct", g, refresh.ClassGoProxy, refresh.RungReaders, refresh.CarrierCost{TCP: 2}, refresh.NoteBoth),
		mk("jsdelivr", g, refresh.ClassJSDelivr, refresh.RungReaders, refresh.CarrierCost{TCP: 2}, refresh.NoteBoth),
		mk("dns", bundle.NoteCarrierDNS, refresh.ClassDNS, refresh.RungDNS, refresh.CarrierCost{DNS: 6}, refresh.NoteMicro),
	}}
	var cs []refresh.Carrier
	for _, c := range f.all {
		cs = append(cs, c)
	}
	r.rp.LadderCarriers = cs
	r.rp.LadderGap = func() time.Duration { return 0 }
	r.rp.DirectDialer = refresh.DialerFn(func() (bootstrap.Dialer, bool, error) { return refresh.NoDialer, false, nil })
	return f
}

func drillCall(t *testing.T, req string) RelayPackRefreshResult {
	t.Helper()
	body, err := RelayPackRefresh(req)
	if err != nil {
		t.Fatal(err)
	}
	var res RelayPackRefreshResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return res
}

func TestDrill_ThroughTheRefreshCall(t *testing.T) {
	r := newC0Rig(t)
	fakes := installDrillFakes(t, r)
	rows, _ := r.c.store.ListRoutes()
	req := `{"drill":true,"route_id":"` + rows[0].RouteID + `"}`

	// An older file: not offered, nothing dialled.
	if res := drillCall(t, req); res.Outcome != RecoverNotAvailable || res.Drill != nil {
		t.Fatalf("older file: %+v", res)
	}
	if fakes.calls() != 0 || len(r.fetchLog()) != 0 {
		t.Fatal("an older file's drill dialled")
	}
	// Unknown route, malformed request.
	if res := drillCall(t, `{"drill":true,"route_id":"nope"}`); res.Outcome != RecoverUnknownPack {
		t.Fatalf("unknown: %+v", res)
	}
	if res := drillCall(t, `{"drill":tru`); res.Outcome != RecoverUnknownPack {
		t.Fatalf("malformed: %+v", res)
	}
	// An object that names no pack is not "every pack".
	for _, q := range []string{`{}`, `{"dril":true,"route_id":"` + rows[0].RouteID + `"}`} {
		if res := drillCall(t, q); res.Outcome != RecoverUnknownPack {
			t.Fatalf("%s: %+v", q, res)
		}
	}
	if len(r.fetchLog()) != 0 {
		t.Fatalf("an object naming no pack walked the mirrors: %v", r.fetchLog())
	}

	seedLadder(t, r)
	body, _ := RelayPackRefresh(req)
	var res RelayPackRefreshResult
	_ = json.Unmarshal([]byte(body), &res)
	if res.Outcome != RecoverUnreachable || len(res.Drill) != 5 || len(res.Packs) != 1 || res.Packs[0].Kind != "drill" {
		t.Fatalf("drill: %s", body)
	}
	if res.Drill[refresh.ClassGitHub].Result != refresh.DrillNothingNew || res.Drill[refresh.ClassDNS].Result != refresh.DrillNothingNew {
		t.Fatalf("drill: %v", res.Drill)
	}
	if len(r.fetchLog()) != 0 {
		t.Fatalf("the drill walked the mirrors: %v", r.fetchLog())
	}
	for _, s := range []string{drillOwner, drillRepo, drillZone, "93.184", r.oldHost} {
		if strings.Contains(body, s) {
			t.Fatalf("%q in the answer: %s", s, body)
		}
	}
	if rb := recoveryBlock(t); rb["trigger"] != RecoverTriggerDrill {
		t.Fatalf("relay_recovery: %v", rb)
	}
	// Once per 10 minutes.
	n := fakes.calls()
	if res := drillCall(t, req); res.Outcome != RecoverRateLimited || res.RetryAfterS <= 0 || fakes.calls() != n {
		t.Fatalf("rate limit: %+v", res)
	}
	// The same pack by its id, after the floor.
	advanceClock(refresh.DrillFloor)
	if res := drillCall(t, `{"drill":true,"relay_pack_id":"`+fixturePackID+`"}`); res.Outcome != RecoverUnreachable || fakes.calls() == n {
		t.Fatalf("by pack id: %+v", res)
	}
	// A plain JSON request without drill is the ordinary button.
	advanceClock(refresh.DrillFloor)
	if res := drillCall(t, `{"relay_pack_id":"`+fixturePackID+`"}`); res.Drill != nil || len(res.Packs) != 1 || res.Packs[0].Kind != "on_demand" {
		t.Fatalf("plain request: %+v", res)
	}

	// Never while a route is up.
	if err := SetRoute(rows[0].RouteID); err != nil {
		t.Fatal(err)
	}
	n = fakes.calls()
	res = drillCall(t, req)
	if res.Outcome != RecoverTunnelRequired || fakes.calls() != n ||
		res.Drill[refresh.ClassDNS] != (refresh.DrillClass{Result: refresh.DrillSkipped, Reason: refresh.DrillSkipRouteUp}) {
		t.Fatalf("under a route: %+v", res)
	}
}

func TestBackupRoutes_InTheRouteSummary(t *testing.T) {
	r := newC0Rig(t)
	rows, _ := r.c.store.ListRoutes()
	read := func(id string) map[string]any {
		t.Helper()
		body, err := RouteSummary(id)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if _, ok := read(rows[0].RouteID)["backup_routes"]; ok {
		t.Fatal("an older file has backup routes")
	}
	seedLadder(t, r)
	for _, row := range rows {
		got, _ := json.Marshal(read(row.RouteID)["backup_routes"])
		if row.RelayPackID == fixturePackID && string(got) != `["gittag","dns"]` {
			t.Fatalf("%s: %s", row.RouteID, got)
		}
	}
	body, _ := AvailableRoutes()
	if !strings.Contains(body, `"backup_routes":["gittag","dns"]`) {
		t.Fatalf("available_routes: %s", body)
	}
	for _, s := range []string{drillOwner, drillRepo, drillZone} {
		if strings.Contains(body, s) {
			t.Fatalf("%q in the listing", s)
		}
	}
}

// A route the store does not hold: an empty answer and no recorded
// failure (the start-up noise "sql: no rows in result set").
func TestRouteSummary_UnknownRouteIsEmpty(t *testing.T) {
	newAutoRig(t, autoFourRoutes)
	for _, id := range []string{"", "no-such-route"} {
		body, err := RouteSummary(id)
		if err != nil || body != "" {
			t.Fatalf("%q: %q %v", id, body, err)
		}
	}
	if body, err := RouteSummary("r1"); err != nil || !strings.Contains(body, `"route_id":"r1"`) {
		t.Fatalf("r1: %s %v", body, err)
	}
	_ = context.Background
}
