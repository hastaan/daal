package pathmanager

import (
	"reflect"
	"testing"
)

// helper: build a Route with sensible defaults.
func r(id, family, tag string, modes []string, hourly, consumed uint64) Route {
	return Route{
		RouteID:      id,
		Family:       family,
		ModesAllowed: modes,
		HourlyCap:    hourly,
		Consumed:     consumed,
		BudgetTag:    tag,
	}
}

// TestRankBulkModeKeepsOnlyBulkCapable asserts the V2.2 explicit-
// opt-in rule: in `bulk` mode, every non-bulk-capable route is
// filtered OUT.
func TestRankBulkModeKeepsOnlyBulkCapable(t *testing.T) {
	in := []Route{
		r("a-bc", "vless", "bulk-capable", []string{"lifeline", "normal", "bulk"}, 0, 0),
		r("b-no", "vless", "normal", []string{"lifeline", "normal"}, 5_000_000, 1_000_000),
		r("c-em", "vless", "emergency", []string{"lifeline"}, 50_000_000, 10_000_000),
		r("d-bc2", "hys", "bulk-capable", []string{"lifeline", "normal", "bulk"}, 0, 0),
	}
	out := Rank(in, "bulk")
	if len(out) != 2 {
		t.Fatalf("expected 2 routes in bulk mode, got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.BudgetTag != "bulk-capable" {
			t.Errorf("non-bulk-capable route survived in bulk mode: %+v", r)
		}
	}
}

// TestRankLifelineFiltersBulkInModesAllowed asserts that the
// `lifeline-only` tag (modes_allowed=["lifeline"]) is filtered OUT
// in normal mode.
func TestRankLifelineFiltersBulkInModesAllowed(t *testing.T) {
	in := []Route{
		r("a-lo", "vless", "lifeline-only", []string{"lifeline"}, 100_000_000, 0),
		r("b-no", "vless", "normal", []string{"lifeline", "normal"}, 5_000_000, 0),
	}
	out := Rank(in, "normal")
	if len(out) != 1 {
		t.Fatalf("expected 1 route in normal mode, got %d: %+v", len(out), out)
	}
	if out[0].RouteID != "b-no" {
		t.Errorf("lifeline-only route should be filtered out: got %+v", out[0])
	}
}

// TestRankNonBulkModeDepriorizesBulkCapable asserts the deprefer
// step: bulk-capable routes survive the filter in normal/lifeline,
// but rank LAST.
func TestRankNonBulkModeDepriorizesBulkCapable(t *testing.T) {
	in := []Route{
		r("z-bc", "vless", "bulk-capable", []string{"lifeline", "normal", "bulk"}, 0, 0),
		r("a-no", "vless", "normal", []string{"lifeline", "normal"}, 1000, 100),
	}
	for _, mode := range []string{"normal", "lifeline"} {
		out := Rank(in, mode)
		if len(out) != 2 {
			t.Fatalf("%s mode: expected 2 routes, got %d", mode, len(out))
		}
		if out[0].RouteID != "a-no" {
			t.Errorf("%s mode: bulk-capable should rank last; got first=%s", mode, out[0].RouteID)
		}
		if out[1].RouteID != "z-bc" {
			t.Errorf("%s mode: bulk-capable should rank last; got last=%s", mode, out[1].RouteID)
		}
	}
}

// TestRankByConsumedFractionAscendingWithinClass asserts within-class
// sort: routes with less burned-fraction rank higher.
func TestRankByConsumedFractionAscendingWithinClass(t *testing.T) {
	in := []Route{
		r("burned", "vless", "normal", []string{"lifeline", "normal"}, 1000, 900), // 90%
		r("fresh", "vless", "normal", []string{"lifeline", "normal"}, 1000, 100),  // 10%
		r("medium", "vless", "normal", []string{"lifeline", "normal"}, 1000, 500), // 50%
	}
	out := Rank(in, "normal")
	want := []string{"fresh", "medium", "burned"}
	got := []string{}
	for _, r := range out {
		got = append(got, r.RouteID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rank order = %v, want %v", got, want)
	}
}

// TestRankStableByRouteIDOnTies — equal consumed-fraction → stable
// route_id sort.
func TestRankStableByRouteIDOnTies(t *testing.T) {
	in := []Route{
		r("zzz", "vless", "normal", []string{"lifeline", "normal"}, 1000, 100),
		r("aaa", "vless", "normal", []string{"lifeline", "normal"}, 1000, 100),
		r("mmm", "vless", "normal", []string{"lifeline", "normal"}, 1000, 100),
	}
	out := Rank(in, "normal")
	want := []string{"aaa", "mmm", "zzz"}
	got := []string{}
	for _, r := range out {
		got = append(got, r.RouteID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tie-break order = %v, want %v", got, want)
	}
}

// TestRankEmptyInput returns an empty slice without panic.
func TestRankEmptyInput(t *testing.T) {
	out := Rank(nil, "normal")
	if len(out) != 0 {
		t.Errorf("expected empty, got %v", out)
	}
}

// fakeView is a minimal NetworkView implementation for the
// 2D lifeline-strict tests.
type fakeView struct {
	failureRates map[string]float64
	allowBulk    bool
}

func (v fakeView) FailureRate(id string) float64      { return v.failureRates[id] }
func (v fakeView) AllowsBulkCapableThisSession() bool { return v.allowBulk }

// TestLifelineStrictFiltersBulkCapableByDefault — in lifeline-strict
// mode, bulk-capable routes are filtered OUT unless the per-session
// opt-in is set.
func TestLifelineStrictFiltersBulkCapableByDefault(t *testing.T) {
	in := []Route{
		r("a-bc", "vless", "bulk-capable", []string{"lifeline", "normal", "bulk"}, 0, 0),
		r("b-no", "vless", "normal", []string{"lifeline", "normal"}, 5_000_000, 0),
	}
	out := RankWithView(in, "lifeline-strict", fakeView{allowBulk: false})
	if len(out) != 1 || out[0].RouteID != "b-no" {
		t.Errorf("bulk-capable not filtered in lifeline-strict: %+v", out)
	}
}

// TestLifelineStrictAllowsBulkCapableWhenSessionFlagSet — when the
// per-session opt-in is set, bulk-capable routes return.
func TestLifelineStrictAllowsBulkCapableWhenSessionFlagSet(t *testing.T) {
	in := []Route{
		r("a-bc", "vless", "bulk-capable", []string{"lifeline", "normal", "bulk"}, 0, 0),
		r("b-no", "vless", "normal", []string{"lifeline", "normal"}, 5_000_000, 0),
	}
	out := RankWithView(in, "lifeline-strict", fakeView{allowBulk: true})
	if len(out) != 2 {
		t.Errorf("bulk-capable not allowed despite session flag: %+v", out)
	}
}

// TestLifelineStrictStabilityBias — a route with lower FailureRate
// ranks first even with a higher consumed-fraction.
func TestLifelineStrictStabilityBias(t *testing.T) {
	// Both routes are normal-tagged, allowed in lifeline.
	// "a-stable" has higher consumed but a much lower failure rate.
	in := []Route{
		r("a-stable", "vless", "normal", []string{"lifeline", "normal"}, 1000, 800),
		r("b-flaky", "vless", "normal", []string{"lifeline", "normal"}, 1000, 100),
	}
	view := fakeView{
		failureRates: map[string]float64{"a-stable": 0.05, "b-flaky": 0.40},
	}
	out := RankWithView(in, "lifeline-strict", view)
	if len(out) != 2 || out[0].RouteID != "a-stable" {
		t.Fatalf("stability bias broken; got order %v", routeIDs(out))
	}
}

// TestLifelineStrictDoesNotFilterRelayRouteFamilies — the V2.5
// roadmap rule "no relay-route filter" applies regardless of family.
// We pass routes from every transport family Daal cares about, all
// tagged `normal` (so allowed in lifeline), and assert NONE are
// dropped solely on family identity.
func TestLifelineStrictDoesNotFilterRelayRouteFamilies(t *testing.T) {
	families := []string{
		"vless-reality", "hysteria2", "trojan", "shadowsocks-2022",
		"webtunnel", "snowflake", "tor-bridge", "wireguard", "naive",
	}
	in := make([]Route, 0, len(families))
	for _, f := range families {
		in = append(in, r("rid-"+f, f, "normal", []string{"lifeline", "normal"}, 1000, 100))
	}
	out := RankWithView(in, "lifeline-strict", fakeView{})
	if len(out) != len(families) {
		t.Errorf("lifeline-strict dropped a family route: in=%d out=%d", len(in), len(out))
	}
}

func routeIDs(rs []Route) []string {
	ids := make([]string, 0, len(rs))
	for _, r := range rs {
		ids = append(ids, r.RouteID)
	}
	return ids
}
