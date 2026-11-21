package netmem

import (
	"strings"
	"testing"
	"time"
)

func TestVariantKey_RoundTrip(t *testing.T) {
	for _, c := range []struct{ route, suffix, key string }{
		{"r1", "", "r1"},
		{"r1", "d:sni-cut", "r1#d:sni-cut"},
		{"r1", "n:2", "r1#n:2"},
		{"r1", "d:sni-cut#n:2", "r1#d:sni-cut#n:2"},
	} {
		if got := VariantKey(c.route, c.suffix); got != c.key {
			t.Fatalf("VariantKey(%q,%q) = %q", c.route, c.suffix, got)
		}
		r, s := SplitVariantKey(c.key)
		if r != c.route || s != c.suffix {
			t.Fatalf("SplitVariantKey(%q) = %q %q", c.key, r, s)
		}
	}
}

// 24 h confidence halving; 72 h expiry of a blocked mark.
func TestVariantAgeing(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var m RouteMemory
	m.apply(RouteOutcome{Carried: true}, 1, t0.Unix())
	for _, c := range []struct {
		after time.Duration
		want  float64
	}{{0, 1}, {23 * time.Hour, 1}, {24 * time.Hour, 0.5}, {49 * time.Hour, 0.25}, {72 * time.Hour, 0.125}} {
		if got := m.Confidence(t0.Add(c.after)); got != c.want {
			t.Fatalf("confidence after %v = %v, want %v", c.after, got, c.want)
		}
	}
	m.apply(RouteOutcome{Category: "tls_sni_or_cert_block_suspected"}, 2, t0.Unix())
	if m.Confidence(t0) != 0 {
		t.Fatal("a variant whose last outcome failed has no confidence")
	}
	if !m.BlockedAt(t0.Add(71*time.Hour)) || m.BlockedAt(t0.Add(73*time.Hour)) {
		t.Fatal("the blocked mark must hold 72 h and then expire")
	}
	// One success clears the mark at once.
	m.apply(RouteOutcome{Carried: true}, 3, t0.Add(time.Hour).Unix())
	if m.BlockedAt(t0.Add(2 * time.Hour)) {
		t.Fatal("carried since: not blocked")
	}
}

func TestForgetRoute_DropsVariants(t *testing.T) {
	s := New(newFakeKV())
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for _, k := range []string{"r1", "r1#d:sni-cut", "r1#n:1", "r10", "r2#n:1"} {
		if err := s.RecordRouteCarried("net-a", k, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordRouteCarried("net-b", "r1#d:chain", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetRoute("r1"); err != nil {
		t.Fatal(err)
	}
	a := s.LookupRouteMemory("net-a")
	for _, k := range []string{"r1", "r1#d:sni-cut", "r1#n:1"} {
		if _, ok := a[k]; ok {
			t.Fatalf("%s kept after ForgetRoute(r1)", k)
		}
	}
	for _, k := range []string{"r10", "r2#n:1"} {
		if _, ok := a[k]; !ok {
			t.Fatalf("%s dropped by ForgetRoute(r1)", k)
		}
	}
	if len(s.LookupRouteMemory("net-b")) != 0 {
		t.Fatal("a variant on another network kept")
	}
	if got := VariantsOf(a, "r2"); len(got) != 1 || got["n:1"].CarriedSeq == 0 {
		t.Fatalf("VariantsOf(r2) = %v", got)
	}
}

// A variant that has carried here before needs two failures in a row to
// be marked blocked; one that never carried is marked by one.
func TestVariantBlockedAt_ProvenWinnerNeedsTwo(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var fresh RouteMemory
	fresh.apply(RouteOutcome{Category: "tcp_reset"}, 1, t0.Unix())
	if !fresh.VariantBlockedAt(t0) {
		t.Fatal("a variant that never carried and failed once is not blocked")
	}
	var won RouteMemory
	won.apply(RouteOutcome{Carried: true}, 1, t0.Unix())
	won.apply(RouteOutcome{Category: "tcp_reset"}, 2, t0.Unix())
	if won.VariantBlockedAt(t0) {
		t.Fatal("one failure blocked a variant that carried here before")
	}
	won.apply(RouteOutcome{Category: "tcp_reset"}, 3, t0.Unix())
	if !won.VariantBlockedAt(t0) || won.VariantBlockedAt(t0.Add(73*time.Hour)) {
		t.Fatal("two failures in a row must block for 72 h")
	}
}

// ForgetVariants drops a route's variants on every network and keeps
// the route's own record and other routes'.
func TestForgetVariants_KeepsTheRoute(t *testing.T) {
	s := New(newFakeKV())
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for _, k := range []string{"r1", "r1#d:sni-cut", "r1#n:1", "r10#n:1"} {
		_ = s.RecordRouteCarried("net-a", k, now)
	}
	_ = s.RecordRouteCarried("net-b", "r1#d:chain", now)
	if err := s.ForgetVariants("r1"); err != nil {
		t.Fatal(err)
	}
	a, b := s.LookupRouteMemory("net-a"), s.LookupRouteMemory("net-b")
	if _, ok := a["r1"]; !ok || len(VariantsOf(a, "r1")) != 0 || len(VariantsOf(b, "r1")) != 0 {
		t.Fatalf("net-a %v net-b %v", a, b)
	}
	if _, ok := a["r10#n:1"]; !ok {
		t.Fatal("another route's variant was dropped")
	}
}

// The per-relay name count: hashes only, idempotent, per network, kept
// across ForgetRoute and the network-change rewrite.
func TestCoverNamesShown(t *testing.T) {
	s := New(newFakeKV())
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	relay, n1, n2 := ShownKey("net-a", "198.51.100.7"), ShownKey("net-a", "one.example"), ShownKey("net-a", "two.example")
	if relay == ShownKey("net-b", "198.51.100.7") {
		t.Fatal("the key is not per network")
	}
	for _, n := range []string{n1, n1, n2} {
		if err := s.RecordCoverNameShown("net-a", relay, n, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.CoverNamesShownTo("net-a", relay); len(got) != 2 {
		t.Fatalf("shown %v", got)
	}
	if got := s.CoverNamesShownTo("net-b", relay); len(got) != 0 {
		t.Fatalf("another network: %v", got)
	}
	_ = s.RecordRouteCarried("net-a", "r1#n:1", now)
	_ = s.ForgetRoute("r1")
	if err := s.PutKeepingRouteMemory("net-a", Snapshot{Mode: "normal"}, now); err != nil {
		t.Fatal(err)
	}
	if got := s.CoverNamesShownTo("net-a", relay); len(got) != 2 {
		t.Fatalf("after ForgetRoute and a rewrite: %v", got)
	}
	snap, _ := s.Get("net-a")
	body, _ := snap.MarshalCanonical()
	for _, plain := range []string{"198.51.100.7", "one.example"} {
		if strings.Contains(string(body), plain) {
			t.Fatalf("the blob holds %q in plaintext", plain)
		}
	}
}
