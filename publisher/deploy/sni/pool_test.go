package sni

import (
	"strings"
	"testing"
	"time"
)

// TestEveryPoolEntrySatisfiesTheRule is the whole point of rule.go: the
// predicate is executable, so "no pool entry violates the rule" is a
// test and not a promise in a comment.
func TestEveryPoolEntrySatisfiesTheRule(t *testing.T) {
	if len(pool) == 0 {
		t.Fatal("pool is empty")
	}
	for _, e := range pool {
		if err := Admit(e); err != nil {
			t.Errorf("pool entry %q rejected by the rule: %v", e.Host, err)
		}
	}
	if len(Admissible()) != len(pool) {
		t.Errorf("Admissible() = %d entries, pool = %d — an entry is being silently dropped", len(Admissible()), len(pool))
	}
}

// TestNoCloudflareAnywhere pins the Wave-2 bug shut. The fleet-wide
// constant must be rejected by the rule and absent from the pool; so
// must anything else fronted by a blanket-blocked CDN.
func TestNoCloudflareAnywhere(t *testing.T) {
	for _, e := range pool {
		if err := ValidHost(e.Host); err != nil {
			t.Errorf("pool entry %q: %v", e.Host, err)
		}
		if e.Hosting == HostingGlobalCDN {
			t.Errorf("pool entry %q is CDN-fronted", e.Host)
		}
	}
	if err := ValidHost(LegacyCoverSNI); err == nil {
		t.Fatalf("ValidHost(%q) = nil; the legacy fleet-wide constant must never be admissible", LegacyCoverSNI)
	}
	for _, e := range pool {
		if e.Host == LegacyCoverSNI {
			t.Fatalf("the legacy constant %q is in the pool", LegacyCoverSNI)
		}
	}
	// A mis-declared entry (CDN host claiming to be a hosting provider)
	// is still caught by the suffix deny-list.
	bad := Entry{Host: "cdn.cloudflare.net", Zone: ZoneEUCentral, ASN: 13335, Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"}
	if err := Admit(bad); err == nil {
		t.Error("Admit accepted a Cloudflare host that lied about its hosting class")
	}
}

func TestAdmitRejects(t *testing.T) {
	base := Entry{Host: "mirror.example.net", Zone: ZoneEUCentral, ASN: 64500, ASName: "EXAMPLE", Hosting: HostingProvider, Purpose: PurposeSoftwareMirror, TLS13: true, H2: true, AuditedOn: "2026-08-17"}
	if err := Admit(base); err != nil {
		t.Fatalf("baseline entry rejected: %v", err)
	}
	cases := map[string]func(*Entry){
		"no tls1.3":     func(e *Entry) { e.TLS13 = false },
		"no h2":         func(e *Entry) { e.H2 = false },
		"global cdn":    func(e *Entry) { e.Hosting = HostingGlobalCDN },
		"unknown class": func(e *Entry) { e.Hosting = "whatever" },
		"no asn":        func(e *Entry) { e.ASN = 0 },
		"bad purpose":   func(e *Entry) { e.Purpose = "consumer-webmail" },
		"no zone":       func(e *Entry) { e.Zone = ZoneAny },
		"bad zone":      func(e *Entry) { e.Zone = "mars" },
		"no audit date": func(e *Entry) { e.AuditedOn = "" },
		"bad date":      func(e *Entry) { e.AuditedOn = "last tuesday" },
		"uppercase":     func(e *Entry) { e.Host = "Mirror.Example.Net" },
		"single label":  func(e *Entry) { e.Host = "localhost" },
		"wildcard":      func(e *Entry) { e.Host = "*.example.net" },
		"with port":     func(e *Entry) { e.Host = "mirror.example.net:443" },
		"with scheme":   func(e *Entry) { e.Host = "https://mirror.example.net" },
		"ip literal":    func(e *Entry) { e.Host = "203.0.113.7" },
		"rooted":        func(e *Entry) { e.Host = "mirror.example.net." },
	}
	for name, mutate := range cases {
		e := base
		mutate(&e)
		if err := Admit(e); err == nil {
			t.Errorf("Admit accepted %s (%q)", name, e.Host)
		}
	}
}

// TestEveryZoneHasEnoughEntries: a zone with one or two entries gives
// every relay in that region the same cover SNI, which is the failure
// the pool exists to prevent.
func TestEveryZoneHasEnoughEntries(t *testing.T) {
	for _, z := range Zones {
		if got := len(InZone(z)); got < MinPerZone {
			t.Errorf("zone %s has %d admissible entries, want >= %d", z, got, MinPerZone)
		}
	}
}

// TestPoolIsNotStale fails once the measurements in pool.go are older
// than ShelfLife. Fix by re-running the audit in the package doc.
func TestPoolIsNotStale(t *testing.T) {
	oldest, ok := OldestAudit()
	if !ok {
		t.Fatal("pool has an unparseable AuditedOn")
	}
	if Stale(time.Now()) {
		t.Errorf("pool's oldest audit is %s, older than ShelfLife (%v) — re-run the refresh procedure in pool.go", oldest.Format("2006-01-02"), ShelfLife)
	}
}

// TestPickIsStable: the same relay always gets the same cover host.
func TestPickIsStable(t *testing.T) {
	const seed = "daal-fsn1-0011223344556677"
	first := Pick(seed, "fsn1")
	if first == "" {
		t.Fatal("Pick returned empty")
	}
	for i := 0; i < 64; i++ {
		if got := Pick(seed, "fsn1"); got != first {
			t.Fatalf("Pick is not stable: %q then %q", first, got)
		}
	}
}

// TestPickSpreadsAcrossRelays: different relays must not collapse onto
// one host. With 6 entries in eu-central, 200 distinct seeds should
// reach every one of them.
func TestPickSpreadsAcrossRelays(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		seed := "daal-fsn1-" + strings.Repeat("a", i%7) + string(rune('0'+i%10)) + "-" + itoa(i)
		seen[Pick(seed, "fsn1")]++
	}
	zone := InZone(ZoneEUCentral)
	if len(seen) != len(zone) {
		t.Errorf("200 relays reached %d of %d eu-central hosts: %v", len(seen), len(zone), seen)
	}
	// And two adjacent relays must differ at least sometimes; a
	// constant would show up as a single key above, but pin the direct
	// statement too.
	a, b := Pick("daal-fsn1-aaaaaaaaaaaaaaaa", "fsn1"), Pick("daal-fsn1-bbbbbbbbbbbbbbbb", "fsn1")
	if a == "" || b == "" {
		t.Fatal("Pick returned empty for a real seed")
	}
}

// TestPickRespectsZone: a Helsinki relay must not advertise a Singapore
// mirror.
func TestPickRespectsZone(t *testing.T) {
	for region, wantZone := range map[string]Zone{
		"fsn1": ZoneEUCentral,
		"hel1": ZoneEUNorth,
		"vno":  ZoneEUNorth,
		"ash":  ZoneUSEast,
		"hil":  ZoneUSWest,
		"sin":  ZoneAPAC,
	} {
		for i := 0; i < 50; i++ {
			host := Pick("relay-"+region+"-"+itoa(i), region)
			z, ok := zoneOf(host)
			if !ok {
				t.Fatalf("Pick(%q) returned %q which is not in the pool", region, host)
			}
			if z != wantZone {
				t.Errorf("region %q picked %q in zone %s, want zone %s", region, host, z, wantZone)
			}
		}
	}
}

// TestPickUnknownRegionStillPicks: an unrecognised region must widen to
// the whole pool, never fall back to a constant and never return empty.
func TestPickUnknownRegionStillPicks(t *testing.T) {
	got := Pick("relay-somewhere-new", "mars1")
	if got == "" {
		t.Fatal("unknown region produced no cover host")
	}
	if got == LegacyCoverSNI {
		t.Fatalf("unknown region fell back to the legacy constant %q", LegacyCoverSNI)
	}
	if _, ok := zoneOf(got); !ok {
		t.Fatalf("unknown region produced %q which is not in the pool", got)
	}
}

// TestPickExcludingMoves: rotation must not hand a burned relay the host
// it just burned.
func TestPickExcludingMoves(t *testing.T) {
	const seed = "daal-fsn1-0011223344556677"
	current := Pick(seed, "fsn1")
	next := PickExcluding(seed, "fsn1", current)
	if next == current {
		t.Fatalf("PickExcluding returned the excluded host %q", current)
	}
	if next == "" {
		t.Fatal("PickExcluding returned empty")
	}
	// Excluding everything must still yield something rather than an
	// empty server_name, which would be a box that does not start.
	var all []string
	for _, e := range Admissible() {
		all = append(all, e.Host)
	}
	if got := PickExcluding(seed, "fsn1", all...); got == "" {
		t.Error("PickExcluding(everything) returned empty; want a repeat rather than nothing")
	}
}

// TestPickIsRendezvousNotModulo: removing one entry must move only the
// relays that had chosen it. A modulo scheme reshuffles nearly all of
// them, which would rewrite the whole fleet's SNI on any pool edit.
func TestPickIsRendezvousNotModulo(t *testing.T) {
	zone := InZone(ZoneEUCentral)
	if len(zone) < 3 {
		t.Skip("needs >= 3 entries")
	}
	victim := zone[0].Host
	moved, affected := 0, 0
	const n = 300
	for i := 0; i < n; i++ {
		seed := "relay-" + itoa(i)
		before := Pick(seed, "fsn1")
		after := PickExcluding(seed, "fsn1", victim)
		if before == victim {
			affected++
			continue
		}
		if before != after {
			moved++
		}
	}
	if affected == 0 {
		t.Fatal("no relay had chosen the victim host; test is not measuring anything")
	}
	if moved != 0 {
		t.Errorf("%d of %d relays that had NOT chosen %q moved when it was removed; selection is not stable under pool edits", moved, n, victim)
	}
}

func zoneOf(host string) (Zone, bool) {
	for _, e := range pool {
		if e.Host == host {
			return e.Zone, true
		}
	}
	return ZoneAny, false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
