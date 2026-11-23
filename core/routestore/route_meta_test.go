package routestore

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func manualRow(id string) RouteRow {
	return RouteRow{
		RouteID: id, TransportFamily: "wireguard", Engine: "sing-box",
		SourceType: "pasted", PublisherID: "fp1", TrustState: "tofu",
		ScarcityClass: "normal", ModesAllowed: []string{"normal"},
		ExpiresAt: "2026-12-26T19:00:00Z", ImportedAt: "2026-11-22T10:00:00Z",
	}
}

func openWithPublisher(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.UpsertPublisher(PublisherRow{
		PublisherID: "fp1", DisplayName: "P", TrustLevel: "tofu_friend",
		FirstSeen: "2026-04-26T19:00:00Z", LastSeenBundle: "2026-04-26T19:00:00Z",
		KeyStatus: "active", RotationChain: []string{}, RevocationSources: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

// The flag round-trips through both scanners, and no upsert clears it.
func TestManualOnlyIsStoredAndSticky(t *testing.T) {
	s := openWithPublisher(t)
	row := manualRow("w1")
	row.ManualOnly = true
	if err := s.UpsertRoute(row); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoute(manualRow("plain")); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRoute("w1")
	if err != nil || !got.ManualOnly {
		t.Fatalf("GetRoute: %+v %v", got.ManualOnly, err)
	}
	all, _ := s.ListRoutes()
	for _, r := range all {
		if r.ManualOnly != (r.RouteID == "w1") {
			t.Fatalf("ListRoutes %s: manual_only=%v", r.RouteID, r.ManualOnly)
		}
	}
	// A re-import that does not say it (core/trust never does) keeps it.
	if err := s.UpsertRoute(manualRow("w1")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRoute("w1"); !got.ManualOnly {
		t.Fatal("an upsert without the flag cleared it")
	}
}

// The meta written before the import marks the row as it is first
// written, whatever path writes it (the RouteRow from core/trust has no
// such field set).
func TestManualOnlyFromMetaOnFirstWrite(t *testing.T) {
	s := openWithPublisher(t)
	now := time.Date(2026, 11, 22, 10, 30, 0, 0, time.UTC)
	if err := s.PutRouteMeta("w2", RouteMeta{ManualOnly: true, Name: "home wg"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoute(manualRow("w2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRoute("w2"); !got.ManualOnly {
		t.Fatal("the meta's manual-only bit did not reach the row")
	}
	m, ok := s.GetRouteMeta("w2")
	if !ok || m.Name != "home wg" || m.At != "2026-11-22T10:00:00Z" {
		t.Fatalf("meta: %+v %v", m, ok)
	}
	// A meta with a name only does not make a route manual-only.
	_ = s.PutRouteMeta("n1", RouteMeta{Name: "x"}, now)
	_ = s.UpsertRoute(manualRow("n1"))
	if got, _ := s.GetRoute("n1"); got.ManualOnly {
		t.Fatal("a name-only meta set manual_only")
	}
	// An empty meta removes what is held.
	_ = s.PutRouteMeta("n1", RouteMeta{}, now)
	if _, ok := s.GetRouteMeta("n1"); ok {
		t.Fatal("an empty meta was kept")
	}
}

// A database from before the column opens, and its rows read as not
// manual-only (the migration's default).
func TestManualOnlyMigrationOnAnOldDatabase(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE routes DROP COLUMN manual_only`); err != nil {
		t.Fatalf("premise: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO publishers (publisher_id, display_name, trust_level, first_seen, last_seen_bundle, key_status)
VALUES ('fp1','P','tofu_friend','a','b','active')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO routes (route_id, transport_family, engine, source_type, publisher_id, trust_state, scarcity_class, expires_at, imported_at)
VALUES ('old','wireguard','sing-box','x','fp1','tofu','normal','e','i')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetRoute("old")
	if err != nil || got.ManualOnly {
		t.Fatalf("old row after the migration: %+v %v", got.ManualOnly, err)
	}
}

func TestCleanRouteName(t *testing.T) {
	cases := map[string]string{
		"Germany 2":           "Germany 2",
		"  🇩🇪  fast\t\nnode ": "🇩🇪 fast node",
		"a‮gnp.exe":           "agnp.exe",    // RLO
		"⁧x⁩ ‏y‎":             "x y",         // isolates, RLM, LRM
		"bell\x07\x1b[31mred": "bell[31mred", // C0 controls
		"c1\u0085x\u009b":     "c1 x",        // NEL is a space; CSI dropped
		"zero​width\uFEFF":    "zerowidth",   // ZWSP, BOM
		"👨‍👩‍👧":               "👨‍👩‍👧",       // ZWJ kept
		"bad\xffutf8":         "badutf8",
		"‎‏":                  "",
		"سرور آلمان":          "سرور آلمان",
	}
	for in, want := range cases {
		if got := CleanRouteName(in); got != want {
			t.Errorf("CleanRouteName(%q) = %q, want %q", in, got, want)
		}
	}
	long := CleanRouteName(strings.Repeat("ab ", 100))
	if n := utf8.RuneCountInString(long); n > MaxRouteNameRunes || strings.HasSuffix(long, " ") {
		t.Fatalf("long name: %d runes %q", n, long)
	}
}

// A name left by a paste whose import never finished goes after a month;
// a manual-only meta stays (a late answer to the trust prompt must still
// find it); a stored route's meta always stays.
func TestPruneRouteMeta(t *testing.T) {
	s := openWithPublisher(t)
	old := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	_ = s.PutRouteMeta("gone-name", RouteMeta{Name: "a"}, old)
	_ = s.PutRouteMeta("gone-manual", RouteMeta{ManualOnly: true, Name: "b"}, old)
	_ = s.PutRouteMeta("fresh", RouteMeta{Name: "c"}, now.Add(-time.Hour))
	_ = s.PutRouteMeta("kept", RouteMeta{Name: "d"}, old)
	_ = s.UpsertRoute(manualRow("kept"))
	n, err := s.PruneRouteMeta(now)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d (%v), want 1", n, err)
	}
	for id, want := range map[string]bool{"gone-name": false, "gone-manual": true, "fresh": true, "kept": true} {
		if _, ok := s.GetRouteMeta(id); ok != want {
			t.Errorf("%s: held=%v, want %v", id, ok, want)
		}
	}
}
