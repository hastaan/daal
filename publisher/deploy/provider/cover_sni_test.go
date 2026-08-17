package provider

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"daal/publisher/deploy/sni"
)

func TestResolveCoverSNI_PicksPerRelay(t *testing.T) {
	a, err := ResolveCoverSNI("", "daal-fsn1-aaaaaaaaaaaaaaaa", "fsn1")
	if err != nil {
		t.Fatal(err)
	}
	if a == "" {
		t.Fatal("no cover host chosen")
	}
	if err := sni.ValidHost(a); err != nil {
		t.Fatalf("chosen host is not admissible: %v", err)
	}
	again, _ := ResolveCoverSNI("", "daal-fsn1-aaaaaaaaaaaaaaaa", "fsn1")
	if again != a {
		t.Errorf("same relay resolved to %q then %q", a, again)
	}
	// Different relays must be able to differ; scan a handful rather
	// than asserting on one pair, since any two seeds may legitimately
	// collide in a pool this size.
	distinct := map[string]bool{a: true}
	for _, seed := range []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"} {
		h, _ := ResolveCoverSNI("", seed, "fsn1")
		distinct[h] = true
	}
	if len(distinct) < 2 {
		t.Errorf("nine relays all resolved to one host: %v", distinct)
	}
}

func TestResolveCoverSNI_HonoursPersisted(t *testing.T) {
	const persisted = "mirror.bahnhof.net"
	got, err := ResolveCoverSNI(persisted, "any-seed", "fsn1")
	if err != nil {
		t.Fatal(err)
	}
	if got != persisted {
		t.Errorf("got %q, want the persisted %q", got, persisted)
	}
}

// TestResolveCoverSNI_UpgradesTheLegacyConstant: a record still carrying
// the fleet-wide constant must not drag a newly built box into the same
// bet.
func TestResolveCoverSNI_UpgradesTheLegacyConstant(t *testing.T) {
	got, err := ResolveCoverSNI(sni.LegacyCoverSNI, "daal-fsn1-legacy", "fsn1")
	if err != nil {
		t.Fatal(err)
	}
	if got == sni.LegacyCoverSNI {
		t.Fatal("a new box was resolved onto the fleet-wide constant")
	}
}

func TestResolveCoverSNI_RejectsGarbage(t *testing.T) {
	for _, bad := range []string{"WWW.Example.Com", "localhost", "203.0.113.1", "example.com:443", "cdn.cloudflare.net"} {
		if _, err := ResolveCoverSNI(bad, "seed", "fsn1"); err == nil {
			t.Errorf("ResolveCoverSNI accepted %q", bad)
		}
	}
}

// TestReuseCoverSNI_RefusesToGuess. The argument is the --cover-sni
// FLAG, not the record, and nothing feeds the record back into it. So an
// empty value means "the caller did not say", never "this box predates
// the field" — and inventing the legacy constant there writes a lie into
// the operator's own source of truth about a live relay, which the pack
// minter and the rotation exclusion both now read.
func TestReuseCoverSNI_RefusesToGuess(t *testing.T) {
	if _, err := ReuseCoverSNI(""); err == nil {
		t.Error("ReuseCoverSNI(\"\") invented a cover host for a box it cannot see")
	}
	got, err := ReuseCoverSNI("mirror.init7.net")
	if err != nil {
		t.Fatal(err)
	}
	if got != "mirror.init7.net" {
		t.Errorf("ReuseCoverSNI overwrote a known value: %q", got)
	}
	// A pre-Wave-2 record has no cover host, so its operator states the
	// constant explicitly. That is a claim somebody made, not one the
	// code invented, and it is honoured verbatim.
	if got, err := ReuseCoverSNI(sni.LegacyCoverSNI); err != nil || got != sni.LegacyCoverSNI {
		t.Errorf("ReuseCoverSNI(legacy) = %q, %v; want the constant honoured", got, err)
	}
}

func TestNextCoverSNI_MovesAway(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	rec := &OperatorRecord{ServerID: "77", Region: "hel1", CoverSNI: sni.Pick("seed", "hel1")}
	next, err := NextCoverSNI(rec, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if next == rec.CoverSNI {
		t.Fatalf("rotation returned the current host %q", next)
	}
	// hel1 is eu-north; the replacement must stay in the neighbourhood.
	found := false
	for _, e := range sni.InZone(sni.ZoneEUNorth) {
		if e.Host == next {
			found = true
		}
	}
	if !found {
		t.Errorf("rotation left the relay's zone: %q", next)
	}
}

func TestNextCoverSNI_ExplicitOverride(t *testing.T) {
	rec := &OperatorRecord{ServerID: "77", Region: "hel1"}
	got, err := NextCoverSNI(rec, "mirrors.dotsrc.org", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != "mirrors.dotsrc.org" {
		t.Errorf("got %q", got)
	}
	if _, err := NextCoverSNI(rec, "www.cloudflare.com", time.Now()); err == nil {
		t.Error("NextCoverSNI accepted a blanket-blocked host")
	}
	if _, err := NextCoverSNI(nil, "", time.Now()); err == nil {
		t.Error("NextCoverSNI accepted a nil record")
	}
}

// TestOperatorRecord_CoverSNIRoundTrips. The record crosses the
// Go → SQLite → Rust → binder boundary as canonical JSON; a field that
// does not survive that is a field the binder never sees. Records
// written before the field existed must still omit it cleanly, so an old
// row stays byte-identical.
func TestOperatorRecord_CoverSNIRoundTrips(t *testing.T) {
	rec := OperatorRecord{Provider: "hetzner", ServerID: "1", CoverSNI: "mirror.xtom.de"}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"cover_sni":"mirror.xtom.de"`)) {
		t.Errorf("cover_sni not serialised: %s", body)
	}
	var got OperatorRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.CoverSNI != rec.CoverSNI {
		t.Errorf("CoverSNI lost: %q", got.CoverSNI)
	}

	legacy := OperatorRecord{Provider: "hetzner", ServerID: "1"}
	body, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("cover_sni")) {
		t.Errorf("legacy record grew a cover_sni key: %s", body)
	}
}
