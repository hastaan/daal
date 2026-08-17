package sni

import "testing"

func TestZoneOfHost_KnownAndUnknown(t *testing.T) {
	for _, e := range Admissible() {
		got, ok := ZoneOfHost(e.Host)
		if !ok {
			t.Errorf("%s: pool entry not found by ZoneOfHost", e.Host)
			continue
		}
		if got != e.Zone {
			t.Errorf("%s: zone = %q, want %q", e.Host, got, e.Zone)
		}
	}
	if _, ok := ZoneOfHost("mirror.example.invalid"); ok {
		t.Error("a host that is not in the pool must be reported as unjudgeable, not placed in a zone")
	}
	if _, ok := ZoneOfHost(""); ok {
		t.Error("empty host must be unjudgeable")
	}
	// Case and whitespace are operator input, not a different host.
	if z, ok := ZoneOfHost("  MIRROR.XTOM.DE "); !ok || z != ZoneEUCentral {
		t.Errorf("ZoneOfHost(mixed case) = %q, %v", z, ok)
	}
}

// ZoneMismatch is the predicate the L3 swap refuses on. It must be
// false whenever the question cannot be settled: a false positive there
// blocks a rotation that is fine, which is worse than a slightly
// less-plausible cover host.
func TestZoneMismatch(t *testing.T) {
	// mirror.xtom.de is eu-central.
	if ZoneMismatch("mirror.xtom.de", "fsn1") {
		t.Error("eu-central host in an eu-central region reported as a mismatch")
	}
	if ZoneMismatch("mirror.xtom.de", "nbg1") {
		t.Error("two regions in the same zone reported as a mismatch")
	}
	if !ZoneMismatch("mirror.xtom.de", "sin") {
		t.Error("an eu-central host advertised from an apac address is a mismatch and must be caught")
	}

	if ZoneMismatch("mirror.example.invalid", "sin") {
		t.Error("an unknown host must not be judged")
	}
	if ZoneMismatch("mirror.xtom.de", "zz-nowhere") {
		t.Error("an unrecognised region resolves to ZoneAny, which Pick treats as the whole pool; it must not be a mismatch either")
	}
	if ZoneMismatch(LegacyCoverSNI, "sin") {
		t.Error("the pre-Wave-2 constant is not in the pool and must be unjudgeable rather than a mismatch")
	}
}
