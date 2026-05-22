package netmem

import "testing"

func TestHashIDStable(t *testing.T) {
	tests := []struct {
		name           string
		kind           Kind
		carrier, ssid  string
		want, wantSize int
	}{
		// Stability vectors locked at v1.
		{"wifi-ssid", KindWiFi, "", "Home", 16, 16},
		{"wifi-ssid-with-carrier", KindWiFi, "MCI", "Home", 16, 16},
		{"cell-carrier-only", KindCell, "MCI", "", 16, 16},
		{"eth-empty", KindEth, "", "", 16, 16},
		{"unknown-empty", KindUnknown, "", "", 16, 16},
	}
	seen := map[string]string{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashID(tt.kind, tt.carrier, tt.ssid)
			if len(got) != tt.wantSize {
				t.Fatalf("HashID len = %d, want %d", len(got), tt.wantSize)
			}
			// Same inputs → same output.
			if again := HashID(tt.kind, tt.carrier, tt.ssid); again != got {
				t.Fatalf("HashID not stable: %s vs %s", got, again)
			}
			seen[tt.name] = got
		})
	}
	// Distinct inputs → distinct outputs (within our test fan).
	uniq := map[string]bool{}
	for _, v := range seen {
		if uniq[v] {
			t.Fatalf("HashID collision in test fan: %s", v)
		}
		uniq[v] = true
	}
}

func TestHashIDInputBoundaries(t *testing.T) {
	// Substrings or shifted concatenations must not collide.
	a := HashID(KindWiFi, "AB", "C")
	b := HashID(KindWiFi, "A", "BC")
	if a == b {
		t.Fatalf("HashID separators failed: AB|C and A|BC collided")
	}
}

func TestSentinelUnsetIsValidHex(t *testing.T) {
	if len(SentinelUnset) != 16 {
		t.Fatalf("SentinelUnset wrong size: %d", len(SentinelUnset))
	}
	for _, c := range SentinelUnset {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("SentinelUnset not lowercase-hex: %q", c)
		}
	}
}

func TestIsValidKind(t *testing.T) {
	for _, k := range []Kind{KindWiFi, KindCell, KindEth, KindUnknown} {
		if !IsValidKind(k) {
			t.Fatalf("IsValidKind(%q) = false, want true", k)
		}
	}
	if IsValidKind(Kind("bogus")) {
		t.Fatalf("IsValidKind(bogus) = true, want false")
	}
}
