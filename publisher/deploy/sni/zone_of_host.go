package sni

import "strings"

// ZoneOfHost answers "which peering neighbourhood does this cover host
// live in?" — the inverse of the ZoneFor(region) lookup Pick uses.
//
// WHY IT EXISTS. Wave 2 chose one cover host per relay from the zone of
// the relay's REGION (R6), and then nothing ever re-checked the pairing,
// because nothing could move a relay's address. Step 9 can: a floating IP
// is a separate cloud object with its OWN home location, and Hetzner
// permits attaching one to a server in a different location (traffic is
// then routed via the home location). So after an L3 swap the address a
// censor sees may sit in a different neighbourhood than the region the
// cover host was picked for, and the R6 claim the record makes about
// itself silently stops being true.
//
// This is the smallest thing that can detect that: the pool already
// records a Zone per entry as measured evidence, so the check is a table
// lookup rather than a runtime inference.
//
// ok=false means "not judgeable", not "bad". Three real cases produce it,
// and all three must be allowed through by callers:
//
//   - an operator-supplied cover host that was never in the pool;
//   - LegacyCoverSNI on a pre-Wave-2 record (inadmissible, but a fact
//     about a running box);
//   - a host dropped from the pool by an audit while relays still
//     advertise it.
//
// Blocking any of those would turn a pool edit into an outage for relays
// that are working fine.
func ZoneOfHost(host string) (Zone, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return ZoneAny, false
	}
	// Read the raw table, not admissible(): a host that has since
	// failed Admit is still *served from where it was served*, and the
	// caller's question is about network neighbourhood, not eligibility.
	for _, e := range pool {
		if e.Host == h {
			return e.Zone, true
		}
	}
	return ZoneAny, false
}

// ZoneMismatch reports whether cover host `host` is known to sit in a
// different neighbourhood than provider region `region` — i.e. whether
// advertising `host` from an address in `region` breaks R6.
//
// It answers false whenever the question cannot be settled: an unknown
// host (see ZoneOfHost) or an unrecognised region code (ZoneFor returns
// ZoneAny, which Pick deliberately treats as "the whole pool"). A check
// that guessed here would reject correct configurations the moment
// somebody added a region to a provider's table before adding it to
// regionZones, and "refuse to rotate" is a worse failure than "slightly
// less plausible cover host" — that trade-off is the same one Pick makes
// when it widens to ZoneAny rather than returning nothing.
func ZoneMismatch(host, region string) bool {
	hz, ok := ZoneOfHost(host)
	if !ok {
		return false
	}
	rz := ZoneFor(region)
	if rz == ZoneAny {
		return false
	}
	return hz != rz
}
