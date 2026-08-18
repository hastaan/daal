package rotation

// THE RUNG THAT MUST NEVER TURN INTO A REBUILD.
//
// L1 and L2 have a documented fallback: a relay too old to rotate in
// place degrades to `reprovision`, which destroys the box. That is
// correct for them — the operator asked to change a credential or a
// cover host, and a rebuild does deliver that outcome, expensively.
//
// L3 has no such fallback and must never grow one, because for L3 the
// fallback would not deliver the outcome at all. An operator reaching
// for L3 has a BLOCKED ADDRESS and is choosing the cheap rung: keep the
// server, keep the mgmt TLS pin, swap the address, seconds. Degrading
// that to a rebuild silently trades a fifteen-second operation for a
// three-minute one that destroys the box, mints new mgmt material and
// invalidates every distributed pack — and the operator pressed a
// button labelled with none of that. This is the same "dial that lies"
// the recommender's wall-clock rule was added to end, one level up.
//
// The shape of the regression is specific and plausible enough to
// name. floatingIPSwapAction hand-rolls its three-state availability
// answer while L1 and L2 both go through withAvailability(...,
// fallbackReprovision(...)). Unifying them looks like a tidy-up and is
// the single most likely way this breaks — especially in a wave that
// is adding a second live provider and reworking the recommender that
// picks the rung.
//
// So: whatever the provider, whatever the relay can do, an L3 stays a
// floating-IP swap. When it cannot be performed it says so and offers
// the rebuild as ADVICE the operator can read; it never silently
// becomes one.

import "testing"

// everyCapabilityShape enumerates the RelayCapabilities lattice that
// matters here: unprobed, probed-and-able, probed-and-unable, and the
// mixed shapes where a relay can do one in-place verb but not another.
func everyCapabilityShape() []RelayCapabilities {
	var out []RelayCapabilities
	for _, known := range []bool{false, true} {
		for _, creds := range []bool{false, true} {
			for _, tls := range []bool{false, true} {
				for _, bind := range []bool{false, true} {
					out = append(out, RelayCapabilities{
						Known:                    known,
						RotateCredentialsInPlace: creds,
						RotateTLSInPlace:         tls,
						BindAddress:              bind,
					})
				}
			}
		}
	}
	return out
}

// The invariant, across every provider name the record can carry and
// every capability shape the probe can return.
func TestL3_IsNeverADestroyingRebuild(t *testing.T) {
	// "" and a nonsense value are included on purpose: an unknown
	// provider is its own state, and the branch that handles it is
	// exactly the kind of default arm a refactor sweeps into a
	// fallback.
	for _, prov := range []string{"hetzner", "vultr", "stark", "", "digitalocean", "HETZNER"} {
		for _, caps := range everyCapabilityShape() {
			a := ActionForProvider(L3, caps, prov)
			if a.DestroysServer {
				t.Fatalf("L3 on %q with caps %+v destroys the server.\n"+
					"An operator reaching for L3 has a blocked address and is choosing the cheap rung; "+
					"a rebuild costs them the box, the mgmt pin and every distributed pack, and they pressed a button that said none of that.\n"+
					"got %+v", prov, caps, a)
			}
			if a.Kind != ActionFloatingIPSwap {
				t.Fatalf("L3 on %q with caps %+v became %q; L3 must stay an address swap and report that it cannot run, "+
					"never quietly turn into a different, more expensive operation", prov, caps, a.Kind)
			}
			if a.CLIVerb != "floating-ip" {
				t.Fatalf("L3 on %q names verb %q; the recommendation and the thing that runs must be the same operation",
					prov, a.CLIVerb)
			}
			// A rung that cannot run must say so. Availability is the
			// only field the caller can act on, and an empty one reads
			// as the zero value rather than as an answer.
			if a.Availability == "" {
				t.Fatalf("L3 on %q with caps %+v carries no availability", prov, caps)
			}
			if a.Availability != AvailabilityReady && a.Note == "" {
				t.Fatalf("L3 on %q with caps %+v is not ready and does not say why", prov, caps)
			}
		}
	}
}

// ActionFor is the no-provider spelling and must reach the same
// conclusion: not knowing which adapter is underneath is a reason to
// withhold the rung, never a reason to substitute a rebuild for it.
func TestL3_WithoutAProviderIsWithheldNotSubstituted(t *testing.T) {
	for _, caps := range everyCapabilityShape() {
		a := ActionFor(L3, caps)
		if a.DestroysServer || a.Kind != ActionFloatingIPSwap {
			t.Fatalf("ActionFor(L3, %+v) = %+v", caps, a)
		}
		if a.Availability != AvailabilityUnknown {
			t.Fatalf("ActionFor(L3, %+v) availability = %q, want unknown: whether a swap moves the record's "+
				"dialled address is a property of the adapter, and we were not told which", caps, a.Availability)
		}
	}
}

// The counterpart, stated so the asymmetry is deliberate rather than
// accidental: L1 and L2 DO degrade to a destroying rebuild on a relay
// that cannot rotate in place. If this ever stops being true the
// asymmetry above has been "fixed" in the wrong direction, and this
// test is where that shows up.
func TestL1L2_DoDegradeToARebuild_AndThatIsTheDifference(t *testing.T) {
	old := RelayCapabilities{Known: true} // probed, and cannot do either in place
	for _, l := range []Level{L1, L2} {
		a := ActionForProvider(l, old, "hetzner")
		if !a.DestroysServer || a.Kind != ActionReprovision {
			t.Fatalf("%s on a relay that cannot rotate in place = %+v, want the destroying fallback", l, a)
		}
		if a.Availability != AvailabilityUnsupported {
			t.Errorf("%s fallback availability = %q, want unsupported (the in-place verb is what is unavailable)", l, a.Availability)
		}
	}
	// And the same relay's L3 does not.
	if a := ActionForProvider(L3, old, "hetzner"); a.DestroysServer {
		t.Fatalf("L3 degraded alongside L1/L2 on the same relay: %+v", a)
	}
}

// The destructive rungs stay destructive, whatever the relay can do in
// place. The recommender quotes wall-clock off DestroysServer, so a
// false here is a rebuild sold as a fifteen-second fix.
func TestL4L5L6_AreDestructiveWhateverTheRelayCanDo(t *testing.T) {
	for _, prov := range []string{"hetzner", "vultr", "stark", ""} {
		for _, caps := range everyCapabilityShape() {
			for _, l := range []Level{L4, L5, L6} {
				a := ActionForProvider(l, caps, prov)
				if !a.DestroysServer {
					t.Fatalf("%s on %q with caps %+v does not report that it destroys the server: %+v", l, prov, caps, a)
				}
				if !a.InvalidatesEveryPack {
					t.Fatalf("%s on %q rebuilds the box but claims the distributed packs survive: %+v", l, prov, a)
				}
			}
		}
	}
}
