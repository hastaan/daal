package profiles

import "testing"

// TestShadowsocksIsOfferedButOffByDefault pins the one thing about this
// family's profile rows that is easy to "tidy" wrong.
//
// It is listed, because the whole chain exists: an ss-in inbound on the
// box, 8446/tcp in both firewalls, a client outbound the strict parser
// accepts, and per-recipient rotation. An operator who has updated their
// relays must be able to name it.
//
// It is OFF by default, and not because of any doubt about the
// transport. The artifact pin in publisher/deploy/cloudinit/artifacts.go
// still names a daal-relay-mgmt build with no ss-in in it, so a relay
// provisioned right now serves nothing on 8446. Default-enabling the
// family would put a shadowsocks route in every new relay's SIGNED
// manifest while the box cannot answer it — and because
// RewriteProfilesForRecipient fails closed on any route it cannot make
// connectable, that is not one dead tier, it is NO PACK AT ALL for that
// relay: every recipient blocked, for a family nobody asked for.
//
// Flip both to true in the same commit that bumps the artifact pin.
func TestShadowsocksIsOfferedButOffByDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func() (*Profile, error)
	}{
		{"iran-default", IranDefault},
		{"iran-tcp443", IranTCP443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.load()
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			var found *ProfileCandidate
			for i := range p.Candidates {
				if p.Candidates[i].Family == "shadowsocks" {
					found = &p.Candidates[i]
				}
			}
			if found == nil {
				t.Fatalf("shadowsocks is not offered; the family is fully built and an operator must be able to opt in")
			}
			if found.DefaultEnabled {
				t.Errorf("shadowsocks is default-enabled: against the currently pinned daal-relay-mgmt the box serves nothing on 8446, and the pack minter fails closed, so EVERY pack for a new relay would fail to build")
			}
			// Not UDP-gated: the inbound is TCP-only and UDP rides
			// udp_over_tcp on the same connection. Marking it gated
			// would drop the family from the TCP-only profile for no
			// reason.
			if found.UDPGated {
				t.Errorf("shadowsocks is marked udp_gated; it is a TCP inbound and its UDP is tunnelled over that same TCP connection")
			}
			// Mux is refused by the renderer regardless (sing-box builds
			// a UoT client OR a mux client, never both, and silently
			// discards the loser), so the profile must not claim it.
			if found.Multiplex != nil && found.Multiplex.Enabled {
				t.Errorf("profile enables multiplex on shadowsocks; udp_over_tcp makes the block inert, so the pack would advertise a mitigation it does not apply")
			}
		})
	}
}
