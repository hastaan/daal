// Package profiles loads toolbox-profile JSON files. Profiles are
// data, not code: adding a new profile (e.g. china-default) is an
// edit + a fixture, not a release. Per supplement §11.5 / phase doc
// invariant 27.
package profiles

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// IranDefaultJSON embeds the canonical iran-default profile so the
// CLI doesn't need a filesystem path to a profiles dir at runtime.
// FRP-8 amends this by adding cdn_fronted entries to the same file.
//
//go:embed iran-default.json
var IranDefaultJSON []byte

// IranTCP443JSON embeds the second profile, and the reason it exists is
// L6.
//
// L6 is the rung whose entire content is "rebuild this relay onto a
// different toolbox profile". With ONE profile in the repo it was
// byte-identical to L1 — an expensive rebuild that changed nothing —
// and the only way to invoke it non-degenerately was to name a slug
// that did not resolve, which (before this wave) silently produced a
// record with zero candidates.
//
// The difference is the one that matters on Iranian networks: every
// udp_gated family is gone. Where UDP is throttled or dropped outright,
// hysteria2/tuic/wireguard are not merely slow — a QUIC-shaped flow to
// a graylisted host is itself the distinguishing feature, so a relay
// that keeps offering them keeps offering a signal. The resulting pack
// has a genuinely different family SET, which is also what makes the
// rung observable: DeriveRelayPackID hashes the family set, so an L6
// visibly renames the pack, and the Step-10 DONE test ("the re-signed
// pack's family set differs from the previous pack's") has something to
// assert.
//
//go:embed iran-tcp443.json
var IranTCP443JSON []byte

// WHY shadowsocks IS IN BOTH PROFILES AND default_enabled IS false.
//
// The family is fully built end to end — box inbound, firewall port,
// client outbound renderer, rotation — but it is NOT on by default, and
// the reason is release coupling rather than doubt about the transport.
//
// cmd/daal-relay-mgmt ships as a hash-pinned artifact
// (publisher/deploy/cloudinit/artifacts.go). Until a human rebuilds it,
// re-signs it, re-uploads it and bumps that pin, a relay provisioned by
// this publisher still boots the OLD binary, which creates no ss-in
// inbound. Turning the family on by default would then put a
// shadowsocks route in every new relay's signed manifest while the box
// serves nothing on 8446 — and because RewriteProfilesForRecipient
// fails closed on a route it cannot make connectable, the result is not
// one dead tier, it is NO PACK AT ALL for that relay. Every recipient
// blocked, for a family nobody asked for.
//
// Present-but-off is the honest middle: an operator who has updated
// their relays can name the family explicitly (enabled_families) and
// get it, and one who has not gets the renderer's specific refusal
// naming the artifact pin instead of a silent dead route.
//
// FLIP BOTH TO true IN THE SAME COMMIT THAT BUMPS THE ARTIFACT PIN.
// That is the whole to-do; nothing else about the family is pending.

// Profile is one toolbox profile parsed from JSON.
type Profile struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	SpecVersion int                `json:"spec_version"`
	Candidates  []ProfileCandidate `json:"candidates"`
}

// ProfileCandidate is the per-candidate row the wizard renders into
// a checkbox grid. The wizard's user can toggle DefaultEnabled.
type ProfileCandidate struct {
	Family           string `json:"family"`
	DefaultEnabled   bool   `json:"default_enabled"`
	ProbingRiskClass string `json:"probing_risk_class"`
	UDPGated         bool   `json:"udp_gated"`

	// Multiplex is the per-route (one route per family) stream-
	// multiplexing knob — Wave 2 Step 5. It lives here, in profile data,
	// rather than in the renderer because the trade is per-transport and
	// per-network: multiplexing is the only documented defence against
	// the Xue et al. nested-TLS classifier, but smux over TCP adds
	// head-of-line blocking, so it belongs on the TLS families and never
	// on the QUIC-native ones. nil = off, which is the pre-Wave-2 wire
	// shape and what every already-distributed pack carries.
	Multiplex *ProfileMultiplex `json:"multiplex,omitempty"`
}

// ProfileMultiplex is the JSON shape of the per-candidate multiplex knob.
// It is deliberately narrower than sing-box's OutboundMultiplexOptions:
// protocol and padding are decided by the renderer (h2mux + padding
// always), because neither is a per-deployment choice, and Brutal is a
// congestion-control override that is not a censorship countermeasure.
type ProfileMultiplex struct {
	Enabled bool `json:"enabled"`
	// MaxStreams is the concurrent-stream ceiling per connection; omit
	// (0) to take the renderer's default.
	MaxStreams int `json:"max_streams,omitempty"`
}

// Load parses the given JSON bytes into a Profile.
func Load(body []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("profile parse: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile missing name")
	}
	if p.SpecVersion == 0 {
		return nil, fmt.Errorf("profile %s missing spec_version", p.Name)
	}
	if len(p.Candidates) == 0 {
		return nil, fmt.Errorf("profile %s has no candidates", p.Name)
	}
	return &p, nil
}

// IranDefault parses the embedded iran-default profile. Called by
// the CLI on `--toolbox iran-default`.
func IranDefault() (*Profile, error) {
	return Load(IranDefaultJSON)
}

// IranTCP443 parses the embedded iran-tcp443 profile.
func IranTCP443() (*Profile, error) {
	return Load(IranTCP443JSON)
}

// Slugs lists every profile this build ships, in the order a UI should
// offer them. Single source of truth: the provider adapters' loadProfile
// dispatch and any picker must both come from here, or "the wizard
// offers a profile the provisioner cannot resolve" becomes a rotation
// that destroys a relay and then errors.
func Slugs() []string { return []string{"iran-default", "iran-tcp443"} }

// ByName resolves a slug. Unknown is an error, never a nil profile —
// see candidatesForProfile in the hetzner adapter for the shape of bug
// a silent nil here produced.
func ByName(name string) (*Profile, error) {
	switch name {
	case "iran-default":
		return IranDefault()
	case "iran-tcp443":
		return IranTCP443()
	default:
		return nil, fmt.Errorf("unknown toolbox profile %q (have: %v)", name, Slugs())
	}
}
