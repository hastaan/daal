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
