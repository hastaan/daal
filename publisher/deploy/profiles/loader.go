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
