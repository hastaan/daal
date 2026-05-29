package selection

import (
	"encoding/json"
	"fmt"

	"daal/core/routestore"
)

// Candidate is the projection layer between core/routestore.RouteRow
// and the FRP-3 selector. It holds only what shortlist + cooldown +
// race + memory need; nothing else. The parsed SharedRiskGraph
// projection (one parse per RouteRow, not per cooldown lookup) is
// the load-bearing detail that lets the cooldown-propagation step
// run in O(edges) without re-parsing JSON.
type Candidate struct {
	// Identity / family.
	RouteID         string
	TransportFamily string
	ScarcityClass   string
	ModesAllowed    []string

	// FRP-2 RelayPack per-candidate fields.
	ExposureMode     string // direct_vps | cdn_fronted | "" (legacy)
	FamilyClass      string
	ProbingRiskClass string // low | moderate | high | ""
	PublicRiskTags   []string
	OriginRiskTags   []string
	ModifiersJSON    string

	// FRP-2 RelayPack bundle-level fields, denormalised onto every
	// candidate by the importer for read-locality.
	RelayPackID     string
	FreshnessURL    string
	SharedRiskGraph []SharedRiskEdge // parsed once from RouteRow.SharedRiskGraphJSON

	// Derived: udp_gated tags drive the selector's UDP-collapse
	// rule. Set by ProjectFromRouteRow when "udp_gated:true" is
	// present in PublicRiskTags.
	UDPGated bool

	// RankScore is an ephemeral selector score computed by Decide
	// from local-only inputs such as per-network memory and probing
	// risk. Higher is better. ProjectFromRouteRow leaves it zero so
	// callers that use Shortlist directly retain deterministic
	// RouteID tie-break behaviour.
	RankScore int
}

// SharedRiskEdge is one entry in the bundle-level shared_risk_graph
// — a tag plus the routes (within the same RelayPack bundle) that
// carry it. The cooldown propagation step looks up the edge by tag
// and propagates a cooldown to every Member except the route that
// just failed.
type SharedRiskEdge struct {
	Tag     string   `json:"tag"`
	Members []string `json:"members"`
}

// ProjectFromRouteRow projects the 9 FRP-2 RelayPack columns onto a
// Candidate. SharedRiskGraphJSON is parsed once (sentinel-empty
// '[]' → empty slice). PublicRiskTags / OriginRiskTags slices are
// adopted as-is (caller owns the underlying memory).
//
// Returns a typed error when SharedRiskGraphJSON is non-empty but
// not parseable. Legacy non-RelayPack rows (sentinel-empty fields)
// project cleanly: ExposureMode == "", PublicRiskTags == nil,
// SharedRiskGraph == nil.
func ProjectFromRouteRow(r routestore.RouteRow) (Candidate, error) {
	c := Candidate{
		RouteID:          r.RouteID,
		TransportFamily:  r.TransportFamily,
		ScarcityClass:    r.ScarcityClass,
		ModesAllowed:     r.ModesAllowed,
		ExposureMode:     r.ExposureMode,
		FamilyClass:      r.FamilyClass,
		ProbingRiskClass: r.ProbingRiskClass,
		PublicRiskTags:   r.PublicRiskTags,
		OriginRiskTags:   r.OriginRiskTags,
		ModifiersJSON:    r.ModifiersJSON,
		RelayPackID:      r.RelayPackID,
		FreshnessURL:     r.FreshnessURL,
	}
	// Detect udp_gated:true in public_risk_tags.
	for _, tag := range c.PublicRiskTags {
		if tag == "udp_gated:true" {
			c.UDPGated = true
			break
		}
	}
	// Parse shared-risk graph. Sentinel-empty '[]' → empty slice;
	// truly-empty '' (legacy schema bug-shaped row) also → empty.
	switch r.SharedRiskGraphJSON {
	case "", "[]", "null":
		c.SharedRiskGraph = nil
	default:
		var edges []SharedRiskEdge
		if err := json.Unmarshal([]byte(r.SharedRiskGraphJSON), &edges); err != nil {
			return Candidate{}, fmt.Errorf("ProjectFromRouteRow %s: shared_risk_graph parse: %w", r.RouteID, err)
		}
		c.SharedRiskGraph = edges
	}
	return c, nil
}

// IsRelayPack reports whether this candidate carries any FRP-1
// RelayPack metadata. Legacy non-RelayPack rows return false.
func (c Candidate) IsRelayPack() bool {
	return c.RelayPackID != "" || c.ExposureMode != ""
}

// SiblingsOnTag returns the route IDs (excluding c.RouteID) that
// share the given tag in c.SharedRiskGraph. Linear scan over the
// shared-risk graph; expected to be small (few edges per bundle).
func (c Candidate) SiblingsOnTag(tag string) []string {
	out, _ := c.SharedRiskMembers(tag)
	return out
}

// SharedRiskMembers returns the sibling route IDs for tag and a bool
// indicating whether the signed shared-risk graph contained an edge
// for that tag. The bool matters: "edge exists with no other members"
// means do not propagate; "edge absent" lets legacy callers fall
// back to raw tag equality.
func (c Candidate) SharedRiskMembers(tag string) ([]string, bool) {
	for _, edge := range c.SharedRiskGraph {
		if edge.Tag != tag {
			continue
		}
		out := make([]string, 0, len(edge.Members))
		for _, m := range edge.Members {
			if m == c.RouteID {
				continue
			}
			out = append(out, m)
		}
		return out, true
	}
	return nil, false
}
