package relaypack

import (
	"sort"

	"daal/bundle-go/bundle"
)

// BuildSharedRiskGraph computes the bundle-level shared_risk_graph
// per supplement v2.3.7 §12.3:
//
// For each tag t appearing in any candidate's public_risk_tags[]:
//
//	members[t] := { candidate_id : t ∈ candidate.public_risk_tags }
//	if |members[t]| ≥ 2:  emit SharedRiskEdge{tag: t, members: sorted(members[t])}
//
// Output is sorted by tag (ascending) for canonical determinism. The
// tag set is taken from public_risk_tags only — origin_risk_tags are
// never propagated through the graph because TIC never observes
// them (per §13.4 cooldown propagation rules; the selector reads this
// graph at selection time without re-deriving it).
//
// candidateIDs[i] must be the route id corresponding to entries[i];
// they are kept as parallel slices so the function is purely
// data-driven (no dependency on the route ordering inside Manifest.Routes).
func BuildSharedRiskGraph(candidateIDs []string, entries []bundle.RelayPackEntry) []bundle.SharedRiskEdge {
	if len(candidateIDs) != len(entries) {
		// Programmer error: kept defensive — callers always pass parallel slices.
		return nil
	}
	tagToMembers := map[string]map[string]struct{}{}
	for i, e := range entries {
		id := candidateIDs[i]
		for _, tag := range e.PublicRiskTags {
			if tagToMembers[tag] == nil {
				tagToMembers[tag] = map[string]struct{}{}
			}
			tagToMembers[tag][id] = struct{}{}
		}
	}

	tags := make([]string, 0, len(tagToMembers))
	for tag := range tagToMembers {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	out := make([]bundle.SharedRiskEdge, 0, len(tags))
	for _, tag := range tags {
		set := tagToMembers[tag]
		if len(set) < 2 {
			continue
		}
		members := make([]string, 0, len(set))
		for id := range set {
			members = append(members, id)
		}
		sort.Strings(members)
		out = append(out, bundle.SharedRiskEdge{Tag: tag, Members: members})
	}
	return out
}
