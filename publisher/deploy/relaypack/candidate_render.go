package relaypack

import (
	"encoding/json"
	"fmt"
	"sort"

	"daal/bundle-go/bundle"
	"daal/publisher/deploy/provider"
)

// renderedCandidates is the parallel-slice output of
// renderCandidates(). Each i-th element refers to the same logical
// candidate; routes[i].FamilySpecificConfig already carries the
// `_relaypack` sub-object for entries[i].
type renderedCandidates struct {
	routes   []bundle.RouteManifestEntry
	entries  []bundle.RelayPackEntry
	profiles map[string][]byte
	ids      []string // parallel id slice for risk-graph builder
}

// renderCandidates folds an OperatorRecord's CandidateMeta slice
// into the parallel structures the binder needs:
//
//   - bundle.RouteManifestEntry: the on-disk per-route shape.
//   - bundle.RelayPackEntry:     the FRP-1 _relaypack sub-object.
//   - profiles map:              one profiles/<route_id>.json file per route,
//     body = the raw FamilySpecificConfig the route ships with.
//
// Route IDs are deterministic: r1, r2, …, rN, ordered by the index
// of the candidate in rec.Candidates. We do NOT sort — the operator's
// candidate ordering is preserved, which makes the risk-graph
// derivation order-stable.
//
// Family name normalisation: FRP-4a's profile names families with a
// hyphen ("amnezia-wg") for human readability but the bundle's
// TransportFamily enum uses the wire-form "amneziawg". This is the
// only normalisation step.
func renderCandidates(rec *provider.OperatorRecord, validFromRFC3339, validUntilRFC3339 string) (*renderedCandidates, error) {
	if rec == nil {
		return nil, fmt.Errorf("nil OperatorRecord")
	}
	if len(rec.Candidates) == 0 {
		return nil, fmt.Errorf("OperatorRecord carries no candidates")
	}
	out := &renderedCandidates{
		routes:   make([]bundle.RouteManifestEntry, 0, len(rec.Candidates)),
		entries:  make([]bundle.RelayPackEntry, 0, len(rec.Candidates)),
		profiles: map[string][]byte{},
		ids:      make([]string, 0, len(rec.Candidates)),
	}

	for i, c := range rec.Candidates {
		id := fmt.Sprintf("r%d", i+1)
		family := normaliseFamily(c.Family)
		if !validTransport(family) {
			return nil, fmt.Errorf("candidate %d: unknown transport_family %q", i, c.Family)
		}

		// Compose the FRP-1 _relaypack sub-object from the meta.
		// Deduplicate-and-sort the tag slices for canonical determinism.
		entry := bundle.RelayPackEntry{
			ExposureMode:     c.ExposureMode,
			FamilyClass:      c.FamilyClass,
			ProbingRiskClass: c.ProbingRiskClass,
			PublicRiskTags:   sortedUniqueStrings(c.PublicRiskTags),
			OriginRiskTags:   sortedUniqueStrings(c.OriginRiskTags),
		}

		// Pass-through any family-specific Params, then inject the
		// _relaypack key. FamilySpecificConfig is opaque to the bundle
		// parser; the FRP-1 validator parses _relaypack out at import.
		fc := map[string]any{}
		if len(c.Params) > 0 {
			if err := json.Unmarshal(c.Params, &fc); err != nil {
				return nil, fmt.Errorf("candidate %d: malformed Params JSON: %w", i, err)
			}
		}
		// "port" is canonical metadata at this level (not bundle-typed)
		// so the wizard / box can render the inbound config without
		// re-parsing the candidate; selector ignores unknown keys.
		fc["port"] = c.Port
		fc["_relaypack"] = entry

		// FRP-8: cdn_fronted candidates carry their §11.7 hardening
		// attestation under the reserved `_cdn_attestation` key.
		// The validator (RP022/RP023) reads it at import time.
		if c.ExposureMode == "cdn_fronted" && c.CDNAttestation != nil {
			fc["_cdn_attestation"] = bundle.CDNAttestation{
				OriginCAFingerprint: c.CDNAttestation.OriginCAFingerprint,
				AOPEnabled:          c.CDNAttestation.AOPEnabled,
				FirewallID:          c.CDNAttestation.FirewallID,
				DNSOnlyPresent:      c.CDNAttestation.DNSOnlyPresent,
			}
		}

		fcBytes, err := json.Marshal(fc)
		if err != nil {
			return nil, fmt.Errorf("candidate %d: marshal family_specific_config: %w", i, err)
		}

		configPath := fmt.Sprintf("profiles/%s.json", id)
		// Profiles archive carries the per-route family-specific blob;
		// recipient parsers read it out via Bundle.Profiles[ConfigPath].
		out.profiles[configPath] = fcBytes

		out.routes = append(out.routes, bundle.RouteManifestEntry{
			ID:                   id,
			ScarcityClass:        string(bundle.ScarcityNormal),
			TransportFamily:      family,
			ConfigPath:           configPath,
			ValidFrom:            validFromRFC3339,
			ValidUntil:           validUntilRFC3339,
			UDPGated:             udpGatedForFamily(family),
			FamilySpecificConfig: fcBytes,
		})
		out.entries = append(out.entries, entry)
		out.ids = append(out.ids, id)
	}
	return out, nil
}

// normaliseFamily maps the FRP-4a profile family-name vocabulary to
// the bundle TransportFamily enum vocabulary.
func normaliseFamily(family string) string {
	switch family {
	case "amnezia-wg":
		return string(bundle.TransportAmneziaWG)
	default:
		return family
	}
}

// validTransport delegates to the bundle package's own predicate.
//
// WAVE-5 REPAIR. This used to be a second hand-kept switch listing the
// families by name, and it had gone stale: `anytls` was added to the
// enum without being added here, so `renderCandidates` refused an
// anytls candidate as an "unknown transport_family" and
// BuildOperatorPack failed for the WHOLE pack — no routes at all, not
// even the four that work. There is now one list
// (bundle.ValidTransportFamily) and this is a thin call into it. Do
// not re-inline the switch.
func validTransport(family string) bool {
	return bundle.ValidTransportFamily(family)
}

// udpGatedForFamily mirrors the FRP-4a profile_render.portProto rule.
func udpGatedForFamily(family string) bool {
	switch family {
	case string(bundle.TransportHysteria2),
		string(bundle.TransportTUIC),
		string(bundle.TransportWireGuard),
		string(bundle.TransportAmneziaWG):
		return true
	}
	return false
}

// anyFamily reports whether any rendered route names the given
// transport family. Used by the binder to decide the manifest's
// spec_version from the pack's actual CONTENT rather than from the
// build that produced it — see the SpecVersionAnyTLS block there.
func anyFamily(routes []bundle.RouteManifestEntry, family string) bool {
	for _, r := range routes {
		if r.TransportFamily == family {
			return true
		}
	}
	return false
}

func sortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
