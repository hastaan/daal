package vultr

import (
	"net"

	"daal/publisher/deploy/provider"
)

// candidatesForProfile produces the CandidateMeta slice for a
// freshly-provisioned Vultr instance. Mirrors the hetzner adapter's
// shape; V1.5 invariant: every candidate's exposure_mode ==
// "direct_vps" and origin_risk_tags is empty.
func candidatesForProfile(toolboxProfile string, mainIP net.IP, enabledFamilies []string) []provider.CandidateMeta {
	families := defaultFamiliesFor(toolboxProfile)
	if len(enabledFamilies) > 0 {
		filter := map[string]struct{}{}
		for _, f := range enabledFamilies {
			filter[f] = struct{}{}
		}
		out := families[:0]
		for _, f := range families {
			if _, ok := filter[f]; ok {
				out = append(out, f)
			}
		}
		families = out
	}
	cands := make([]provider.CandidateMeta, 0, len(families))
	for _, f := range families {
		cands = append(cands, provider.CandidateMeta{
			Family:           f,
			ExposureMode:     "direct_vps",
			FamilyClass:      "vps-native",
			ProbingRiskClass: probingRiskClassFor(f),
			Port:             portFor(f),
			PublicRiskTags:   []string{"public_ip:" + mainIP.String(), "public_port:tcp443"},
			OriginRiskTags:   []string{},
		})
	}
	return cands
}

func defaultFamiliesFor(profile string) []string {
	switch profile {
	case "iran-default":
		return []string{"vless-reality", "hysteria2", "trojan-tls", "shadowsocks-2022"}
	case "iran-aggressive":
		return []string{"vless-reality", "hysteria2", "tuic", "naive"}
	default:
		return []string{"vless-reality"}
	}
}

func probingRiskClassFor(family string) string {
	switch family {
	case "vless-reality", "trojan-tls":
		return "low"
	case "hysteria2", "tuic":
		return "medium"
	default:
		return "low"
	}
}

func portFor(family string) int {
	switch family {
	case "hysteria2", "tuic":
		return 443
	default:
		return 443
	}
}
